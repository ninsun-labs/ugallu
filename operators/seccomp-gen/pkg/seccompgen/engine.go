// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package seccompgen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	bridgev1 "github.com/ninsun-labs/tetragon-bridge/proto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Engine owns the lifecycle of in-flight training goroutines so the
// reconciler doesn't kick off duplicates on requeues.
type Engine struct {
	mu      sync.Mutex
	running map[string]context.CancelFunc
}

// NewEngine returns an empty engine.
func NewEngine() *Engine {
	return &Engine{running: map[string]context.CancelFunc{}}
}

// runKey is the engine-internal identifier - namespace/name of the
// SeccompTrainingRun.
func runKey(namespace, name string) string { return namespace + "/" + name }

// IsRunning reports whether the engine already has a goroutine
// attached for this run.
func (e *Engine) IsRunning(namespace, name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.running[runKey(namespace, name)]
	return ok
}

// Cancel stops an in-flight training (Pod selector changed, run
// deleted, etc.). Idempotent.
func (e *Engine) Cancel(namespace, name string) {
	e.mu.Lock()
	cancel := e.running[runKey(namespace, name)]
	delete(e.running, runKey(namespace, name))
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Capture is the result of one training run.
type Capture struct {
	// Syscalls is the deduplicated set of syscall names observed.
	// Sorted for deterministic profile bytes.
	Syscalls []string

	// PathsByPod is the per-Pod set of opened paths (debug aid; not
	// emitted in the seccomp.json itself).
	PathsByPod map[string]map[string]struct{}
}

// Start launches one training goroutine bound to the run. The
// returned channel emits exactly one Capture (or an error) when the
// duration elapses or ctx is cancelled.
func (e *Engine) Start(ctx context.Context, opts *RunOpts) (<-chan StartResult, error) {
	if opts == nil || opts.BridgeEndpoint == "" {
		return nil, errors.New("engine: empty BridgeEndpoint")
	}
	if opts.Duration <= 0 {
		return nil, errors.New("engine: non-positive Duration")
	}
	key := runKey(opts.RunNamespace, opts.RunName)

	e.mu.Lock()
	if _, exists := e.running[key]; exists {
		e.mu.Unlock()
		return nil, fmt.Errorf("training already running for %s", key)
	}
	runCtx, cancel := context.WithTimeout(ctx, opts.Duration)
	e.running[key] = cancel
	e.mu.Unlock()

	out := make(chan StartResult, 1)
	go func() {
		defer func() {
			e.mu.Lock()
			delete(e.running, key)
			e.mu.Unlock()
			cancel()
		}()
		capture, err := e.runCapture(runCtx, opts)
		out <- StartResult{Capture: capture, Err: err}
		close(out)
	}()
	return out, nil
}

// RunOpts carries the parameters one training pass needs.
type RunOpts struct {
	RunNamespace   string
	RunName        string
	BridgeEndpoint string
	BridgeToken    string

	// TargetPods is the list of namespace/name pairs the engine
	// subscribes to in parallel. Resolved by the reconciler from
	// Spec.TargetSelector + Spec.ReplicaRatio.
	TargetPods []NamespacedName

	// Duration bounds the training window.
	Duration time.Duration
}

// NamespacedName is a small local type so the engine doesn't pull in
// k8s.io/apimachinery just for this.
type NamespacedName struct {
	Namespace, Name string
}

// StartResult is what the engine emits to the reconciler when a
// training finishes (clean or error).
type StartResult struct {
	Capture *Capture
	Err     error
}

// runCapture dials the bridge, opens one StreamFileOpen per target
// Pod, and folds every observation into a per-pod path set + a
// global syscall set. The bridge proto exposes FileOpen explicitly,
// so v0.1.0 infers the syscall surface from the open() events
// (every captured Pod always invokes openat at minimum). A future
// bridge version with StreamSyscallEnter will replace this.
func (e *Engine) runCapture(ctx context.Context, opts *RunOpts) (*Capture, error) {
	conn, err := grpc.NewClient(opts.BridgeEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", opts.BridgeEndpoint, err)
	}
	defer func() { _ = conn.Close() }()

	client := bridgev1.NewTetragonBridgeClient(conn)

	capture := &Capture{
		Syscalls:   nil,
		PathsByPod: map[string]map[string]struct{}{},
	}
	syscallSet := map[string]struct{}{
		// Every container invokes these on boot (loader, runtime).
		// Seed the set so even a 0-event run produces a non-empty
		// profile that doesn't deny exec immediately on the next
		// container start.
		"openat":      {},
		"read":        {},
		"write":       {},
		"close":       {},
		"mmap":        {},
		"execve":      {},
		"brk":         {},
		"fstat":       {},
		"lseek":       {},
		"futex":       {},
		"sigprocmask": {},
		"sigreturn":   {},
	}
	pathMu := sync.Mutex{}

	streamCtx := ctx
	if opts.BridgeToken != "" {
		streamCtx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+opts.BridgeToken)
	}

	var wg sync.WaitGroup
	for _, pod := range opts.TargetPods {
		wg.Add(1)
		go func(p NamespacedName) {
			defer wg.Done()
			s, err := client.StreamFileOpen(streamCtx, &bridgev1.SubscribeRequest{
				SubscriberId: fmt.Sprintf("seccomp-gen-%s/%s", opts.RunNamespace, opts.RunName),
				TargetPod:    &bridgev1.PodRef{Namespace: p.Namespace, Name: p.Name},
			})
			if err != nil {
				return
			}
			for {
				ev, err := s.Recv()
				if errors.Is(err, io.EOF) || err != nil {
					return
				}
				key := p.Namespace + "/" + p.Name
				pathMu.Lock()
				if _, ok := capture.PathsByPod[key]; !ok {
					capture.PathsByPod[key] = map[string]struct{}{}
				}
				capture.PathsByPod[key][ev.GetPath()] = struct{}{}
				// Every FileOpen implies the openat syscall. Glob-y
				// path classification (e.g. dlopen → mmap) is a
				// follow-up; widen the seed set when the captured
				// paths suggest dynamic loading.
				if strings.HasSuffix(filepath.Base(ev.GetPath()), ".so") {
					syscallSet["mprotect"] = struct{}{}
				}
				pathMu.Unlock()
			}
		}(pod)
	}
	wg.Wait()

	capture.Syscalls = make([]string, 0, len(syscallSet))
	for s := range syscallSet {
		capture.Syscalls = append(capture.Syscalls, s)
	}
	sort.Strings(capture.Syscalls)
	return capture, nil
}
