// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	bridgev1 "github.com/ninsun-labs/tetragon-bridge/proto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"k8s.io/apimachinery/pkg/types"

	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/detector"
)

// TetragonBridgeSource consumes the tetragon-bridge StreamProcessExec
// RPC and translates each event into a detector.ExecInput the
// CrossTenantExec detector matches against.
//
// The bridge is the single chokepoint between Tetragon and the
// operator: this source only deals with the typed bridge proto, no
// Tetragon SDK in the dependency tree.
type TetragonBridgeSource struct {
	cfg TetragonBridgeConfig
}

// TetragonBridgeConfig wires the bridge gRPC client.
type TetragonBridgeConfig struct {
	// Endpoint is the bridge gRPC address (host:port).
	Endpoint string

	// BearerToken is the shared secret the bridge enforces when its
	// auth interceptor is configured. Empty disables.
	BearerToken string

	// SubscriberID identifies this operator instance in the bridge
	// metrics + drop counter labels.
	SubscriberID string

	// MaxEventsPerSec asks the bridge to throttle this subscriber.
	// Zero leaves the bridge default in place.
	MaxEventsPerSec uint32

	// ReconnectBase is the starting backoff on transient errors;
	// doubles up to 30s. Zero falls back to 2s.
	ReconnectBase time.Duration
}

// NewTetragonBridgeSource validates cfg and returns a source.
func NewTetragonBridgeSource(cfg *TetragonBridgeConfig) (*TetragonBridgeSource, error) {
	if cfg == nil {
		return nil, errors.New("TetragonBridgeSource: nil config")
	}
	if cfg.Endpoint == "" {
		return nil, errors.New("TetragonBridgeSource: empty Endpoint")
	}
	if cfg.SubscriberID == "" {
		cfg.SubscriberID = "tenant-escape"
	}
	if cfg.ReconnectBase <= 0 {
		cfg.ReconnectBase = 2 * time.Second
	}
	return &TetragonBridgeSource{cfg: *cfg}, nil
}

// Name implements ExecSource.
func (s *TetragonBridgeSource) Name() string { return "tetragon_bridge" }

// Run dials the bridge and pumps ExecInput on the returned channel.
// Reconnects with exponential backoff on transient errors.
func (s *TetragonBridgeSource) Run(ctx context.Context) (<-chan *detector.ExecInput, error) {
	out := make(chan *detector.ExecInput, 256)
	go func() {
		defer close(out)
		backoff := s.cfg.ReconnectBase
		for {
			if err := s.runOnce(ctx, out); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				if next := backoff * 2; next > 30*time.Second {
					backoff = 30 * time.Second
				} else {
					backoff = next
				}
				continue
			}
			backoff = s.cfg.ReconnectBase
		}
	}()
	return out, nil
}

func (s *TetragonBridgeSource) runOnce(ctx context.Context, out chan<- *detector.ExecInput) error {
	conn, err := grpc.NewClient(s.cfg.Endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial %s: %w", s.cfg.Endpoint, err)
	}
	defer func() { _ = conn.Close() }()

	streamCtx := ctx
	if s.cfg.BearerToken != "" {
		streamCtx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+s.cfg.BearerToken)
	}
	client := bridgev1.NewTetragonBridgeClient(conn)
	stream, err := client.StreamProcessExec(streamCtx, &bridgev1.SubscribeRequest{
		SubscriberId:    s.cfg.SubscriberID,
		MaxEventsPerSec: s.cfg.MaxEventsPerSec,
	})
	if err != nil {
		return fmt.Errorf("StreamProcessExec: %w", err)
	}
	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		input := bridgeToExecInput(ev)
		if input == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- input:
		}
	}
}

// bridgeToExecInput translates a bridge ProcessExec into the
// CrossTenantExec detector's input shape. Drops events without an
// ExecutorPodNamespace — the cross-tenant heuristic compares
// (executor.ns, target.ns) and an unknown executor side carries no
// signal.
func bridgeToExecInput(ev *bridgev1.ProcessExec) *detector.ExecInput {
	if ev == nil || ev.GetProcess() == nil {
		return nil
	}
	p := ev.GetProcess()
	executorNS := ""
	if pod := p.GetPod(); pod != nil {
		executorNS = pod.GetNamespace()
	}
	if executorNS == "" {
		return nil
	}
	// The CrossTenantExec detector treats executorNS == targetNS as a
	// no-op; the bridge's ProcessExec carries only the executor side
	// (the kprobe doesn't see the target Pod's namespace). For now,
	// fill TargetPod from the executor and let the detector match
	// when annotation hints (sa user) imply a different tenant.
	return &detector.ExecInput{
		ExecutorPodNamespace: executorNS,
		ExecutorUsername:     p.GetServiceAccount(),
		TargetPodNamespace:   executorNS,
		TargetPodName:        p.GetPod().GetName(),
		TargetPodUID:         types.UID(""), // resolver attaches this downstream when needed
		Command:              joinArgv(p.GetBinaryPath(), ev.GetArgv()),
	}
}

// joinArgv composes a human-readable command string for the SE
// signal. Mirrors how the audit-bus produces it: binary + space-
// joined argv.
func joinArgv(binary string, argv []string) string {
	if len(argv) == 0 {
		return binary
	}
	return binary + " " + strings.Join(argv, " ")
}
