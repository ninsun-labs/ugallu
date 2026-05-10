// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package serverv1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"k8s.io/apimachinery/pkg/types"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	resolverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/clientv1"
)

// Server implements the resolver gRPC service backed by a Cache.
//
// Phase 2 wires ResolveByCgroupID via the cgroup-ID index populated
// by the filesystem walker, and ResolveByPID via /proc/<pid>/cgroup.
// Watch (Phase 4) is still deferred. Phase 3 will replace the cold
// walk with an eBPF tracer for live updates.
type Server struct {
	resolverv1.UnimplementedResolverServer

	Cache *Cache
	Log   *slog.Logger

	// SysFsCgroupRoot overrides the cgroup mountpoint
	// (DefaultSysFsCgroup when empty).
	SysFsCgroupRoot string

	// ProcRoot overrides /proc (DefaultProcRoot when empty).
	ProcRoot string
}

// NewServer wires a Cache to a slog logger. Either argument may be
// nil; nil Log produces a discard logger.
func NewServer(c *Cache, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}
	return &Server{Cache: c, Log: log}
}

// --- Phase 1 RPCs ---------------------------------------------------

// ResolveByPodIP resolves a Pod IP (v4 or v6) via the secondary IP index.
func (s *Server) ResolveByPodIP(_ context.Context, req *resolverv1.PodIPRequest) (*resolverv1.SubjectResponse, error) {
	start := time.Now()
	snap, ok := s.Cache.PodByIP(req.GetIp())
	if !ok {
		recordResolve(methodPodIP, outcomeMiss, start)
		return unresolved("podIP not in cache"), nil
	}
	return s.responseFromSnapshot(snap, methodPodIP, start), nil
}

// ResolveByPodUID resolves a Pod by its primary UID index.
func (s *Server) ResolveByPodUID(_ context.Context, req *resolverv1.PodUIDRequest) (*resolverv1.SubjectResponse, error) {
	start := time.Now()
	snap, ok := s.Cache.PodByUID(types.UID(req.GetUid()))
	if !ok {
		recordResolve(methodPodUID, outcomeMiss, start)
		return unresolved("podUID not in cache"), nil
	}
	return s.responseFromSnapshot(snap, methodPodUID, start), nil
}

// ResolveByContainerID resolves a CRI container ID to its owning Pod.
func (s *Server) ResolveByContainerID(_ context.Context, req *resolverv1.ContainerIDRequest) (*resolverv1.SubjectResponse, error) {
	start := time.Now()
	snap, ok := s.Cache.PodByContainerID(req.GetContainerId())
	if !ok {
		recordResolve(methodContainerID, outcomeMiss, start)
		return unresolved("containerID not in cache"), nil
	}
	return s.responseFromSnapshot(snap, methodContainerID, start), nil
}

// ResolveBySAUsername parses a Kubernetes auth username and resolves
// the matching SA / Node / external subject.
func (s *Server) ResolveBySAUsername(_ context.Context, req *resolverv1.SAUsernameRequest) (*resolverv1.SubjectResponse, error) {
	start := time.Now()
	lookup := ResolveSAUsername(s.Cache, req.GetUsername())
	if lookup.Subject == nil {
		recordResolve(methodSAUsername, outcomeError, start)
		return unresolved("ResolveBySAUsername: lister error"), nil
	}
	resp, err := responseFromSubject(lookup.Subject)
	if err != nil {
		recordResolve(methodSAUsername, outcomeError, start)
		return unresolved("ResolveBySAUsername: marshal failed: " + err.Error()), nil
	}
	if lookup.Partial {
		resp.Partial = true
		recordResolve(methodSAUsername, outcomePartial, start)
	} else {
		recordResolve(methodSAUsername, outcomeHit, start)
	}
	return resp, nil
}

// --- Phase 2/3 placeholders -----------------------------------------

// ResolveByCgroupID resolves a kernel cgroup ID via the cgroup index
// populated by the cold-walker (and, in Phase 3, by the live eBPF
// tracer).
func (s *Server) ResolveByCgroupID(_ context.Context, req *resolverv1.CgroupIDRequest) (*resolverv1.SubjectResponse, error) {
	start := time.Now()
	id := req.GetCgroupId()
	if id == 0 {
		recordResolve(methodCgroupID, outcomeMiss, start)
		return unresolved("ResolveByCgroupID: zero id"), nil
	}
	snap, ok := s.Cache.PodByCgroupID(id)
	if !ok {
		recordResolve(methodCgroupID, outcomeMiss, start)
		return unresolved("ResolveByCgroupID: cgroup id not in index"), nil
	}
	return s.responseFromSnapshot(snap, methodCgroupID, start), nil
}

// ResolveByPID maps a host PID to a Subject by reading /proc/<pid>/cgroup
// and resolving the unified cgroup either via the cgroup-ID index or
// by parsing the path directly into a Pod UID (path-based fallback).
func (s *Server) ResolveByPID(_ context.Context, req *resolverv1.PIDRequest) (*resolverv1.SubjectResponse, error) {
	start := time.Now()
	pid := req.GetPid()
	if pid <= 0 {
		recordResolve(methodPID, outcomeMiss, start)
		return unresolved("ResolveByPID: non-positive pid"), nil
	}

	// Fast path: resolve via cgroup-ID index when /sys/fs/cgroup is
	// available. This is the production path on Linux DaemonSets.
	if cgroupID, _, err := CgroupIDForPID(s.ProcRoot, s.SysFsCgroupRoot, pid); err == nil {
		if snap, ok := s.Cache.PodByCgroupID(cgroupID); ok {
			return s.responseFromSnapshot(snap, methodPID, start), nil
		}
	}

	// Fallback: parse the cgroup path directly to extract the Pod UID
	// and look it up in the primary index. This works even for pods
	// created after the cold-walk because the path itself encodes the
	// UID — at the cost of not exposing the cgroup ID to the caller.
	info, err := PodInfoForPID(s.ProcRoot, pid)
	if err != nil {
		recordResolve(methodPID, outcomeMiss, start)
		return unresolved("ResolveByPID: " + err.Error()), nil
	}
	if snap, ok := s.Cache.PodByUID(types.UID(info.PodUID)); ok {
		return s.responseFromSnapshot(snap, methodPID, start), nil
	}
	recordResolve(methodPID, outcomeMiss, start)
	return unresolved("ResolveByPID: pod uid " + info.PodUID + " not in cache"), nil
}

// Watch streams SubjectChange events to the caller. The cache
// publishes ADDED/UPDATED/DELETED/TOMBSTONE_GC events as Pod
// snapshots mutate; the server forwards them through the gRPC
// stream until the client cancels or the subscription overflows.
//
// Filter is best-effort — empty Kind / Namespace match anything;
// non-empty values are checked at the cache fan-out before the event
// reaches the stream.
func (s *Server) Watch(req *resolverv1.WatchRequest, stream resolverv1.Resolver_WatchServer) error {
	filter := Filter{Kind: req.GetKind(), Namespace: req.GetNamespace()}
	sub := s.Cache.Subscribe(filter, DefaultSubscriberBuffer)
	defer sub.Close()

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ch, ok := <-sub.Events():
			if !ok {
				if sub.Overflowed() {
					return fmt.Errorf("watch buffer overflow (consumer too slow)")
				}
				return nil
			}
			msg, err := s.changeToProto(ch)
			if err != nil {
				s.Log.Warn("watch: encode change failed", "err", err)
				continue
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

// changeToProto translates a cache Change into a wire SubjectChange.
// Snapshots are encoded through the same Tier-1 marshaller used by
// the unary Resolve* RPCs so consumers get a uniform payload shape.
func (s *Server) changeToProto(ch Change) (*resolverv1.SubjectChange, error) {
	if ch.Snapshot == nil || ch.Snapshot.Pod == nil {
		return &resolverv1.SubjectChange{Type: changeTypeToProto(ch.Type)}, nil
	}
	subj := BuildPodSubject(ch.Snapshot.Pod)
	if ch.Snapshot.Tombstone || ch.Type == ChangeDeleted || ch.Type == ChangeTombstoneGC {
		subj.Tombstone = true
	}
	resp, err := responseFromSubject(subj)
	if err != nil {
		return nil, err
	}
	return &resolverv1.SubjectChange{
		Type:    changeTypeToProto(ch.Type),
		Subject: resp,
	}, nil
}

// changeTypeToProto maps the local enum onto the proto's enum.
func changeTypeToProto(t ChangeType) resolverv1.SubjectChange_ChangeType {
	switch t {
	case ChangeAdded:
		return resolverv1.SubjectChange_ADDED
	case ChangeUpdated:
		return resolverv1.SubjectChange_UPDATED
	case ChangeDeleted:
		return resolverv1.SubjectChange_DELETED
	case ChangeTombstoneGC:
		return resolverv1.SubjectChange_TOMBSTONE_GC
	default:
		return resolverv1.SubjectChange_UNKNOWN
	}
}

// --- helpers --------------------------------------------------------

// responseFromSnapshot encodes the Tier-1 PodSubject from snap into
// a SubjectResponse, applying the tombstone marker when present and
// recording the appropriate metric outcome.
func (s *Server) responseFromSnapshot(snap *PodSnapshot, method string, start time.Time) *resolverv1.SubjectResponse {
	if snap == nil || snap.Pod == nil {
		recordResolve(method, outcomeMiss, start)
		return unresolved("snapshot empty")
	}
	subj := BuildPodSubject(snap.Pod)
	if snap.Tombstone {
		subj.Tombstone = true
	}
	resp, err := responseFromSubject(subj)
	if err != nil {
		recordResolve(method, outcomeError, start)
		return unresolved("marshal Tier-1: " + err.Error())
	}
	if snap.Tombstone {
		recordResolve(method, outcomeTombstone, start)
	} else {
		recordResolve(method, outcomeHit, start)
	}
	return resp
}

// responseFromSubject populates a SubjectResponse from a Tier-1 Subject
// (common identity fields + JSON-encoded tier1_json blob).
func responseFromSubject(subj *securityv1alpha1.SubjectTier1) (*resolverv1.SubjectResponse, error) {
	if subj == nil {
		return nil, fmt.Errorf("nil subject")
	}
	raw, err := json.Marshal(subj)
	if err != nil {
		return nil, err
	}
	return &resolverv1.SubjectResponse{
		Kind:            string(subj.Kind),
		ApiVersion:      subj.APIVersion,
		Name:            subj.Name,
		Namespace:       subj.Namespace,
		Uid:             string(subj.UID),
		ResourceVersion: subj.ResourceVersion,
		Labels:          subj.Labels,
		Tier1Json:       raw,
		Partial:         subj.Partial,
		Tombstone:       subj.Tombstone,
		Unresolved:      subj.Unresolved,
	}, nil
}

func unresolved(diag string) *resolverv1.SubjectResponse {
	return &resolverv1.SubjectResponse{Unresolved: true, Diagnostic: diag}
}

// discardWriter is an io.Writer that discards everything; used as a
// log target when the caller passes nil.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// Compile-time assertion that Server satisfies the gRPC interface.
var _ resolverv1.ResolverServer = (*Server)(nil)
