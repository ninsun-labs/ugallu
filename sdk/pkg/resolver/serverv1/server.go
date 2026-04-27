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
// ResolveByCgroupID + ResolveByPID return Unresolved=true in this
// phase; the eBPF tracker (Phase 3) and /proc walker (Phase 2) are
// deferred to follow-up commits. Watch is also deferred (Phase 4).
type Server struct {
	resolverv1.UnimplementedResolverServer

	Cache *Cache
	Log   *slog.Logger
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

// ResolveBySAUsername parses a Kubernetes auth username (design 03 R4)
// and resolves the matching SA / Node / external subject.
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

// ResolveByCgroupID is a Phase 3 placeholder: requires the eBPF
// cgroup tracker, currently returns Unresolved.
func (s *Server) ResolveByCgroupID(_ context.Context, _ *resolverv1.CgroupIDRequest) (*resolverv1.SubjectResponse, error) {
	recordResolve(methodCgroupID, outcomeUnresolved, time.Now())
	return unresolved("ResolveByCgroupID: eBPF tracker pending (Phase 3)"), nil
}

// ResolveByPID is a Phase 2 placeholder: requires the /proc walker,
// currently returns Unresolved.
func (s *Server) ResolveByPID(_ context.Context, _ *resolverv1.PIDRequest) (*resolverv1.SubjectResponse, error) {
	recordResolve(methodPID, outcomeUnresolved, time.Now())
	return unresolved("ResolveByPID: /proc walker pending (Phase 2)"), nil
}

// Watch is a Phase 4 placeholder: streaming SubjectChange events
// lands once consumers need it.
func (s *Server) Watch(_ *resolverv1.WatchRequest, _ resolverv1.Resolver_WatchServer) error {
	// Streaming Watch is Phase 4. Closing immediately tells callers
	// to fall back to periodic re-resolves.
	return nil
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

// Compile-time assertion that we satisfy the gRPC interface.
var _ resolverv1.ResolverServer = (*Server)(nil)
