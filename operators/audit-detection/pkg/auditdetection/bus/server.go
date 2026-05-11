// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package bus implements the AuditDetection event bus. It is the
// server side of the auditstreamv1.AuditStream Subscribe RPC: every
// AuditEvent the sigma engine consumes is published, fanned out to
// the connected subscribers per their AuditDetectionConsumer filter
// and MaxEventsPerSec cap, and pushed onto each subscriber's bounded
// drop-oldest ring buffer so a slow consumer never stalls the engine.
//
// Subscribers authenticate with a bearer token (when configured); a
// future commit swaps in mTLS without changing the wire shape.
package bus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	ctrl "sigs.k8s.io/controller-runtime"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
	auditstreamv1 "github.com/ninsun-labs/ugallu/sdk/pkg/auditstream/clientv1"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection"
)

// DefaultRingBuffer is the per-subscriber backlog when the consumer
// declaration omits an explicit cap. Drop-oldest semantics - a full
// buffer pops the head before pushing the tail.
const DefaultRingBuffer = 512

// Config wires the bus server.
type Config struct {
	// ListenAddr is the gRPC bind address (e.g. ":8444").
	ListenAddr string
	// BearerToken is the shared secret subscribers authenticate
	// with via gRPC metadata "authorization: Bearer <tok>". Empty =
	// unauthenticated (lab-only).
	BearerToken string
	// Consumers is the consumer allowlist + per-consumer filter
	// declared in AuditDetectionConfig.spec.consumers.
	Consumers []securityv1alpha1.AuditDetectionConsumer
	// RingBuffer overrides DefaultRingBuffer.
	RingBuffer int
}

// Server fan-outs AuditEvents to subscribed consumers.
type Server struct {
	auditstreamv1.UnimplementedAuditStreamServer

	cfg     Config
	mu      sync.RWMutex
	subs    map[string]*subscriber // keyed by consumerName + remote addr (one entry per stream)
	pubMu   sync.Mutex             // serialises Publish to keep ordering predictable per subscriber
	pubSeq  uint64
	consume map[string]securityv1alpha1.AuditDetectionConsumer // consumerName → declaration
}

type subscriber struct {
	id       string
	consumer securityv1alpha1.AuditDetectionConsumer
	limiter  *rate.Limiter
	ch       chan *auditstreamv1.AuditEvent
	dropped  atomic.Uint64
}

// New validates cfg and returns a server.
func New(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("bus: empty ListenAddr")
	}
	if cfg.RingBuffer <= 0 {
		cfg.RingBuffer = DefaultRingBuffer
	}
	consume := map[string]securityv1alpha1.AuditDetectionConsumer{}
	for _, c := range cfg.Consumers {
		if c.Name == "" {
			continue
		}
		consume[c.Name] = c
	}
	return &Server{
		cfg:     cfg,
		subs:    map[string]*subscriber{},
		consume: consume,
	}, nil
}

// Start binds the listener and serves until ctx is cancelled. Returns
// nil on graceful shutdown.
func (s *Server) Start(ctx context.Context) error {
	log := ctrl.Log.WithName("audit-bus")
	log.Info("bus listening", "addr", s.cfg.ListenAddr, "consumers", len(s.cfg.Consumers))
	lis, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	gs := grpc.NewServer()
	auditstreamv1.RegisterAuditStreamServer(gs, s)

	go func() {
		<-ctx.Done()
		gs.GracefulStop()
	}()
	if err := gs.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("grpc serve: %w", err)
	}
	return nil
}

// ListenAddr returns the configured gRPC bind address.
func (s *Server) ListenAddr() string { return s.cfg.ListenAddr }

// ConsumersConnected returns the live subscriber count. Used by the
// AuditDetectionConfig status reconciler.
func (s *Server) ConsumersConnected() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subs)
}

// Subscribe is the gRPC entry point.
func (s *Server) Subscribe(req *auditstreamv1.SubscribeRequest, stream grpc.ServerStreamingServer[auditstreamv1.AuditEvent]) error {
	if err := s.authenticate(stream.Context()); err != nil {
		return err
	}
	name := req.GetConsumerName()
	if name == "" {
		return status.Error(codes.InvalidArgument, "consumer_name is required")
	}
	consumer, ok := s.consume[name]
	if !ok {
		return status.Errorf(codes.PermissionDenied, "consumer %q not declared in AuditDetectionConfig", name)
	}
	ctrl.Log.WithName("audit-bus").Info("subscriber connected", "consumer", name)

	sub := &subscriber{
		id:       fmt.Sprintf("%s/%d", name, time.Now().UnixNano()),
		consumer: consumer,
		ch:       make(chan *auditstreamv1.AuditEvent, s.cfg.RingBuffer),
	}
	if r := consumer.MaxEventsPerSec; r > 0 {
		// #nosec G115 - rate is uint32; rate.Limit (float64) covers it.
		sub.limiter = rate.NewLimiter(rate.Limit(float64(r)), int(r))
	}

	s.register(sub)
	defer s.unregister(sub)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev := <-sub.ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

// Publish implements engine.Publisher: fan out one AuditEvent to
// every connected subscriber that passes its declared filter +
// rate-limit. Drop-oldest on full buffer.
func (s *Server) Publish(ev *auditdetection.AuditEvent) {
	if ev == nil {
		return
	}
	wire := toWireEvent(ev)
	s.pubMu.Lock()
	defer s.pubMu.Unlock()
	s.pubSeq++

	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sub := range s.subs {
		if !filterMatch(&sub.consumer.Filter, ev) {
			continue
		}
		if sub.limiter != nil && !sub.limiter.Allow() {
			sub.dropped.Add(1)
			continue
		}
		select {
		case sub.ch <- wire:
		default:
			// Buffer full: pop head, push tail (drop oldest).
			select {
			case <-sub.ch:
			default:
			}
			select {
			case sub.ch <- wire:
			default:
			}
			sub.dropped.Add(1)
		}
	}
}

func (s *Server) register(sub *subscriber) {
	s.mu.Lock()
	s.subs[sub.id] = sub
	s.mu.Unlock()
}

func (s *Server) unregister(sub *subscriber) {
	s.mu.Lock()
	delete(s.subs, sub.id)
	s.mu.Unlock()
}

func (s *Server) authenticate(ctx context.Context) error {
	if s.cfg.BearerToken == "" {
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	auth := md.Get("authorization")
	if len(auth) == 0 {
		return status.Error(codes.Unauthenticated, "missing authorization header")
	}
	const prefix = "Bearer "
	v := auth[0]
	if len(v) <= len(prefix) || v[:len(prefix)] != prefix {
		return status.Error(codes.Unauthenticated, "authorization header must start with Bearer")
	}
	if v[len(prefix):] != s.cfg.BearerToken {
		return status.Error(codes.Unauthenticated, "invalid bearer token")
	}
	return nil
}

// filterMatch evaluates the consumer-declared filter against a
// freshly-consumed AuditEvent. Empty filter = match-all.
func filterMatch(f *securityv1alpha1.AuditDetectionConsumerFilter, ev *auditdetection.AuditEvent) bool {
	if f == nil {
		return true
	}
	if f.ObjectRefHasNamespace {
		if ev.ObjectRef == nil || ev.ObjectRef.Namespace == "" {
			return false
		}
	}
	if len(f.VerbAllowlist) > 0 {
		ok := false
		for _, v := range f.VerbAllowlist {
			if v == ev.Verb {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// toWireEvent translates the engine-side AuditEvent into the protobuf
// shape the auditstream gRPC contract carries.
func toWireEvent(ev *auditdetection.AuditEvent) *auditstreamv1.AuditEvent {
	out := &auditstreamv1.AuditEvent{
		AuditId:   ev.AuditID,
		Stage:     ev.Stage,
		Verb:      ev.Verb,
		SourceIps: ev.SourceIPs,
		UserAgent: ev.UserAgent,
		User:      toWireUser(&ev.User),
		ObjectRef: toWireObjectRef(ev.ObjectRef),
		Timestamp: pickTimestamp(ev),
	}
	if ev.ImpersonatedUser != nil {
		out.ImpersonatedUser = toWireUser(ev.ImpersonatedUser)
	}
	if ev.ResponseStatus != nil {
		out.ResponseStatusCode = uint32(ev.ResponseStatus.Code) //nolint:gosec // HTTP status code, fits in uint32
	}
	// Forward RequestObject / ResponseObject as JSON bytes so
	// downstream consumers (tenant-escape HostPathOverlap +
	// NetworkPolicy detectors, honeypot Misplaced detector) can
	// peek inside Pod / NetworkPolicy specs. Size guard pending.
	if len(ev.RequestObject) > 0 {
		if b, err := json.Marshal(ev.RequestObject); err == nil {
			out.RequestObject = b
		}
	}
	if len(ev.ResponseObject) > 0 {
		if b, err := json.Marshal(ev.ResponseObject); err == nil {
			out.ResponseObject = b
		}
	}
	return out
}

func toWireUser(u *auditdetection.UserInfo) *auditstreamv1.AuditUser {
	if u == nil || (u.Username == "" && len(u.Groups) == 0) {
		return nil
	}
	return &auditstreamv1.AuditUser{
		Username: u.Username,
		Groups:   u.Groups,
	}
}

func toWireObjectRef(ref *auditdetection.ObjectReference) *auditstreamv1.ObjectReference {
	if ref == nil {
		return nil
	}
	return &auditstreamv1.ObjectReference{
		ApiGroup:    ref.APIGroup,
		ApiVersion:  ref.APIVersion,
		Resource:    ref.Resource,
		Subresource: ref.Subresource,
		Namespace:   ref.Namespace,
		Name:        ref.Name,
		Uid:         ref.UID,
	}
}

func pickTimestamp(ev *auditdetection.AuditEvent) *timestamppb.Timestamp {
	if !ev.StageTimestamp.IsZero() {
		return timestamppb.New(ev.StageTimestamp)
	}
	if !ev.RequestReceivedTimestamp.IsZero() {
		return timestamppb.New(ev.RequestReceivedTimestamp)
	}
	return timestamppb.New(time.Now())
}
