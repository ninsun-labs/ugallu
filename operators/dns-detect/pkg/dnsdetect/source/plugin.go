// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	dnseventv1 "github.com/ninsun-labs/coredns-ugallu/proto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"k8s.io/apimachinery/pkg/types"

	resolverv1 "github.com/ninsun-labs/ugallu/sdk/pkg/resolver/clientv1"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

// DefaultEnrichTimeout caps a single resolver round-trip so a slow
// resolver never stalls the DNS event stream. Sized for the UDS-fast
// path.
const DefaultEnrichTimeout = 100 * time.Millisecond

// Resolver is the subset of the resolver SDK stub the source needs to
// hydrate Pod attribution on inbound events. CachedClient satisfies it.
type Resolver interface {
	ResolveByCgroupID(ctx context.Context, in *resolverv1.CgroupIDRequest, opts ...grpc.CallOption) (*resolverv1.SubjectResponse, error)
	ResolveByPodIP(ctx context.Context, in *resolverv1.PodIPRequest, opts ...grpc.CallOption) (*resolverv1.SubjectResponse, error)
}

// CoreDNSPluginConfig wires the gRPC stream client.
type CoreDNSPluginConfig struct {
	GRPCEndpoint    string        // host:port
	BearerToken     string        // shared-secret auth
	NodeName        string        // SubscribeRequest.subscriber_id discriminator
	MaxEventsPerSec uint32        // server-side rate limit
	ReconnectBase   time.Duration // base for exponential backoff

	// Resolver hydrates Pod / SubjectUID per event using the SDK
	// resolver. Nil disables enrichment; detectors fall back to the
	// SrcIP synthetic key.
	Resolver Resolver

	// EnrichTimeout caps each resolver call. Zero falls back to
	// DefaultEnrichTimeout.
	EnrichTimeout time.Duration
}

// CoreDNSPluginSource is the primary backend. Dials
// the coredns-ugallu plugin's UgalluDNSStream.Subscribe RPC,
// reconnects with exponential backoff on transient errors, and
// translates protobuf DNSEvent into the source-agnostic
// dnsevent.DNSEvent shape consumed by the dispatcher.
type CoreDNSPluginSource struct {
	cfg CoreDNSPluginConfig
}

// NewCoreDNSPluginSource validates cfg and returns a source.
func NewCoreDNSPluginSource(cfg *CoreDNSPluginConfig) (*CoreDNSPluginSource, error) {
	if cfg == nil {
		return nil, errors.New("CoreDNSPluginSource: nil config")
	}
	if cfg.GRPCEndpoint == "" {
		return nil, errors.New("CoreDNSPluginSource: empty GRPCEndpoint")
	}
	if cfg.ReconnectBase <= 0 {
		cfg.ReconnectBase = 2 * time.Second
	}
	if cfg.NodeName == "" {
		cfg.NodeName = "dns-detect-unknown"
	}
	if cfg.EnrichTimeout <= 0 {
		cfg.EnrichTimeout = DefaultEnrichTimeout
	}
	return &CoreDNSPluginSource{cfg: *cfg}, nil
}

// Name implements Source.
func (s *CoreDNSPluginSource) Name() string { return string(dnsevent.SourceCoreDNSPlugin) }

// Run dials the plugin gRPC and forwards events on the returned
// channel. Reconnects with exponential backoff on transient errors.
// The channel closes when ctx is cancelled.
func (s *CoreDNSPluginSource) Run(ctx context.Context) (<-chan *dnsevent.DNSEvent, error) {
	out := make(chan *dnsevent.DNSEvent, 256)
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
			// Stream closed cleanly (server side). Reset backoff and
			// re-dial.
			backoff = s.cfg.ReconnectBase
		}
	}()
	return out, nil
}

// runOnce performs a single dial + Subscribe lifecycle. Returns nil
// on graceful EOF, error otherwise.
func (s *CoreDNSPluginSource) runOnce(ctx context.Context, out chan<- *dnsevent.DNSEvent) error {
	conn, err := grpc.NewClient(s.cfg.GRPCEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial %s: %w", s.cfg.GRPCEndpoint, err)
	}
	defer func() { _ = conn.Close() }()

	client := dnseventv1.NewUgalluDNSStreamClient(conn)
	streamCtx := ctx
	if s.cfg.BearerToken != "" {
		streamCtx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+s.cfg.BearerToken)
	}
	stream, err := client.Subscribe(streamCtx, &dnseventv1.SubscribeRequest{
		SubscriberId:    s.cfg.NodeName,
		MaxEventsPerSec: s.cfg.MaxEventsPerSec,
	})
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- s.toEnriched(ctx, ev):
		}
	}
}

// toEnriched runs the wire→internal translation and (when configured)
// the resolver lookup that fills Pod + SubjectUID. Errors are swallowed
// - a resolver outage degrades detectors to the SrcIP fallback path,
// it must not stop the DNS stream.
func (s *CoreDNSPluginSource) toEnriched(ctx context.Context, ev *dnseventv1.DNSEvent) *dnsevent.DNSEvent {
	internal := pbToInternal(ev)
	if internal == nil || s.cfg.Resolver == nil {
		return internal
	}
	s.enrich(ctx, internal)
	return internal
}

// enrich queries the resolver with cgroup-id (UDS-fast path) first,
// then falls back to PodIP. The first successful hit wins. Both calls
// are bounded by EnrichTimeout so a slow resolver never blocks the
// stream - on a miss the detector chain still runs and the SrcIP
// fallback in subjectFromEvent keeps state-keying coherent.
func (s *CoreDNSPluginSource) enrich(parent context.Context, ev *dnsevent.DNSEvent) {
	if ev.SrcCgroup != 0 {
		ctx, cancel := context.WithTimeout(parent, s.cfg.EnrichTimeout)
		resp, err := s.cfg.Resolver.ResolveByCgroupID(ctx, &resolverv1.CgroupIDRequest{CgroupId: ev.SrcCgroup})
		cancel()
		if err == nil && applySubjectResponse(ev, resp) {
			return
		}
	}
	if ev.SrcIP != nil {
		ctx, cancel := context.WithTimeout(parent, s.cfg.EnrichTimeout)
		resp, err := s.cfg.Resolver.ResolveByPodIP(ctx, &resolverv1.PodIPRequest{Ip: ev.SrcIP.String()})
		cancel()
		if err == nil {
			_ = applySubjectResponse(ev, resp)
		}
	}
}

// applySubjectResponse copies a non-empty resolver response into the
// event. Returns true when the event was populated (a real Pod hit).
// Unresolved/Tombstone responses are intentionally ignored so the
// caller can try the next lookup path.
func applySubjectResponse(ev *dnsevent.DNSEvent, resp *resolverv1.SubjectResponse) bool {
	if resp == nil || resp.GetUnresolved() || resp.GetTombstone() {
		return false
	}
	if resp.GetNamespace() == "" || resp.GetName() == "" {
		return false
	}
	ev.Pod = types.NamespacedName{Namespace: resp.GetNamespace(), Name: resp.GetName()}
	if uid := resp.GetUid(); uid != "" {
		ev.SubjectUID = types.UID(uid)
	}
	return true
}

// pbToInternal translates the wire protobuf shape to the
// source-agnostic dnsevent.DNSEvent the dispatcher consumes. Resolver
// enrichment is layered on top by toEnriched.
func pbToInternal(ev *dnseventv1.DNSEvent) *dnsevent.DNSEvent {
	if ev == nil {
		return nil
	}
	out := &dnsevent.DNSEvent{
		Source:     dnsevent.SourceCoreDNSPlugin,
		NodeName:   ev.GetNodeName(),
		QName:      strings.ToLower(ev.GetQname()),
		QType:      ev.GetQtype(),
		QClass:     ev.GetQclass(),
		DstPort:    uint16(ev.GetDstPort()),     //nolint:gosec // protobuf field is uint32 but DNS port range fits uint16; validated at upstream send
		RCODE:      uint8(ev.GetResponseCode()), //nolint:gosec // RFC 1035 RCODE is 4 bits; uint32 → uint8 is safe
		ResponseRR: ev.GetResponseRr(),
		PayloadLen: int(ev.GetPayloadLength()),
		SrcCgroup:  ev.GetSrcCgroupId(),
	}
	if ev.GetTimestamp() != nil {
		out.Timestamp = ev.GetTimestamp().AsTime()
	}
	if ev.GetLatency() != nil {
		out.Latency = ev.GetLatency().AsDuration()
	}
	if b := ev.GetSrcIp(); len(b) > 0 {
		out.SrcIP = net.IP(b)
	}
	if b := ev.GetDstIp(); len(b) > 0 {
		out.DstIP = net.IP(b)
	}
	return out
}
