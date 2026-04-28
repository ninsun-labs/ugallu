// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"errors"
	"time"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

// CoreDNSPluginConfig wires the gRPC stream client.
type CoreDNSPluginConfig struct {
	GRPCEndpoint string        // host:port
	BearerToken  string        // shared-secret auth (Wave 3 Sprint 3); mTLS lands later
	NodeName     string        // SubscribeRequest subscriber_id discriminator
	MaxEventsPerSec uint32     // server-side rate limit
	ReconnectBase time.Duration // base for exponential backoff
}

// CoreDNSPluginSource is the primary backend (design 21 §D2.1). Once
// the coredns-ugallu plugin v0.1.0 ships, this source dials the
// Subscribe RPC and translates UgalluDNSStream.DNSEvent protobuf
// messages into dnsevent.DNSEvent.
//
// Wave 3 Sprint 3: stub returning an empty closed channel. The full
// gRPC client lands once the proto schema is published in
// `ninsun-labs/coredns-ugallu` v0.1.0 — same sprint, separate commit
// in that repo.
type CoreDNSPluginSource struct {
	cfg CoreDNSPluginConfig
}

// NewCoreDNSPluginSource validates cfg and returns a source.
func NewCoreDNSPluginSource(cfg CoreDNSPluginConfig) (*CoreDNSPluginSource, error) {
	if cfg.GRPCEndpoint == "" {
		return nil, errors.New("CoreDNSPluginSource: empty GRPCEndpoint")
	}
	if cfg.ReconnectBase <= 0 {
		cfg.ReconnectBase = 2 * time.Second
	}
	return &CoreDNSPluginSource{cfg: cfg}, nil
}

// Name implements Source.
func (s *CoreDNSPluginSource) Name() string { return string(dnsevent.SourceCoreDNSPlugin) }

// Run dials the plugin gRPC. Stub for Sprint 3: returns immediately
// with a closed channel so the dispatcher knows the source is
// "silent" and emits DNSSourceSilent. The reconnect loop + protobuf
// translation lands in the next sprint pass once coredns-ugallu has
// shipped its v0.1.0 image.
func (s *CoreDNSPluginSource) Run(_ context.Context) (<-chan *dnsevent.DNSEvent, error) {
	out := make(chan *dnsevent.DNSEvent)
	close(out)
	// TODO(coredns-ugallu v0.1.0): dial cfg.GRPCEndpoint, send
	// SubscribeRequest{subscriber_id: NodeName, max_events_per_sec:
	// MaxEventsPerSec}, translate stream → out.
	return out, nil
}
