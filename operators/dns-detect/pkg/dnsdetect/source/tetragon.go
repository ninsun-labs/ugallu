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

	bridgev1 "github.com/ninsun-labs/tetragon-bridge/proto/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"k8s.io/apimachinery/pkg/types"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

// TetragonKprobeSource is the fallback backend: it subscribes to the
// tetragon-bridge StreamDNSQuery RPC and translates each event into
// the source-agnostic dnsevent shape.
//
// Limitations carried over from the kprobe data path:
//   - PayloadLength is not available (kprobe doesn't see the answer
//     section), so the exfiltration detector falls back to qname
//     length only.
//   - ResponseRR is empty.
//   - Latency is zero - the kprobe fires on the request, not the
//     matched response.
//
// Detectors that need those fields emit `Class=Anomaly
// type=DNSDetectorDegraded` (one-shot) and skip evaluation.
type TetragonKprobeSource struct {
	cfg TetragonKprobeConfig
}

// TetragonKprobeConfig wires the bridge gRPC client.
type TetragonKprobeConfig struct {
	// Endpoint is the bridge gRPC address (host:port).
	Endpoint string

	// BearerToken is the shared secret the bridge enforces when its
	// auth interceptor is configured. Empty disables.
	BearerToken string

	// SubscriberID identifies this operator instance in the bridge
	// metrics / drop counter labels.
	SubscriberID string

	// MaxEventsPerSec asks the bridge to throttle this subscriber.
	// Zero leaves the bridge default.
	MaxEventsPerSec uint32

	// ReconnectBase is the starting backoff on transient errors;
	// doubles up to 30s. Zero falls back to 2s.
	ReconnectBase time.Duration
}

// NewTetragonKprobeSource validates cfg and returns a source.
func NewTetragonKprobeSource(cfg *TetragonKprobeConfig) (*TetragonKprobeSource, error) {
	if cfg == nil {
		return nil, errors.New("TetragonKprobeSource: nil config")
	}
	if cfg.Endpoint == "" {
		return nil, errors.New("TetragonKprobeSource: empty Endpoint")
	}
	if cfg.SubscriberID == "" {
		cfg.SubscriberID = "dns-detect"
	}
	if cfg.ReconnectBase <= 0 {
		cfg.ReconnectBase = 2 * time.Second
	}
	return &TetragonKprobeSource{cfg: *cfg}, nil
}

// Name implements Source.
func (s *TetragonKprobeSource) Name() string { return string(dnsevent.SourceTetragonKprobe) }

// Run dials the bridge and fans events into the returned channel.
// Reconnects on transient errors with exponential backoff.
func (s *TetragonKprobeSource) Run(ctx context.Context) (<-chan *dnsevent.DNSEvent, error) {
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
			backoff = s.cfg.ReconnectBase
		}
	}()
	return out, nil
}

func (s *TetragonKprobeSource) runOnce(ctx context.Context, out chan<- *dnsevent.DNSEvent) error {
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
	stream, err := client.StreamDNSQuery(streamCtx, &bridgev1.SubscribeRequest{
		SubscriberId:    s.cfg.SubscriberID,
		MaxEventsPerSec: s.cfg.MaxEventsPerSec,
	})
	if err != nil {
		return fmt.Errorf("StreamDNSQuery: %w", err)
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
		case out <- bridgeToInternal(ev):
		}
	}
}

// bridgeToInternal translates the bridge DNSQuery into the
// dispatcher-facing dnsevent. Pod attribution comes straight from
// the bridge - no second resolver hop is needed.
func bridgeToInternal(ev *bridgev1.DNSQuery) *dnsevent.DNSEvent {
	if ev == nil {
		return nil
	}
	out := &dnsevent.DNSEvent{
		Source:   dnsevent.SourceTetragonKprobe,
		NodeName: ev.GetNodeName(),
		QName:    strings.ToLower(ev.GetQname()),
		QType:    ev.GetQtype(),
		DstPort:  uint16(ev.GetDstPort()), //nolint:gosec // bridge proto uses uint32 for port; DNS port range fits uint16
	}
	if ev.GetTimestamp() != nil {
		out.Timestamp = ev.GetTimestamp().AsTime()
	}
	if b := ev.GetDstIp(); len(b) > 0 {
		out.DstIP = net.IP(b)
	}
	if p := ev.GetProcess(); p != nil {
		if pod := p.GetPod(); pod != nil && pod.GetName() != "" {
			out.Pod = types.NamespacedName{Namespace: pod.GetNamespace(), Name: pod.GetName()}
		}
	}
	return out
}
