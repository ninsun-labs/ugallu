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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"k8s.io/apimachinery/pkg/types"

	auditstreamv1 "github.com/ninsun-labs/ugallu/sdk/pkg/auditstream/clientv1"

	"github.com/ninsun-labs/ugallu/operators/tenant-escape/pkg/tenantescape/detector"
)

// AuditBusConfig wires the gRPC stream client.
type AuditBusConfig struct {
	// Endpoint is the audit-detection bus address (host:port).
	Endpoint string
	// BearerToken authenticates the client when the server has
	// AuditDetectionConfig.spec.eventBus.tokenSecret set. Empty =
	// unauthenticated (lab-only).
	BearerToken string
	// ConsumerName is the SubscribeRequest.consumer_name; must
	// match an entry in AuditDetectionConfig.spec.consumers.
	ConsumerName string
	// ReconnectBase is the base for exponential backoff on
	// transient errors. Capped at 30s.
	ReconnectBase time.Duration
}

// AuditBusSource is the primary backend (design 21 §S2). Subscribes
// to the audit-detection event bus and translates protobuf
// AuditEvent into the source-agnostic detector.AuditInput shape.
type AuditBusSource struct {
	cfg AuditBusConfig
}

// NewAuditBusSource validates cfg and returns a source.
func NewAuditBusSource(cfg AuditBusConfig) (*AuditBusSource, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("AuditBusSource: empty Endpoint")
	}
	if cfg.ConsumerName == "" {
		cfg.ConsumerName = "tenant-escape"
	}
	if cfg.ReconnectBase <= 0 {
		cfg.ReconnectBase = 2 * time.Second
	}
	return &AuditBusSource{cfg: cfg}, nil
}

// Name implements AuditSource.
func (s *AuditBusSource) Name() string { return "audit_bus" }

// Run dials the bus and forwards events. Reconnects with exponential
// backoff on transient errors; closes the channel when ctx is
// cancelled.
func (s *AuditBusSource) Run(ctx context.Context) (<-chan *detector.AuditInput, error) {
	out := make(chan *detector.AuditInput, 256)
	go func() {
		defer close(out)
		backoff := s.cfg.ReconnectBase
		for {
			err := s.runOnce(ctx, out)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if err == nil {
				backoff = s.cfg.ReconnectBase
				continue
			}
			if next := backoff * 2; next > 30*time.Second {
				backoff = 30 * time.Second
			} else {
				backoff = next
			}
		}
	}()
	return out, nil
}

// runOnce performs a single dial + Subscribe lifecycle. Returns nil
// on graceful EOF, error otherwise.
func (s *AuditBusSource) runOnce(ctx context.Context, out chan<- *detector.AuditInput) error {
	conn, err := grpc.NewClient(s.cfg.Endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial %s: %w", s.cfg.Endpoint, err)
	}
	defer func() { _ = conn.Close() }()

	client := auditstreamv1.NewAuditStreamClient(conn)
	streamCtx := ctx
	if s.cfg.BearerToken != "" {
		streamCtx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+s.cfg.BearerToken)
	}
	stream, err := client.Subscribe(streamCtx, &auditstreamv1.SubscribeRequest{
		ConsumerName: s.cfg.ConsumerName,
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
		case out <- pbToAuditInput(ev):
		}
	}
}

// pbToAuditInput translates the wire protobuf shape into the
// source-agnostic detector.AuditInput. Parses the SA username
// "system:serviceaccount:<ns>:<name>" prefix when present so the
// detectors can match on UserNamespace without re-parsing.
func pbToAuditInput(ev *auditstreamv1.AuditEvent) *detector.AuditInput {
	if ev == nil {
		return nil
	}
	in := &detector.AuditInput{
		AuditID:       ev.GetAuditId(),
		Verb:          ev.GetVerb(),
		RequestObject: ev.GetRequestObject(),
	}
	if u := ev.GetUser(); u != nil {
		in.UserUsername = u.GetUsername()
		in.UserNamespace = saUsernameNamespace(u.GetUsername())
	}
	if ref := ev.GetObjectRef(); ref != nil {
		in.ObjectAPIGroup = ref.GetApiGroup()
		in.ObjectResource = ref.GetResource()
		in.ObjectNamespace = ref.GetNamespace()
		in.ObjectName = ref.GetName()
		if uid := ref.GetUid(); uid != "" {
			in.ObjectUID = types.UID(uid)
		}
	}
	return in
}

// saUsernameNamespace extracts the namespace component from a
// "system:serviceaccount:<ns>:<name>" username. Returns "" when the
// principal is not a service account.
func saUsernameNamespace(username string) string {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(username, prefix) {
		return ""
	}
	rest := username[len(prefix):]
	if i := strings.Index(rest, ":"); i > 0 {
		return rest[:i]
	}
	return ""
}
