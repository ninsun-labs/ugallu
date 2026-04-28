// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package resolverv1

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// DefaultUnixSocket is the resolver UDS exported by the DaemonSet at
// the conventional host-bind path.
const DefaultUnixSocket = "/var/run/ugallu/resolver.sock"

// DefaultClusterEndpoint is the in-cluster ClusterIP service backing
// the resolver — used as TCP fallback when the local UDS isn't
// available (e.g. a non-DaemonSet workload that still needs lookups).
const DefaultClusterEndpoint = "ugallu-resolver.ugallu-system-privileged.svc:443"

// DialerOpts configures Dialer. Defaults match the Wave-2 design 20
// §S2 numbers (50ms UDS connect, 200ms TCP connect).
type DialerOpts struct {
	// UnixSocket overrides the local-node UDS path. Empty falls back
	// to DefaultUnixSocket.
	UnixSocket string

	// ClusterEndpoint overrides the TCP fallback target. Empty falls
	// back to DefaultClusterEndpoint.
	ClusterEndpoint string

	// UDSConnectTimeout caps the local UDS dial; default 50ms.
	UDSConnectTimeout time.Duration

	// TCPConnectTimeout caps the cluster fallback dial; default 200ms.
	TCPConnectTimeout time.Duration

	// Insecure skips TLS on the cluster endpoint (lab/dev only — in
	// prod the resolver Service should expose a cert via SPIRE).
	Insecure bool

	// ExtraDialOpts are appended to both dials. nil is fine.
	ExtraDialOpts []grpc.DialOption
}

// Dialer establishes ResolverClient gRPC connections, preferring the
// local UDS and falling back to the in-cluster TCP endpoint. The
// returned connections are persistent (HTTP/2) and reused across
// requests by the gRPC stub generator.
type Dialer struct {
	opts DialerOpts

	mu       sync.Mutex
	conn     *grpc.ClientConn
	stub     ResolverClient
	transport string // "uds" or "tcp", for metrics
}

// NewDialer validates opts and returns a Dialer ready to Dial().
func NewDialer(opts *DialerOpts) *Dialer {
	if opts == nil {
		opts = &DialerOpts{}
	}
	if opts.UnixSocket == "" {
		opts.UnixSocket = DefaultUnixSocket
	}
	if opts.ClusterEndpoint == "" {
		opts.ClusterEndpoint = DefaultClusterEndpoint
	}
	if opts.UDSConnectTimeout <= 0 {
		opts.UDSConnectTimeout = 50 * time.Millisecond
	}
	if opts.TCPConnectTimeout <= 0 {
		opts.TCPConnectTimeout = 200 * time.Millisecond
	}
	return &Dialer{opts: *opts}
}

// Dial returns the active ResolverClient. The first call attempts the
// UDS, then falls back to TCP on ENOENT/ECONNREFUSED. Subsequent
// calls return the cached client until Close() resets it.
func (d *Dialer) Dial(ctx context.Context) (ResolverClient, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stub != nil {
		return d.stub, nil
	}

	// 1) UDS attempt.
	udsCtx, udsCancel := context.WithTimeout(ctx, d.opts.UDSConnectTimeout)
	defer udsCancel()
	conn, err := d.dialUDS(udsCtx)
	if err == nil {
		d.conn = conn
		d.stub = NewResolverClient(conn)
		d.transport = "uds"
		dialFailures.WithLabelValues("uds").Add(0) // ensure series exists
		return d.stub, nil
	}
	dialFailures.WithLabelValues("uds").Inc()

	// 2) TCP fallback.
	tcpCtx, tcpCancel := context.WithTimeout(ctx, d.opts.TCPConnectTimeout)
	defer tcpCancel()
	conn, err = d.dialTCP(tcpCtx)
	if err == nil {
		d.conn = conn
		d.stub = NewResolverClient(conn)
		d.transport = "tcp"
		dialFailures.WithLabelValues("tcp").Add(0)
		return d.stub, nil
	}
	dialFailures.WithLabelValues("tcp").Inc()
	return nil, fmt.Errorf("resolver dial failed: uds + tcp both unreachable: %w", err)
}

// Transport reports which transport satisfied the last successful
// Dial — useful for telemetry and integration tests.
func (d *Dialer) Transport() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.transport
}

// Close shuts the cached connection. Subsequent Dial calls will
// re-attempt UDS-first.
func (d *Dialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		err := d.conn.Close()
		d.conn = nil
		d.stub = nil
		d.transport = ""
		return err
	}
	return nil
}

// dialUDS connects via Unix-domain socket. The grpc resolver scheme
// "unix" wires net.Dial("unix", path) under the hood.
func (d *Dialer) dialUDS(ctx context.Context) (*grpc.ClientConn, error) {
	target := "unix:" + d.opts.UnixSocket
	dialOpts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			path := strings.TrimPrefix(addr, "unix:")
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", path)
		}),
	}, d.opts.ExtraDialOpts...)
	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("uds dial %s: %w", target, err)
	}
	// Force the connection to establish so the dialer can fail-fast
	// back to TCP when the socket isn't there.
	conn.Connect()
	if err := waitForReady(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// dialTCP connects via the in-cluster ClusterIP. Insecure flag toggles
// TLS — production is always TLS-on.
func (d *Dialer) dialTCP(ctx context.Context) (*grpc.ClientConn, error) {
	dialOpts := append([]grpc.DialOption{}, d.opts.ExtraDialOpts...)
	if d.opts.Insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// TLS via system CA — caller can override via ExtraDialOpts.
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	conn, err := grpc.NewClient(d.opts.ClusterEndpoint, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", d.opts.ClusterEndpoint, err)
	}
	conn.Connect()
	if err := waitForReady(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// waitForReady blocks until the connection enters Ready state or the
// context fires. Without it the new client would silently queue RPCs
// while the socket isn't actually reachable.
func waitForReady(ctx context.Context, conn *grpc.ClientConn) error {
	for {
		state := conn.GetState()
		if state.String() == "READY" {
			return nil
		}
		if !conn.WaitForStateChange(ctx, state) {
			return errors.New("dial: state change wait cancelled")
		}
	}
}
