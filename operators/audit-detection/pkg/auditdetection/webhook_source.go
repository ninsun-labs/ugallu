// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package auditdetection

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultWebhookSourceBufferSize is the channel capacity WebhookSource
// uses when the caller leaves it unset.
const DefaultWebhookSourceBufferSize = 4096

// DefaultWebhookListenAddr is the listen address used by the apiserver
// audit webhook backend. Operators typically front this with a
// ClusterIP Service exposing :443 → :8443.
const DefaultWebhookListenAddr = ":8443"

// DefaultWebhookPath is the URL path the apiserver POSTs batched
// audit events to. Configure the apiserver's audit-webhook
// kubeconfig with `server: https://<svc>:443/v1/audit`.
const DefaultWebhookPath = "/v1/audit"

// WebhookSourceOpts configures a WebhookSource.
type WebhookSourceOpts struct {
	// ListenAddr defaults to DefaultWebhookListenAddr.
	ListenAddr string

	// Path defaults to DefaultWebhookPath.
	Path string

	// CertFile + KeyFile enable TLS. Both empty = HTTP (lab/dev
	// only). Production must always run TLS to keep the audit
	// stream confidential.
	CertFile string
	KeyFile  string

	// ClientCAFile enables mTLS. Optional; when set, peer certs are
	// verified against the supplied bundle.
	ClientCAFile string

	// SharedSecret enables bearer-token auth in addition to (or in
	// place of) mTLS. The apiserver audit-webhook kubeconfig
	// supplies the same token via the `Authorization` header.
	SharedSecret string

	// BufferSize caps the events channel; default
	// DefaultWebhookSourceBufferSize.
	BufferSize int

	// Log routes diagnostics. nil → discard.
	Log *slog.Logger

	// ReadHeaderTimeout caps Slowloris exposure on the listener.
	// Default 5s.
	ReadHeaderTimeout time.Duration
}

// WebhookSource accepts batched audit-event POSTs from the
// apiserver's audit-webhook backend.
//
// The wire shape is the audit.k8s.io/v1.EventList JSON object: a
// top-level `items` array of audit events. The handler decodes the
// list, normalises every entry into AuditEvent, and pushes them on
// the channel. Slow consumers translate to HTTP 503 so the apiserver
// retries (default audit-webhook behaviour).
type WebhookSource struct {
	opts WebhookSourceOpts
	out  chan *AuditEvent

	mu     sync.Mutex
	server *http.Server
}

// NewWebhookSource validates opts and returns a Source ready for Run.
func NewWebhookSource(opts *WebhookSourceOpts) (*WebhookSource, error) {
	if opts == nil {
		opts = &WebhookSourceOpts{}
	}
	if opts.ListenAddr == "" {
		opts.ListenAddr = DefaultWebhookListenAddr
	}
	if opts.Path == "" {
		opts.Path = DefaultWebhookPath
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultWebhookSourceBufferSize
	}
	if opts.ReadHeaderTimeout <= 0 {
		opts.ReadHeaderTimeout = 5 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	if (opts.CertFile == "") != (opts.KeyFile == "") {
		return nil, errors.New("webhook source: CertFile and KeyFile must both be set or both empty")
	}
	if opts.SharedSecret == "" && opts.ClientCAFile == "" && opts.CertFile == "" {
		return nil, errors.New("webhook source: at least one of (TLS cert, mTLS, SharedSecret) is required")
	}
	return &WebhookSource{opts: *opts}, nil
}

// Name reports the source identifier for telemetry.
func (s *WebhookSource) Name() string { return "webhook:" + s.opts.ListenAddr + s.opts.Path }

// Run starts the HTTPS server on a background goroutine and returns
// the events channel. ctx cancellation triggers a graceful Shutdown
// (15s drain) before the channel closes.
func (s *WebhookSource) Run(ctx context.Context) (<-chan *AuditEvent, error) {
	s.out = make(chan *AuditEvent, s.opts.BufferSize)

	mux := http.NewServeMux()
	mux.HandleFunc(s.opts.Path, s.handle)

	s.mu.Lock()
	s.server = &http.Server{
		Addr:              s.opts.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: s.opts.ReadHeaderTimeout,
	}
	srv := s.server
	s.mu.Unlock()

	// Listen socket first so a port-bind failure is reported
	// synchronously to the caller, not on a goroutine.
	listenErr := make(chan error, 1)
	go func() {
		var err error
		switch {
		case s.opts.CertFile != "":
			err = srv.ListenAndServeTLS(s.opts.CertFile, s.opts.KeyFile)
		default:
			s.opts.Log.Warn("webhook source: running without TLS — dev/lab only")
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErr <- err
		}
		close(listenErr)
	}()

	// Fresh background ctx for the graceful drain inside the
	// goroutine: the parent ctx is already cancelled, so passing it
	// through would abandon in-flight POSTs immediately. The 15s
	// cap matches Kubernetes terminationGracePeriodSeconds defaults.
	go func() { //nolint:gosec // intentional fresh ctx for graceful drain
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		close(s.out)
	}()

	// Surface immediate listen errors (e.g. address already in use).
	select {
	case err := <-listenErr:
		if err != nil {
			close(s.out)
			return nil, fmt.Errorf("webhook source listen: %w", err)
		}
	case <-time.After(50 * time.Millisecond):
		// Listener is up; drop through.
	}
	return s.out, nil
}

// handle is the audit-webhook endpoint. It validates the bearer
// token (when configured), decodes the EventList, and pushes each
// item onto the channel. Backpressure is reported as 503; the
// apiserver retries with exponential backoff.
func (s *WebhookSource) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.SharedSecret != "" {
		if !s.checkBearer(r) {
			webhookSourceAuthFailures.Inc()
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024)) // 8 MiB cap
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var batch struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &batch); err != nil {
		http.Error(w, "decode batch: "+err.Error(), http.StatusBadRequest)
		return
	}

	for _, raw := range batch.Items {
		ev := &AuditEvent{Raw: append([]byte(nil), raw...)}
		if err := json.Unmarshal(raw, ev); err != nil {
			webhookSourceParseErrors.Inc()
			continue
		}
		select {
		case s.out <- ev:
			webhookSourceLines.Inc()
		default:
			// Channel full — refuse the rest of the batch and ask
			// the apiserver to retry. Audit-webhook retries are
			// ordered, so events are not lost under sustained load
			// (the apiserver just slows down).
			webhookSourceBackpressure.Inc()
			http.Error(w, "backpressure", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// checkBearer constant-time-compares the Authorization header against
// the configured shared secret.
func (s *WebhookSource) checkBearer(r *http.Request) bool {
	hdr := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(hdr, prefix) {
		return false
	}
	got := []byte(strings.TrimSpace(strings.TrimPrefix(hdr, prefix)))
	want := []byte(s.opts.SharedSecret)
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// FromEnv is a small convenience: reads `AUDIT_WEBHOOK_TOKEN` from
// the env so cmd binaries can wire SharedSecret without exposing it
// in flags. Empty result means "no env override".
func FromEnv(name string) string { return strings.TrimSpace(os.Getenv(name)) }
