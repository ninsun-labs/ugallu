// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package auditdetection_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ninsun-labs/ugallu/operators/audit-detection/pkg/auditdetection"
)

// freePort returns an OS-allocated TCP port for the test webhook
// listener. Reduces flakiness when several tests run in parallel.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func startWebhook(t *testing.T, opts *auditdetection.WebhookSourceOpts) (url string, out <-chan *auditdetection.AuditEvent, cancel context.CancelFunc) {
	t.Helper()
	src, err := auditdetection.NewWebhookSource(opts)
	if err != nil {
		t.Fatalf("NewWebhookSource: %v", err)
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	ch, runErr := src.Run(ctx)
	if runErr != nil {
		cancelFn()
		t.Fatalf("Run: %v", runErr)
	}
	// Wait for the server to bind.
	time.Sleep(100 * time.Millisecond)
	return "http://127.0.0.1" + opts.ListenAddr + opts.Path, ch, cancelFn
}

func TestWebhookSource_AcceptsBatchedEvents(t *testing.T) {
	port := freePort(t)
	url, out, cancel := startWebhook(t, &auditdetection.WebhookSourceOpts{
		ListenAddr:   fmt.Sprintf(":%d", port),
		Path:         "/v1/audit",
		SharedSecret: "test-token",
	})
	defer cancel()

	batch := map[string]any{
		"items": []map[string]any{
			{"auditID": "wh-1", "verb": "create"},
			{"auditID": "wh-2", "verb": "delete"},
		},
	}
	body, _ := json.Marshal(batch)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	for i, want := range []string{"wh-1", "wh-2"} {
		select {
		case ev := <-out:
			if ev.AuditID != want {
				t.Errorf("event[%d].AuditID = %q, want %q", i, ev.AuditID, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for event %d", i)
		}
	}
}

func TestWebhookSource_RejectsMissingBearer(t *testing.T) {
	port := freePort(t)
	url, _, cancel := startWebhook(t, &auditdetection.WebhookSourceOpts{
		ListenAddr:   fmt.Sprintf(":%d", port),
		Path:         "/v1/audit",
		SharedSecret: "secret",
	})
	defer cancel()

	body, _ := json.Marshal(map[string]any{"items": []map[string]any{{"auditID": "x"}}})
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestWebhookSource_RejectsWrongBearer(t *testing.T) {
	port := freePort(t)
	url, _, cancel := startWebhook(t, &auditdetection.WebhookSourceOpts{
		ListenAddr:   fmt.Sprintf(":%d", port),
		Path:         "/v1/audit",
		SharedSecret: "good",
	})
	defer cancel()

	body, _ := json.Marshal(map[string]any{"items": []map[string]any{{"auditID": "x"}}})
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestWebhookSource_RejectsNonPOST(t *testing.T) {
	port := freePort(t)
	url, _, cancel := startWebhook(t, &auditdetection.WebhookSourceOpts{
		ListenAddr:   fmt.Sprintf(":%d", port),
		Path:         "/v1/audit",
		SharedSecret: "x",
	})
	defer cancel()

	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestNewWebhookSource_RejectsNoAuth(t *testing.T) {
	if _, err := auditdetection.NewWebhookSource(&auditdetection.WebhookSourceOpts{}); err == nil {
		t.Error("expected error when neither TLS nor SharedSecret is set")
	}
}

func TestNewWebhookSource_RequiresPairedTLS(t *testing.T) {
	if _, err := auditdetection.NewWebhookSource(&auditdetection.WebhookSourceOpts{
		CertFile:     "/tmp/cert",
		SharedSecret: "x",
	}); err == nil {
		t.Error("expected error when CertFile is set without KeyFile")
	}
}

func TestWebhookSource_BackpressureReturns503(t *testing.T) {
	port := freePort(t)
	src, err := auditdetection.NewWebhookSource(&auditdetection.WebhookSourceOpts{
		ListenAddr:   fmt.Sprintf(":%d", port),
		Path:         "/v1/audit",
		SharedSecret: "x",
		BufferSize:   1,
	})
	if err != nil {
		t.Fatalf("NewWebhookSource: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, runErr := src.Run(ctx); runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/v1/audit", port)
	time.Sleep(100 * time.Millisecond)

	// 1) push a batch of 5; consumer not draining → second event
	// fills the buffer (cap=1) and the rest get rejected with 503.
	batch := map[string]any{
		"items": []map[string]any{
			{"auditID": "1"}, {"auditID": "2"}, {"auditID": "3"},
		},
	}
	body, _ := json.Marshal(batch)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer x")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (backpressure)", resp.StatusCode)
	}
}
