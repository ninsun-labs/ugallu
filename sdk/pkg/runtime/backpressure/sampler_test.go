// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package backpressure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrometheusSampler_PrefersApiserverStorageMetric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`# HELP apiserver_storage_size_bytes per-resource storage usage
# TYPE apiserver_storage_size_bytes gauge
apiserver_storage_size_bytes{resource="pods"} 1024
apiserver_storage_size_bytes{resource="secrets"} 2048
etcd_db_total_size_in_bytes 9999
`))
	}))
	defer srv.Close()

	s := &PrometheusSampler{URL: srv.URL}
	out, err := s.Sample(context.Background())
	if err != nil {
		t.Fatalf("Sample: %v", err)
	}
	// Must sum the per-label apiserver_storage_size_bytes series and
	// ignore the older etcd metric when the modern one is present.
	if out.UsedBytes != 1024+2048 {
		t.Errorf("UsedBytes = %d, want %d", out.UsedBytes, 1024+2048)
	}
}

func TestPrometheusSampler_FallsBackToEtcdMetric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`# only legacy metric
etcd_db_total_size_in_bytes 5242880
`))
	}))
	defer srv.Close()

	s := &PrometheusSampler{URL: srv.URL}
	out, err := s.Sample(context.Background())
	if err != nil {
		t.Fatalf("Sample: %v", err)
	}
	if out.UsedBytes != 5242880 {
		t.Errorf("UsedBytes = %d, want 5242880", out.UsedBytes)
	}
}

func TestPrometheusSampler_NoMatchingMetric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`go_goroutines 12`))
	}))
	defer srv.Close()
	s := &PrometheusSampler{URL: srv.URL}
	if _, err := s.Sample(context.Background()); err == nil {
		t.Fatal("expected error for missing metric")
	} else if !strings.Contains(err.Error(), "no metric") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrometheusSampler_HonoursBearerToken(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("apiserver_storage_size_bytes 1\n"))
	}))
	defer srv.Close()
	s := &PrometheusSampler{URL: srv.URL, BearerToken: "test-jwt"}
	if _, err := s.Sample(context.Background()); err != nil {
		t.Fatalf("Sample: %v", err)
	}
	if seen != "Bearer test-jwt" {
		t.Errorf("Authorization = %q, want Bearer test-jwt", seen)
	}
}

func TestSample_RatioFallback(t *testing.T) {
	s := Sample{UsedBytes: 800}
	if got := s.Ratio(1000); got != 0.8 {
		t.Errorf("Ratio fallback = %v, want 0.8", got)
	}
	if got := (Sample{UsedBytes: 800, CapacityBytes: 2000}).Ratio(1000); got != 0.4 {
		t.Errorf("Ratio with explicit capacity = %v, want 0.4", got)
	}
	if got := (Sample{UsedBytes: 1}).Ratio(0); got != 0 {
		t.Errorf("Ratio with zero capacity = %v, want 0", got)
	}
}
