// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package backpressure

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Sample is one observation of etcd storage usage. Either CapacityBytes
// is supplied (preferred - the controller can compute the live ratio)
// or the controller falls back to its configured EtcdCapacityBytes.
type Sample struct {
	UsedBytes     uint64
	CapacityBytes uint64
}

// Ratio returns Used / Capacity, falling back to the controller-side
// capacity when the sampler couldn't supply one. Returns 0 when both
// capacity sources are unset (treated as Green).
func (s Sample) Ratio(fallbackCapacity uint64) float64 {
	capBytes := s.CapacityBytes
	if capBytes == 0 {
		capBytes = fallbackCapacity
	}
	if capBytes == 0 {
		return 0
	}
	return float64(s.UsedBytes) / float64(capBytes)
}

// Sampler returns the latest etcd storage observation. Implementations
// may scrape the kube-apiserver metrics endpoint, query Prometheus, or
// be hand-rolled fakes in tests.
type Sampler interface {
	Sample(ctx context.Context) (Sample, error)
}

// PrometheusSampler scrapes the kube-apiserver /metrics endpoint and
// extracts apiserver_storage_size_bytes (K8s ≥1.28) - falling back to
// etcd_db_total_size_in_bytes for older surfaces.
type PrometheusSampler struct {
	URL string

	// BearerToken authenticates the scrape request. Empty falls back
	// to BearerTokenFile.
	BearerToken string

	// BearerTokenFile, when set, is read at every scrape so that
	// rotated projected SA tokens are picked up.
	BearerTokenFile string

	// CABundle is PEM-encoded; empty uses the system trust store.
	CABundle []byte

	// InsecureSkipVerify disables TLS verification - dev/lab only.
	InsecureSkipVerify bool

	// HTTPClient is reused across requests when set. nil triggers a
	// default client built from the TLS knobs above.
	HTTPClient *http.Client
}

// metricCandidates is the ordered list of metric names the sampler
// accepts. First match wins. apiserver_storage_size_bytes is the
// modern surface; etcd_db_total_size_in_bytes is the historical name
// still present on older clusters.
var metricCandidates = []string{
	"apiserver_storage_size_bytes",
	"etcd_db_total_size_in_bytes",
}

// Sample scrapes the metrics endpoint and returns the first matching
// gauge. CapacityBytes is left zero - kube-apiserver does not export
// the etcd cap; the controller's EtcdCapacityBytes field provides it.
func (p *PrometheusSampler) Sample(ctx context.Context) (Sample, error) {
	if p.URL == "" {
		return Sample{}, errors.New("PrometheusSampler.URL is required")
	}
	cli := p.HTTPClient
	if cli == nil {
		cli = newScrapeClient(p.CABundle, p.InsecureSkipVerify)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, http.NoBody)
	if err != nil {
		return Sample{}, fmt.Errorf("build request: %w", err)
	}
	tok := p.BearerToken
	if tok == "" && p.BearerTokenFile != "" {
		b, rErr := os.ReadFile(p.BearerTokenFile) //nolint:gosec // operator-controlled path
		if rErr != nil {
			return Sample{}, fmt.Errorf("read bearer token: %w", rErr)
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := cli.Do(req)
	if err != nil {
		return Sample{}, fmt.Errorf("scrape %s: %w", p.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return Sample{}, fmt.Errorf("scrape %s: HTTP %d", p.URL, resp.StatusCode)
	}
	used, err := scanMetric(resp.Body, metricCandidates)
	if err != nil {
		return Sample{}, err
	}
	return Sample{UsedBytes: used}, nil
}

// scanMetric reads a Prometheus text-format response line by line,
// returning the value of the first matching metric. Lines starting
// with '#' (HELP / TYPE) and labelled series are tolerated; the gauge
// is selected by exact metric-name match (label sets are summed when
// multiple series share the chosen name - matches the kube-apiserver
// per-resource breakdown of apiserver_storage_size_bytes).
func scanMetric(r io.Reader, names []string) (uint64, error) {
	wantSet := make(map[string]struct{}, len(names))
	for _, n := range names {
		wantSet[n] = struct{}{}
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	hits := map[string]uint64{}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Split on the first whitespace; before it is the series, after
		// it is the value (Prometheus text format).
		ws := strings.IndexAny(line, " \t")
		if ws <= 0 {
			continue
		}
		series := line[:ws]
		valStr := strings.TrimSpace(line[ws+1:])
		// Strip an optional second whitespace-separated timestamp.
		if i := strings.IndexAny(valStr, " \t"); i >= 0 {
			valStr = valStr[:i]
		}
		// Series may be either "name" or "name{labels}".
		name := series
		if i := strings.IndexByte(series, '{'); i >= 0 {
			name = series[:i]
		}
		if _, ok := wantSet[name]; !ok {
			continue
		}
		v, err := strconv.ParseFloat(valStr, 64)
		if err != nil || v < 0 {
			continue
		}
		hits[name] += uint64(v)
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan metrics: %w", err)
	}
	for _, n := range names {
		if v, ok := hits[n]; ok {
			return v, nil
		}
	}
	return 0, fmt.Errorf("no metric in %v found in scrape", names)
}

// newScrapeClient returns an http.Client wired for kube-apiserver
// scrapes, honouring CABundle / InsecureSkipVerify.
func newScrapeClient(caBundle []byte, insecure bool) *http.Client {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // caller may opt into InsecureSkipVerify in dev
	if insecure {
		tlsCfg.InsecureSkipVerify = true
	}
	if len(caBundle) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caBundle) {
			tlsCfg.RootCAs = pool
		}
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       tlsCfg,
			MaxIdleConns:          4,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}
