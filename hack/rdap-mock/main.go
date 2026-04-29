// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command rdap-mock is a tiny HTTP server that satisfies the subset
// of RDAP (RFC 7480/9082) the dns-detect young-domain detector calls.
// Routes:
//
//	GET /domain/<fqdn>   → { events: [...] }
//
// Behaviour:
//   - When the FQDN's leftmost label starts with "young-" or matches
//     the env var YOUNG_DOMAIN_PATTERN (regex), the response carries
//     a recent registration date (yesterday in UTC).
//   - Otherwise the response carries an old registration date
//     (3 years ago).
//   - 404 on every other path so misconfigurations are loud.
//
// Build: go build -trimpath -ldflags='-s -w' -o rdap-mock-bin .
//
// The image is intentionally separate from the multi-binary lab
// image — this mock has no business shipping in production.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	pattern := os.Getenv("YOUNG_DOMAIN_PATTERN")
	if pattern == "" {
		pattern = `^young-`
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		log.Fatalf("YOUNG_DOMAIN_PATTERN regex: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/domain/", func(w http.ResponseWriter, r *http.Request) {
		fqdn := strings.TrimPrefix(r.URL.Path, "/domain/")
		fqdn = strings.TrimSuffix(fqdn, ".")
		if fqdn == "" {
			http.Error(w, "empty domain", http.StatusBadRequest)
			return
		}

		left := fqdn
		if i := strings.IndexByte(fqdn, '.'); i > 0 {
			left = fqdn[:i]
		}
		var regDate time.Time
		if re.MatchString(left) {
			regDate = time.Now().UTC().Add(-24 * time.Hour)
		} else {
			regDate = time.Now().UTC().AddDate(-3, 0, 0)
		}

		resp := map[string]any{
			"objectClassName": "domain",
			"ldhName":         fqdn,
			"events": []map[string]string{
				{"eventAction": "registration", "eventDate": regDate.Format(time.RFC3339)},
			},
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rdap-mock: only /domain/<fqdn> + /healthz are served", http.StatusNotFound)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Fprintln(os.Stderr, "rdap-mock listening on", addr)
	log.Fatal(srv.ListenAndServe())
}
