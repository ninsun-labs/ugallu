// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package compliancescan

import (
	"testing"
)

// TestParseKubeBenchReport_HappyPath pins the JSON shape kube-bench
// emits on stdout. The fixture is a minimal but real-shape sample
// taken from kube-bench v0.7+.
func TestParseKubeBenchReport_HappyPath(t *testing.T) {
	raw := `{
  "Controls": [
    {
      "id": "1",
      "version": "cis-1.10",
      "tests": [
        {
          "section": "1.1",
          "results": [
            {"test_number": "1.1.1", "test_desc": "Ensure that the API server pod specification file permissions are set to 600 or more restrictive", "status": "PASS"},
            {"test_number": "1.1.2", "test_desc": "Ensure that the kubelet service file permissions are set to 600", "status": "FAIL"},
            {"test_number": "1.1.3", "test_desc": "Note: manual review", "status": "WARN"}
          ]
        }
      ],
      "total_pass": 1,
      "total_fail": 1,
      "total_warn": 1,
      "total_info": 0
    }
  ]
}`
	out := parseKubeBenchReport(raw)
	if out == nil {
		t.Fatal("parseKubeBenchReport returned nil")
	}
	if got := len(out.Checks); got != 3 {
		t.Fatalf("Checks = %d, want 3", got)
	}
	wantOutcomes := map[string]string{
		"cis.1.1.1": "pass",
		"cis.1.1.2": "fail",
		"cis.1.1.3": "warn",
	}
	for _, c := range out.Checks {
		if want := wantOutcomes[c.CheckID]; want == "" {
			t.Errorf("unexpected CheckID %q", c.CheckID)
		} else if c.Outcome != want {
			t.Errorf("%s outcome = %q, want %q", c.CheckID, c.Outcome, want)
		}
	}
	if out.Summary["pass"] != 1 || out.Summary["fail"] != 1 || out.Summary["warn"] != 1 {
		t.Errorf("Summary = %+v", out.Summary)
	}
}

// TestParseKubeBenchReport_MalformedReturnsWarning ensures a parse
// error doesn't panic and surfaces a single warn-severity finding.
func TestParseKubeBenchReport_MalformedReturnsWarning(t *testing.T) {
	out := parseKubeBenchReport("not-json")
	if len(out.Checks) != 1 || out.Checks[0].Outcome != "warn" {
		t.Errorf("expected one warn finding; got %+v", out.Checks)
	}
}
