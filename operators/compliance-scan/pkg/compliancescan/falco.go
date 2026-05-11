// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package compliancescan

import (
	"context"
	"fmt"
	"strings"
	"time"

	falcoclient "github.com/falcosecurity/client-go/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"
)

// realFalcoScanner consumes the Falco gRPC outputs.Service.Get RPC
// for the scan window and folds every observed Output into a
// ComplianceCheckResult. The check id mirrors Falco's rule.tag
// (e.g. cis.5.4.1, mitre.t1059) so downstream consumers can map
// findings to their framework of choice.
type realFalcoScanner struct {
	hostname    string
	port        uint16
	certFile    string
	keyFile     string
	caRootFile  string
	maxFindings int
	timeout     time.Duration
}

func newRealFalcoScanner(host string, port uint16, certFile, keyFile, caFile string, timeout time.Duration) *realFalcoScanner {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &realFalcoScanner{
		hostname: host, port: port,
		certFile: certFile, keyFile: keyFile, caRootFile: caFile,
		maxFindings: 200, timeout: timeout,
	}
}

func (s *realFalcoScanner) Scan(ctx context.Context, _ client.Client, _ *securityv1alpha1.ComplianceScanRunSpec) (*ScanOutcome, error) {
	dialCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	c, err := falcoclient.NewForConfig(dialCtx, &falcoclient.Config{
		Hostname:   s.hostname,
		Port:       s.port,
		CertFile:   s.certFile,
		KeyFile:    s.keyFile,
		CARootFile: s.caRootFile,
	})
	if err != nil {
		return nil, fmt.Errorf("falco dial %s:%d: %w", s.hostname, s.port, err)
	}
	defer func() { _ = c.Close() }()

	osc, err := c.Outputs()
	if err != nil {
		return nil, fmt.Errorf("falco outputs client: %w", err)
	}
	stream, err := osc.Get(dialCtx, nil)
	if err != nil {
		return nil, fmt.Errorf("falco Get: %w", err)
	}

	out := &ScanOutcome{Summary: map[string]int{"pass": 0, "fail": 0, "warn": 0, "skip": 0}}
	count := 0
	for {
		ev, err := stream.Recv()
		if err != nil {
			break
		}
		count++
		if count > s.maxFindings {
			break
		}
		check := falcoOutputToCheck(ev.GetRule(), ev.GetPriority().String(), ev.GetOutput(), ev.GetTags())
		out.Checks = append(out.Checks, check)
		out.Summary[check.Outcome]++
	}

	if len(out.Checks) == 0 {
		// Empty scan window - record a pass so the run is non-empty
		// and ops can confirm Falco itself was reachable.
		out.Checks = append(out.Checks, securityv1alpha1.ComplianceCheckResult{
			CheckID:  "ugallu.falco.no-events",
			Title:    "Falco reachable but no rule fired during the scan window",
			Outcome:  "pass",
			Severity: securityv1alpha1.SeverityInfo,
		})
		out.Summary["pass"]++
	}
	return out, nil
}

// falcoOutputToCheck maps a Falco event onto the ComplianceCheckResult
// shape. Priority drives severity; the rule + tag list drive checkID.
func falcoOutputToCheck(rule, priority, output string, tags []string) securityv1alpha1.ComplianceCheckResult {
	severity := securityv1alpha1.SeverityInfo
	switch strings.ToLower(priority) {
	case "emergency", "alert", "critical":
		severity = securityv1alpha1.SeverityCritical
	case "error":
		severity = securityv1alpha1.SeverityHigh
	case "warning":
		severity = securityv1alpha1.SeverityMedium
	case "notice":
		severity = securityv1alpha1.SeverityLow
	}
	checkID := "ugallu.falco." + slugify(rule)
	if len(tags) > 0 {
		// Prefer the first dotted tag (mitre.t1059, cis.5.4.1, …) as
		// it tends to be the framework-aligned identifier.
		for _, t := range tags {
			if strings.Contains(t, ".") {
				checkID = t
				break
			}
		}
	}
	return securityv1alpha1.ComplianceCheckResult{
		CheckID:  checkID,
		Title:    rule,
		Outcome:  "fail", // Every Falco event is a rule violation by construction.
		Severity: severity,
		Detail:   output,
	}
}

// slugify turns "Detect ssh exec into pod" → "detect-ssh-exec-into-pod".
func slugify(s string) string {
	out := strings.Builder{}
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				out.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(out.String(), "-")
}
