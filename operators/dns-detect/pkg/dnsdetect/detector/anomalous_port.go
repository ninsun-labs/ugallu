// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"strconv"

	securityv1alpha1 "github.com/ninsun-labs/ugallu/sdk/pkg/api/v1alpha1"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

// AnomalousPortDetector flags DNS queries directed at a non-53 port.
// Stateless — each event is independent.
type AnomalousPortDetector struct{}

// NewAnomalousPortDetector returns a ready detector.
func NewAnomalousPortDetector() *AnomalousPortDetector { return &AnomalousPortDetector{} }

// Name returns the detector name.
func (d *AnomalousPortDetector) Name() string { return "anomalous_port" }

// Evaluate fires whenever DstPort != 53. Skips events with
// DstPort=0 (the source backend didn't populate the field — rare,
// but Tetragon kprobe sometimes elides).
func (d *AnomalousPortDetector) Evaluate(ev *dnsevent.DNSEvent) Finding {
	if ev == nil || ev.DstPort == 0 || ev.DstPort == 53 {
		return Finding{}
	}
	return Finding{
		Type:     securityv1alpha1.TypeDNSAnomalousPort,
		Severity: string(securityv1alpha1.SeverityMedium),
		Subject:  subjectFromEvent(ev),
		Signals: map[string]string{
			"qname":    ev.QName,
			"dst_port": strconv.Itoa(int(ev.DstPort)),
			"dst_ip":   ev.DstIP.String(),
		},
	}
}
