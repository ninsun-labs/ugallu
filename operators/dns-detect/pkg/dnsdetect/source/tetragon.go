// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"

	"github.com/ninsun-labs/ugallu/operators/dns-detect/pkg/dnsevent"
)

// TetragonKprobeSource is the fallback backend (design 21 §D2.3).
// Limited to DstPort + Pod attribution — only DNSAnomalousPort
// detector is fully functional against this source. The other 4
// detectors emit `Class=Anomaly type=DNSDetectorDegraded` (one-shot
// per detector) and skip evaluation while running on this source.
//
// Wave 3 Sprint 3 ships a stub implementation that returns an empty
// closed channel. The real Tetragon Hubble client wiring follows
// once the tetragon-bridge v0.1.0 lands (Wave 4 Sprint 1).
type TetragonKprobeSource struct{}

// NewTetragonKprobeSource returns the fallback source stub.
func NewTetragonKprobeSource() *TetragonKprobeSource { return &TetragonKprobeSource{} }

// Name implements Source.
func (s *TetragonKprobeSource) Name() string { return string(dnsevent.SourceTetragonKprobe) }

// Run returns a closed channel — the fallback path is wired against
// the tetragon-bridge gRPC in Wave 4 Sprint 1, so for now any
// operator that resolves Primary→TetragonKprobe enters the
// degraded state and emits DNSSourceSilent.
func (s *TetragonKprobeSource) Run(_ context.Context) (<-chan *dnsevent.DNSEvent, error) {
	out := make(chan *dnsevent.DNSEvent)
	close(out)
	return out, nil
}
