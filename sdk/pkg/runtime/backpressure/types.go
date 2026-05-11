// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package backpressure

// Level is the discrete pressure tier reported in the output
// ConfigMap. It is the only stable contract between this controller
// and the SDK emitters: emitters must read `data.level` and adapt
// their token bucket / severity gate accordingly.
type Level string

// Level constants.
const (
	// LevelGreen - etcd is well below the saturation threshold and
	// every emitter runs at full configured rate.
	LevelGreen Level = "Green"

	// LevelYellow - etcd is past the warn threshold; emitters halve
	// their effective rate while still accepting every severity tier.
	LevelYellow Level = "Yellow"

	// LevelRed - etcd is near saturation; emitters drop every event
	// whose severity is below MinSeverityRed (default "high").
	LevelRed Level = "Red"
)

// Output captures the data plane of the backpressure ConfigMap. It is
// reduced to a string map by the controller before the apply.
type Output struct {
	Level                   Level
	EffectiveRateMultiplier string
	MinSeverityAccepted     string
}

// ConfigMap field names. Exposed as constants so consuming SDKs (and
// tests) reference the same keys as the controller.
const (
	FieldLevel                   = "level"
	FieldEffectiveRateMultiplier = "effectiveRateMultiplier"
	FieldMinSeverityAccepted     = "minSeverityAccepted"
)

// DefaultConfigMapName is the canonical ConfigMap consumed by every
// emitter.
const DefaultConfigMapName = "ugallu-backpressure"

// DefaultNamespace is the conventional control-plane namespace that
// owns the backpressure ConfigMap.
const DefaultNamespace = "ugallu-system"
