// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package backpressure

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Defaults tuned conservatively: emitters keep going
// at full rate until 70% of etcd capacity, halve at 70-90%, drop
// non-critical above 90%, and recover only once usage falls under 50%
// (hysteresis to avoid oscillation around the threshold).
const (
	DefaultPollInterval        = 30 * time.Second
	DefaultEtcdCapacityBytes   = uint64(8 * 1024 * 1024 * 1024)
	DefaultYellowAt            = 0.70
	DefaultRedAt               = 0.90
	DefaultRecoverAt           = 0.50
	DefaultMinSeverityRedTier  = "high"
	DefaultMinSeverityNonRed   = "info"
	DefaultRateMultiplierGreen = "1.0"
	DefaultRateMultiplierYel   = "0.5"
	DefaultRateMultiplierRed   = "0.0"
)

// Options configures the Controller. Zero-valued fields fall back to
// the Default* constants above.
type Options struct {
	// Sampler is the source of etcd usage observations. Required.
	Sampler Sampler

	// Client is the namespaced k8s client used to apply the output
	// ConfigMap. Required.
	Client client.Client

	// Namespace + ConfigMapName name the output ConfigMap. Empty falls
	// back to DefaultNamespace + DefaultConfigMapName.
	Namespace     string
	ConfigMapName string

	// PollInterval — polling cadence. Defaults to DefaultPollInterval.
	PollInterval time.Duration

	// EtcdCapacityBytes is the controller-side fallback used when the
	// sampler doesn't report capacity. Defaults to DefaultEtcdCapacityBytes.
	EtcdCapacityBytes uint64

	// YellowAt / RedAt / RecoverAt are storage-usage ratios in [0,1]
	// driving level transitions.
	YellowAt  float64
	RedAt     float64
	RecoverAt float64
}

// Controller is a manager.Runnable that periodically samples etcd
// usage, computes a Level (with hysteresis), and reconciles the
// backpressure ConfigMap. One instance per cluster is expected; the
// embedding command is responsible for leader election.
type Controller struct {
	opts Options

	// lastLevel survives across polls so hysteresis on the
	// recover-down transition can be applied.
	lastLevel atomic.Value // Level
}

// NewController validates opts and returns a Controller ready to be
// added to a controller-runtime manager.
func NewController(opts *Options) (*Controller, error) {
	if opts == nil {
		return nil, errors.New("backpressure: opts is required")
	}
	if opts.Sampler == nil {
		return nil, errors.New("backpressure: Sampler is required")
	}
	if opts.Client == nil {
		return nil, errors.New("backpressure: Client is required")
	}
	if opts.Namespace == "" {
		opts.Namespace = DefaultNamespace
	}
	if opts.ConfigMapName == "" {
		opts.ConfigMapName = DefaultConfigMapName
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.EtcdCapacityBytes == 0 {
		opts.EtcdCapacityBytes = DefaultEtcdCapacityBytes
	}
	if opts.YellowAt == 0 {
		opts.YellowAt = DefaultYellowAt
	}
	if opts.RedAt == 0 {
		opts.RedAt = DefaultRedAt
	}
	if opts.RecoverAt == 0 {
		opts.RecoverAt = DefaultRecoverAt
	}
	if !(opts.RecoverAt < opts.YellowAt && opts.YellowAt < opts.RedAt) {
		return nil, fmt.Errorf("backpressure: invalid thresholds RecoverAt=%.2f YellowAt=%.2f RedAt=%.2f (must be strictly increasing)",
			opts.RecoverAt, opts.YellowAt, opts.RedAt)
	}
	c := &Controller{opts: *opts}
	c.lastLevel.Store(LevelGreen)
	return c, nil
}

// Start implements manager.Runnable. Returns when ctx is cancelled.
func (c *Controller) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("backpressure")
	if err := c.tick(ctx, logger); err != nil {
		logger.Error(err, "initial tick failed; will retry on schedule")
	}
	t := time.NewTicker(c.opts.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := c.tick(ctx, logger); err != nil {
				logger.Error(err, "backpressure tick failed")
			}
		}
	}
}

// NeedLeaderElection reports true so controller-runtime only runs one
// instance cluster-wide.
func (c *Controller) NeedLeaderElection() bool { return true }

// tick runs a single sample → compute → reconcile cycle. Exported via
// the controller surface so tests can drive it deterministically.
func (c *Controller) tick(ctx context.Context, logger interface {
	Info(string, ...any)
},
) error {
	sample, err := c.opts.Sampler.Sample(ctx)
	if err != nil {
		return fmt.Errorf("sample: %w", err)
	}
	prev, _ := c.lastLevel.Load().(Level)
	if prev == "" {
		prev = LevelGreen
	}
	ratio := sample.Ratio(c.opts.EtcdCapacityBytes)
	next := decideLevel(prev, ratio, c.opts.YellowAt, c.opts.RedAt, c.opts.RecoverAt)
	out := buildOutput(next)

	if err := c.applyConfigMap(ctx, out, ratio, sample.UsedBytes); err != nil {
		return fmt.Errorf("apply configmap: %w", err)
	}
	if next != prev {
		logger.Info("backpressure level transition",
			"from", prev, "to", next, "ratio", ratio,
			"usedBytes", sample.UsedBytes, "capacityBytes", c.opts.EtcdCapacityBytes,
		)
		c.lastLevel.Store(next)
	}
	return nil
}

// decideLevel applies the spec's hysteresis: up-escalation is direct
// (Green→Yellow at yellowAt, →Red at redAt); de-escalation steps down
// one tier at a time (Red→Yellow when ratio < redAt; Yellow→Green
// only when ratio < recoverAt) to avoid flapping around the band
// edges.
func decideLevel(prev Level, ratio, yellowAt, redAt, recoverAt float64) Level {
	if ratio >= redAt {
		return LevelRed
	}
	if ratio >= yellowAt {
		return LevelYellow
	}
	switch prev {
	case LevelRed:
		// Step down one tier on the next-lower threshold.
		return LevelYellow
	case LevelYellow:
		if ratio < recoverAt {
			return LevelGreen
		}
		return LevelYellow
	default:
		return LevelGreen
	}
}

// buildOutput maps a Level onto its ConfigMap data fields.
func buildOutput(l Level) Output {
	switch l {
	case LevelRed:
		return Output{
			Level:                   LevelRed,
			EffectiveRateMultiplier: DefaultRateMultiplierRed,
			MinSeverityAccepted:     DefaultMinSeverityRedTier,
		}
	case LevelYellow:
		return Output{
			Level:                   LevelYellow,
			EffectiveRateMultiplier: DefaultRateMultiplierYel,
			MinSeverityAccepted:     DefaultMinSeverityNonRed,
		}
	default:
		return Output{
			Level:                   LevelGreen,
			EffectiveRateMultiplier: DefaultRateMultiplierGreen,
			MinSeverityAccepted:     DefaultMinSeverityNonRed,
		}
	}
}

// applyConfigMap performs an upsert of the backpressure ConfigMap.
// Includes informational diagnostic fields (ratio, usedBytes) so an
// operator can sanity-check the controller's view from `kubectl get`.
func (c *Controller) applyConfigMap(ctx context.Context, out Output, ratio float64, used uint64) error {
	cm := &corev1.ConfigMap{}
	key := types.NamespacedName{Namespace: c.opts.Namespace, Name: c.opts.ConfigMapName}
	getErr := c.opts.Client.Get(ctx, key, cm)

	data := map[string]string{
		FieldLevel:                   string(out.Level),
		FieldEffectiveRateMultiplier: out.EffectiveRateMultiplier,
		FieldMinSeverityAccepted:     out.MinSeverityAccepted,
		"ratio":                      strconv.FormatFloat(ratio, 'f', 4, 64),
		"usedBytes":                  strconv.FormatUint(used, 10),
		"updatedAt":                  metav1.Now().UTC().Format(time.RFC3339),
	}

	switch {
	case apierrors.IsNotFound(getErr):
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      c.opts.ConfigMapName,
				Namespace: c.opts.Namespace,
				Labels: map[string]string{
					"app.kubernetes.io/name":      "ugallu",
					"app.kubernetes.io/component": "backpressure",
				},
			},
			Data: data,
		}
		return c.opts.Client.Create(ctx, cm)
	case getErr != nil:
		return getErr
	default:
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		for k, v := range data {
			cm.Data[k] = v
		}
		return c.opts.Client.Update(ctx, cm)
	}
}

// AddToManager registers the controller as a leader-elected runnable.
func (c *Controller) AddToManager(mgr manager.Manager) error {
	return mgr.Add(c)
}
