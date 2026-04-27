// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package backpressure_test

import (
	"context"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/ninsun-labs/ugallu/sdk/pkg/runtime/backpressure"
)

// fakeSampler returns successive UsedBytes values from a slice. Once
// exhausted it keeps returning the last value.
type fakeSampler struct {
	idx     atomic.Int32
	samples []uint64
}

func (f *fakeSampler) Sample(_ context.Context) (backpressure.Sample, error) {
	i := int(f.idx.Add(1)) - 1
	if i >= len(f.samples) {
		i = len(f.samples) - 1
	}
	return backpressure.Sample{UsedBytes: f.samples[i]}, nil
}

func newK8sClient() client.Client {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).Build()
}

func mustController(t *testing.T, sampler backpressure.Sampler, c client.Client, capBytes uint64) *backpressure.Controller {
	t.Helper()
	ctrl, err := backpressure.NewController(&backpressure.Options{
		Sampler:           sampler,
		Client:            c,
		Namespace:         "ugallu-system",
		EtcdCapacityBytes: capBytes,
	})
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	return ctrl
}

func readCM(t *testing.T, c client.Client) *corev1.ConfigMap {
	t.Helper()
	cm := &corev1.ConfigMap{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Namespace: "ugallu-system",
		Name:      backpressure.DefaultConfigMapName,
	}, cm); err != nil {
		t.Fatalf("get cm: %v", err)
	}
	return cm
}

// TestController_RejectsBadOptions exercises the constructor guards.
func TestController_RejectsBadOptions(t *testing.T) {
	cases := []struct {
		name string
		opts *backpressure.Options
	}{
		{"nil opts", nil},
		{"nil sampler", &backpressure.Options{Client: newK8sClient()}},
		{"nil client", &backpressure.Options{Sampler: &fakeSampler{samples: []uint64{1}}}},
		{"non-monotonic thresholds", &backpressure.Options{
			Sampler: &fakeSampler{samples: []uint64{1}}, Client: newK8sClient(),
			YellowAt: 0.95, RedAt: 0.90, RecoverAt: 0.50,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := backpressure.NewController(tc.opts); err == nil {
				t.Errorf("NewController accepted invalid opts %+v", tc.opts)
			}
		})
	}
}

// TestController_GreenStaysGreen verifies the steady state at low usage.
func TestController_GreenStaysGreen(t *testing.T) {
	c := newK8sClient()
	capBytes := uint64(1000)
	sampler := &fakeSampler{samples: []uint64{100}} // 10% usage
	ctrl := mustController(t, sampler, c, capBytes)

	if err := backpressure.TickForTest(ctx(), ctrl); err != nil {
		t.Fatalf("tick: %v", err)
	}
	cm := readCM(t, c)
	if cm.Data[backpressure.FieldLevel] != string(backpressure.LevelGreen) {
		t.Errorf("level = %q, want Green", cm.Data[backpressure.FieldLevel])
	}
	if cm.Data[backpressure.FieldEffectiveRateMultiplier] != backpressure.DefaultRateMultiplierGreen {
		t.Errorf("multiplier = %q, want %q", cm.Data[backpressure.FieldEffectiveRateMultiplier], backpressure.DefaultRateMultiplierGreen)
	}
}

// TestController_GreenToYellowToRed walks the up-escalation path.
func TestController_GreenToYellowToRed(t *testing.T) {
	c := newK8sClient()
	capBytes := uint64(1000)
	sampler := &fakeSampler{samples: []uint64{
		100, // 10% → Green
		750, // 75% → Yellow (>= 0.70)
		950, // 95% → Red    (>= 0.90)
	}}
	ctrl := mustController(t, sampler, c, capBytes)

	wants := []backpressure.Level{backpressure.LevelGreen, backpressure.LevelYellow, backpressure.LevelRed}
	for i, want := range wants {
		if err := backpressure.TickForTest(ctx(), ctrl); err != nil {
			t.Fatalf("tick #%d: %v", i, err)
		}
		got := readCM(t, c).Data[backpressure.FieldLevel]
		if got != string(want) {
			t.Errorf("tick #%d level = %q, want %q", i, got, want)
		}
	}
}

// TestController_RecoverAppliesHysteresis confirms a sample at 60% (in
// the [recoverAt, yellowAt] band) does NOT drop the controller back
// to Green — only sub-recoverAt readings demote.
func TestController_RecoverAppliesHysteresis(t *testing.T) {
	c := newK8sClient()
	capBytes := uint64(1000)
	sampler := &fakeSampler{samples: []uint64{
		950, // 95% → Red
		600, // 60% → must STAY at Yellow (above RecoverAt 0.50)
		400, // 40% → Green
	}}
	ctrl := mustController(t, sampler, c, capBytes)

	for i, want := range []backpressure.Level{
		backpressure.LevelRed,
		backpressure.LevelYellow,
		backpressure.LevelGreen,
	} {
		if err := backpressure.TickForTest(ctx(), ctrl); err != nil {
			t.Fatalf("tick #%d: %v", i, err)
		}
		got := readCM(t, c).Data[backpressure.FieldLevel]
		if got != string(want) {
			t.Errorf("tick #%d level = %q, want %q", i, got, want)
		}
	}
}

// TestController_UpsertExistingConfigMap covers the path where a CM
// already exists (operator-managed): controller must update rather
// than try to recreate.
func TestController_UpsertExistingConfigMap(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	pre := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      backpressure.DefaultConfigMapName,
			Namespace: "ugallu-system",
		},
		Data: map[string]string{"hand-set": "yes"},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pre).Build()

	sampler := &fakeSampler{samples: []uint64{50}}
	ctrl := mustController(t, sampler, c, 1000)
	if err := backpressure.TickForTest(ctx(), ctrl); err != nil {
		t.Fatalf("tick: %v", err)
	}
	cm := readCM(t, c)
	if cm.Data[backpressure.FieldLevel] != string(backpressure.LevelGreen) {
		t.Errorf("level not written to existing CM: %v", cm.Data)
	}
	if cm.Data["hand-set"] != "yes" {
		t.Error("upsert wiped existing keys")
	}
}

func ctx() context.Context { return context.Background() }
