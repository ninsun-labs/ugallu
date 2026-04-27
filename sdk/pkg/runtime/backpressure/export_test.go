// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package backpressure

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// TickForTest drives a single sample/compute/reconcile cycle without
// the goroutine + ticker around it. Exported only to *_test.go via the
// package_test convention.
func TickForTest(ctx context.Context, c *Controller) error {
	return c.tick(ctx, log.FromContext(ctx))
}
