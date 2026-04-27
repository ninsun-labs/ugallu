// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package backpressure implements the cluster-wide backpressure
// controller from design 16. It samples kube-apiserver storage usage,
// computes a Green/Yellow/Red level, and reconciles a ConfigMap
// (default ugallu-backpressure in ugallu-system) consumed by every SDK
// emitter to throttle SecurityEvent emission before etcd saturates.
package backpressure
