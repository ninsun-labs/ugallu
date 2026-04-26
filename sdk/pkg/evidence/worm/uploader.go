// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package worm

import (
	"context"
	"io"
	"time"
)

// Uploader writes immutable blobs to a WORM backend and returns an
// ObjectRef the bundle Status can reference.
type Uploader interface {
	// Put streams content to the backend under the given key. The
	// returned ObjectRef carries the canonical URL, the sha256 digest
	// (computed by the uploader for integrity), and the size in bytes.
	Put(ctx context.Context, key string, content io.Reader, opts PutOpts) (*ObjectRef, error)

	// Endpoint returns a stable identifier of the backend, e.g.
	// "s3://ugallu-worm" or "stub:dev:/tmp/ugallu-worm".
	Endpoint() string
}

// PutOpts configures a single Put.
type PutOpts struct {
	// LockUntil is the earliest time the object may be deleted. The
	// real S3 implementation maps this to Object Lock retention in
	// Compliance mode (design 07 W2). The stub stores the value but
	// does not enforce it.
	LockUntil time.Time

	// MediaType is the Content-Type of the payload.
	MediaType string

	// Metadata are user-defined key=value tags to attach to the object
	// (e.g. clusterID, sha256, parentBundleUID).
	Metadata map[string]string
}

// ObjectRef describes one immutably-stored blob.
type ObjectRef struct {
	// URL is the canonical reference to the blob (e.g. "s3://bucket/key"
	// or "file:///path"). It is what the bundle Status records.
	URL string

	// SHA256 is the hex-encoded sha256 of the payload, prefixed with
	// "sha256:".
	SHA256 string

	// Size is the payload size in bytes.
	Size int64

	// MediaType echoes the PutOpts.MediaType for callers that need to
	// re-stream the blob.
	MediaType string
}
