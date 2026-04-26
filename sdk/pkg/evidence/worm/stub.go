// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package worm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// StubUploader is a filesystem-backed Uploader for dev / test. Blobs are
// written under a single base directory; LockUntil is recorded in a
// sidecar metadata file but NOT enforced (the host filesystem has no
// Object Lock notion). Production deployments must use S3Uploader once
// it lands.
type StubUploader struct {
	baseDir string
}

// NewStubUploader returns an Uploader backed by baseDir. The directory
// is created if missing.
func NewStubUploader(baseDir string) (*StubUploader, error) {
	if baseDir == "" {
		return nil, errors.New("baseDir is required")
	}
	if err := os.MkdirAll(baseDir, 0o750); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", baseDir, err)
	}
	return &StubUploader{baseDir: baseDir}, nil
}

// Put writes the content under baseDir/key and returns the ObjectRef.
func (u *StubUploader) Put(_ context.Context, key string, content io.Reader, opts PutOpts) (*ObjectRef, error) {
	if content == nil {
		return nil, errors.New("nil content")
	}
	clean, err := safeKey(key)
	if err != nil {
		return nil, err
	}
	target := filepath.Join(u.baseDir, clean)
	if err = os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return nil, fmt.Errorf("mkdir parent: %w", err)
	}

	hash := sha256.New()
	tee := io.TeeReader(content, hash)

	// target is u.baseDir + safeKey(key); safeKey rejects absolute paths
	// and any '..' segments, so traversal outside u.baseDir is prevented.
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G304: safeKey() prevents traversal
	if err != nil {
		return nil, fmt.Errorf("open target: %w", err)
	}

	n, err := io.Copy(f, tee)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(target)
		return nil, fmt.Errorf("write: %w", err)
	}
	if err = f.Close(); err != nil {
		return nil, fmt.Errorf("close target: %w", err)
	}

	digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	return &ObjectRef{
		URL:       "file://" + target,
		SHA256:    digest,
		Size:      n,
		MediaType: opts.MediaType,
	}, nil
}

// Endpoint returns the stub's identifier.
func (u *StubUploader) Endpoint() string {
	return "stub:dev:" + u.baseDir
}

// safeKey rejects path traversal attempts and forbids absolute paths.
// Any "../" segment in the input is rejected even if it cleans to an
// in-base path (defense in depth).
func safeKey(key string) (string, error) {
	if key == "" {
		return "", errors.New("empty key")
	}
	if filepath.IsAbs(key) {
		return "", fmt.Errorf("absolute key %q not allowed", key)
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return "", fmt.Errorf("unsafe key %q (contains '..' segment)", key)
		}
	}
	clean := filepath.Clean(key)
	if clean == "." {
		return "", fmt.Errorf("unsafe key %q", key)
	}
	return clean, nil
}
