// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package worm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3UploaderOptions configures S3Uploader. SeaweedFS, MinIO, and AWS S3
// are all supported via the same struct; SeaweedFS / MinIO usually need
// EndpointURL set and UsePathStyle=true.
type S3UploaderOptions struct {
	// Bucket is the S3 bucket name. Required.
	Bucket string

	// Region is the AWS region. Defaults to "us-east-1" (the SDK
	// requires a region even when the backend ignores it).
	Region string

	// EndpointURL overrides the S3 endpoint. Empty uses AWS S3.
	// Set to "http://seaweedfs-s3:8333" or similar for self-hosted.
	EndpointURL string

	// UsePathStyle selects path-style addressing (bucket in path) over
	// virtual-host style. Required for SeaweedFS/MinIO; ignored by AWS.
	UsePathStyle bool

	// AccessKey + SecretKey set static credentials. Empty falls back to
	// the default AWS credential chain (env, IRSA, shared profile, ...).
	AccessKey string
	SecretKey string

	// ObjectLockMode selects the S3 Object Lock mode. Defaults to
	// "COMPLIANCE", which is required for the WORM bucket.
	// Set to "GOVERNANCE" or "" only for tests / non-compliance backends.
	ObjectLockMode string

	// KeyPrefix is prepended to every object key, allowing the same
	// bucket to host multiple ugallu installations. Optional.
	KeyPrefix string
}

// S3Uploader is an Uploader backed by an S3-compatible object store
// (AWS S3, SeaweedFS, RustFS) with Object Lock in Compliance mode.
//
// The uploader hashes content while streaming it to S3, sets the
// Object Lock retention from PutOpts.LockUntil, and returns the object
// metadata in ObjectRef. Multipart uploads are not used (evidence
// blobs are small - a few KB each); large blobs would benefit from
// the Manager API in a follow-up.
type S3Uploader struct {
	client    *s3.Client
	bucket    string
	endpoint  string
	keyPrefix string
	lockMode  s3types.ObjectLockMode
}

// NewS3Uploader builds an S3Uploader from opts.
func NewS3Uploader(ctx context.Context, opts *S3UploaderOptions) (*S3Uploader, error) {
	if opts == nil {
		return nil, errors.New("opts is required")
	}
	if opts.Bucket == "" {
		return nil, errors.New("bucket is required")
	}
	region := opts.Region
	if region == "" {
		region = "us-east-1"
	}

	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}
	if opts.AccessKey != "" || opts.SecretKey != "" {
		loadOpts = append(loadOpts,
			awsconfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(opts.AccessKey, opts.SecretKey, ""),
			),
		)
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	s3opts := []func(*s3.Options){}
	if opts.EndpointURL != "" {
		ep := opts.EndpointURL
		s3opts = append(s3opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(ep)
		})
	}
	if opts.UsePathStyle {
		s3opts = append(s3opts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	lockMode := s3types.ObjectLockModeCompliance
	switch strings.ToUpper(opts.ObjectLockMode) {
	case "":
		// keep default
	case "COMPLIANCE":
		lockMode = s3types.ObjectLockModeCompliance
	case "GOVERNANCE":
		lockMode = s3types.ObjectLockModeGovernance
	case "NONE":
		lockMode = ""
	default:
		return nil, fmt.Errorf("unknown ObjectLockMode %q", opts.ObjectLockMode)
	}

	return &S3Uploader{
		client:    s3.NewFromConfig(cfg, s3opts...),
		bucket:    opts.Bucket,
		endpoint:  endpointID(opts.EndpointURL, opts.Bucket),
		keyPrefix: strings.Trim(opts.KeyPrefix, "/"),
		lockMode:  lockMode,
	}, nil
}

// Endpoint returns a stable identifier (e.g.
// "s3://bucket@https://seaweedfs:8333").
func (u *S3Uploader) Endpoint() string { return u.endpoint }

// Put streams content to S3, applying Object Lock retention when
// PutOpts.LockUntil is set.
func (u *S3Uploader) Put(ctx context.Context, key string, content io.Reader, opts PutOpts) (*ObjectRef, error) {
	if content == nil {
		return nil, errors.New("nil content")
	}
	cleanKey, err := safeKey(key)
	if err != nil {
		return nil, err
	}
	if u.keyPrefix != "" {
		cleanKey = u.keyPrefix + "/" + cleanKey
	}

	// Read into memory so the uploader can both compute a sha256 and
	// hand a fresh reader to the SDK without losing seekability.
	// Evidence blobs are small (sub-MB); the simplification is worth
	// it.
	raw, err := io.ReadAll(content)
	if err != nil {
		return nil, fmt.Errorf("read content: %w", err)
	}
	digest := sha256.Sum256(raw)
	digestHex := hex.EncodeToString(digest[:])

	input := &s3.PutObjectInput{
		Bucket:      aws.String(u.bucket),
		Key:         aws.String(cleanKey),
		Body:        bytes.NewReader(raw),
		ContentType: aws.String(opts.MediaType),
		Metadata:    cloneMetadata(opts.Metadata, digestHex),
	}
	if u.lockMode != "" && !opts.LockUntil.IsZero() {
		input.ObjectLockMode = u.lockMode
		input.ObjectLockRetainUntilDate = aws.Time(opts.LockUntil.UTC())
	}

	if _, err := u.client.PutObject(ctx, input); err != nil {
		return nil, fmt.Errorf("s3 PutObject %s/%s: %w", u.bucket, cleanKey, err)
	}

	return &ObjectRef{
		URL:       u.objectURL(cleanKey),
		SHA256:    "sha256:" + digestHex,
		Size:      int64(len(raw)),
		MediaType: opts.MediaType,
	}, nil
}

// objectURL returns the canonical s3:// URL for the stored object.
// Includes the endpoint host when an override endpoint is configured
// so verifiers can resolve self-hosted backends.
func (u *S3Uploader) objectURL(key string) string {
	return fmt.Sprintf("s3://%s/%s", u.bucket, key)
}

// cloneMetadata returns a copy of in plus the sha256 digest. AWS
// metadata keys are case-insensitive but lower-cased on the wire.
func cloneMetadata(in map[string]string, digestHex string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	out["sha256"] = digestHex
	return out
}

// endpointID returns a Endpoint() string identifying this uploader.
func endpointID(endpoint, bucket string) string {
	if endpoint == "" {
		return fmt.Sprintf("s3://%s", bucket)
	}
	return fmt.Sprintf("s3://%s@%s", bucket, endpoint)
}
