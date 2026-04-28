// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Package snapshot is the forensics-snapshot binary's library half.
// It tar+gzip-streams a target Pod's filesystem (read in-process via
// /proc/<pid>/root) into an S3-compatible WORM bucket using a
// multipart upload, computes the sha256 of the payload in-flight, and
// writes a structured Result to a caller-supplied Writer (stdout in
// the cmd path) so the operator can ingest evidence references
// without resorting to log scraping.
//
// Memory budget is bounded by the multipart part-size (5 MiB
// default) regardless of the snapshot total size — the entire
// pipeline is `io.Pipe`-based, no temp files on disk.
package snapshot

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	tmtypes "github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// DefaultPartSize is the multipart-upload chunk size. 5 MiB is the
// AWS minimum for non-final parts and bounds peak memory at
// PartSize * Concurrency = 5 MiB * 5 = 25 MiB by default.
const DefaultPartSize = 5 * 1024 * 1024

// DefaultConcurrency is the per-upload parallelism passed to the
// AWS multipart manager.
const DefaultConcurrency = 5

// DefaultTimeout caps the total snapshot duration.
const DefaultTimeout = 5 * time.Minute

// DefaultMaxBytes is the upload-size ceiling. The pipeline aborts
// the upload (clean multipart abort, no orphan parts) once the
// streamed byte count exceeds this value, marking the result
// Truncated=true.
const DefaultMaxBytes int64 = 2 * 1024 * 1024 * 1024 // 2 GiB

// Options configures a single Run() invocation.
type Options struct {
	// Paths are the on-disk roots to tar. The default targets the
	// suspect container's filesystem view via /proc/<pid>/root.
	Paths []string

	// ExcludeGlobs are filepath.Match patterns evaluated against the
	// in-tar header name. Matching entries are skipped (not recursed
	// into for directories).
	ExcludeGlobs []string

	// MaxBytes is the streamed-payload ceiling; defaults to 2 GiB.
	MaxBytes int64

	// Timeout is the total Run() duration cap; defaults to 5 minutes.
	Timeout time.Duration

	// S3 destination ----------------------------------------------------
	Bucket       string
	Region       string
	Endpoint     string
	UsePathStyle bool
	AccessKey    string
	SecretKey    string
	Key          string

	// LockMode + LockUntil set Object Lock retention. Empty LockMode
	// or zero LockUntil disables retention (lab/dev). Production
	// targets COMPLIANCE per design 07 W2.
	LockMode  string
	LockUntil time.Time

	// PartSize + Concurrency override the multipart-manager defaults.
	PartSize    int64
	Concurrency int

	// Now is injectable for tests; defaults to time.Now.
	Now func() time.Time
}

// Result is the JSON-serialisable summary written to stdout. The
// operator deserialises it from the ephemeral container's logs.
type Result struct {
	URL        string `json:"url"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	DurationMS int64  `json:"durationMs"`
	Truncated  bool   `json:"truncated"`
	MediaType  string `json:"mediaType"`
}

// Runner executes one snapshot end-to-end.
type Runner struct {
	opts Options
}

// New validates opts and returns a Runner.
func New(opts *Options) (*Runner, error) {
	if opts == nil {
		return nil, errors.New("snapshot: opts is required")
	}
	if opts.Bucket == "" {
		return nil, errors.New("snapshot: Bucket is required")
	}
	if opts.Key == "" {
		return nil, errors.New("snapshot: Key is required")
	}
	if len(opts.Paths) == 0 {
		return nil, errors.New("snapshot: at least one Path is required")
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.PartSize <= 0 {
		opts.PartSize = DefaultPartSize
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Runner{opts: *opts}, nil
}

// Run drives the tar → gzip → sha256 → S3 multipart pipeline. The
// returned Result describes the uploaded object even when truncated
// (the partial blob is retained so the operator can flag the SE as
// IncidentCaptureFailed with reason=truncated).
func (r *Runner) Run(ctx context.Context) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
	defer cancel()

	uploader, err := r.newUploader(ctx)
	if err != nil {
		return nil, fmt.Errorf("uploader: %w", err)
	}

	pr, pw := io.Pipe()
	hasher := sha256.New()
	sink := &capWriter{
		w:        io.MultiWriter(pw, hasher),
		max:      r.opts.MaxBytes,
		canceler: cancel,
	}

	start := r.opts.Now()
	tarErrCh := make(chan error, 1)
	go func() {
		tarErrCh <- r.streamTar(ctx, sink)
		// Always close the write side; otherwise the uploader blocks
		// forever waiting for EOF.
		_ = pw.Close()
	}()

	putInput := &transfermanager.UploadObjectInput{
		Bucket:      aws.String(r.opts.Bucket),
		Key:         aws.String(r.opts.Key),
		Body:        pr,
		ContentType: aws.String("application/x-tar+gzip"),
	}
	if mode := r.objectLockMode(); mode != "" && !r.opts.LockUntil.IsZero() {
		putInput.ObjectLockMode = mode
		putInput.ObjectLockRetainUntilDate = aws.Time(r.opts.LockUntil.UTC())
	}

	_, upErr := uploader.UploadObject(ctx, putInput)

	// Drain the tar-side error if the writer goroutine finished first.
	tarErr := <-tarErrCh

	truncated := errors.Is(tarErr, errSizeCap) || errors.Is(upErr, errSizeCap)
	switch {
	case truncated:
		// The size cap aborted the pipeline — the partial multipart
		// upload was cleanly aborted by the manager when the body
		// reader returned the cap error; nothing else to clean up.
	case upErr != nil:
		return nil, fmt.Errorf("s3 upload: %w", upErr)
	case tarErr != nil:
		return nil, fmt.Errorf("tar stream: %w", tarErr)
	}

	dur := r.opts.Now().Sub(start)
	return &Result{
		URL:        fmt.Sprintf("s3://%s/%s", r.opts.Bucket, r.opts.Key),
		SHA256:     "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		Size:       sink.bytesWritten,
		DurationMS: dur.Milliseconds(),
		Truncated:  truncated,
		MediaType:  "application/x-tar+gzip",
	}, nil
}

// newUploader builds a transfermanager.Client against the configured
// S3 endpoint. Endpoint + path-style support keep the binary
// compatible with SeaweedFS / MinIO without code changes.
func (r *Runner) newUploader(ctx context.Context) (*transfermanager.Client, error) {
	region := r.opts.Region
	if region == "" {
		region = "us-east-1"
	}
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(region),
	}
	if r.opts.AccessKey != "" || r.opts.SecretKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(r.opts.AccessKey, r.opts.SecretKey, ""),
		))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	s3opts := []func(*s3.Options){}
	if r.opts.Endpoint != "" {
		ep := r.opts.Endpoint
		s3opts = append(s3opts, func(o *s3.Options) { o.BaseEndpoint = aws.String(ep) })
	}
	if r.opts.UsePathStyle {
		s3opts = append(s3opts, func(o *s3.Options) { o.UsePathStyle = true })
	}
	client := s3.NewFromConfig(cfg, s3opts...)
	return transfermanager.New(client, func(o *transfermanager.Options) {
		o.PartSizeBytes = r.opts.PartSize
		o.Concurrency = r.opts.Concurrency
	}), nil
}

func (r *Runner) objectLockMode() tmtypes.ObjectLockMode {
	switch strings.ToUpper(r.opts.LockMode) {
	case "COMPLIANCE":
		return tmtypes.ObjectLockModeCompliance
	case "GOVERNANCE":
		return tmtypes.ObjectLockModeGovernance
	}
	return ""
}

// streamTar walks the configured Paths and writes each entry through
// the gzip + tar writers. Size cap is enforced by capWriter; any
// errSizeCap return aborts the pipeline cleanly.
func (r *Runner) streamTar(ctx context.Context, w io.Writer) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	defer func() {
		_ = tw.Close()
		_ = gz.Close()
	}()

	for _, root := range r.opts.Paths {
		if err := r.walkRoot(ctx, tw, root); err != nil {
			return err
		}
	}
	return nil
}

// walkRoot tar-walks a single root path, pruning excluded entries and
// honouring ctx cancellation (timeout / size-cap abort).
func (r *Runner) walkRoot(ctx context.Context, tw *tar.Writer, root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Soft fail on per-entry errors (broken symlinks, racing
			// deletes inside /proc/*/root). Skip and keep going.
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		header := filepath.Join(filepath.Base(root), rel)
		if r.excluded(header) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}

		var link string
		if info.Mode()&os.ModeSymlink != 0 {
			link, err = os.Readlink(path)
			if err != nil {
				return nil
			}
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return nil
		}
		hdr.Name = header
		if writeErr := tw.WriteHeader(hdr); writeErr != nil {
			return writeErr
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		f, err := os.Open(path) //nolint:gosec // path is operator-controlled (forensics inputs)
		if err != nil {
			return nil
		}
		_, copyErr := io.Copy(tw, f)
		_ = f.Close()
		return copyErr
	})
}

// excluded reports whether name matches any configured exclude glob.
func (r *Runner) excluded(name string) bool {
	for _, g := range r.opts.ExcludeGlobs {
		if ok, _ := filepath.Match(g, name); ok {
			return true
		}
	}
	return false
}

// errSizeCap is the sentinel returned when MaxBytes is exceeded.
var errSizeCap = errors.New("snapshot: payload exceeded MaxBytes")

// capWriter is an io.Writer that enforces a byte cap and cancels its
// owning ctx when the cap is hit.
type capWriter struct {
	w            io.Writer
	max          int64
	bytesWritten int64
	canceler     context.CancelFunc
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.bytesWritten+int64(len(p)) > c.max {
		// Emit whatever fits before the cap, then cancel.
		fits := c.max - c.bytesWritten
		if fits > 0 {
			n, err := c.w.Write(p[:fits])
			c.bytesWritten += int64(n)
			if err != nil {
				return n, err
			}
		}
		c.canceler()
		return int(c.max - c.bytesWritten), errSizeCap
	}
	n, err := c.w.Write(p)
	c.bytesWritten += int64(n)
	return n, err
}

// EncodeResult writes r as a single JSON object terminated by '\n' to
// the supplied writer. Used by the cmd binary so the operator can
// parse the ephemeral container's logs deterministically.
func EncodeResult(w io.Writer, r *Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "")
	return enc.Encode(r)
}
