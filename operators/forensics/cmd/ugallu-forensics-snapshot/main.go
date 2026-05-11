// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

// Command ugallu-forensics-snapshot is the in-process tar+gzip
// streamer the forensics operator injects as an ephemeral debug
// container in suspect Pods. The binary reads /proc/<pid>/root (and
// any extra paths passed via --paths), pipes the tar stream through
// gzip + sha256 + S3 multipart upload, and writes a single JSON
// Result line to stdout for the operator to parse.
//
// Memory budget is bounded by the multipart part-size; no temp
// files are written to disk. SIGTERM (sent by the kubelet on
// snapshot timeout) cancels the context, which the manager
// translates into a clean multipart-abort - no orphan parts.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ninsun-labs/ugallu/operators/forensics/pkg/snapshot"
)

const exitFailure = 1

func main() {
	step, err := runMain()
	if err == nil {
		return
	}
	// Emit a JSON failure record on stdout so the operator can
	// parse it from the ephemeral container's logs and surface
	// the (step, error) tuple on the IncidentCaptureFailed SE.
	// Stderr keeps the human-friendly prefix for kubectl log
	// readers; stdout is the machine-parsed channel.
	if encErr := snapshot.EncodeFailure(os.Stdout, snapshot.FailureFromError(err, step)); encErr != nil {
		fmt.Fprintln(os.Stderr, "ugallu-forensics-snapshot: emit failure:", encErr)
	}
	fmt.Fprintln(os.Stderr, "ugallu-forensics-snapshot:", err)
	os.Exit(exitFailure)
}

// runMain returns (defaultStep, err). The defaultStep is used when
// err is not already wrapped in a snapshot.StepError - it labels
// the early validation phase that produced the failure.
func runMain() (string, error) {
	var (
		targetPID    int
		paths        stringSlice
		excludeGlobs stringSlice
		maxBytes     int64
		timeout      time.Duration
		bucket       string
		region       string
		endpoint     string
		usePathStyle bool
		key          string
		accessKeyEnv string
		secretKeyEnv string
		lockMode     string
		lockUntil    time.Duration
		partSize     int64
		concurrency  int
	)
	flag.IntVar(&targetPID, "target-pid", 1, "PID inside the suspect container (defaults to PID 1, the container's init process)")
	flag.Var(&paths, "paths", "Filesystem paths to capture; repeat the flag for multiple (defaults to /proc/<target-pid>/root)")
	flag.Var(&excludeGlobs, "exclude-glob", "filepath.Match pattern excluded from the tar; repeat for multiple")
	flag.Int64Var(&maxBytes, "max-bytes", snapshot.DefaultMaxBytes, "Cap on streamed payload size; aborts the upload with truncated=true on overflow")
	flag.DurationVar(&timeout, "timeout", snapshot.DefaultTimeout, "Total snapshot duration cap")
	flag.StringVar(&bucket, "worm-bucket", "", "WORM S3 bucket name (required)")
	flag.StringVar(&region, "worm-region", "us-east-1", "WORM S3 region (sent in headers; ignored by self-hosted backends)")
	flag.StringVar(&endpoint, "worm-endpoint", "", "WORM S3 endpoint override (e.g. https://seaweedfs:8333)")
	flag.BoolVar(&usePathStyle, "worm-path-style", true, "Use path-style addressing (required for SeaweedFS / MinIO)")
	flag.StringVar(&key, "worm-key", "", "S3 object key for the snapshot blob (required)")
	flag.StringVar(&accessKeyEnv, "worm-access-key-env", "WORM_ACCESS_KEY", "Env var name carrying the access key")
	flag.StringVar(&secretKeyEnv, "worm-secret-key-env", "WORM_SECRET_KEY", "Env var name carrying the secret key")
	flag.StringVar(&lockMode, "lock-mode", "COMPLIANCE", "Object Lock mode: COMPLIANCE / GOVERNANCE / NONE")
	flag.DurationVar(&lockUntil, "lock-until", 168*time.Hour, "Object Lock retention duration from now (e.g. 168h = 7d)")
	flag.Int64Var(&partSize, "part-size", snapshot.DefaultPartSize, "Multipart upload part size in bytes")
	flag.IntVar(&concurrency, "concurrency", snapshot.DefaultConcurrency, "Multipart upload parallelism")
	flag.Parse()

	if bucket == "" {
		return "config", fmt.Errorf("--worm-bucket is required")
	}
	if key == "" {
		return "config", fmt.Errorf("--worm-key is required")
	}
	if len(paths) == 0 {
		paths = stringSlice{"/proc/" + strconv.Itoa(targetPID) + "/root"}
	}

	accessKey := strings.TrimSpace(os.Getenv(accessKeyEnv))
	secretKey := strings.TrimSpace(os.Getenv(secretKeyEnv))
	if accessKey == "" || secretKey == "" {
		return "creds", fmt.Errorf("WORM credentials missing: env %s and %s must both be set", accessKeyEnv, secretKeyEnv)
	}

	runner, err := snapshot.New(&snapshot.Options{
		Paths:        paths,
		ExcludeGlobs: excludeGlobs,
		MaxBytes:     maxBytes,
		Timeout:      timeout,
		Bucket:       bucket,
		Region:       region,
		Endpoint:     endpoint,
		UsePathStyle: usePathStyle,
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		Key:          key,
		LockMode:     lockMode,
		LockUntil:    time.Now().Add(lockUntil),
		PartSize:     partSize,
		Concurrency:  concurrency,
	})
	if err != nil {
		return "config", err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	res, err := runner.Run(ctx)
	if err != nil {
		// runner.Run wraps every error in StepError; FailureFromError
		// pulls out the right step. The "run" default below is a
		// safety net for any future error path that forgets to wrap.
		return "run", err
	}
	if encErr := snapshot.EncodeResult(os.Stdout, res); encErr != nil {
		return "encode", encErr
	}
	return "", nil
}

// stringSlice implements flag.Value so multi-arg --paths /
// --exclude-glob behave like in `kubectl --port-forward`.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }
