// Copyright 2026 The ninsun-labs Authors.
// SPDX-License-Identifier: Apache-2.0

package auditdetection

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// DefaultFileSourceBufferSize is the channel capacity FileSource uses
// when the caller leaves it unset.
const DefaultFileSourceBufferSize = 1024

// FileSourceOpts configures a FileSource.
type FileSourceOpts struct {
	// Path points at the audit-log JSON file (one event per line).
	// Required.
	Path string

	// BufferSize caps the events channel; default
	// DefaultFileSourceBufferSize.
	BufferSize int

	// Log routes diagnostics. nil → discard.
	Log *slog.Logger

	// PollInterval is the fallback polling cadence used when inotify
	// is unavailable (e.g. running on macOS in a unit test). On
	// Linux the watcher does the heavy lifting and this only paces
	// the rotation/EOF retry loop. Default 250ms.
	PollInterval time.Duration
}

// FileSource tails an apiserver audit-log file. It honours rotation
// (the kubelet's logrotate signals via WRITE on a new inode), keeps a
// single file handle until rotation closes the old fd, and delivers
// each line as a parsed AuditEvent on the channel returned by Run.
//
// The implementation is intentionally simple: it does not back-pressure
// the kubelet (the file is shared, the kubelet writes at its own
// pace) but it does back-pressure the engine when the channel fills,
// which slows the file read and is the right behaviour for a single
// node.
type FileSource struct {
	opts FileSourceOpts

	mu       sync.Mutex
	currFile *os.File
	currPath string

	out chan *AuditEvent
}

// NewFileSource validates opts and returns a Source ready for Run.
func NewFileSource(opts *FileSourceOpts) (*FileSource, error) {
	if opts == nil {
		return nil, errors.New("file source: opts is required")
	}
	if opts.Path == "" {
		return nil, errors.New("file source: Path is required")
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultFileSourceBufferSize
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 250 * time.Millisecond
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
	}
	return &FileSource{opts: *opts}, nil
}

// Name reports the source identifier for telemetry.
func (s *FileSource) Name() string { return "file:" + s.opts.Path }

// Run drives the tail loop. It returns a buffered channel; consumers
// drain at their own pace. ctx cancellation triggers a graceful
// shutdown that flushes the in-flight scanner before returning.
func (s *FileSource) Run(ctx context.Context) (<-chan *AuditEvent, error) {
	s.out = make(chan *AuditEvent, s.opts.BufferSize)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("file source: inotify watcher: %w", err)
	}
	if err := watcher.Add(filepath.Dir(s.opts.Path)); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("file source: watch dir %s: %w", filepath.Dir(s.opts.Path), err)
	}
	go s.tail(ctx, watcher)
	return s.out, nil
}

// tail is the main loop: it ensures the current file handle is open,
// drains pending lines, and waits for inotify or a poll tick before
// looping. Rotation is detected by re-stat-ing the path and comparing
// inode numbers (or, on platforms where inode is unstable, by ENOENT
// on the open fd).
func (s *FileSource) tail(ctx context.Context, watcher *fsnotify.Watcher) {
	defer close(s.out)
	defer func() { _ = watcher.Close() }()

	// First open: try the path; if missing, the loop below waits
	// for CREATE before reading.
	if err := s.reopen(); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.opts.Log.Error("file source initial open", "path", s.opts.Path, "err", err)
	}

	pollTick := time.NewTicker(s.opts.PollInterval)
	defer pollTick.Stop()

	for {
		// Drain whatever is currently buffered. A fresh Scanner is
		// constructed each iteration: bufio.Scanner stays "done"
		// after the first false Scan(), so reusing it would miss
		// every line appended after the previous EOF. The fd's read
		// position survives across scanners, so a new Scanner
		// continues reading from where the previous one stopped.
		if scanner := s.scanner(); scanner != nil {
			s.drainLines(ctx, scanner)
			if ctx.Err() != nil {
				return
			}
			if rotated := s.detectRotation(); rotated {
				if err := s.reopen(); err != nil {
					s.opts.Log.Warn("file source reopen after rotation", "err", err)
				}
				continue
			}
		}
		// Wait for the next signal.
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			// The kubelet writes via Append; the source reacts to
			// Write, Create (rotation: new file appears), and
			// Rename (rotation: old file vanishes).
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			if filepath.Base(ev.Name) != filepath.Base(s.opts.Path) {
				continue
			}
			if ev.Op&(fsnotify.Create|fsnotify.Rename) != 0 {
				if err := s.reopen(); err != nil {
					s.opts.Log.Warn("file source reopen on watch event", "err", err)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			s.opts.Log.Warn("file source watcher error", "err", err)
		case <-pollTick.C:
			if s.currentFD() == nil {
				if err := s.reopen(); err != nil && !errors.Is(err, os.ErrNotExist) {
					s.opts.Log.Debug("file source poll reopen", "err", err)
				}
			}
		}
	}
}

// drainLines reads every line currently buffered into scanner and
// pushes one AuditEvent per JSON line. Malformed lines bump
// fileSourceParseErrors and are dropped silently.
func (s *FileSource) drainLines(ctx context.Context, scanner *bufio.Scanner) {
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		ev := &AuditEvent{Raw: append([]byte(nil), line...)}
		if err := json.Unmarshal(line, ev); err != nil {
			fileSourceParseErrors.Inc()
			continue
		}
		select {
		case s.out <- ev:
			fileSourceLines.Inc()
		case <-ctx.Done():
			return
		}
	}
}

// scanner returns a Scanner over the currently open file, or nil
// when no file is open. Constructed fresh on every loop iteration so
// the EOF/sticky-done semantics of bufio.Scanner don't hide newly
// appended lines.
func (s *FileSource) scanner() *bufio.Scanner {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currFile == nil {
		return nil
	}
	sc := bufio.NewScanner(s.currFile)
	// Audit lines can be large (RequestObject + ResponseObject); raise
	// the buffer ceiling well above the default 64K.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return sc
}

// currentFD reports the cached open file (or nil). Used by the
// poll-tick branch to decide whether to attempt a reopen.
func (s *FileSource) currentFD() *os.File {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currFile
}

// reopen closes the current handle (if any) and opens the configured
// path. The caller is expected to refresh its scanner afterwards.
func (s *FileSource) reopen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currFile != nil {
		_ = s.currFile.Close()
		s.currFile = nil
	}
	f, err := os.Open(s.opts.Path) //nolint:gosec // Path is operator-controlled config
	if err != nil {
		return err
	}
	if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
		_ = f.Close()
		return fmt.Errorf("seek: %w", seekErr)
	}
	s.currFile = f
	s.currPath = s.opts.Path
	return nil
}

// detectRotation re-stats the configured path and compares its inode
// against the open fd's inode. A mismatch (or ENOENT on the path)
// signals rotation.
func (s *FileSource) detectRotation() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currFile == nil {
		return false
	}
	pathStat, err := os.Stat(s.currPath)
	if err != nil {
		return true // assume rotation on stat failure
	}
	fdStat, err := s.currFile.Stat()
	if err != nil {
		return true
	}
	return !sameInode(pathStat, fdStat)
}
