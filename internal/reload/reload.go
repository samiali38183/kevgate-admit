// Package reload keeps a parsed copy of a file in memory and swaps it
// atomically when the file changes. A file that fails to parse never replaces
// the last good copy.
package reload

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"
)

// Observer receives the outcome of every reload attempt.
type Observer interface {
	Reloaded(component string, err error)
}

// File is a hot-reloaded, parsed file.
type File[T any] struct {
	name     string
	path     string
	maxBytes int64
	parse    func([]byte) (*T, error)
	obs      Observer

	// Optional companion file (a detached signature). When set, check must
	// accept the pair before the content is parsed, and a change to the
	// companion alone triggers a new attempt.
	companion string
	check     func(data, companion []byte) error

	cur   atomic.Pointer[T]
	state atomic.Pointer[fileState]
	bad   atomic.Pointer[fileState]
}

type fileState struct {
	mtime time.Time
	size  int64
	sum   [sha256.Size]byte
	cm    time.Time // companion mtime, zero when absent
	csize int64
}

// MaxCompanionBytes bounds the companion file.
const MaxCompanionBytes = 4096

// Option customises New.
type Option func(*options)

type options struct {
	companion string
	check     func(data, companion []byte) error
}

// WithCompanion makes the file load only if check(data, companionBytes)
// returns nil. A missing companion is passed as nil. check runs before parse,
// so an unverified file is never parsed. If the companion changes, the file is
// re-checked even when its own content did not.
func WithCompanion(path string, check func(data, companion []byte) error) Option {
	return func(o *options) { o.companion, o.check = path, check }
}

// New loads the file once and fails if that first load fails.
func New[T any](name, path string, maxBytes int64, parse func([]byte) (*T, error), obs Observer, opts ...Option) (*File[T], error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	f := &File[T]{name: name, path: path, maxBytes: maxBytes, parse: parse, obs: obs, companion: o.companion, check: o.check}
	if _, err := f.load(true); err != nil {
		return nil, err
	}
	return f, nil
}

// Get returns the current parsed value.
func (f *File[T]) Get() *T { return f.cur.Load() }

// ModTime returns the modification time of the file at the last successful load.
func (f *File[T]) ModTime() time.Time {
	if s := f.state.Load(); s != nil {
		return s.mtime
	}
	return time.Time{}
}

// Reload re-reads the file if it changed. It reports whether a new value was
// installed. On error the previous value stays active.
func (f *File[T]) Reload() (bool, error) {
	changed, err := f.load(false)
	if f.obs != nil && (changed || err != nil) {
		f.obs.Reloaded(f.name, err)
	}
	return changed, err
}

func (f *File[T]) load(first bool) (bool, error) {
	fi, err := os.Stat(f.path)
	if err != nil {
		return false, fmt.Errorf("%s: %w", f.name, err)
	}
	if !fi.Mode().IsRegular() {
		return false, fmt.Errorf("%s: %s is not a regular file", f.name, f.path)
	}
	var cm time.Time
	var csize int64
	if f.companion != "" {
		if cfi, err := os.Stat(f.companion); err == nil {
			cm, csize = cfi.ModTime(), cfi.Size()
		}
	}
	if !first {
		for _, st := range []*fileState{f.state.Load(), f.bad.Load()} {
			if st != nil && st.mtime.Equal(fi.ModTime()) && st.size == fi.Size() && st.cm.Equal(cm) && st.csize == csize {
				return false, nil
			}
		}
	}
	if f.maxBytes > 0 && fi.Size() > f.maxBytes {
		return false, fmt.Errorf("%s: file larger than %d bytes", f.name, f.maxBytes)
	}
	fh, err := os.Open(f.path)
	if err != nil {
		return false, fmt.Errorf("%s: %w", f.name, err)
	}
	defer fh.Close()
	var r io.Reader = fh
	if f.maxBytes > 0 {
		r = io.LimitReader(fh, f.maxBytes+1)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return false, fmt.Errorf("%s: %w", f.name, err)
	}
	if f.maxBytes > 0 && int64(len(data)) > f.maxBytes {
		return false, fmt.Errorf("%s: file larger than %d bytes", f.name, f.maxBytes)
	}
	st := &fileState{mtime: fi.ModTime(), size: int64(len(data)), sum: sha256.Sum256(data), cm: cm, csize: csize}
	if f.check != nil {
		var comp []byte
		if f.companion != "" {
			if c, err := readCompanion(f.companion); err == nil {
				comp = c
			}
		}
		if err := f.check(data, comp); err != nil {
			f.bad.Store(st)
			return false, fmt.Errorf("%s: %w", f.name, err)
		}
	}
	if old := f.state.Load(); !first && old != nil && old.sum == st.sum && old.cm.Equal(cm) && old.csize == csize {
		f.state.Store(st) // same content, newer mtime
		return false, nil
	}
	v, err := f.parse(data)
	if err != nil {
		// Remember the bad version so a broken file is reported once per change,
		// not on every tick.
		f.bad.Store(st)
		return false, fmt.Errorf("%s: %w", f.name, err)
	}
	if v == nil {
		return false, errors.New(f.name + ": parser returned nil")
	}
	f.cur.Store(v)
	f.state.Store(st)
	return !first, nil
}

// Run polls the file until ctx is cancelled.
func (f *File[T]) Run(ctx context.Context, interval time.Duration, onError func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := f.Reload(); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

func readCompanion(path string) ([]byte, error) {
	fh, err := os.Open(path) // #nosec G304 -- operator supplied path next to the policy file
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, MaxCompanionBytes+1))
	if err != nil || len(data) > MaxCompanionBytes {
		return nil, errors.New("companion unreadable or too large")
	}
	return data, nil
}
