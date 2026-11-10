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

	cur   atomic.Pointer[T]
	state atomic.Pointer[fileState]
	bad   atomic.Pointer[fileState]
}

type fileState struct {
	mtime time.Time
	size  int64
	sum   [sha256.Size]byte
}

// New loads the file once and fails if that first load fails.
func New[T any](name, path string, maxBytes int64, parse func([]byte) (*T, error), obs Observer) (*File[T], error) {
	f := &File[T]{name: name, path: path, maxBytes: maxBytes, parse: parse, obs: obs}
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
	if !first {
		for _, st := range []*fileState{f.state.Load(), f.bad.Load()} {
			if st != nil && st.mtime.Equal(fi.ModTime()) && st.size == fi.Size() {
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
	st := &fileState{mtime: fi.ModTime(), size: int64(len(data)), sum: sha256.Sum256(data)}
	if old := f.state.Load(); !first && old != nil && old.sum == st.sum {
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
