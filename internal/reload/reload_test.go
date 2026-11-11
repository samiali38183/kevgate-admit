package reload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type obs struct {
	mu   sync.Mutex
	ok   int
	errs int
}

func (o *obs) Reloaded(_ string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err != nil {
		o.errs++
	} else {
		o.ok++
	}
}

func (o *obs) counts() (int, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.ok, o.errs
}

func parseUpper(b []byte) (*string, error) {
	s := string(b)
	if strings.Contains(s, "BAD") {
		return nil, errors.New("bad content")
	}
	return &s, nil
}

func write(t *testing.T, path, content string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func TestReloadLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.txt")
	t0 := time.Now().Add(-time.Hour)
	write(t, path, "one", t0)
	o := &obs{}
	f, err := New("test", path, 100, parseUpper, o)
	if err != nil {
		t.Fatal(err)
	}
	if *f.Get() != "one" || !f.ModTime().Equal(t0) {
		t.Fatalf("initial: %v %v", *f.Get(), f.ModTime())
	}

	// Unchanged: no reload, no observer call.
	if changed, err := f.Reload(); changed || err != nil {
		t.Fatalf("unchanged: %v %v", changed, err)
	}
	// Changed content.
	write(t, path, "two", t0.Add(time.Minute))
	if changed, err := f.Reload(); !changed || err != nil || *f.Get() != "two" {
		t.Fatalf("changed: %v %v %v", changed, err, *f.Get())
	}
	// Broken content keeps the last good value and is reported once.
	write(t, path, "BAD", t0.Add(2*time.Minute))
	if changed, err := f.Reload(); changed || err == nil || *f.Get() != "two" {
		t.Fatalf("bad: %v %v %v", changed, err, *f.Get())
	}
	if changed, err := f.Reload(); changed || err != nil {
		t.Fatalf("bad file must not be re-reported until it changes: %v %v", changed, err)
	}
	// Same content with a new mtime: no swap.
	write(t, path, "two", t0.Add(3*time.Minute))
	if changed, err := f.Reload(); changed || err != nil {
		t.Fatalf("same content: %v %v", changed, err)
	}
	// Different size triggers a reload even with an identical mtime.
	write(t, path, "three", t0.Add(3*time.Minute))
	if changed, err := f.Reload(); !changed || err != nil || *f.Get() != "three" {
		t.Fatalf("size change: %v %v", changed, err)
	}
	if ok, errs := o.counts(); ok != 2 || errs != 1 {
		t.Errorf("observer ok=%d errs=%d, want 2 and 1", ok, errs)
	}
}

func TestNewFailures(t *testing.T) {
	dir := t.TempDir()
	if _, err := New("t", filepath.Join(dir, "missing"), 0, parseUpper, nil); err == nil {
		t.Error("missing file")
	}
	if _, err := New("t", dir, 0, parseUpper, nil); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Errorf("directory: %v", err)
	}
	p := filepath.Join(dir, "bad")
	write(t, p, "BAD", time.Now())
	if _, err := New("t", p, 0, parseUpper, nil); err == nil {
		t.Error("unparsable first load must fail")
	}
	p = filepath.Join(dir, "big")
	write(t, p, strings.Repeat("x", 200), time.Now())
	if _, err := New("t", p, 100, parseUpper, nil); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("oversize: %v", err)
	}
	if _, err := New("t", p, 0, func([]byte) (*string, error) { return nil, nil }, nil); err == nil {
		t.Error("nil parse result must fail")
	}
}

func TestFileGrowsPastCapAfterLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	t0 := time.Now().Add(-time.Hour)
	write(t, path, "ok", t0)
	f, err := New("t", path, 10, parseUpper, nil)
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, strings.Repeat("y", 50), t0.Add(time.Minute))
	if _, err := f.Reload(); err == nil {
		t.Fatal("expected size error")
	}
	if *f.Get() != "ok" {
		t.Error("last good value lost")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Reload(); err == nil {
		t.Fatal("expected error for removed file")
	}
	if *f.Get() != "ok" {
		t.Error("last good value lost after removal")
	}
}

func TestRunPollsUntilCancelled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	t0 := time.Now().Add(-time.Hour)
	write(t, path, "a", t0)
	f, err := New("t", path, 0, parseUpper, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 4)
	done := make(chan struct{})
	go func() {
		f.Run(ctx, 10*time.Millisecond, func(e error) { errs <- e })
		close(done)
	}()
	write(t, path, "BAD", t0.Add(time.Minute))
	select {
	case <-errs:
	case <-time.After(3 * time.Second):
		t.Fatal("onError not called")
	}
	write(t, path, "b", t0.Add(2*time.Minute))
	deadline := time.Now().Add(3 * time.Second)
	for *f.Get() != "b" {
		if time.Now().After(deadline) {
			t.Fatal("reload not observed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}
