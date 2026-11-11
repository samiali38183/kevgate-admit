// Package evidence defines where vulnerability evidence for an image digest
// comes from. Providers only report what some scanner already found; nothing
// here scans an image.
package evidence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/samiali38183/kevgate-admit/internal/trivy"
	"github.com/samiali38183/kevgate-admit/internal/vuln"
)

// ErrNotFound means the provider has no evidence for the digest. It is not a
// failure of the provider.
var ErrNotFound = errors.New("no evidence for digest")

// Evidence is the scan result for one image digest.
type Evidence struct {
	Digest    string
	Source    string
	ScannedAt time.Time // zero when the source does not say
	Findings  []vuln.Finding
}

// Provider looks up evidence by image digest (for example sha256:...).
// Implementations must honour ctx cancellation and return ErrNotFound (possibly
// wrapped) when there is simply no data.
type Provider interface {
	Name() string
	Lookup(ctx context.Context, digest string) (*Evidence, error)
}

var digestRe = regexp.MustCompile(`^(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})$`)

// ValidDigest reports whether s is a well formed lower-case digest.
func ValidDigest(s string) bool { return digestRe.MatchString(s) }

// FileName maps a digest to its report file name: sha256:abc -> sha256-abc.json.
// The character set is restricted so the name is safe as a path element and as
// a ConfigMap key.
func FileName(digest string) (string, error) {
	if !ValidDigest(digest) {
		return "", fmt.Errorf("evidence: malformed digest")
	}
	return strings.Replace(digest, ":", "-", 1) + ".json", nil
}

// DirProvider reads Trivy JSON reports named <algo>-<hex>.json from a
// directory, such as a mounted ConfigMap or volume populated by a scan job.
type DirProvider struct {
	Dir      string
	MaxBytes int64 // per report; default trivy.DefaultMaxBytes
}

// Name implements Provider.
func (p *DirProvider) Name() string { return "dir" }

// Lookup implements Provider.
func (p *DirProvider) Lookup(ctx context.Context, digest string) (*Evidence, error) {
	name, err := FileName(digest)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := filepath.Join(p.Dir, name)
	f, err := os.Open(path) //nolint:gosec // name derives from a validated digest, no traversal possible
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("evidence: open report: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("evidence: stat report: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("evidence: report is not a regular file")
	}
	limit := p.MaxBytes
	if limit <= 0 {
		limit = trivy.DefaultMaxBytes
	}
	rep, err := trivy.ParseReader(f, limit)
	if err != nil {
		return nil, err
	}
	// A report that names other digests was written for a different image.
	// Accepting it would let a misnamed file vouch for the wrong image.
	if len(rep.Digests) > 0 {
		match := false
		for _, d := range rep.Digests {
			if d == digest {
				match = true
				break
			}
		}
		if !match {
			return nil, errors.New("evidence: report metadata does not match the requested digest")
		}
	}
	at := rep.CreatedAt
	if at.IsZero() {
		at = fi.ModTime().UTC()
	}
	return &Evidence{Digest: digest, Source: "trivy-dir", ScannedAt: at, Findings: rep.Findings}, nil
}

// Chain tries providers in order. The first one that has evidence wins; if
// none has it, ErrNotFound is returned unless some provider failed, in which
// case the first failure is returned.
type Chain []Provider

// Name implements Provider.
func (c Chain) Name() string {
	names := make([]string, len(c))
	for i, p := range c {
		names[i] = p.Name()
	}
	return strings.Join(names, "+")
}

// Lookup implements Provider.
func (c Chain) Lookup(ctx context.Context, digest string) (*Evidence, error) {
	var firstErr error
	for _, p := range c {
		ev, err := p.Lookup(ctx, digest)
		if err == nil {
			return ev, nil
		}
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", p.Name(), err)
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, ErrNotFound
}
