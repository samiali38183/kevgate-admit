// Package imageref parses container image references. It never resolves tags:
// only a content digest identifies an image for policy purposes.
package imageref

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalid is returned for references that cannot be parsed.
var ErrInvalid = errors.New("invalid image reference")

var (
	digestRe = regexp.MustCompile(`^(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})$`)
	tagRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

const maxRefLen = 512

// Ref is a parsed image reference.
type Ref struct {
	Raw        string
	Registry   string // lower-case host[:port], docker.io when omitted
	Repository string // path below the registry, library/ added for docker.io
	Tag        string // empty when absent; ignored by the kubelet if Digest is set
	Digest     string // algo:hex, empty when absent
}

// Name returns registry/repository without tag or digest.
func (r Ref) Name() string { return r.Registry + "/" + r.Repository }

// Pinned reports whether the reference carries a digest.
func (r Ref) Pinned() bool { return r.Digest != "" }

// Short returns a log and message friendly form with the digest abbreviated.
func (r Ref) Short() string {
	s := r.Name()
	if r.Digest != "" {
		algo, hex, _ := strings.Cut(r.Digest, ":")
		if len(hex) > 12 {
			hex = hex[:12]
		}
		return s + "@" + algo + ":" + hex
	}
	if r.Tag != "" {
		return s + ":" + r.Tag
	}
	return s
}

// Parse splits a reference into registry, repository, tag and digest.
// A malformed digest or tag is an error: such an image cannot be pulled and
// must not be mistaken for an unpinned one.
func Parse(raw string) (Ref, error) {
	if raw == "" || len(raw) > maxRefLen {
		return Ref{}, fmt.Errorf("%w: empty or too long", ErrInvalid)
	}
	for _, r := range raw {
		if r <= ' ' || r == 0x7f {
			return Ref{}, fmt.Errorf("%w: whitespace or control character", ErrInvalid)
		}
	}
	ref := Ref{Raw: raw}
	s := raw
	if i := strings.IndexByte(s, '@'); i >= 0 {
		d := s[i+1:]
		if !digestRe.MatchString(d) {
			return Ref{}, fmt.Errorf("%w: malformed digest", ErrInvalid)
		}
		ref.Digest = d
		s = s[:i]
	}
	if c, sl := strings.LastIndexByte(s, ':'), strings.LastIndexByte(s, '/'); c > sl {
		tag := s[c+1:]
		if !tagRe.MatchString(tag) {
			return Ref{}, fmt.Errorf("%w: malformed tag", ErrInvalid)
		}
		ref.Tag = tag
		s = s[:c]
	}
	if s == "" {
		return Ref{}, fmt.Errorf("%w: empty repository", ErrInvalid)
	}
	first, rest, found := strings.Cut(s, "/")
	switch {
	case found && (strings.ContainsAny(first, ".:") || first == "localhost"):
		ref.Registry = strings.ToLower(first)
		ref.Repository = rest
	case found:
		ref.Registry = "docker.io"
		ref.Repository = s
	default:
		ref.Registry = "docker.io"
		ref.Repository = "library/" + s
	}
	if ref.Registry == "index.docker.io" {
		ref.Registry = "docker.io"
	}
	if ref.Repository == "" || strings.HasPrefix(ref.Repository, "/") || strings.HasSuffix(ref.Repository, "/") || strings.Contains(ref.Repository, "//") {
		return Ref{}, fmt.Errorf("%w: malformed repository", ErrInvalid)
	}
	return ref, nil
}

// MatchesRegistry reports whether the image lives under the allowed prefix,
// which is a registry host or a registry host plus a path prefix. Matching is
// done on path boundaries so "ghcr.io/org" does not match "ghcr.io/org2/app".
func (r Ref) MatchesRegistry(prefix string) bool {
	p := strings.ToLower(strings.TrimSuffix(prefix, "/"))
	if p == "index.docker.io" || strings.HasPrefix(p, "index.docker.io/") {
		p = "docker.io" + strings.TrimPrefix(p, "index.docker.io")
	}
	n := strings.ToLower(r.Name())
	return n == p || strings.HasPrefix(n, p+"/")
}
