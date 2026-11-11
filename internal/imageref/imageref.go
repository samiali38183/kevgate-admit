// Package imageref parses container image references. It never resolves tags:
// only a content digest identifies an image for policy purposes.
//
// The grammar follows the OCI Distribution Specification (pull and push
// "name" and "reference" patterns, section "Pulling manifests"), the OCI Image
// Specification descriptor digests (descriptor.md, "Digests"), and the
// registry host syntax of github.com/distribution/reference. Deliberate
// differences: only sha256 and sha512 digests are accepted (the evidence store
// is keyed by those), ports are limited to 1..65535, host labels follow
// RFC 1123 length limits, and the whole reference must be printable ASCII.
package imageref

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// ErrInvalid is returned for references that cannot be parsed.
var ErrInvalid = errors.New("invalid image reference")

var (
	digestRe = regexp.MustCompile(`^(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})$`)
	tagRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	// repoRe is the OCI distribution name pattern: path components of
	// lower-case alphanumerics joined by ".", "_", "__" or runs of "-".
	repoRe       = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*$`)
	identifierRe = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

const (
	maxRefLen  = 512
	maxRepoLen = 255 // NameTotalLengthMax in distribution/reference
)

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

// Parse splits a reference into registry, repository, tag and digest and
// enforces the reference grammar strictly. A reference that cannot be pulled
// is an error: it must not be mistaken for an unpinned image, and a path with
// dot segments must never be compared textually against an allow-list.
//
// Accepted references are printable ASCII only. Registry hosts are lower-cased
// (the DNS name is case-insensitive); repository names must already be lower
// case, as the grammar requires.
func Parse(raw string) (Ref, error) {
	if raw == "" || len(raw) > maxRefLen {
		return Ref{}, fmt.Errorf("%w: empty or too long", ErrInvalid)
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= ' ' || c >= 0x7f {
			return Ref{}, fmt.Errorf("%w: whitespace, control or non-ASCII character", ErrInvalid)
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
	var host string
	first, rest, found := strings.Cut(s, "/")
	switch {
	case found && isDomain(first):
		host, ref.Repository = first, rest
	case !found && identifierRe.MatchString(s):
		// A bare 64 hex digit name is an image ID, not a repository; runtimes
		// built on distribution/reference refuse it too.
		return Ref{}, fmt.Errorf("%w: name looks like an image ID", ErrInvalid)
	default:
		host, ref.Repository = "docker.io", s
	}
	reg, err := normalizeHost(host)
	if err != nil {
		return Ref{}, err
	}
	ref.Registry = reg
	if !repoRe.MatchString(ref.Repository) {
		return Ref{}, fmt.Errorf("%w: malformed repository", ErrInvalid)
	}
	if ref.Registry == "docker.io" && !strings.Contains(ref.Repository, "/") {
		ref.Repository = "library/" + ref.Repository
	}
	if len(ref.Repository) > maxRepoLen {
		return Ref{}, fmt.Errorf("%w: repository name too long", ErrInvalid)
	}
	return ref, nil
}

// isDomain reports whether the first path component names a registry rather
// than a Docker Hub namespace. This is the rule of distribution/reference: a
// component with a dot, a colon, an upper-case letter, or the name localhost.
func isDomain(first string) bool {
	return strings.ContainsAny(first, ".:") || first == "localhost" || first != strings.ToLower(first)
}

// normalizeHost validates host[:port] (a DNS name, IPv4 address or bracketed
// IPv6 address) and returns it lower-cased. index.docker.io becomes docker.io.
func normalizeHost(h string) (string, error) {
	bad := fmt.Errorf("%w: malformed registry host", ErrInvalid)
	var name, port string
	if strings.HasPrefix(h, "[") {
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return "", bad
		}
		addr, err := netip.ParseAddr(h[1:end])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", bad
		}
		name = "[" + addr.String() + "]"
		switch tail := h[end+1:]; {
		case tail == "":
		case tail[0] == ':':
			port = tail[1:]
		default:
			return "", bad
		}
		if strings.HasSuffix(h, ":") {
			return "", bad
		}
	} else {
		if strings.Count(h, ":") > 1 {
			return "", bad
		}
		var hasPort bool
		name, port, hasPort = strings.Cut(h, ":")
		if hasPort && port == "" {
			return "", bad
		}
		if !validDomainName(name) {
			return "", bad
		}
		name = strings.ToLower(name)
	}
	if port != "" {
		if len(port) > 5 {
			return "", bad
		}
		n := 0
		for i := 0; i < len(port); i++ {
			if port[i] < '0' || port[i] > '9' {
				return "", bad
			}
			n = n*10 + int(port[i]-'0')
		}
		if n < 1 || n > 65535 {
			return "", bad
		}
		name += ":" + port
	}
	if name == "index.docker.io" {
		name = "docker.io"
	}
	return name, nil
}

// validDomainName checks RFC 1123 labels: 1 to 63 characters of letters,
// digits and hyphens, not starting or ending with a hyphen, 253 in total.
func validDomainName(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !isHostChar(c) {
				return false
			}
		}
	}
	return true
}

func isHostChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

// NormalizePrefix validates an allowedRegistries entry (host[:port] with an
// optional repository path prefix, no scheme) and returns its canonical form:
// lower case, no trailing slash, index.docker.io as docker.io. A prefix that
// is not a valid host or path is an error, so it can never match anything by
// accident.
func NormalizePrefix(s string) (string, error) {
	p := strings.ToLower(strings.TrimSuffix(s, "/"))
	host, path, hasPath := strings.Cut(p, "/")
	reg, err := normalizeHost(host)
	if err != nil {
		return "", err
	}
	if hasPath && (len(path) > maxRepoLen || !repoRe.MatchString(path)) {
		return "", fmt.Errorf("%w: malformed repository prefix", ErrInvalid)
	}
	if hasPath {
		return reg + "/" + path, nil
	}
	return reg, nil
}

// MatchesRegistry reports whether the image lives under the allowed prefix,
// which is a registry host or a registry host plus a path prefix. The match is
// on whole path components, so "ghcr.io/org" does not match "ghcr.io/org2/app".
// Parse has already rejected dot segments, so there is no path to walk out of.
// An invalid prefix matches nothing.
func (r Ref) MatchesRegistry(prefix string) bool {
	p, err := NormalizePrefix(prefix)
	if err != nil {
		return false
	}
	n := r.Name()
	return n == p || strings.HasPrefix(n, p+"/")
}
