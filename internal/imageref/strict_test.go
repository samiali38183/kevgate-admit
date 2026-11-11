package imageref

import (
	"errors"
	"strings"
	"testing"
)

// Reference grammar: OCI Distribution Spec, "Pulling manifests" (name and
// reference patterns) and OCI Image Spec descriptor.md "Digests". The domain
// part follows the Docker reference grammar (distribution/reference).
func TestParseStrictRejects(t *testing.T) {
	long255 := strings.Repeat("a", 255)
	tests := []struct{ name, in string }{
		// fuzz findings
		{"fuzz ::0", "::0"},
		{"fuzz invalid utf8 host", "\xed\xa0\x80.io/app"},
		{"fuzz invalid utf8 host with port", "h\xffst.io:5000/app"},
		// path traversal and dot components
		{"dotdot in path", "ghcr.io/org/../evil"},
		{"dotdot docker hub", "org/x/../../y"},
		{"leading dotdot", "ghcr.io/../org/app"},
		{"dot component", "ghcr.io/org/./app"},
		{"dotdot only", "ghcr.io/org/.."},
		{"dot only", "ghcr.io/."},
		{"consecutive dots in component", "ghcr.io/org/a..b"},
		{"leading dot component", "ghcr.io/org/.app"},
		{"trailing dot component", "ghcr.io/org/app."},
		{"percent encoded dots", "ghcr.io/org/%2e%2e/evil"},
		{"backslash", "ghcr.io/org\\app"},
		// empty components
		{"empty component", "ghcr.io/org//app"},
		{"leading slash", "/org/app"},
		{"trailing slash", "ghcr.io/org/app/"},
		{"slash only", "/"},
		{"host only slash", "ghcr.io/"},
		// separators
		{"triple underscore", "ghcr.io/org/a___b"},
		{"leading dash", "ghcr.io/org/-app"},
		{"trailing dash", "ghcr.io/org/app-"},
		{"underscore dot", "ghcr.io/org/a_.b"},
		// uppercase and other characters in the repository
		{"uppercase repo", "ghcr.io/Org/app"},
		{"uppercase repo docker hub", "user/App"},
		{"uppercase single", "NGINX"},
		{"plus in repo", "ghcr.io/org/a+b"},
		{"star in repo", "ghcr.io/org/*"},
		{"colon in repo path", "ghcr.io/org:x/app"},
		{"non ascii repo", "ghcr.io/org/café"},
		{"non ascii host", "ghçr.io/org/app"},
		{"fullwidth slash", "ghcr.io/org／app"},
		{"del", "ghcr.io/org/a\x7fb"},
		{"nbsp", "ghcr.io/org/a b"},
		{"tab", "ghcr.io/org/a\tb"},
		// hosts
		{"ipv6 without brackets", "::1/app"},
		{"ipv6 unclosed", "[::0/app"},
		{"ipv6 empty brackets", "[]/app"},
		{"ipv6 bad", "[:::]/app"},
		{"ipv6 zone", "[fe80::1%25eth0]:5000/app"},
		{"ipv6 embedded ipv4 junk", "[::1.2.3]:5000/app"},
		{"ipv6 brackets non ipv6", "[1.2.3.4]:5000/app"},
		{"host underscore", "my_host.io/app"},
		{"host leading dash label", "-a.io/app"},
		{"host trailing dash label", "a-.io/app"},
		{"host empty label", "a..io/app"},
		{"host leading dot", ".io/app"},
		{"host trailing dot", "ghcr.io./app"},
		{"host label too long", strings.Repeat("a", 64) + ".io/app"},
		{"host too long", strings.Repeat("a.", 130) + "io/app"},
		{"userinfo", "user@ghcr.io/app"},
		{"scheme", "https://ghcr.io/org/app"},
		{"query", "ghcr.io/org/app?x=1"},
		{"fragment", "ghcr.io/org/app#x"},
		// ports
		{"empty port", "ghcr.io:/app"},
		{"zero port", "ghcr.io:0/app"},
		{"port too large", "ghcr.io:65536/app"},
		{"non numeric port", "ghcr.io:http/app"},
		{"two ports", "ghcr.io:5000:5000/app"},
		{"signed port", "ghcr.io:+80/app"},
		{"port with space", "ghcr.io: 80/app"},
		// tags
		{"tag starts with dot", "nginx:.x"},
		{"tag starts with dash", "nginx:-x"},
		{"tag with slash", "ghcr.io/org/app:a/b"},
		{"tag too long", "nginx:" + strings.Repeat("a", 129)},
		{"tag unicode", "nginx:vé"},
		{"tag with plus", "nginx:v1+build"},
		{"two tags", "nginx:1:2"},
		{"empty tag with digest", "nginx:@" + d256},
		// digests
		{"two digests", "nginx@" + d256 + "@" + d256},
		{"digest then tag", "nginx@" + d256 + ":v1"},
		{"digest hex too long", "nginx@sha256:" + strings.Repeat("a", 65)},
		{"digest non hex", "nginx@sha256:" + strings.Repeat("g", 64)},
		{"sha512 with sha256 length", "nginx@sha512:" + strings.Repeat("a", 64)},
		{"empty digest", "nginx@"},
		{"digest algorithm only", "nginx@sha256"},
		{"digest trailing newline", "nginx@" + d256 + "\n"},
		{"bare image id", strings.Repeat("a", 64)},

		// length
		{"repository over 255", "ghcr.io/org/" + long255},
		{"docker hub name over 255 with library", strings.Repeat("a", 248)},
		{"reference over 512", "ghcr.io/" + strings.Repeat("a/", 300) + "x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Parse(tc.in)
			if err == nil {
				t.Fatalf("Parse(%q) accepted: %+v", tc.in, r)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error %v does not wrap ErrInvalid", err)
			}
		})
	}
}

func TestParseStrictAccepts(t *testing.T) {
	tests := []struct {
		in, reg, repo string
	}{
		{"a", "docker.io", "library/a"},
		{"docker.io/nginx", "docker.io", "library/nginx"},
		{"registry-1.docker.io/user/app", "registry-1.docker.io", "user/app"},
		{"ghcr.io/org/a-b.c_d__e---f/app", "ghcr.io", "org/a-b.c_d__e---f/app"},
		{"ghcr.io/org/app@" + d256, "ghcr.io", "org/app"},
		{"[::1]:5000/app", "[::1]:5000", "app"},
		{"[2001:db8::1]/org/app", "[2001:db8::1]", "org/app"},
		{"[2001:DB8::1]:443/org/app", "[2001:db8::1]:443", "org/app"},
		{"127.0.0.1:5000/app", "127.0.0.1:5000", "app"},
		{"HOST.Example.COM:65535/app", "host.example.com:65535", "app"},
		{"xn--bcher-kva.example/app", "xn--bcher-kva.example", "app"},
		// An uppercase first component is a host, as in distribution/reference.
		{"Registry/app", "registry", "app"},
		{"ghcr.io/" + strings.Repeat("a", 255), "ghcr.io", strings.Repeat("a", 255)},
		{"ghcr.io/" + strings.Repeat("0", 64), "ghcr.io", strings.Repeat("0", 64)},
		{strings.Repeat("a", 247), "docker.io", "library/" + strings.Repeat("a", 247)},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			r, err := Parse(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if r.Registry != tc.reg || r.Repository != tc.repo {
				t.Errorf("got registry %q repository %q", r.Registry, r.Repository)
			}
		})
	}
	// A 128 character tag is the maximum.
	if _, err := Parse("nginx:" + strings.Repeat("a", 128)); err != nil {
		t.Errorf("128 character tag rejected: %v", err)
	}
}

func TestMatchesRegistryHostBoundaries(t *testing.T) {
	// Every image here must parse; none may match the allowed prefix.
	notMatching := []struct{ image, prefix string }{
		{"ghcr.io/organization/app", "ghcr.io/org"},
		{"ghcr.io/org-evil/app", "ghcr.io/org"},
		{"ghcr.io/org.evil/app", "ghcr.io/org"},
		{"ghcr.io/org_x/app", "ghcr.io/org"},
		{"ghcr.io.evil.com/org/app", "ghcr.io"},
		{"ghcr.io:5000/org/app", "ghcr.io"},
		{"ghcr.io/org/app", "ghcr.io:443"},
		{"xghcr.io/org/app", "ghcr.io"},
		{"evil.io/ghcr.io/org/app", "ghcr.io/org"},
		{"docker.io/org/app", "docker.io/library"},
		{"[::1]:5000/app", "[::1]"},
	}
	for _, tc := range notMatching {
		r, err := Parse(tc.image)
		if err != nil {
			t.Fatalf("%q: %v", tc.image, err)
		}
		if r.MatchesRegistry(tc.prefix) {
			t.Errorf("%q matches prefix %q", tc.image, tc.prefix)
		}
	}
	// A traversal reference never parses, so it can never reach the match.
	for _, in := range []string{"ghcr.io/org/../evil", "ghcr.io/org/../../other/app", "ghcr.io/org/./app"} {
		if r, err := Parse(in); err == nil {
			t.Errorf("%q parsed: %+v (matches ghcr.io/org: %v)", in, r, r.MatchesRegistry("ghcr.io/org"))
		}
	}
	// Prefixes that are not valid host[/path] values match nothing.
	r, _ := Parse("ghcr.io/org/app")
	for _, p := range []string{"", "ghcr.io/org/..", "ghcr.io//org", "https://ghcr.io", "ghcr.io/org/app/..", "*"} {
		if r.MatchesRegistry(p) {
			t.Errorf("invalid prefix %q matched", p)
		}
	}
}

func TestNormalizePrefix(t *testing.T) {
	good := map[string]string{
		"ghcr.io":                   "ghcr.io",
		"GHCR.IO/":                  "ghcr.io",
		"ghcr.io/Org/":              "ghcr.io/org",
		"index.docker.io":           "docker.io",
		"index.docker.io/library":   "docker.io/library",
		"registry.example.com:5000": "registry.example.com:5000",
		"[::1]:5000/team":           "[::1]:5000/team",
		"localhost":                 "localhost",
		"ghcr.io/org/team-a_b.c__d": "ghcr.io/org/team-a_b.c__d",
	}
	for in, want := range good {
		got, err := NormalizePrefix(in)
		if err != nil || got != want {
			t.Errorf("NormalizePrefix(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "/", "ghcr.io/..", "ghcr.io/org/../x", "ghcr.io//org", "a b", "https://ghcr.io",
		"ghcr.io/org:tag", "ghcr.io@x", "::0", "ghcr.io:0", "ghcr.io/\xff", "-a.io"}
	for _, in := range bad {
		if got, err := NormalizePrefix(in); err == nil {
			t.Errorf("NormalizePrefix(%q) accepted as %q", in, got)
		}
	}
}

// FuzzParse checks properties that must hold for every input: Parse never
// panics, accepted references are printable ASCII with a clean repository
// path, the canonical name parses back to itself, and the reference matches
// its own registry and name.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"", "nginx", "nginx:1.25", "ghcr.io/org/app@" + d256, "::0", "\xed\xa0\x80.io/app",
		"ghcr.io/org/../evil", "org/x/../../y", "[::1]:5000/app", "a/./b", "ghcr.io//x", "UPPER/Case",
		"host:99999/app", "nginx:", "nginx@sha256:", "a@b@c", "localhost:5000/a:b",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		r, err := Parse(in)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			return
		}
		for i := 0; i < len(in); i++ {
			if in[i] <= ' ' || in[i] >= 0x7f {
				t.Fatalf("accepted non printable ASCII byte %#x in %q", in[i], in)
			}
		}
		if r.Registry == "" || r.Repository == "" {
			t.Fatalf("empty registry or repository for %q: %+v", in, r)
		}
		if r.Repository != strings.ToLower(r.Repository) || strings.Contains(r.Repository, "..") {
			t.Fatalf("unclean repository %q for %q", r.Repository, in)
		}
		for _, c := range strings.Split(r.Repository, "/") {
			if c == "" || c == "." || c == ".." {
				t.Fatalf("bad path component %q in %q", c, in)
			}
		}
		if strings.ContainsAny(r.Registry, "/@ ") || r.Registry != strings.ToLower(r.Registry) {
			t.Fatalf("bad registry %q for %q", r.Registry, in)
		}
		// The canonical name parses back to itself, unless the host is a bare
		// label (reachable only as "Host/app" with an upper-case first component),
		// which Parse reads as a Docker Hub namespace once lower-cased.
		if isDomain(r.Registry) {
			again, err := Parse(r.Name())
			if err != nil || again.Name() != r.Name() {
				t.Fatalf("Name() %q does not round trip: %v", r.Name(), err)
			}
		}
		if !r.MatchesRegistry(r.Registry) || !r.MatchesRegistry(r.Name()) {
			t.Fatalf("%q does not match its own registry or name", in)
		}
	})
}
