package imageref

import (
	"strings"
	"testing"
)

const d256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestParse(t *testing.T) {
	tests := []struct {
		in                     string
		reg, repo, tag, digest string
		pinned                 bool
	}{
		{"nginx", "docker.io", "library/nginx", "", "", false},
		{"nginx:1.25", "docker.io", "library/nginx", "1.25", "", false},
		{"user/app:v1", "docker.io", "user/app", "v1", "", false},
		{"index.docker.io/user/app", "docker.io", "user/app", "", "", false},
		{"ghcr.io/org/app:v2", "ghcr.io", "org/app", "v2", "", false},
		{"GHCR.io/org/app", "ghcr.io", "org/app", "", "", false},
		{"localhost:5000/app", "localhost:5000", "app", "", "", false},
		{"localhost/app:1", "localhost", "app", "1", "", false},
		{"registry.example.com:5000/a/b/c:t", "registry.example.com:5000", "a/b/c", "t", "", false},
		{"ghcr.io/org/app@" + d256, "ghcr.io", "org/app", "", d256, true},
		{"ghcr.io/org/app:v1@" + d256, "ghcr.io", "org/app", "v1", d256, true},
		{"nginx@" + d256, "docker.io", "library/nginx", "", d256, true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			r, err := Parse(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if r.Registry != tc.reg || r.Repository != tc.repo || r.Tag != tc.tag || r.Digest != tc.digest || r.Pinned() != tc.pinned {
				t.Errorf("got %+v", r)
			}
			if r.Name() != tc.reg+"/"+tc.repo {
				t.Errorf("Name() = %q", r.Name())
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct{ name, in string }{
		{"empty", ""},
		{"space", "nginx :1"},
		{"newline", "nginx\n"},
		{"control", "ng\x00inx"},
		{"short digest", "nginx@sha256:abc"},
		{"upper digest", "nginx@sha256:" + strings.Repeat("A", 64)},
		{"unknown algo", "nginx@md5:" + strings.Repeat("a", 32)},
		{"empty tag", "nginx:"},
		{"bad tag", "nginx:-x"},
		{"empty repo", ":tag"},
		{"double slash", "ghcr.io//app"},
		{"trailing slash", "ghcr.io/app/"},
		{"too long", strings.Repeat("a", 600)},
		{"only digest", "@" + d256},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if r, err := Parse(tc.in); err == nil {
				t.Fatalf("expected error, got %+v", r)
			}
		})
	}
}

func TestShort(t *testing.T) {
	r, _ := Parse("ghcr.io/org/app@" + d256)
	if got, want := r.Short(), "ghcr.io/org/app@sha256:aaaaaaaaaaaa"; got != want {
		t.Errorf("Short() = %q, want %q", got, want)
	}
	r, _ = Parse("nginx:1.25")
	if got := r.Short(); got != "docker.io/library/nginx:1.25" {
		t.Errorf("Short() = %q", got)
	}
	r, _ = Parse("nginx")
	if got := r.Short(); got != "docker.io/library/nginx" {
		t.Errorf("Short() = %q", got)
	}
}

func TestMatchesRegistry(t *testing.T) {
	tests := []struct {
		image, prefix string
		want          bool
	}{
		{"ghcr.io/org/app:1", "ghcr.io", true},
		{"ghcr.io/org/app:1", "ghcr.io/org", true},
		{"ghcr.io/org/app:1", "ghcr.io/org/app", true},
		{"ghcr.io/org2/app:1", "ghcr.io/org", false},
		{"ghcr.io/organ/app", "ghcr.io/org", false},
		{"nginx", "docker.io", true},
		{"nginx", "index.docker.io", true},
		{"nginx", "docker.io/library", true},
		{"evil.io/ghcr.io/app", "ghcr.io", false},
		{"ghcr.io/org/app", "GHCR.IO/", true},
		{"registry.example.com:5000/x", "registry.example.com", false},
		{"registry.example.com:5000/x", "registry.example.com:5000", true},
	}
	for _, tc := range tests {
		r, err := Parse(tc.image)
		if err != nil {
			t.Fatal(err)
		}
		if got := r.MatchesRegistry(tc.prefix); got != tc.want {
			t.Errorf("%q vs %q = %v, want %v", tc.image, tc.prefix, got, tc.want)
		}
	}
}
