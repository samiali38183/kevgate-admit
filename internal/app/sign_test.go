package app

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func copyDemoReports(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(demoPath("reports"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(demoPath("reports", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func reportPath(dir, digest string) string {
	return filepath.Join(dir, strings.Replace(digest, ":", "-", 1)+".json")
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKeygenSignVerifyCLI(t *testing.T) {
	for _, kind := range []string{"ed25519", "ecdsa"} {
		t.Run(kind, func(t *testing.T) {
			dir := copyDemoReports(t)
			keys := t.TempDir()
			priv, pub := filepath.Join(keys, "priv.pem"), filepath.Join(keys, "pub.pem")
			if c, o, e := runCLI("keygen", "-type", kind, "-private-out", priv, "-public-out", pub); c != 0 || !strings.Contains(o, kind) {
				t.Fatalf("keygen: %d %q %q", c, o, e)
			}
			if fi, err := os.Stat(priv); err != nil || (os.PathSeparator == '/' && fi.Mode().Perm() != 0o600) {
				t.Errorf("private key mode: %v %v", fi, err)
			}
			// never overwrite an existing key
			if c, _, e := runCLI("keygen", "-type", kind, "-private-out", priv, "-public-out", filepath.Join(keys, "other.pem")); c != 1 || e == "" {
				t.Errorf("keygen overwrote an existing key: %d %q", c, e)
			}

			a, b := reportPath(dir, dClean), reportPath(dir, dKEV)
			if c, o, e := runCLI("sign-report", "-key", priv, a, b); c != 0 || strings.Count(o, "signed ") != 2 {
				t.Fatalf("sign-report: %d %q %q", c, o, e)
			}
			if c, o, e := runCLI("verify-report", "-public-key", pub, a, b); c != 0 || strings.Count(o, "OK   ") != 2 {
				t.Fatalf("verify-report: %d %q %q", c, o, e)
			}

			// tampered report
			orig := mustRead(t, a)
			if err := os.WriteFile(a, bytes.Replace(orig, []byte("SYNTHETIC"), []byte("synthetic"), 1), 0o600); err != nil {
				t.Fatal(err)
			}
			if c, o, e := runCLI("verify-report", "-public-key", pub, a, b); c != 1 || !strings.Contains(e, "FAIL "+a) || !strings.Contains(o, "OK   "+b) {
				t.Errorf("tampered: %d %q %q", c, o, e)
			}
			if err := os.WriteFile(a, orig, 0o600); err != nil {
				t.Fatal(err)
			}

			// signature copied to another digest's report
			c1 := reportPath(dir, dOver)
			if err := os.WriteFile(c1+".sig", mustRead(t, a+".sig"), 0o600); err != nil {
				t.Fatal(err)
			}
			if c, _, e := runCLI("verify-report", "-public-key", pub, c1); c != 1 || !strings.Contains(e, "FAIL") {
				t.Errorf("replayed signature: %d %q", c, e)
			}

			// missing signature
			_ = os.Remove(b + ".sig")
			if c, _, e := runCLI("verify-report", "-public-key", pub, b); c != 1 || !strings.Contains(e, "FAIL") {
				t.Errorf("missing signature: %d %q", c, e)
			}

			// wrong key
			otherPriv, otherPub := filepath.Join(keys, "p2.pem"), filepath.Join(keys, "q2.pem")
			if c, _, _ := runCLI("keygen", "-type", kind, "-private-out", otherPriv, "-public-out", otherPub); c != 0 {
				t.Fatal("keygen 2")
			}
			if c, _, e := runCLI("verify-report", "-public-key", otherPub, a); c != 1 || !strings.Contains(e, "no trusted key verifies it") {
				t.Errorf("wrong key: %d %q", c, e)
			}
		})
	}
}

func TestSignVerifyCLIUsageAndErrors(t *testing.T) {
	keys := t.TempDir()
	priv, pub := filepath.Join(keys, "priv.pem"), filepath.Join(keys, "pub.pem")
	if c, _, _ := runCLI("keygen", "-private-out", priv, "-public-out", pub); c != 0 {
		t.Fatal("keygen")
	}
	dir := copyDemoReports(t)
	odd := filepath.Join(dir, "scan.json")
	if err := os.WriteFile(odd, []byte(`{"SchemaVersion":2}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		code int
		err  string
	}{
		{"keygen no paths", []string{"keygen"}, 2, "-private-out"},
		{"keygen bad type", []string{"keygen", "-type", "rsa", "-private-out", filepath.Join(keys, "a"), "-public-out", filepath.Join(keys, "b")}, 2, "unknown key type"},
		{"keygen bad flag", []string{"keygen", "-nope"}, 2, ""},
		{"sign no args", []string{"sign-report"}, 2, "usage"},
		{"sign bad flag", []string{"sign-report", "-nope"}, 2, ""},
		{"sign missing key file", []string{"sign-report", "-key", filepath.Join(keys, "none"), odd}, 1, ""},
		{"sign public key as private", []string{"sign-report", "-key", pub, reportPath(dir, dClean)}, 1, "PRIVATE KEY"},
		{"sign odd file name needs digest", []string{"sign-report", "-key", priv, odd}, 1, "pass -digest"},
		{"sign bad digest", []string{"sign-report", "-key", priv, "-digest", "latest", odd}, 1, "not a valid"},
		{"sign digest with two files", []string{"sign-report", "-key", priv, "-digest", dClean, odd, odd}, 2, "single report"},
		{"sign missing report", []string{"sign-report", "-key", priv, reportPath(dir, "sha256:"+strings.Repeat("9", 64))}, 1, ""},
		{"verify no args", []string{"verify-report"}, 2, "usage"},
		{"verify bad flag", []string{"verify-report", "-nope"}, 2, ""},
		{"verify missing key", []string{"verify-report", "-public-key", filepath.Join(keys, "none"), odd}, 1, ""},
		{"verify private key as public", []string{"verify-report", "-public-key", priv, odd}, 1, "PUBLIC KEY"},
		{"verify digest with two files", []string{"verify-report", "-public-key", pub, "-digest", dClean, odd, odd}, 2, "single report"},
		{"verify odd name", []string{"verify-report", "-public-key", pub, odd}, 1, "pass -digest"},
	}
	for _, tc := range cases {
		c, _, e := runCLI(tc.args...)
		if c != tc.code || !strings.Contains(e, tc.err) {
			t.Errorf("%s: code %d stderr %q, want %d containing %q", tc.name, c, e, tc.code, tc.err)
		}
	}
	for _, sub := range []string{"keygen", "sign-report", "verify-report"} {
		if c, _, _ := runCLI(sub, "-h"); c != 0 {
			t.Errorf("%s -h: %d", sub, c)
		}
	}

	// -digest allows an arbitrarily named report; the signature binds that digest.
	if c, o, e := runCLI("sign-report", "-key", priv, "-digest", dClean, odd); c != 0 {
		t.Fatalf("sign with -digest: %d %q %q", c, o, e)
	}
	if c, _, e := runCLI("verify-report", "-public-key", pub, "-digest", dClean, odd); c != 0 {
		t.Errorf("verify with -digest: %d %q", c, e)
	}
	if c, _, _ := runCLI("verify-report", "-public-key", pub, "-digest", dKEV, odd); c != 1 {
		t.Errorf("verify with the wrong -digest passed")
	}
}

const signedPolicy = `version: 1
default:
  requireDigest: true
  requireEvidence: deny
  denyKev: true
  maxRisk: 40
  requireSignedEvidence: true
`

func TestServeWithSignedEvidence(t *testing.T) {
	dir := copyDemoReports(t)
	keys := t.TempDir()
	priv, pub := filepath.Join(keys, "priv.pem"), filepath.Join(keys, "pub.pem")
	if c, _, e := runCLI("keygen", "-type", "ecdsa", "-private-out", priv, "-public-out", pub); c != 0 {
		t.Fatal(e)
	}
	// The clean and KEV reports are signed; the over-threshold one stays unsigned.
	if c, _, e := runCLI("sign-report", "-key", priv, reportPath(dir, dClean), reportPath(dir, dKEV)); c != 0 {
		t.Fatal(e)
	}
	pol := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(pol, []byte(signedPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	s := startWith(t, pol, dir, "-evidence-public-key-file", pub)
	img := func(name, d string) string { return "registry.example.com/demo/" + name + "@" + d }

	r := s.validate(t, "ns", img("clean", dClean))
	if !r.Allowed || len(r.Warnings) != 0 {
		t.Fatalf("signed clean report: %+v", r)
	}

	r = s.validate(t, "ns", img("kev-vulnerable", dKEV))
	if r.Allowed || !strings.Contains(r.Result.Message, "[denyKev]") {
		t.Fatalf("signed KEV report must still be judged on content: %+v", r)
	}

	r = s.validate(t, "ns", img("over-threshold", dOver))
	t.Logf("unsigned report:\n%s", r.Result.Message)
	if r.Allowed || !strings.Contains(r.Result.Message, "[requireEvidence]") ||
		!strings.Contains(r.Result.Message, "scan report is unsigned") || strings.Contains(r.Result.Message, "CVE-2099-10004") {
		t.Fatalf("unsigned report: %+v", r)
	}

	// Someone with write access to the store edits a signed report (renames the
	// KEV finding) but cannot re-sign it.
	forged := bytes.ReplaceAll(mustRead(t, reportPath(dir, dKEV)), []byte("CVE-2021-44228"), []byte("CVE-2021-00000"))
	if err := os.WriteFile(reportPath(dir, dKEV), forged, 0o600); err != nil {
		t.Fatal(err)
	}
	r = s.validate(t, "ns", img("kev-vulnerable", dKEV))
	t.Logf("tampered report:\n%s", r.Result.Message)
	if r.Allowed || !strings.Contains(r.Result.Message, "scan report signature is invalid") {
		t.Fatalf("tampered report accepted: %+v", r)
	}
}

func TestServeSignedPolicyWithoutKey(t *testing.T) {
	pol := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(pol, []byte(signedPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	s := startWith(t, pol, demoPath("reports"))
	r := s.validate(t, "ns", "registry.example.com/demo/clean@"+dClean)
	if r.Allowed || !strings.Contains(r.Result.Message, "cannot be authenticated") {
		t.Fatalf("a signed-evidence policy without a key must deny: %+v", r)
	}
}

func TestServeRejectsBadEvidenceKey(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": filepath.Join(dir, "none.pem"), "garbage": bad} {
		cfg, err := ParseServeFlags([]string{
			"-listen", "127.0.0.1:0", "-metrics-listen", "127.0.0.1:0", "-self-signed",
			"-policy-file", demoPath("policy.yaml"), "-kev-file", demoPath("kev-demo.json"),
			"-evidence-dir", demoPath("reports"), "-evidence-public-key-file", path,
		}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if err := Serve(context.Background(), cfg, newLogger(io.Discard, "error"), nil); err == nil || !strings.Contains(err.Error(), "-evidence-public-key-file") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPolicyCLIAndSignedPolicyServing(t *testing.T) {
	keys := t.TempDir()
	priv, pub := filepath.Join(keys, "priv.pem"), filepath.Join(keys, "pub.pem")
	if c, _, e := runCLI("keygen", "-type", "ed25519", "-private-out", priv, "-public-out", pub); c != 0 {
		t.Fatal(e)
	}
	pol := filepath.Join(t.TempDir(), "policy.yaml")
	good := mustRead(t, demoPath("policy.yaml"))
	if err := os.WriteFile(pol, good, 0o600); err != nil {
		t.Fatal(err)
	}

	// A policy the webhook would refuse to load is not signed.
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\ndefault:\n  maxRisk: 500\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := runCLI("sign-policy", "-key", priv, bad); c == 0 {
		t.Fatal("signed an invalid policy")
	}
	if c, _, _ := runCLI("verify-policy", "-public-key", pub, pol); c == 0 {
		t.Fatal("verified a policy with no signature")
	}
	if c, _, e := runCLI("sign-policy", "-key", priv, pol); c != 0 {
		t.Fatal(e)
	}
	if c, o, e := runCLI("verify-policy", "-public-key", pub, pol); c != 0 || !strings.Contains(o, "OK") {
		t.Fatalf("verify: %d %q %q", c, o, e)
	}

	// The server starts, enforces the signed policy (KEV image denied) ...
	s := startWith(t, pol, demoPath("reports"), "-policy-public-key-file", pub)
	kevImg := "registry.example.com/demo/kev-vulnerable@" + dKEV
	if r := s.validate(t, "demo-enforce", kevImg); r.Allowed {
		t.Fatalf("signed policy not enforced: %+v", r)
	}
	// ... and an edit that weakens it (denyKev off, limit raised) without a new
	// signature is never installed, so the KEV image stays denied.
	weak := strings.NewReplacer("denyKev: true", "denyKev: false", "maxRisk: 40", "maxRisk: 100").Replace(string(good))
	if weak == string(good) {
		t.Fatal("test edit changed nothing; update it to match deploy/demo/policy.yaml")
	}
	if err := os.WriteFile(pol, []byte(weak), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond) // several 50 ms reload ticks
	if r := s.validate(t, "demo-enforce", kevImg); r.Allowed {
		t.Fatalf("an unsigned policy edit took effect: %+v", r)
	}
	// Signing the edit makes it effective, which shows the previous check was the signature and not a stuck reload.
	if c, _, e := runCLI("sign-policy", "-key", priv, pol); c != 0 {
		t.Fatal(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if r := s.validate(t, "demo-enforce", kevImg); r.Allowed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a correctly signed policy was never installed")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestServeRefusesUnsignedPolicyAtStart(t *testing.T) {
	keys := t.TempDir()
	priv, pub := filepath.Join(keys, "priv.pem"), filepath.Join(keys, "pub.pem")
	if c, _, e := runCLI("keygen", "-private-out", priv, "-public-out", pub); c != 0 {
		t.Fatal(e)
	}
	cfg, err := ParseServeFlags([]string{
		"-listen", "127.0.0.1:0", "-metrics-listen", "127.0.0.1:0", "-self-signed",
		"-policy-file", demoPath("policy.yaml"), "-kev-file", demoPath("kev-demo.json"),
		"-evidence-dir", demoPath("reports"), "-policy-public-key-file", pub,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	err = Serve(context.Background(), cfg, newLogger(io.Discard, "error"), nil)
	if err == nil || !strings.Contains(err.Error(), "policy signature") {
		t.Fatalf("started with an unsigned policy: %v", err)
	}
}
