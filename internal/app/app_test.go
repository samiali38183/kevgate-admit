package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
)

const (
	dClean = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dKEV   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dOver  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func demoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "deploy", "demo"}, parts...)...)
}

func review(ns, image string) string {
	obj := fmt.Sprintf(`{"metadata":{"name":"web"},"spec":{"template":{"spec":{"containers":[{"name":"web","image":%q}]}}}}`, image)
	return fmt.Sprintf(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"u1","kind":{"group":"apps","version":"v1","kind":"Deployment"},"resource":{"group":"apps","version":"v1","resource":"deployments"},"operation":"CREATE","namespace":%q,"object":%s}}`, ns, obj)
}

type server struct {
	cfg    Config
	addrs  Addrs
	client *http.Client
	stop   func() error
}

func (s *server) validate(t *testing.T, ns, image string) *admissionv1.AdmissionResponse {
	t.Helper()
	resp, err := s.client.Post("https://"+s.addrs.Admission+"/validate", "application/json", strings.NewReader(review(ns, image)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rev admissionv1.AdmissionReview
	if err := json.NewDecoder(resp.Body).Decode(&rev); err != nil {
		t.Fatal(err)
	}
	return rev.Response
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func start(t *testing.T, policyFile string) *server {
	t.Helper()
	dir := t.TempDir()
	if policyFile == "" {
		policyFile = demoPath("policy.yaml")
	}
	ca := filepath.Join(dir, "ca.pem")
	cfg, err := ParseServeFlags([]string{
		"-listen", "127.0.0.1:0", "-metrics-listen", "127.0.0.1:0",
		"-self-signed", "-self-signed-hosts", "localhost,127.0.0.1", "-self-signed-ca-out", ca,
		"-policy-file", policyFile, "-kev-file", demoPath("kev-demo.json"),
		"-evidence-dir", demoPath("reports"),
		"-reload-interval", "50ms", "-shutdown-timeout", "2s",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan Addrs, 1)
	done := make(chan error, 1)
	logs := &bytes.Buffer{}
	go func() { done <- Serve(ctx, cfg, slog.New(slog.NewJSONHandler(logs, nil)), ready) }()
	var addrs Addrs
	select {
	case addrs = <-ready:
	case err := <-done:
		t.Fatalf("server exited early: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server did not start")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(addrs.CAPEM) {
		t.Fatal("no CA")
	}
	if b, err := os.ReadFile(ca); err != nil || !bytes.Equal(b, addrs.CAPEM) {
		t.Fatalf("CA file not written: %v", err)
	}
	s := &server{cfg: cfg, addrs: addrs, client: &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}},
	}}
	var once sync.Once
	var stopErr error
	s.stop = func() error { once.Do(func() { cancel(); stopErr = <-done }); return stopErr }
	t.Cleanup(func() { _ = s.stop() })
	return s
}

// TestDemoScenarios runs the demo fixtures through the real TLS server and
// pins the denial text that deploy/demo/demo.sh and the e2e workflow assert.
func TestDemoScenarios(t *testing.T) {
	s := start(t, "")
	img := func(name, d string) string { return "registry.example.com/demo/" + name + "@" + d }

	r := s.validate(t, "demo-enforce", img("clean", dClean))
	if !r.Allowed || len(r.Warnings) != 0 {
		t.Fatalf("clean image: %+v", r)
	}

	r = s.validate(t, "demo-enforce", img("kev-vulnerable", dKEV))
	if r.Allowed {
		t.Fatal("kev image allowed")
	}
	t.Logf("denial message for the KEV image:\n%s", r.Result.Message)
	for _, want := range []string{
		`kevgate-admit: request denied by policy (namespace "demo-enforce", scope "demo-enforce")`,
		"[denyKev] registry.example.com/demo/kev-vulnerable@sha256:222222222222: 1 finding(s) in the CISA KEV catalog",
		"CVE-2021-44228",
		"KEV  risk  ",
		"log4j-core 2.14.1 (fixed 2.17.1)",
	} {
		if !strings.Contains(r.Result.Message, want) {
			t.Errorf("KEV denial lacks %q", want)
		}
	}

	r = s.validate(t, "demo-enforce", img("over-threshold", dOver))
	if r.Allowed {
		t.Fatal("over-threshold image allowed in enforce namespace")
	}
	t.Logf("denial message for the over-threshold image:\n%s", r.Result.Message)
	for _, want := range []string{"[maxRisk]", "above max risk 40.0 (highest 47.7)", "CVE-2099-10004", "risk  47.7"} {
		if !strings.Contains(r.Result.Message, want) {
			t.Errorf("maxRisk denial lacks %q", want)
		}
	}

	r = s.validate(t, "demo-audit", img("over-threshold", dOver))
	if !r.Allowed || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "would deny [maxRisk]") {
		t.Fatalf("audit namespace: %+v", r)
	}
	t.Logf("audit warning: %s", r.Warnings[0])

	r = s.validate(t, "demo-enforce", "registry.example.com/demo/clean:latest")
	if r.Allowed || !strings.Contains(r.Result.Message, "[requireDigest]") {
		t.Fatalf("tag-only: %+v", r)
	}
	r = s.validate(t, "demo-enforce", "docker.io/library/nginx@sha256:"+strings.Repeat("4", 64))
	if r.Allowed || !strings.Contains(r.Result.Message, "[allowedRegistries]") || !strings.Contains(r.Result.Message, "[requireEvidence]") {
		t.Fatalf("foreign registry without evidence: %+v", r)
	}
}

func TestHealthMetricsAndShutdown(t *testing.T) {
	s := start(t, "")
	s.validate(t, "demo-enforce", "registry.example.com/demo/kev-vulnerable@"+dKEV)
	base := "http://" + s.addrs.Metrics
	if c, b := get(t, base+"/healthz"); c != 200 || !strings.HasPrefix(b, "ok") {
		t.Errorf("healthz %d %q", c, b)
	}
	if c, _ := get(t, base+"/readyz"); c != 200 {
		t.Errorf("readyz %d", c)
	}
	_, m := get(t, base+"/metrics")
	for _, want := range []string{
		`kevgate_admit_decisions_total{namespace="demo-enforce",outcome="deny",rule="denyKev"} 1`,
		`kevgate_admit_evidence_lookup_seconds_count{provider="dir",result="found"} 1`,
		`kevgate_admit_reloads_total{component="policy"}`,
		`kevgate_admit_reload_errors_total{component="policy"} 0`,
		`kevgate_admit_kev_entries 3`,
		`kevgate_admit_kev_catalog_mtime_seconds`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	// The admission port refuses plain HTTP and other paths.
	if resp, err := s.client.Get("https://" + s.addrs.Admission + "/validate"); err != nil || resp.StatusCode != 405 {
		t.Errorf("GET /validate: %v %v", resp, err)
	}
	if resp, err := s.client.Get("https://" + s.addrs.Admission + "/other"); err != nil || resp.StatusCode != 404 {
		t.Errorf("GET /other: %v %v", resp, err)
	}
	if err := s.stop(); err != nil {
		t.Errorf("shutdown error: %v", err)
	}
	if _, err := http.Get(base + "/healthz"); err == nil {
		t.Error("metrics listener still up after shutdown")
	}
}

func TestPolicyHotReload(t *testing.T) {
	dir := t.TempDir()
	pf := filepath.Join(dir, "policy.yaml")
	base, _ := os.ReadFile(demoPath("policy.yaml"))
	write := func(b []byte, at time.Time) {
		if err := os.WriteFile(pf, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(pf, at, at)
	}
	t0 := time.Now().Add(-time.Hour)
	write(base, t0)
	s := start(t, pf)
	img := "registry.example.com/demo/over-threshold@" + dOver
	if r := s.validate(t, "demo-enforce", img); r.Allowed {
		t.Fatal("expected deny before reload")
	}
	relaxed := strings.Replace(string(base), "maxRisk: 40", "maxRisk: 90", 2)
	write([]byte(relaxed), t0.Add(time.Minute))
	waitFor(t, func() bool { return s.validate(t, "demo-enforce", img).Allowed })

	// A broken policy keeps the last good one and bumps the error counter.
	write([]byte("version: 1\ndefault: [\n"), t0.Add(2*time.Minute))
	waitFor(t, func() bool {
		_, m := get(t, "http://"+s.addrs.Metrics+"/metrics")
		return strings.Contains(m, `kevgate_admit_reload_errors_total{component="policy"} 1`)
	})
	if r := s.validate(t, "demo-enforce", img); !r.Allowed {
		t.Fatal("last good policy was discarded")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestServeStartupErrors(t *testing.T) {
	dir := t.TempDir()
	badPolicy := filepath.Join(dir, "p.yaml")
	_ = os.WriteFile(badPolicy, []byte("version: 9"), 0o600)
	notDir := filepath.Join(dir, "file")
	_ = os.WriteFile(notDir, []byte("x"), 0o600)
	mk := func(mod func(*Config)) Config {
		c := Config{
			Listen: "127.0.0.1:0", MetricsListen: "127.0.0.1:0", SelfSigned: true, Hosts: []string{"localhost"},
			PolicyFile: demoPath("policy.yaml"), KEVFile: demoPath("kev-demo.json"), EvidenceDir: demoPath("reports"),
			FailMode: "closed", ReloadInterval: time.Second, ShutdownTimeout: time.Second,
		}
		mod(&c)
		return c
	}
	tests := []struct {
		name string
		mod  func(*Config)
	}{
		{"bad policy", func(c *Config) { c.PolicyFile = badPolicy }},
		{"missing kev", func(c *Config) { c.KEVFile = filepath.Join(dir, "none") }},
		{"missing epss", func(c *Config) { c.EPSSFile = filepath.Join(dir, "none") }},
		{"evidence dir is a file", func(c *Config) { c.EvidenceDir = notDir }},
		{"missing token file", func(c *Config) { c.EvidenceURL = "http://x"; c.EvidenceToken = filepath.Join(dir, "none") }},
		{"no self-signed hosts", func(c *Config) { c.Hosts = nil }},
		{"missing tls files", func(c *Config) {
			c.SelfSigned = false
			c.TLSCertFile = filepath.Join(dir, "c")
			c.TLSKeyFile = filepath.Join(dir, "k")
		}},
		{"bad listen", func(c *Config) { c.Listen = "999.1.1.1:99999" }},
		{"bad metrics listen", func(c *Config) { c.MetricsListen = "999.1.1.1:99999" }},
		{"unwritable CA path", func(c *Config) { c.SelfSignedCA = filepath.Join(dir, "no", "ca.pem") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := Serve(ctx, mk(tc.mod), slog.New(slog.NewJSONHandler(io.Discard, nil)), nil); err == nil {
				t.Fatal("expected startup error")
			}
		})
	}
}

func TestServeWithCertFilesEPSSAndHTTPProvider(t *testing.T) {
	dir := t.TempDir()
	// Reuse the self-signed generator to produce mounted-secret style files.
	var logs bytes.Buffer
	_ = logs
	epssFile := filepath.Join(dir, "epss.csv")
	_ = os.WriteFile(epssFile, []byte("cve,epss,percentile\nCVE-2099-10004,0.9,0.99\n"), 0o600)
	tokFile := filepath.Join(dir, "tok")
	_ = os.WriteFile(tokFile, []byte("secret\n"), 0o600)
	certFile, keyFile := writeCert(t, dir)

	cfg, err := ParseServeFlags([]string{
		"-listen", "127.0.0.1:0", "-metrics-listen", "127.0.0.1:0",
		"-tls-cert-file", certFile, "-tls-key-file", keyFile,
		"-policy-file", demoPath("policy.yaml"), "-kev-file", demoPath("kev-demo.json"),
		"-epss-file", epssFile, "-evidence-dir", demoPath("reports"),
		"-evidence-url", "http://127.0.0.1:1", "-evidence-token-file", tokFile,
		"-fail-mode", "open", "-reload-interval", "50ms", "-log-level", "debug",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan Addrs, 1)
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)), ready) }()
	addrs := <-ready
	if c, _ := get(t, "http://"+addrs.Metrics+"/readyz"); c != 200 {
		t.Errorf("readyz %d", c)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestParseServeFlags(t *testing.T) {
	ok := []string{"-self-signed", "-policy-file", "p", "-kev-file", "k", "-evidence-dir", "d"}
	if _, err := ParseServeFlags(ok, io.Discard); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no tls", []string{"-policy-file", "p", "-kev-file", "k", "-evidence-dir", "d"}, "-tls-cert-file"},
		{"both tls modes", append([]string{"-tls-cert-file", "c"}, ok...), "cannot be combined"},
		{"no policy", []string{"-self-signed", "-kev-file", "k", "-evidence-dir", "d"}, "-policy-file"},
		{"no kev", []string{"-self-signed", "-policy-file", "p", "-evidence-dir", "d"}, "-kev-file"},
		{"no evidence", []string{"-self-signed", "-policy-file", "p", "-kev-file", "k"}, "-evidence-dir"},
		{"bad fail mode", append([]string{"-fail-mode", "maybe"}, ok...), "-fail-mode"},
		{"bad duration", append([]string{"-lookup-timeout", "0s"}, ok...), "positive"},
		{"stray arg", append(ok, "extra"), "unexpected argument"},
		{"unknown flag", append(ok, "-nope"), "nope"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseServeFlags(tc.args, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunSubcommands(t *testing.T) {
	ctx := context.Background()
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Run(ctx, args, &out, &errb)
		return code, out.String(), errb.String()
	}
	if c, o, _ := run("version"); c != 0 || !strings.Contains(o, "kevgate-admit") {
		t.Errorf("version: %d %q", c, o)
	}
	if c, o, _ := run("help"); c != 0 || !strings.Contains(o, "usage:") {
		t.Errorf("help: %d", c)
	}
	if c, _, e := run(); c != 2 || !strings.Contains(e, "usage:") {
		t.Errorf("no args: %d", c)
	}
	if c, _, e := run("bogus"); c != 2 || !strings.Contains(e, "unknown command") {
		t.Errorf("bogus: %d", c)
	}
	if c, o, _ := run("check-policy", "-policy-file", demoPath("policy.yaml")); c != 0 || !strings.Contains(o, "policy ok") {
		t.Errorf("check-policy ok: %d %q", c, o)
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	_ = os.WriteFile(bad, []byte("version: 1\ndefault:\n  maxRsik: 1\n"), 0o600)
	if c, _, e := run("check-policy", "-policy-file", bad); c != 1 || !strings.Contains(e, "maxRsik") {
		t.Errorf("check-policy bad: %d %q", c, e)
	}
	if c, _, _ := run("check-policy", "-policy-file", filepath.Join(t.TempDir(), "none")); c != 1 {
		t.Errorf("check-policy missing: %d", c)
	}
	if c, _, _ := run("check-policy"); c != 2 {
		t.Errorf("check-policy no flag: %d", c)
	}
	if c, _, _ := run("check-policy", "-nope"); c != 2 {
		t.Errorf("check-policy bad flag: %d", c)
	}
	if c, _, e := run("kev-refresh"); c != 2 || !strings.Contains(e, "-out") {
		t.Errorf("kev-refresh no out: %d", c)
	}
	if c, _, e := run("kev-refresh", "-out", filepath.Join(t.TempDir(), "k.json"), "-url", "http://insecure.invalid/k.json"); c != 1 || !strings.Contains(e, "non-HTTPS") {
		t.Errorf("kev-refresh http: %d %q", c, e)
	}
	if c, _, _ := run("kev-refresh", "-nope"); c != 2 {
		t.Errorf("kev-refresh bad flag: %d", c)
	}
	if c, _, _ := run("serve", "-nope"); c != 2 {
		t.Errorf("serve bad flag: %d", c)
	}
	if c, _, _ := run("serve", "-h"); c != 0 {
		t.Errorf("serve -h: %d", c)
	}
	if c, _, _ := run("serve", "-self-signed", "-policy-file", filepath.Join(t.TempDir(), "none"), "-kev-file", "k", "-evidence-dir", "d"); c != 1 {
		t.Errorf("serve with missing policy: %d", c)
	}
	if c, _, _ := run("check-policy", "-h"); c != 0 {
		t.Errorf("check-policy -h: %d", c)
	}
	if c, _, _ := run("kev-refresh", "-h"); c != 0 {
		t.Errorf("kev-refresh -h: %d", c)
	}
}

func TestNewLoggerLevels(t *testing.T) {
	var b bytes.Buffer
	l := newLogger(&b, "warn")
	l.Info("hidden")
	l.Warn("shown")
	if strings.Contains(b.String(), "hidden") || !strings.Contains(b.String(), "shown") {
		t.Errorf("logs = %s", b.String())
	}
	b.Reset()
	newLogger(&b, "nonsense").Info("default-info")
	if !strings.Contains(b.String(), "default-info") {
		t.Error("unknown level must fall back to info")
	}
}

func TestSignalContextCancels(t *testing.T) {
	ctx, stop := SignalContext()
	stop()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("context not cancelled by stop")
	}
}
