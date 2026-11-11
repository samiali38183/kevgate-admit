package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	admissionv1 "k8s.io/api/admission/v1"

	"github.com/samiali38183/kevgate-admit/internal/evidence"
	"github.com/samiali38183/kevgate-admit/internal/metrics"
	"github.com/samiali38183/kevgate-admit/internal/policy"
	"github.com/samiali38183/kevgate-admit/internal/vuln"
)

const (
	dA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

var podSpec = func(images ...string) string {
	var cs []string
	for i, im := range images {
		cs = append(cs, fmt.Sprintf(`{"name":"c%d","image":%q}`, i, im))
	}
	return `{"containers":[` + strings.Join(cs, ",") + `]}`
}

// objects builds the object JSON for each supported kind.
func object(kind string, spec string) string {
	tpl := `{"spec":` + spec + `}`
	switch kind {
	case "Pod":
		return `{"metadata":{"name":"obj"},"spec":` + spec + `}`
	case "CronJob":
		return `{"metadata":{"name":"obj"},"spec":{"jobTemplate":{"spec":{"template":` + tpl + `}}}}`
	}
	return `{"metadata":{"name":"obj"},"spec":{"template":` + tpl + `}}`
}

var kinds = []struct{ group, kind string }{
	{"", "Pod"}, {"apps", "Deployment"}, {"apps", "StatefulSet"}, {"apps", "DaemonSet"}, {"batch", "Job"}, {"batch", "CronJob"},
}

func review(group, kind, op, ns, obj, old string) string {
	oldField := ""
	if old != "" {
		oldField = `,"oldObject":` + old
	}
	return fmt.Sprintf(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"u-1","kind":{"group":%q,"version":"v1","kind":%q},"resource":{"group":%q,"version":"v1","resource":"x"},"operation":%q,"namespace":%q,"object":%s%s}}`,
		group, kind, group, op, ns, obj, oldField)
}

func TestDecodeReview(t *testing.T) {
	good := review("", "Pod", "CREATE", "ns", object("Pod", podSpec("a")), "")
	rev, err := DecodeReview([]byte(good))
	if err != nil || rev.Request.UID != "u-1" {
		t.Fatalf("%v", err)
	}
	tests := []struct{ name, in string }{
		{"empty", ``},
		{"not json", `{`},
		{"array", `[]`},
		{"unknown envelope field", strings.Replace(good, `"request"`, `"extra":1,"request"`, 1)},
		{"unknown request field", strings.Replace(good, `"uid"`, `"surprise":true,"uid"`, 1)},
		{"trailing data", good + `{}`},
		{"trailing garbage", good + ` x`},
		{"wrong apiVersion", strings.Replace(good, "admission.k8s.io/v1", "admission.k8s.io/v1beta1", 1)},
		{"wrong kind", strings.Replace(good, `"AdmissionReview"`, `"Other"`, 1)},
		{"no request", `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`},
		{"empty uid", strings.Replace(good, `"u-1"`, `""`, 1)},
		{"wrong type", strings.Replace(good, `"operation":"CREATE"`, `"operation":5`, 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeReview([]byte(tc.in)); err == nil || !errors.Is(err, ErrBadRequest) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func extractFrom(t *testing.T, group, kind, op, obj, old string) (*Workload, error) {
	t.Helper()
	rev, err := DecodeReview([]byte(review(group, kind, op, "ns", obj, old)))
	if err != nil {
		t.Fatal(err)
	}
	return Extract(rev.Request)
}

func TestExtractEachKind(t *testing.T) {
	spec := `{"containers":[{"name":"a","image":"img/a:1"},{"name":"b","image":"img/b@` + dA + `"},{"name":"dup","image":"img/a:1"}],
		"initContainers":[{"name":"i","image":"img/init"}],
		"ephemeralContainers":[{"name":"e","image":"img/debug"}]}`
	for _, k := range kinds {
		t.Run(k.kind, func(t *testing.T) {
			w, err := extractFrom(t, k.group, k.kind, "CREATE", object(k.kind, spec), "")
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"img/a:1", "img/b@" + dA, "img/init", "img/debug"}
			if strings.Join(w.Images, ",") != strings.Join(want, ",") {
				t.Errorf("images = %v", w.Images)
			}
			if w.Kind != k.kind || w.Name != "obj" {
				t.Errorf("workload = %+v", w)
			}
		})
	}
}

func TestExtractErrors(t *testing.T) {
	if _, err := extractFrom(t, "", "Service", "CREATE", `{}`, ""); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unsupported kind: %v", err)
	}
	if _, err := extractFrom(t, "example.com", "Pod", "CREATE", object("Pod", podSpec("a")), ""); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Pod in a foreign group must not be treated as a Pod: %v", err)
	}
	if _, err := extractFrom(t, "apps", "Deployment", "CREATE", `{"spec":"nope"}`, ""); !errors.Is(err, ErrBadRequest) {
		t.Errorf("bad object: %v", err)
	}
	rev, _ := DecodeReview([]byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"u","kind":{"kind":"Pod"},"operation":"CREATE"}}`))
	if _, err := Extract(rev.Request); !errors.Is(err, ErrBadRequest) {
		t.Errorf("empty object: %v", err)
	}
	rev, _ = DecodeReview([]byte(review("", "Pod", "CREATE", "ns", object("Pod", podSpec("a")), "")))
	rev.Request.SubResource = "status"
	if _, err := Extract(rev.Request); !errors.Is(err, ErrUnsupported) {
		t.Errorf("subresource: %v", err)
	}
	rev.Request.SubResource = "ephemeralcontainers"
	if _, err := Extract(rev.Request); err != nil {
		t.Errorf("ephemeralcontainers must be supported: %v", err)
	}
	many := make([]string, maxImages+1)
	for i := range many {
		many[i] = fmt.Sprintf("img/a%d", i)
	}
	if _, err := extractFrom(t, "", "Pod", "CREATE", object("Pod", podSpec(many...)), ""); !errors.Is(err, ErrBadRequest) {
		t.Errorf("too many images: %v", err)
	}
}

func TestExtractUpdateOnlyNewImages(t *testing.T) {
	old := object("Deployment", podSpec("img/keep@"+dA, "img/old@"+dB))
	cur := object("Deployment", podSpec("img/keep@"+dA, "img/new@"+dC))
	w, err := extractFrom(t, "apps", "Deployment", "UPDATE", cur, old)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Images) != 1 || w.Images[0] != "img/new@"+dC {
		t.Errorf("images = %v, want only the new one", w.Images)
	}
	// CREATE ignores any old object; an unreadable old object falls back to all images.
	w, _ = extractFrom(t, "apps", "Deployment", "UPDATE", cur, `{"spec":"nope"}`)
	if len(w.Images) != 2 {
		t.Errorf("fallback images = %v", w.Images)
	}
}

// ---- handler ----

type provider struct {
	byDigest map[string]*evidence.Evidence
	err      error
	delay    time.Duration
	block    chan struct{}
	calls    atomic.Int32
	panics   bool
}

func (p *provider) Name() string { return "fake" }
func (p *provider) Lookup(ctx context.Context, d string) (*evidence.Evidence, error) {
	p.calls.Add(1)
	if p.panics {
		panic("boom")
	}
	if p.block != nil {
		<-p.block // ignores ctx on purpose
	}
	if p.delay > 0 {
		select {
		case <-time.After(p.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if p.err != nil {
		return nil, p.err
	}
	if ev, ok := p.byDigest[d]; ok {
		return ev, nil
	}
	return nil, evidence.ErrNotFound
}

type kevSet map[string]bool

func (k kevSet) Contains(id string) bool { return k[id] }

const testPolicy = `
version: 1
default:
  denyKev: true
  maxRisk: 40
  requireEvidence: deny
namespaces:
  audit:
    mode: audit
    denyKev: true
  loose:
    requireEvidence: allow
`

func newHandler(t *testing.T, p *provider) (*Handler, *bytes.Buffer) {
	t.Helper()
	pol, err := policy.Parse([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	h := &Handler{
		Policy:        func() *policy.Policy { return pol },
		KEV:           func() policy.KEVSet { return kevSet{"CVE-2021-44228": true} },
		Provider:      p,
		Metrics:       metrics.New(),
		Log:           slog.New(slog.NewJSONHandler(buf, nil)),
		LookupTimeout: 200 * time.Millisecond,
		EvalTimeout:   2 * time.Second,
		Now:           func() time.Time { return time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC) },
	}
	return h, buf
}

func evid(digest string, fs ...vuln.Finding) *evidence.Evidence {
	return &evidence.Evidence{Digest: digest, Findings: fs}
}

func post(h http.Handler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decodeResp(t *testing.T, w *httptest.ResponseRecorder) *admissionv1.AdmissionResponse {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body)
	}
	var rev admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &rev); err != nil {
		t.Fatal(err)
	}
	if rev.APIVersion != "admission.k8s.io/v1" || rev.Kind != "AdmissionReview" || rev.Response == nil {
		t.Fatalf("bad envelope: %s", w.Body)
	}
	return rev.Response
}

func TestHandlerDecisionsPerKind(t *testing.T) {
	p := &provider{byDigest: map[string]*evidence.Evidence{
		dA: evid(dA, vuln.Finding{ID: "CVE-2024-0001", CVSS: 3.1}),
		dB: evid(dB, vuln.Finding{ID: "CVE-2021-44228", CVSS: 10, Package: "log4j-core", Installed: "2.14.1", Fixed: "2.17.1"}),
	}}
	h, _ := newHandler(t, p)
	for _, k := range kinds {
		t.Run(k.kind, func(t *testing.T) {
			ok := decodeResp(t, post(h, review(k.group, k.kind, "CREATE", "prod", object(k.kind, podSpec("ghcr.io/o/app@"+dA)), "")))
			if !ok.Allowed || ok.UID != "u-1" {
				t.Fatalf("clean image: %+v", ok)
			}
			bad := decodeResp(t, post(h, review(k.group, k.kind, "CREATE", "prod", object(k.kind, podSpec("ghcr.io/o/app@"+dB)), "")))
			if bad.Allowed || bad.Result == nil || bad.Result.Code != 403 {
				t.Fatalf("kev image: %+v", bad)
			}
			for _, want := range []string{"[denyKev]", "CVE-2021-44228", "log4j-core 2.14.1 (fixed 2.17.1)", `namespace "prod"`} {
				if !strings.Contains(bad.Result.Message, want) {
					t.Errorf("message lacks %q:\n%s", want, bad.Result.Message)
				}
			}
			none := decodeResp(t, post(h, review(k.group, k.kind, "CREATE", "prod", object(k.kind, podSpec("ghcr.io/o/app@"+dC)), "")))
			if none.Allowed || !strings.Contains(none.Result.Message, "[requireEvidence]") {
				t.Fatalf("unscanned image: %+v", none)
			}
		})
	}
}

func TestHandlerAuditLooseAndOperations(t *testing.T) {
	p := &provider{byDigest: map[string]*evidence.Evidence{dB: evid(dB, vuln.Finding{ID: "CVE-2021-44228", CVSS: 10})}}
	h, _ := newHandler(t, p)
	bad := object("Pod", podSpec("ghcr.io/o/app@"+dB))

	r := decodeResp(t, post(h, review("", "Pod", "CREATE", "audit", bad, "")))
	if !r.Allowed || len(r.Warnings) == 0 || !strings.Contains(r.Warnings[0], "would deny [denyKev]") {
		t.Fatalf("audit: %+v", r)
	}
	r = decodeResp(t, post(h, review("", "Pod", "CREATE", "loose", object("Pod", podSpec("ghcr.io/o/app@"+dC)), "")))
	if !r.Allowed {
		t.Fatalf("requireEvidence allow with unscanned image: %+v", r)
	}
	for _, op := range []string{"DELETE", "CONNECT"} {
		r = decodeResp(t, post(h, review("", "Pod", op, "prod", bad, "")))
		if !r.Allowed {
			t.Errorf("%s must be allowed", op)
		}
	}
	if n := p.calls.Load(); n != 1 {
		t.Errorf("provider called %d times, want 1 (audit only)", n)
	}
	// Update of a running workload whose images are unchanged is not re-judged.
	r = decodeResp(t, post(h, review("apps", "Deployment", "UPDATE", "prod", object("Deployment", podSpec("ghcr.io/o/app@"+dB)), object("Deployment", podSpec("ghcr.io/o/app@"+dB)))))
	if !r.Allowed {
		t.Errorf("unchanged update denied: %+v", r)
	}
}

func TestHandlerTagOnlyNeverLooksUp(t *testing.T) {
	p := &provider{}
	h, _ := newHandler(t, p)
	r := decodeResp(t, post(h, review("", "Pod", "CREATE", "prod", object("Pod", podSpec("nginx:latest", "bad ref")), "")))
	if r.Allowed || p.calls.Load() != 0 {
		t.Fatalf("allowed=%v calls=%d", r.Allowed, p.calls.Load())
	}
	if !strings.Contains(r.Result.Message, "no digest to look up") || !strings.Contains(r.Result.Message, "[imageRef]") {
		t.Errorf("message:\n%s", r.Result.Message)
	}
}

func TestHandlerProviderFailures(t *testing.T) {
	pod := review("", "Pod", "CREATE", "prod", object("Pod", podSpec("ghcr.io/o/app@"+dA)), "")
	tests := []struct {
		name      string
		p         *provider
		fail      policy.FailMode
		wantAllow bool
		want      string
	}{
		{"error closed", &provider{err: errors.New("malformed report")}, policy.FailClosed, false, "failing closed"},
		{"error open", &provider{err: errors.New("malformed report")}, policy.FailOpen, true, "failing open"},
		{"timeout closed", &provider{delay: 5 * time.Second}, policy.FailClosed, false, "deadline exceeded"},
		{"timeout open", &provider{delay: 5 * time.Second}, policy.FailOpen, true, "deadline exceeded"},
		{"provider ignores context", &provider{block: make(chan struct{})}, policy.FailClosed, false, "deadline exceeded"},
		{"provider panics", &provider{panics: true}, policy.FailClosed, false, "panic"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newHandler(t, tc.p)
			h.FailMode = tc.fail
			start := time.Now()
			r := decodeResp(t, post(h, pod))
			if time.Since(start) > time.Second {
				t.Errorf("took %v; lookup timeout not enforced", time.Since(start))
			}
			if r.Allowed != tc.wantAllow {
				t.Fatalf("allowed = %v: %+v", r.Allowed, r)
			}
			text := strings.Join(r.Warnings, "|")
			if r.Result != nil {
				text += r.Result.Message
			}
			if !strings.Contains(text, tc.want) {
				t.Errorf("want %q in %q", tc.want, text)
			}
			if tc.p.block != nil {
				close(tc.p.block)
			}
		})
	}
}

func TestHandlerLookupConcurrencyBound(t *testing.T) {
	p := &provider{block: make(chan struct{})}
	h, _ := newHandler(t, p)
	h.Concurrency = 1
	h.LookupTimeout = 100 * time.Millisecond
	// Two distinct digests, one slot: the second cannot start before the deadline.
	r := decodeResp(t, post(h, review("", "Pod", "CREATE", "prod", object("Pod", podSpec("a/x@"+dA, "a/y@"+dB)), "")))
	close(p.block)
	if r.Allowed || !strings.Contains(r.Result.Message, "lookup slot") {
		t.Fatalf("%+v", r)
	}
}

func TestHandlerInternalFailures(t *testing.T) {
	h, _ := newHandler(t, &provider{})
	h.Policy = func() *policy.Policy { return nil }
	pod := review("", "Pod", "CREATE", "prod", object("Pod", podSpec("a")), "")
	r := decodeResp(t, post(h, pod))
	if r.Allowed || !strings.Contains(r.Result.Message, "no policy loaded") || r.Result.Code != 500 {
		t.Fatalf("closed: %+v", r)
	}
	h.FailMode = policy.FailOpen
	r = decodeResp(t, post(h, pod))
	if !r.Allowed || !strings.Contains(r.Warnings[0], "failing open") {
		t.Fatalf("open: %+v", r)
	}
	// Unsupported kind reaches the same path.
	h2, _ := newHandler(t, &provider{})
	r = decodeResp(t, post(h2, review("", "Service", "CREATE", "prod", `{}`, "")))
	if r.Allowed {
		t.Fatalf("unsupported kind should fail closed: %+v", r)
	}
	// A panic in a snapshot function is recovered.
	h3, _ := newHandler(t, &provider{})
	h3.KEV = func() policy.KEVSet { panic("kev snapshot") }
	r = decodeResp(t, post(h3, review("", "Pod", "CREATE", "prod", object("Pod", podSpec("a/x@"+dA)), "")))
	if r.Allowed || !strings.Contains(r.Result.Message, "internal error") {
		t.Fatalf("panic: %+v", r)
	}
}

func TestHandlerHTTPLayer(t *testing.T) {
	h, _ := newHandler(t, &provider{})
	h.MaxBody = 512
	good := review("", "Pod", "CREATE", "prod", object("Pod", podSpec("a/x@"+dA)), "")

	do := func(method, ctype, body string) int {
		r := httptest.NewRequest(method, "/validate", strings.NewReader(body))
		if ctype != "" {
			r.Header.Set("Content-Type", ctype)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	tests := []struct {
		name       string
		method, ct string
		body       string
		want       int
	}{
		{"get", http.MethodGet, "application/json", "", 405},
		{"put", http.MethodPut, "application/json", good, 405},
		{"no content type", http.MethodPost, "", good, 415},
		{"wrong content type", http.MethodPost, "text/plain", good, 415},
		{"json with charset", http.MethodPost, "application/json; charset=utf-8", good, 200},
		{"too large", http.MethodPost, "application/json", good + strings.Repeat(" ", 600), 413},
		{"malformed", http.MethodPost, "application/json", `{"apiVersion":`, 400},
		{"unknown field", http.MethodPost, "application/json", strings.Replace(good, `"uid"`, `"x":1,"uid"`, 1), 400},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := do(tc.method, tc.ct, tc.body); got != tc.want {
				t.Errorf("status = %d, want %d", got, tc.want)
			}
		})
	}
	if v := testutil.ToFloat64(h.Metrics.Requests.WithLabelValues("415")); v != 2 {
		t.Errorf("415 counter = %v", v)
	}
}

func TestHandlerMetricsAndLogs(t *testing.T) {
	p := &provider{byDigest: map[string]*evidence.Evidence{dB: evid(dB, vuln.Finding{ID: "CVE-2021-44228", CVSS: 10})}}
	h, logs := newHandler(t, p)
	post(h, review("", "Pod", "CREATE", "prod", object("Pod", podSpec("ghcr.io/o/app@"+dB)), ""))
	post(h, review("", "Pod", "CREATE", "audit", object("Pod", podSpec("ghcr.io/o/app@"+dB)), ""))
	post(h, review("", "Pod", "CREATE", "prod", object("Pod", podSpec("ghcr.io/o/app@"+dC)), ""))

	m := h.Metrics.Decisions
	if v := testutil.ToFloat64(m.WithLabelValues("deny", "_default", "denyKev")); v != 1 {
		t.Errorf("deny/_default/denyKev = %v", v)
	}
	if v := testutil.ToFloat64(m.WithLabelValues("audit_deny", "audit", "denyKev")); v != 1 {
		t.Errorf("audit_deny = %v", v)
	}
	if v := testutil.ToFloat64(m.WithLabelValues("deny", "_default", "requireEvidence")); v != 1 {
		t.Errorf("requireEvidence = %v", v)
	}
	if n := testutil.CollectAndCount(h.Metrics.Lookup); n != 2 {
		t.Errorf("lookup series = %d, want found and not_found", n)
	}
	out := logs.String()
	for _, want := range []string{`"msg":"admission decision"`, `"outcome":"deny"`, `"namespace":"prod"`} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %s", want)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if _, leaked := m["object"]; leaked {
			t.Error("log must not contain the request object")
		}
	}
}

func TestExpiredExceptionIsLoggedAndCounted(t *testing.T) {
	pol, err := policy.Parse([]byte(`
version: 1
default:
  denyKev: true
  exceptions:
    - id: old-waiver
      cve: CVE-2021-44228
      justification: expired waiver for the log test
      expires: 2026-01-01
`))
	if err != nil {
		t.Fatal(err)
	}
	p := &provider{byDigest: map[string]*evidence.Evidence{dB: evid(dB, vuln.Finding{ID: "CVE-2021-44228", CVSS: 10})}}
	h, logs := newHandler(t, p)
	h.Policy = func() *policy.Policy { return pol }
	r := decodeResp(t, post(h, review("", "Pod", "CREATE", "prod", object("Pod", podSpec("a/x@"+dB)), "")))
	if r.Allowed {
		t.Fatal("expired exception must not waive")
	}
	if !strings.Contains(logs.String(), "expired policy exception") || !strings.Contains(logs.String(), "old-waiver") {
		t.Errorf("expired exception not logged:\n%s", logs)
	}
	if v := testutil.ToFloat64(h.Metrics.Exceptions.WithLabelValues("expired")); v != 1 {
		t.Errorf("expired counter = %v", v)
	}
}

func TestDefaultsApplied(t *testing.T) {
	h := &Handler{Policy: func() *policy.Policy { return nil }, Provider: &provider{}}
	w := post(h, review("", "Pod", "CREATE", "prod", object("Pod", podSpec("a")), ""))
	r := decodeResp(t, w)
	if r.Allowed {
		t.Fatal("default fail mode must be closed")
	}
	if h.MaxBody != DefaultMaxBody || h.Concurrency != DefaultConcurrency || h.LookupTimeout != DefaultLookupTimeout {
		t.Errorf("defaults not applied: %+v", h)
	}
	_ = io.Discard
}

func FuzzDecodeAndExtract(f *testing.F) {
	for _, k := range kinds {
		f.Add([]byte(review(k.group, k.kind, "CREATE", "ns", object(k.kind, podSpec("a/b@"+dA, "nginx")), "")))
	}
	f.Add([]byte(review("apps", "Deployment", "UPDATE", "ns", object("Deployment", podSpec("a")), object("Deployment", podSpec("b")))))
	f.Add([]byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"x"}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		rev, err := DecodeReview(data)
		if err != nil {
			if !errors.Is(err, ErrBadRequest) {
				t.Fatalf("decode error not wrapped: %v", err)
			}
			return
		}
		if rev.Request == nil || rev.Request.UID == "" {
			t.Fatal("accepted review without request or uid")
		}
		w, err := Extract(rev.Request)
		if err != nil {
			if !errors.Is(err, ErrBadRequest) && !errors.Is(err, ErrUnsupported) {
				t.Fatalf("extract error not wrapped: %v", err)
			}
			return
		}
		if len(w.Images) > maxImages {
			t.Fatalf("too many images: %d", len(w.Images))
		}
		seen := map[string]bool{}
		for _, i := range w.Images {
			if seen[i] {
				t.Fatalf("duplicate image %q", i)
			}
			seen[i] = true
		}
	})
}
