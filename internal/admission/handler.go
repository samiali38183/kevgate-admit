package admission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/samiali38183/kevgate-admit/internal/evidence"
	"github.com/samiali38183/kevgate-admit/internal/imageref"
	"github.com/samiali38183/kevgate-admit/internal/metrics"
	"github.com/samiali38183/kevgate-admit/internal/policy"
)

// Defaults for Handler fields left at zero.
const (
	DefaultMaxBody       = 4 << 20
	DefaultEvalTimeout   = 8 * time.Second
	DefaultLookupTimeout = 3 * time.Second
	DefaultConcurrency   = 8
)

// Handler serves AdmissionReview requests. The snapshot functions are called
// once per request so hot-reloaded files are consistent within a request.
type Handler struct {
	Policy   func() *policy.Policy
	KEV      func() policy.KEVSet
	EPSS     func() policy.EPSSSource // optional
	Provider evidence.Provider
	Metrics  *metrics.Metrics
	Log      *slog.Logger
	FailMode policy.FailMode

	MaxBody       int64
	EvalTimeout   time.Duration
	LookupTimeout time.Duration
	Concurrency   int
	Now           func() time.Time

	once sync.Once
	sem  chan struct{}
}

func (h *Handler) init() {
	h.once.Do(func() {
		if h.MaxBody <= 0 {
			h.MaxBody = DefaultMaxBody
		}
		if h.EvalTimeout <= 0 {
			h.EvalTimeout = DefaultEvalTimeout
		}
		if h.LookupTimeout <= 0 {
			h.LookupTimeout = DefaultLookupTimeout
		}
		if h.Concurrency <= 0 {
			h.Concurrency = DefaultConcurrency
		}
		if h.Now == nil {
			h.Now = time.Now
		}
		if h.Log == nil {
			h.Log = slog.New(slog.NewJSONHandler(io.Discard, nil))
		}
		if h.FailMode == "" {
			h.FailMode = policy.FailClosed
		}
		if h.Metrics == nil {
			h.Metrics = metrics.New()
		}
		h.sem = make(chan struct{}, h.Concurrency)
	})
}

// ServeHTTP implements http.Handler for POST /validate.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.init()
	start := time.Now()
	code := h.serve(w, r)
	h.Metrics.Requests.WithLabelValues(strconv.Itoa(code)).Inc()
	h.Metrics.Duration.Observe(time.Since(start).Seconds())
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) int {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		return httpError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return httpError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.MaxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return httpError(w, http.StatusRequestEntityTooLarge, "request body too large")
		}
		return httpError(w, http.StatusBadRequest, "cannot read request body")
	}
	rev, err := DecodeReview(body)
	if err != nil {
		h.Log.Warn("rejected malformed admission review", "error", err.Error())
		return httpError(w, http.StatusBadRequest, "malformed admission review")
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.EvalTimeout)
	defer cancel()
	resp := h.Review(ctx, rev.Request)
	out := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Response: resp,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(&out); err != nil {
		h.Log.Warn("writing response failed", "error", err.Error())
	}
	return http.StatusOK
}

func httpError(w http.ResponseWriter, code int, msg string) int {
	http.Error(w, msg, code)
	return code
}

// Review evaluates one admission request. It never panics: an internal error
// becomes a response according to the configured fail mode.
func (h *Handler) Review(ctx context.Context, req *admissionv1.AdmissionRequest) (resp *admissionv1.AdmissionResponse) {
	h.init()
	start := time.Now()
	defer func() {
		if rec := recover(); rec != nil {
			h.Log.Error("panic while evaluating request", "uid", string(req.UID), "panic", fmt.Sprint(rec))
			resp = h.failure(req, "internal error")
		}
	}()
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		return &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
	}
	wl, err := Extract(req)
	if err != nil {
		h.Log.Warn("cannot extract images", "uid", string(req.UID), "kind", req.Kind.Kind, "error", err.Error())
		return h.failure(req, "cannot read workload: "+err.Error())
	}
	pol := h.Policy()
	if pol == nil {
		return h.failure(req, "no policy loaded")
	}
	scope, rule := pol.RuleFor(req.Namespace)

	inputs := h.resolve(ctx, rule, wl.Images)
	env := policy.Env{Namespace: req.Namespace, Now: h.Now(), FailMode: h.FailMode}
	if h.KEV != nil {
		env.KEV = h.KEV()
	}
	if h.EPSS != nil {
		env.EPSS = h.EPSS()
	}
	d := pol.Evaluate(env, inputs)
	h.record(req, wl, d, scope, time.Since(start))

	resp = &admissionv1.AdmissionResponse{UID: req.UID, Allowed: d.Allowed(), Warnings: d.ResponseWarnings()}
	if !d.Allowed() {
		resp.Result = &metav1.Status{
			Status:  metav1.StatusFailure,
			Code:    http.StatusForbidden,
			Reason:  metav1.StatusReasonForbidden,
			Message: d.Message(),
		}
	}
	return resp
}

func (h *Handler) failure(req *admissionv1.AdmissionRequest, why string) *admissionv1.AdmissionResponse {
	h.Metrics.Decisions.WithLabelValues(string(policy.OutcomeError), "_none", "internal").Inc()
	if h.FailMode == policy.FailOpen {
		return &admissionv1.AdmissionResponse{
			UID: req.UID, Allowed: true,
			Warnings: []string{"kevgate-admit: " + why + " (failing open, request not evaluated)"},
		}
	}
	return &admissionv1.AdmissionResponse{
		UID: req.UID, Allowed: false,
		Result: &metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusInternalServerError, Reason: metav1.StatusReasonInternalError,
			Message: "kevgate-admit: " + why + " (failing closed)",
		},
	}
}

// resolve parses the references and looks up evidence for the pinned ones,
// concurrently and with a bound on in-flight lookups across all requests.
func (h *Handler) resolve(ctx context.Context, rule *policy.Rule, raws []string) []policy.ImageInput {
	inputs := make([]policy.ImageInput, len(raws))
	var wg sync.WaitGroup
	for i, raw := range raws {
		in := &inputs[i]
		in.Raw = raw
		in.Ref, in.RefErr = imageref.Parse(raw)
		if in.RefErr != nil || !in.Ref.Pinned() || !rule.NeedsEvidence() {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			in.Evidence, in.EvidenceErr = h.lookup(ctx, in.Ref.Digest)
		}()
	}
	wg.Wait()
	return inputs
}

type lookupResult struct {
	ev  *evidence.Evidence
	err error
}

func (h *Handler) lookup(ctx context.Context, digest string) (*evidence.Evidence, error) {
	start := time.Now()
	ev, err := h.lookupBounded(ctx, digest)
	result := "found"
	switch {
	case err == nil:
	case errors.Is(err, evidence.ErrNotFound):
		result = "not_found"
	case errors.Is(err, context.DeadlineExceeded):
		result = "timeout"
	default:
		result = "error"
	}
	h.Metrics.Lookup.WithLabelValues(h.Provider.Name(), result).Observe(time.Since(start).Seconds())
	return ev, err
}

// lookupBounded enforces the lookup timeout even when a provider ignores its
// context: the call runs in its own goroutine and the caller stops waiting at
// the deadline.
func (h *Handler) lookupBounded(ctx context.Context, digest string) (*evidence.Evidence, error) {
	lctx, cancel := context.WithTimeout(ctx, h.LookupTimeout)
	defer cancel()
	select {
	case h.sem <- struct{}{}:
	case <-lctx.Done():
		return nil, fmt.Errorf("waiting for a lookup slot: %w", lctx.Err())
	}
	ch := make(chan lookupResult, 1)
	go func() {
		defer func() { <-h.sem }()
		defer func() {
			if rec := recover(); rec != nil {
				ch <- lookupResult{err: fmt.Errorf("provider panic: %v", rec)}
			}
		}()
		ev, err := h.Provider.Lookup(lctx, digest)
		ch <- lookupResult{ev, err}
	}()
	select {
	case r := <-ch:
		return r.ev, r.err
	case <-lctx.Done():
		return nil, fmt.Errorf("evidence lookup: %w", lctx.Err())
	}
}

func (h *Handler) record(req *admissionv1.AdmissionRequest, wl *Workload, d *policy.Decision, scope string, took time.Duration) {
	label := scope
	rule := d.PrimaryRule()
	if rule == "" {
		rule = "none"
	}
	h.Metrics.Decisions.WithLabelValues(string(d.Outcome()), label, rule).Inc()
	for range d.Applied {
		h.Metrics.Exceptions.WithLabelValues("applied").Inc()
	}
	for _, id := range d.Expired {
		h.Metrics.Exceptions.WithLabelValues("expired").Inc()
		h.Log.Warn("expired policy exception matched and was not applied", "exception", id, "namespace", req.Namespace, "scope", scope)
	}
	h.Log.Info("admission decision",
		"uid", string(req.UID),
		"operation", string(req.Operation),
		"kind", wl.Kind,
		"name", wl.Name,
		"namespace", req.Namespace,
		"scope", scope,
		"mode", string(d.Mode),
		"outcome", string(d.Outcome()),
		"rule", rule,
		"images", len(wl.Images),
		"violations", len(d.Violations),
		"exceptions_applied", d.Applied,
		"duration_ms", took.Milliseconds(),
	)
}
