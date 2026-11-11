// Package app wires the webhook together: flags, hot-reloaded inputs, the TLS
// listener, the metrics and health listener, and graceful shutdown.
package app

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/samiali38183/kevgate-admit/internal/admission"
	"github.com/samiali38183/kevgate-admit/internal/epss"
	"github.com/samiali38183/kevgate-admit/internal/evidence"
	"github.com/samiali38183/kevgate-admit/internal/evsign"
	"github.com/samiali38183/kevgate-admit/internal/kev"
	"github.com/samiali38183/kevgate-admit/internal/metrics"
	"github.com/samiali38183/kevgate-admit/internal/policy"
	"github.com/samiali38183/kevgate-admit/internal/reload"
	"github.com/samiali38183/kevgate-admit/internal/tlsutil"
)

// Version is set at build time with -ldflags.
var Version = "dev"

// Config is the serve configuration.
type Config struct {
	Listen        string
	MetricsListen string
	TLSCertFile   string
	TLSKeyFile    string
	SelfSigned    bool
	SelfSignedCA  string // where to write the CA PEM in self-signed mode
	Hosts         []string

	PolicyFile    string
	KEVFile       string
	EPSSFile      string
	EvidenceDir   string
	EvidenceURL   string
	EvidenceToken string // path to a file holding the token
	// EvidencePublicKey is a PEM file of trusted report-signing public keys.
	// When set, report signatures are verified; policies decide with
	// requireSignedEvidence.
	EvidencePublicKey string

	FailMode        policy.FailMode
	EvalTimeout     time.Duration
	LookupTimeout   time.Duration
	MaxRequestBytes int64
	ReloadInterval  time.Duration
	ShutdownTimeout time.Duration
	LogLevel        string
}

// Run executes a subcommand and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "serve":
		cfg, err := ParseServeFlags(args[1:], stderr)
		if err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		log := newLogger(stderr, cfg.LogLevel)
		if err := Serve(ctx, cfg, log, nil); err != nil {
			log.Error("server stopped with error", "error", err.Error())
			return 1
		}
		return 0
	case "kev-refresh":
		return kevRefresh(ctx, args[1:], stdout, stderr)
	case "check-policy":
		return checkPolicy(args[1:], stdout, stderr)
	case "keygen":
		return keygen(args[1:], stdout, stderr)
	case "sign-report":
		return signReport(args[1:], stdout, stderr)
	case "verify-report":
		return verifyReport(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "kevgate-admit", Version)
		return 0
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: kevgate-admit <command> [flags]

commands:
  serve         run the admission webhook
  kev-refresh   download and validate the CISA KEV catalog
  check-policy  validate a policy file
  keygen        create a report-signing key pair (Ed25519 or ECDSA P-256)
  sign-report   write a detached signature next to each scan report
  verify-report check a report signature offline
  version       print the version
`)
}

// ParseServeFlags parses the serve flags and validates the combination.
func ParseServeFlags(args []string, out io.Writer) (Config, error) {
	var c Config
	var hosts, fail string
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&c.Listen, "listen", ":8443", "address of the TLS admission listener")
	fs.StringVar(&c.MetricsListen, "metrics-listen", ":8080", "address of the plain HTTP listener for /metrics, /healthz, /readyz")
	fs.StringVar(&c.TLSCertFile, "tls-cert-file", "", "serving certificate (PEM); reloaded when the file changes")
	fs.StringVar(&c.TLSKeyFile, "tls-key-file", "", "serving key (PEM)")
	fs.BoolVar(&c.SelfSigned, "self-signed", false, "generate a throw-away certificate in memory (CI and local development only)")
	fs.StringVar(&hosts, "self-signed-hosts", "localhost,127.0.0.1", "comma separated DNS names and IPs for the self-signed certificate")
	fs.StringVar(&c.SelfSignedCA, "self-signed-ca-out", "", "write the self-signed certificate PEM here so it can be used as caBundle")
	fs.StringVar(&c.PolicyFile, "policy-file", "", "policy YAML (hot reloaded)")
	fs.StringVar(&c.KEVFile, "kev-file", "", "CISA KEV catalog JSON (hot reloaded)")
	fs.StringVar(&c.EPSSFile, "epss-file", "", "optional EPSS CSV (hot reloaded)")
	fs.StringVar(&c.EvidenceDir, "evidence-dir", "", "directory of Trivy reports named <algo>-<hex>.json")
	fs.StringVar(&c.EvidenceURL, "evidence-url", "", "optional kevgate base URL used when no report file exists")
	fs.StringVar(&c.EvidenceToken, "evidence-token-file", "", "file holding a bearer token for -evidence-url")
	fs.StringVar(&c.EvidencePublicKey, "evidence-public-key-file", "", "PEM public key(s) (Ed25519 or ECDSA P-256) that sign reports; enables <report>.json.sig verification for policies with requireSignedEvidence")
	fs.StringVar(&fail, "fail-mode", "closed", "closed: deny when the evidence source fails; open: allow with a warning")
	fs.DurationVar(&c.EvalTimeout, "eval-timeout", admission.DefaultEvalTimeout, "time budget per admission request (keep below the webhook timeoutSeconds)")
	fs.DurationVar(&c.LookupTimeout, "lookup-timeout", admission.DefaultLookupTimeout, "time budget per evidence lookup")
	fs.Int64Var(&c.MaxRequestBytes, "max-request-bytes", admission.DefaultMaxBody, "maximum admission request body")
	fs.DurationVar(&c.ReloadInterval, "reload-interval", 15*time.Second, "how often files are checked for changes")
	fs.DurationVar(&c.ShutdownTimeout, "shutdown-timeout", 15*time.Second, "grace period for in-flight requests")
	fs.StringVar(&c.LogLevel, "log-level", "info", "debug, info, warn or error")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() > 0 {
		return c, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	switch policy.FailMode(fail) {
	case policy.FailClosed, policy.FailOpen:
		c.FailMode = policy.FailMode(fail)
	default:
		return c, fmt.Errorf("-fail-mode must be closed or open, got %q", fail)
	}
	for _, h := range strings.Split(hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			c.Hosts = append(c.Hosts, h)
		}
	}
	switch {
	case c.SelfSigned && (c.TLSCertFile != "" || c.TLSKeyFile != ""):
		return c, errors.New("-self-signed cannot be combined with -tls-cert-file/-tls-key-file")
	case !c.SelfSigned && (c.TLSCertFile == "" || c.TLSKeyFile == ""):
		return c, errors.New("-tls-cert-file and -tls-key-file are required (or use -self-signed for development)")
	case c.PolicyFile == "":
		return c, errors.New("-policy-file is required")
	case c.KEVFile == "":
		return c, errors.New("-kev-file is required")
	case c.EvidenceDir == "" && c.EvidenceURL == "":
		return c, errors.New("-evidence-dir or -evidence-url is required")
	case c.EvidencePublicKey != "" && c.EvidenceDir == "":
		return c, errors.New("-evidence-public-key-file needs -evidence-dir (signatures are files next to the reports)")
	case c.ReloadInterval <= 0 || c.EvalTimeout <= 0 || c.LookupTimeout <= 0:
		return c, errors.New("durations must be positive")
	}
	return c, nil
}

func newLogger(w io.Writer, level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l}))
}

// Addrs are the bound listener addresses, useful when listening on port 0.
type Addrs struct {
	Admission string
	Metrics   string
	CAPEM     []byte
}

// Serve runs until ctx is cancelled. If ready is non-nil it receives the bound
// addresses once both listeners accept connections.
func Serve(ctx context.Context, cfg Config, log *slog.Logger, ready chan<- Addrs) error {
	m := metrics.New()
	onErr := func(component string) func(error) {
		return func(err error) {
			log.Error("reload failed, keeping previous version", "component", component, "error", err.Error())
		}
	}

	pol, err := reload.New("policy", cfg.PolicyFile, policy.MaxPolicyBytes, policy.Parse, m)
	if err != nil {
		return err
	}
	catalog, err := reload.New("kev", cfg.KEVFile, kev.DefaultMaxBytes, kev.Parse, m)
	if err != nil {
		return err
	}
	m.KEVEntries.Set(float64(catalog.Get().Len()))
	m.Registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "kevgate_admit_kev_catalog_mtime_seconds",
		Help: "Modification time of the loaded KEV catalog file, as a Unix timestamp. Alert when it gets old.",
	}, func() float64 { return float64(catalog.ModTime().Unix()) }))
	var epssTable *reload.File[epss.Table]
	if cfg.EPSSFile != "" {
		if epssTable, err = reload.New("epss", cfg.EPSSFile, 64<<20, epss.Parse, m); err != nil {
			return err
		}
	}

	provider, err := buildProvider(cfg)
	if err != nil {
		return err
	}
	if pol.Get().RequiresSignedEvidence() && cfg.EvidencePublicKey == "" {
		log.Warn("the policy sets requireSignedEvidence but no -evidence-public-key-file is configured: every report will be treated as unauthenticated")
	}

	var certs *tlsutil.Reloader
	var caPEM []byte
	if cfg.SelfSigned {
		var cert tls.Certificate
		cert, caPEM, err = tlsutil.SelfSigned(cfg.Hosts, 365*24*time.Hour)
		if err != nil {
			return err
		}
		certs = tlsutil.Static(cert)
		if cfg.SelfSignedCA != "" {
			if err := os.WriteFile(cfg.SelfSignedCA, caPEM, 0o644); err != nil { // #nosec G306 -- public CA certificate, must be readable by clients
				return fmt.Errorf("write CA: %w", err)
			}
		}
		log.Warn("serving a self-signed certificate; do not use this mode in production")
	} else if certs, err = tlsutil.NewReloader(cfg.TLSCertFile, cfg.TLSKeyFile, m); err != nil {
		return err
	}

	h := &admission.Handler{
		Policy:        pol.Get,
		KEV:           func() policy.KEVSet { return catalog.Get() },
		Provider:      provider,
		Metrics:       m,
		Log:           log,
		FailMode:      cfg.FailMode,
		MaxBody:       cfg.MaxRequestBytes,
		EvalTimeout:   cfg.EvalTimeout,
		LookupTimeout: cfg.LookupTimeout,
	}
	if epssTable != nil {
		h.EPSS = func() policy.EPSSSource { return epssTable.Get() }
	}

	mux := http.NewServeMux()
	mux.Handle("POST /validate", h)
	mux.Handle("/validate", h) // lets the handler answer 405 for other methods
	admSrv := &http.Server{
		Handler:           mux,
		TLSConfig:         certs.Config(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      cfg.EvalTimeout + 5*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ready200 := func(w http.ResponseWriter, _ *http.Request) {
		if pol.Get() == nil || catalog.Get() == nil || !certs.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	}
	mmux := http.NewServeMux()
	mmux.Handle("GET /metrics", m.Handler())
	mmux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mmux.HandleFunc("GET /readyz", ready200)
	metSrv := &http.Server{
		Handler:           mmux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	var lc net.ListenConfig
	admLn, err := lc.Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	metLn, err := lc.Listen(ctx, "tcp", cfg.MetricsListen)
	if err != nil {
		_ = admLn.Close()
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go pol.Run(runCtx, cfg.ReloadInterval, onErr("policy"))
	go func() {
		catalog.Run(runCtx, cfg.ReloadInterval, onErr("kev"))
	}()
	go keepKEVGauge(runCtx, catalog, m, cfg.ReloadInterval)
	if epssTable != nil {
		go epssTable.Run(runCtx, cfg.ReloadInterval, onErr("epss"))
	}
	if !cfg.SelfSigned {
		go certs.Run(runCtx, cfg.ReloadInterval, onErr("tls"))
	}

	errc := make(chan error, 2)
	go func() { errc <- wrapServe(admSrv.ServeTLS(admLn, "", "")) }()
	go func() { errc <- wrapServe(metSrv.Serve(metLn)) }()
	log.Info("kevgate-admit started",
		"version", Version, "admission", admLn.Addr().String(), "metrics", metLn.Addr().String(),
		"fail_mode", string(cfg.FailMode), "provider", provider.Name(), "evidence_signatures", cfg.EvidencePublicKey != "", "kev_entries", catalog.Get().Len())
	if ready != nil {
		ready <- Addrs{Admission: admLn.Addr().String(), Metrics: metLn.Addr().String(), CAPEM: caPEM}
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	log.Info("shutting down")
	shCtx, shCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shCancel()
	_ = admSrv.Shutdown(shCtx)
	_ = metSrv.Shutdown(shCtx)
	cancel()
	return serveErr
}

func wrapServe(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func keepKEVGauge(ctx context.Context, c *reload.File[kev.Catalog], m *metrics.Metrics, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.KEVEntries.Set(float64(c.Get().Len()))
		}
	}
}

func buildProvider(cfg Config) (evidence.Provider, error) {
	var chain evidence.Chain
	if cfg.EvidenceDir != "" {
		fi, err := os.Stat(cfg.EvidenceDir)
		if err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("-evidence-dir %q is not a readable directory", cfg.EvidenceDir)
		}
		dp := &evidence.DirProvider{Dir: cfg.EvidenceDir}
		if cfg.EvidencePublicKey != "" {
			data, err := os.ReadFile(cfg.EvidencePublicKey)
			if err != nil {
				return nil, fmt.Errorf("-evidence-public-key-file: %w", err)
			}
			if dp.Verifier, err = evsign.NewVerifier(data); err != nil {
				return nil, fmt.Errorf("-evidence-public-key-file: %w", err)
			}
		}
		chain = append(chain, dp)
	}
	if cfg.EvidenceURL != "" {
		p := &evidence.HTTPProvider{BaseURL: cfg.EvidenceURL, Client: &http.Client{Timeout: cfg.LookupTimeout}}
		if cfg.EvidenceToken != "" {
			tok, err := os.ReadFile(cfg.EvidenceToken)
			if err != nil {
				return nil, fmt.Errorf("evidence token: %w", err)
			}
			p.Token = strings.TrimSpace(string(tok))
		}
		chain = append(chain, p)
	}
	if len(chain) == 1 {
		return chain[0], nil
	}
	return chain, nil
}

// SignalContext returns a context cancelled on SIGINT or SIGTERM.
func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func kevRefresh(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kev-refresh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", kev.DefaultURL, "feed URL (https only)")
	out := fs.String("out", "", "destination file")
	timeout := fs.Duration("timeout", 30*time.Second, "request timeout")
	maxBytes := fs.Int64("max-bytes", kev.DefaultMaxBytes, "maximum feed size")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *out == "" {
		fmt.Fprintln(stderr, "error: -out is required")
		return 2
	}
	n, err := kev.Refresh(ctx, kev.RefreshOptions{URL: *url, Dest: *out, Timeout: *timeout, MaxBytes: *maxBytes})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %d KEV entries to %s\n", n, *out)
	return 0
}

func checkPolicy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check-policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("policy-file", "", "policy YAML to validate")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *file == "" {
		fmt.Fprintln(stderr, "error: -policy-file is required")
		return 2
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	p, err := policy.Parse(data)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(stdout, "policy ok: mode %s, %d namespace rule(s)\n", p.Mode, len(p.Namespaces))
	return 0
}
