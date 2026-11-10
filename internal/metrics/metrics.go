// Package metrics defines the Prometheus metrics exposed by the webhook.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds every collector. It uses a private registry so tests and
// multiple instances do not collide on the global one.
type Metrics struct {
	Registry      *prometheus.Registry
	Decisions     *prometheus.CounterVec
	Requests      *prometheus.CounterVec
	Duration      prometheus.Histogram
	Lookup        *prometheus.HistogramVec
	Reloads       *prometheus.CounterVec
	ReloadErrors  *prometheus.CounterVec
	Exceptions    *prometheus.CounterVec
	KEVEntries    prometheus.Gauge
	PolicyApplied prometheus.Gauge
}

// New creates and registers all metrics.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kevgate_admit_decisions_total",
			Help: "Admission decisions by outcome, policy scope (namespace with its own rule, else _default) and first rule that fired.",
		}, []string{"outcome", "namespace", "rule"}),
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kevgate_admit_requests_total",
			Help: "HTTP requests to the validate endpoint by status code.",
		}, []string{"code"}),
		Duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "kevgate_admit_request_duration_seconds",
			Help:    "End to end time spent handling an admission review.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}),
		Lookup: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kevgate_admit_evidence_lookup_seconds",
			Help:    "Time spent looking up evidence for one image digest.",
			Buckets: []float64{.0005, .001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}, []string{"provider", "result"}),
		Reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kevgate_admit_reloads_total",
			Help: "Successful hot reloads by component (policy, kev, epss, tls).",
		}, []string{"component"}),
		ReloadErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kevgate_admit_reload_errors_total",
			Help: "Failed hot reloads by component; the previous version stays active.",
		}, []string{"component"}),
		Exceptions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kevgate_admit_exceptions_total",
			Help: "Policy exceptions that matched, by result (applied or expired).",
		}, []string{"result"}),
		KEVEntries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "kevgate_admit_kev_entries",
			Help: "Number of CVEs in the loaded KEV catalog.",
		}),
	}
	m.Registry.MustRegister(m.Decisions, m.Requests, m.Duration, m.Lookup, m.Reloads, m.ReloadErrors, m.Exceptions, m.KEVEntries,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	// Make zero series visible so rate() and absent() behave from the start.
	for _, c := range []string{"policy", "kev", "epss", "tls"} {
		m.Reloads.WithLabelValues(c)
		m.ReloadErrors.WithLabelValues(c)
	}
	return m
}

// Reloaded implements reload.Observer.
func (m *Metrics) Reloaded(component string, err error) {
	if err != nil {
		m.ReloadErrors.WithLabelValues(component).Inc()
		return
	}
	m.Reloads.WithLabelValues(component).Inc()
}

// Handler serves the registry in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
}
