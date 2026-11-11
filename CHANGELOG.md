# Changelog

## 0.1.0

Initial version.

- Validating admission webhook (AdmissionReview v1) for Pod, Deployment, StatefulSet, DaemonSet, Job and CronJob, including ephemeral containers.
- Risk scoring identical to the kevgate service, checked against 1000 vectors from the Python implementation.
- Evidence providers: directory of Trivy JSON reports named by digest, optional kevgate HTTP API, chained.
- CISA KEV catalog from a local file, `kev-refresh` command (HTTPS only, timeout, size cap, schema validation, shrink guard).
- Optional EPSS CSV.
- YAML policy with hot reload: per-namespace `maxRisk`, `denyKev`, `requireDigest`, `requireEvidence`, `allowedRegistries`, `assetCriticality`, `maxEvidenceAge`, `ignoreUnfixed`, exceptions with required expiry and justification, audit mode.
- TLS serving with certificate reload and a self-signed development mode, graceful shutdown, timeouts and request size limit.
- Fail-closed or fail-open handling of evidence source errors.
- Structured JSON logs, Prometheus metrics, `/healthz` and `/readyz`.
- Helm chart (cert-manager optional, NetworkPolicy, PodDisruptionBudget, ServiceMonitor optional), Dockerfile on distroless static, kind demo with synthetic fixtures.
- GitHub Actions: CI, kind end to end, security scans, release skeleton.
