# Changelog

## 0.1.0

First release.

### Webhook

- Validating admission webhook (AdmissionReview v1) for Pod, Deployment, StatefulSet, DaemonSet, Job and CronJob, including ephemeral containers.
- Risk scoring identical to the kevgate service, checked against 1000 vectors from the Python implementation.
- Evidence providers: directory of Trivy JSON reports named by digest, optional kevgate HTTP API, chained. Parses a real Trivy 0.76.2 report (trimmed) as a compatibility test.
- CISA KEV catalog from a local file, `kev-refresh` command (HTTPS only, timeout, size cap, schema validation, shrink guard).
- Optional EPSS CSV.
- YAML policy with hot reload: per-namespace `maxRisk`, `denyKev`, `requireDigest`, `requireEvidence`, `requireSignedEvidence`, `allowedRegistries`, `assetCriticality`, `maxEvidenceAge`, `ignoreUnfixed`, exceptions with required expiry and justification, audit mode.
- TLS serving with certificate reload and a self-signed development mode, graceful shutdown, timeouts and request size limit.
- Fail-closed or fail-open handling of evidence source errors.
- Structured JSON logs, Prometheus metrics, `/healthz` and `/readyz`.

### Hardening since the first review

- Image references are parsed with the OCI distribution grammar. Rejected now: dot and empty path components (`ghcr.io/org/../evil`), upper-case repositories, invalid UTF-8 and non-ASCII bytes, malformed hosts and IPv6 literals (`::0`), ports outside 1 to 65535, bad tags and digests, names over the length limits. `allowedRegistries` entries are validated with the same rules and match on whole path components.
- `ignoreUnfixed` never drops a finding that is in the CISA KEV catalog or marked KEV by the evidence source; it was possible before for an exploited CVE with no fix to pass `denyKev`.
- Optional signed evidence: `requireSignedEvidence`, `--evidence-public-key-file`, detached `<digest>.json.sig` (Ed25519 or ECDSA P-256, standard library only) over the report and its digest, plus the `keygen`, `sign-report` and `verify-report` subcommands and a chart value for the public key. An unauthenticated report is never scored.
- The end to end run now also covers the outage behaviour: `failurePolicy: Fail` rejects with "failed calling webhook", `Ignore` admits, `kube-system` and the webhook namespace are not gated, and decisions resume after recovery.
- The reference parser has a property fuzz target with a seed corpus, run in CI.

### Packaging

- Helm chart (cert-manager optional, NetworkPolicy, PodDisruptionBudget, ServiceMonitor optional), Dockerfile on distroless static, kind demo with synthetic fixtures.
- GitHub Actions: CI, kind end to end, security scans, release workflow (build, Trivy scan, push to GHCR, cosign keyless signature and SBOM attestation, verification step).

### Not in this release

- Image signature or attestation verification (cosign, Notary) at admission time.
- A cluster run of the cert-manager TLS mode, of `helm upgrade` in `tls.mode=helm`, or of node drains with the PodDisruptionBudget.
