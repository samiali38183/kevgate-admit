# kevgate-admit

[![ci](https://github.com/samiali38183/kevgate-admit/actions/workflows/ci.yml/badge.svg)](https://github.com/samiali38183/kevgate-admit/actions/workflows/ci.yml)
[![e2e-kind](https://github.com/samiali38183/kevgate-admit/actions/workflows/e2e-kind.yml/badge.svg)](https://github.com/samiali38183/kevgate-admit/actions/workflows/e2e-kind.yml)
[![security](https://github.com/samiali38183/kevgate-admit/actions/workflows/security.yml/badge.svg)](https://github.com/samiali38183/kevgate-admit/actions/workflows/security.yml)

A Kubernetes validating admission webhook, written in Go, that decides whether a workload may be created based on vulnerability evidence for the exact image digests it runs. Findings are scored with the same risk model as the sibling project [kevgate](https://github.com/samiali38183/kevgate): exploitation in the wild (CISA KEV) carries the largest weight, followed by asset criticality, EPSS and CVSS.

The webhook does not scan images. It consumes reports that a scan pipeline already produced (Trivy JSON, one file per digest) and enforces a policy over them at admission time.

## What it does

For CREATE and UPDATE of Pod, Deployment, StatefulSet, DaemonSet, Job and CronJob:

1. Extract every container, init container and ephemeral container image.
2. Parse each reference without ever resolving a tag. Only a digest identifies an image.
3. Look up the report for each digest (a directory or ConfigMap of `sha256-<hex>.json` files, optionally a kevgate HTTP API as a fallback).
4. Score each finding: `risk = 100 * (0.40*kev + 0.25*acr/8 + 0.20*epss + 0.20*cvss/10) / 1.05`, rounded to one decimal.
5. Apply the namespace rule: `denyKev`, `maxRisk`, `requireDigest`, `requireEvidence`, `allowedRegistries`, exceptions with expiry, audit mode.
6. Answer with an AdmissionReview v1 response: allow, allow with warnings, or deny with a message listing the top findings and the rule that fired.

```mermaid
flowchart LR
    API[kube-apiserver] -->|AdmissionReview v1, TLS| H[POST /validate]
    subgraph webhook [kevgate-admit pod]
        H --> D[strict decode and image extraction]
        D --> R[image reference parser]
        R --> L[evidence lookup, bounded and timed]
        L --> E[policy evaluation and risk scoring]
        E --> O[response: allow, warn or deny]
        P[(policy.yaml)] -. hot reload .-> E
        K[(KEV catalog JSON)] -. hot reload .-> E
        S[(EPSS CSV, optional)] -. hot reload .-> E
        C[(tls.crt and tls.key)] -. hot reload .-> H
    end
    L --> T[(Trivy reports: ConfigMap or volume)]
    L -.-> Q[kevgate GET /queue, optional]
    SCAN[scan pipeline] -->|writes sha256-hex.json| T
    OPS[kevgate-admit kev-refresh] -->|HTTPS, size cap, schema check| K
    M[:8080 /metrics /healthz /readyz] --- webhook
```

## Quick start

```sh
go build -o bin/kevgate-admit ./cmd/kevgate-admit

# run locally with a throw-away certificate and the synthetic demo data
bin/kevgate-admit serve --self-signed --self-signed-ca-out /tmp/ca.pem \
  --policy-file deploy/demo/policy.yaml \
  --kev-file deploy/demo/kev-demo.json \
  --evidence-dir deploy/demo/reports

bin/kevgate-admit check-policy --policy-file deploy/demo/policy.yaml
bin/kevgate-admit kev-refresh --out kev.json        # downloads the real catalog over HTTPS
```

Install into a cluster with the chart (see `deploy/helm/kevgate-admit/values.yaml`). `tls.mode=helm` generates a CA and certificate for kind and demos, `tls.mode=certManager` creates a cert-manager Certificate, `tls.mode=existingSecret` uses a secret you provide.

## Examples from the test suite

These come from `internal/app/app_test.go` (`TestDemoScenarios`), which starts the real TLS server and posts AdmissionReviews built from the synthetic fixtures in `deploy/demo`. They are test output, not a cluster run.

A Deployment whose image carries a KEV finding, in a namespace with `denyKev: true` and `maxRisk: 40`:

```
kevgate-admit: request denied by policy (namespace "demo-enforce", scope "demo-enforce")
- [denyKev] registry.example.com/demo/kev-vulnerable@sha256:222222222222: 1 finding(s) in the CISA KEV catalog
    CVE-2021-44228   KEV  risk  87.5  log4j-core 2.14.1 (fixed 2.17.1)
- [maxRisk] registry.example.com/demo/kev-vulnerable@sha256:222222222222: 1 finding(s) above max risk 40.0 (highest 87.5)
    CVE-2021-44228   KEV  risk  87.5  log4j-core 2.14.1 (fixed 2.17.1)
```

An image without a KEV finding but over the risk threshold (asset criticality 4, CVSS 9.8, EPSS 0.9):

```
kevgate-admit: request denied by policy (namespace "demo-enforce", scope "demo-enforce")
- [maxRisk] registry.example.com/demo/over-threshold@sha256:333333333333: 1 finding(s) above max risk 40.0 (highest 47.7)
    CVE-2099-10004        risk  47.7  libwidget 3.2 (fixed 3.3)
```

The same image in a namespace with `mode: audit` is admitted and returns this warning, which `kubectl` prints:

```
kevgate-admit audit: would deny [maxRisk] registry.example.com/demo/over-threshold@sha256:333333333333: 1 finding(s) above max risk 40.0 (highest 47.7)
```

## Verification status

Measured on a Windows workstation with Go 1.27.4:

- 72 top-level tests (308 including subtests and fuzz seed runs), total statement coverage 95.0 percent across all packages.
- The scoring function matches the Python kevgate implementation on 1000 vectors generated by `scripts/gen_parity.py` (a grid plus a seeded random sample), alongside 12 hand-computed vectors.
- Two fuzz targets (`FuzzParse` for the Trivy parser, `FuzzDecodeAndExtract` for the AdmissionReview decoder), each run for 25 seconds locally without findings. Seed corpora are in `testdata/fuzz`.
- `go vet`, `golangci-lint` 2.15.0 (with gosec, errorlint, bodyclose and others), `govulncheck` and `trivy fs` report nothing.
- `helm lint --strict` and `helm template | kubeconform -strict` are clean for the default values and for a values file that enables every optional template (cert-manager Certificate and ServiceMonitor schemas from the datree CRDs catalog).
- `actionlint` and `shellcheck` are clean.
- The race detector needs cgo and a C compiler, which this workstation does not have, so `go test -race` has not been run locally. CI runs it.

Verified by CI on GitHub Actions (see the badges above): the Docker build, the kind end to end run, hadolint, gosec, govulncheck, the Trivy filesystem and image scans, gitleaks, and `go test -race`. The release workflow is a skeleton and has never run.

## End to end transcript

`deploy/demo/demo.sh` runs in the `e2e-kind` workflow on a hosted runner: it builds the image, creates a kind cluster, loads the image, installs the chart with `tls.mode=helm` (a CA and serving certificate generated at install time) and the synthetic evidence from `deploy/demo/reports`, then applies the demo workloads and fails the job unless every outcome and denial text matches. The webhook log, pod descriptions, resource listing, metrics and this transcript are uploaded as the `e2e-demo-output` artifact. The cert-manager path is not exercised in CI; it is only covered by `helm template | kubeconform`.

Below is the unedited output of that step from a passing run (timestamps trimmed). The "waiting" step sends one or more extra requests for the always-denied `tag-only` workload until the webhook answers, so they are also counted in the decision counters. The counters also include the Pods that the Deployments in `clean` and `over-threshold-audit` create.

```text
== namespaces and evidence
namespace/kevgate-system created
namespace/demo-enforce created
namespace/demo-audit created
configmap/demo-kev created
configmap/demo-evidence created

== installing the chart
Release "kevgate-admit" does not exist. Installing it now.
NAME: kevgate-admit
LAST DEPLOYED: Wed Nov 11 04:17:00 2026
NAMESPACE: kevgate-system
STATUS: deployed
REVISION: 1
DESCRIPTION: Install complete
TEST SUITE: None

== waiting for the webhook endpoint to accept connections

== clean in demo-enforce (expect: allowed)
deployment.apps/clean created
RESULT clean: PASS

== kev-vulnerable in demo-enforce (expect: denied)
Error from server (Forbidden): error when creating "/home/runner/work/kevgate-admit/kevgate-admit/deploy/demo/workloads/kev-vulnerable.yaml": admission webhook "validate.kevgate-admit.samiali38183.github.io" denied the request: kevgate-admit: request denied by policy (namespace "demo-enforce", scope "demo-enforce")
- [denyKev] registry.example.com/demo/kev-vulnerable@sha256:222222222222: 1 finding(s) in the CISA KEV catalog
    CVE-2021-44228   KEV  risk  87.5  log4j-core 2.14.1 (fixed 2.17.1)
- [maxRisk] registry.example.com/demo/kev-vulnerable@sha256:222222222222: 1 finding(s) above max risk 40.0 (highest 87.5)
    CVE-2021-44228   KEV  risk  87.5  log4j-core 2.14.1 (fixed 2.17.1)
RESULT kev-vulnerable: PASS

== over-threshold-enforce in demo-enforce (expect: denied)
Error from server (Forbidden): error when creating "/home/runner/work/kevgate-admit/kevgate-admit/deploy/demo/workloads/over-threshold.yaml": admission webhook "validate.kevgate-admit.samiali38183.github.io" denied the request: kevgate-admit: request denied by policy (namespace "demo-enforce", scope "demo-enforce")
- [maxRisk] registry.example.com/demo/over-threshold@sha256:333333333333: 1 finding(s) above max risk 40.0 (highest 47.7)
    CVE-2099-10004        risk  47.7  libwidget 3.2 (fixed 3.3)
RESULT over-threshold-enforce: PASS

== over-threshold-audit in demo-audit (expect: warned)
Warning: kevgate-admit audit: would deny [maxRisk] registry.example.com/demo/over-threshold@sha256:333333333333: 1 finding(s) above max risk 40.0 (highest 47.7)
deployment.apps/over-threshold created
RESULT over-threshold-audit: PASS

== tag-only in demo-enforce (expect: denied)
Error from server (Forbidden): error when creating "/home/runner/work/kevgate-admit/kevgate-admit/deploy/demo/workloads/tag-only.yaml": admission webhook "validate.kevgate-admit.samiali38183.github.io" denied the request: kevgate-admit: request denied by policy (namespace "demo-enforce", scope "demo-enforce")
- [requireDigest] registry.example.com/demo/clean:latest: image is not pinned by digest; tags are mutable
RESULT tag-only: PASS

== collecting webhook logs and metrics
kevgate_admit_decisions_total{namespace="demo-audit",outcome="audit_deny",rule="maxRisk"} 2
kevgate_admit_decisions_total{namespace="demo-enforce",outcome="allow",rule="none"} 2
kevgate_admit_decisions_total{namespace="demo-enforce",outcome="deny",rule="denyKev"} 1
kevgate_admit_decisions_total{namespace="demo-enforce",outcome="deny",rule="maxRisk"} 1
kevgate_admit_decisions_total{namespace="demo-enforce",outcome="deny",rule="requireDigest"} 2

demo finished: all checks passed
```

## Configuration

`kevgate-admit serve` flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--listen` | `:8443` | TLS admission listener |
| `--metrics-listen` | `:8080` | plain HTTP for `/metrics`, `/healthz`, `/readyz` |
| `--tls-cert-file`, `--tls-key-file` | | serving pair, reloaded when the files change |
| `--self-signed`, `--self-signed-hosts`, `--self-signed-ca-out` | off | in-memory throw-away certificate for CI and development |
| `--policy-file` | | policy YAML, hot reloaded |
| `--kev-file` | | CISA KEV JSON, hot reloaded |
| `--epss-file` | | optional EPSS CSV, hot reloaded |
| `--evidence-dir` | | directory of `sha256-<hex>.json` Trivy reports |
| `--evidence-url`, `--evidence-token-file` | | optional kevgate API used when no report exists |
| `--fail-mode` | `closed` | `closed` denies when the evidence source fails, `open` allows with a warning |
| `--eval-timeout` | `8s` | budget per request; keep it below the webhook `timeoutSeconds` |
| `--lookup-timeout` | `3s` | budget per evidence lookup |
| `--max-request-bytes` | 4 MiB | request body limit |
| `--reload-interval` | `15s` | how often files are checked |

Documentation: [policy reference](docs/POLICY.md), [design notes](docs/DESIGN.md), [threat model](docs/THREAT_MODEL.md), [changelog](CHANGELOG.md).

## Limitations

- It does not scan images. A digest with no report is "no evidence", handled by `requireEvidence`.
- Reports go stale. `maxEvidenceAge` bounds it when the report carries a timestamp.
- Exceptions are policy entries with an expiry date, not signed attestations. Whoever can edit the policy can add one.
- ConfigMaps are limited to 1 MiB in total, which is a few hundred typical reports. Use a volume for more.

## Development

```sh
make test cover lint vet vuln helm
make fuzz            # 30 seconds per target
make race            # needs cgo
```

## License

MIT, see [LICENSE](LICENSE).
