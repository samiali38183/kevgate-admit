# kevgate-admit

[![ci](https://github.com/samiali38183/kevgate-admit/actions/workflows/ci.yml/badge.svg)](https://github.com/samiali38183/kevgate-admit/actions/workflows/ci.yml)
[![e2e-kind](https://github.com/samiali38183/kevgate-admit/actions/workflows/e2e-kind.yml/badge.svg)](https://github.com/samiali38183/kevgate-admit/actions/workflows/e2e-kind.yml)
[![security](https://github.com/samiali38183/kevgate-admit/actions/workflows/security.yml/badge.svg)](https://github.com/samiali38183/kevgate-admit/actions/workflows/security.yml)

kevgate-admit is a Kubernetes validating admission webhook written in Go. Before a Pod, Deployment, StatefulSet, DaemonSet, Job or CronJob is created, it checks each container image and refuses the workload if the image has a vulnerability on CISA's Known Exploited Vulnerabilities (KEV) list, or a risk score above a limit set per namespace. It does not scan anything. It reads scan reports that something else produced and looks them up by image digest, never by tag.

I built it to answer a practical question about admission control: what does the webhook trust, and what happens when it fails? So the work went into the parts around the decision. Reports can be required to carry an Ed25519 or ECDSA signature, and the policy file can be signed the same way, so a failed check never replaces the policy in force. Image references are parsed with the OCI grammar before any comparison. The kind cluster test also takes the webhook down and records what `failurePolicy: Fail` and `Ignore` each do. The risk score is the one used in [kevgate](https://github.com/samiali38183/kevgate), checked against the Python implementation on 1,000 generated vectors.

![Result of the kind cluster test: five demo workloads applied, three denied, one allowed and one admitted with a warning in audit mode, then the outage test showing that failurePolicy Fail rejects new Pods while the webhook is down and Ignore lets a Pod through that the policy would deny.](docs/img/hero-e2e.png)

*From the `e2e-kind` CI transcript in [docs/E2E.md](docs/E2E.md). The scan data is synthetic; the repository has no real scan data. `scripts/make_hero.py` redraws the image from the transcript.*

## Try it

```sh
go build -o bin/kevgate-admit ./cmd/kevgate-admit
bin/kevgate-admit serve --self-signed --self-signed-ca-out /tmp/ca.pem \
  --policy-file deploy/demo/policy.yaml \
  --kev-file deploy/demo/kev-demo.json \
  --evidence-dir deploy/demo/reports
```

`go test ./internal/app` runs the same server over real TLS against the demo fixtures. This is a deny it produces for a Deployment in a namespace with `denyKev: true` and `maxRisk: 40`:

```
kevgate-admit: request denied by policy (namespace "demo-enforce", scope "demo-enforce")
- [denyKev] registry.example.com/demo/kev-vulnerable@sha256:222222222222: 1 finding(s) in the CISA KEV catalog
    CVE-2021-44228   KEV  risk  87.5  log4j-core 2.14.1 (fixed 2.17.1)
- [maxRisk] registry.example.com/demo/kev-vulnerable@sha256:222222222222: 1 finding(s) above max risk 40.0 (highest 87.5)
    CVE-2021-44228   KEV  risk  87.5  log4j-core 2.14.1 (fixed 2.17.1)
```

## What was tested

- `go test -race` in CI with an 85% coverage floor, three fuzz targets (image references, Trivy reports, AdmissionReview decoding) at 30 s each, gosec, govulncheck, Trivy and gitleaks.
- The `e2e-kind` workflow installs the Helm chart on a kind cluster and asserts allow, deny and audit-warn outcomes, a `helm upgrade` that keeps the TLS Secret, and the outage behaviour above. `failurePolicy: Ignore` admits a Pod the policy would deny, so it is a bypass window and not a safe default.
- The `v0.1.0` image is on GHCR, signed with cosign (keyless) and attested with a CycloneDX SBOM; the verify command is in [docs/USAGE.md](docs/USAGE.md#published-image). The signature shows what built the image. The webhook does not check image signatures at admission.

## Limits

It does not scan images, does not verify image signatures (Kyverno `verifyImages` and the Sigstore policy-controller do that), and has no multi-replica or production design. The KEV catalog file is unsigned. The cert-manager TLS mode and the signed-policy path are not covered by the kind run. Everything runs in kind and Go tests; nothing here has been deployed to a production cluster. The full list is in [docs/USAGE.md](docs/USAGE.md#limitations).

## Docs

[Usage and flags](docs/USAGE.md), [policy reference](docs/POLICY.md), [design notes](docs/DESIGN.md), [threat model](docs/THREAT_MODEL.md), [kind transcripts](docs/E2E.md), [changelog](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
