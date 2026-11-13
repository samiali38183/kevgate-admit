# Design notes

## Why digests

A tag is a pointer that the registry owner can move. A report that says "nginx:1.25 has no KEV findings" says nothing about the bytes a node will pull tomorrow. A digest names content, so evidence keyed by digest stays true for as long as it is fresh. For that reason the webhook never resolves tags: a tag-only image has no evidence and is handled by `requireDigest` and `requireEvidence`. When a reference has both a tag and a digest the digest wins, as it does in the kubelet.

Pinning also closes a time-of-check gap. If the webhook resolved a tag at admission time, the kubelet could pull a different image later.

## Why a report store

The alternatives were to scan inside the webhook, or to call a scanner service at admission time. Both put slow, failure-prone work on the critical path of every deploy. The webhook has a ten second budget set by the API server, and a scan takes longer than that.

A report store moves scanning to a pipeline that runs when an image is built or on a schedule. The webhook does a file read, which is fast and has simple failure modes (missing, malformed, stale). Reports are plain Trivy JSON, so any pipeline that can run `trivy image --format json` can feed it. The optional kevgate HTTP provider exists for setups that already track findings per asset there.

A report is only accepted for a digest when its metadata does not name a different one. A file renamed to another image's digest is rejected as an evidence error rather than vouching for the wrong image.

## Image references

The image reference is the key for everything else (the allow-list, the digest used to find a report, exception scopes), so it is parsed strictly before any of that happens. An earlier version only split on `/`, `:` and `@`, and fuzzing showed that it accepted `::0`, invalid UTF-8 hosts, and `ghcr.io/org/../evil`, which then matched the allowed prefix `ghcr.io/org` textually. The runtime would probably have refused such an image, but an allow-list should not depend on that. `internal/imageref` now implements the OCI distribution name grammar and a validated registry host syntax, rejects anything else as `imageRef`, and validates `allowedRegistries` entries with the same rules when the policy loads. The grammar and the deliberate differences from `distribution/reference` are listed in the policy reference.

## Evidence authenticity

Digest keys say which bytes a report is about, not who wrote the report. The store is a directory or ConfigMap, so write access is the trust boundary. Signing is an opt-in layer: `requireSignedEvidence` plus `--evidence-public-key-file` makes the directory provider verify a detached `<digest>.json.sig` over the report bytes and the digest, and the policy treats an unverified report as missing evidence. Only the standard library is used (Ed25519 and ECDSA P-256), which keeps the dependency set unchanged. Cosign-style keyless signing, transparency logs and attestations were left out on purpose: they need network access or a bundle verifier at admission time, and the webhook's design rule is a fast local read. The cost of that choice is that trust is a long-lived key that the operator must protect and rotate.

## Scoring

The model is the one in the kevgate service: weights 0.40 KEV, 0.25 asset criticality (acr/8), 0.20 EPSS, 0.20 CVSS (/10), divided by their sum 1.05, times 100, rounded to one decimal. The Go implementation reproduces the Python arithmetic order and the rounding rule. The test suite compares 1000 vectors produced by the Python function.

Inputs come from different places:

- KEV membership: the local catalog file, or a hint from the HTTP provider.
- CVSS: the highest v3 score across the sources in the report, else the highest v2 score, else a value implied by the severity label (critical 9.0, high 7.5, medium 5.0, low 2.0).
- EPSS: the report if it carries an `EPSS` field, else the local CSV, else 0. A missing EPSS therefore lowers the score, which is the less safe direction. Keep the CSV loaded if `maxRisk` matters.
- Unfixed findings: scored like any other unless `ignoreUnfixed` is set, which drops them except KEV findings (never dropped). `maxRisk` is per finding, not an aggregate.
- Asset criticality: per namespace in the policy. The webhook does not know how important a workload is, only where it runs.

## Failure behaviour

There are two layers and they are configured separately.

`failurePolicy` on the ValidatingWebhookConfiguration is the API server's decision when it cannot get an answer at all (webhook down, TLS failure, timeout). `Fail` rejects requests, which is the only setting that cannot be bypassed by taking the webhook down, but it makes the webhook a cluster dependency. It is the chart default. `Ignore` keeps the cluster available and turns an outage into a bypass window. Choose `Fail` with at least two replicas and a PodDisruptionBudget, or `Ignore` with alerting on webhook availability and an audit trail elsewhere. The webhook's own namespace and the system namespaces are excluded by `namespaceSelector` so that it can always start.

`--fail-mode` is the webhook's own decision when it answered but could not do its job (evidence source error, unreadable object, panic). `closed` denies, `open` allows with a warning. A missing report is not a failure and is governed by `requireEvidence`.

The e2e workflow tests the first layer: it scales the webhook to zero and checks that `Fail` rejects with "failed calling webhook", that `Ignore` admits, that `kube-system` and the webhook namespace are not gated, and that normal decisions resume after recovery. `--fail-mode` is covered by unit and server tests, not by the cluster run.

## Tradeoffs

- Hot reload by polling. Files are checked on an interval and re-read when size or modification time changed, with a content hash to skip no-op rewrites. This works with ConfigMap volume updates (symlink swaps) without a file watcher dependency. The cost is a delay of up to one interval.
- Last good wins. A bad policy, KEV file or certificate never replaces a working one, so a broken edit cannot disable enforcement. The failure is visible in metrics and logs.
- The `namespace` metric label is the policy scope, not the raw namespace, to bound cardinality.
- Envelope decoding is strict (unknown fields rejected), the embedded object is decoded leniently. The API server already validated the object against its schema, and rejecting unknown object fields would make the webhook fail on every API upgrade.
- Pod evaluation is on top of workload evaluation. A Deployment is judged when it is created and again when its ReplicaSet creates Pods. This catches workloads created by controllers and custom resources the webhook does not list, at the price of duplicate work.
- Lookups run in their own goroutine with a deadline, so a provider that ignores its context cannot hold a request past the timeout. A semaphore bounds in-flight lookups across requests. An abandoned lookup finishes in the background.

## Limitations

- It does not scan images. Without a pipeline producing reports, `requireEvidence: deny` rejects everything.
- Evidence freshness depends on the pipeline. Reports describe what was known when they were written. A CVE published after the scan is invisible until the next scan, although KEV membership is evaluated at admission time against the current catalog file, so a report with a CVE that later enters KEV is caught as soon as the catalog is refreshed.
- Running workloads are not re-evaluated. A new KEV entry blocks new and changed images, not existing pods. Pair it with a periodic report or runtime control for that.
- Exceptions are policy entries, not signed statements. Anyone who can change the policy ConfigMap can add one. Review the policy through the same process as code, and watch the `exceptions_total` metric and the logs.
- The kevgate HTTP provider cannot tell an unknown asset from a clean one (an empty list means "no evidence"), and has no scan timestamp.
- No support for ReplicaSet or ReplicationController objects, or other CRDs that embed pod templates.
- No image signature verification. Report signatures authenticate the report store only; checking cosign or Notary signatures on the image, with an identity policy, is future work (see Kyverno `verifyImages` and the Sigstore policy-controller for the shape of it).
- The cert-manager TLS mode is covered by `helm template` and kubeconform only, never by a cluster run.
- The chart in `tls.mode=helm` reads the existing Secret with `lookup` and renders it again unchanged on later revisions (omitting it would make Helm delete it on upgrade); `deploy/demo/upgrade.sh` checks this in CI. The certificate is not rotated. Use cert-manager or an existing Secret for anything but demos.
- ConfigMap-based report storage tops out at 1 MiB in total.
