# End to end runs on kind

These transcripts come from the `e2e-kind` workflow ([`.github/workflows/e2e-kind.yml`](../.github/workflows/e2e-kind.yml)) on a GitHub-hosted runner. They are unedited apart from trimmed timestamps.

## Install, allow, deny, warn

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


## Failure modes: webhook down, then recovery

The same workflow then runs `deploy/demo/outage.sh` against the same cluster. It checks that `kube-system` and the webhook namespace are not gated, scales the webhook to zero replicas, shows what the API server does under `failurePolicy: Fail` and under `Ignore`, restores the webhook and checks that allow and deny decisions resume. The script fails the job unless every assertion holds. With zero endpoints the API server's error text says "failed calling webhook", which the script asserts; the exact reason after it (here `connection refused`) depends on the Kubernetes version and kube-proxy.

What this shows, and what it does not:

- Under `Fail` a Pod create is rejected while the webhook is down, and nothing is created. The excluded namespaces (`kube-system`, the webhook's namespace) keep admitting, which is what lets the webhook come back.
- Under `Ignore` the same outage admits a Pod that the policy denies (a tag-only image in an enforcing namespace). That is the bypass window of that setting.
- It does not test `--fail-mode` (the webhook answering but unable to judge), slow responses or timeouts at the API server, or node drains with the PodDisruptionBudget. The demo runs one replica. `helm upgrade` is checked in a separate step, `deploy/demo/upgrade.sh`.

Unedited output of that step from a passing run (timestamps trimmed; run <https://github.com/samiali38183/kevgate-admit/actions/runs/43042286763>):

```text
== webhook configuration under test
failurePolicy: Fail, replicas: 1
namespaceSelector: kubernetes.io/metadata.name NotIn ["kube-system","kube-public","kube-node-lease","kevgate-system"]

== baseline: a tag-only Pod is denied in a gated namespace
Error from server (Forbidden): error when creating "STDIN": admission webhook "validate.kevgate-admit.samiali38183.github.io" denied the request: kevgate-admit: request denied by policy (namespace "demo-enforce", scope "demo-enforce")
- [requireDigest] registry.example.com/demo/clean:latest: image is not pinned by digest; tags are mutable
RESULT baseline-denied: PASS

== self-exclusion: the same Pod is not judged in kube-system or in the webhook namespace
pod/excluded-kube-system created (server dry run)
RESULT excluded-kube-system: PASS
pod/excluded-kevgate-system created (server dry run)
RESULT excluded-kevgate-system: PASS

== outage: scale the webhook to zero replicas
deployment.apps/kevgate-admit scaled
pod/kevgate-admit-76778bfc5-6p2cr condition met
Warning: v1 Endpoints is deprecated in v1.33+; use discovery.k8s.io/v1 EndpointSlice
NAME                      ENDPOINTS   AGE
endpoints/kevgate-admit   <none>      5s

== failurePolicy Fail: a Pod create is rejected by the API server
Error from server (InternalError): error when creating "STDIN": Internal error occurred: failed calling webhook "validate.kevgate-admit.samiali38183.github.io": failed to call webhook: Post "https://kevgate-admit.kevgate-system.svc:443/validate?timeout=10s": dial tcp 10.96.183.14:443: connect: connection refused
RESULT fail-policy-rejects: PASS
RESULT fail-policy-no-pod: PASS

== failurePolicy Fail: excluded namespaces still admit during the outage
pod/excluded-kube-system created (server dry run)
RESULT outage-excluded-kube-system: PASS
pod/excluded-kevgate-system created (server dry run)
RESULT outage-excluded-kevgate-system: PASS

== failurePolicy Ignore: the same outage admits the Pod, even one the policy would deny
validatingwebhookconfiguration.admissionregistration.k8s.io/kevgate-admit patched
pod/outage-ignore created
RESULT ignore-policy-admits-tag-only-pod: PASS
pod "outage-ignore" deleted from demo-enforce namespace

== restore: failurePolicy back to Fail, webhook back to 1 replicas
validatingwebhookconfiguration.admissionregistration.k8s.io/kevgate-admit patched
deployment.apps/kevgate-admit scaled
Waiting for deployment "kevgate-admit" rollout to finish: 0 of 1 updated replicas are available...
deployment "kevgate-admit" successfully rolled out
RESULT webhook-answers-again: PASS

== normal decisions resume: denied
Error from server (Forbidden): error when creating "STDIN": admission webhook "validate.kevgate-admit.samiali38183.github.io" denied the request: kevgate-admit: request denied by policy (namespace "demo-enforce", scope "demo-enforce")
- [requireDigest] registry.example.com/demo/clean:latest: image is not pinned by digest; tags are mutable
RESULT resumed-deny-tag-only: PASS
Error from server (Forbidden): error when creating "/home/runner/work/kevgate-admit/kevgate-admit/deploy/demo/workloads/kev-vulnerable.yaml": admission webhook "validate.kevgate-admit.samiali38183.github.io" denied the request: kevgate-admit: request denied by policy (namespace "demo-enforce", scope "demo-enforce")
- [denyKev] registry.example.com/demo/kev-vulnerable@sha256:222222222222: 1 finding(s) in the CISA KEV catalog
    CVE-2021-44228   KEV  risk  87.5  log4j-core 2.14.1 (fixed 2.17.1)
- [maxRisk] registry.example.com/demo/kev-vulnerable@sha256:222222222222: 1 finding(s) above max risk 40.0 (highest 87.5)
    CVE-2021-44228   KEV  risk  87.5  log4j-core 2.14.1 (fixed 2.17.1)
RESULT resumed-deny-kev: PASS

== normal decisions resume: allowed
pod/outage-clean created
RESULT resumed-allow-clean: PASS

outage test finished: all checks passed
```
