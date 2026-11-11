# Threat model (STRIDE)

Scope: the kevgate-admit webhook, its inputs (policy, KEV catalog, EPSS CSV, evidence reports, TLS material) and its connection to the API server. Out of scope: the scanner that produces reports, the registry, the container runtime, and compromise of the API server or etcd.

Assets: the integrity of allow and deny decisions, availability of workload admission, the policy and evidence data.

Trust boundaries: the API server to the webhook (mutual trust through the CA bundle in the webhook configuration), the webhook to its mounted files, and the optional webhook to kevgate HTTP call.

## Spoofing

| Threat | Mitigation | Residual |
| --- | --- | --- |
| A host other than the API server calls `/validate` | The response is only a decision and has no side effects, so a forged caller gains nothing. The NetworkPolicy limits the port to cluster traffic. | Anyone in the cluster network can ask for decisions and learn which findings an image has. The denial text discloses CVE IDs and package versions, so treat it as internal. |
| An impostor webhook answers the API server | The API server verifies the serving certificate against `caBundle`. | A stolen key allows impersonation, see cert compromise below. |
| A report for another image vouches for this digest | The report must not name a different digest in its metadata, and file names are derived from a strictly validated digest. | A report with no metadata and a correct name is trusted. Control write access to the report store. |

## Tampering

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Policy tampering (an exception added, `maxRisk` raised) | Policy is a ConfigMap, so Kubernetes RBAC governs it. Strict parsing, mandatory justification and expiry on exceptions, expired exceptions logged and counted, a failed reload keeps the last good policy. | A user with write access to the ConfigMap in the webhook namespace controls enforcement. Restrict that RBAC and manage the policy through review. There are no signatures. |
| Tampered reports (findings removed) | The report store is read-only to the webhook. | Anyone who can write the store can make an image look clean. Treat the store as a trusted input and restrict writers to the scan pipeline. |
| Poisoned KEV or EPSS download | `kev-refresh` uses HTTPS only, refuses redirects to HTTP, enforces a timeout and size cap, validates schema and CVE format, refuses a catalog less than half the size of the existing one, and writes atomically. | The feed's TLS chain is trusted as the system store sees it. |
| Malformed or hostile AdmissionReview | Strict envelope decoding, request size limit, content type check, header and read timeouts, image count limit, fuzzed decoder. | |
| Hostile report content (huge file, control characters, absurd scores) | Size cap, strict range checks that reject the whole report, control characters stripped from text that reaches messages and logs, fuzzed parser. | |

## Repudiation

Each decision logs one structured line with the request UID, operation, kind, workload name, namespace, scope, outcome and rule. Exception use and expired exception matches are logged and counted. Object bodies, environment variables and user identities are not logged. The API server audit log remains the authority for who submitted what.

## Information disclosure

The denial message goes back to the requester, so it names CVEs, packages and versions of the image they submitted. That is the point of the message, but it also means a user who can submit requests can probe the report store by digest. Logs and metrics carry no secrets. The optional kevgate token is read from a mounted file and sent only as an Authorization header to the configured URL. It is never logged. Metrics use the policy scope as label, not raw namespace names.

## Denial of service

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Slow or hung evidence provider | Per-lookup timeout enforced in the caller even if the provider ignores its context, an overall evaluation timeout below the webhook `timeoutSeconds`, a global bound on in-flight lookups, and a timeout result that follows `--fail-mode`. | With `closed`, a slow provider turns into denied deployments, which is the intended failure direction. |
| Flood of requests or very large requests | Body size limit, header limits, server timeouts, replicas and PDB in the chart. The webhook only receives requests for the listed resources. | No rate limiting. API server priority and fairness applies upstream. |
| Webhook outage blocks the cluster (`failurePolicy: Fail`) | Two replicas by default, rolling update with zero unavailable, PodDisruptionBudget, the webhook namespace and system namespaces excluded so recovery is always possible. | A cluster-wide misconfiguration of the namespace selector could still deadlock. The recovery step is deleting the ValidatingWebhookConfiguration. |
| A Pod with thousands of containers | At most 128 distinct images per request. | |

## Elevation of privilege and bypass of the webhook

| Threat | Mitigation | Residual |
| --- | --- | --- |
| Deploy into an excluded namespace | `kube-system`, `kube-public`, `kube-node-lease` and the webhook namespace are excluded. This is necessary and is also a gap. | Anyone allowed to create workloads there bypasses it. Restrict RBAC in those namespaces. The selector uses only the immutable `kubernetes.io/metadata.name` label, so relabelling a namespace does not move it out of scope. |
| Use a resource the webhook does not list | Pods and `pods/ephemeralcontainers` are covered, so workloads created by any controller or CRD still get judged when their Pods are created. `matchPolicy: Equivalent` covers other API versions of the same resources. | Static pods created by the kubelet do not pass through admission. ReplicaSet and ReplicationController are not listed but their Pods are. |
| Image tag swap after admission | Tags are not trusted: with `requireDigest` the kubelet pulls the exact content that was judged. | Without `requireDigest`, tag-only images fall to `requireEvidence`. |
| Wrong registry | `allowedRegistries` with path-boundary matching. | The registry name is matched textually, and a pull-through mirror is not considered. |
| Compromised webhook pod | Non-root, read-only root filesystem, all capabilities dropped, no service account token, no egress by default, distroless image. | The pod can still return arbitrary decisions to the API server. |

## Specific scenarios

Stale evidence. A report can be days old while the base image is patched or a new CVE enters KEV. KEV membership is checked at admission against the current catalog, so a known CVE that becomes KEV is caught once the catalog file is refreshed. New CVEs absent from the report are not. `maxEvidenceAge` forces re-scanning, and the `kevgate_admit_kev_catalog_mtime_seconds` gauge supports an alert when the catalog stops being refreshed.

Certificate compromise. The serving key is a mounted Secret. Anyone who reads it can impersonate the webhook to the API server only if they can also intercept that traffic, but the consequence is forged allow decisions. Use cert-manager with short lifetimes (the chart sets 90 days with renewal 15 days ahead and key rotation on renewal). The server reloads the certificate when the files change, no restart needed. After a suspected leak, rotate the key and, if the CA was affected, the `caBundle`. The `helm` TLS mode generates a long-lived CA and is for demos only.

Fail-open risk. `failurePolicy: Ignore` or `--fail-mode open` converts any outage or error into admission. If the evidence store is wiped, every image looks unscanned, and with `requireEvidence: allow` or open failure everything passes. The defaults are closed, and the audit mode lets a rollout begin with warnings before enforcing. Alert on `kevgate_admit_decisions_total{outcome="error"}`, on lookup `timeout` and `error` results, and on reload errors.
