# Policy reference

The policy is one YAML file, hot reloaded. Unknown fields are rejected, so a misspelled rule name fails the load instead of silently doing nothing. When a reload fails, the previous policy stays active, `kevgate_admit_reload_errors_total{component="policy"}` increases and the error is logged. A policy that fails to load at startup stops the process. Validate a file offline with `kevgate-admit check-policy --policy-file policy.yaml`.

```yaml
version: 1            # required, must be 1
mode: enforce         # enforce (default) or audit
default:              # required, used for namespaces without their own entry
  requireDigest: true
  requireEvidence: deny
  denyKev: true
namespaces:
  prod:
    maxRisk: 40
    denyKev: true
    requireDigest: true
    requireEvidence: deny
    allowedRegistries: [ghcr.io/my-org, registry.example.com]
    assetCriticality: 7
    maxEvidenceAge: 168h
    ignoreUnfixed: false
    exceptions:
      - id: logging-waf-2026-11
        cve: CVE-2021-44228
        image: ghcr.io/my-org/legacy-app
        justification: mitigated by WAF rule 1234, upgrade tracked in TICKET-1
        expires: 2026-12-15
  staging:
    mode: audit
    denyKev: true
```

A namespace entry replaces the default rule completely. It does not inherit from `default`. Fields left out take the values in the table below, so a namespace that only sets `maxRisk` has `requireDigest: false` and `denyKev: false`.

## Rule fields

| Field | Default | Effect |
| --- | --- | --- |
| `mode` | policy `mode` | `audit` always admits, but returns a warning for every violation and counts it with outcome `audit_deny`. |
| `maxRisk` | unset | Deny when any finding scores strictly above the value (0 to 100). |
| `denyKev` | false | Deny when any finding is in the CISA KEV catalog, or the evidence source marks it as KEV. |
| `requireDigest` | false | Deny images without a valid digest. Tags are mutable and are never resolved. |
| `requireEvidence` | `deny` | What to do when there is no usable report: `deny`, `warn` or `allow`. Applies to missing reports, tag-only images when evidence is needed, and stale reports. |
| `allowedRegistries` | empty (any) | Registry host or host plus path prefix. Matching is on path boundaries: `ghcr.io/org` does not match `ghcr.io/org2/app`. `docker.io` covers Docker Hub names. |
| `assetCriticality` | 4 | The `acr` input of the risk formula, 1 to 8, for every workload in the namespace. |
| `maxEvidenceAge` | unset | Reports older than this count as missing. Needs a report timestamp (`CreatedAt`, else the file modification time). The kevgate HTTP provider has no timestamp, so the check is skipped for it. |
| `ignoreUnfixed` | false | Drop findings with no fixed version before scoring. |
| `exceptions` | none | See below. At most 500 per rule. |

Evidence is only looked up when a rule uses it: `maxRisk`, `denyKev`, or `requireEvidence` other than `allow`. A policy made only of `allowedRegistries` and `requireDigest` never touches the evidence source.

## Evidence failures

Two different situations are kept apart:

- No report for the digest, or a stale one: follows `requireEvidence`.
- The source itself fails (timeout, malformed or mismatched report, I/O error, panic): follows the server flag `--fail-mode`. With `closed` the request is denied under the rule name `evidenceError`. With `open` it is admitted with a warning.

## Exceptions

An exception waives one CVE or one rule, never everything.

| Field | Meaning |
| --- | --- |
| `id` | unique within the rule, no spaces, shown in warnings and logs |
| `cve` | waive this CVE (use this or `rule`) |
| `rule` | waive `requireDigest`, `allowedRegistries` or `requireEvidence`; needs `image` |
| `image` | scope: a digest (`sha256:...`) or a repository name without tag (`ghcr.io/org/app`). Optional for `cve` exceptions, in which case it covers every image in the namespace. |
| `justification` | required, at least 10 characters |
| `expires` | required. `YYYY-MM-DD` is valid through the end of that day in UTC, an RFC 3339 timestamp is valid until that instant. |

An expired exception does not apply. Every time one matches a request after expiry it is logged at warn level (`expired policy exception matched and was not applied`) and counted in `kevgate_admit_exceptions_total{result="expired"}`, so stale waivers show up before someone wonders why a deploy started failing. An exception that applies adds a notice to the response warnings and increments the `applied` series.

## Decision output

- Allowed, nothing to say: `allowed: true`, no warnings.
- Allowed with notices (missing evidence under `warn`, exception applied, failing open): `allowed: true` plus `warnings`.
- Audit: `allowed: true`, one warning per violation starting with `kevgate-admit audit: would deny`.
- Denied: `allowed: false`, status 403, message with the namespace and scope, one block per violated rule, and the three highest-risk findings of each block (CVE, KEV flag, risk, package, fix). At most five violations are printed.

Findings are ordered by risk, then KEV first, then EPSS, then CVSS, then CVE ID.

## What is judged on UPDATE

For UPDATE requests only images that are not present in the old object are evaluated. A running Deployment keeps updating (scaling, labels) after a new KEV entry appears, and the controllers that own Pods are not blocked. Changing the image to something new is judged in full.

## Metrics label for namespaces

`kevgate_admit_decisions_total` uses the policy scope as its `namespace` label: the namespace name when it has its own entry, otherwise `_default`. This keeps label cardinality bounded by the policy rather than by whatever namespaces users create.
