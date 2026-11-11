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
| `allowedRegistries` | empty (any) | Registry host or host plus repository path prefix, validated with the same grammar as image references (see "Image references"). Matching is on whole path components: `ghcr.io/org` does not match `ghcr.io/org2/app`, and a prefix such as `ghcr.io/org/..` is rejected when the policy loads. `docker.io` covers Docker Hub names. |
| `assetCriticality` | 4 | The `acr` input of the risk formula, 1 to 8, for every workload in the namespace. |
| `maxEvidenceAge` | unset | Reports older than this count as missing. Needs a report timestamp (`CreatedAt`, else the file modification time). The kevgate HTTP provider has no timestamp, so the check is skipped for it. |
| `ignoreUnfixed` | false | Drop findings with no fixed version before scoring, except findings in the CISA KEV catalog (or marked KEV by the evidence source), which are never dropped. See "Unfixed findings". |
| `requireSignedEvidence` | false | Only trust scan reports whose detached signature verifies against a configured key. See "Signed evidence". |
| `exceptions` | none | See below. At most 500 per rule. |

Evidence is only looked up when a rule uses it: `maxRisk`, `denyKev`, or `requireEvidence` other than `allow`. A policy made only of `allowedRegistries` and `requireDigest` never touches the evidence source.

## Evidence failures

Two different situations are kept apart:

- No report for the digest, a stale one, or (with `requireSignedEvidence`) an unauthenticated one: follows `requireEvidence`.
- The source itself fails (timeout, malformed or mismatched report, I/O error, panic): follows the server flag `--fail-mode`. With `closed` the request is denied under the rule name `evidenceError`. With `open` it is admitted with a warning.

## Image references

Every image is parsed before it is judged. A reference that cannot be pulled is denied under the rule name `imageRef`; it is never treated as merely unpinned. The grammar follows the OCI Distribution Specification (the name and reference patterns in "Pulling manifests") and the OCI Image Specification digest syntax (descriptor.md, "Digests"), with the registry host syntax of `github.com/distribution/reference`:

- Printable ASCII only. No whitespace, control characters or non-ASCII bytes.
- Registry host: a DNS name (RFC 1123 labels, at most 63 characters each), an IPv4 address, or a bracketed IPv6 address, with an optional port from 1 to 65535. Hosts are lower-cased. The first path component is a host when it contains `.` or `:`, is `localhost`, or contains an upper-case letter; otherwise the image is on Docker Hub, and `name` becomes `docker.io/library/name`.
- Repository: path components of lower-case letters and digits joined by `.`, `_`, `__` or runs of `-`, separated by `/`, at most 255 characters. Components `.` and `..`, empty components, and upper-case letters are rejected, so `ghcr.io/org/../evil` is invalid instead of matching the prefix `ghcr.io/org`.
- Tag: `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
- Digest: `sha256:` plus 64 or `sha512:` plus 128 lower-case hex digits. Other algorithms are rejected because the report store is keyed by these two.
- A bare 64 hex digit name with no host or namespace is an image ID, which runtimes built on `distribution/reference` also refuse.
- At most 512 characters in total.

Deliberately stricter than `distribution/reference`: ports outside 1 to 65535, host labels over 63 characters, underscores in host names, IPv6 literals that are not valid addresses, and the 512 character total are rejected. A differential fuzz run against that library in a scratch module found no other class of disagreement (see the README verification section).

## Unfixed findings

A finding with no fixed version in the report (`FixedVersion` empty, which Trivy also uses for "will not fix" and "affected") is called unfixed here.

- `ignoreUnfixed: false` (default): unfixed findings are scored and judged like any other.
- `ignoreUnfixed: true`: unfixed findings are dropped before scoring, so they count for neither `denyKev` nor `maxRisk`, with one exception that cannot be switched off: a finding that is in the CISA KEV catalog, or that the evidence source marks as KEV, is never dropped. A vulnerability that is exploited in the wild is the last one to ignore for lack of a fix. It still counts for `denyKev` and, with its KEV weight, for `maxRisk`.
- Only an explicit exception (`cve:`, with justification and expiry) can waive a KEV finding without a fix.

`maxRisk` is evaluated per finding, not summed: an image passes when no single finding scores above the limit, however many mid-risk findings it has. An unfixed finding that is not KEV scores like any other, using its CVSS, EPSS and the namespace's `assetCriticality`; with `ignoreUnfixed: true` it does not count at all.

## Signed evidence

Reports in the store are plain files, so whoever can write there can make an image look clean. `requireSignedEvidence: true` makes a rule trust only reports that carry a valid detached signature.

- Server side: start with `--evidence-public-key-file keys.pem` (one or more PEM `PUBLIC KEY` blocks, Ed25519 or ECDSA P-256; several keys allow rotation). The directory provider then checks `<digest>.json.sig` next to every `<digest>.json`. In the chart: `evidence.publicKey.existingConfigMap`.
- Signing side: `kevgate-admit keygen`, then `kevgate-admit sign-report -key priv.pem sha256-<hex>.json`, and `kevgate-admit verify-report -public-key pub.pem sha256-<hex>.json` to check offline. Keep the private key in the scan pipeline, not in the cluster.
- What is signed: `"kevgate-admit report signature v1\n" + digest + "\n" + report bytes`. Binding the digest means a signed report copied to another digest's file name does not verify. The `.sig` file is the base64 of the signature (Ed25519 over the message; ECDSA over its SHA-256, ASN.1 DER).
- Failure behaviour: a report that is unsigned, badly signed, signed by an untrusted key, or checked without any key configured is not scored and none of its findings are shown. It is treated as missing evidence, so `requireEvidence` decides: `deny` (default) rejects with the reason in the message (`scan report is unsigned`, `scan report signature is invalid`, `scan report cannot be authenticated`), `warn` admits with a warning, `allow` admits. A `requireEvidence` exception for the image applies as for any missing report.
- The kevgate HTTP provider cannot carry signatures, so with `requireSignedEvidence` its answers count as unauthenticated.
- If the policy sets `requireSignedEvidence` but no key is configured, every report is treated as unauthenticated and the server logs a warning at start.
- Without the option, signatures are not consulted for decisions even when a key is configured.

Scope: this authenticates the report store. It does not verify that the image bytes are what the report describes beyond the digest key, and it does not verify image signatures (cosign or Notary). A valid signature on an old report stays valid, so keep `maxEvidenceAge` set: the age comes from the signed `CreatedAt` field when the report has one, and from the unsigned file modification time otherwise.

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
