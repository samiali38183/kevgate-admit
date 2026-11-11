#!/usr/bin/env bash
# End to end demo on a kind cluster: installs the chart with synthetic evidence
# and checks that the webhook allows, denies and warns as expected.
#
# Requires: kind, kubectl, helm and a local image already built, for example
#   docker build -t kevgate-admit:demo .
#
# Usage: deploy/demo/demo.sh [--cluster NAME] [--image IMAGE] [--out DIR] [--keep] [--use-current-context]
#
# The evidence in deploy/demo/reports is SYNTHETIC. It is not scan output.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cluster="kevgate-demo"
image="kevgate-admit:demo"
out="$root/demo-out"
keep=0
own_cluster=1

while [ $# -gt 0 ]; do
  case "$1" in
    --cluster) cluster="$2"; shift 2 ;;
    --image) image="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --keep) keep=1; shift ;;
    --use-current-context) own_cluster=0; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$out"
failures=0

step() { printf '\n== %s\n' "$*"; }

cleanup() {
  if [ "$keep" -eq 0 ] && [ "$own_cluster" -eq 1 ]; then
    kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [ "$own_cluster" -eq 1 ]; then
  step "creating kind cluster $cluster"
  kind create cluster --name "$cluster" --wait 120s
  kind load docker-image "$image" --name "$cluster"
fi

step "namespaces and evidence"
kubectl create namespace kevgate-system --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace demo-enforce --dry-run=client -o yaml | kubectl apply -f -
kubectl create namespace demo-audit --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kevgate-system create configmap demo-kev \
  --from-file=known_exploited_vulnerabilities.json="$here/kev-demo.json" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kevgate-system create configmap demo-evidence \
  --from-file="$here/reports" --dry-run=client -o yaml | kubectl apply -f -

step "installing the chart"
repo="${image%%:*}"
tag="${image#*:}"
helm upgrade --install kevgate-admit "$root/deploy/helm/kevgate-admit" \
  --namespace kevgate-system -f "$here/values-demo.yaml" \
  --set image.repository="$repo" --set image.tag="$tag" \
  --wait --timeout 180s

step "waiting for the webhook endpoint to accept connections"
# helm --wait only proves the pod is Ready. The Service route can lag behind by
# a few seconds, and failurePolicy is Fail, so poll with a server-side dry run
# until the API server can reach the webhook (any answer except a call failure).
reachable=0
for _ in $(seq 1 60); do
  if ! kubectl -n demo-enforce apply --dry-run=server -f "$here/workloads/clean.yaml" 2>&1 | grep -q "failed calling webhook"; then
    reachable=1
    break
  fi
  sleep 2
done
if [ "$reachable" -ne 1 ]; then
  echo "webhook did not become reachable within 120s" >&2
  kubectl -n kevgate-system get pods,svc,endpoints -o wide >&2 || true
  kubectl -n kevgate-system logs deploy/kevgate-admit >&2 || true
  exit 1
fi

# check NAME NAMESPACE MANIFEST EXPECT(allowed|denied|warned) PATTERN...
# Applies the manifest, stores the output and verifies the outcome and that
# every PATTERN appears in the output.
check() {
  local name="$1" ns="$2" manifest="$3" expect="$4"
  shift 4
  local file="$out/$name.txt" rc=0
  step "$name in $ns (expect: $expect)"
  kubectl -n "$ns" apply -f "$here/workloads/$manifest" >"$file" 2>&1 || rc=$?
  cat "$file"
  local ok=1
  case "$expect" in
    allowed) [ "$rc" -eq 0 ] && ! grep -q "^Warning:" "$file" || ok=0 ;;
    warned) [ "$rc" -eq 0 ] && grep -q "^Warning:" "$file" || ok=0 ;;
    denied) [ "$rc" -ne 0 ] && grep -q "denied the request" "$file" || ok=0 ;;
  esac
  local p
  for p in "$@"; do
    grep -qF -- "$p" "$file" || { echo "missing text: $p"; ok=0; }
  done
  if [ "$ok" -eq 1 ]; then echo "RESULT $name: PASS"; else echo "RESULT $name: FAIL"; failures=$((failures + 1)); fi
}

check clean demo-enforce clean.yaml allowed
check kev-vulnerable demo-enforce kev-vulnerable.yaml denied \
  'kevgate-admit: request denied by policy (namespace "demo-enforce", scope "demo-enforce")' \
  '[denyKev] registry.example.com/demo/kev-vulnerable@sha256:222222222222' \
  'CVE-2021-44228' 'log4j-core 2.14.1 (fixed 2.17.1)'
check over-threshold-enforce demo-enforce over-threshold.yaml denied \
  '[maxRisk] registry.example.com/demo/over-threshold@sha256:333333333333' \
  'above max risk 40.0 (highest 47.7)' 'CVE-2099-10004'
check over-threshold-audit demo-audit over-threshold.yaml warned \
  'would deny [maxRisk]' 'highest 47.7'
check tag-only demo-enforce tag-only.yaml denied '[requireDigest]' 'not pinned by digest'

step "collecting webhook logs and metrics"
kubectl -n kevgate-system logs deploy/kevgate-admit >"$out/webhook.log" 2>&1 || true
pod="$(kubectl -n kevgate-system get pod -l app.kubernetes.io/name=kevgate-admit -o jsonpath='{.items[0].metadata.name}')"
kubectl get --raw "/api/v1/namespaces/kevgate-system/pods/${pod}:8080/proxy/metrics" >"$out/metrics.txt" 2>&1 || true
grep '^kevgate_admit_decisions_total' "$out/metrics.txt" || true

echo
if [ "$failures" -eq 0 ]; then
  echo "demo finished: all checks passed"
else
  echo "demo finished: $failures check(s) failed" >&2
  exit 1
fi
