#!/usr/bin/env bash
# Failure-mode test for a cluster that already runs the chart (run demo.sh first).
#
# It proves what the documentation says about availability:
#   1. the webhook's own namespace and kube-system are never sent to the webhook
#   2. with failurePolicy Fail and no webhook endpoints, a Pod create is rejected
#      by the API server ("failed calling webhook"), while excluded namespaces
#      keep working
#   3. with failurePolicy Ignore the same outage admits the Pod, even one the
#      policy would deny (the bypass window)
#   4. after the webhook is restored, normal allow and deny decisions resume
#
# Requires: kubectl pointing at the cluster, the release "kevgate-admit" in
# namespace kevgate-system, and the demo namespaces created by demo.sh.
#
# Usage: deploy/demo/outage.sh [--out DIR]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$here/../../demo-out"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$out"

webhook="validate.kevgate-admit.samiali38183.github.io"
config="kevgate-admit"
sysns="kevgate-system"
deploy="deploy/kevgate-admit"
selector="app.kubernetes.io/name=kevgate-admit"
tagonly_image="registry.example.com/demo/clean:latest"
clean_image="registry.example.com/demo/clean@sha256:1111111111111111111111111111111111111111111111111111111111111111"
failures=0

step() { printf '\n== %s\n' "$*"; }

# pod_manifest NAME IMAGE
pod_manifest() {
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $1
spec:
  restartPolicy: Never
  containers:
    - name: c
      image: $2
EOF
}

# create NAMESPACE NAME IMAGE [kubectl flags]: creates the Pod, stores output in $LAST
# and the exit status in $RC.
LAST=""
RC=0
create() {
  local ns="$1" name="$2" image="$3"
  shift 3
  RC=0
  LAST="$(pod_manifest "$name" "$image" | kubectl -n "$ns" create -f - "$@" 2>&1)" || RC=$?
  printf '%s\n' "$LAST"
}

# verdict NAME OK(0|1) [MESSAGE]
verdict() {
  if [ "$2" -eq 1 ]; then
    echo "RESULT $1: PASS"
  else
    echo "RESULT $1: FAIL${3:+ ($3)}"
    failures=$((failures + 1))
  fi
}

# has TEXT: succeeds when $LAST contains the text.
has() { grep -qF -- "$1" <<<"$LAST"; }

wait_webhook_answers() {
  # Poll with a pod the policy always denies until the webhook itself answers.
  for _ in $(seq 1 60); do
    create demo-enforce probe "$tagonly_image" --dry-run=server >/dev/null || true
    if has "denied the request"; then return 0; fi
    sleep 2
  done
  return 1
}

orig_replicas="$(kubectl -n "$sysns" get "$deploy" -o jsonpath='{.spec.replicas}')"
orig_policy="$(kubectl get validatingwebhookconfiguration "$config" -o jsonpath='{.webhooks[0].failurePolicy}')"
restore() {
  kubectl patch validatingwebhookconfiguration "$config" --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/webhooks/0/failurePolicy\",\"value\":\"$orig_policy\"}]" >/dev/null 2>&1 || true
  kubectl -n "$sysns" scale "$deploy" --replicas="$orig_replicas" >/dev/null 2>&1 || true
  for p in outage-fail outage-ignore outage-clean; do
    kubectl -n demo-enforce delete pod "$p" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done
}
trap restore EXIT

step "webhook configuration under test"
echo "failurePolicy: $orig_policy, replicas: $orig_replicas"
kubectl get validatingwebhookconfiguration "$config" -o jsonpath='{range .webhooks[0].namespaceSelector.matchExpressions[*]}namespaceSelector: {.key} {.operator} {.values}{"\n"}{end}'

step "baseline: a tag-only Pod is denied in a gated namespace"
create demo-enforce baseline "$tagonly_image" --dry-run=server
ok=0; { [ "$RC" -ne 0 ] && has "denied the request" && has "[requireDigest]"; } && ok=1
verdict baseline-denied "$ok"

step "self-exclusion: the same Pod is not judged in kube-system or in the webhook namespace"
for ns in kube-system "$sysns"; do
  create "$ns" "excluded-$ns" "$tagonly_image" --dry-run=server
  ok=0; { [ "$RC" -eq 0 ] && has "created (server dry run)"; } && ok=1
  verdict "excluded-$ns" "$ok"
done

step "outage: scale the webhook to zero replicas"
kubectl -n "$sysns" scale "$deploy" --replicas=0
kubectl -n "$sysns" wait --for=delete pod -l "$selector" --timeout=120s || true
kubectl -n "$sysns" get pods,endpoints -l "$selector" 2>&1 || true

step "failurePolicy Fail: a Pod create is rejected by the API server"
create demo-enforce outage-fail "$clean_image"
ok=0; { [ "$RC" -ne 0 ] && has "failed calling webhook \"$webhook\""; } && ok=1
verdict fail-policy-rejects "$ok"
if kubectl -n demo-enforce get pod outage-fail >/dev/null 2>&1; then verdict fail-policy-no-pod 0 "pod exists"; else verdict fail-policy-no-pod 1; fi

step "failurePolicy Fail: excluded namespaces still admit during the outage"
for ns in kube-system "$sysns"; do
  create "$ns" "excluded-$ns" "$tagonly_image" --dry-run=server
  ok=0; { [ "$RC" -eq 0 ] && has "created (server dry run)"; } && ok=1
  verdict "outage-excluded-$ns" "$ok"
done

step "failurePolicy Ignore: the same outage admits the Pod, even one the policy would deny"
kubectl patch validatingwebhookconfiguration "$config" --type=json \
  -p '[{"op":"replace","path":"/webhooks/0/failurePolicy","value":"Ignore"}]'
ok=0
for _ in $(seq 1 30); do
  create demo-enforce outage-ignore "$tagonly_image"
  if [ "$RC" -eq 0 ] && has "pod/outage-ignore created"; then ok=1; break; fi
  sleep 1
done
verdict ignore-policy-admits-tag-only-pod "$ok"
kubectl -n demo-enforce delete pod outage-ignore --ignore-not-found --wait=false

step "restore: failurePolicy back to $orig_policy, webhook back to $orig_replicas replicas"
kubectl patch validatingwebhookconfiguration "$config" --type=json \
  -p "[{\"op\":\"replace\",\"path\":\"/webhooks/0/failurePolicy\",\"value\":\"$orig_policy\"}]"
kubectl -n "$sysns" scale "$deploy" --replicas="$orig_replicas"
kubectl -n "$sysns" rollout status "$deploy" --timeout=180s
if wait_webhook_answers; then verdict webhook-answers-again 1; else verdict webhook-answers-again 0 "no answer within 120s"; fi

step "normal decisions resume: denied"
create demo-enforce probe "$tagonly_image" --dry-run=server
ok=0; { [ "$RC" -ne 0 ] && has "denied the request" && has "[requireDigest]"; } && ok=1
verdict resumed-deny-tag-only "$ok"
RC=0
kubectl -n demo-enforce apply -f "$here/workloads/kev-vulnerable.yaml" >"$out/outage-kev.txt" 2>&1 || RC=$?
LAST="$(cat "$out/outage-kev.txt")"
printf '%s\n' "$LAST"
ok=0; { [ "$RC" -ne 0 ] && has "denied the request" && has "[denyKev]" && has "CVE-2021-44228"; } && ok=1
verdict resumed-deny-kev "$ok"

step "normal decisions resume: allowed"
create demo-enforce outage-clean "$clean_image"
ok=0; { [ "$RC" -eq 0 ] && has "pod/outage-clean created"; } && ok=1
verdict resumed-allow-clean "$ok"

echo
if [ "$failures" -eq 0 ]; then
  echo "outage test finished: all checks passed"
else
  echo "outage test finished: $failures check(s) failed" >&2
  exit 1
fi
