#!/usr/bin/env bash
# helm upgrade test for tls.mode=helm (run demo.sh first, on the same cluster).
#
# With tls.mode=helm the chart generates a CA and serving certificate on the first
# install. On later revisions it must keep that Secret and the webhook's caBundle
# unchanged; if the Secret disappears from the manifest, Helm deletes it.
#
# Usage: deploy/demo/upgrade.sh [--image IMAGE]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
image="kevgate-admit:demo"
while [ $# -gt 0 ]; do
  case "$1" in
    --image) image="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
repo="${image%%:*}"
tag="${image#*:}"
ns="kevgate-system"
secret="kevgate-admit-tls"
failures=0

step() { printf '\n== %s\n' "$*"; }
ca_secret() { kubectl -n "$ns" get secret "$secret" -o jsonpath='{.data.ca\.crt}'; }
ca_webhook() { kubectl get validatingwebhookconfiguration kevgate-admit -o jsonpath='{.webhooks[0].clientConfig.caBundle}'; }
verdict() { if [ "$2" -eq 1 ]; then echo "RESULT $1: PASS"; else echo "RESULT $1: FAIL"; failures=$((failures + 1)); fi; }

step "before the upgrade"
secret_before="$(ca_secret)"
webhook_before="$(ca_webhook)"
helm -n "$ns" history kevgate-admit | tail -n 2

step "helm upgrade with the same values"
helm upgrade kevgate-admit "$root/deploy/helm/kevgate-admit" \
  --namespace "$ns" -f "$here/values-demo.yaml" \
  --set image.repository="$repo" --set image.tag="$tag" \
  --wait --timeout 180s
helm -n "$ns" history kevgate-admit | tail -n 2

step "the TLS Secret and the caBundle are unchanged"
secret_after="$(ca_secret || true)"
webhook_after="$(ca_webhook)"
ok=0; if [ -n "$secret_after" ] && [ "$secret_after" = "$secret_before" ]; then ok=1; fi
verdict secret-kept-and-unchanged "$ok"
ok=0; if [ "$webhook_after" = "$webhook_before" ] && [ "$webhook_after" = "$secret_after" ]; then ok=1; fi
verdict cabundle-matches-secret "$ok"

step "the webhook still answers: a tag-only Pod is denied"
probe=""
for _ in $(seq 1 30); do
  probe="$(kubectl -n demo-enforce apply -f "$here/workloads/tag-only.yaml" 2>&1 || true)"
  grep -q "denied the request" <<<"$probe" && break
  sleep 2
done
echo "$probe"
ok=0; if grep -q "denied the request" <<<"$probe"; then ok=1; fi
verdict deny-after-upgrade "$ok"

if [ "$failures" -ne 0 ]; then echo "upgrade test failed: $failures check(s)" >&2; exit 1; fi
echo "upgrade test finished: all checks passed"
