#!/usr/bin/env bash
# End-to-end proof inside the 200 MB container. Run against an already started compose stack.
#
#   ./scripts/e2e-docker.sh            # real Trivy scan of NodeGoat; expects ≥1 CRITICAL
#   ./scripts/e2e-docker.sh --fixture  # 600 MB synthetic report (docker-compose.oom.yml)
#   ./scripts/e2e-docker.sh --split    # API and worker in separate containers (docker-compose.split.yml)
#
# EXTRA_COMPOSE_FILES adds override files (e.g. docker-compose.150m.yml). WEB_URL (e.g. http://localhost:8080)
# also checks the React UI and the nginx proxy for REST and GraphQL.
#
# Fails unless the scan Finishes, the container was NOT OOM-killed, and its workspace is empty afterwards.
set -euo pipefail

API="${API:-http://localhost:3000}"
REPO="${REPO:-https://github.com/armansw/NodeGoat}"   # the assignment's fork of OWASP/NodeGoat
MODE="${1:-trivy}"
TIMEOUT_S="${TIMEOUT_S:-900}"
SERVICE="${SERVICE:-app}"
COMPOSE=(docker compose -f docker-compose.yml)
[[ "$MODE" == "--fixture" ]] && COMPOSE+=(-f docker-compose.oom.yml)
if [[ "$MODE" == "--split" ]]; then COMPOSE+=(-f docker-compose.split.yml); SERVICE=worker; fi   # inspect the worker
for f in ${EXTRA_COMPOSE_FILES:-}; do COMPOSE+=(-f "$f"); done

container="$("${COMPOSE[@]}" ps -q "$SERVICE")"
[[ -n "$container" ]] || { echo "service '$SERVICE' is not running" >&2; exit 1; }

echo "waiting for $API/readyz"
for _ in $(seq 1 120); do curl -fsS "$API/readyz" >/dev/null 2>&1 && break; sleep 2; done
curl -fsS "$API/readyz"; echo

# Sample container memory while the scan runs (cgroup usage as reported by docker stats).
peak_file="$(mktemp)"; echo 0 > "$peak_file"
( while true; do
    mem="$(docker stats --no-stream --format '{{.MemUsage}}' "$container" 2>/dev/null | awk '{print $1}')"
    mib="$(awk -v m="$mem" 'BEGIN{ v=m+0; if (m ~ /GiB/) v*=1024; else if (m ~ /KiB/) v/=1024; else if (m ~ /B$/ && m !~ /iB/) v/=1048576; printf "%d", v }')"
    [[ "$mib" -gt "$(cat "$peak_file")" ]] && echo "$mib" > "$peak_file"
    sleep 1
  done ) & sampler=$!
trap 'kill $sampler 2>/dev/null || true' EXIT

scan_id="$(curl -fsS -X POST "$API/api/scan" -H 'content-type: application/json' -d "{\"repoUrl\":\"$REPO\"}" | sed -E 's/.*"scanId":"([^"]+)".*/\1/')"
echo "scanId=$scan_id"

deadline=$((SECONDS + TIMEOUT_S)); status=""
while (( SECONDS < deadline )); do
  if ! body="$(curl -fsS "$API/api/scan/$scan_id?limit=1")"; then
    echo "API unreachable — container state: $(docker inspect -f '{{json .State}}' "$container")"
    break
  fi
  status="$(sed -E 's/.*"status":"([A-Za-z]+)".*/\1/' <<<"$body")"
  printf '%s  %s\n' "$(date +%T)" "$(grep -oE '"(status|phase|progressPct)":("[^"]*"|[0-9]+|null)' <<<"$body" | tr '\n' ' ')"
  [[ "$status" == "Finished" || "$status" == "Failed" ]] && break
  sleep 2
done

kill $sampler 2>/dev/null || true
echo "final: $body"
oom="$(docker inspect -f '{{.State.OOMKilled}}' "$container")"
limit_mib="$(( $(docker inspect -f '{{.HostConfig.Memory}}' "$container") / 1048576 ))"
leftovers="$(docker exec "$container" sh -c 'ls -A /work | grep "^scan-" | wc -l')"
critical="$(grep -oE '"criticalCount":[0-9]+' <<<"$body" | cut -d: -f2)"

echo "status=$status criticalCount=${critical:-?} containerLimit=${limit_mib}MiB peakContainerMem=$(cat "$peak_file")MiB OOMKilled=$oom leftoverWorkspaces=$leftovers"
[[ "$status" == "Finished" ]] || { echo "FAIL: scan did not finish"; exit 1; }
[[ "$oom" == "false" ]] || { echo "FAIL: container was OOM-killed"; exit 1; }
[[ "$leftovers" == "0" ]] || { echo "FAIL: workspace not cleaned up"; exit 1; }
[[ "${critical:-0}" -ge 1 ]] || { echo "FAIL: expected at least one CRITICAL vulnerability"; exit 1; }

if [[ -n "${WEB_URL:-}" ]]; then
  echo "checking the web UI and its nginx proxy at $WEB_URL"
  curl -fsS "$WEB_URL/" | grep -q '<div id="root">' || { echo "FAIL: UI did not serve index.html"; exit 1; }
  curl -fsS "$WEB_URL/some/client/route" | grep -q '<div id="root">' || { echo "FAIL: SPA fallback missing"; exit 1; }
  curl -fsS "$WEB_URL/api/scan/$scan_id?limit=1" | grep -q '"status":"Finished"' || { echo "FAIL: REST through nginx"; exit 1; }
  curl -fsS "$WEB_URL/graphql" -H 'content-type: application/json' \
    -d "{\"query\":\"{ scan(id: \\\"$scan_id\\\") { status criticalCount } }\"}" | grep -q '"status":"Finished"' \
    || { echo "FAIL: GraphQL through nginx"; exit 1; }
  # Unpaginated results are streamed; nginx must pass the full body through.
  full="$(curl -fsS "$WEB_URL/api/scan/$scan_id" | grep -o '"severity":"CRITICAL"' | wc -l | tr -d ' ')"
  [[ "$full" == "$critical" ]] || { echo "FAIL: streamed body through nginx had $full of $critical findings"; exit 1; }
  echo "web UI + proxy OK (REST, GraphQL, streamed body with $full findings)"
fi
echo PASS
