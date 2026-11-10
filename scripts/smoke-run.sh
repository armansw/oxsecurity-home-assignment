#!/usr/bin/env bash
# Smoke test for ./run.sh from a clean machine (used by CI on Linux and macOS):
# start it, run a real scan through the UI's proxy, stop it (as Ctrl-C does), and check everything stopped.
#   CG_FORCE_LOCAL_TOOLS=1 ./scripts/smoke-run.sh      # also forces the Node/Trivy download path
set -euo pipefail
cd "$(dirname "$0")/.."
API_PORT="${API_PORT:-3000}"; WEB_PORT="${WEB_PORT:-5173}"
REPO="${REPO:-https://github.com/armansw/NodeGoat}"
LOG="$(mktemp)"

API_PORT="$API_PORT" WEB_PORT="$WEB_PORT" ./run.sh > "$LOG" 2>&1 &
RUN_PID=$!
trap 'kill -TERM $RUN_PID 2>/dev/null || true; cat "$LOG"' EXIT

for _ in $(seq 1 450); do
  grep -q "is running" "$LOG" && break
  kill -0 "$RUN_PID" 2>/dev/null || { echo "FAIL: run.sh exited during start-up"; exit 1; }
  sleep 2
done
grep -q "is running" "$LOG" || { echo "FAIL: run.sh did not become ready"; exit 1; }
echo "run.sh is up"

# run.sh moves to the next free port when one is busy; use the ports it actually printed.
WEB_PORT="$(sed -E 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -oE 'Web UI +http://localhost:[0-9]+' | grep -oE '[0-9]+$')"
API_PORT="$(sed -E 's/\x1b\[[0-9;]*m//g' "$LOG" | grep -oE 'REST API +http://localhost:[0-9]+' | grep -oE '[0-9]+$')"
UI="http://127.0.0.1:$WEB_PORT"
curl -fsS "$UI/" | grep -q '<div id="root">' || { echo "FAIL: UI not served"; exit 1; }
id="$(curl -fsS -X POST "$UI/api/scan" -H 'content-type: application/json' -d "{\"repoUrl\":\"$REPO\"}" | sed -E 's/.*"scanId":"([^"]+)".*/\1/')"
status=""
for _ in $(seq 1 300); do
  body="$(curl -fsS "$UI/api/scan/$id?limit=1")"
  status="$(sed -E 's/.*"status":"([A-Za-z]+)".*/\1/' <<<"$body")"
  [[ "$status" == Finished || "$status" == Failed ]] && break
  sleep 2
done
critical="$(grep -oE '"criticalCount":[0-9]+' <<<"$body" | cut -d: -f2 || true)"
echo "scan: status=$status criticalCount=${critical:-?}"
[[ "$status" == Finished && "${critical:-0}" -ge 1 ]] || { echo "FAIL: scan did not finish with criticals: $body"; exit 1; }

trap - EXIT
# SIGTERM, not SIGINT: background jobs of a non-interactive shell ignore SIGINT. run.sh traps both identically.
kill -TERM "$RUN_PID"; wait "$RUN_PID" || true
sleep 2
if curl -fsS "http://127.0.0.1:$API_PORT/healthz" >/dev/null 2>&1 || curl -fsS "$UI/" >/dev/null 2>&1; then
  echo "FAIL: servers still running after stop"; exit 1
fi
echo "PASS: run.sh started, scanned, and stopped cleanly"
