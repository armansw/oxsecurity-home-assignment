#!/usr/bin/env bash
# Code Guardian — one command to run everything locally.
#
#   ./run.sh              build and start the API + worker and the web UI (Ctrl-C stops everything)
#   ./run.sh docker       same, with docker compose (200 MB container + Trivy server sidecar)
#   ./run.sh test         lint, typecheck and test backend and frontend
#   ./run.sh oom-check    600 MB report under --max-old-space-size=150 (pass a size: ./run.sh oom-check 300)
#   ./run.sh doctor       show which tools were found or will be installed
#   ./run.sh clean        remove the local toolchain, data and build output
#
# Nothing is installed globally. Node and Trivy are used from your PATH when suitable; otherwise pinned,
# checksum-verified copies are downloaded into ./.cg-env/. Requires only: bash, curl (or wget), tar, git.
#
# Environment: API_PORT (default 3000), WEB_PORT (default 5173), CG_FORCE_LOCAL_TOOLS=1 (ignore PATH tools).
# Works on Linux and macOS (x64, arm64). On Windows, use WSL2 or `./run.sh docker`.

set -euo pipefail

NODE_VERSION="24.22.1"   # LTS "Krypton"; same major version as the Docker image
NODE_MIN_MAJOR=22
NODE_MIN_MINOR=12
TRIVY_VERSION="0.76.1"   # postdates every 2026 Trivy security advisory; same version as the Docker image

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR="$ROOT/.cg-env"
TOOLS="$ENV_DIR/tools"
API_PORT="${API_PORT:-3000}"
WEB_PORT="${WEB_PORT:-5173}"

# ---------------------------------------------------------------------------------------------- output
if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'; else B= D= G= Y= R= N=; fi
step() { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '    %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

# ------------------------------------------------------------------------------------------- platform
detect_platform() {
  case "$(uname -s)" in
    Linux)  OS=linux ;;
    Darwin) OS=darwin ;;
    MINGW*|MSYS*|CYGWIN*) die "Windows shells are not supported. Use WSL2 (then run ./run.sh there) or ./run.sh docker." ;;
    *) die "Unsupported OS: $(uname -s)" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) ARCH=x64 ;;
    arm64|aarch64) ARCH=arm64 ;;
    *) die "Unsupported CPU architecture: $(uname -m)" ;;
  esac
}

have() { command -v "$1" >/dev/null 2>&1; }

download() { # url dest
  if have curl; then curl -fL --retry 3 --progress-bar -o "$2" "$1"
  elif have wget; then wget -q --show-progress -O "$2" "$1"
  else die "curl or wget is required to download tools"; fi
}

sha256_of() {
  if have sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif have shasum; then shasum -a 256 "$1" | awk '{print $1}'
  else die "sha256sum or shasum is required to verify downloads"; fi
}

verify() { # file expected-sha
  local actual; actual="$(sha256_of "$1")"
  [ -n "$2" ] && [ "$actual" = "$2" ] || die "checksum mismatch for $(basename "$1") — refusing to use it (expected $2, got $actual)"
}

require_basics() {
  local missing=""
  for t in tar git; do have "$t" || missing="$missing $t"; done
  have curl || have wget || missing="$missing curl"
  [ -z "$missing" ] && return 0
  local hint
  if [ "$OS" = darwin ]; then hint="xcode-select --install"
  elif have apt-get; then hint="sudo apt-get install -y${missing}"
  elif have dnf; then hint="sudo dnf install -y${missing}"
  elif have apk; then hint="sudo apk add${missing}"
  else hint="install:${missing}"; fi
  die "missing required tools:${missing}. Install them with: $hint"
}

# ----------------------------------------------------------------------------------------------- node
node_is_suitable() { # node-binary
  local v major minor
  v="$("$1" -v 2>/dev/null)" || return 1
  v="${v#v}"; major="${v%%.*}"; minor="${v#*.}"; minor="${minor%%.*}"
  [ "$major" -gt "$NODE_MIN_MAJOR" ] || { [ "$major" -eq "$NODE_MIN_MAJOR" ] && [ "$minor" -ge "$NODE_MIN_MINOR" ]; }
}

ensure_node() {
  local local_bin="$TOOLS/node/bin"
  if [ "${CG_FORCE_LOCAL_TOOLS:-0}" != 1 ] && have node && node_is_suitable node; then
    NODE_SOURCE="system $(node -v)"; return 0
  fi
  if [ -x "$local_bin/node" ] && node_is_suitable "$local_bin/node"; then
    export PATH="$local_bin:$PATH"; NODE_SOURCE="local $(node -v)"; return 0
  fi
  step "Installing Node.js v$NODE_VERSION into .cg-env (no system changes)"
  local ext=tar.xz; [ "$OS" = darwin ] && ext=tar.gz
  local name="node-v$NODE_VERSION-$OS-$ARCH" tmp; tmp="$(mktemp -d)"
  download "https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt" "$tmp/SHASUMS256.txt"
  download "https://nodejs.org/dist/v$NODE_VERSION/$name.$ext" "$tmp/$name.$ext"
  verify "$tmp/$name.$ext" "$(awk -v f="$name.$ext" '$2==f {print $1}' "$tmp/SHASUMS256.txt")"
  rm -rf "$TOOLS/node"; mkdir -p "$TOOLS"
  tar -xf "$tmp/$name.$ext" -C "$tmp" && mv "$tmp/$name" "$TOOLS/node"
  rm -rf "$tmp"
  export PATH="$local_bin:$PATH"
  NODE_SOURCE="local $(node -v)"
  ok "Node $(node -v) (checksum verified)"
}

# ---------------------------------------------------------------------------------------------- trivy
ensure_trivy() {
  if [ "${CG_FORCE_LOCAL_TOOLS:-0}" != 1 ] && have trivy; then
    TRIVY_BIN="$(command -v trivy)"; TRIVY_SOURCE="system $(trivy --version 2>/dev/null | head -1)"; return 0
  fi
  if [ -x "$TOOLS/trivy/trivy" ]; then
    TRIVY_BIN="$TOOLS/trivy/trivy"; TRIVY_SOURCE="local $("$TRIVY_BIN" --version | head -1)"; return 0
  fi
  step "Installing Trivy v$TRIVY_VERSION into .cg-env"
  local os_label arch_label
  if [ "$OS" = darwin ]; then os_label=macOS; else os_label=Linux; fi
  if [ "$ARCH" = arm64 ]; then arch_label=ARM64; else arch_label=64bit; fi
  local name="trivy_${TRIVY_VERSION}_${os_label}-${arch_label}.tar.gz" base tmp
  base="https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION"
  tmp="$(mktemp -d)"
  download "$base/trivy_${TRIVY_VERSION}_checksums.txt" "$tmp/checksums.txt"
  download "$base/$name" "$tmp/$name"
  verify "$tmp/$name" "$(awk -v f="$name" '$2==f {print $1}' "$tmp/checksums.txt")"
  mkdir -p "$TOOLS/trivy" && tar -xzf "$tmp/$name" -C "$TOOLS/trivy" trivy
  rm -rf "$tmp"
  TRIVY_BIN="$TOOLS/trivy/trivy"; TRIVY_SOURCE="local $("$TRIVY_BIN" --version | head -1)"
  ok "Trivy $TRIVY_VERSION (checksum verified)"
}

# --------------------------------------------------------------------------------------------- deps
install_deps() { # dir label
  local dir="$1" stamp="$ENV_DIR/stamps/$2.lock-sha"
  mkdir -p "$ENV_DIR/stamps"
  local want; want="$(sha256_of "$dir/package-lock.json")"
  if [ -d "$dir/node_modules" ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$want" ]; then
    ok "$2 dependencies up to date"; return 0
  fi
  step "Installing $2 dependencies"
  (cd "$dir" && npm ci --no-audit --no-fund --loglevel=error)
  echo "$want" > "$stamp"
  ok "$2 dependencies installed"
}

build_all() {
  step "Building backend and web UI"
  (cd "$ROOT" && npm run --silent build)
  (cd "$ROOT/web" && ./node_modules/.bin/vite build --logLevel error)
  ok "build complete"
}

port_free() { # port
  node -e "const s=require('net').createServer();s.once('error',()=>process.exit(1));s.listen($1,'127.0.0.1',()=>s.close(()=>process.exit(0)))"
}

pick_port() { # preferred -> first free port at or above it
  local p="$1"
  while ! port_free "$p"; do p=$((p + 1)); done
  echo "$p"
}

wait_http() { # url seconds
  local i=0
  until node -e "fetch('$1').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -ge "$2" ] && return 1; sleep 1
  done
}

bootstrap() {
  detect_platform
  require_basics
  ensure_node
  ensure_trivy
  install_deps "$ROOT" backend
  install_deps "$ROOT/web" web
}

# -------------------------------------------------------------------------------------------- commands
cmd_start() {
  bootstrap
  build_all

  local api_port web_port
  api_port="$(pick_port "$API_PORT")"; web_port="$(pick_port "$WEB_PORT")"
  [ "$api_port" = "$API_PORT" ] || warn "port $API_PORT is busy; API uses $api_port"
  [ "$web_port" = "$WEB_PORT" ] || warn "port $WEB_PORT is busy; UI uses $web_port"
  mkdir -p "$ENV_DIR/data" "$ENV_DIR/work" "$ENV_DIR/logs"

  PIDS=""
  cleanup() {
    trap - INT TERM EXIT
    printf '\n'; step "Stopping"
    for pid in $PIDS; do kill "$pid" 2>/dev/null || true; done   # SIGTERM: the API re-queues in-flight scans
    wait 2>/dev/null || true
    ok "stopped"
  }
  trap 'cleanup; exit 0' INT TERM
  trap cleanup EXIT

  step "Starting API + worker on :$api_port  ${D}(node --max-old-space-size=150, the brief's self-test)${N}"
  if [ ! -d "$ENV_DIR/trivy-cache/db" ]; then
    info "First scan downloads Trivy's vulnerability database (~1 min, kept in .cg-env for later runs)."
  fi
  (cd "$ROOT" && exec env \
      PORT="$api_port" HOST=127.0.0.1 ROLE=all LOG_LEVEL="${LOG_LEVEL:-info}" \
      DATABASE_PATH="$ENV_DIR/data/code-guardian.db" WORK_DIR="$ENV_DIR/work" \
      TRIVY_BIN="$TRIVY_BIN" TRIVY_CACHE_DIR="$ENV_DIR/trivy-cache" MIN_FREE_DISK_MB="${MIN_FREE_DISK_MB:-1024}" \
      NODE_OPTIONS="${NODE_OPTIONS:---max-semi-space-size=2}" \
      node --max-old-space-size=150 dist/index.js) > "$ENV_DIR/logs/api.log" 2>&1 &
  PIDS="$PIDS $!"
  wait_http "http://127.0.0.1:$api_port/healthz" 30 || { tail -20 "$ENV_DIR/logs/api.log" >&2; die "API did not start (log: .cg-env/logs/api.log)"; }
  ok "API ready"

  step "Starting web UI on :$web_port"
  # exec the vite binary itself (not npx), so the PID we hold is the server and Ctrl-C really stops it.
  (cd "$ROOT/web" && BACKEND_URL="http://127.0.0.1:$api_port" exec ./node_modules/.bin/vite preview \
      --host 127.0.0.1 --port "$web_port" --strictPort) > "$ENV_DIR/logs/web.log" 2>&1 &
  PIDS="$PIDS $!"
  wait_http "http://127.0.0.1:$web_port/" 30 || { tail -20 "$ENV_DIR/logs/web.log" >&2; die "web UI did not start (log: .cg-env/logs/web.log)"; }
  ok "web UI ready"

  cat <<EOF

  ${B}Code Guardian is running${N}
    Web UI     ${G}http://localhost:$web_port${N}
    REST API   http://localhost:$api_port/api/scan
    GraphQL    http://localhost:$api_port/graphql   ${D}(GraphiQL: http://localhost:$api_port/graphiql)${N}
    Metrics    http://localhost:$api_port/metrics
    Logs       .cg-env/logs/api.log, .cg-env/logs/web.log

  Try:  curl -s -X POST localhost:$api_port/api/scan -H 'content-type: application/json' \\
             -d '{"repoUrl":"https://github.com/OWASP/NodeGoat"}'

  Press Ctrl-C to stop.
EOF
  # Exit (and clean up) as soon as either process dies.
  while :; do
    for pid in $PIDS; do kill -0 "$pid" 2>/dev/null || { warn "a process exited; see .cg-env/logs"; exit 1; }; done
    sleep 2
  done
}

cmd_docker() {
  have docker || die "Docker is not installed. Run ./run.sh (no Docker needed) or install Docker Desktop / Docker Engine."
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (docker compose ...)."
  step "Starting with docker compose (app mem_limit ${APP_MEM_LIMIT:-200m}, Trivy server, web UI)"
  info "UI http://localhost:8080 · API http://localhost:3000 · first start downloads Trivy's DB (~1 min)"
  cd "$ROOT" && exec docker compose up --build
}

cmd_test() {
  bootstrap
  step "Backend: lint, typecheck, tests with coverage"
  (cd "$ROOT" && npm run --silent lint && npm run --silent typecheck && npm run --silent test:coverage)
  step "Web: lint, typecheck, tests with coverage"
  (cd "$ROOT/web" && npm run --silent lint && npm run --silent typecheck && npm run --silent test:coverage)
  ok "all checks passed"
}

cmd_oom_check() {
  detect_platform; require_basics; ensure_node; install_deps "$ROOT" backend
  step "OOM check: ${1:-600} MB report under --max-old-space-size=150"
  (cd "$ROOT" && npm run --silent build && node --max-old-space-size=150 dist/scripts/oom-check.js --size-mb "${1:-600}" --dir "$ENV_DIR/oom")
}

cmd_doctor() {
  detect_platform
  step "Platform: $OS/$ARCH"
  for t in bash git tar curl wget docker; do
    if have "$t"; then ok "$t: $(command -v "$t")"; else warn "$t: not found"; fi
  done
  if have node && node_is_suitable node; then ok "node: $(node -v) (system)"
  elif [ -x "$TOOLS/node/bin/node" ]; then ok "node: $("$TOOLS/node/bin/node" -v) (.cg-env)"
  else warn "node: none suitable (need >= $NODE_MIN_MAJOR.$NODE_MIN_MINOR) — ./run.sh will install v$NODE_VERSION locally"; fi
  if have trivy; then ok "trivy: $(trivy --version 2>/dev/null | head -1) (system)"
  elif [ -x "$TOOLS/trivy/trivy" ]; then ok "trivy: $("$TOOLS/trivy/trivy" --version | head -1) (.cg-env)"
  else warn "trivy: not found — ./run.sh will install v$TRIVY_VERSION locally"; fi
}

cmd_clean() {
  step "Removing .cg-env, dist/, web/dist/ and node_modules/"
  rm -rf "$ENV_DIR" "$ROOT/dist" "$ROOT/web/dist" "$ROOT/node_modules" "$ROOT/web/node_modules"
  ok "clean"
}

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

case "${1:-start}" in
  start)            cmd_start ;;
  docker)           cmd_docker ;;
  test)             cmd_test ;;
  oom-check)        shift; cmd_oom_check "${1:-600}" ;;
  doctor)           cmd_doctor ;;
  clean)            cmd_clean ;;
  -h|--help|help)   usage ;;
  *)                usage; exit 1 ;;
esac
