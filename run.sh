#!/usr/bin/env bash
# Code Guardian launcher for Linux and macOS (Windows: run.cmd or run.ps1, same commands).
#
#   ./run.sh              build and start the API + worker and the web UI (Ctrl-C stops everything)
#   ./run.sh docker       same, with docker compose (200 MB container + Trivy server sidecar)
#   ./run.sh test         lint, typecheck and test backend and frontend
#   ./run.sh oom-check    600 MB report under --max-old-space-size=150 (pass a size: ./run.sh oom-check 300)
#   ./run.sh doctor       show which tools were found or will be installed
#   ./run.sh clean        remove the local toolchain, data and build output
#
# This script only makes sure a suitable Node.js exists (system, or a pinned, checksum-verified copy downloaded into
# ./.cg-env/). Everything else is scripts/cg.mjs, shared by every OS. Requires only: bash, curl (or wget), tar, git.
# Environment: API_PORT (default 3000), WEB_PORT (default 5173), CG_FORCE_LOCAL_TOOLS=1 (ignore PATH tools).

set -euo pipefail

NODE_VERSION="24.22.1"   # LTS "Krypton"; same major version as the Docker image
NODE_MIN_MAJOR=22
NODE_MIN_MINOR=12

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_DIR="$ROOT/.cg-env"
TOOLS="$ENV_DIR/tools"

# ---------------------------------------------------------------------------------------------- output
if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'; else B= D= G= Y= R= N=; fi
step() { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '    %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

# ------------------------------------------------------------------------------------------- platform
detect_platform() { # args are passed through for the Windows hand-off
  case "$(uname -s)" in
    Linux)  OS=linux ;;
    Darwin) OS=darwin ;;
    MINGW*|MSYS*|CYGWIN*)
      # Git Bash on Windows: use Node if it is installed, otherwise the PowerShell launcher downloads it.
      if have node && node_is_suitable node; then exec node "$ROOT/scripts/cg.mjs" "$@"; fi
      die "On Windows, run: run.cmd ${1:-}   (it installs Node locally if needed)" ;;
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

# ------------------------------------------------------------------------------------------------ main
case "${1:-start}" in
  -h|--help|help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
esac
detect_platform "$@"
if [ "${1:-start}" = docker ] && ! { have node && node_is_suitable node; }; then
  # Docker needs no Node on the host.
  have docker || die "Docker is not installed. Run ./run.sh (no Docker needed) or install Docker Desktop / Docker Engine."
  cd "$ROOT" && exec docker compose up --build
fi
require_basics
ensure_node
exec node "$ROOT/scripts/cg.mjs" "$@"
