#!/usr/bin/env bash
# Harn.x Cursor hook bridge — invoked by Cursor Agent hooks.
# stdin: Cursor hook JSON · stdout: permission JSON · exit 2 = deny
set -euo pipefail

HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "$HOOK_DIR/env.sh" ]]; then
  # shellcheck disable=SC1091
  source "$HOOK_DIR/env.sh"
fi

PKG="${HARNX_PACKAGE:-}"
if [[ -z "$PKG" ]]; then
  CAND="$(cd "$HOOK_DIR/../../.." && pwd)"
  for _ in 1 2 3 4 5 6 7 8; do
    if [[ -d "$CAND/packages/harnesssec" ]]; then
      PKG="$CAND/packages/harnesssec"
      break
    fi
    CAND="$(dirname "$CAND")"
  done
fi

if [[ -z "${PKG}" || ! -d "${PKG}" ]]; then
  echo '{"permission":"deny","user_message":"Harn.x: HARNX_PACKAGE not set / packages/harnesssec not found","agent_message":"Harn.x misconfigured"}'
  exit 2
fi

STORE="${HARNX_STORE:-${HARNESSSEC_STORE:-}}"
if [[ -z "$STORE" ]]; then
  STORE="$(cd "$HOOK_DIR/../../.." && pwd)/../evidence"
  mkdir -p "$STORE"
fi
export HARNX_STORE="$STORE"

if [[ -f "$PKG/dist/cli/main.js" ]]; then
  exec node "$PKG/dist/cli/main.js" cursor-hook
fi
exec node --import tsx "$PKG/src/cli/main.ts" cursor-hook
