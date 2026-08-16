#!/usr/bin/env bash
# Harn.x Cursor hook bridge — lab project only.
# stdin: Cursor hook JSON · stdout: permission JSON · exit 2 = deny
#
# Evidence: $HARNX_EVIDENCE_ROOT/sessions/<conversation_id>/
# Never deletes evidence.
#
# CRITICAL:
# 1) Run Node with cwd = HARNX_PACKAGE so dist/ (and package-local tsx) resolve.
# 2) Do NOT use `printf | exec node` — exec in a pipeline does not replace this
#    shell, so ALLOW (exit 0) falls through into later deny paths.
set -euo pipefail

HOOK_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "$HOOK_DIR/env.sh" ]]; then
  # shellcheck disable=SC1091
  source "$HOOK_DIR/env.sh"
fi

PKG="${HARNX_PACKAGE:-}"
if [[ -z "$PKG" || ! -d "$PKG" ]]; then
  echo '{"permission":"deny","user_message":"Harn.x lab misconfigured: HARNX_PACKAGE missing","agent_message":"Harn.x lab misconfigured: HARNX_PACKAGE missing"}'
  exit 2
fi

EVIDENCE_ROOT="${HARNX_EVIDENCE_ROOT:-}"
if [[ -z "$EVIDENCE_ROOT" ]]; then
  EVIDENCE_ROOT="$(cd "$HOOK_DIR/../../.." && pwd)/evidence"
fi
mkdir -p "$EVIDENCE_ROOT/sessions"

INPUT="$(cat)"
CID="$(
  printf '%s' "$INPUT" | python3 -c '
import json, sys, re
try:
    d = json.load(sys.stdin)
except Exception:
    print("unknown"); raise SystemExit(0)
cid = d.get("conversation_id") or d.get("session_id") or "unknown"
cid = re.sub(r"[^A-Za-z0-9._-]+", "_", str(cid))[:120] or "unknown"
print(cid)
'
)"
STORE="$EVIDENCE_ROOT/sessions/$CID"
mkdir -p "$STORE"
export HARNX_STORE="$STORE"

cd "$PKG"

run_node() {
  # Feed stdin without pipeline-exec so we can exit with Node's status.
  set +e
  printf '%s' "$INPUT" | node "$@"
  local ec=$?
  set -e
  return "$ec"
}

if [[ -f dist/cli/main.js ]]; then
  run_node dist/cli/main.js cursor-hook
  exit $?
fi

if [[ -d node_modules/tsx ]] || [[ -f node_modules/tsx/dist/esm/index.js ]]; then
  run_node --import tsx src/cli/main.ts cursor-hook
  exit $?
fi

echo '{"permission":"deny","user_message":"Harn.x lab misconfigured: build packages/harnesssec (npm run build) — dist/cli/main.js missing and tsx unavailable","agent_message":"Harn.x lab misconfigured: run npm run build in packages/harnesssec"}'
exit 2
