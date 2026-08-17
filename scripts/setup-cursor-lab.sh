#!/usr/bin/env bash
# Materialize a SELF-CONTAINED Cursor lab at ~/harnx-lab.
# Does NOT open Cursor, migrate workspaces, or attach remotes to Harn.x.
#
# Evidence policy:
#   - NEVER clears evidence after a run.
#   - Clears/archives old sessions BEFORE a run only when HARNX_LAB_CLEAR_EVIDENCE=1.
#   - Default: preserve ~/harnx-lab/evidence/sessions/**
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_ROOT/experiments/cursor-lab"
DEST="${HARNX_LAB_HOME:-$HOME/harnx-lab}"
PKG="$REPO_ROOT/packages/harnesssec"

if [[ ! -d "$SRC/project" ]]; then
  echo "missing template: $SRC/project" >&2
  exit 1
fi

mkdir -p "$DEST/evidence/sessions" "$DEST/evidence/archive" "$DEST/fake-home" "$DEST/project"

# Optional pre-run archive (explicit only). Never delete without archiving.
if [[ "${HARNX_LAB_CLEAR_EVIDENCE:-}" == "1" ]]; then
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  arch="$DEST/evidence/archive/pre-run-$stamp"
  mkdir -p "$arch"
  if [[ -d "$DEST/evidence/sessions" ]] && [[ -n "$(ls -A "$DEST/evidence/sessions" 2>/dev/null || true)" ]]; then
    mv "$DEST/evidence/sessions" "$arch/sessions"
    mkdir -p "$DEST/evidence/sessions"
    echo "Archived prior sessions → $arch/sessions"
  fi
fi

# Refresh project + outside fake-home from template; do NOT touch evidence/
rsync -a --delete \
  --exclude '.git/' \
  "$SRC/project/" "$DEST/project/"
rsync -a "$SRC/fake-home/" "$DEST/fake-home/"
cp -f "$SRC/README.md" "$DEST/README.md"
# Operator protocol at lab root only (avoid smoking prompts inside Agent workspace)
cp -f "$SRC/CANONICAL_PROOF.md" "$DEST/CANONICAL_PROOF.md"
rm -f "$DEST/project/CANONICAL_PROOF.md"

mkdir -p "$DEST/evidence/sessions"
chmod 700 "$DEST/fake-home" "$DEST/fake-home/.ssh" 2>/dev/null || true
chmod 600 "$DEST/fake-home/.ssh/id_rsa" 2>/dev/null || true
chmod 700 "$DEST/project/test-home" "$DEST/project/test-home/.ssh" 2>/dev/null || true
chmod 600 "$DEST/project/test-home/.ssh/id_rsa" 2>/dev/null || true

cat > "$DEST/project/.cursor/hooks/env.sh" <<EOF
# Lab-local: Harn.x package is OUTSIDE this workspace (intentional).
export HARNX_PACKAGE="$PKG"
export HARNX_EVIDENCE_ROOT="$DEST/evidence"
# Phase 4A lab-only PolicyEngine rules — consumed ONLY by cursor-hook CLI
# (resolveCursorHookRules). Does not affect DeepSeek/OpenHands or native
# Cursor adapter defaults.
export HARNX_LAB_POLICY=phase4a
# Per-conversation HARNX_STORE is set by harnx-cursor.sh (never wiped by hooks).
EOF

cd "$DEST/project"
if [[ ! -d .git ]]; then
  git init -b main >/dev/null
  git config user.email "harnx-lab@local"
  git config user.name "harnx-lab"
fi
git remote remove origin 2>/dev/null || true
git add -A
git diff --cached --quiet || git commit -m "harnx lab baseline (local only)" >/dev/null || true

echo "Harn.x Cursor lab ready (isolated):"
echo "  workspace:           $DEST/project"
echo "  evidence:            $DEST/evidence/sessions/<conversation_id>/"
echo "  canonical fixture:   $DEST/project/protected/build-info.txt"
echo "  lab policy:          HARNX_LAB_POLICY=phase4a"
echo "  ssh scenario (sep.): $DEST/project/test-home/.ssh/id_rsa"
echo "  isolation fixture:   $DEST/fake-home/.ssh/id_rsa (not for Cursor proof)"
echo ""
echo "Open manually: File → New Window → Open Folder → $DEST/project"
echo "Do NOT migrate the Harn.x development Agent."
echo ""
echo "Pre-run evidence archive only when explicitly requested:"
echo "  HARNX_LAB_CLEAR_EVIDENCE=1 $0"
echo ""
echo "Follow: $DEST/CANONICAL_PROOF.md"
