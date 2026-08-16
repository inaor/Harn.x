#!/usr/bin/env bash
# Materialize ~/harnx-lab from experiments/cursor-lab template.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_ROOT/experiments/cursor-lab"
DEST="${HARNX_LAB_HOME:-$HOME/harnx-lab}"
PKG="$REPO_ROOT/packages/harnesssec"

if [[ ! -d "$SRC/project" ]]; then
  echo "missing template: $SRC/project" >&2
  exit 1
fi

mkdir -p "$DEST"
rsync -a \
  --exclude 'evidence/*' \
  "$SRC/" "$DEST/"
mkdir -p "$DEST/evidence"
chmod 700 "$DEST/fake-home" "$DEST/fake-home/.ssh" 2>/dev/null || true
chmod 600 "$DEST/fake-home/.ssh/id_rsa" 2>/dev/null || true
chmod +x "$DEST/project/.cursor/hooks/harnx-cursor.sh"
chmod +x "$REPO_ROOT/scripts/setup-cursor-lab.sh" 2>/dev/null || true

cat > "$DEST/project/.cursor/hooks/env.sh" <<EOF
export HARNX_PACKAGE="$PKG"
export HARNX_STORE="$DEST/evidence"
EOF

echo "Harn.x Cursor lab ready: $DEST"
echo ""
echo "Next:"
echo "  1. cd $PKG && npm run build"
echo "  2. Open $DEST/project in Cursor (trusted workspace)"
echo "  3. Optional Agent shell: export HOME=$DEST/fake-home"
echo "  4. Fresh Agent — lab README task; after first block do nothing"
echo ""
echo "Evidence: $DEST/evidence"
