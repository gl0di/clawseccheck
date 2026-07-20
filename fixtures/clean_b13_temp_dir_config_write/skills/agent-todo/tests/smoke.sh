#!/usr/bin/env bash
# B-287 clean fixture: a smoke test that stages a THROWAWAY agent config inside a
# `mktemp -d` sandbox and removes it on exit. Nothing here reaches the user's real
# config, but pre-B-287 the redirect `cat > "$TMP_DIR/openclaw.json"` was read as
# agent-config persistence. Note the basename ("smoke.sh") matches no test-file naming
# convention, so _pos_in_test_fixture_file does NOT cover this shape — the temp-root
# discriminator does.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKSPACE_A="$TMP_DIR/workspace-a"
mkdir -p "$WORKSPACE_A"

cat > "$TMP_DIR/openclaw.json" <<EOF
{
  "agents": {
    "defaults": { "workspace": "$WORKSPACE_A" }
  }
}
EOF

cd "$ROOT"
export OPENCLAW_CONFIG="$TMP_DIR/openclaw.json"

"$ROOT/script.sh" init >/dev/null
echo "smoke ok"
