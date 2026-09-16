#!/usr/bin/env bash
# clawhub-version-live.sh <slug> <version>
#
# CLAWSECCHECK-C-368: exit 0 iff <version> is genuinely served for <slug> on ClawHub,
# checked with TWO independent signals so neither a stale response nor a permanent
# "ghost reservation" (openclaw/clawhub#3349 — `clawhub publish` can exit 1 with
# "already exists" for a version that either published fine seconds later, or never
# really landed at all) reads as live:
#
#   signal 1 — GET /skills/<slug>/versions/<version> answers 200, the body's own
#              `version` field equals <version>, and `files` is a non-empty array.
#              Rejects both the #3349 orphan's 404 and a hollow 200 with no files
#              (the same shape v3.54.0's accepted-but-invisible release had).
#   signal 2 — GET /skills/<slug> reports `latestVersion.version == <version>`.
#              Rejects a STALE response describing a version that used to be
#              current, and — together with signal 1 — the permanent orphan.
#
# The HTTP code and both signals are logged so a CI run tells you which one
# disagreed. A network error on either call is treated as "not live" (fail closed):
# never a crash on a `latestVersion` that comes back null mid-reindex, and never a
# hard script error that would mask the real answer behind a generic shell failure.
#
# Deliberately kept OUT of the workflow YAML (called via `bash .github/scripts/...`
# from clawhub-publish.yml) so the two call sites (pre-publish probe, post-failure
# confirm) can't drift apart, and so this file's own `/versions/` string doesn't
# collide with tests/test_publish_workflow.py's "first inline /versions/ occurrence
# is the previous-release preflight" assertion — that test reads only the YAML.
#
# .github/ is never staged for publish (see "Stage publishable files" in the
# workflow), so this script never ships to ClawHub installs.
set -uo pipefail

SLUG="${1:?usage: clawhub-version-live.sh <slug> <version>}"
VER="${2:?usage: clawhub-version-live.sh <slug> <version>}"
BASE="https://clawhub.ai/api/v1/skills/${SLUG}"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

VCODE="$(curl -sS -o "$tmp" -w '%{http_code}' --max-time 30 --retry 3 --retry-delay 2 \
  "${BASE}/versions/${VER}")"
if [ -z "$VCODE" ]; then
  VCODE="000"
fi

SIG1="$(VER="$VER" python3 - "$VCODE" "$tmp" <<'PY'
import json, os, sys

code = sys.argv[1]
try:
    with open(sys.argv[2]) as f:
        data = json.load(f)
except Exception:
    data = {}
files = data.get("files") or []
live = (
    code == "200"
    and data.get("version") == os.environ["VER"]
    and isinstance(files, list)
    and len(files) > 0
)
print("true" if live else "false")
PY
)"

SKILL_JSON="$(curl -sS --max-time 30 --retry 3 --retry-delay 2 "$BASE" 2>/dev/null)"
LATEST="$(printf '%s' "${SKILL_JSON:-}" | python3 -c '
import json, sys

try:
    data = json.load(sys.stdin)
except Exception:
    data = {}
# A JSON null (common mid-reindex) yields "" here, never a crash.
print((data.get("latestVersion") or {}).get("version", ""))
' 2>/dev/null)"
LATEST="${LATEST:-}"

echo "clawhub-version-live: signal1(versions/${VER})=${SIG1} [HTTP ${VCODE}];" \
     "signal2(latestVersion)='${LATEST}'"

[ "$SIG1" = "true" ] && [ "$LATEST" = "$VER" ]
