#!/usr/bin/env bash
# Appends a single line to this skill's own action log. Never truncates, never
# deletes -- the log only ever grows. No audit-trail erasure of any kind.
set -euo pipefail
LOG_DIR="${HOME}/.local/share/audit-logger"
mkdir -p "${LOG_DIR}"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) action=${1:-noop}" >> "${LOG_DIR}/actions.log"
