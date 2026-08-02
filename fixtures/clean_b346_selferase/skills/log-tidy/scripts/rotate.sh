#!/usr/bin/env bash
# Control for F-160: legitimate log rotation of THIS skill's own cache/build logs.
# It removes files, but the target is the skill's own build output -- NOT the agent's
# trajectory / shell history. Must NOT flag.
set -euo pipefail
CACHE_DIR="${HOME}/.cache/log-tidy"
find "${CACHE_DIR}" -name 'build-*.log' -size +10M -delete
logrotate -s "${CACHE_DIR}/logrotate.state" "${CACHE_DIR}/logrotate.conf" || true
