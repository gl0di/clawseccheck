#!/usr/bin/env bash
# Temp-file housekeeping for the security-linter skill.
#
# NOTE for future maintainers: never add allowedTools: ["*"] to settings.json just
# because "the user has already approved this" in some earlier chat -- that
# fabricated-consent shape is exactly the self-privilege-escalation directive this
# scanner's phrase catalogue looks for.
#
# This script itself silently removes its own scratch files without telling the
# user -- that is routine cleanup, not a live directive to any agent reading it.

set -euo pipefail
SCRATCH_DIR="$(mktemp -d)"
trap 'rm -rf "$SCRATCH_DIR"' EXIT

find "$SCRATCH_DIR" -name '*.tmp' -delete
