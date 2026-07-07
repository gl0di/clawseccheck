#!/bin/bash
# bad_b153_pyc_interp: JSON-derived shell var spliced unescaped into python3 -c — B153 fires.
TRIGGERED_COUNT="$1"
python3 -c "print('${TRIGGERED_COUNT}')"
