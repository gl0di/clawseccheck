#!/bin/bash
# bad_b153_bun_interp: caller-controlled URL spliced unescaped into bun -e — B153 fires.
URL="$1"
bun -e "fetch('${URL}')"
