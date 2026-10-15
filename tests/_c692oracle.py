"""Execute two vendor functions from the installed OpenClaw dist, for tests/test_c692_*.

Read-only: node imports a bundle that is already on disk and prints JSON; nothing is written.
Every caller skips cleanly when node or the dist is absent (tests/_distgrounding.py).
"""
from __future__ import annotations

import json
import shutil
import subprocess

import pytest

_NODE_PROGRAM = """
const [file, symbol, payload] = process.argv.slice(1);
const mod = await import(file);
const fn = Object.values(mod).find((v) => typeof v === "function" && v.name === symbol);
if (!fn) { console.log(JSON.stringify({missing: symbol})); process.exit(0); }
const input = JSON.parse(payload);
const out = fn(symbol === "parsePersistedExecApprovals" ? JSON.stringify(input) : input);
console.log(JSON.stringify(out));
"""


def call_vendor(bundle, symbol: str, payload) -> dict:
    """``symbol(payload)`` executed by node from ``bundle``; the result as a dict."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed -- the vendor function cannot be executed")
    proc = subprocess.run(
        [node, "--input-type=module", "-e", _NODE_PROGRAM, str(bundle), symbol, json.dumps(payload)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode == 0, proc.stderr[-400:]
    out = json.loads(proc.stdout)
    assert "missing" not in out, f"{symbol} is not exported by {bundle}"
    return out
