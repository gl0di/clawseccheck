"""RISK-03 and B4 disagree on sandbox mode "non-main" - on purpose, and documented.

B4 WARNs on `agents.defaults.sandbox.mode: "non-main"` because that mode leaves the agent's
own main session on the host. RISK-03 ("no sandbox + untrusted ingress + exec/write tools")
is gated by `risk._sandbox_off`, which is true only for mode "off" or an absent mode. So a
`non-main` setup can show a B4 WARN and no RISK-03.

That is a documented limitation, not an oversight. Aligning RISK-03 with B4 was tried: it
raised a new RISK-03 on the development machine, on `fixtures/home_safe` and on 17 clean
fixtures, although a per-peer `session.dmScope` routes channel DMs into sandboxed sessions.
These tests pin the current behaviour on four configs so that any change is deliberate:

  a  non-main, dmScope main                  -> B4 WARN, no RISK-03
  g  non-main, no `tools` key at all         -> B4 WARN, no RISK-03
  c  off                                     -> B4 FAIL, RISK-03
  d  all                                     -> B4 PASS, neither

They also pin that the WARN's `fix` and the docs say so, and that B4's `detail` (hashed by
`baseline.fingerprint()`) is unchanged.

Offline, read-only, stdlib only; every config is written under pytest's tmp_path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import run_all
from clawseccheck.collector import collect
from clawseccheck.risk import risk_paths

REPO = Path(__file__).resolve().parent.parent

_BASE = {
    "channels": {"discord": {"dmPolicy": "open"}},
    "tools": {"exec": {"security": "full"}},
}


def _cfg(mode, *, base=_BASE, **extra) -> dict:
    cfg = {k: v for k, v in base.items()}
    cfg["agents"] = {"defaults": {"sandbox": {"mode": mode}}}
    cfg.update(extra)
    return cfg


_CONFIGS = {
    "a": _cfg("non-main", session={"dmScope": "main"}),
    "g": _cfg("non-main", base={"channels": {"discord": {"dmPolicy": "open"}}}),
    "c": _cfg("off"),
    "d": _cfg("all"),
}


def _audit(tmp_path: Path, cfg: dict):
    path = tmp_path / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(str(tmp_path))
    findings = run_all(ctx)
    b4 = next(f for f in findings if f.id == "B4")
    return b4, {r.id for r in risk_paths(ctx, findings)}


@pytest.mark.parametrize("name", ["a", "g"])
def test_non_main_warns_in_b4_and_does_not_open_risk03(tmp_path, name):
    b4, ids = _audit(tmp_path, _CONFIGS[name])
    assert b4.status == WARN, (name, b4.status, b4.detail)
    assert "RISK-03" not in ids, (
        f"config {name}: RISK-03 now fires for sandbox.mode 'non-main'. The documented limit "
        "(docs/USAGE.md, docs/THREAT_COVERAGE.md, B4's fix) says it does not; if this change is "
        "deliberate, update those three and tests/test_b738_remediation_actually_fixes.py."
    )


def test_mode_off_fails_b4_and_opens_risk03(tmp_path):
    b4, ids = _audit(tmp_path, _CONFIGS["c"])
    assert b4.status == FAIL, (b4.status, b4.detail)
    assert "RISK-03" in ids, ids


def test_mode_all_passes_b4_and_opens_neither(tmp_path):
    b4, ids = _audit(tmp_path, _CONFIGS["d"])
    assert b4.status == PASS, (b4.status, b4.detail)
    assert "RISK-03" not in ids, ids


def test_b4_non_main_fix_names_the_gap_and_detail_is_unchanged(tmp_path):
    b4, _ = _audit(tmp_path, _CONFIGS["a"])
    assert b4.fix.startswith(
        "Set agents.defaults.sandbox.mode to 'all' so the main session is sandboxed too"
    ), b4.fix
    assert "RISK-03" in b4.fix and "'off' or absent" in b4.fix, (
        "the WARN's fix must say that RISK-03 treats only mode 'off' or absent as no sandbox"
    )
    # `detail` is hashed by baseline.fingerprint(): byte-identical to the C-641 text.
    assert b4.detail == (
        "agents.defaults.sandbox.mode is 'non-main': only an agent's non-main sessions "
        "are sandboxed, so its own main session still runs exec tooling directly on the "
        "host, allowing a prompt-injected message in that session to run commands with "
        "host access."
    )


def test_the_per_agent_warn_carries_the_same_disclosure(tmp_path):
    cfg = {
        **_BASE,
        "agents": {
            "defaults": {"sandbox": {"mode": "all"}},
            "list": [{"id": "main", "sandbox": {"mode": "non-main"}}],
        },
    }
    b4, ids = _audit(tmp_path, cfg)
    assert b4.status == WARN, (b4.status, b4.detail)
    assert "RISK-03" in b4.fix and "'off' or absent" in b4.fix, b4.fix
    assert "RISK-03" not in ids, ids


def test_the_docs_state_the_limit():
    usage = (REPO / "docs" / "USAGE.md").read_text(encoding="utf-8")
    coverage = (REPO / "docs" / "THREAT_COVERAGE.md").read_text(encoding="utf-8")
    needle = "RISK-03 treats only sandbox mode `off` or absent as"
    assert needle in " ".join(usage.split()), "docs/USAGE.md must state the RISK-03 limit"
    assert needle in " ".join(coverage.split()), (
        "docs/THREAT_COVERAGE.md (B4 row) must state the RISK-03 limit"
    )
