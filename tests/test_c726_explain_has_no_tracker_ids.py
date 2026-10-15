"""C-726 item 2: no ``--explain`` output carries an internal tracker id.

``--explain B174`` printed "(C-135 re-pass, B-238: grounded against the dist ...": the coverage
note of a finding is docs/THREAT_COVERAGE.md's own text, and the stripper only removed the
shapes it knew. This sweeps EVERY catalog id (and every RISK id through the real CLI) for a
tracker-style id or a process word, so a new row that leaks fails the build. Check ids
(B174, C015, RISK-12) have no hyphen between the letter and the digits and are never tracker ids.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import contextlib
import io
import re
from pathlib import Path

from clawseccheck.catalog import BY_ID, WARN, Finding
from clawseccheck.cli import _threat_coverage_note, main
from clawseccheck.report import render_explain

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")

_TRACKER = re.compile(r"\b[A-Z]-\d{2,4}\b")
_PROCESS_WORDS = re.compile(r"re-pass|\bround[ -]\d", re.IGNORECASE)
_PUBLIC = {"P-256", "E-164"}          # standards, not tracker ids


def _leaks(text: str) -> "list[str]":
    hits = [h for h in _TRACKER.findall(text) if h not in _PUBLIC]
    return sorted(set(hits + _PROCESS_WORDS.findall(text)))


def _explain_text(cid: str) -> str:
    meta = BY_ID[cid]
    f = Finding(id=cid, title=meta.title, severity=meta.severity, status=WARN,
                detail="d", fix="f", framework=meta.framework)
    return render_explain(f, coverage_note=_threat_coverage_note(cid))


def _cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue() + err.getvalue()


def test_the_sweep_has_something_to_find():
    """Positive control: the doc itself carries tracker ids for many ids, so an empty result
    below means the stripper works, not that the sweep looked at nothing."""
    raw = [cid for cid in BY_ID if _leaks(_threat_coverage_note(cid) or "")]
    assert len(raw) > 50, len(raw)


def test_no_catalog_id_explains_with_a_tracker_id():
    leaking = {cid: _leaks(_explain_text(cid)) for cid in sorted(BY_ID)}
    leaking = {cid: hits for cid, hits in leaking.items() if hits}
    assert not leaking, leaking


def test_explain_b174_through_the_real_cli_has_no_tracker_id():
    rc, text = _cli(["--explain", "B174", "--home", SAFE, "--no-deptree", "--no-host",
                     "--no-sockets", "--no-dist"])
    assert rc == 0
    assert "coverage note" in text, "the note is where the ids were"
    assert _leaks(text) == [], text


def test_every_risk_id_explains_with_a_message_free_of_tracker_ids():
    risk_ids = sorted(set(re.findall(r"RISK-\d+", (REPO_ROOT / "clawseccheck" / "risk.py")
                                     .read_text(encoding="utf-8"))))
    assert len(risk_ids) > 10, risk_ids
    for rid in risk_ids:
        _rc, text = _cli(["--explain", rid, "--home", SAFE])
        assert _leaks(text) == [], (rid, text)
