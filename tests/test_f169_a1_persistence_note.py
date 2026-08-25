"""F-169 — A1 said nothing about what is already in the identity files.

OpenClaw injects the bootstrap/identity files into context every turn, so a directive
already written into one keeps loading no matter what the config says afterwards. Palo
Alto call persistent memory an accelerant on the trifecta; Zenity demonstrated the whole
chain against OpenClaw — indirect injection, then a scheduled task rewriting SOUL.md every
two minutes — under the framing "no software vulnerability is required".

The gap this closes is the one a user actually hits: break a leg, watch A1 flip to PASS,
and be told nothing about the directive still sitting in SOUL.md.

Deliberately NOT a fourth leg — the reasoning is recorded in `_persistence_note`'s
docstring and in F-169, so it is not re-litigated here.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.checks import _persistence_note
from clawseccheck.collector import BOOTSTRAP_FILES, Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_EXEC_CFG = {"tools": {"exec": {"mode": "on"}}}
_MARKER = "load into context"


def _ctx(bootstrap: dict, config: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = config
    c.bootstrap = bootstrap
    return c


# ------------------------------------------------------------------ the note fires
def test_the_note_fires_when_identity_files_and_a_write_path_are_both_present():
    note = _persistence_note(_ctx({"workspace/SOUL.md": "x"}, _EXEC_CFG))
    assert _MARKER in note
    assert "SOUL.md" in note


def test_it_names_the_content_ring_not_more_config():
    """The whole point: config hardening cannot clear a content finding."""
    note = _persistence_note(_ctx({"workspace/SOUL.md": "x"}, _EXEC_CFG))
    assert "B6" in note and "B161" in note
    assert "CONTENT" in note


def test_bootstrap_keys_are_paths_not_bare_filenames():
    """The first version of this note compared `ctx.bootstrap` keys against
    BOOTSTRAP_FILES directly and therefore never fired on ANY home, including the real
    one — the keys are paths like "workspace/AGENTS.md"."""
    assert "SOUL.md" in BOOTSTRAP_FILES
    assert _MARKER in _persistence_note(_ctx({"workspace-home/SOUL.md": "x"}, _EXEC_CFG))


def test_an_explicit_write_tool_also_counts_as_a_write_path():
    cfg = {"tools": {"allow": ["write", "edit"]}}
    assert _MARKER in _persistence_note(_ctx({"workspace/SOUL.md": "x"}, cfg))


# ------------------------------------------------------------------ and stays silent
def test_silent_with_no_identity_files():
    assert _persistence_note(_ctx({}, _EXEC_CFG)) == ""


def test_silent_with_no_write_path():
    assert _persistence_note(_ctx({"workspace/SOUL.md": "x"}, {})) == ""


def test_a_non_bootstrap_file_does_not_trigger_it():
    assert _persistence_note(_ctx({"workspace/notes.md": "x"}, _EXEC_CFG)) == ""


# ------------------------------------------------------------------ end to end
def test_it_reaches_a1s_detail_on_a_real_fixture():
    _, findings, _ = audit(FIXTURES / "home_vuln", include_native=False)
    a1 = [f for f in findings if f.id == "A1"][0]
    assert _MARKER in a1.detail


def test_it_appears_even_when_a1_passes():
    """The reason this exists at all.

    A user who breaks a leg sees A1 go PASS; the content already in the identity files is
    untouched, and before this they were told nothing about it. A note that only rode
    along on FAIL would miss exactly the person who needs it.
    """
    _, findings, _ = audit(FIXTURES / "home_safe", include_native=False)
    a1 = [f for f in findings if f.id == "A1"][0]
    assert a1.status == "PASS"
    assert _MARKER in a1.detail


def test_it_changes_no_verdict_anywhere():
    """Acceptance criterion, checked here on two fixtures and measured across the whole
    corpus when this landed: 646 fixtures, zero status sets moved, zero scores moved.
    Only A1's detail text changed, on the 11 fixtures that have both preconditions."""
    for name, expected in (("home_vuln", "FAIL"), ("home_safe", "PASS")):
        _, findings, score = audit(FIXTURES / name, include_native=False)
        a1 = [f for f in findings if f.id == "A1"][0]
        assert a1.status == expected
        assert "Active legs" in a1.detail
        assert "/3:" in a1.detail, "leg count or threshold moved"


def test_the_note_never_claims_a_fourth_leg():
    """Printing '4/4' would redefine a named three-part concept in our own output."""
    _, findings, _ = audit(FIXTURES / "home_vuln", include_native=False)
    a1 = [f for f in findings if f.id == "A1"][0]
    assert "4/4" not in a1.detail
    assert "/4" not in a1.detail
