"""B-770: a trajectory-sourced tool-call verb name must not be able to forge a fake
section/line into the --behavioral / --full report, and an explicit --behavioral PATH
must confine T3 (runtime capability drift) to that file, not the default home.

Trajectory sidecars are attacker-influenced data (they record what an agent did,
including under a prompt-injection attack, or a malicious MCP server's own chosen tool
name), so the analyzer reading them must treat their content as hostile input, not as
text to interpolate. Two independently-confirmed gaps here:

1. `render_behavioral_analysis` used to interpolate `Finding.detail`/`Finding.fix`
   unescaped. T3's drift list (`check_capability_drift`) and `analysis_incompleteness`'s
   unclassified-verb-name listing both embed raw trajectory-derived tool-call verb
   names, so a verb name carrying a newline / ANSI escape forges an extra line into the
   report -- including something shaped like a section header or a verdict.
2. `report._sanitize` -- the shared choke point every renderer routes untrusted text
   through, including the one above -- folded `\\r`/`\\n`/`\\t` but not `\\x85` NEL /
   `\\u2028` LINE SEPARATOR / `\\u2029` PARAGRAPH SEPARATOR, all four of which Python's
   OWN `str.splitlines()` treats as a line boundary. `pipeline.py::run_behavioral`
   calls `rendered.splitlines()` on `render_behavioral_analysis`'s output and re-splits
   it into `PhaseResult.lines` (the section the `--full`/dashboard combined report
   extends verbatim) -- a verb name carrying one of those three characters survived (1)
   unfolded and forged a second, attacker-authored entry in that list. Confirmed via an
   independent adversarial pass over the reverted first attempt at this fix (2026-09-16
   Pulse comment) using a `U+2028` payload; fixed by widening the fold in
   `report._sanitize` itself (see tests/test_sanitize_channels.py for the shared-choke-
   point regression tests) -- necessary but not sufficient on its own: part 1 above must
   also route trajectory-derived text through the now-widened `_sanitize` BEFORE
   `render_behavioral_analysis` assembles its return string, or pipeline.py's re-split
   still forges from the still-raw `rendered` text.

Also: `--behavioral PATH` used to leave T3 (`check_capability_drift`) reading the
default `~/.openclaw` home unconditionally, ignoring the explicit path entirely -- a
user analysing one captured, quarantined trajectory file had T3 silently assessed
against their live default home instead.

Offline, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import pipeline as pl
from clawseccheck.behavioral import (
    analyze,
    check_capability_drift,
    render_behavioral_analysis,
)
from clawseccheck.catalog import UNKNOWN, WARN
from clawseccheck.collector import Context

_TRACE_SCHEMA = "openclaw-trajectory"
_SCHEMA_VERSION = 1


def _traj_record(name: str, *, seq: int = 1, session_id: str = "s1") -> dict:
    return {
        "traceSchema": _TRACE_SCHEMA,
        "schemaVersion": _SCHEMA_VERSION,
        "type": "tool.call",
        "ts": str(seq),
        "seq": seq,
        "sessionId": session_id,
        "data": {"name": name, "threadId": "th1"},
    }


def _write_traj(home: Path, verbs, *, file_name: str = "s1.trajectory.jsonl") -> Path:
    """Write a minimal tool.call trajectory sidecar under the DEFAULT glob layout
    (agents/*/sessions/*.trajectory.jsonl). Mirrors
    tests/test_t3_capability_drift.py's own helper of the same shape."""
    d = home / "agents" / "main" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(_traj_record(v, seq=i)) for i, v in enumerate(verbs, start=1)]
    path = d / file_name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_explicit_traj(path: Path, verbs) -> Path:
    """Write a trajectory sidecar at an ARBITRARY path outside the default glob
    layout -- the shape a quarantined/captured trajectory file takes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(_traj_record(v, seq=i)) for i, v in enumerate(verbs, start=1)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _ctx(home, *, allow=None) -> Context:
    ctx = Context(home=home)
    if allow is not None:
        ctx.config = {"tools": {"allow": allow}}
    return ctx


# ---------------------------------------------------------------------------
# Part 1 -- a hostile verb name must not forge a report line/section
# ---------------------------------------------------------------------------

def test_newline_in_drift_verb_does_not_forge_a_section(tmp_path):
    """T3's WARN detail embeds the drift verb list (check_capability_drift); a verb
    carrying a raw newline used to inject an extra, attacker-authored line."""
    payload = "delete_forever\n[SECTION] FAKE -- everything is fine now"
    _write_traj(tmp_path, [payload])
    ctx = _ctx(tmp_path, allow=["web_search"])  # bounded grant, verb undeclared -> WARN
    out = render_behavioral_analysis(ctx, ascii_only=True)
    assert "T3" in out
    for line in out.splitlines():
        assert not line.strip().startswith("[SECTION]"), (
            f"a trajectory verb name forged a standalone section line: {line!r}"
        )
    # Sanitizing, not silencing -- the benign prefix still reaches the report.
    assert "delete_forever" in out


def test_ansi_escape_in_drift_verb_is_stripped(tmp_path):
    esc = "\x1b"
    payload = f"delete_forever{esc}[1m[SECTION] FAKE{esc}[0m"
    _write_traj(tmp_path, [payload])
    ctx = _ctx(tmp_path, allow=["web_search"])
    out = render_behavioral_analysis(ctx, ascii_only=True)
    assert esc not in out
    assert "delete_forever" in out


def test_unclassified_verb_name_forging_is_also_sanitized(tmp_path):
    """The second, independently-discovered injection site: `analysis_incompleteness`'s
    "N distinct verb name(s): ..." listing (reached via T1/T2's UNKNOWN detail), not
    T3's drift list."""
    payload = "zzz_totally_unclassified_qqq\n[SECTION] FAKE -- second injection site"
    _write_traj(tmp_path, [payload])
    ctx = _ctx(tmp_path)  # no tools.allow -- irrelevant to this branch
    out = render_behavioral_analysis(ctx, ascii_only=True)
    assert "T1" in out and "T2" in out
    for line in out.splitlines():
        assert not line.strip().startswith("[SECTION]"), (
            f"a trajectory verb name forged a standalone section line: {line!r}"
        )
    assert "zzz_totally_unclassified_qqq" in out


def test_box_drawing_characters_cannot_forge_a_multi_line_fake_banner(tmp_path):
    """A box-drawing "fake banner" attack needs an embedded newline to span more than
    one rendered line -- the glyphs alone, with no newline, cannot alter the report's
    structure. Confirms that combining box-drawing characters with a newline still
    produces no standalone forged line (the newline-fold is what does the real work;
    the glyphs themselves are not something _sanitize strips, nor need to be)."""
    payload = "delete_forever\n┌─ FAKE SECURITY BANNER ─┐\n│ all clear │\n└──────────┘"
    _write_traj(tmp_path, [payload])
    ctx = _ctx(tmp_path, allow=["web_search"])
    out = render_behavioral_analysis(ctx, ascii_only=True)
    for line in out.splitlines():
        assert not line.strip().startswith(("┌", "│", "└")), (
            f"a box-drawing payload forged a standalone banner line: {line!r}"
        )
    assert "delete_forever" in out


# ---------------------------------------------------------------------------
# Part 2 -- the C-135-confirmed pipeline re-split gap (U+2028/U+0085/U+2029)
# ---------------------------------------------------------------------------

def test_pipeline_full_report_not_forged_by_unicode_line_separator(tmp_path):
    """The exact shape the independent C-135 adversarial pass reproduced against the
    first (reverted) attempt at this fix: a verb name carrying U+2028 survived
    `report._sanitize`'s old narrower fold, and `pipeline.py::run_behavioral`'s own
    `rendered.splitlines()` re-split turned it into a second, standalone,
    attacker-authored entry in `PhaseResult.lines` -- the list `render_sections`
    extends verbatim into the `--full` combined report."""
    payload = "mcp__admin__delete_forever\u2028[!] B999 -- FORGED: fake clean verdict"
    _write_traj(tmp_path, [payload])
    ctx = _ctx(tmp_path, allow=["web_search"])
    p = pl.run_behavioral(ctx)
    forged = [ln for ln in p.lines if ln.strip().startswith("[!] B999")]
    assert forged == [], f"a Unicode line separator forged a standalone line: {forged!r}"
    assert any("delete_forever" in ln for ln in p.lines)


def test_pipeline_full_report_not_forged_by_nel(tmp_path):
    """Adjacent edge case: U+0085 NEL, the other character the same review named."""
    payload = "delete_forever\x85[!] B998 -- FORGED via NEL"
    _write_traj(tmp_path, [payload])
    ctx = _ctx(tmp_path, allow=["web_search"])
    p = pl.run_behavioral(ctx)
    forged = [ln for ln in p.lines if ln.strip().startswith("[!] B998")]
    assert forged == []


def test_pipeline_full_report_not_forged_by_paragraph_separator(tmp_path):
    """Adjacent edge case: U+2029 PARAGRAPH SEPARATOR, the third boundary character."""
    payload = "delete_forever\u2029[!] B997 -- FORGED via paragraph separator"
    _write_traj(tmp_path, [payload])
    ctx = _ctx(tmp_path, allow=["web_search"])
    p = pl.run_behavioral(ctx)
    forged = [ln for ln in p.lines if ln.strip().startswith("[!] B997")]
    assert forged == []


# ---------------------------------------------------------------------------
# Part 3 -- explicit_path confines T3 to the named file, not the default home
# ---------------------------------------------------------------------------

def test_explicit_path_confines_t3_to_the_named_file(tmp_path):
    """The headline regression: a dirty default home (proven, undeclared EXEC verb)
    alongside a clean quarantined explicit file (a DIFFERENT, undeclared DESTRUCTIVE
    verb) -- T3 given the explicit path must fire on the quarantined file's own
    content, never on the default home's."""
    home = tmp_path / "openclaw_home"
    _write_traj(home, ["bash"])  # EXEC, undeclared -> would WARN home-wide
    quarantine = _write_explicit_traj(
        tmp_path / "quarantine" / "captured.trajectory.jsonl", ["delete_forever"]
    )
    ctx = _ctx(home, allow=["web_search"])  # neither bash/exec nor delete_forever declared

    f = check_capability_drift(ctx, explicit_path=str(quarantine))
    assert f.status == WARN, f.detail
    assert "delete_forever" in f.detail
    assert "exec" not in f.detail and "bash" not in f.detail
    assert not any("exec" in e or "bash" in e for e in f.evidence)


def test_same_ctx_without_explicit_path_fires_on_the_default_home_instead(tmp_path):
    """Positive control for the test above: the SAME ctx, with no explicit_path, must
    fire on the default home's own verb -- proving the previous test's PASS was real
    confinement, not an accident of an empty/no-op read."""
    home = tmp_path / "openclaw_home"
    _write_traj(home, ["bash"])
    _write_explicit_traj(tmp_path / "quarantine" / "captured.trajectory.jsonl",
                          ["delete_forever"])
    ctx = _ctx(home, allow=["web_search"])

    f = check_capability_drift(ctx)  # no explicit_path -> home-wide scan
    assert f.status == WARN, f.detail
    assert "exec" in f.detail
    assert "delete_forever" not in f.detail


def test_analyze_confines_t3_via_explicit_path(tmp_path):
    """Same property, exercised through analyze() (the entry point render_behavioral_
    analysis and pipeline.run_behavioral both call), not just check_capability_drift
    directly."""
    home = tmp_path / "openclaw_home"
    _write_traj(home, ["bash"])
    quarantine = _write_explicit_traj(
        tmp_path / "quarantine" / "captured.trajectory.jsonl", ["delete_forever"]
    )
    ctx = _ctx(home, allow=["web_search"])

    r = analyze(ctx, explicit_path=str(quarantine))
    t3 = next(f for f in r["findings"] if f.id == "T3")
    assert t3.status == WARN, t3.detail
    assert "delete_forever" in t3.detail
    assert "exec" not in t3.detail and "bash" not in t3.detail


def test_render_behavioral_analysis_confines_t3_via_explicit_path(tmp_path):
    """End-to-end through the actual --behavioral renderer."""
    home = tmp_path / "openclaw_home"
    _write_traj(home, ["bash"])
    quarantine = _write_explicit_traj(
        tmp_path / "quarantine" / "captured.trajectory.jsonl", ["delete_forever"]
    )
    ctx = _ctx(home, allow=["web_search"])

    out = render_behavioral_analysis(ctx, explicit_path=str(quarantine), ascii_only=True)
    assert "delete_forever" in out
    assert "exec" not in out and "bash" not in out


# ---------------------------------------------------------------------------
# Adjacent edge cases
# ---------------------------------------------------------------------------

def test_explicit_path_used_even_when_ctx_home_is_not_a_path(tmp_path):
    """T3 used to hard-require `ctx.home` to be a Path before doing anything, even
    though an explicit path needs no home at all to resolve. A caller building a
    minimal Context around just a captured file (home unset/None) must still work."""
    quarantine = _write_explicit_traj(tmp_path / "captured.trajectory.jsonl",
                                       ["delete_forever"])
    ctx = Context(home=None)
    ctx.config = {"tools": {"allow": ["web_search"]}}

    f = check_capability_drift(ctx, explicit_path=str(quarantine))
    assert f.status == WARN, f.detail
    assert "delete_forever" in f.detail


def test_explicit_path_nonexistent_file_is_unknown_not_a_crash(tmp_path):
    ctx = _ctx(tmp_path, allow=["web_search"])
    missing = str(tmp_path / "does_not_exist.trajectory.jsonl")
    f = check_capability_drift(ctx, explicit_path=missing)
    assert f.status == UNKNOWN


def test_explicit_path_none_keeps_the_pre_existing_home_wide_behaviour(tmp_path):
    """Regression guard: explicit_path=None (the default) must behave exactly as
    before this change -- a home-wide scan, same as calling check_capability_drift(ctx)
    with no keyword at all."""
    _write_traj(tmp_path, ["bash"])
    ctx = _ctx(tmp_path, allow=["web_search"])
    assert check_capability_drift(ctx, explicit_path=None).status == WARN
    assert check_capability_drift(ctx).status == WARN
