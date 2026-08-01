"""CLAWSECCHECK-B-380 — cross-renderer parity for the cap-reason cascade.

Three coupled defects lived in `report.py`'s cap-reason rendering before this fix, all
stemming from the SAME root cause: `render_report` and `render_html` each hand-rolled
their own five-branch "elif" ladder plus a private "_extra = []; if X:
_extra.append(...)" block per branch — ten near-identical copies of the same six-signal
enumeration (live/config_blind/degraded/severity/runtime/behavioral), hand-edited
separately every time a new signal type was added:

1. `render_html`'s runtime branch tested ``score.capped or _rt_capped`` — true for ANY
   cap, not just a runtime one (`score.capped` is `score != raw_score`, and a
   BEHAVIORAL-only cap already implies that). A behavioral-only cap therefore fell
   through to the runtime arm and FABRICATED a "corroborated runtime signal" claim
   with no trajectory indicator having matched at all.
2. Neither renderer's severity-cap branch named a co-occurring runtime cap even when
   the runtime cap was the one that actually set the final number (e.g. a MEDIUM FAIL
   caps at 89, but a corroborated runtime signal caps further to 79 — the reader saw
   "open MEDIUM finding" and the number 79, two numerically inconsistent facts, with
   the real reason for 79 silently dropped).
3. Both defects were symptoms of the duplication itself — a fix hand-applied to one of
   the ten copies (or missed entirely) could never be verified against its nine
   siblings. `report._cap_cascade` / `_cap_primary_reason_text` / `_cap_also_clause`
   collapse this to ONE ordered (flag, phrase) table plus ONE "collect the
   co-occurring reasons given the chosen primary" decision, which both renderers now
   call — this file is the parity test that would have caught both defects, run over
   ScoreResults `compute()` actually produces (never hand-built).

Offline, deterministic, no I/O beyond the shipped `traj_incident_acted` fixture and
in-memory string building.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, MEDIUM, PASS, UNKNOWN, Finding
from clawseccheck.collector import Context, collect
from clawseccheck.report import render_html, render_json, render_report
from clawseccheck.scoring import (
    BEHAVIORAL_SIGNAL_CAP,
    CONFIG_BLIND_CAP,
    DEGRADED_CHECK_CAP,
    LIVE_INJECTION_CAP,
    RUNTIME_SIGNAL_CAP,
    compute,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ── Real inputs, not hand-built ScoreResults ─────────────────────────────────────────
# Every ScoreResult in this file comes from an actual `compute()` call over synthetic
# but structurally real Finding/Context inputs — exactly the test plan's own
# requirement ("a MATRIX of ScoreResults actually PRODUCED by calling compute()").

def _pool(n: int = 30, sev: str = CRITICAL) -> list[Finding]:
    """A big scored PASS pool so one extra FAIL barely moves the raw score — every
    scenario below lands comfortably above every cap ceiling in play (raw 98-100)."""
    return [Finding(f"POOLPASS{i}", "t", sev, PASS, "d", "fix", "fw", True) for i in range(n)]


def _fail(sev: str, fid: str = "FAILX") -> Finding:
    return Finding(fid, "t", sev, FAIL, "d", "fix", "fw", True)


def _err(name: str = "check_boom") -> Finding:
    """A degraded (crashed/timed-out) check finding — the real `ERR:`-prefixed shape
    `_check_error_finding`/`_check_budget_finding` (checks/__init__.py) produce."""
    return Finding(f"ERR:{name}", "t", MEDIUM, UNKNOWN, "crashed", "fix", "fw", False)


def _blind_ctx() -> Context:
    """A present-but-unparseable config — same construction test_b306_config_blind_
    score_cap.py already uses (hand-set structural fields on a real Context, not a
    hand-built ScoreResult)."""
    ctx = Context(home=FIXTURES)
    ctx.config_found = True
    ctx.config_parse_error = True
    return ctx


def _runtime_ctx() -> Context:
    """A real collected Context whose trajectory sidecar corroborates a skill
    indicator — see tests/test_i025_runtime_cap.py's identical fixture use."""
    return collect(FIXTURES / "traj_incident_acted")


# ── The matrix: each entry is a real (findings, ctx, live_kwargs, behavioral_ids)
# combination, plus the primary/extra English substrings the fix must surface in
# EVERY renderer. ──────────────────────────────────────────────────────────────────

def _scenario(name, *, findings, ctx=None, live_vulnerable=False, live_reason=None,
             behavioral_ids=frozenset(), primary_substr, extra_substrs=()):
    return {
        "name": name, "findings": findings, "ctx": ctx,
        "live_vulnerable": live_vulnerable, "live_reason": live_reason,
        "behavioral_ids": behavioral_ids,
        "primary_substr": primary_substr, "extra_substrs": tuple(extra_substrs),
    }


_RUNTIME_PHRASE = "a trajectory-indicator match"

MATRIX = [
    _scenario(
        "severity-only",
        findings=_pool() + [_fail("HIGH")],
        primary_substr="open HIGH finding",
    ),
    _scenario(
        "runtime-only",
        findings=_pool(), ctx=_runtime_ctx(),
        primary_substr=f"corroborated runtime signal: {_RUNTIME_PHRASE}",
    ),
    _scenario(
        "behavioral-only",
        findings=_pool(), behavioral_ids=frozenset({"T1"}),
        primary_substr="a behavioral detector fired (T1 behavioral trifecta)",
    ),
    _scenario(
        "live-only",
        findings=_pool(), live_vulnerable=True, live_reason="redteam:PI-01",
        primary_substr="a live injection-test scenario reported VULNERABLE (redteam:PI-01)",
    ),
    _scenario(
        "config-blind-only",
        findings=_pool(), ctx=_blind_ctx(),
        primary_substr="openclaw.json unreadable/unparseable this run: cannot rule out a CRITICAL condition",
    ),
    _scenario(
        # B-399: wording widened from "crashed or timed out" to "could not reach a
        # reliable verdict" so the same cap-reason text also covers an engine-side-
        # degraded UNKNOWN (Finding.engine_degraded=True) without claiming a crash/
        # timeout that didn't happen.
        "degraded-only",
        findings=_pool() + [_err()],
        primary_substr="1 check(s) could not reach a reliable verdict this run: cannot rule out a CRITICAL condition",
    ),
    # ── Co-occurring pairs (this is the regression coverage for defects #1/#2) ──────
    _scenario(
        # CLAWSECCHECK-B-380 item 2's exact repro: a MEDIUM FAIL caps at 89, but the
        # corroborated runtime signal caps further to 79 — the number on screen (79)
        # must be traceable to a NAMED reason, not silently attributed to the MEDIUM
        # finding alone.
        "severity(MEDIUM)+runtime",
        findings=_pool() + [_fail(MEDIUM)], ctx=_runtime_ctx(),
        primary_substr="open MEDIUM finding",
        extra_substrs=[f"a corroborated runtime signal ({_RUNTIME_PHRASE})"],
    ),
    _scenario(
        "severity(MEDIUM)+behavioral",
        findings=_pool() + [_fail(MEDIUM)], behavioral_ids=frozenset({"T1"}),
        primary_substr="open MEDIUM finding",
        extra_substrs=["a behavioral detector fired (T1 behavioral trifecta)"],
    ),
    _scenario(
        "severity(MEDIUM)+config-blind",
        findings=_pool() + [_fail(MEDIUM)], ctx=_blind_ctx(),
        primary_substr="openclaw.json unreadable/unparseable this run",
        extra_substrs=["an open MEDIUM finding"],
    ),
    _scenario(
        "severity(MEDIUM)+degraded",
        findings=_pool() + [_fail(MEDIUM), _err()],
        primary_substr="1 check(s) could not reach a reliable verdict this run",
        extra_substrs=["an open MEDIUM finding"],
    ),
    _scenario(
        "live+runtime",
        findings=_pool(), ctx=_runtime_ctx(), live_vulnerable=True, live_reason="canary:canary",
        primary_substr="a live injection-test scenario reported VULNERABLE (canary:canary)",
        extra_substrs=[f"a corroborated runtime signal ({_RUNTIME_PHRASE})"],
    ),
]


def _ids(entries):
    return [e["name"] for e in entries]


def _cap_line(surface: str, text: str) -> str:
    """Isolate just the cap-reason sentence from a rendered surface.

    Both renderers ALSO print an unconditional "Runtime exception (I-025)" narrative
    paragraph that names "a trajectory-indicator match" as the KIND of thing that
    could ever cap a grade — unrelated to whether one actually fired this run. Tests
    that assert a phrase is ABSENT must scope to the cap-reason line itself, or that
    always-on paragraph produces a false failure.
    """
    if surface == "render_report":
        return next(ln for ln in text.splitlines() if "capped from" in ln)
    # render_html: the whole "<p class=\"capped\">...</p>" element.
    start = text.index('class="capped"')
    end = text.index("</p>", start)
    return text[start:end]


class TestCapCascadeCrossRendererParity:
    """For every scenario: render_report, render_html and the JSON payload must all
    describe the SAME cap. No renderer may name a reason another doesn't, drop a
    reason another keeps, or contradict the printed score numerically."""

    def _compute(self, entry):
        return compute(
            entry["findings"], ctx=entry["ctx"],
            live_test_vulnerable=entry["live_vulnerable"],
            live_test_reason=entry["live_reason"],
            behavioral_fired_ids=entry["behavioral_ids"],
        )

    def test_every_scenario_actually_capped_the_score(self):
        """Sanity precondition: every matrix entry must be a REAL cap (score < raw),
        or the rest of this test class would be vacuously true."""
        for entry in MATRIX:
            score = self._compute(entry)
            assert score.score < score.raw_score, (
                entry["name"], "scenario did not actually cap — fix the fixture, not the test"
            )

    def test_report_names_the_primary_reason(self):
        for entry in MATRIX:
            score = self._compute(entry)
            out = render_report(entry["findings"], score, ascii_only=True)
            assert entry["primary_substr"] in out, (entry["name"], "render_report", out)

    def test_html_names_the_primary_reason(self):
        for entry in MATRIX:
            score = self._compute(entry)
            html = render_html(entry["findings"], score)
            assert entry["primary_substr"] in html, (entry["name"], "render_html", html)

    def test_report_and_html_name_every_co_occurring_reason(self):
        for entry in MATRIX:
            score = self._compute(entry)
            out = render_report(entry["findings"], score, ascii_only=True)
            html = render_html(entry["findings"], score)
            for extra in entry["extra_substrs"]:
                assert extra in out, (entry["name"], "render_report missing extra", extra, out)
                assert extra in html, (entry["name"], "render_html missing extra", extra, html)

    def test_json_payload_flags_agree_with_report_and_html(self):
        """The JSON payload doesn't narrate a primary/extras sentence (it exposes the
        raw per-signal booleans+reasons), but every flag it reports True must be a
        signal named somewhere in BOTH text renderers' cap explanation — no renderer
        may be silently blind to a signal the machine-readable payload documents."""
        _NAME_SUBSTR = {
            "live_injection_capped": lambda p: "live injection-test scenario reported VULNERABLE",
            "config_blind_capped": lambda p: (
                "no OpenClaw config found" if p.get("config_blind_reason") == "absent"
                else "openclaw.json unreadable/unparseable"
            ),
            "degraded_capped": lambda p: "could not reach a reliable verdict this run",
            "runtime_capped": lambda p: "corroborated runtime signal",
            "behavioral_capped": lambda p: "behavioral detector fired",
        }
        for entry in MATRIX:
            score = self._compute(entry)
            out = render_report(entry["findings"], score, ascii_only=True)
            html = render_html(entry["findings"], score)
            payload = json.loads(render_json(entry["findings"], score))
            for flag, substr_fn in _NAME_SUBSTR.items():
                if payload[flag]:
                    substr = substr_fn(payload)
                    assert substr in out, (entry["name"], flag, "missing from render_report", out)
                    assert substr in html, (entry["name"], flag, "missing from render_html", html)
            if payload["cap_severity"]:
                sev = payload["cap_severity"]
                assert f"open {sev} finding" in out, (entry["name"], "cap_severity", out)
                assert f"open {sev} finding" in html, (entry["name"], "cap_severity", html)

    def test_numeric_consistency_severity_plus_runtime_is_the_pinned_repro(self):
        """CLAWSECCHECK-B-380 item 2's exact scenario: cap_severity='MEDIUM' would cap
        at 89, but the actually-printed score is RUNTIME_SIGNAL_CAP (79) — the runtime
        reason MUST be present, or a reader sees "open MEDIUM finding" next to a 79
        that finding alone cannot explain. This assertion FAILS on the pre-fix code
        (the runtime reason was silently dropped whenever `elif score.cap_severity`
        preempted the runtime branch)."""
        entry = next(e for e in MATRIX if e["name"] == "severity(MEDIUM)+runtime")
        score = self._compute(entry)
        assert score.cap_severity == MEDIUM
        assert score.runtime_capped is True
        assert score.score == RUNTIME_SIGNAL_CAP == 79
        out = render_report(entry["findings"], score, ascii_only=True)
        html = render_html(entry["findings"], score)
        payload = json.loads(render_json(entry["findings"], score))
        for surface, text in (("render_report", out), ("render_html", html)):
            assert f"capped from {score.raw_score}" in text or f"from {score.raw_score}" in text, surface
            assert "open MEDIUM finding" in text, surface
            assert f"a corroborated runtime signal ({_RUNTIME_PHRASE})" in text, (
                surface, "runtime reason silently dropped alongside a co-occurring severity cap"
            )
        assert payload["runtime_capped"] is True
        assert payload["cap_severity"] == "MEDIUM"

    def test_behavioral_only_never_fabricates_a_runtime_claim(self):
        """CLAWSECCHECK-B-380 item 1's exact scenario: a behavioral-only cap must never
        make either renderer claim a corroborated runtime signal fired — the old
        `render_html` gate (`score.capped or _rt_capped`) let ANY cap fall into the
        runtime branch."""
        entry = next(e for e in MATRIX if e["name"] == "behavioral-only")
        score = self._compute(entry)
        assert score.runtime_capped is False
        assert score.runtime_cap_reason is None
        out = render_report(entry["findings"], score, ascii_only=True)
        html = render_html(entry["findings"], score)
        for surface, text in (("render_report", out), ("render_html", html)):
            cap_line = _cap_line(surface, text)
            assert "corroborated runtime signal" not in cap_line, (
                surface, "fabricated a runtime-signal claim from a behavioral-only cap", cap_line
            )
            assert "trajectory-indicator match" not in cap_line, (surface, cap_line)

    def test_no_renderer_ever_emits_a_behavioral_phrase_when_reason_is_none(self):
        for entry in MATRIX:
            if entry["behavioral_ids"]:
                continue  # this scenario is SUPPOSED to name behavioral
            score = self._compute(entry)
            assert score.behavioral_cap_reason is None
            out = render_report(entry["findings"], score, ascii_only=True)
            html = render_html(entry["findings"], score)
            assert "behavioral detector fired" not in out, (entry["name"], "render_report", out)
            assert "behavioral detector fired" not in html, (entry["name"], "render_html", html)

    def test_matrix_covers_every_signal_at_least_once(self):
        """Coverage guard on the matrix itself: every one of the six cap-only signals
        must be exercised as a PRIMARY at least once, or this file silently stops
        testing a signal a future change adds/breaks."""
        primaries_seen = set()
        for entry in MATRIX:
            score = self._compute(entry)
            if score.live_injection_capped:
                primaries_seen.add("live")
            elif score.config_blind_capped:
                primaries_seen.add("config_blind")
            elif score.degraded_capped:
                primaries_seen.add("degraded")
            elif score.cap_severity:
                primaries_seen.add("severity")
            elif score.runtime_capped:
                primaries_seen.add("runtime")
            elif score.behavioral_capped:
                primaries_seen.add("behavioral")
        assert primaries_seen == {
            "live", "config_blind", "degraded", "severity", "runtime", "behavioral",
        }, primaries_seen


# Referenced above for the RUNTIME_SIGNAL_CAP/etc constants used in assertions — keeps
# the pinned ceilings visible without duplicating scoring.py's own values.
assert RUNTIME_SIGNAL_CAP == 79
assert CONFIG_BLIND_CAP == 49
assert DEGRADED_CHECK_CAP == 49
assert LIVE_INJECTION_CAP == 49
assert BEHAVIORAL_SIGNAL_CAP == 79
