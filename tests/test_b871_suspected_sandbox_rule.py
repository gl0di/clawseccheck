"""B-871: the sandbox stop rule was a POST-condition — nothing told an agent that merely
*suspects* sandboxing, before it has run anything this session, to run the bare default
audit once anyway.

Incident (2026-09-20): an OpenClaw agent, asked to audit the user's setup, believed it was
sandboxed and never ran the tool at all — it wrote its own paraphrase of the sandbox
situation instead. Measured: the sandbox's `~/.clawseccheck/` was last written 2026-09-15,
and even a bare run appends a `graded:false` history row, so no run happened that day.

`SKILL.md`'s Step 2 stop rule only fired on "a run this session already reported ... this
session is sandboxed" — a condition that presupposes a run already happened. An agent
reasoning ahead of its first run had no clause pointing it at the one cheap, read-only
command that would have produced the authoritative answer, so it fell back on prose
resembling the tool's own B-776 sandbox sentence without ever triggering the detector.

This file pins the added "Suspected-sandbox rule" paragraph so it cannot quietly rot back
into a doc that only covers the post-run case: it must (a) exist in these exact load-bearing
phrases, (b) tell the agent to run the bare default audit once anyway even under suspicion,
(c) forbid asserting sandboxing from priors, and (d) still precede the original post-run
stop rule in document order, since that rule's own text is worded to run "next".

Offline, reads SKILL.md only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SKILL_TEXT = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
_FLAT = " ".join(_SKILL_TEXT.split())


def test_suspected_sandbox_rule_exists():
    """The new clause's heading is present at all — the core B-871 fix."""
    assert "Suspected-sandbox rule" in _FLAT


def test_suspected_sandbox_rule_tells_the_agent_to_run_it_anyway():
    """The whole point: suspicion alone must not license skipping the one cheap,
    read-only, authoritative command."""
    assert "run the bare default audit ONCE anyway" in _FLAT
    assert "even if you suspect sandboxing" in _FLAT
    assert "python3 {baseDir}/audit.py" in _FLAT


def test_suspected_sandbox_rule_forbids_asserting_from_priors():
    """An agent must relay the run's own wording, never its own paraphrase of what it
    expects the sandbox situation to be."""
    assert "Never assert sandboxing from priors" in _FLAT
    assert "never write your own paraphrase of it" in _FLAT


def test_suspected_sandbox_rule_precedes_the_post_run_stop_rule():
    """Document order matters here: the pre-run rule must be checked before the
    post-run stop rule, and the post-run rule's own wording ('checked next') only
    makes sense if it still follows this one."""
    pre_idx = _FLAT.index("Suspected-sandbox rule")
    post_idx = _FLAT.index("Stop rule — checked next")
    assert pre_idx < post_idx


def test_post_run_stop_rule_still_covers_the_original_two_conditions():
    """B-871 must not regress the original B-306/B-776 post-run behaviour it sits next
    to: a prior run reporting no config, or a prior run reporting sandboxing, still
    stops the deeper flow."""
    assert "already reported no OpenClaw config found" in _FLAT
    assert "reported that this session is sandboxed" in _FLAT
    assert "STOP here" in _FLAT
