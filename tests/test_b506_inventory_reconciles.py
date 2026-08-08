"""B-506 — the summary may not contradict the body of the same report.

The report builds its subject view twice, from two different sources: the top
INVENTORY BY SUBJECT block from `build_inventory()`, and the detail sections
below by grouping findings through `SUBJECT_OF`. Nothing reconciled them, and on
the maintainer's own config they said opposite things:

    Skills (2 bundled with a plugin · 1 self-excluded) — ✅ clear
    ...
    │ Skills — 3 issue(s)
    🟠 HIGH  security.installPolicy.* operator gate + exec-hook escape flags

Five of the eight subjects were always fine: they go through `_bucket()`, which
derives status and count from the findings grouped under that subject. `skills`
and `mcp` bypassed it — they are built from per-ITEM rosters (a list of installed
skills, a list of configured servers), so a finding filed against the SUBJECT had
nowhere to land and an empty roster read as "clear". `MCP servers (none
configured)` printed above `MCP servers — 2 issue(s)` for the same reason.

This is the product's stated contract, not a nicety. The shipped docs say: *"No
mode may print 'clear' about a subject it did not look at. A summary line's status
and count must be derived from the same data as the detail section beneath it, so
the two cannot disagree."* Until this holds, that promise is not kept.

So the load-bearing test here is the **invariant over every subject**, not a
regression pin on the two that were broken — it fails for the next divergence too.

Stdlib-only, offline, writes nothing.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from clawseccheck.catalog import CATALOG, FAIL, HIGH, LOW, MEDIUM, PASS, WARN, Finding
from clawseccheck.collector import Context
from clawseccheck.report import (
    SUBJECT_LABEL,
    SUBJECT_OF,
    SUBJECT_ORDER,
    build_inventory,
    render_report,
)
from clawseccheck.scoring import compute

# A finding's subject is derived from its CATALOG entry's surface, not from the
# Finding itself — so the seeds below have to be real check ids. Picked from the
# catalog at import time rather than hardcoded, so a retagged check surfaces here as
# a changed seed instead of silently narrowing the sweep.
_IDS_FOR: dict[str, list[str]] = {}
for _meta in CATALOG:
    _subject = SUBJECT_OF.get(_meta.surface)
    if _subject:
        _IDS_FOR.setdefault(_subject, []).append(_meta.id)

# `plugins` has no surface of its own (F-163 tracks that); it cannot carry a
# subject-level finding today, so it is out of scope for this invariant.
SUBJECTS = [s for s in SUBJECT_ORDER if len(_IDS_FOR.get(s, ())) >= 2]


def _f(fid: str, severity: str, status: str) -> Finding:
    return Finding(fid, f"seeded problem {fid}", severity, status,
                   "detail", "fix", "framework")


def _seed(subject: str, n: int) -> list[Finding]:
    """`n` FAIL/WARN findings that land under `subject`, plus nothing else."""
    ids = _IDS_FOR[subject][:n]
    sev = [HIGH, MEDIUM, LOW]
    return [_f(fid, sev[i % len(sev)], FAIL if i == 0 else WARN)
            for i, fid in enumerate(ids)]


def _clean(subject: str) -> Finding:
    """One PASS finding under `subject` — present, assessed, carrying no issue."""
    return _f(_IDS_FOR[subject][0], LOW, PASS)


def _ctx() -> Context:
    return Context(home=Path("/nonexistent"))


def _render(findings):
    return render_report(findings, compute(findings), ctx=_ctx(),
                         ascii_only=False, color=False)


def _inventory_counts(text: str) -> dict:
    """Subject label -> issue count stated in the INVENTORY BY SUBJECT block.

    `None` means the line claims no issues at all (it says "clear", or names only a
    roster). That is exactly the shape that used to lie, so it is kept distinct from
    a real zero rather than folded into it.
    """
    block = text.split("== INVENTORY BY SUBJECT")[1].split("(details by subject below)")[0]
    out = {}
    for line in block.splitlines():
        if not line.startswith(" ") or line.startswith("   "):
            continue
        m = re.match(r"^ (.+?) [—-] .*?(\d+) issue\(s\)", line)
        if m:
            out[m.group(1)] = int(m.group(2))
            continue
        m = re.match(r"^ (.+?)(?: [—-].*)?$", line.rstrip())
        if m:
            out.setdefault(m.group(1), None)
    return out


def _detail_counts(text: str) -> dict:
    """Subject label -> issue count stated by the detail section header."""
    pattern = r"(?:\u2502 |\[)(.+?)(?:\])? [—-] (\d+) issue\(s\)"
    return {m.group(1): int(m.group(2)) for m in re.finditer(pattern, text)}


def _label_of(subject: str) -> str:
    """The rendered label, minus any parenthetical roster suffix."""
    return SUBJECT_LABEL[subject]


def _match(counts: dict, subject: str):
    """Look a subject up by label prefix — inventory labels carry roster suffixes
    ("Skills (2 installed)") that the detail headers do not."""
    label = _label_of(subject)
    for key, value in counts.items():
        if key == label or key.startswith(label + " ("):
            return key, value
    return None, None


# ── the invariant ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("subject", SUBJECTS)
def test_summary_and_body_agree_for_every_subject(subject):
    """A finding under any subject must be counted by that subject's summary line."""
    findings = _seed(subject, 2) + [_clean("openclaw")]
    text = _render(findings)

    inv_key, inv_count = _match(_inventory_counts(text), subject)
    det_key, det_count = _match(_detail_counts(text), subject)

    assert det_count == 2, (
        f"the detail section for {subject!r} did not render the two seeded findings; "
        f"the fixture, not the code, is wrong (found {det_key!r}={det_count})")
    assert inv_key is not None, f"{subject!r} has no line in INVENTORY BY SUBJECT"
    assert inv_count == det_count, (
        f"INVENTORY BY SUBJECT says {inv_key!r} carries {inv_count} issue(s) while its "
        f"own detail section below says {det_count}. The summary and the body of one "
        f"report must be derived from the same data — see this module's docstring.")


@pytest.mark.parametrize("subject", SUBJECTS)
def test_a_subject_carrying_a_finding_says_so_on_its_own_line(subject):
    """The contract in its plainest form, stated positively.

    Asserting merely that the word "clear" is absent is vacuous for a subject with
    an empty roster: `Skills (none installed)` never said "clear" and still reported
    nothing while carrying findings. Proven vacuous, then rewritten — what the
    invariant needs is that the line STATES the count, not that it avoids one word.
    """
    text = _render(_seed(subject, 1))
    block = text.split("== INVENTORY BY SUBJECT")[1].split("(details by subject below)")[0]
    label = _label_of(subject)
    line = next((ln for ln in block.splitlines() if ln.startswith(f" {label}")), None)
    assert line is not None, f"{subject!r} has no line in INVENTORY BY SUBJECT"
    assert "1 issue(s)" in line, (
        f"{subject!r} carries a FAIL in this report and its summary line does not say "
        f"so: {line!r}")
    assert "clear" not in line, line


def test_a_genuinely_clean_subject_still_says_clear():
    """Withholding 'clear' must not become unconditional — it is still the right
    word when the subject really carries nothing."""
    text = _render([_clean("skills")])
    block = text.split("== INVENTORY BY SUBJECT")[1].split("(details by subject below)")[0]
    skills = [ln for ln in block.splitlines() if ln.startswith(f" {SUBJECT_LABEL['skills']}")]
    assert skills, "no Skills line in the inventory"
    assert "issue(s)" not in skills[0], skills


# ── the two that were actually broken, pinned by name ────────────────────────

def test_skills_subject_finding_reaches_the_inventory_payload():
    """`skills`/`mcp` are per-item rosters; the subject bucket is a sibling key."""
    seeded = _seed("skills", 1)
    inv = build_inventory(seeded, _ctx())
    assert inv["skills_subject"]["findings"] == [seeded[0].id]
    assert inv["skills_subject"]["status"] == FAIL
    assert isinstance(inv["skills"], list), "the roster's shape must not have changed"


def test_mcp_none_configured_still_reports_its_findings():
    """The real config has no `mcp.servers` at all and still carried two findings."""
    text = _render(_seed("mcp", 2))
    line = [ln for ln in text.splitlines() if ln.startswith(f" {SUBJECT_LABEL['mcp']}")]
    assert line, "no MCP line in the inventory"
    assert "none configured" in line[0], "fixture no longer exercises the empty roster"
    assert "2 issue(s)" in line[0], line[0]


def test_roster_and_subject_counts_are_named_separately():
    """A flagged installed skill and a misconfigured skill subsystem are different
    facts; summing them into one total would trade one lie for another."""
    from clawseccheck.report import _roster_and_subject_count_text as fmt
    assert fmt(0, 0) == "clear"
    assert fmt(2, 0) == "2 flagged"
    assert fmt(0, 3) == "3 issue(s)"
    assert fmt(2, 3) == "2 flagged · 3 issue(s)"
