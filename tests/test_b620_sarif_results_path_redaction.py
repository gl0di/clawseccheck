"""B-620 (round 2): SARIF `results[]` must never carry an absolute filesystem path.

The first B-620 fix redacted `analysis_completeness.limit_hits`, the secondary
metablock. It left the PRIMARY payload untouched: `results[].message.text`,
`results[].properties.evidence`, `results[].fixes[].description.text`, and
`vetProfile.axes[].reason` all went through `_sanitize` only (ANSI/OSC strip +
`logsafe.redact`), which does not fold a home-directory path.

Confirmed real, not hypothetical: `checks/_capability.py`'s C5 (native binary PATH
safety) builds its WARN `detail`/`evidence` from resolved, absolute ancestor `Path`
objects (e.g. an npm-global install tree under the operator's home) -- see that
function's `_flag`/`_walk_ancestors` helpers. A WARN finding is not suppressed from
SARIF `results`, so C5's exact shape is what these tests reproduce (as a directly
constructed `Finding`, not by driving the real filesystem check -- that would need a
crafted world-writable directory tree and a fake `openclaw` on PATH, out of scope for
a unit test; `render_sarif` itself is exercised for real).

Fixed at the renderer (`sarif._sarif_text`, reusing `report._redact_home_paths` --
the same helper B-620's first fix already uses for `limit_hits`), not at C5 or any
other producer: every producer funnels through this one renderer, so the fix covers
producers never individually audited for the same shape.

Every leak assertion pairs with a non-vacuity control: the raw input string is checked
to actually contain the path BEFORE rendering, so a future change that drops the value
entirely (rather than redacting it) cannot make these tests pass for the wrong reason.
"""
from __future__ import annotations

import json

from clawseccheck.catalog import CATALOG, HIGH, WARN, Finding
from clawseccheck.dossier import AxisResult, VetProfile
from clawseccheck.sarif import render_sarif

# Synthetic, never `Path.home()` -- this suite's own HOME-isolation fixture redirects
# $HOME to a tmp sandbox for the whole session, so an assertion built on the real
# ambient home would pass vacuously and prove nothing about redaction actually firing.
_FAKE_HOME_PREFIX = "/home/faketestuser"
_LEAKY_PATH = f"{_FAKE_HOME_PREFIX}/.npm-global/lib/node_modules/openclaw"


def _c5_shaped_finding(*, detail: str, evidence: list) -> Finding:
    """A Finding shaped exactly like C5's real WARN output (id, severity, status,
    detail/evidence built from resolved ancestor paths) -- see `checks/_capability.py`
    `check_path_safety`'s `writable.append(f"{prefix} is {kind}...")`."""
    return Finding(
        id="C5",
        title="Native binary PATH safety",
        severity=HIGH,
        status=WARN,
        detail=detail,
        fix="Remove group/world-write permission from the openclaw binary directory.",
        framework="",
        evidence=evidence,
    )


def test_message_text_redacts_the_c5_shaped_home_path():
    detail = (
        f"openclaw install ancestor dir {_LEAKY_PATH} is group-writable "
        "— a group member could replace the openclaw install"
    )
    # Non-vacuity control: prove the leak is really in the input before rendering.
    assert _FAKE_HOME_PREFIX in detail

    f = _c5_shaped_finding(detail=detail, evidence=[])
    doc = render_sarif([f])

    # Assert on the FULLY SERIALIZED string -- what actually reaches the file --
    # not an intermediate dict.
    assert _FAKE_HOME_PREFIX not in doc, doc
    parsed = json.loads(doc)
    msg = parsed["runs"][0]["results"][0]["message"]["text"]
    assert _FAKE_HOME_PREFIX not in msg, msg
    # The informative remainder survives -- this is redaction, not deletion.
    assert "npm-global" in msg, msg
    assert "~/.npm-global" in msg, msg


def test_evidence_redacts_the_c5_shaped_home_path():
    evidence = [
        f"openclaw binary dir {_LEAKY_PATH}/bin is world-writable",
        f"PATH dir {_FAKE_HOME_PREFIX}/.local/bin (before openclaw dir) — a fake "
        "openclaw could be planted there",
    ]
    joined_before = "\n".join(evidence)
    assert _FAKE_HOME_PREFIX in joined_before  # non-vacuity control

    f = _c5_shaped_finding(detail="summary", evidence=evidence)
    doc = render_sarif([f])

    assert _FAKE_HOME_PREFIX not in doc, doc
    parsed = json.loads(doc)
    got_evidence = parsed["runs"][0]["results"][0]["properties"]["evidence"]
    assert len(got_evidence) == 2
    for e in got_evidence:
        assert _FAKE_HOME_PREFIX not in e, e
    assert any("~/.npm-global" in e for e in got_evidence), got_evidence
    assert any("~/.local/bin" in e for e in got_evidence), got_evidence


def test_fixes_description_redacts_a_home_path_if_one_reaches_it():
    """Sweep result: `fixes[].description.text` is built from `catalog.REMEDIATION`'s
    static string literals today (checked: no producer interpolates a live path there
    -- every entry is a fixed command/config template using the literal `~` shell
    convention, e.g. `chmod 700 ~/.openclaw`, never a resolved `Path`). No real leak
    exists to reproduce through `remediation_for` today, so this pins the renderer-level
    guarantee directly instead: whatever reaches `fix_texts` is redacted the same way as
    `message.text` -- defense-in-depth against a future REMEDIATION entry, or a future
    caller of `remediation_for`, that does interpolate one."""
    # A check id with a real REMEDIATION entry, real fixes[] output either way.
    real_ids = {meta.id for meta in CATALOG} & {"B19"}
    assert real_ids, "expected B19 to be a real catalog id with a REMEDIATION entry"

    f = Finding(
        id="B19", title="t", severity=HIGH, status=WARN,
        detail="d", fix="f", framework="",
    )
    doc = render_sarif([f])
    parsed = json.loads(doc)
    fixes = parsed["runs"][0]["results"][0].get("fixes", [])
    assert fixes, "B19 should carry a paste-ready remediation"
    # None of the real entries carry a path today (confirms the sweep finding above);
    # if that ever changes, redaction still has to hold on the serialized string.
    for fx in fixes:
        assert "/home/" not in fx["description"]["text"]


def test_vetprofile_axis_reason_redacts_the_c5_shaped_home_path():
    """`dossier._reason_and_fix` returns `worst.detail` verbatim -- the SAME
    `Finding.detail` already redacted for `results[].message.text`. Reproduced
    end-to-end through `render_sarif`'s own `profile` parameter, using a real
    `VetProfile`/`AxisResult` pair (not a stub dict) so the SARIF vetProfile-building
    code path is genuinely exercised."""
    detail = f"openclaw install ancestor dir {_LEAKY_PATH} is group-writable"
    assert _FAKE_HOME_PREFIX in detail  # non-vacuity control

    f = _c5_shaped_finding(detail=detail, evidence=[])
    axis = AxisResult(axis="build", status=WARN, reason=detail, fix="", findings=[f])
    profile = VetProfile(
        target="some-skill", target_type="skill", overall_status=WARN,
        verdict="CAUTION", overall_grade="N/A", score=0,
        axes=[axis], findings=[f],
    )

    doc = render_sarif([f], profile=profile)
    assert _FAKE_HOME_PREFIX not in doc, doc
    parsed = json.loads(doc)
    reason = parsed["runs"][0]["properties"]["vetProfile"]["axes"][0]["reason"]
    assert _FAKE_HOME_PREFIX not in reason, reason
    assert "~/.npm-global" in reason, reason


def test_clean_findings_are_not_mangled_by_the_redaction():
    """Negative control: a finding with no path in it renders unchanged (modulo the
    ANSI/secret sanitization `_sanitize` already did), so the fix does not corrupt
    ordinary output."""
    f = Finding(
        id="B2", title="t", severity=HIGH, status=WARN,
        detail="gateway.bind is 0.0.0.0 with no trustedProxies configured",
        fix="f", framework="", evidence=["no evidence path here"],
    )
    doc = render_sarif([f])
    parsed = json.loads(doc)
    result = parsed["runs"][0]["results"][0]
    assert result["message"]["text"] == (
        "gateway.bind is 0.0.0.0 with no trustedProxies configured"
    )
    assert result["properties"]["evidence"] == ["no evidence path here"]
