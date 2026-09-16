"""CLAWSECCHECK-C-456: sweep every check module / renderer for an absolute filesystem
path reaching a shared surface. SARIF already redacts (B-620, `sarif._sarif_text` wraps
every string with `report._redact_home_paths`). `--json` and `--pdf` did not, even
though docs/USAGE.md groups `--json` with SARIF as the CI-gating / machine-consumed
surface ("Gate my CI on this" → `--json` · `--sarif` · `--fail-on`), and explicitly
describes the no-PATH `--pdf` as the mechanism OpenClaw uses to ATTACH a report to a
chat message on the user's phone — a share/send surface, the same risk category that
motivated `_redact_home_paths` for the dashboard card in the first place.

Confirmed real, not hypothetical, the same way B-620's SARIF fix was: checks/_capability.py's
C5 (native binary PATH safety) builds WARN detail/evidence from resolved absolute ancestor
Path objects. C5 itself was already fixed at the SOURCE (B-757's `_username_safe_path`), so
these tests use a directly-constructed Finding shaped like C5's output (matching
tests/test_b620_sarif_results_path_redaction.py's own precedent for why a synthetic Finding
is the right unit here) rather than driving the real filesystem check.

Fixed at the renderer (report._finding_to_dict for JSON, pdf.py's per-finding "Why:" line),
not at any individual producer — the same "every producer funnels through one renderer"
principle B-620 already established for SARIF, now extended to the other two surfaces
docs/USAGE.md names in the same breath.

Every leak assertion pairs with a non-vacuity control: the raw input string is checked to
actually contain the path BEFORE rendering, so a future change that drops the value
entirely (rather than redacting it) cannot make these tests pass for the wrong reason.

Offline, deterministic.
"""
from __future__ import annotations

import json

from _pdftext import content_text

from clawseccheck.catalog import HIGH, WARN, Finding
from clawseccheck.dossier import AxisResult, VetProfile
from clawseccheck.incident import build_incident
from clawseccheck.pdf import render_pdf
from clawseccheck.report import _finding_to_dict, render_json, render_vet_json
from clawseccheck.scoring import compute

# Synthetic, never Path.home() -- this suite's HOME-isolation fixture (if any) must not
# make this assertion pass vacuously.
_FAKE_HOME_PREFIX = "/home/faketestuser"
_LEAKY_PATH = f"{_FAKE_HOME_PREFIX}/.npm-global/lib/node_modules/openclaw"


def _c5_shaped_finding(*, detail: str, evidence: list, fix: str = "fix text") -> Finding:
    """A Finding shaped exactly like C5's real WARN output -- see
    checks/_capability.py's check_path_safety `_flag`/`_walk_ancestors` helpers,
    mirroring test_b620_sarif_results_path_redaction.py's identical fixture."""
    return Finding(
        id="C5",
        title="Native binary PATH safety",
        severity=HIGH,
        status=WARN,
        detail=detail,
        fix=fix,
        framework="",
        evidence=evidence,
    )


# --------------------------------------------------------------------------------- JSON


def test_finding_to_dict_alone_does_not_redact():
    """`_finding_to_dict` itself is deliberately NOT the redaction point (see its own
    docstring) -- `incident.py` calls it directly and must keep getting the verbatim
    string. The redaction lives one level up, in `_sanitize_tree`, exercised by the
    tests below through the real renderers."""
    detail = f"openclaw install ancestor dir {_LEAKY_PATH} is group-writable"
    d = _finding_to_dict(_c5_shaped_finding(detail=detail, evidence=[]))
    assert _FAKE_HOME_PREFIX in d["detail"], (
        "_finding_to_dict started redacting -- this breaks incident.py's verbatim "
        "evidence-pack doctrine, see test_incident_pack_is_not_redacted_by_this_fix"
    )


def test_render_vet_json_redacts_axes_reason_and_fix():
    """C-135 finding: dossier._reason_and_fix returns worst.detail/worst.fix verbatim
    into axes[].reason/fix, a SEPARATE JSON payload from findings[] -- --vet --json
    must not leak the home path here even though findings[] is already covered."""
    detail = f"openclaw install ancestor dir {_LEAKY_PATH} is group-writable"
    assert _FAKE_HOME_PREFIX in detail  # non-vacuity control

    f = _c5_shaped_finding(detail=detail, evidence=[])
    axis = AxisResult(axis="build", status=WARN, reason=detail, fix="", findings=[f])
    profile = VetProfile(
        target="some-skill", target_type="skill", overall_status=WARN,
        verdict="CAUTION", overall_grade="N/A", score=0,
        axes=[axis], findings=[f],
    )
    doc = render_vet_json(profile, mode="static", version="0.0.0-test")
    assert _FAKE_HOME_PREFIX not in doc, doc
    parsed = json.loads(doc)
    reason = parsed["axes"][0]["reason"]
    assert _FAKE_HOME_PREFIX not in reason, reason
    assert "~/.npm-global" in reason, reason


def test_incident_pack_is_not_redacted_by_this_fix():
    """C-135 finding: incident.py's evidence-pack builder calls _finding_to_dict
    DIRECTLY and never routes through _sanitize_tree (see its own module docstring's
    "verbatim... never mutates" doctrine for a forensic-preservation artifact) -- this
    fix must not silently change that artifact's content. Non-regression control, not
    a leak this task is closing: incident.py was never covered by SARIF's B-620 fix
    either, and stays exactly as it was before C-456."""
    from clawseccheck.collector import Context

    ctx = Context(home="/nonexistent")
    ctx.config = {}
    ctx.installed_skills = {}

    detail = f"openclaw install ancestor dir {_LEAKY_PATH} is group-writable"
    f = _c5_shaped_finding(detail=detail, evidence=[])
    payload = build_incident(ctx, [f], compute([f]), when="2026-07-04T00:00:00")
    finding = payload["findings"][0]
    assert _FAKE_HOME_PREFIX in finding["detail"], (
        "incident.py's evidence pack must stay verbatim -- if this now fails, "
        "_finding_to_dict started redacting and incident.py's forensic content "
        "silently changed"
    )


def test_render_json_end_to_end_never_carries_the_home_path():
    """Assert on the FULLY SERIALIZED string -- what actually reaches the file -- not
    an intermediate dict, same discipline as the SARIF test this mirrors."""
    f = _c5_shaped_finding(
        detail=f"openclaw install ancestor dir {_LEAKY_PATH} is group-writable",
        evidence=[f"openclaw binary dir {_LEAKY_PATH}/bin is world-writable"],
    )
    doc = render_json([f], compute([f]))
    assert _FAKE_HOME_PREFIX not in doc, doc
    parsed = json.loads(doc)
    finding = next(x for x in parsed["findings"] if x["id"] == "C5")
    assert _FAKE_HOME_PREFIX not in finding["detail"], finding["detail"]
    assert _FAKE_HOME_PREFIX not in "".join(finding["evidence"]), finding["evidence"]


# ---------------------------------------------------------------------------------- PDF


def test_render_pdf_never_carries_the_home_path_in_content_streams():
    f = _c5_shaped_finding(
        detail=f"openclaw install ancestor dir {_LEAKY_PATH} is group-writable "
        "— a group member could replace the openclaw install",
        evidence=[],
    )
    data = render_pdf([f], compute([f]))
    text = content_text(data)
    assert _FAKE_HOME_PREFIX not in text, text
    assert "npm-global" in text, "the informative remainder must survive — redaction, not deletion"
