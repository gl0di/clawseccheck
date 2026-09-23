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
    must not leak the home path here even though findings[] is already covered.

    B-866: the reviewer's own finding on this test was that ``fix=""`` here never
    exercised ``axes[].fix`` at all -- an empty string trivially contains no home path,
    so the assertion below would have passed whether or not redaction ran. ``fix_text``
    is a SEPARATE leaking string from ``detail`` (not just the same value reused) so a
    future regression that redacts ``reason`` but not ``fix`` -- or vice versa -- cannot
    hide behind the other field's assertion."""
    detail = f"openclaw install ancestor dir {_LEAKY_PATH} is group-writable"
    fix_text = f"chmod 700 {_LEAKY_PATH}"
    assert _FAKE_HOME_PREFIX in detail  # non-vacuity control
    assert _FAKE_HOME_PREFIX in fix_text  # non-vacuity control -- axes[].fix specifically

    f = _c5_shaped_finding(detail=detail, evidence=[], fix=fix_text)
    axis = AxisResult(axis="build", status=WARN, reason=detail, fix=fix_text, findings=[f])
    profile = VetProfile(
        target="some-skill", target_type="skill", overall_status=WARN,
        verdict="CAUTION", overall_grade="N/A", score=0,
        axes=[axis], findings=[f],
    )
    doc = render_vet_json(profile, mode="static", version="0.0.0-test")
    assert _FAKE_HOME_PREFIX not in doc, doc
    parsed = json.loads(doc)
    reason = parsed["axes"][0]["reason"]
    fix = parsed["axes"][0]["fix"]
    assert _FAKE_HOME_PREFIX not in reason, reason
    assert "~/.npm-global" in reason, reason
    assert _FAKE_HOME_PREFIX not in fix, fix
    assert "~/.npm-global" in fix, fix


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


class _LeakyPluginSweep:
    """Duck-typed like checks._mcp.PluginSweep -- see report._plugins_inventory_lines's
    own docstring for the exact surface this needs (.no_roots/.no_targets/.rows/
    .findings). One flagged row, so the "flagged" line is built from `finding.detail`
    (report.py: ``reason = _sanitize(f.detail) if f is not None and f.detail else
    verdict``) exactly the way a real plugin-vet finding would."""

    def __init__(self, finding: Finding):
        self.no_roots = False
        self.no_targets = False
        self.rows = [("evil-plugin", finding.status, [])]
        self.findings = [("evil-plugin", finding)]


def test_render_pdf_full_pipeline_plugins_block_redacts_home_paths():
    """B-866: the `--full` pipeline blocks pdf._pipeline_block draws (Plugins/MCP/
    Behavioural/Second opinion among them) never went through `_finding_block`'s own
    `_redact_home_paths` call -- `_plugins_inventory_lines` builds its 'flagged' line
    straight from `Finding.detail` (report.py: ``reason = _sanitize(f.detail)``), with
    no redaction step of its own (that renderer is shared with the plain-text
    `--full`/`--dashboard` report, which keeps full paths by design -- see
    `_redact_home_paths`'s own docstring). Drives the REAL call site
    (`render_pdf`'s 'Plugins' block via `plugin_sweep`), not `_pipeline_block` in
    isolation, so a regression in how `render_pdf` wires `plugin_sweep` through
    cannot hide behind a lower-level test."""
    finding = _c5_shaped_finding(
        detail=f"plugin installs a launcher at {_LEAKY_PATH}/bin/evil", evidence=[],
    )
    sweep = _LeakyPluginSweep(finding)
    data = render_pdf([], compute([]), plugin_sweep=sweep)
    text = content_text(data)
    assert _FAKE_HOME_PREFIX not in text, text
    assert "evil-plugin" in text and "bin/evil" in text, (
        "redaction, not deletion -- the remainder must survive: " + text
    )


def test_pipeline_block_redacts_home_paths_in_every_line():
    """B-866, direct unit test of `pdf._pipeline_block` itself -- the ONE place all
    eight `--full` pipeline blocks (Skills/Plugins/MCP/RISK chains/Behavioural/Second
    opinion/Coverage/Worth a glance) reach the PDF page. Same `_bare_flow` pattern
    `test_pdf.py`'s `test_line_sanitises_a_hostile_string_directly` uses for a DIRECT
    unit test of a render boundary, rather than trusting some upstream caller to have
    already redacted the input -- the leaking line is fed in raw here, bypassing
    report.py's line renderers entirely, so this cannot pass merely because one of
    THEM happens to redact."""
    from clawseccheck.pdf import _PageFlow, _PdfDoc, _pipeline_block

    def _flow():
        doc = _PdfDoc()
        font_helv = doc.add_object(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        font_bold = doc.add_object(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
            b"/Encoding /WinAnsiEncoding >>")
        return _PageFlow(doc, font_helv, font_bold)

    leaking_line = f"   [WARN] evil-plugin  CAUTION - installs to {_LEAKY_PATH}/bin/evil"
    flow = _flow()
    _pipeline_block(flow, "Plugins", [leaking_line])
    drawn = "\n".join(flow._page_ops)
    assert _FAKE_HOME_PREFIX not in drawn, drawn
    assert "bin/evil" in drawn, "redaction, not deletion -- the remainder must survive"

    # Mutation control (this repo's "a control that cannot fail controls nothing"
    # standard): reproduce _pipeline_block's own per-line loop with the
    # `_redact_home_paths` call removed, and confirm the assertion above would have
    # caught its absence.
    from clawseccheck.pdf import _draw_section_header

    mutated_flow = _flow()
    _draw_section_header(mutated_flow, "Plugins")
    for raw in [leaking_line]:
        text = raw.rstrip()
        indent = (len(text) - len(text.lstrip(" "))) * 3.0
        mutated_flow.wrapped(text.lstrip(" "), size=9, color="#333333",
                              indent=min(indent, 60.0))
    mutated_drawn = "\n".join(mutated_flow._page_ops)
    assert _FAKE_HOME_PREFIX in mutated_drawn, (
        "mutation control failed to reproduce the leak -- this test would pass even "
        "with _pipeline_block's own redaction removed, so it proves nothing"
    )
