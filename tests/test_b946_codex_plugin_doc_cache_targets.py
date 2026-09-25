"""B-946: the real-fleet FP gate's skill-discovery walk could not see plugin-bundled
skill trees under a Codex CLI plugin's own doc-cache
(agents/*/agent/codex-home/.tmp/plugins/plugins/*/skills/*).

Neither `discover_targets()` (config-declared roots only, via `skill_load_roots`) nor
`discover_plugin_roots()` (OpenClaw's own plugin-index SQLite table only) reached that
tree, so a real skill bundled there — and any FAIL it genuinely produces through
`vet_skill()` — was invisible to `compare()`'s new-FAIL blocker entirely. Confirmed on a
real machine: the tree is large (dozens of vendored plugin dirs, 502 bundled skill dirs)
and at least one bundled skill (the zoom plugin's `zoom-apps-sdk`) genuinely FAILs
CRITICAL through `vet_skill()` right now.

This widens `discover_targets()` to also walk that tree, alongside the config-declared
roots it already walked. It does NOT change what `vet_skill()`/`vet_plugin()` themselves
convict, and does not touch `checks/_config.py`'s C015 at-rest-secrets exclusion for the
identical path shape (a different decision protecting against a different problem,
B-124, over the same tree — see the module comment above `_CODEX_PLUGIN_CACHE_MARKER` in
`scripts/fleet_fp_gate.py`).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_GATE = _REPO / "scripts" / "fleet_fp_gate.py"


def _load():
    spec = importlib.util.spec_from_file_location("_b946_gate", _GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate = _load()


def _make_bundled_skill(root, agent, plugin, skill, *, write_manifest=True):
    """agents/<agent>/agent/codex-home/.tmp/plugins/plugins/<plugin>/skills/<skill>/"""
    d = (root / "agents" / agent / "agent" / "codex-home" / ".tmp" / "plugins" /
         "plugins" / plugin / "skills" / skill)
    d.mkdir(parents=True)
    if write_manifest:
        (d / "SKILL.md").write_text(
            f"---\nname: {skill}\ndescription: test fixture\n---\nBody.\n",
            encoding="utf-8",
        )
    return d


# --------------------------------------------------------------- _child_dirs (shared)

def test_child_dirs_of_a_missing_root_is_empty(tmp_path):
    assert gate._child_dirs(tmp_path / "nope") == []


def test_child_dirs_skips_dot_dirs_and_the_skip_list(tmp_path):
    (tmp_path / ".hidden").mkdir()
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "real").mkdir()
    (tmp_path / "a_file.txt").write_text("x", encoding="utf-8")
    names = [p.name for p in gate._child_dirs(tmp_path)]
    assert names == ["real"], names


# --------------------------------------- _codex_plugin_doc_cache_skill_pairs (new walk)

def test_finds_a_skill_bundled_in_the_codex_plugin_doc_cache(tmp_path):
    skill_dir = _make_bundled_skill(tmp_path, "main", "zoom", "zoom-apps-sdk")
    pairs = gate._codex_plugin_doc_cache_skill_pairs(tmp_path)
    assert pairs == [("zoom-apps-sdk", skill_dir)], pairs


def test_walks_every_agent_not_just_the_first(tmp_path):
    _make_bundled_skill(tmp_path, "main", "zoom", "zoom-apps-sdk")
    _make_bundled_skill(tmp_path, "second", "adobe", "adobe-skill")
    names = sorted(n for n, _ in gate._codex_plugin_doc_cache_skill_pairs(tmp_path))
    assert names == ["adobe-skill", "zoom-apps-sdk"], names


def test_a_plugin_dir_with_no_skills_subdir_contributes_nothing(tmp_path):
    plugin_dir = (tmp_path / "agents" / "main" / "agent" / "codex-home" / ".tmp" /
                  "plugins" / "plugins" / "codex-security")
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "assets").mkdir()
    assert gate._codex_plugin_doc_cache_skill_pairs(tmp_path) == []


def test_dot_and_skip_listed_dirs_inside_skills_are_not_treated_as_skills(tmp_path):
    skills_dir = (tmp_path / "agents" / "main" / "agent" / "codex-home" / ".tmp" /
                  "plugins" / "plugins" / "zoom" / "skills")
    skills_dir.mkdir(parents=True)
    (skills_dir / ".hidden").mkdir()
    (skills_dir / "node_modules").mkdir()
    (skills_dir / "real-skill").mkdir()
    names = [n for n, _ in gate._codex_plugin_doc_cache_skill_pairs(tmp_path)]
    assert names == ["real-skill"], names


def test_no_agents_dir_is_no_targets_rather_than_an_error(tmp_path):
    assert gate._codex_plugin_doc_cache_skill_pairs(tmp_path) == []


def test_no_codex_home_under_an_agent_is_no_targets_rather_than_an_error(tmp_path):
    (tmp_path / "agents" / "main" / "agent").mkdir(parents=True)
    assert gate._codex_plugin_doc_cache_skill_pairs(tmp_path) == []


# --------------------------------------------------------- discover_targets (widened)

def test_discover_targets_widens_to_include_codex_plugin_doc_cache_skills(tmp_path):
    """The load-bearing behaviour: `discover_targets()` itself -- not just the new
    helper -- must return the widened set, since that is what `build_snapshot()` calls."""
    (tmp_path / "skills" / "clawseccheck").mkdir(parents=True)
    _make_bundled_skill(tmp_path, "main", "zoom", "zoom-apps-sdk")
    targets, dropped = gate.discover_targets(tmp_path)
    names = {n for n, _ in targets}
    assert {"clawseccheck", "zoom-apps-sdk"} <= names, names
    assert dropped == []


def test_two_different_plugins_bundling_a_same_named_skill_is_a_disclosed_drop(tmp_path):
    """Real measured shape on this machine (5 of 502 bundled skill basenames): a generic
    skill name (e.g. "index"/"user-context") repeats across unrelated vendored plugins.
    The dedupe POLICY stays "keep one, disclose the drop" -- the same contract
    `_dedupe_by_name` already has for config-declared roots (B-627)."""
    _make_bundled_skill(tmp_path, "main", "plugin-a", "shared-name")
    _make_bundled_skill(tmp_path, "main", "plugin-b", "shared-name")
    targets, dropped = gate.discover_targets(tmp_path)
    assert dropped == ["shared-name"], dropped
    assert len([n for n, _ in targets if n == "shared-name"]) == 1


def test_no_codex_plugin_tree_at_all_does_not_break_ordinary_discovery(tmp_path):
    """Negative control: a fleet with no Codex CLI in use must discover exactly what it
    did before this change."""
    (tmp_path / "skills" / "clawseccheck").mkdir(parents=True)
    targets, dropped = gate.discover_targets(tmp_path)
    assert [n for n, _ in targets] == ["clawseccheck"], targets
    assert dropped == []


# ------------------------------------------------------------- build_snapshot (wiring)

def test_build_snapshot_actually_vets_a_bundled_skill(tmp_path):
    """End-to-end: a skill bundled in the Codex CLI plugin doc-cache must be discovered,
    vetted (scope="vet", same scope `--scope vet` already diagnoses), and counted in
    `reach` -- not merely findable by the standalone helper."""
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    _make_bundled_skill(tmp_path, "main", "zoom", "zoom-apps-sdk")

    snap = gate.build_snapshot(str(tmp_path))

    assert "zoom-apps-sdk" in snap["targets"], snap["targets"]
    assert snap["reach"]["skill_targets"] >= 1, snap["reach"]
    assert snap["reach"]["dropped_duplicate_names"] == []
    # Every fail row this bundled skill could produce is scoped "vet" with its own bare
    # name as target -- the SAME identity `--scope vet --target zoom-apps-sdk` already
    # diagnoses, never a separate scope this task would have had to invent.
    assert all(
        r["scope"] == "vet"
        for r in snap["fails"]
        if r["target"] == "zoom-apps-sdk"
    )
