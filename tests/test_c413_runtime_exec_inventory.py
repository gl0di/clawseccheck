"""C-413 — skill/plugin runtime-exec inventory checks: B367 (skills.load.
allowSymlinkTargets), B368 (skills.load.watch), B369 (acp.backend), B370
(agentRuntime.id).

Re-grounded against the INSTALLED dist (openclaw@2026.9.3), correcting the filed task's
stub on several points:

- B367's classifier is NOT "is this path a well-known broad root" (the stub's own
  proposed "FAIL if any entry is a broad/writable/non-narrow root") — that shape was
  tried for the analogous B186 (bundled-root-override) check and explicitly RETRACTED
  there (checks/_host.py, B186's own comment block): a 0700 directory under /tmp is as
  private as one in the user's home. This check reuses the discriminator B186 replaced
  it with instead — _shared._dir_replaceable_by_others (sticky-aware, POSIX-only).

- B369/B370 are disclosure-only (scored=False, matching B364's precedent) — neither
  attempts to classify a value as safe/risky, matching B331's own pre-existing
  reasoning (this module) for why agentRuntime.id's value vocabulary is not safely
  characterizable from config alone.

- B370's real path is agents.{defaults,entries.<id>}.models.<ref>.agentRuntime.id, NOT
  the stub's cited models.providers.*.agentRuntime.id.

- memory.qmd.mcporter.* (the stub's fifth item) is dropped entirely: memory.qmd is
  RETIRED (confirmed during C-412's grounding — the QMD memory backend was removed).
  There is no field left to audit.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import os
from pathlib import Path

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    check_acp_backend_inventory,
    check_agent_runtime_id_inventory,
    check_skill_load_hot_reload,
    check_skill_symlink_target_writability,
)
from clawseccheck.collector import Context


def _ctx(cfg: dict, home: Path, parse_error: bool = False) -> Context:
    c = Context(home=home)
    c.config = cfg
    c.config_parse_error = parse_error
    return c


def _blob(f) -> str:
    return " ".join(f.evidence or []) + " " + (f.detail or "") + " " + (f.fix or "")


# ===========================================================================
# B367 — skills.load.allowSymlinkTargets
# ===========================================================================


class TestSymlinkTargetWritability:
    def test_absent_passes(self, tmp_path):
        f = check_skill_symlink_target_writability(_ctx({}, tmp_path))
        assert f.status == PASS

    def test_empty_list_passes(self, tmp_path):
        cfg = {"skills": {"load": {"allowSymlinkTargets": []}}}
        f = check_skill_symlink_target_writability(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_safe_owner_only_target_warns_not_fails(self, tmp_path):
        target = tmp_path / "trusted-root"
        target.mkdir()
        os.chmod(target, 0o700)
        cfg = {"skills": {"load": {"allowSymlinkTargets": [str(target)]}}}
        f = check_skill_symlink_target_writability(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert str(target) in _blob(f)

    def test_world_writable_target_fails(self, tmp_path):
        target = tmp_path / "open-root"
        target.mkdir()
        os.chmod(target, 0o777)
        cfg = {"skills": {"load": {"allowSymlinkTargets": [str(target)]}}}
        f = check_skill_symlink_target_writability(_ctx(cfg, tmp_path))
        assert f.status == FAIL
        assert str(target) in _blob(f)
        assert "world-writable" in _blob(f)

    def test_unresolvable_target_warns_not_fails(self, tmp_path):
        """Golden Rule #4: a path that cannot be resolved on THIS machine (e.g. an
        exported config from a different host) must not be asserted safe OR unsafe."""
        missing = tmp_path / "does-not-exist" / "nested"
        cfg = {"skills": {"load": {"allowSymlinkTargets": [str(missing)]}}}
        f = check_skill_symlink_target_writability(_ctx(cfg, tmp_path))
        assert f.status == WARN

    def test_relative_entry_never_stats_a_guessed_path(self, tmp_path):
        """Regression: an earlier draft of this check resolved a bare relative entry
        against ctx.home's parent and statted THAT — but the real runtime
        (resolveHomeRelativePath) resolves a relative entry against the OpenClaw
        process's own cwd at agent start, which this audit cannot know. Make ctx.home's
        own parent WORLD-WRITABLE and confirm a relative entry still does not FAIL —
        proving it was never statted via a guessed base."""
        home = tmp_path / "writable-parent" / "openclaw-home"
        home.parent.mkdir()
        os.chmod(home.parent, 0o777)
        home.mkdir()
        cfg = {"skills": {"load": {"allowSymlinkTargets": ["custom-skills"]}}}
        f = check_skill_symlink_target_writability(_ctx(cfg, home))
        assert f.status == WARN
        assert "relative path" in _blob(f)

    def test_tilde_expands_against_ctx_home_not_os_home(self, tmp_path):
        """~ must expand against ctx.home (the audited OpenClaw home, which
        OPENCLAW_HOME may have moved) — never the audit process's own OS $HOME, which
        would silently point at the wrong machine's directory entirely when auditing
        someone else's exported config."""
        home = tmp_path / "audited-home"
        home.mkdir()
        target = home / "trusted-root"
        target.mkdir()
        os.chmod(target, 0o777)
        cfg = {"skills": {"load": {"allowSymlinkTargets": ["~/trusted-root"]}}}
        f = check_skill_symlink_target_writability(_ctx(cfg, home))
        # FAIL only fires if _dir_replaceable_by_others was actually called on the
        # correctly-resolved (ctx.home-relative) target — proving the expansion used
        # ctx.home, not the audit process's own OS $HOME (which has no such directory).
        assert f.status == FAIL
        assert "~/trusted-root" in _blob(f)

    def test_mixed_one_bad_one_safe_still_fails(self, tmp_path):
        safe = tmp_path / "safe"
        safe.mkdir()
        os.chmod(safe, 0o700)
        bad = tmp_path / "bad"
        bad.mkdir()
        os.chmod(bad, 0o777)
        cfg = {"skills": {"load": {"allowSymlinkTargets": [str(safe), str(bad)]}}}
        f = check_skill_symlink_target_writability(_ctx(cfg, tmp_path))
        assert f.status == FAIL
        assert str(bad) in _blob(f)

    def test_sticky_tmp_style_dir_not_flagged_as_fail(self, tmp_path):
        """The retracted "broad root" heuristic would have flagged this purely on
        being world-writable-looking; the sticky bit is what actually neutralizes it
        (mirrors _dir_replaceable_by_others' own contract, already proven at B186)."""
        target = tmp_path / "sticky-like"
        target.mkdir()
        os.chmod(target, 0o1777)
        cfg = {"skills": {"load": {"allowSymlinkTargets": [str(target)]}}}
        f = check_skill_symlink_target_writability(_ctx(cfg, tmp_path))
        assert f.status != FAIL

    def test_non_list_value_is_unknown(self, tmp_path):
        cfg = {"skills": {"load": {"allowSymlinkTargets": "not-a-list"}}}
        f = check_skill_symlink_target_writability(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN

    def test_non_string_entries_is_unknown(self, tmp_path):
        cfg = {"skills": {"load": {"allowSymlinkTargets": [123]}}}
        f = check_skill_symlink_target_writability(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN

    def test_unreadable_config_is_unknown(self, tmp_path):
        f = check_skill_symlink_target_writability(_ctx({}, tmp_path, parse_error=True))
        assert f.status == UNKNOWN

    def test_catalog_entry(self):
        meta = BY_ID["B367"]
        assert meta.surface == "skills"
        assert meta.scored is True


# ===========================================================================
# B368 — skills.load.watch
# ===========================================================================


class TestSkillLoadHotReload:
    def test_watch_absent_passes(self, tmp_path):
        f = check_skill_load_hot_reload(_ctx({}, tmp_path))
        assert f.status == PASS

    def test_watch_false_passes(self, tmp_path):
        cfg = {"skills": {"load": {"watch": False}}}
        f = check_skill_load_hot_reload(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_watch_true_no_extra_dirs_passes(self, tmp_path):
        cfg = {"skills": {"load": {"watch": True}}}
        f = check_skill_load_hot_reload(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_watch_true_with_extra_dirs_warns(self, tmp_path):
        cfg = {"skills": {"load": {"watch": True, "extraDirs": ["/opt/custom-skills"]}}}
        f = check_skill_load_hot_reload(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "/opt/custom-skills" in _blob(f)

    def test_watch_not_a_bool_is_unknown(self, tmp_path):
        cfg = {"skills": {"load": {"watch": "yes"}}}
        f = check_skill_load_hot_reload(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN

    def test_unreadable_config_is_unknown(self, tmp_path):
        f = check_skill_load_hot_reload(_ctx({}, tmp_path, parse_error=True))
        assert f.status == UNKNOWN

    def test_catalog_entry(self):
        meta = BY_ID["B368"]
        assert meta.surface == "skills"
        assert meta.scored is True


# ===========================================================================
# B369 — acp.backend inventory
# ===========================================================================


class TestAcpBackendInventory:
    def test_absent_passes(self, tmp_path):
        f = check_acp_backend_inventory(_ctx({}, tmp_path))
        assert f.status == PASS

    def test_backend_set_warns(self, tmp_path):
        cfg = {"acp": {"backend": "custom-harness"}}
        f = check_acp_backend_inventory(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "custom-harness" in _blob(f)

    def test_fallbacks_set_warns(self, tmp_path):
        cfg = {"acp": {"fallbacks": ["harness-a", "harness-b"]}}
        f = check_acp_backend_inventory(_ctx(cfg, tmp_path))
        assert f.status == WARN

    def test_install_command_disclosed_when_backend_set(self, tmp_path):
        cfg = {"acp": {"backend": "x", "runtime": {"installCommand": "npm install -g x"}}}
        f = check_acp_backend_inventory(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "installCommand" in _blob(f)

    def test_empty_backend_string_passes(self, tmp_path):
        cfg = {"acp": {"backend": ""}}
        f = check_acp_backend_inventory(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_acp_not_a_dict_is_unknown(self, tmp_path):
        f = check_acp_backend_inventory(_ctx({"acp": "nope"}, tmp_path))
        assert f.status == UNKNOWN

    def test_backend_not_a_string_is_unknown(self, tmp_path):
        f = check_acp_backend_inventory(_ctx({"acp": {"backend": 5}}, tmp_path))
        assert f.status == UNKNOWN

    def test_fallbacks_not_a_list_is_unknown(self, tmp_path):
        f = check_acp_backend_inventory(_ctx({"acp": {"fallbacks": "nope"}}, tmp_path))
        assert f.status == UNKNOWN

    def test_unreadable_config_is_unknown(self, tmp_path):
        f = check_acp_backend_inventory(_ctx({}, tmp_path, parse_error=True))
        assert f.status == UNKNOWN

    def test_never_scored(self):
        assert BY_ID["B369"].scored is False

    def test_catalog_entry(self):
        meta = BY_ID["B369"]
        assert meta.surface == "mcp"


# ===========================================================================
# B370 — agentRuntime.id inventory
# ===========================================================================


class TestAgentRuntimeIdInventory:
    def test_no_models_passes(self, tmp_path):
        f = check_agent_runtime_id_inventory(_ctx({}, tmp_path))
        assert f.status == PASS

    def test_global_defaults_model_runtime_id_warns(self, tmp_path):
        cfg = {
            "agents": {"defaults": {"models": {
                "anthropic/claude-opus": {"agentRuntime": {"id": "claude-cli"}}
            }}}
        }
        f = check_agent_runtime_id_inventory(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "agents.defaults.models.anthropic/claude-opus.agentRuntime.id" in _blob(f)
        assert "claude-cli" in _blob(f)

    def test_per_agent_entries_model_runtime_id_warns(self, tmp_path):
        cfg = {
            "agents": {"entries": {"researcher": {"models": {
                "openai/gpt-5": {"agentRuntime": {"id": "codex"}}
            }}}}
        }
        f = check_agent_runtime_id_inventory(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "agents.entries.researcher.models.openai/gpt-5.agentRuntime.id" in _blob(f)

    def test_legacy_agents_list_model_runtime_id_warns(self, tmp_path):
        cfg = {
            "agents": {"list": [{
                "id": "researcher",
                "models": {"openai/gpt-5": {"agentRuntime": {"id": "codex"}}},
            }]}
        }
        f = check_agent_runtime_id_inventory(_ctx(cfg, tmp_path))
        assert f.status == WARN

    def test_empty_agent_runtime_id_not_flagged(self, tmp_path):
        cfg = {
            "agents": {"defaults": {"models": {
                "anthropic/claude-opus": {"agentRuntime": {"id": ""}}
            }}}
        }
        f = check_agent_runtime_id_inventory(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_model_entry_with_no_agent_runtime_not_flagged(self, tmp_path):
        cfg = {"agents": {"defaults": {"models": {"anthropic/claude-opus": {}}}}}
        f = check_agent_runtime_id_inventory(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_unreadable_config_is_unknown(self, tmp_path):
        f = check_agent_runtime_id_inventory(_ctx({}, tmp_path, parse_error=True))
        assert f.status == UNKNOWN

    def test_never_scored(self):
        assert BY_ID["B370"].scored is False

    def test_catalog_entry(self):
        meta = BY_ID["B370"]
        assert meta.surface == "mcp"
