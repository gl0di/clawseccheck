"""B-872: skill discovery has no sandbox-layout awareness.

Inside an OpenClaw sandbox the state dir is `$HOME/.openclaw` but the real skill tree is
`$HOME/skills` — a SIBLING of the state dir, never a child. Every skill root
`_read_installed_skills` builds is home-relative (`SKILL_DIRS`), so an audit pointed at the
state dir itself finds nothing there and says nothing about why: "none installed" reads
identically whether the population really is empty or the scan simply looked in the wrong
directory. Measured on a real incident (2026-09-20): 29 real skills, 0 found, no hint in the
output that a different `--home` would have found them.

`ctx.sandboxed` (B-776) is already the precise compound signal for this shape — the sandbox
sync marker present AND no config resolvable this run — and `_read_installed_skills` already
computes the exact `user_home`/`audited_home` pair this fix needs (reused from the
pre-existing `~/.agents/skills` root below it). This file pins the new behaviour: on the
conjunction (sandboxed AND `$HOME/skills` exists with real skill dirs in it), the run gets a
`ctx.disclosures` entry naming the count and telling the user to re-run one level up — never a
silent new scan root (Golden Rule #2: report, do not redirect).

Offline, deterministic; all filesystem work stays inside pytest's tmp_path — the same
Path.home()/Path.cwd() monkeypatching idiom as tests/test_b776_sandbox_signal.py.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.collector import collect


def _write_marker(base: Path) -> None:
    skills = base / "skills"
    skills.mkdir(parents=True, exist_ok=True)
    (skills / ".openclaw-sync.json").write_text("{}", encoding="utf-8")


def _write_skill(skills_dir: Path, name: str) -> None:
    d = skills_dir / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A test skill.\n---\n\n# {name}\n",
        encoding="utf-8",
    )


def _own_home(monkeypatch, home: Path) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("HOME", str(home))


def _disclosures_of_kind(ctx, kind: str):
    return [d for d in (ctx.disclosures or []) if getattr(d, "kind", None) == kind]


class TestBadSandboxSiblingSkillsFound:
    """The bug fixture: sandbox marker present, no config, real skills beside the state
    dir — the disclosure must fire and name the count."""

    def test_disclosure_fires_with_the_right_count(self, tmp_path, monkeypatch):
        sandbox_root = tmp_path / "sandbox"
        sandbox_root.mkdir()
        _write_marker(sandbox_root)  # sandbox_root/skills/.openclaw-sync.json
        for name in ("alpha", "beta", "gamma"):
            _write_skill(sandbox_root / "skills", name)
        _own_home(monkeypatch, sandbox_root)
        monkeypatch.chdir(sandbox_root)

        audited = sandbox_root / ".openclaw"
        audited.mkdir()  # no openclaw.json inside -> config_found is False

        ctx = collect(audited)
        assert ctx.config_found is False
        assert ctx.sandboxed is True
        # The normal, home-relative scan genuinely finds nothing -- this is the "0 of 29"
        # half of the incident, reproduced.
        assert ctx.installed_skills == {}

        found = _disclosures_of_kind(ctx, "skills_beside_state_dir")
        assert len(found) == 1, ctx.disclosures
        assert "3 skill directories" in found[0].detail, found[0].detail
        assert "--home" in found[0].detail

    def test_disclosure_never_adds_a_scan_root(self, tmp_path, monkeypatch):
        """Golden Rule #2 / the task's own guard: report, never silently redirect. The
        sibling skills must stay OUT of ctx.installed_skills even though their count is
        now disclosed."""
        sandbox_root = tmp_path / "sandbox"
        sandbox_root.mkdir()
        _write_marker(sandbox_root)
        _write_skill(sandbox_root / "skills", "solo")
        _own_home(monkeypatch, sandbox_root)
        monkeypatch.chdir(sandbox_root)

        audited = sandbox_root / ".openclaw"
        audited.mkdir()

        ctx = collect(audited)
        assert "solo" not in (ctx.installed_skills or {})
        assert ctx.installed_skill_roots == [] or all(
            r != sandbox_root / "skills" for r in ctx.installed_skill_roots
        )

    def test_disclosure_detail_carries_no_path(self, tmp_path, monkeypatch):
        """tests/test_b617_disclosure_channel.py's own rule for every disclosure: no
        absolute path, and no '/' at all, in subject or detail."""
        sandbox_root = tmp_path / "sandbox"
        sandbox_root.mkdir()
        _write_marker(sandbox_root)
        _write_skill(sandbox_root / "skills", "solo")
        _own_home(monkeypatch, sandbox_root)
        monkeypatch.chdir(sandbox_root)

        audited = sandbox_root / ".openclaw"
        audited.mkdir()

        ctx = collect(audited)
        found = _disclosures_of_kind(ctx, "skills_beside_state_dir")
        assert len(found) == 1
        rec = found[0]
        assert "/" not in rec.subject
        assert "/" not in rec.detail.replace("--home", "")

    def test_singular_wording_for_exactly_one_skill(self, tmp_path, monkeypatch):
        sandbox_root = tmp_path / "sandbox"
        sandbox_root.mkdir()
        _write_marker(sandbox_root)
        _write_skill(sandbox_root / "skills", "solo")
        _own_home(monkeypatch, sandbox_root)
        monkeypatch.chdir(sandbox_root)

        audited = sandbox_root / ".openclaw"
        audited.mkdir()

        ctx = collect(audited)
        found = _disclosures_of_kind(ctx, "skills_beside_state_dir")
        assert "1 skill directory " in found[0].detail, found[0].detail
        assert "1 skill directories" not in found[0].detail


class TestCleanNoFalsePositive:
    """Every term of the conjunction must independently gate the disclosure off."""

    def test_quiet_when_sibling_skills_dir_is_empty(self, tmp_path, monkeypatch):
        """Sandboxed, no config -- but the sibling 'skills' dir holds only the marker
        file itself, no real skill directories. Nothing to disclose."""
        sandbox_root = tmp_path / "sandbox"
        sandbox_root.mkdir()
        _write_marker(sandbox_root)
        _own_home(monkeypatch, sandbox_root)
        monkeypatch.chdir(sandbox_root)

        audited = sandbox_root / ".openclaw"
        audited.mkdir()

        ctx = collect(audited)
        assert ctx.sandboxed is True
        assert not _disclosures_of_kind(ctx, "skills_beside_state_dir")

    def test_quiet_when_not_sandboxed_even_with_a_real_sibling_skills_dir(
        self, tmp_path, monkeypatch
    ):
        """An ordinary (non-sandboxed) home that happens to have a '.openclaw' dir with
        a sibling 'skills' folder full of real skills must NOT be treated as the sandbox
        case just because the shape matches -- ctx.sandboxed gates it."""
        home_root = tmp_path / "home"
        home_root.mkdir()
        for name in ("alpha", "beta"):
            _write_skill(home_root / "skills", name)
        _own_home(monkeypatch, home_root)
        monkeypatch.chdir(home_root)

        audited = home_root / ".openclaw"
        audited.mkdir()
        (audited / "openclaw.json").write_text("{}", encoding="utf-8")

        ctx = collect(audited)
        assert ctx.config_found is True
        assert ctx.sandboxed is False
        assert not _disclosures_of_kind(ctx, "skills_beside_state_dir")

    def test_quiet_when_audited_home_is_not_a_profile_dir_under_user_home(
        self, tmp_path, monkeypatch
    ):
        """Sandboxed and a real sibling 'skills' dir exist, but the audited --home is
        not shaped like `$HOME/.openclaw*` (e.g. a hermetic fixture/custom --home target)
        -- must stay quiet, matching the identical guard on the pre-existing
        `~/.agents/skills` root just above this one in the source."""
        sandbox_root = tmp_path / "sandbox"
        sandbox_root.mkdir()
        _write_marker(sandbox_root)
        _write_skill(sandbox_root / "skills", "alpha")
        _own_home(monkeypatch, sandbox_root)
        monkeypatch.chdir(sandbox_root)

        audited = tmp_path / "unrelated_fixture_home"
        audited.mkdir()

        ctx = collect(audited)
        assert ctx.sandboxed is True
        assert not _disclosures_of_kind(ctx, "skills_beside_state_dir")


class TestUnreadableSiblingIsQuietNotACrash:
    """UNKNOWN-shaped path: the sibling directory exists but cannot be stat'd. This is a
    disclosure channel, never a verdict, so the honest behaviour is silence, not a crash
    and not a fabricated count."""

    def test_permission_denied_on_sibling_dir_does_not_crash_or_fabricate_a_count(
        self, tmp_path, monkeypatch
    ):
        sandbox_root = tmp_path / "sandbox"
        sandbox_root.mkdir()
        _write_marker(sandbox_root)
        skills_dir = sandbox_root / "skills"
        _write_skill(skills_dir, "alpha")
        _own_home(monkeypatch, sandbox_root)
        monkeypatch.chdir(sandbox_root)

        audited = sandbox_root / ".openclaw"
        audited.mkdir()

        # 0o111 (search-only, no read): a specific already-known filename (the sandbox
        # marker) can still be stat'd through it -- so `ctx.sandboxed` stays True, the
        # same as production would see on a directory that denies listing but not
        # lookup -- while `iterdir()` (what the skill-count probe needs) is refused.
        skills_dir.chmod(0o111)
        try:
            ctx = collect(audited)  # must not raise
        finally:
            skills_dir.chmod(0o755)

        assert ctx.sandboxed is True
        # Either silence (permission blocked the listing) or a correct count of 1
        # (running as root, which ignores the mode) -- either way, never a crash and
        # never a count that does not match what is actually on disk.
        found = _disclosures_of_kind(ctx, "skills_beside_state_dir")
        assert len(found) in (0, 1)
        if found:
            assert "1 skill directory " in found[0].detail
