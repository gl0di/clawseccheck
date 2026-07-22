"""B-306 safe-symlink split — a dotfiles-style openclaw.json symlink is NOT config-blind.

Golden-Rule-#5 false CAP: a VALID, READABLE, SAFE ``openclaw.json`` reached through a
dotfiles-style symlink whose target escapes ``~/.openclaw`` was graded F/49 by B-306's
``CONFIG_BLIND_CAP`` — even though reading the identical bytes directly grades A/95. The
config loader (``configloader.load_openclaw_config``) refuses to FOLLOW a top-level config
symlink whose resolved target leaves the config dir, for its own read-safety; that refusal
set ``ctx.config_parse_error`` and the aggregate cap then hard-capped the grade to F.

But that state is NOT blind — the content is fully readable and safe; the loader merely
declined to follow the symlink. Dotfiles managers (stow / chezmoi / yadm / bare-git) that
symlink the config out to a version-controlled repo are mainstream for this tool's
audience, so this false F was a real Golden-Rule-#5 blocker.

The fix distinguishes — by STRUCTURE, never by any keyword/text match — the two states
``config_parse_error`` conflated:

  * corrupt / truncated / genuinely unreadable bytes -> truly blind; the F cap is correct.
  * a readable REGULAR file the tool merely DECLINED to follow, owned by the auditing user
    -> NOT blind; the collector follows it and audits the real bytes -> real grade, and an
    INFO note ("your openclaw.json symlinks outside ~/.openclaw"), never an F cap.

This file pins the benign case (no false cap), proves the genuine-blind siblings still cap,
and locks the scoring-layer invariant. Offline, read-only of tmp_path, stdlib only.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import CRITICAL, FAIL, LOW, PASS, Finding
from clawseccheck.collector import Context
from clawseccheck.report import render_report, render_json
from clawseccheck.scoring import CONFIG_BLIND_CAP, compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CLEAN_DOTFILES_CFG = FIXTURES / "clean_b306_symlink_safe_dotfiles" / "openclaw.json"


def _build_dotfiles_symlink(tmp_path: Path, cfg_bytes_src: Path) -> Path:
    """Lay out a benign dotfiles setup and return the audited HOME dir.

    ``<tmp>/home/openclaw.json`` is a symlink to ``<tmp>/dotfiles/openclaw.json`` (a
    readable regular file owned by the auditing user, outside the config dir).
    """
    home = tmp_path / "home"
    dotfiles = tmp_path / "dotfiles"
    home.mkdir()
    dotfiles.mkdir()
    real_cfg = dotfiles / "openclaw.json"
    shutil.copyfile(cfg_bytes_src, real_cfg)
    os.chmod(real_cfg, 0o600)
    (home / "openclaw.json").symlink_to(real_cfg)
    return home


# ── The benign repro: safe dotfiles symlink must grade like a direct read ─────────────

class TestSafeSymlinkEscapeNotCapped:
    def test_symlinked_config_grades_identically_to_direct_read(self, tmp_path):
        # Direct read of the identical bytes (reference), then the symlinked layout.
        direct_home = tmp_path / "direct"
        direct_home.mkdir()
        shutil.copyfile(CLEAN_DOTFILES_CFG, direct_home / "openclaw.json")
        os.chmod(direct_home / "openclaw.json", 0o600)
        ctx_direct, _, score_direct = audit(direct_home)

        home = _build_dotfiles_symlink(tmp_path, CLEAN_DOTFILES_CFG)
        ctx_sym, _, score_sym = audit(home)

        # The whole point: a safe symlink is audited on its merits, not hard-capped.
        assert ctx_sym.config_parse_error is False
        assert ctx_sym.config_symlink_escapes_home is True
        assert score_sym.config_blind_capped is False
        assert score_sym.grade == score_direct.grade
        assert score_sym.score == score_direct.score
        # And that reference grade is a real, high grade (the F cap is truly gone).
        assert score_sym.grade == "A"

    def test_config_mode_reflects_the_target_perms(self, tmp_path):
        # The at-rest perm view must be the TARGET's mode (the file OpenClaw reads),
        # so a 0600 dotfiles target is not mistaken for a loose config.
        home = _build_dotfiles_symlink(tmp_path, CLEAN_DOTFILES_CFG)
        ctx, _, _ = audit(home)
        assert ctx.config_mode == 0o600

    def test_reason_and_json_surface_the_relocation(self, tmp_path):
        home = _build_dotfiles_symlink(tmp_path, CLEAN_DOTFILES_CFG)
        ctx, findings, score = audit(home)
        assert ctx.config_parse_reason and "symlink" in ctx.config_parse_reason

        text = render_report(findings, score, ctx=ctx)
        assert "symlinks outside ~/.openclaw" in text

        import json as _json
        payload = _json.loads(render_json(findings, score, ctx=ctx))
        assert payload["config_symlink_escapes_home"] is True
        assert payload["config_parse_error"] is False
        assert payload["config_parse_reason"]


# ── The genuine-blind siblings must STILL cap (no false negative opened) ───────────────

class TestGenuineBlindStillCaps:
    def test_symlink_to_corrupt_owned_target_stays_blind(self, tmp_path):
        # Readable regular file the user OWNS, reached via an escaping symlink — but the
        # bytes are corrupt. The re-load fails, so this is genuinely blind: the F cap must
        # stand. This is the structural sibling of the benign case and the exact place a
        # naive "any owned regular file" exemption would have opened a hole.
        home = tmp_path / "home"
        dotfiles = tmp_path / "dotfiles"
        home.mkdir()
        dotfiles.mkdir()
        corrupt = dotfiles / "openclaw.json"
        corrupt.write_text('{"mcp": {"servers": ')  # truncated mid-object
        os.chmod(corrupt, 0o600)
        (home / "openclaw.json").symlink_to(corrupt)

        ctx, _, score = audit(home)
        assert ctx.config_parse_error is True
        assert ctx.config_symlink_escapes_home is False
        assert score.config_blind_capped is True
        assert score.grade == "F"
        assert score.score <= CONFIG_BLIND_CAP

    @pytest.mark.parametrize(
        "name,writer",
        [
            ("truncated", lambda p: p.write_text('{"mcp": {"servers": ')),
            ("non_object", lambda p: p.write_text("[1, 2, 3]")),
            ("trailing_garbage", lambda p: p.write_text('{"a": 1} GARBAGE!!!')),
            ("empty", lambda p: p.write_text("")),
        ],
    )
    def test_present_but_unreadable_config_still_caps(self, tmp_path, name, writer):
        cfg = tmp_path / "openclaw.json"
        writer(cfg)
        os.chmod(cfg, 0o600)
        ctx, _, score = audit(tmp_path)
        assert ctx.config_parse_error is True, name
        assert ctx.config_symlink_escapes_home is False, name
        assert score.config_blind_capped is True, name
        assert score.grade == "F", name

    def test_perms_000_regular_file_still_caps(self, tmp_path):
        cfg = tmp_path / "openclaw.json"
        shutil.copyfile(CLEAN_DOTFILES_CFG, cfg)
        os.chmod(cfg, 0o000)
        try:
            ctx, _, score = audit(tmp_path)
            assert ctx.config_parse_error is True
            assert ctx.config_symlink_escapes_home is False
            assert score.config_blind_capped is True
            assert score.grade == "F"
        finally:
            os.chmod(cfg, 0o600)  # let tmp cleanup remove it


# ── Scoring-layer invariant lock (defense in depth) ───────────────────────────────────

class TestScoringInvariantLock:
    def _f(self, severity, status):
        return Finding("X", "t", severity, status, "d", "fix", "fw", True)

    def test_safe_symlink_flag_exempts_config_blind_cap(self, tmp_path):
        # Even if a future collector change surfaced BOTH flags at once, the scoring layer
        # must never treat a safely-followed symlink as config-blind. Pins the second term
        # of the `config_blind` gate directly.
        ctx = Context(home=tmp_path)
        ctx.config_parse_error = True
        ctx.config_symlink_escapes_home = True
        findings = [self._f(LOW, PASS) for _ in range(20)]
        r = compute(findings, ctx)
        assert r.config_blind_capped is False
        assert r.score == 100

    def test_blind_without_safe_flag_still_caps(self, tmp_path):
        # The control: config_parse_error alone (no safe-symlink flag) still caps, so the
        # exemption cannot be reached by accident.
        ctx = Context(home=tmp_path)
        ctx.config_parse_error = True
        findings = [self._f(LOW, PASS) for _ in range(20)]
        r = compute(findings, ctx)
        assert r.config_blind_capped is True
        assert r.score <= CONFIG_BLIND_CAP

    def test_real_critical_fail_under_safe_symlink_still_caps_on_its_own_merits(self, tmp_path):
        # A genuine CRITICAL FAIL from the (readable) config still caps normally — the
        # exemption only removes the BLIND cap, never a real finding's cap.
        ctx = Context(home=tmp_path)
        ctx.config_parse_error = True
        ctx.config_symlink_escapes_home = True
        findings = [self._f(CRITICAL, FAIL)] + [self._f(LOW, PASS) for _ in range(20)]
        r = compute(findings, ctx)
        assert r.score <= CONFIG_BLIND_CAP
        assert r.config_blind_capped is False  # the CRITICAL FAIL, not the blind cap
        assert r.cap_severity == CRITICAL
