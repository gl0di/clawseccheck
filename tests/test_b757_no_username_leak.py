"""B-757: reports must not name the OS account's home directory.

Findings that interpolate an absolute filesystem path leak the operator's OS username
into the text report, --json, --html, --pdf, --sarif and the incident pack -- every
artifact a user would paste into a chat channel or attach to a bug report. Two concrete
producers measured live on this machine: C5 (checks/_capability.py, native binary PATH
safety -- npm install tree paths) and B136 (checks/_lifecycle.py, Codex CLI project
trust -- codex-home config paths), plus the "Audited config:" line in the text report.
The established precedents this fix follows: `report._credential_surface_rel` (the
credential-surface map) and `invocation._display_path` (paths printed for the user to
run) both already solve the identical problem for their own surfaces.

Testing note, established by tests/test_b679_invocation_prefix.py's identical leak test:
this suite's own session-scoped `_isolate_local_store` fixture (conftest.py) already
redirects $HOME to a throwaway sandbox for every test, so `Path.home()` inside a test is
NEVER the real machine account home. Each test here further pins $HOME via monkeypatch to
its own tmp_path-based directory and builds fixtures under exactly that path, so the
assertion `str(home) not in <rendered output>` is meaningful rather than vacuous (a bare
assertion against the ambient `Path.home()` would prove nothing, since nothing in a
fixture happens to live under the session sandbox by construction).

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from _pdftext import shown_strings

from clawseccheck import audit, render_json, render_pdf, render_report, render_sarif
from clawseccheck.checks import (
    _shared,
    _username_safe_path,
    check_codex_project_trust,
    check_path_safety,
    check_symlink_escape,
)
from clawseccheck.collector import Context
from clawseccheck.report import render_html

posix_only = pytest.mark.skipif(os.name != "posix", reason="symlinks are POSIX-only")

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# _username_safe_path itself
# ---------------------------------------------------------------------------

def test_username_safe_path_collapses_a_path_under_home(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    target = home / ".npm-global" / "lib" / "node_modules" / "openclaw"
    assert _username_safe_path(target) == "~/.npm-global/lib/node_modules/openclaw"


def test_username_safe_path_leaves_home_itself_as_bare_tilde(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    assert _username_safe_path(home) == "~"


def test_username_safe_path_leaves_a_path_outside_home_unchanged(monkeypatch, tmp_path):
    """Anti-vacuity: this is a home-relative rendering, not a blanket rewrite -- a path
    that never carries the username (e.g. a system-wide /opt install) must stay legible
    and addressable, matching invocation._display_path's own documented behavior."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    outside = tmp_path / "opt" / "openclaw"
    assert _username_safe_path(outside) == str(outside.resolve())


# ---------------------------------------------------------------------------
# C5 -- native binary PATH safety
# ---------------------------------------------------------------------------

def test_c5_warn_detail_never_carries_the_home_prefix(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    bin_dir = home / ".npm-global" / "lib" / "node_modules" / "openclaw" / "bin"
    bin_dir.mkdir(parents=True)
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh\necho openclaw")
    fake_exe.chmod(0o755)
    bin_dir.chmod(0o777)  # world-writable -> WARN
    try:
        monkeypatch.setattr(_shared, "_is_posix", lambda: True)
        monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
        monkeypatch.setenv("PATH", str(bin_dir))

        ctx = Context(home=Path("/nonexistent"))
        ctx.config = {}
        ctx.include_host = True
        f = check_path_safety(ctx)

        assert f.status == "WARN"
        assert str(home) not in f.detail, f.detail
        assert all(str(home) not in e for e in f.evidence), f.evidence
        assert "~/.npm-global/lib/node_modules/openclaw/bin" in f.detail, f.detail
    finally:
        bin_dir.chmod(0o755)


def test_c5_pass_detail_never_carries_the_home_prefix(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    bin_dir = home / ".npm-global" / "lib" / "node_modules" / "openclaw" / "bin"
    bin_dir.mkdir(parents=True)
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh\necho openclaw")
    fake_exe.chmod(0o755)  # tight -> PASS
    # mkdir(parents=True) leaves intermediate dirs group-writable under a permissive
    # umask (0o775, not 0o755) -- tighten every ancestor _walk_ancestors will visit so
    # this is genuinely a PASS scenario, not an accidental WARN from mkdir's own default.
    for d in (bin_dir, bin_dir.parent, bin_dir.parent.parent, bin_dir.parent.parent.parent,
             home / ".npm-global", home):
        d.chmod(0o755)

    monkeypatch.setattr(_shared, "_is_posix", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
    monkeypatch.setenv("PATH", str(bin_dir))

    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {}
    ctx.include_host = True
    f = check_path_safety(ctx)

    assert f.status == "PASS"
    assert str(home) not in f.detail, f.detail
    assert "~/.npm-global/lib/node_modules/openclaw/bin/openclaw" in f.detail, f.detail


# ---------------------------------------------------------------------------
# B136 -- Codex CLI project trust
# ---------------------------------------------------------------------------

def test_b136_warn_detail_never_carries_the_home_prefix(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    openclaw_home = home / ".openclaw"
    project_dir = home / "workspace" / "my-project"
    config = openclaw_home / "agents" / "main" / "agent" / "codex-home" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(f'[projects."{project_dir}"]\ntrust_level = "trusted"\n', encoding="utf-8")

    ctx = Context(home=openclaw_home)
    f = check_codex_project_trust(ctx)

    assert f.status == "WARN"
    assert str(home) not in f.detail, f.detail
    assert all(str(home) not in e for e in f.evidence), f.evidence
    assert "~/workspace/my-project" in f.detail, f.detail


# ---------------------------------------------------------------------------
# B87 -- symlink escape into a sensitive/host path (C-456 follow-up, CLAWSECCHECK-C-456)
# ---------------------------------------------------------------------------

def _mk_skill(root, name="demo"):
    d = root / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(f"---\nname: {name}\n---\nhello\n", encoding="utf-8")
    return d


@posix_only
def test_b87_fail_detail_never_carries_the_home_prefix(monkeypatch, tmp_path):
    """A symlink resolving into the OPERATOR'S real account home's ~/.ssh -- not into
    ctx.home, which in --vet mode is the unrelated vetted skill dir, so `_detail_path`
    (relative to ctx.home) would miss this entirely. `_username_safe_path` collapses
    Path.home() instead, the right frame for a target that can point anywhere."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    ssh_key = home / ".ssh" / "id_rsa"
    ssh_key.parent.mkdir(parents=True)
    ssh_key.write_text("x", encoding="utf-8")
    skill = _mk_skill(home / "downloads" / "suspicious-skill")
    os.symlink(ssh_key, skill / "data")

    f = check_symlink_escape(Context(home=skill))

    assert f.status == "FAIL"
    assert str(home) not in f.detail, f.detail
    assert all(str(home) not in e for e in f.evidence), f.evidence
    assert "~/.ssh/id_rsa" in f.detail, f.detail


@posix_only
def test_b87_warn_escape_detail_never_carries_the_home_prefix(monkeypatch, tmp_path):
    """Same leak shape on the WARN (non-sensitive escape) branch, not just FAIL."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    target = home / "elsewhere" / "notes.txt"
    target.parent.mkdir(parents=True)
    target.write_text("x", encoding="utf-8")
    skill = _mk_skill(home / "downloads" / "some-skill")
    os.symlink(target, skill / "ext")

    f = check_symlink_escape(Context(home=skill))

    assert f.status == "WARN"
    assert str(home) not in f.detail, f.detail
    assert all(str(home) not in e for e in f.evidence), f.evidence
    assert "~/elsewhere/notes.txt" in f.detail, f.detail


@posix_only
def test_b87_warn_in_tree_sensitive_detail_never_carries_the_home_prefix(monkeypatch, tmp_path):
    """The `sclass and in_tree` WARN branch (sensitive-named target that stays INSIDE the
    audited tree, e.g. a monorepo `apps/web/.env -> apps/api/.env`) -- a distinct code path
    from the FAIL and escape-WARN branches above; a partial fix could redact those two and
    miss this one (C-135 adversarial review caught this gap)."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    skill = _mk_skill(home / "downloads" / "monorepo-skill")
    real_env = skill / "apps" / "api" / ".env"
    real_env.parent.mkdir(parents=True)
    real_env.write_text("SECRET=1", encoding="utf-8")
    link = skill / "apps" / "web" / ".env"
    link.parent.mkdir(parents=True)
    os.symlink(real_env, link)

    f = check_symlink_escape(Context(home=skill))

    assert f.status == "WARN"
    assert str(home) not in f.detail, f.detail
    assert all(str(home) not in e for e in f.evidence), f.evidence
    assert "~/downloads/monorepo-skill/demo/apps/api/.env" in f.detail, f.detail


@posix_only
def test_b87_unknown_dangling_link_never_carries_the_home_prefix(monkeypatch, tmp_path):
    """The broken/dangling branch renders the literal on-disk symlink text (`raw`), not
    the resolved target -- a skill author can write that text as an absolute path too."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    skill = _mk_skill(home / "downloads" / "another-skill")
    absent = home / "scratch" / "gone.txt"  # deliberately never created, not sensitive-named
    os.symlink(absent, skill / "broken")

    f = check_symlink_escape(Context(home=skill))

    assert f.status == "UNKNOWN"
    assert str(home) not in f.detail, f.detail
    assert "~/scratch/gone.txt" in f.detail, f.detail


# ---------------------------------------------------------------------------
# The text report's "Audited config:" line
# ---------------------------------------------------------------------------

def test_audited_config_line_never_carries_the_home_prefix(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    openclaw_home = home / ".openclaw"
    shutil.copytree(FIXTURES / "home_safe", openclaw_home)

    ctx, findings, score = audit(openclaw_home)
    text = render_report(findings, score, ctx=ctx)

    assert "Audited config:" in text
    assert str(home) not in text, text
    assert "~/.openclaw/openclaw.json" in text, text


# ---------------------------------------------------------------------------
# The comprehensive sweep the DoD calls for: every check, every renderer
# ---------------------------------------------------------------------------

def test_no_renderer_leaks_the_home_prefix_over_a_real_audit(monkeypatch, tmp_path):
    """Runs the real engine (every registered check) against fixtures/home_vuln, plus a
    live C5/B136 leak scenario layered on top so this guard is proven non-vacuous, and
    asserts the account home never survives into any of the six renderers. A future check
    that starts embedding an absolute ctx.home-derived path fails here even if nobody
    thinks to write a dedicated test for it."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    openclaw_home = home / ".openclaw"
    shutil.copytree(FIXTURES / "home_vuln", openclaw_home)

    # Layer a live C5 WARN on top so the sweep is proven to fail without the fix (see the
    # mutation-proof in the commit description) rather than passing because nothing in
    # home_vuln alone happens to exercise a leaking producer.
    bin_dir = home / ".npm-global" / "lib" / "node_modules" / "openclaw" / "bin"
    bin_dir.mkdir(parents=True)
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh\necho openclaw")
    fake_exe.chmod(0o755)
    bin_dir.chmod(0o777)
    try:
        monkeypatch.setattr(_shared, "_is_posix", lambda: True)
        monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
        monkeypatch.setenv("PATH", str(bin_dir))

        ctx, findings, score = audit(openclaw_home, include_host=True)

        surfaces = {
            "text": render_report(findings, score, ctx=ctx),
            "json": render_json(findings, score, ctx=ctx),
            "html": render_html(findings, score, ctx=ctx),
            "sarif": render_sarif(findings, score, ctx=ctx),
        }
        surfaces["pdf"] = shown_strings(render_pdf(findings, score, ctx=ctx))

        c5 = next((f for f in findings if f.id == "C5"), None)
        assert c5 is not None and c5.status == "WARN", "precondition: C5 must fire"

        leaking = {name: body for name, body in surfaces.items() if str(home) in body}
        assert not leaking, f"home prefix leaked into: {sorted(leaking)}"
    finally:
        bin_dir.chmod(0o755)
