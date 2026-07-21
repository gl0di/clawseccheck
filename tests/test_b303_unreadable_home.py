"""CLAWSECCHECK-B-303: a non-traversable home (``chmod 000``) must degrade to UNKNOWN,
never crash the whole audit.

stat()/is_dir()/is_file()/is_symlink() need EXECUTE (search) permission on every
ANCESTOR directory of the path being checked, not just on the target itself. Several
pre-checks in collector.py ran that stat before any try/except existed to catch a
PermissionError, so a single ``chmod 000`` on the audited home (or, for the systemd-unit
probe, on ``~/.config/systemd/user``) took the WHOLE process down with an uncaught
traceback instead of the honest "not found" -> UNKNOWN degrade every one of these
collectors already documents for a path that genuinely does not exist (Golden Rule #4).

The root cause reproduces identically for EVERY direct child of an unreadable home:
openclaw.json, every BOOTSTRAP_FILES entry, every skill-load root, cron/, state/
(exec-approvals via a sibling file check, cron/plugin-trust/capture-state/cron-run-logs
via the shared state/ dir), and exec-approvals.json itself. This file exercises the
top-level repro (the whole home unreadable) plus a handful of the individual sibling
collectors directly, so a future edit to any ONE of them cannot silently reopen the
crash without a test noticing.

Every test that mutates a real directory's mode restores it in a ``finally`` so the
tree stays deletable by pytest's own ``tmp_path`` cleanup (no test pollutes the real
``~/.clawseccheck/`` or leaves a chmod-000 directory behind on failure).
"""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from clawseccheck.checks import run_all
from clawseccheck.collector import (
    Context,
    _collect_cron,
    _collect_exec_approvals,
    _collect_plugin_trust,
    _read_installed_skills,
    collect,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX permission bits only"
)
_SKIP_ROOT = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores the read bit"
)


def _unreadable_dir(tmp_path: Path, name: str = "home") -> Path:
    """A directory under tmp_path made non-traversable (mode 000)."""
    d = tmp_path / name
    d.mkdir()
    os.chmod(d, 0o000)
    return d


# ---------------------------------------------------------------------------
# The repro: the whole home is non-traversable.
# ---------------------------------------------------------------------------

@_SKIP_ROOT
def test_collect_survives_chmod000_home(tmp_path):
    """The literal bug repro: collect() must not raise on a non-traversable home."""
    home = _unreadable_dir(tmp_path)
    try:
        ctx = collect(home)  # must not raise PermissionError
    finally:
        os.chmod(home, 0o700)

    assert isinstance(ctx, Context)


@_SKIP_ROOT
def test_collect_chmod000_home_degrades_every_dimension_honestly(tmp_path):
    """Every dimension collect() could not read must land in its own documented
    "not found" state -- never a fabricated value, never a crash."""
    home = _unreadable_dir(tmp_path)
    try:
        ctx = collect(home)
    finally:
        os.chmod(home, 0o700)

    assert ctx.config_found is False
    assert ctx.config == {}
    assert ctx.bootstrap == {}
    assert ctx.installed_skills == {}
    assert ctx.cron_found is False
    assert ctx.exec_approvals_found is False
    assert ctx.plugin_trust_found is False
    assert ctx.capture_tables_found is False
    # The permission problem is recorded, not swallowed -- Golden Rule #4's "stated
    # reason", and evidence for anyone reading the report.
    assert any("Permission denied" in e for e in ctx.errors), ctx.errors
    assert any(
        "bootstrap" in h.lower() or "NOT scanned" in h for h in ctx.limit_hits
    ), ctx.limit_hits


@_SKIP_ROOT
def test_run_all_on_chmod000_home_no_fail_and_key_checks_unknown(tmp_path):
    """The consuming checks must not crash either, must never fabricate a FAIL over
    data that was never read (Golden Rule #5), and the checks that live directly off
    the dimensions above must say UNKNOWN, not a lying clean PASS."""
    home = _unreadable_dir(tmp_path)
    try:
        ctx = collect(home)
        findings = run_all(ctx)  # must not raise
    finally:
        os.chmod(home, 0o700)

    by_id = {f.id: f for f in findings}
    assert not [f for f in findings if f.status == "FAIL"], [
        (f.id, f.detail) for f in findings if f.status == "FAIL"
    ]
    for check_id in ("B13", "B59"):  # installed-skill safety / bootstrap image-exfil
        assert by_id[check_id].status == "UNKNOWN", (check_id, by_id[check_id].status)


@_SKIP_ROOT
def test_subprocess_exit_code_normal_on_chmod000_home(tmp_path):
    """End-to-end, in a REAL separate process: no unhandled-exception abort.

    A crash inside collect() would exit non-zero with a traceback on stderr; this
    proves the fix at the process-exit-code level the task's own test plan asks for,
    not just "no exception observed by the same interpreter that already imported
    everything once."
    """
    home = _unreadable_dir(tmp_path)
    script = textwrap.dedent(
        f"""
        from clawseccheck.collector import collect
        ctx = collect({str(home)!r})
        print("collected", ctx.config_found, len(ctx.errors))
        """
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        os.chmod(home, 0o700)

    assert result.returncode == 0, (
        f"subprocess aborted (exit {result.returncode}); stderr:\n{result.stderr}"
    )
    assert "Traceback" not in result.stderr, result.stderr
    assert "collected False" in result.stdout, result.stdout


# ---------------------------------------------------------------------------
# Control: an ordinary readable home is unaffected by the new guards.
# ---------------------------------------------------------------------------

def test_collect_readable_home_is_unaffected(tmp_path):
    """Regression control: a normal, fully-readable home must collect exactly as
    before -- config found, bootstrap file read, skill read, and no spurious
    permission-related errors/limit-hits from the new guards."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}")
    (home / "SOUL.md").write_text("Be a helpful assistant.")
    skill_dir = home / "skills" / "demo"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: demo\ndescription: test\n---\nharmless content\n"
    )

    ctx = collect(home)

    assert ctx.config_found is True
    assert ctx.bootstrap.get("SOUL.md") == "Be a helpful assistant."
    assert "demo" in ctx.installed_skills
    assert not any("could not check" in e for e in ctx.errors)
    assert not any("NOT scanned" in h for h in ctx.limit_hits)


# ---------------------------------------------------------------------------
# Sibling sweep -- individual collectors, exercised DIRECTLY (bypassing the rest of
# collect()) with *home itself* made non-traversable, so each function's own guard is
# pinned in isolation. This is deliberately chmod(home), not chmod(the subdirectory the
# function checks): stat()/is_dir()/is_file() need +x on the ANCESTOR of the path being
# probed, not on the target itself, so e.g. `(home / "cron").is_dir()` only ever raises
# when *home* (its parent) is non-traversable -- chmod-000'ing "cron" alone stats fine
# from outside (proven by re-running this file against the pre-fix collector.py: a
# locked-but-listed subdirectory never raised there either, because os.walk already
# swallows a PermissionError from ITS OWN scandir; only the ancestor-permission shape
# reproduces B-303).
# ---------------------------------------------------------------------------

@_SKIP_ROOT
def test_read_installed_skills_survives_unreadable_home(tmp_path):
    """Every hardcoded skill-load root is a direct child of home, so a non-traversable
    home must degrade ctx.installed_skills to empty (-> B13 UNKNOWN), not raise."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "skills").mkdir()
    (home / "skills" / "somewhere.txt").write_text("irrelevant")
    os.chmod(home, 0o000)

    ctx = Context(home=home)
    try:
        _read_installed_skills(home, ctx)  # must not raise
    finally:
        os.chmod(home, 0o755)

    assert ctx.installed_skills == {}


@_SKIP_ROOT
def test_collect_cron_survives_unreadable_home(tmp_path):
    """cron/ is a direct child of home, so cron_dir.is_dir() must not raise when home
    itself is non-traversable; must degrade to cron_found False instead."""
    home = tmp_path / "home"
    home.mkdir()
    os.chmod(home, 0o000)

    ctx = Context(home=home)
    try:
        _collect_cron(home, ctx)  # must not raise
    finally:
        os.chmod(home, 0o755)

    assert ctx.cron_found is False


@_SKIP_ROOT
def test_collect_exec_approvals_survives_unreadable_home(tmp_path):
    """exec-approvals.json living under a non-traversable home must degrade to
    exec_approvals_found False, not raise."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "exec-approvals.json").write_text("{}")
    os.chmod(home, 0o000)

    ctx = Context(home=home)
    try:
        _collect_exec_approvals(home, ctx)  # must not raise
    finally:
        os.chmod(home, 0o755)

    assert ctx.exec_approvals_found is False


@_SKIP_ROOT
def test_collect_plugin_trust_survives_unreadable_home(tmp_path):
    """state/ is a direct child of home, so state_dir.is_dir() must not raise when
    home itself is non-traversable; must degrade to plugin_trust_found False instead."""
    home = tmp_path / "home"
    home.mkdir()
    os.chmod(home, 0o000)

    ctx = Context(home=home)
    try:
        _collect_plugin_trust(home, ctx)  # must not raise
    finally:
        os.chmod(home, 0o755)

    assert ctx.plugin_trust_found is False
