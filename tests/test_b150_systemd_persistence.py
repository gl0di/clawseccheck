"""B150 — OpenClaw-related systemd user-unit Restart=always persistence.

Real observed shape: ~/.config/systemd/user/openclaw-gateway.service carrying
Restart=always + WantedBy=default.target. ~/.config/systemd/user/ is a sibling of
~/.openclaw under the same real user home, reached via ctx.home.parent (same idiom as
check_backups' C3 ctx.home.parent / "backups" lookup).

Advisory only (WARN, LOW, never FAIL) — Restart=always is common, legitimate
infrastructure for a long-running gateway service, not proof of compromise.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_systemd_persistence
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home: Path) -> Context:
    c = Context(home=home)
    return c


def _write_unit(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Unit-level (synthetic tmp_path homes)
# ---------------------------------------------------------------------------

def test_no_systemd_user_dir_is_unknown(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    f = check_systemd_persistence(_ctx(home))
    assert f.status == UNKNOWN


def test_systemd_dir_present_but_no_openclaw_unit_is_unknown(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    _write_unit(
        tmp_path / ".config" / "systemd" / "user" / "some-other-app.service",
        "[Service]\nExecStart=/usr/bin/some-other-app\nRestart=always\n",
    )
    f = check_systemd_persistence(_ctx(home))
    assert f.status == UNKNOWN


def test_openclaw_unit_restart_always_warns(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    _write_unit(
        tmp_path / ".config" / "systemd" / "user" / "openclaw-gateway.service",
        "[Service]\nExecStart=/usr/bin/openclaw gateway start\nRestart=always\n"
        "[Install]\nWantedBy=default.target\n",
    )
    f = check_systemd_persistence(_ctx(home))
    assert f.status == WARN
    assert any("Restart=always" in e for e in f.evidence)


def test_openclaw_unit_restart_on_failure_passes(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    _write_unit(
        tmp_path / ".config" / "systemd" / "user" / "openclaw-gateway.service",
        "[Service]\nExecStart=/usr/bin/openclaw gateway start\nRestart=on-failure\n",
    )
    f = check_systemd_persistence(_ctx(home))
    assert f.status == PASS


def test_unit_name_without_openclaw_but_execstart_mentions_it_warns(tmp_path):
    """The unit NAME need not mention openclaw if ExecStart= does."""
    home = tmp_path / ".openclaw"
    home.mkdir()
    _write_unit(
        tmp_path / ".config" / "systemd" / "user" / "gateway.service",
        "[Service]\nExecStart=/usr/local/bin/openclaw-gateway\nRestart=always\n",
    )
    f = check_systemd_persistence(_ctx(home))
    assert f.status == WARN


def test_never_fails(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    _write_unit(
        tmp_path / ".config" / "systemd" / "user" / "openclaw-gateway.service",
        "[Service]\nExecStart=/usr/bin/openclaw gateway start\nRestart=always\n",
    )
    assert check_systemd_persistence(_ctx(home)).status != "FAIL"


# ---------------------------------------------------------------------------
# Fixture-level (collect())
# ---------------------------------------------------------------------------

def test_bad_fixture_warns():
    ctx = collect(FIXTURES / "bad_b150_systemd_restart" / "openclaw_home")
    f = check_systemd_persistence(ctx)
    assert f.status == WARN
    assert any("openclaw-gateway.service" in e for e in f.evidence)


def test_clean_fixture_passes():
    ctx = collect(FIXTURES / "clean_b150_systemd_restart" / "openclaw_home")
    f = check_systemd_persistence(ctx)
    assert f.status == PASS


def test_real_fixtures_are_unknown_not_false_positive():
    """No systemd context shipped with home_safe/home_vuln -> honest UNKNOWN."""
    for fx in ("home_safe", "home_vuln"):
        ctx = collect(FIXTURES / fx)
        assert check_systemd_persistence(ctx).status == UNKNOWN


def test_registered_in_audit():
    from clawseccheck import audit
    _ctx_, findings, _score = audit(
        FIXTURES / "bad_b150_systemd_restart" / "openclaw_home", include_native=False
    )
    ids = {f.id for f in findings}
    assert "B150" in ids
