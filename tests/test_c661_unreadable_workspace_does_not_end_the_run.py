"""C-661: an unreadable workspace directory must not end the whole run.

``pathprobe`` raises ``OSError`` on an unreadable path on every interpreter (C-647). The
credential-surface map probed ``<home>/workspace/.env`` with no handler, so a workspace the
audited user cannot read (mode 000, a directory owned by another user) ended both the text
report and ``--json`` with ``clawseccheck: unexpected internal error (PermissionError)`` and
exit 1: no verdict at all. Found by a single-fault sweep over a rich home (every path in turn
at mode 000, as a symlink loop and as mode 311), run against the CLI in text, JSON, SARIF and
HTML output on Python 3.12 and 3.14: this was the only variant that ended a run.

The map now counts the locations it could not read and says so in the ``.env`` entry's
evidence; ``reachable`` still reflects only what was seen.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck.collector import collect
from clawseccheck.report import _credential_surface_map

REPO = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="mode 000 does not bind root"
)


def _home(tmp_path: Path) -> Path:
    home = tmp_path / ".openclaw"
    (home / "workspace").mkdir(parents=True)
    (home / "workspace" / ".env").write_text("KEY=value\n", encoding="utf-8")
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({"gateway": {"bind": "127.0.0.1:8080"}}), encoding="utf-8")
    cfg.chmod(0o600)
    return home


@pytest.fixture
def readable_home(tmp_path):
    return _home(tmp_path)


@pytest.fixture
def locked_home(tmp_path):
    home = _home(tmp_path)
    ws = home / "workspace"
    ws.chmod(0)
    try:
        yield home
    finally:
        ws.chmod(0o700)


def _dotenv_entry(home: Path) -> dict:
    entries = _credential_surface_map(collect(home))
    return next(e for e in entries if e["class"] == ".env")


def test_a_readable_workspace_dotenv_is_still_reported(readable_home):
    entry = _dotenv_entry(readable_home)
    assert entry["reachable"] is True
    assert entry["evidence"] == ["workspace/.env"]


def test_an_unreadable_workspace_is_disclosed_not_a_crash(locked_home):
    entry = _dotenv_entry(locked_home)
    assert entry["reachable"] is False
    assert len(entry["evidence"]) == 1
    assert "could not be read" in entry["evidence"][0]
    assert "permission denied" in entry["evidence"][0]


def _cli(home: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", str(home), "--no-history",
         "--data-dir", str(home.parent / "data"), "--no-deptree", "--no-host",
         "--no-sockets", "--no-native", *extra],
        cwd=REPO, capture_output=True, text=True, timeout=300,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
    )


@pytest.mark.parametrize("extra", [(), ("--json",)], ids=["text", "json"])
def test_the_cli_ends_in_a_report_not_an_internal_error(locked_home, extra):
    cp = _cli(locked_home, *extra)
    assert "unexpected internal error" not in cp.stderr, cp.stderr[-400:]
    assert cp.returncode in (0, 1), (cp.returncode, cp.stderr[-400:])
    if extra:
        payload = json.loads(cp.stdout)
        rows = payload["secret_reachability"]
        dotenv = next(r for r in rows if r["class"] == ".env")
        assert any("could not be read" in e for e in dotenv["evidence"]), dotenv
    else:
        assert cp.stdout.strip(), "no report was printed"
