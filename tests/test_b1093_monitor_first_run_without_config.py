"""B-1093: a first ``--monitor`` run against a home with no openclaw.json is refused.

It used to save a baseline of nothing and exit 0, also under ``--exit-code``, so a cron job
pointed at the wrong ``--home`` stayed green forever. Now it prints MONITORING NOT
ESTABLISHED, writes nothing, and exits 1 - bare ``--monitor`` included.

The refusal is first-run only. The positive controls pin the two paths it must not touch:
an ordinary first run on a real home (rc 0, baseline saved), and a baselined home whose
config then disappears (a journaled HIGH alert, rc 3 under ``--exit-code``).

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import contextlib
import io
import json
import shutil
from pathlib import Path

import pytest

from clawseccheck.cli import main

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = REPO_ROOT / "fixtures" / "home_safe"


def _monitor(home: Path, store: Path, *extra):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(["--monitor", "--home", str(home), "--data-dir", str(store), *extra,
                   "--no-deptree", "--no-host"])
    return rc, out.getvalue(), err.getvalue()


def _homes(tmp_path: Path) -> dict:
    empty = tmp_path / "empty"
    empty.mkdir()
    # Not empty, but no openclaw.json: the realistic cron mistake (`--home ~`).
    noconf = tmp_path / "noconf"
    (noconf / "skills" / "something").mkdir(parents=True)
    (noconf / "notes.txt").write_text("not an OpenClaw home\n")
    return {"missing": tmp_path / "does-not-exist", "empty": empty, "noconf": noconf}


@pytest.fixture(autouse=True)
def _scratch_home(tmp_path, monkeypatch):
    fakehome = tmp_path / "fakehome"
    fakehome.mkdir()
    monkeypatch.setenv("HOME", str(fakehome))


@pytest.mark.parametrize("shape", ["missing", "empty", "noconf"])
@pytest.mark.parametrize("extra", [(), ("--exit-code",), ("--probe", "--exit-code"),
                                   ("--json", "--exit-code"), ("--fail-on", "critical")])
def test_a_first_run_without_a_config_is_refused_and_writes_nothing(tmp_path, shape, extra):
    home = _homes(tmp_path)[shape]
    store = tmp_path / "store"

    rc, out, err = _monitor(home, store, *extra)

    assert rc == 1
    assert "MONITORING NOT ESTABLISHED" in err
    assert "no openclaw.json" in err
    assert "Baseline saved" not in out
    assert not store.exists() or not any(store.iterdir()), sorted(store.iterdir())
    if "--json" in extra:
        assert out == "", "stdout must stay empty or one JSON document"


def test_an_ordinary_first_run_still_saves_a_baseline(tmp_path):
    home = tmp_path / "home"
    shutil.copytree(SAFE, home)
    store = tmp_path / "store"

    rc, out, err = _monitor(home, store, "--exit-code")

    assert rc == 0, err
    assert "MONITORING NOT ESTABLISHED" not in err
    assert (store / "state.json").is_file()


def test_a_baselined_home_losing_its_config_still_alerts(tmp_path):
    home = tmp_path / "home"
    shutil.copytree(SAFE, home)
    store = tmp_path / "store"
    assert _monitor(home, store)[0] == 0
    shutil.rmtree(home)

    rc, out, err = _monitor(home, store, "--exit-code")

    assert rc == 3, err
    assert "MONITORING NOT ESTABLISHED" not in err
    levels = [json.loads(line)["level"]
              for line in (store / "events.jsonl").read_text().splitlines() if line.strip()]
    assert "HIGH" in levels
