"""C-726 item 1: ``--monitor --json`` writes exactly one JSON document on stdout.

``references/cli-flags.md`` promises that machine-readable stdout stays clean, and the cron
recipe polls with ``--monitor --probe``. The probe sentence used to follow the document on
stdout, so ``json.loads`` of the whole stream failed. Every variant below goes through the
real ``main()`` and parses the WHOLE of stdout.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
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


def _home(tmp_path: Path, name: str = "home") -> Path:
    dst = tmp_path / name
    shutil.copytree(SAFE, dst)
    return dst


def _drift(home: Path) -> None:
    """Make the gateway bind change, so the next comparison carries an alert."""
    cfg = home / "openclaw.json"
    data = json.loads(cfg.read_text(encoding="utf-8"))
    data.setdefault("gateway", {})["bind"] = "0.0.0.0"
    cfg.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(cfg, 0o600)


_VARIANTS = {
    "plain": [],
    "probe": ["--probe"],
    "verbose": ["--verbose"],
    "exit-code": ["--exit-code"],
    "fail-on-low": ["--fail-on", "low"],
    "probe-exit-fail-on": ["--probe", "--exit-code", "--fail-on", "low"],
}


def _one_document(out: str) -> dict:
    doc = json.loads(out)  # the WHOLE stream, so any prose around the document fails
    assert isinstance(doc, dict)
    return doc


@pytest.mark.parametrize("variant", sorted(_VARIANTS))
def test_first_run_stdout_is_one_json_document(tmp_path, variant):
    home = _home(tmp_path)
    rc, out, _err = _monitor(home, tmp_path / "store", "--json", *_VARIANTS[variant])
    assert rc == 0
    doc = _one_document(out)
    assert doc["baseline_status"] == "absent"


@pytest.mark.parametrize("variant", sorted(_VARIANTS))
def test_baselined_run_stdout_is_one_json_document(tmp_path, variant):
    home, store = _home(tmp_path), tmp_path / "store"
    assert _monitor(home, store, "--json")[0] == 0
    rc, out, _err = _monitor(home, store, "--json", *_VARIANTS[variant])
    assert rc == 0
    assert _one_document(out)["baseline_status"] == "ok"


@pytest.mark.parametrize("variant", sorted(_VARIANTS))
def test_run_with_alerts_stdout_is_one_json_document(tmp_path, variant):
    home, store = _home(tmp_path), tmp_path / "store"
    assert _monitor(home, store, "--json")[0] == 0
    _drift(home)
    rc, out, _err = _monitor(home, store, "--json", *_VARIANTS[variant])
    doc = _one_document(out)
    assert doc["alerts"], "the drift fixture must produce an alert, or this test proves nothing"
    assert rc in (0, 3)


@pytest.mark.parametrize("variant", sorted(_VARIANTS))
def test_corrupt_state_stdout_is_one_json_document(tmp_path, variant):
    home, store = _home(tmp_path), tmp_path / "store"
    assert _monitor(home, store, "--json")[0] == 0
    (store / "state.json").write_text("{ not json", encoding="utf-8")
    rc, out, _err = _monitor(home, store, "--json", *_VARIANTS[variant])
    assert _one_document(out)["baseline_status"] == "corrupt"


@pytest.mark.parametrize("variant", sorted(_VARIANTS))
def test_refused_run_never_puts_prose_on_stdout(tmp_path, variant):
    home, other, store = _home(tmp_path), _home(tmp_path, "other"), tmp_path / "store"
    assert _monitor(home, store, "--json")[0] == 0
    rc, out, err = _monitor(other, store, "--json", *_VARIANTS[variant])
    assert rc == 1
    assert "MONITORING NOT ESTABLISHED" in err
    assert out.strip() == "" or isinstance(json.loads(out), dict)


def test_probe_sentence_is_a_field_of_the_document(tmp_path):
    home, store = _home(tmp_path), tmp_path / "store"
    assert _monitor(home, store, "--json")[0] == 0
    _drift(home)
    _rc, out, _err = _monitor(home, store, "--json", "--probe")
    doc = _one_document(out)
    assert doc["probe"] is True
    assert "nothing was recorded" in doc["probe_notice"]
    assert doc["persisted"] is False


def test_ordinary_run_says_it_was_not_a_probe(tmp_path):
    home, store = _home(tmp_path), tmp_path / "store"
    _rc, out, _err = _monitor(home, store, "--json")
    doc = _one_document(out)
    assert doc["probe"] is False
    assert doc["probe_notice"] is None


def test_text_mode_probe_line_is_unchanged(tmp_path):
    home, store = _home(tmp_path), tmp_path / "store"
    assert _monitor(home, store)[0] == 0
    _rc, out, _err = _monitor(home, store, "--probe")
    assert "This was a probe: nothing was recorded, so your baseline still points at the last ordinary check." in out
