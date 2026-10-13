"""C-726 item 4: a ``--monitor`` run refused for a different ``--home`` writes nothing.

``docs/USAGE.md`` says of the refusal: "nothing is compared and nothing is written". It used
to append a row to ``history.jsonl`` (and exit 1). The whole store is compared byte for byte
before and after, and HOME is a scratch directory so a write to the default store shows too.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import shutil
from pathlib import Path

from clawseccheck.cli import main

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = REPO_ROOT / "fixtures" / "home_safe"
VULN = REPO_ROOT / "fixtures" / "home_vuln"


def _tree(root: Path) -> dict:
    """Relative path -> sha256 of the bytes ("<dir>" for a directory), for everything under root."""
    out = {}
    for p in sorted(root.rglob("*")):
        rel = str(p.relative_to(root))
        out[rel] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "<dir>"
    return out


def _monitor(home: Path, store: Path, *extra):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(["--monitor", "--home", str(home), "--data-dir", str(store), *extra,
                   "--no-deptree", "--no-host"])
    return rc, out.getvalue(), err.getvalue()


def test_a_refused_monitor_run_leaves_the_store_and_the_home_dir_untouched(tmp_path, monkeypatch):
    fakehome = tmp_path / "fakehome"
    fakehome.mkdir()
    monkeypatch.setenv("HOME", str(fakehome))
    store = tmp_path / "store"
    home_a, home_b = tmp_path / "a", tmp_path / "b"
    shutil.copytree(SAFE, home_a)
    shutil.copytree(VULN, home_b)
    assert _monitor(home_a, store)[0] == 0
    before_store, before_home = _tree(store), _tree(fakehome)
    assert "history.jsonl" in before_store, "the baseline run must have written a history row"

    rc, out, err = _monitor(home_b, store)

    assert rc == 1
    assert "MONITORING NOT ESTABLISHED" in err
    assert _tree(store) == before_store
    assert _tree(fakehome) == before_home


def test_a_refused_json_run_writes_nothing_either(tmp_path, monkeypatch):
    fakehome = tmp_path / "fakehome"
    fakehome.mkdir()
    monkeypatch.setenv("HOME", str(fakehome))
    store = tmp_path / "store"
    home_a, home_b = tmp_path / "a", tmp_path / "b"
    shutil.copytree(SAFE, home_a)
    shutil.copytree(VULN, home_b)
    assert _monitor(home_a, store, "--json")[0] == 0
    before = _tree(store)
    assert _monitor(home_b, store, "--json", "--exit-code")[0] == 1
    assert _tree(store) == before
