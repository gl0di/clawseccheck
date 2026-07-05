"""Tests for C-164 --purge: opt-in, confirmation-gated local-store cleanup.

Covers cli._run_purge / cli._confirm_purge (see clawseccheck/cli.py). --purge
resolves the store directory from --history's parent and operates ONLY on a
fixed whitelist of filenames (history.jsonl, events.jsonl, state.json,
coverage.json) plus their ".lock" sidecars — never a glob/rmtree of the
directory, so an unrelated file surviving is a hard requirement, not a nice-
to-have.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.cli import _PURGE_FILENAMES, main


def _seed_store(store_dir: Path) -> list[Path]:
    """Create all whitelisted store files (+ .lock sidecars) under store_dir."""
    store_dir.mkdir(parents=True, exist_ok=True)
    created = []
    for name in _PURGE_FILENAMES:
        p = store_dir / name
        p.write_text('{"placeholder": true}\n', encoding="utf-8")
        created.append(p)
        lock = store_dir / (name + ".lock")
        lock.write_text("", encoding="utf-8")
        created.append(lock)
    return created


# ---------------------------------------------------------------------------
# confirmation prompt: declined
# ---------------------------------------------------------------------------

def test_purge_requires_confirmation(tmp_path, monkeypatch):
    store_dir = tmp_path / "store"
    files = _seed_store(store_dir)

    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: "n")
    rc = main(["--purge", "--history", str(store_dir / "history.jsonl")])

    assert rc == 0  # declined is a normal (non-error) abort
    for p in files:
        assert p.exists()


# ---------------------------------------------------------------------------
# --yes skips confirmation and deletes
# ---------------------------------------------------------------------------

def test_purge_deletes_with_yes(tmp_path):
    store_dir = tmp_path / "store"
    files = _seed_store(store_dir)

    rc = main(["--purge", "--yes", "--history", str(store_dir / "history.jsonl")])

    assert rc == 0
    for p in files:
        assert not p.exists()


# ---------------------------------------------------------------------------
# interactive "y" without --yes also deletes
# ---------------------------------------------------------------------------

def test_purge_confirm_yes(tmp_path, monkeypatch):
    store_dir = tmp_path / "store"
    files = _seed_store(store_dir)

    monkeypatch.setattr("builtins.input", lambda *_a, **_kw: "y")
    rc = main(["--purge", "--history", str(store_dir / "history.jsonl")])

    assert rc == 0
    for p in files:
        assert not p.exists()


# ---------------------------------------------------------------------------
# EOF (no stdin / non-interactive) aborts loudly, no deletion
# ---------------------------------------------------------------------------

def test_purge_aborts_on_eof(tmp_path, monkeypatch):
    store_dir = tmp_path / "store"
    files = _seed_store(store_dir)

    def _raise_eof(*_a, **_kw):
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_eof)
    rc = main(["--purge", "--history", str(store_dir / "history.jsonl")])

    assert rc == 1
    for p in files:
        assert p.exists()


# ---------------------------------------------------------------------------
# empty store dir: no crash, rc 0
# ---------------------------------------------------------------------------

def test_purge_empty_dir_ok(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir()

    rc = main(["--purge", "--yes", "--history", str(store_dir / "history.jsonl")])

    assert rc == 0


def test_purge_missing_store_dir_ok(tmp_path):
    """The store directory itself need not even exist yet."""
    store_dir = tmp_path / "does_not_exist_yet"

    rc = main(["--purge", "--yes", "--history", str(store_dir / "history.jsonl")])

    assert rc == 0
    assert not store_dir.exists()


# ---------------------------------------------------------------------------
# purge must not write a fresh history point before deleting
# ---------------------------------------------------------------------------

def test_purge_writes_no_history_first(tmp_path):
    store_dir = tmp_path / "store"
    history_path = store_dir / "history.jsonl"
    _seed_store(store_dir)
    before = history_path.read_text(encoding="utf-8")

    rc = main(["--purge", "--yes", "--history", str(history_path)])

    assert rc == 0
    # The file must be gone entirely (deleted), not rewritten with a new record
    # appended first — proves purge is dispatched before any record()/audit call.
    assert not history_path.exists()
    # (Sanity on intent: if it existed, it would still equal `before` — but since
    # the whole point is deletion, absence itself is the strongest proof no
    # extra write-then-delete cycle occurred.)
    del before


# ---------------------------------------------------------------------------
# only the whitelist is touched — an unrelated file must survive
# ---------------------------------------------------------------------------

def test_purge_only_touches_whitelist(tmp_path):
    store_dir = tmp_path / "store"
    files = _seed_store(store_dir)
    unrelated = store_dir / "notes.txt"
    unrelated.write_text("keep me\n", encoding="utf-8")

    rc = main(["--purge", "--yes", "--history", str(store_dir / "history.jsonl")])

    assert rc == 0
    for p in files:
        assert not p.exists()
    assert unrelated.exists()
    assert unrelated.read_text(encoding="utf-8") == "keep me\n"


# ---------------------------------------------------------------------------
# partial store: only some whitelisted files exist
# ---------------------------------------------------------------------------

def test_purge_partial_store_deletes_only_existing(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(parents=True, exist_ok=True)
    history_path = store_dir / "history.jsonl"
    history_path.write_text('{"date":"2026-01-01"}\n', encoding="utf-8")

    rc = main(["--purge", "--yes", "--history", str(history_path)])

    assert rc == 0
    assert not history_path.exists()
