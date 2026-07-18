"""B-244 round 2: ``walk_dir_safely``'s ``capped`` sentinel must mean "genuinely
truncated — more of the tree exists beyond max_files", never "out happened to reach
max_files entries", so a caller (e.g. C015) can tell a complete scan of exactly
max_files files apart from a real truncation.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.safeio import walk_dir_safely


def _make_files(dirpath: Path, count: int) -> None:
    dirpath.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        (dirpath / f"file{i:05d}.txt").write_text("x\n", encoding="utf-8")


def test_capped_not_set_when_walk_has_exactly_max_files(tmp_path):
    """Exactly max_files candidate files and nothing beyond: the walk reached
    everything, so `capped` must stay empty (no false 'truncated' claim)."""
    _make_files(tmp_path, 10)
    capped: list = []
    out = walk_dir_safely(tmp_path, max_files=10, capped=capped)
    assert len(out) == 10
    assert capped == []


def test_capped_set_when_one_file_exists_beyond_max_files(tmp_path):
    """max_files + 1 candidate files: the walk finds genuine proof of truncation
    (the (max_files+1)-th file), so `capped` must be set and `out` still holds
    only max_files entries."""
    _make_files(tmp_path, 11)
    capped: list = []
    out = walk_dir_safely(tmp_path, max_files=10, capped=capped)
    assert len(out) == 10
    assert capped == [True]


def test_capped_not_set_when_under_max_files(tmp_path):
    _make_files(tmp_path, 5)
    capped: list = []
    out = walk_dir_safely(tmp_path, max_files=10, capped=capped)
    assert len(out) == 5
    assert capped == []


def test_capped_default_none_is_a_no_op(tmp_path):
    """Callers that don't pass `capped` keep the original truncate-silently
    behaviour — no crash, no forced list."""
    _make_files(tmp_path, 11)
    out = walk_dir_safely(tmp_path, max_files=10)
    assert len(out) == 10
