"""C-658 (slice 1): a declared skill / plugin load root that is a symlink loop must reach B158
as a declared-but-unreadable root on every interpreter.

``skilldiscovery.config_extra_skill_dirs`` / ``config_plugin_load_paths`` used to de-duplicate
through ``Path.resolve()`` and ``continue`` on its error. ``resolve()`` raises ``RuntimeError``
for a symlink loop on 3.9 / 3.12 and returns the path on 3.14, so the root was dropped (and B158
said "Every declared ... load source resolves to a present directory") on the older
interpreters only. The root is now always kept; whether it is present is decided by the caller
through ``pathprobe``, which classifies ELOOP identically everywhere.

The ``old_interpreter`` fixture makes ``Path.resolve`` raise ``RuntimeError`` for a loop on ANY
interpreter, so the 3.9 / 3.12 behaviour is exercised on 3.14 as well.
"""
from __future__ import annotations

import os
import pathlib
from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_declared_skill_reconciliation
from clawseccheck.collector import Context
from clawseccheck.skilldiscovery import config_extra_skill_dirs, config_plugin_load_paths

posix_only = pytest.mark.skipif(os.name != "posix", reason="symlinks and permission bits are POSIX-only")
root_skip = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root bypasses permission bits, so an unreadable directory cannot be provoked",
)

# (config key path, discovery function) - the two sources C-658 slice 1 covers.
_SOURCES = {
    "extraDirs": (lambda v: {"skills": {"load": {"extraDirs": v}}}, config_extra_skill_dirs),
    "plugin_paths": (lambda v: {"plugins": {"load": {"paths": v}}}, config_plugin_load_paths),
}


def _ctx(home, cfg):
    c = Context(home=Path(home))
    c.config = cfg
    c.config_found = True
    c.bootstrap = {}
    c.limit_hits = []
    return c


@pytest.fixture
def old_interpreter(monkeypatch):
    """``Path.resolve()`` as 3.9 / 3.12 behave it: a symlink loop raises ``RuntimeError``."""
    real = pathlib.Path.resolve

    def resolve(self, *args, **kwargs):
        out = real(self, *args, **kwargs)
        try:
            os.stat(self)
        except OSError as exc:
            if exc.errno == 40:  # ELOOP
                raise RuntimeError(f"Symlink loop from {str(self)!r}")
        return out

    monkeypatch.setattr(pathlib.Path, "resolve", resolve)


def _make(kind: str, home: Path) -> str:
    """Build the declared root of *kind* under *home*; return the config entry for it."""
    if kind == "loop":
        os.symlink("extra", home / "extra")
        return "extra"
    if kind == "loop_in_the_middle":
        os.symlink("lp", home / "lp")
        return "lp/sub"
    if kind == "two_step_loop":
        os.symlink("b", home / "a")
        os.symlink("a", home / "b")
        return "a"
    if kind == "regular_file":
        (home / "extra").write_text("not a directory")
        return "extra"
    if kind == "missing":
        return "extra"
    if kind == "clean":
        (home / "extra").mkdir()
        return "extra"
    raise AssertionError(kind)


@posix_only
@pytest.mark.parametrize("source", sorted(_SOURCES))
@pytest.mark.parametrize("kind", ["loop", "loop_in_the_middle", "two_step_loop"])
@pytest.mark.parametrize("interp", ["native", "old"])
def test_a_looping_declared_root_is_kept_and_b158_warns(tmp_path, request, source, kind, interp):
    if interp == "old":
        request.getfixturevalue("old_interpreter")
    mkcfg, discover = _SOURCES[source]
    entry = _make(kind, tmp_path)
    cfg = mkcfg([entry])
    assert discover(tmp_path, cfg) == [tmp_path / entry]
    f = check_declared_skill_reconciliation(_ctx(tmp_path, cfg))
    assert f.status == WARN, (f.status, f.detail)
    assert "declared but not present on disk" in f.detail
    assert "resolves to a present directory" not in f.detail


@posix_only
@pytest.mark.parametrize("source", sorted(_SOURCES))
@pytest.mark.parametrize("interp", ["native", "old"])
def test_regular_file_and_missing_roots_still_warn(tmp_path, request, source, interp):
    if interp == "old":
        request.getfixturevalue("old_interpreter")
    mkcfg, discover = _SOURCES[source]
    for kind in ("regular_file", "missing"):
        home = tmp_path / kind
        home.mkdir()
        cfg = mkcfg([_make(kind, home)])
        assert discover(home, cfg) == [home / "extra"]
        f = check_declared_skill_reconciliation(_ctx(home, cfg))
        if kind == "regular_file" and source == "plugin_paths":
            # C-742: plugins.load.paths accepts files, so a present regular file is a present
            # source. skills.load.extraDirs names skill ROOTS and keeps warning on a file.
            assert f.status == PASS, (f.status, f.detail)
            continue
        assert f.status == WARN and "declared but not present on disk" in f.detail, kind


@posix_only
@pytest.mark.parametrize("source", sorted(_SOURCES))
@pytest.mark.parametrize("interp", ["native", "old"])
def test_a_clean_directory_still_passes(tmp_path, request, source, interp):
    """Positive control: an ordinary readable root is unchanged."""
    if interp == "old":
        request.getfixturevalue("old_interpreter")
    mkcfg, discover = _SOURCES[source]
    cfg = mkcfg([_make("clean", tmp_path)])
    assert discover(tmp_path, cfg) == [tmp_path / "extra"]
    assert check_declared_skill_reconciliation(_ctx(tmp_path, cfg)).status == PASS


@posix_only
@root_skip
@pytest.mark.parametrize("source", sorted(_SOURCES))
@pytest.mark.parametrize("interp", ["native", "old"])
def test_an_unreadable_directory_root_is_kept(tmp_path, request, source, interp):
    """A chmod 000 directory is still a present directory for B158 (stat of the directory
    itself works); the point pinned here is only that discovery never drops it."""
    if interp == "old":
        request.getfixturevalue("old_interpreter")
    mkcfg, discover = _SOURCES[source]
    target = tmp_path / "extra"
    target.mkdir()
    (target / "inner").mkdir()
    os.chmod(target, 0)
    try:
        assert discover(tmp_path, mkcfg(["extra"])) == [target]
        # a root under an unsearchable parent: stat raises EACCES, which B158 reads as "not there"
        assert discover(tmp_path, mkcfg(["extra/inner"])) == [target / "inner"]
        f = check_declared_skill_reconciliation(_ctx(tmp_path, mkcfg(["extra/inner"])))
        assert f.status == WARN
    finally:
        os.chmod(target, 0o700)


@posix_only
@pytest.mark.parametrize("source", sorted(_SOURCES))
@pytest.mark.parametrize("interp", ["native", "old"])
def test_two_spellings_of_one_root_collapse_and_two_roots_do_not(tmp_path, request, source, interp):
    if interp == "old":
        request.getfixturevalue("old_interpreter")
    mkcfg, discover = _SOURCES[source]
    (tmp_path / "real").mkdir()
    (tmp_path / "other").mkdir()
    os.symlink("real", tmp_path / "alias")
    os.symlink("lp", tmp_path / "lp")
    # same directory spelled three ways -> one entry (the first spelling wins)
    cfg = mkcfg(["real", "./real", "alias"])
    assert discover(tmp_path, cfg) == [tmp_path / "real"]
    # distinct directories stay distinct
    assert discover(tmp_path, mkcfg(["real", "other"])) == [tmp_path / "real", tmp_path / "other"]
    # the same loop spelled twice -> one entry; a different loop stays its own entry
    assert discover(tmp_path, mkcfg(["lp/sub", "./lp/sub", "lp/other"])) == [
        tmp_path / "lp" / "sub",
        tmp_path / "lp" / "other",
    ]
