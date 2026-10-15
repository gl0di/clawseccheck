"""C-647: ``clawseccheck.pathprobe`` reproduces the Python 3.9-3.12 ``pathlib`` predicate
contract on every interpreter.

The expected outcomes below are a LITERAL table - what 3.9-3.12's ``Path.exists()`` /
``is_dir()`` / ``is_file()`` / ``is_symlink()`` return or raise for each path shape. The table
is not derived from the interpreter under test, so it is the same assertion on 3.9, 3.12 and
3.14. On 3.14 ``pathlib`` itself no longer follows that contract (an unreadable path reads as
absent), which is exactly why ``pathprobe`` exists.

The differential half runs only below 3.14: there ``pathlib.Path(p).<name>()`` must give the
SAME outcome as the table, i.e. the table really is the old pathlib behaviour and not a
guess. It cannot run on 3.14, the interpreter that changed.

Outcome vocabulary: ``True`` / ``False`` for a return value, or the exception CLASS (exact
type) for a raise.
"""
from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

from clawseccheck import pathprobe

posix_only = pytest.mark.skipif(os.name != "posix", reason="symlinks and permission bits are POSIX-only")
root_skip = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root bypasses permission bits, so EACCES cannot be provoked",
)

_NAMES = ("exists", "is_dir", "is_file", "is_symlink")

# row -> expected outcome for (exists, is_dir, is_file, is_symlink): the 3.9-3.12 behaviour.
_T, _F = True, False
_EXPECTED = {
    "absent":                 (_F, _F, _F, _F),
    "regular_file":           (_T, _F, _T, _F),
    "directory":              (_T, _T, _F, _F),
    "symlink_to_file":        (_T, _F, _T, _T),
    "symlink_to_dir":         (_T, _T, _F, _T),
    "dangling_symlink":       (_F, _F, _F, _T),
    # stat() follows the loop and fails ELOOP (-> False); lstat() sees the link itself.
    "symlink_loop":           (_F, _F, _F, _T),
    # a path THROUGH a regular file: ENOTDIR on both stat and lstat.
    "through_a_regular_file": (_F, _F, _F, _F),
    # a directory with mode 000 is itself stat-able; only what is INSIDE it is not.
    "mode000_dir_itself":     (_T, _T, _F, _F),
    # EACCES is not in the ignored set, so every probe re-raises it.
    "under_mode000_dir":      (PermissionError, PermissionError, PermissionError, PermissionError),
    "under_mode444_dir":      (PermissionError, PermissionError, PermissionError, PermissionError),
    # ENAMETOOLONG is not in the ignored set either: a plain OSError.
    "overlong_component":     (OSError, OSError, OSError, OSError),
    # ValueError (embedded NUL) is swallowed by every one of them.
    "embedded_nul":           (_F, _F, _F, _F),
}

_NEEDS_PERMISSION_BITS = {"under_mode000_dir", "under_mode444_dir"}


@pytest.fixture
def matrix(tmp_path):
    """Build every row under tmp_path; return {row: path-string}. Directory modes are always
    restored on teardown so pytest can delete tmp_path."""
    base = tmp_path / "m"
    base.mkdir()
    (base / "reg").write_text("x", encoding="utf-8")
    (base / "dir").mkdir()
    os.symlink(base / "reg", base / "lnk_file")
    os.symlink(base / "dir", base / "lnk_dir")
    os.symlink(base / "nowhere", base / "dangling")
    os.symlink(base / "loop_b", base / "loop_a")
    os.symlink(base / "loop_a", base / "loop_b")
    for name in ("locked000", "ro444"):
        (base / name / "inner").mkdir(parents=True)
        (base / name / "inner" / "f.txt").write_text("x", encoding="utf-8")
    rows = {
        "absent": base / "absent",
        "regular_file": base / "reg",
        "directory": base / "dir",
        "symlink_to_file": base / "lnk_file",
        "symlink_to_dir": base / "lnk_dir",
        "dangling_symlink": base / "dangling",
        "symlink_loop": base / "loop_a",
        "through_a_regular_file": base / "reg" / "child",
        "mode000_dir_itself": base / "locked000",
        "under_mode000_dir": base / "locked000" / "inner",
        "under_mode444_dir": base / "ro444" / "inner",
        "overlong_component": base / ("a" * 300),
        "embedded_nul": None,  # a str, not a Path: Path() construction is not the point
    }
    out = {k: (str(v) if v is not None else str(base / "has\0nul")) for k, v in rows.items()}
    os.chmod(base / "locked000", 0o000)
    os.chmod(base / "ro444", 0o444)
    try:
        yield out
    finally:
        os.chmod(base / "locked000", 0o755)
        os.chmod(base / "ro444", 0o755)


def _outcome(fn, arg):
    try:
        return bool(fn(arg))
    except Exception as exc:  # noqa: BLE001 - the exact class IS the outcome under test
        return type(exc)


def _rows():
    for row in _EXPECTED:
        marks = []
        if row in _NEEDS_PERMISSION_BITS:
            marks.append(root_skip)
        yield pytest.param(row, marks=marks, id=row)


@posix_only
@pytest.mark.parametrize("as_path", [False, True], ids=["str", "Path"])
@pytest.mark.parametrize("row", list(_rows()))
def test_pathprobe_matches_the_3_12_table(matrix, row, as_path):
    arg = matrix[row]
    if as_path and row != "embedded_nul":
        arg = Path(arg)
    for name, expected in zip(_NAMES, _EXPECTED[row]):
        got = _outcome(getattr(pathprobe, name), arg)
        assert got == expected, f"pathprobe.{name}({row}) -> {got!r}, expected {expected!r}"


@posix_only
def test_the_overlong_component_raises_enametoolong_not_just_some_oserror(matrix):
    for name in _NAMES:
        with pytest.raises(OSError) as info:
            getattr(pathprobe, name)(matrix["overlong_component"])
        assert info.value.errno == errno.ENAMETOOLONG, (name, info.value.errno)


@posix_only
@root_skip
def test_the_denied_rows_raise_eacces(matrix):
    for row in ("under_mode000_dir", "under_mode444_dir"):
        for name in _NAMES:
            with pytest.raises(PermissionError) as info:
                getattr(pathprobe, name)(matrix[row])
            assert info.value.errno == errno.EACCES, (row, name, info.value.errno)


@posix_only
def test_the_ignored_errnos_are_exactly_the_four_pathlib_ones():
    """The constants are copied from CPython 3.12's pathlib, not paraphrased."""
    assert pathprobe._IGNORED_ERRNOS == (errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP)
    assert pathprobe._IGNORED_WINERRORS == (21, 123, 1921)


@pytest.mark.parametrize("winerror", [21, 123, 1921])
def test_the_three_windows_error_codes_read_as_absent(winerror):
    """The Windows half of the contract, pinned without a Windows machine: an OSError that
    carries one of the three codes is 'not there', one that carries another is re-raised."""
    exc = OSError(0, "x")
    exc.winerror = winerror  # only ever set by the OS on Windows; settable on any platform
    assert pathprobe._ignore_error(exc) is True
    other = OSError(errno.EACCES, "denied")
    other.winerror = 5
    assert pathprobe._ignore_error(other) is False


def test_an_errno_outside_the_set_is_not_ignored():
    for code in (errno.EACCES, errno.EPERM, errno.ENAMETOOLONG, errno.EIO, errno.EINVAL):
        assert pathprobe._ignore_error(OSError(code, "x")) is False, code
    for code in (errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP):
        assert pathprobe._ignore_error(OSError(code, "x")) is True, code


def test_a_non_oserror_other_than_valueerror_is_not_swallowed():
    """Only OSError (minus the ignored set) and ValueError are handled. A TypeError (a bad
    argument) is a bug at the call site and must stay loud."""
    with pytest.raises(TypeError):
        pathprobe.exists(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        pathprobe.is_dir(1.5)  # type: ignore[arg-type]  (an int would be a file descriptor)


@posix_only
def test_is_symlink_does_not_follow_and_the_others_do(tmp_path):
    (tmp_path / "t").write_text("x", encoding="utf-8")
    os.symlink(tmp_path / "t", tmp_path / "l")
    assert pathprobe.is_symlink(tmp_path / "l") is True
    assert pathprobe.is_file(tmp_path / "l") is True  # follows
    assert pathprobe.is_symlink(tmp_path / "t") is False
    os.unlink(tmp_path / "t")
    assert pathprobe.exists(tmp_path / "l") is False  # dangling: followed, not there
    assert pathprobe.is_symlink(tmp_path / "l") is True  # lstat still sees the link


def test_pathprobe_is_a_leaf_that_imports_nothing_from_the_package():
    import ast

    src = Path(pathprobe.__file__).read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0, "pathprobe must not import from the package"
            assert not (node.module or "").startswith("clawseccheck")
        if isinstance(node, ast.Import):
            assert not any(a.name.startswith("clawseccheck") for a in node.names)


def test_pathprobe_does_not_ask_which_interpreter_it_runs_on():
    """No version guard anywhere: a branch on sys.version_info is the unmeasured path this
    module exists to remove."""
    src = Path(pathprobe.__file__).read_text(encoding="utf-8")
    assert "version_info" not in src
    assert "sys.version" not in src
    assert "platform." not in src


# ------------------------------------------------------- the differential half (< 3.14 only)


@pytest.mark.skipif(sys.version_info >= (3, 14),
                    reason="3.14 rewrote pathlib's predicates - that change is what pathprobe replaces")
@posix_only
@pytest.mark.parametrize("row", list(_rows()))
def test_the_table_is_what_pathlib_actually_does_before_3_14(matrix, row):
    """The differential: the literal table above must equal ``pathlib.Path`` on the
    interpreters where pathlib still has the contract. If this fails the table, not
    pathprobe, is what is wrong."""
    arg = matrix[row]
    for name, expected in zip(_NAMES, _EXPECTED[row]):
        got = _outcome(lambda a, n=name: getattr(Path(a), n)(), arg)
        assert got == expected, f"pathlib.Path({row}).{name}() -> {got!r}, expected {expected!r}"
        assert got == _outcome(getattr(pathprobe, name), arg), (row, name)
