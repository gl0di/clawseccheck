"""C-616 -- `collector._is_own_source` bounds the engine directory AS A WHOLE.

Before this change only ONE file was bounded (`_MAX_OWN_SOURCE_BYTES`, per file). The
glob of `<root>/clawseccheck/checks/*.py` had no entry-count bound, nothing summed the
bytes read and parsed, and the loop trusted `st_size`, which is 0 for a symlink to a
character device. One planted directory of under-cap decoy files (the three marker names
in a comment are enough to force the `ast.parse`) therefore cost seconds and about
1 GB per directory, unbounded in the number of files, on every audit, `--vet` and
`--monitor` cycle. A `.py` symlink to `/dev/zero` raised an uncaught `MemoryError`.

The fix answers False ("not our source, scan the tree" -- the SAFE direction, it never
grants identity) when the directory holds more than `_MAX_OWN_SOURCE_FILES` entries, when
the admitted bytes exceed `_MAX_OWN_SOURCE_TOTAL_BYTES`, or when any entry is not a
regular file, and it reads NOTHING once a bound has tripped.

These tests pin work counters (`ast.parse` / `Path.read_text` calls), not wall-clock, so a
reverted fix fails fast instead of spending minutes. The headroom pins at the bottom go
red BEFORE the real engine outgrows a cap, which is the point: growing past one silently
loses recognition of the tool's own install and the audit then self-flags on it.

Every test is offline and writes only under `tmp_path`.
"""
from __future__ import annotations

import ast
import os
import re
import time
import weakref
from pathlib import Path

import pytest

from clawseccheck import collector as _collector_mod
from clawseccheck.collector import (
    _MAX_OWN_SOURCE_BYTES,
    _MAX_OWN_SOURCE_FILES,
    _MAX_OWN_SOURCE_TOTAL_BYTES,
    _OWN_ENGINE_MARKER_STATEMENTS,
    _OWN_ENGINE_MARKERS,
    _is_own_source,
)

_REPO = Path(__file__).resolve().parent.parent

_ENGINE_TEXT = "\n".join(_OWN_ENGINE_MARKER_STATEMENTS)


def _checks_dir(root: Path) -> Path:
    d = root / "clawseccheck" / "checks"
    d.mkdir(parents=True)
    return d


def _write_engine(d: Path, name: str = "engine.py") -> Path:
    """A GENUINE engine file: real FunctionDef / Assign nodes for all three markers."""
    f = d / name
    f.write_text(_ENGINE_TEXT, encoding="utf-8")
    return f


def _write_decoys(d: Path, n: int) -> None:
    """`n` tiny files that name none of the markers (skipped on the raw-text check)."""
    for i in range(n):
        (d / f"d{i:05d}.py").write_text("x = 1\n", encoding="utf-8")


def _padded(head: str, size: int) -> bytes:
    """`head` followed by a comment, as EXACTLY `size` bytes (ASCII)."""
    body = head + "# "
    assert len(body) + 1 <= size
    return (body + "p" * (size - len(body) - 1) + "\n").encode("ascii")


def _normalise(text: str) -> str:
    """Comment markers and line wraps removed, so a sentence split over `# ` comment lines
    or a wrapped docstring reads as one line."""
    lines = [ln.strip().lstrip("#").strip() for ln in text.splitlines()]
    return " ".join(" ".join(lines).split())


def _module_prose() -> str:
    """The whole text of `collector.py` (docstrings AND comments), normalised."""
    return _normalise(Path(_collector_mod.__file__).read_text(encoding="utf-8"))


class _AstProxy:
    """`collector.ast` with only `parse` replaced. The GLOBAL `ast.parse` must stay real:
    pytest itself calls it while rendering a failure, so patching it globally turns any
    failing test into an INTERNALERROR instead of a readable report."""

    def __init__(self, parse):
        self.parse = parse

    def __getattr__(self, name):
        return getattr(ast, name)


def _spy_parse(monkeypatch, spy) -> None:
    monkeypatch.setattr(_collector_mod, "ast", _AstProxy(spy))


def _forbid_parse_and_read(monkeypatch, root: Path) -> None:
    """Make any parse or any read under `root` fail the test: a tripped bound reads NOTHING."""
    real_read = Path.read_text

    def no_parse(*_a, **_k):
        raise AssertionError("ast.parse ran although a directory bound had tripped")

    def no_read(self, *a, **k):
        if root in self.parents:
            raise AssertionError(f"read_text({self.name}) ran although a bound had tripped")
        return real_read(self, *a, **k)

    _spy_parse(monkeypatch, no_parse)
    monkeypatch.setattr(Path, "read_text", no_read)


def _forbid_reading(monkeypatch, *names: str) -> None:
    """Fail fast (instead of hanging / exhausting memory) if `names` are ever read."""
    real = Path.read_text

    def guarded(self, *a, **k):
        if self.name in names:
            raise AssertionError(f"read_text was asked to read non-regular {self.name}")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", guarded)


class TestFileCountBound:
    def test_exactly_the_cap_is_still_recognised(self, tmp_path):
        checks = _checks_dir(tmp_path)
        _write_decoys(checks, _MAX_OWN_SOURCE_FILES - 1)
        _write_engine(checks)
        assert len(list(checks.glob("*.py"))) == _MAX_OWN_SOURCE_FILES
        assert _is_own_source(tmp_path) is True

    def test_one_over_the_cap_is_not_own_source_and_reads_nothing(self, tmp_path, monkeypatch):
        checks = _checks_dir(tmp_path)
        _write_decoys(checks, _MAX_OWN_SOURCE_FILES)
        _write_engine(checks)  # a genuine engine file: True without the bound
        assert len(list(checks.glob("*.py"))) == _MAX_OWN_SOURCE_FILES + 1
        _forbid_parse_and_read(monkeypatch, tmp_path)
        start = time.perf_counter()
        assert _is_own_source(tmp_path) is False
        assert time.perf_counter() - start < 1.0

    def test_package_dir_layout_gets_the_same_bound(self, tmp_path, monkeypatch):
        """`<dir>/checks/` with `<dir>.name == "clawseccheck"` is the second call site."""
        pkg = tmp_path / "clawseccheck"
        checks = pkg / "checks"
        checks.mkdir(parents=True)
        _write_decoys(checks, _MAX_OWN_SOURCE_FILES - 1)
        _write_engine(checks)
        assert _is_own_source(pkg) is True  # positive control for this layout
        (checks / "one_more.py").write_text("x = 1\n", encoding="utf-8")  # cap + 1 now
        assert len(list(checks.glob("*.py"))) == _MAX_OWN_SOURCE_FILES + 1
        _forbid_parse_and_read(monkeypatch, tmp_path)
        assert _is_own_source(pkg) is False

    def test_a_flood_of_entries_is_not_listed_in_full(self, tmp_path, monkeypatch):
        checks = _checks_dir(tmp_path)
        flood = 5_000
        _write_decoys(checks, flood)
        _write_engine(checks)
        yielded = []
        real_glob = Path.glob

        def counting_glob(self, pattern):
            for entry in real_glob(self, pattern):
                yielded.append(entry)
                yield entry

        monkeypatch.setattr(Path, "glob", counting_glob)
        _forbid_parse_and_read(monkeypatch, tmp_path)
        start = time.perf_counter()
        assert _is_own_source(tmp_path) is False
        assert time.perf_counter() - start < 1.0
        assert len(yielded) <= _MAX_OWN_SOURCE_FILES + 1, (
            f"the listing was consumed for {len(yielded)} of {flood + 1} entries; it must "
            "stop as soon as the file-count bound trips"
        )

    def test_the_legacy_single_file_layout_is_unchanged(self, tmp_path):
        pkg = tmp_path / "clawseccheck"
        pkg.mkdir()
        (pkg / "checks.py").write_text(_ENGINE_TEXT, encoding="utf-8")
        assert _is_own_source(tmp_path) is True


class TestTotalBytesBound:
    def test_exactly_the_cap_is_allowed_and_one_byte_over_is_not(self, tmp_path, monkeypatch):
        cap = 10_000
        monkeypatch.setattr(_collector_mod, "_MAX_OWN_SOURCE_TOTAL_BYTES", cap)
        checks = _checks_dir(tmp_path)
        engine = _write_engine(checks)
        pad = checks / "pad.py"
        pad.write_bytes(_padded("", cap - engine.stat().st_size))
        assert engine.stat().st_size + pad.stat().st_size == cap
        assert _is_own_source(tmp_path) is True  # total == cap

        pad.write_bytes(_padded("", cap - engine.stat().st_size + 1))
        assert engine.stat().st_size + pad.stat().st_size == cap + 1
        _forbid_parse_and_read(monkeypatch, tmp_path)
        assert _is_own_source(tmp_path) is False  # total == cap + 1

    def test_real_size_files_each_under_the_per_file_cap_but_over_the_total(
        self, tmp_path, monkeypatch
    ):
        checks = _checks_dir(tmp_path)
        each = 1_700_000  # under _MAX_OWN_SOURCE_BYTES, five of them over the total cap
        assert each <= _MAX_OWN_SOURCE_BYTES
        n = _MAX_OWN_SOURCE_TOTAL_BYTES // each + 1
        assert n * each > _MAX_OWN_SOURCE_TOTAL_BYTES
        for i in range(n):
            (checks / f"big{i}.py").write_bytes(_padded("x = 1  ", each))
        _write_engine(checks)
        _forbid_parse_and_read(monkeypatch, tmp_path)
        start = time.perf_counter()
        assert _is_own_source(tmp_path) is False
        assert time.perf_counter() - start < 1.0

    def test_a_file_at_exactly_the_per_file_cap_is_still_admitted(self, tmp_path):
        checks = _checks_dir(tmp_path)
        (checks / "engine.py").write_bytes(_padded(_ENGINE_TEXT + "\n", _MAX_OWN_SOURCE_BYTES))
        assert (checks / "engine.py").stat().st_size == _MAX_OWN_SOURCE_BYTES
        assert _is_own_source(tmp_path) is True

    def test_oversized_files_do_not_consume_the_total_budget(self, tmp_path, monkeypatch):
        """A file over the per-file cap is skipped WHOLE and never counted toward the sum."""
        monkeypatch.setattr(_collector_mod, "_MAX_OWN_SOURCE_BYTES", 1_000)
        monkeypatch.setattr(_collector_mod, "_MAX_OWN_SOURCE_TOTAL_BYTES", 2_500)
        checks = _checks_dir(tmp_path)
        for i in range(3):
            (checks / f"big{i}.py").write_bytes(_padded("", 2_000))
        engine = _write_engine(checks)
        assert engine.stat().st_size <= 1_000
        assert 3 * 2_000 > 2_500  # their sum alone would trip the total cap
        assert _is_own_source(tmp_path) is True


class TestNonRegularEntries:
    """`st_size` says nothing about how much a read returns for a device or FIFO."""

    def test_symlink_to_dev_zero_is_not_own_source_and_is_never_read(
        self, tmp_path, monkeypatch
    ):
        checks = _checks_dir(tmp_path)
        _write_engine(checks)
        os.symlink("/dev/zero", checks / "z.py")
        assert (checks / "z.py").stat().st_size == 0  # the size cap cannot see it
        _forbid_reading(monkeypatch, "z.py")
        assert _is_own_source(tmp_path) is False

    def test_a_fifo_is_not_own_source_and_is_never_read(self, tmp_path, monkeypatch):
        checks = _checks_dir(tmp_path)
        _write_engine(checks)
        os.mkfifo(checks / "f.py")
        _forbid_reading(monkeypatch, "f.py")
        assert _is_own_source(tmp_path) is False

    def test_a_directory_named_like_a_source_is_not_own_source(self, tmp_path):
        checks = _checks_dir(tmp_path)
        _write_engine(checks)
        (checks / "sub.py").mkdir()
        assert _is_own_source(tmp_path) is False

    def test_a_broken_symlink_is_not_own_source(self, tmp_path):
        checks = _checks_dir(tmp_path)
        _write_engine(checks)
        os.symlink(tmp_path / "does-not-exist", checks / "gone.py")
        assert _is_own_source(tmp_path) is False

    def test_a_symlink_to_a_regular_file_is_still_followed(self, tmp_path):
        """Unchanged behaviour: `stat` follows the link, so a regular target is admitted."""
        checks = _checks_dir(tmp_path)
        real = tmp_path / "elsewhere.txt"
        real.write_text(_ENGINE_TEXT, encoding="utf-8")
        os.symlink(real, checks / "engine.py")
        assert _is_own_source(tmp_path) is True


class TestUnderCapDenseFile:
    def test_an_under_cap_dense_file_is_parsed_once_within_the_per_file_cap(
        self, tmp_path, monkeypatch
    ):
        """The per-file cap is UNCHANGED by design (the real engine's largest file is about
        0.94 MB, so a ~1 MB cap would lose recognition of the tool's own install), so an
        under-cap dense file is still parsed. What is pinned is the WORK: at most one
        parse, of a text no larger than the cap. The wall-clock ceiling is only a smoke
        test; the counters are the guard. Scaled down from the real 2 MB cap (about 9 s
        and 1.8 GB for a real-size `a;` file: 4.3 s/MB over the whole call, parse plus
        walk) by patching the cap; the logic is size-blind.
        """
        cap = 200_000
        monkeypatch.setattr(_collector_mod, "_MAX_OWN_SOURCE_BYTES", cap)
        checks = _checks_dir(tmp_path)
        header = "".join(f"# {m}\n" for m in _OWN_ENGINE_MARKERS)
        line = "a;" * 50 + "\n"
        body = line * ((cap - 10_000 - len(header)) // len(line))
        (checks / "x.py").write_text(header + body, encoding="utf-8")
        size = (checks / "x.py").stat().st_size
        assert cap - 20_000 < size <= cap

        parsed = []
        real_parse = ast.parse

        def spy(text, *a, **k):
            parsed.append(len(text))
            return real_parse(text, *a, **k)

        _spy_parse(monkeypatch, spy)
        start = time.perf_counter()
        assert _is_own_source(tmp_path) is False  # markers are only in a comment
        assert time.perf_counter() - start < 60.0  # smoke ceiling, not the guard
        assert len(parsed) == 1
        assert parsed[0] <= cap

    def test_each_tree_is_released_before_the_next_parse(self, tmp_path, monkeypatch):
        """Peak memory is ONE tree, not two: measured 1,262 MB -> 908 MB on three ~1 MB
        dense files. Pinned with a weakref rather than tracemalloc (stable on 3.9 and 3.12)."""
        checks = _checks_dir(tmp_path)
        for name in ("a.py", "b.py", "c.py"):  # each names a marker, so each is parsed
            (checks / name).write_text("# def vet_skill\nx = 1\n", encoding="utf-8")
        refs = []
        alive_when_next_parse_starts = []
        real_parse = ast.parse

        def spy(text, *a, **k):
            if refs:
                alive_when_next_parse_starts.append(refs[-1]() is not None)
            tree = real_parse(text, *a, **k)
            refs.append(weakref.ref(tree))
            return tree

        _spy_parse(monkeypatch, spy)
        assert _is_own_source(tmp_path) is False
        assert len(refs) == 3, "all three decoys must be parsed for this to measure anything"
        assert alive_when_next_parse_starts == [False, False], (
            "the previous file's tree was still alive while the next one was being parsed"
        )


class TestTheDisclosedResidualIsTheTrueOne:
    """C-135 rounds 2 and 3: the in-source RESIDUAL paragraph has been understated twice.
    Round 2: it priced the worst case of one `_is_own_source` call at a flat 2.7 s/MB
    (about 22 s at the total cap); on CPython 3.12 it was about 7x worse, because
    `ast.parse` is superlinear on f-string-dense source (`f"{a}";` repeated: 0.8 s at
    250 KB, 2.6 s at 500 KB, 9.5 s at 1 MB, 27-37 s at 1.99 MB, against ~2.9 s/MB for
    `a;`), so the PER-FILE cap dominates and the total cap multiplies it: 4 files of ~2 MB
    (7,999,948 B) cost 126-160 s CPU and ~940 MB for one call and the answer is still
    False. Round 3: it then called THAT shape "the worst shape that still fits every
    bound", but many interpolations per f-string (`f"{a}{a}...{a}";`) cost about 2x as
    much per file (55.7 s against 27.3 s for one 1,999,979-byte file, same load).

    The shape space is open, so the sound statement is a measured floor plus an explicit
    "this is not a ceiling", never a third "worst shape" number. These tests do not time
    anything (wall-clock is load-sensitive and this is a property of CPython, not of our
    code). They pin the DISCLOSURE to the caps: the prose has to name the measured shapes,
    refuse the word "worst", and the arithmetic has to agree with the constants, so that
    changing a cap, or a bound that starts cutting a shape short, turns this red and
    forces a re-measurement and a fresh ruling instead of leaving a stale number behind.
    To re-measure by hand: build files of `# <marker>` comment lines followed by `f"{a}";`
    (or `f"{a}{a}...{a}";`) repeated to 1,999,987 bytes under `<root>/clawseccheck/checks/`,
    then time `_is_own_source(<root>)` with `time.process_time()` on the interpreter in
    question.
    """

    @staticmethod
    def _doc() -> str:
        return " ".join((_is_own_source.__doc__ or "").split())

    def test_the_residual_names_the_measured_shapes(self):
        doc = self._doc()
        for needle in (
            "C-616 RESIDUAL",
            "SUPERLINEAR",
            "f-string",
            "CPython 3.12",
            "PER-FILE cap",
            "7,999,948 bytes",
            "126-160 s CPU",
            "_MAX_SKILLS",
            "Dave's decision",
            # C-135 round 3 / B1: the denser shape, measured at the full per-file cap.
            "interpolations per f-string",
            "1,999,979-byte file",
            "55.7 s CPU",
            "27.3 s",
        ):
            assert needle in doc, f"the C-616 residual paragraph no longer says {needle!r}"

    def test_the_residual_says_it_is_not_a_ceiling_and_refuses_a_third_worst_case(self):
        """B1: the residual named `f"{a}";` the worst shape; a denser one costs ~2x. The
        paragraph must say plainly that no figure in it is a ceiling."""
        doc = self._doc()
        assert "NOT A CEILING" in doc
        assert "no figure below is the worst case" in doc
        assert "Do not add a third" in doc
        assert "denser" in doc

    def test_no_prose_in_collector_calls_a_measured_shape_the_worst(self):
        """B1: the CONSTANTS comment said 'the worst shape that still fits every bound
        costs ~126-160 s'. Read the whole module text (comments included)."""
        text = _module_prose()
        assert "worst shape that still fits" not in text
        assert "NO ceiling is claimed" in text, (
            "the constants comment must state that no ceiling is claimed"
        )

    def test_the_residual_no_longer_quotes_the_flat_cost_as_the_worst_case(self):
        """The retracted sentence: worst case of ONE call as (total cap) x 2.7 s/MB."""
        doc = self._doc()
        assert "(admitted-bytes cap) x 2.7 s/MB" not in doc
        assert "can still make ONE call cost about" not in doc

    def test_the_disclosed_file_count_is_what_the_caps_admit(self):
        """'4 files of ~2 MB' is derived from the constants, not typed in twice."""
        n = _MAX_OWN_SOURCE_TOTAL_BYTES // _MAX_OWN_SOURCE_BYTES
        assert n == 4, (
            f"the caps now admit {n} full-size files, not the 4 the C-616 residual "
            "discloses -- re-measure the worst case and rewrite that paragraph"
        )
        assert f"{n} files of ~2 MB" in self._doc()
        # The disclosed 7,999,948 B is 4 x 1,999,987 B: under both caps, so no bound trips.
        assert n * 1_999_987 == 7_999_948
        assert 1_999_987 <= _MAX_OWN_SOURCE_BYTES
        assert 7_999_948 <= _MAX_OWN_SOURCE_TOTAL_BYTES

    @pytest.mark.parametrize(
        "unit",
        ['f"{a}";', 'f"' + "{a}" * 16 + '";'],
        ids=["one-interpolation", "sixteen-interpolations"],
    )
    def test_the_disclosed_shape_passes_every_bound_and_is_parsed_in_full(
        self, tmp_path, monkeypatch, unit
    ):
        """The shapes the paragraph prices are REACHABLE: n near-cap files of f-string-dense
        source (one interpolation per f-string, and the denser sixteen that C-135 round 3
        measured at about 2x the cost), markers only in a comment, trip no bound, and all n
        are parsed in full and the answer is False. Scaled down 20x with the real cap ratio
        preserved (the logic is size-blind; the real size would cost minutes)."""
        n = _MAX_OWN_SOURCE_TOTAL_BYTES // _MAX_OWN_SOURCE_BYTES
        per_file = 100_000
        monkeypatch.setattr(_collector_mod, "_MAX_OWN_SOURCE_BYTES", per_file)
        monkeypatch.setattr(
            _collector_mod,
            "_MAX_OWN_SOURCE_TOTAL_BYTES",
            per_file * _MAX_OWN_SOURCE_TOTAL_BYTES // _MAX_OWN_SOURCE_BYTES,
        )
        checks = _checks_dir(tmp_path)
        header = "".join(f"# {m}\n" for m in _OWN_ENGINE_MARKERS)
        body = unit * ((per_file - 13 - len(header)) // len(unit))
        for i in range(n):
            (checks / f"hostile{i}.py").write_text(header + body, encoding="utf-8")
        sizes = [f.stat().st_size for f in checks.glob("*.py")]
        assert len(sizes) == n and max(sizes) <= per_file and min(sizes) > per_file - 50
        assert sum(sizes) <= per_file * _MAX_OWN_SOURCE_TOTAL_BYTES // _MAX_OWN_SOURCE_BYTES

        parsed = []
        real_parse = ast.parse

        def spy(text, *a, **k):
            parsed.append(len(text))
            return real_parse(text, *a, **k)

        _spy_parse(monkeypatch, spy)
        assert _is_own_source(tmp_path) is False  # markers sit only in a comment
        assert len(parsed) == n, "a bound cut the disclosed worst shape short -- re-disclose"
        assert min(parsed) > per_file - 50, "each parse must be of a near-cap file"


class TestHeadroomOnTheRealPackage:
    """These go red BEFORE the real engine outgrows a cap (recognition of the tool's own
    install would be lost first, and the audit would then self-flag CRITICAL on itself)."""

    _MSG = (
        " -- raise the cap deliberately, and re-measure the parse cost first: it is NOT a "
        "flat 2.7 s/MB -- on Python 3.12 an f-string-dense file is superlinear (9.5 s at "
        "1 MB, 27-37 s at 1.99 MB), 4 such files of ~2 MB cost 126-160 s CPU for ONE call "
        "and a denser interpolation shape about twice that; NO ceiling is claimed. See the "
        "C-616 RESIDUAL in _is_own_source's docstring"
    )

    @staticmethod
    def _real_engine_files():
        return sorted((_REPO / "clawseccheck" / "checks").glob("*.py"))

    def test_the_real_package_is_still_recognised(self):
        assert _is_own_source(_REPO) is True

    def test_file_count_has_2x_headroom(self):
        n = len(self._real_engine_files())
        assert n * 2 <= _MAX_OWN_SOURCE_FILES, (
            f"engine has {n} files vs cap {_MAX_OWN_SOURCE_FILES}" + self._MSG
        )

    def test_largest_file_has_1_5x_headroom(self):
        biggest = max(f.stat().st_size for f in self._real_engine_files())
        assert biggest * 1.5 <= _MAX_OWN_SOURCE_BYTES, (
            f"largest engine file is {biggest} B vs cap {_MAX_OWN_SOURCE_BYTES}" + self._MSG
        )

    def test_total_bytes_have_1_5x_headroom(self):
        total = sum(f.stat().st_size for f in self._real_engine_files())
        assert total * 1.5 <= _MAX_OWN_SOURCE_TOTAL_BYTES, (
            f"engine is {total} B vs total cap {_MAX_OWN_SOURCE_TOTAL_BYTES}" + self._MSG
        )

    def test_the_caps_are_ordered_sanely(self):
        assert _MAX_OWN_SOURCE_BYTES < _MAX_OWN_SOURCE_TOTAL_BYTES
        assert _MAX_OWN_SOURCE_FILES >= 1


class TestQuotedEngineFiguresAreTheRealOnes:
    """C-135 round 3 / B2: the new prose quoted the RELEASED 4.3.1 engine (4,131,357 B,
    largest 934,306) after the change was ported onto a dev tree holding 4,198,709 B and
    943,255. Exact byte counts go stale with every commit that touches `checks/`, so the
    prose quotes ROUNDED figures in one fixed phrase ("N files, about X MB in all, largest
    about Y MB") and a headroom ratio rounded to one decimal; each must match the real
    package (file count exactly, sizes within 3%, the ratio exactly as rounded). It goes
    red when the engine grows enough for the quoted figure to be stale, which is when the
    prose must be restated."""

    _TRIPLE = re.compile(
        r"(\d+) files, about (\d+(?:\.\d+)?) MB in all, largest about (\d+(?:\.\d+)?) MB"
    )
    _HEADROOM = re.compile(r"so (32|8 MB) is ~(\d+\.\d+)x headroom")

    @staticmethod
    def _real():
        sizes = [f.stat().st_size for f in (_REPO / "clawseccheck" / "checks").glob("*.py")]
        return len(sizes), sum(sizes), max(sizes)

    def test_every_quoted_engine_triple_matches_the_real_package(self):
        found = self._TRIPLE.findall(_module_prose())
        assert len(found) >= 3, (
            f"expected the rounded engine-size phrase in the constants comment, the "
            f"_is_own_source docstring and the PERFORMANCE comment; found {len(found)}"
        )
        n_real, total, largest = self._real()
        for n, mb_total, mb_largest in found:
            assert int(n) == n_real, f"prose says {n} engine files, the package has {n_real}"
            assert abs(float(mb_total) * 1_000_000 - total) <= 0.03 * total, (
                f"prose says about {mb_total} MB in all, the package has {total} B"
            )
            assert abs(float(mb_largest) * 1_000_000 - largest) <= 0.03 * largest, (
                f"prose says largest about {mb_largest} MB, the package has {largest} B"
            )

    def test_the_quoted_headroom_ratios_match_the_real_package(self):
        found = self._HEADROOM.findall(_module_prose())
        assert found, "the constants comment no longer states its headroom ratios"
        n_real, total, _largest = self._real()
        for cap, ratio in found:
            true = _MAX_OWN_SOURCE_FILES / n_real if cap == "32" else (
                _MAX_OWN_SOURCE_TOTAL_BYTES / total
            )
            assert float(ratio) == round(true, 1), (
                f"prose says the {cap} cap has ~{ratio}x headroom, the package gives {true:.3f}x"
            )


class TestUsageDocMatchesTheTotalBound:
    """C-135 round 3 / B3: docs/USAGE.md said an engine folder with 'more than 8 MB of
    them' is not matched. A file over the per-file cap is skipped WHOLE and never counts
    toward the total, so 9 MB of `*.py` made of three 3 MB files is still matched. The
    in-source docstring was precise; the user doc was not."""

    def test_files_over_the_per_file_cap_do_not_count_toward_the_total(
        self, tmp_path, monkeypatch
    ):
        checks = _checks_dir(tmp_path)
        _write_engine(checks)
        names = []
        for i in range(3):
            huge = checks / f"huge{i}.py"
            huge.write_bytes(b"")
            os.truncate(huge, 3_000_000)  # sparse; over the per-file cap, so never read
            names.append(huge.name)
        assert sum(p.stat().st_size for p in checks.glob("*.py")) > _MAX_OWN_SOURCE_TOTAL_BYTES
        _forbid_reading(monkeypatch, *names)
        assert _is_own_source(tmp_path) is True

    def test_the_usage_sentence_states_the_per_file_qualifier(self):
        text = " ".join((_REPO / "docs" / "USAGE.md").read_text(encoding="utf-8").split())
        start = text.index("an engine folder with more than ")
        seg = text[start : text.index(" is not matched", start)]

        def mb(n: int) -> str:
            return f"{n // 1_000_000} MB"

        assert f"more than {_MAX_OWN_SOURCE_FILES} `*.py` files" in seg
        want = (
            f"more than {mb(_MAX_OWN_SOURCE_TOTAL_BYTES)} of `*.py` files that are each "
            f"under {mb(_MAX_OWN_SOURCE_BYTES)}"
        )
        assert want in seg, f"USAGE.md no longer says {want!r}: {seg!r}"
        assert "does not count" in seg


@pytest.mark.parametrize("n", [0, 1])
def test_a_directory_without_an_engine_is_simply_false(tmp_path, n):
    checks = _checks_dir(tmp_path)
    _write_decoys(checks, n)
    assert _is_own_source(tmp_path) is False
