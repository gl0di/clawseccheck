"""B-519 — the suite must not write into the user's real ``~/.clawseccheck/`` store.

It had been doing so since the store existed. Measured on the maintainer's box before
``conftest._isolate_local_store`` landed: **4,414 of the 4,547 rows** in the real
``history.jsonl`` (97%, 937 KB) carried ``source="test"``, burying 132 genuine audits in
suite exhaust. ``--trend`` reads that file, so the user's own security history was mostly
ours.

What made it survive: F-128 tags test rows ``source="test"`` (``history._run_source``
consults ``PYTEST_CURRENT_TEST``), and a tag reads like containment. It is not. The row is
still appended, still hashed into the chain, still counted by anything that does not
filter.

Three layers here, and the third is the one that matters:

1. the redirect is actually in effect (``$HOME`` is a tmp dir during a test);
2. an end-to-end write through the shipped default path lands there and the real store is
   byte-unchanged — not a trace, the real ``history.record()``;
3. **no test reaches the real machine except through ``_realhome.REAL_HOME``.** This is the
   non-growable part. A blanket redirect would have silently turned four live guards into
   vacuous passes (the fleet-FP baseline, schema grounding against the installed dist, and
   two real-fleet SKILL.md sweeps), which is the failure mode this project keeps finding:
   a fix that removes the symptom by disabling the detector. The AST scan below fails the
   build if a new ``Path.home()`` or ``expanduser("~...")`` appears in ``tests/``.

The scan is AST-based, not grep-based, on purpose: the corpus is full of fixture *content*
like ``"open(os.path.expanduser('~/.aws/credentials'))"`` — strings being scanned by a
check, not calls being made. A textual guard would drown in them (21 files match the text;
0 make the call).

Stdlib-only, offline, writes nothing outside tmp_path.
"""
from __future__ import annotations

import ast
import os
import pathlib
from pathlib import Path

from clawseccheck import history
from clawseccheck.catalog import FAIL, HIGH, Finding
from clawseccheck.scoring import compute
from _realhome import REAL_HOME, real_path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent

# One entry, and meant to stay that way. Any other name here is a test that reads the real
# machine WITHOUT going through REAL_HOME — i.e. one the redirect silently broke. Add a
# name only with the reason, and prefer fixing the call site.
_ALLOWED_REAL_HOME_READERS: dict[str, str] = {
    # This module asserts the redirect is in effect, which it can only do by reading the
    # ambient home and showing it is NOT the real one. Excluding itself is the exception
    # the rule is built on, not a hole in it.
    "test_b519_store_isolation.py": "asserts the redirect itself",
    # The sanctioned definition site: REAL_HOME has to be captured from the ambient home
    # once, before the redirect, and everything else reads it from there.
    "_realhome.py": "defines REAL_HOME",
}


# ── 1: the redirect is live ──────────────────────────────────────────────────

def test_home_is_redirected_away_from_the_real_one():
    assert Path.home() != REAL_HOME
    assert Path(os.environ["HOME"]) == Path.home()
    assert Path.home().is_dir()


def test_real_home_still_resolves_the_shipped_store_constant():
    """The escape hatch has to actually reach the real store, or the guards it exists
    for (fleet-FP baseline, installed dist) would be testing a tmp dir."""
    assert real_path(history.DEFAULT_HISTORY) == REAL_HOME / ".clawseccheck/history.jsonl"
    assert real_path("~") == REAL_HOME
    assert real_path("/etc/passwd") == Path("/etc/passwd")


# ── 2: an end-to-end default-path write stays out of the real store ──────────

def _score():
    return compute([Finding("B1", "t", HIGH, FAIL, "d", "f", "fw")])


def test_default_path_history_write_lands_in_the_isolated_home():
    """The real ``record()`` on its real default path — the exact call the suite makes
    thousands of times."""
    real_store = REAL_HOME / ".clawseccheck" / "history.jsonl"
    before = real_store.stat().st_size if real_store.is_file() else None

    history.record(_score())

    written = Path.home() / ".clawseccheck" / "history.jsonl"
    assert written.is_file(), "record() did not write under the redirected home"
    assert written.read_text(encoding="utf-8").strip(), "wrote an empty history row"

    after = real_store.stat().st_size if real_store.is_file() else None
    assert after == before, (
        f"record() grew the REAL store at {real_store} ({before} -> {after} bytes)")


def test_the_default_argument_is_still_a_tilde_string():
    """Why the fix is a $HOME redirect and not six monkeypatched constants.

    ``record(score, path=DEFAULT_HISTORY)`` binds its default at def time, so patching
    ``history.DEFAULT_HISTORY`` cannot reach it. What IS bound is the unexpanded string,
    expanded by ``expanduser()`` at write time — which is why redirecting $HOME works and
    catches every store path at once, including ones added later.
    """
    import inspect
    default = inspect.signature(history.record).parameters["path"].default
    assert isinstance(default, str) and default.startswith("~/"), (
        "if this stops being a lazily-expanded '~' string, the $HOME redirect no longer "
        "covers it and this module's premise needs re-checking")


# ── 3: no test reaches the real machine except via REAL_HOME ─────────────────

def _real_home_reads(path: pathlib.Path) -> list[tuple[int, str]]:
    """Calls that resolve against the ambient home: ``Path.home()``,
    ``os.path.expanduser("~...")`` and ``Path("~...").expanduser()``."""
    found: list[tuple[int, str]] = []
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if (func.attr == "home" and isinstance(func.value, ast.Name)
                and func.value.id == "Path"):
            found.append((node.lineno, "Path.home()"))
        elif func.attr == "expanduser":
            arg = node.args[0] if node.args else None
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) \
                    and arg.value.startswith("~"):
                found.append((node.lineno, f"expanduser({arg.value!r})"))
            elif arg is None:
                recv = func.value
                if isinstance(recv, ast.Call) and recv.args \
                        and isinstance(recv.args[0], ast.Constant) \
                        and isinstance(recv.args[0].value, str) \
                        and recv.args[0].value.startswith("~"):
                    found.append((node.lineno, f"Path({recv.args[0].value!r}).expanduser()"))
    return found


def test_no_test_reads_the_ambient_home_directly():
    offenders: dict[str, list[tuple[int, str]]] = {}
    for path in sorted(TESTS_DIR.glob("*.py")):
        if path.name in _ALLOWED_REAL_HOME_READERS:
            continue
        hits = _real_home_reads(path)
        if hits:
            offenders[path.name] = hits
    assert not offenders, (
        "these read the ambient $HOME, which the suite redirects to a tmp dir — the call "
        "will not find what it is looking for and the test will pass vacuously. Use "
        "`from _realhome import REAL_HOME` (or `real_path`) when the test is genuinely "
        f"about this machine: {offenders}")


def test_the_scanner_can_see_what_it_is_looking_for():
    """A guard nobody has watched fail is not a guard. Proven on synthetic sources so it
    cannot silently degrade into `assert not {}` if the AST shapes change."""
    import tempfile
    samples = [
        ("p = Path.home() / '.openclaw'", "Path.home()"),
        ("import os\nx = os.path.expanduser('~/.clawseccheck/history.jsonl')", "expanduser"),
        ("p = Path('~/.config').expanduser()", "expanduser"),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        for i, (src, needle) in enumerate(samples):
            probe = Path(tmp) / f"probe_{i}.py"
            probe.write_text(src, encoding="utf-8")
            hits = _real_home_reads(probe)
            assert hits, f"scanner missed: {src!r}"
            assert any(needle in h[1] for h in hits), (src, hits)
        # ...and does NOT fire on the fixture-content shape that fills this corpus.
        inert = Path(tmp) / "inert.py"
        inert.write_text(
            'BLOB = "creds = open(os.path.expanduser(\'~/.aws/credentials\')).read()"\n',
            encoding="utf-8")
        assert _real_home_reads(inert) == []
