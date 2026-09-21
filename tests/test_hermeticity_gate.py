"""Hermeticity ledger comparator (CLAWSECCHECK-hermeticity).

The instrument itself (the two-halves ``sys.addaudithook``, opt-in via
``CSC_HERMETICITY_LEDGER``) lives in ``conftest.py`` (parent half: ``pytest_configure``/
``pytest_unconfigure``) and ``tests/_hermledger.py`` (child half: the generated
``sitecustomize.py`` + ``classify()``). This module is only the comparison: read the
ledger the instrument wrote, bucket every recorded path, and decide what is a violation.

Same spirit as ``tests/test_module_layout.py`` / ``tests/test_public_boundary.py`` /
``tests/test_schema_grounding.py``: an explicit, reasoned exemption list
(``tests/hermeticity_allowlist.txt``, one entry per line, each dated and reasoned in its
own comment) rather than a silent tolerance, and a failure message that says WHY the
rule exists, not just that it broke.

Two thresholds, matching the FAILURE MODE the ledger was designed against:
  * a WRITE-shaped event outside repo/tmp is ALWAYS a hard FAIL -- no allowlist, no
    grandfathering. There is no legitimate reason for a hermetic test to write anywhere
    else, so `CSC_HERMETICITY_LEDGER=1` and `=strict` treat writes identically.
  * a READ-shaped event outside the computed-safe categories (repo / tempfile.gettempdir
    / this interpreter's own stdlib+site-packages, computed live -- see
    ``_hermledger.classify``) and not in the allowlist is a hard FAIL only under
    `CSC_HERMETICITY_LEDGER=strict`. A plain `=1` run WARNS (prints the diff, exits 0) --
    for local investigation, same idiom as `scripts/fleet_fp_gate.py compare` reporting
    without blocking.

This guard is NOT wired into the default `pytest -q` path (CSC_HERMETICITY_LEDGER is
unset there) and is NOT a required CI job today -- see the two dated entries in
tests/hermeticity_allowlist.txt for why strict mode would currently start red, and
CLAUDE.md's testing protocol for where a gate like this (real cost, not per-commit)
belongs once it is wired up.
"""
from __future__ import annotations

import fnmatch
import os
import tempfile
from pathlib import Path

import pytest

from _hermledger import classify
from _realhome import REAL_HOME

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PATH = Path(__file__).resolve().parent / "hermeticity_allowlist.txt"


def _load_allowlist(path: Path) -> list[str]:
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def _read_ledger(path: Path):
    """Yield (category, raw_path, test_id, child_home) tuples, skipping any line that
    does not have exactly 4 tab-separated fields.

    A skip (rather than a hard parse error) is deliberate: the buffered atexit flush is
    one ``os.write()`` per child, practically but not FORMALLY atomic against a sibling
    process's concurrent flush (tests/_hermledger.py's docstring). A torn line from two
    interleaved writes should not crash the comparator; it should be rare enough that
    losing that one line does not hide a real violation, and _skipped below makes the
    count visible rather than silent.
    """
    skipped = 0
    rows = []
    text = path.read_text(encoding="utf-8", errors="surrogateescape")
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            skipped += 1
            continue
        rows.append(tuple(fields))
    return rows, skipped


def _normalize_token(norm_path: str, child_home: str) -> str:
    """Replace a $HOME-relative prefix with the literal token ``"$HOME"``.

    Tries the CHILD's own reported ``$HOME`` first (it may differ from the session
    default -- conftest's `_isolate_local_store` sets one fake home for the whole
    session, but an individual test may override HOME again for a single subprocess
    call, e.g. tests/test_b582_viewer_chain_provenance.py's `_run` helper). Falls back
    to this MACHINE's real home (`tests/_realhome.REAL_HOME`) because at least one known
    violation (the deptree walk) resolves a real, machine-global path via `$PATH` /
    `shutil.which()` -- entirely independent of whatever HOME that specific subprocess
    was given -- so a fake-HOME-only normalizer would never match it and the allowlist
    entry for it would need a raw, unnormalized path instead.
    """
    for home in (child_home, str(REAL_HOME)):
        if not home:
            continue
        home = os.path.normpath(home)
        if norm_path == home:
            return "$HOME"
        prefix = home + os.sep
        if norm_path.startswith(prefix):
            return "$HOME" + os.sep + norm_path[len(prefix):]
    return norm_path


def _real_machine_node_ids(session) -> set:
    return {
        item.nodeid
        for item in session.items
        if item.get_closest_marker("real_machine") is not None
    }


def test_no_unexplained_paths_outside_tmp_and_repo(request):
    """The gated comparison. Skips outright when the instrument was not enabled for
    this run -- CSC_HERMETICITY_LEDGER is opt-in (conftest.pytest_configure), so a plain
    `pytest -q` never reaches the assertions below."""
    ledger = os.environ.get("CSC_HERM_LEDGER_PATH")
    if not ledger or not Path(ledger).exists():
        pytest.skip("CSC_HERMETICITY_LEDGER not enabled for this run")

    allow = _load_allowlist(ALLOWLIST_PATH)
    real_machine_ids = _real_machine_node_ids(request.session)
    rows, skipped_lines = _read_ledger(Path(ledger))

    write_violations = []
    read_violations = []
    for cat, raw_path, test_id, child_home in rows:
        if any(test_id.startswith(nid) for nid in real_machine_ids):
            # Deliberately about THIS machine's real fleet/home content -- a global
            # diff would either mask genuine new violations under that noise or need
            # an ever-growing literal-path allowlist. Dropped entirely, not just
            # exempted from one bucket, matching the design's per-test attribution.
            continue

        norm = classify(raw_path, str(REPO_ROOT))
        if norm in ("<repo>", "<tmp>", "<site-packages>"):
            continue

        token = _normalize_token(norm, child_home)
        if cat == "W":
            # No allowlist, no grandfathering (FAILURE MODE, always) -- a hermetic
            # test has no legitimate reason to write outside repo/tmp.
            write_violations.append((token, test_id))
            continue
        if any(fnmatch.fnmatchcase(token, pat) for pat in allow):
            continue
        read_violations.append((token, test_id))

    strict = os.environ.get("CSC_HERMETICITY_LEDGER") == "strict"

    if write_violations:
        lines = "\n".join(
            f"  W {p} ({t})" for p, t in sorted(set(write_violations))[:50]
        )
        pytest.fail(
            "hermeticity ledger: WRITE-shaped event(s) outside the repo/tmp: no test "
            "has a legitimate reason to write anywhere else, so this is a hard FAIL "
            "regardless of strict mode:\n" + lines
        )

    if read_violations:
        lines = "\n".join(
            f"  R {p} ({t})" for p, t in sorted(set(read_violations))[:50]
        )
        msg = (
            f"hermeticity ledger: {len(read_violations)} READ-shaped path(s) outside "
            "the repo, tempfile.gettempdir(), and this interpreter's own stdlib/"
            "site-packages, and not in tests/hermeticity_allowlist.txt -- meaning some "
            "test depends on undeclared machine state that will not be there (or will "
            "differ) on another box or a clean CI runner:\n" + lines +
            "\n\nEither the test should build its own fixture instead of reading real "
            "machine state, or -- if the path is a genuinely universal extra (like "
            "/proc/**) or a diagnosed, already-being-fixed violation -- add a dated, "
            "reasoned line to tests/hermeticity_allowlist.txt."
        )
        if strict:
            pytest.fail(msg)
        print(f"[hermeticity WARN]\n{msg}")

    if skipped_lines:
        print(f"[hermeticity] {skipped_lines} malformed ledger line(s) skipped")


# --------------------------------------------------------------------------------------
# Always-on, offline, deterministic sanity checks -- cheap (no ledger file needed), so
# they run on every `pytest -q` regardless of CSC_HERMETICITY_LEDGER, the same way
# test_schema_grounding.py's shipped-manifest guard is unconditional while the
# recon/dist-comparison layers are local-only.

def test_allowlist_file_parses_and_is_nonempty():
    patterns = _load_allowlist(ALLOWLIST_PATH)
    assert patterns, "hermeticity_allowlist.txt parsed empty -- the READ-side gate is inert."
    for pat in patterns:
        assert pat.startswith("/") or pat.startswith("$HOME"), (
            f"{pat!r}: allowlist entries are absolute-style patterns ('/proc/**') or "
            "$HOME-relative ('$HOME/.npm-global/**') -- see the file's own header "
            "for why a raw '/home/<user>/...' literal must never appear here."
        )
        assert "/home/" not in pat, (
            f"{pat!r}: a raw /home/<user>/ path leaked into a committed allowlist "
            "entry -- normalize it to the $HOME token instead."
        )


def test_classify_recognizes_repo_tmp_and_interpreter_roots():
    """Unit-level check of _hermledger.classify(), independent of the ledger file --
    proves the three computed-safe categories actually match what they claim to,
    rather than only being exercised indirectly through a gated, skip-by-default test."""
    repo = str(REPO_ROOT)
    assert classify(str(REPO_ROOT / "conftest.py"), repo) == "<repo>"
    assert classify(os.path.join(tempfile.gettempdir(), "x", "y"), repo) == "<tmp>"
    # os.__file__ is always somewhere under this running interpreter's OWN stdlib root
    # (sysconfig.get_paths()["stdlib"]), whatever that root happens to be on this box —
    # exactly the "computed live, not hardcoded" property _safe_roots() exists for.
    assert classify(os.__file__, repo) == "<site-packages>"
    # A path with nothing to do with any of the three stays a raw path, unclassified --
    # the comparator is the one that decides whether an unclassified path is fine
    # (allowlisted) or a violation.
    assert classify("/etc/hostname", repo) == "/etc/hostname"
