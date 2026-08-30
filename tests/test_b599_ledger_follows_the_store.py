"""B-599: `--data-dir` moved three of the store's four files and stamped the real one.

The flag's own help text promised the opposite — *"the three move together, so a scratch run
cannot half-redirect and write into your real history"* — while the coverage/freshness ledger
followed `HOME` regardless. So scratch runs, CI runs and the test suite itself wrote today's
date into the user's real `~/.clawseccheck/coverage.json`.

Caught during the 2026-08-20 live-agent work, and caught by accident: runs I believed were
sandboxed under `--data-dir` moved the real ledger's mtime three minutes after the agent's
session had ended.

It is a correctness bug, not hygiene. `ledger.freshness_notice` reads this file to tell the
user when they last exercised a capability, so a stamp they never earned makes the tool report
coverage that did not happen — Golden Rule #4, reached through the Golden Rule #2 violation
`_record_run`'s own docstring cites.

The tree already believed the four files live together: `_run_purge` derives the store from
`--history`'s parent and `_PURGE_FILENAMES` has always listed `coverage.json` among the files
it deletes from there. Only the writer disagreed. Both now derive it from one helper, which is
what this file pins — the invariant, not the plumbing.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest

from clawseccheck.ledger import load_ledger, record_run

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")


def _run(tmp_path: Path, *args: str, store: str | None = "store"):
    """A run whose HOME is redirected, so 'did it touch the real store' is observable."""
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    extra = ["--data-dir", str(tmp_path / store)] if store else []
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", VULN, *extra, *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)})


def _home_store(tmp_path: Path) -> Path:
    return tmp_path / "home" / ".clawseccheck"


# ------------------------------------------------------------------ the headline case

def test_the_ledger_lands_in_the_data_dir(tmp_path):
    _run(tmp_path, "--full")
    assert (tmp_path / "store" / "coverage.json").exists()


def test_nothing_reaches_the_real_store(tmp_path):
    """The half of the promise that was broken. Asserted on the HOME store's existence
    rather than on the data-dir's contents: a run can put a file in the right place and
    still have put one in the wrong place too."""
    _run(tmp_path, "--full")
    assert not _home_store(tmp_path).exists(), \
        f"leaked into the real store: {list(_home_store(tmp_path).iterdir())}"


def test_without_data_dir_the_default_still_applies(tmp_path):
    """The fix must redirect, not relocate. A user who passes no flag keeps their ledger
    exactly where it has always been."""
    _run(tmp_path, "--dryrun", store=None)
    assert (_home_store(tmp_path) / "coverage.json").exists()


# ------------------------------------------------------- writer and reader agree

def test_a_capability_recorded_in_the_store_is_read_back_from_it(tmp_path):
    """Moving the write alone would have been worse than the bug: the run would write to
    the scratch store and read freshness from the real one."""
    _run(tmp_path, "--dryrun")               # records "self_test" into the store
    out = _run(tmp_path).stdout
    assert "Coverage gap: prompt-injection" not in out


def test_an_empty_store_still_reports_the_gap(tmp_path):
    """Guards the assertion above from being a false pass — if the notice were merely
    suppressed, both tests would look identical."""
    out = _run(tmp_path, store="fresh-store").stdout
    assert "Coverage gap: prompt-injection" in out


# --------------------------------------------------------------- the ledger API

@pytest.mark.parametrize("capability", ["self_test", "vet", "vet_mcp", "vet_plugin",
                                        "vet_source", "behavioral"])
def test_every_capability_key_honours_the_path(tmp_path, capability):
    """All nineteen call sites funnel through one helper, so covering the keys at the
    ledger's own boundary covers them all — and names them, so a new key has to appear
    here to be considered done."""
    dest = str(tmp_path / "c.json")
    record_run(capability, path=dest, today=date(2026, 1, 1))
    assert load_ledger(path=dest) == {capability: "2026-01-01"}
    assert not _home_store(tmp_path).exists()


def test_a_second_write_preserves_the_first(tmp_path):
    """The trap inside the fix itself: `record_run` re-reads the ledger before writing, and
    threading the path into the write but NOT that read would silently drop every other
    capability's date on the first redirected write."""
    dest = str(tmp_path / "m.json")
    record_run("self_test", path=dest, today=date(2026, 1, 1))
    record_run("vet_mcp", path=dest, today=date(2026, 2, 2))
    assert load_ledger(path=dest) == {"self_test": "2026-01-01", "vet_mcp": "2026-02-02"}


def test_path_wins_over_home(tmp_path):
    """Both knobs exist — `home` predates this and tests still use it. Precedence is stated
    rather than left to whichever branch happens to come first."""
    dest = str(tmp_path / "explicit.json")
    record_run("self_test", home=str(tmp_path / "ignored"), path=dest,
               today=date(2026, 3, 3))
    assert Path(dest).exists()
    assert not (tmp_path / "ignored").exists()


# ------------------------------------------------------ one store, one definition

def test_purge_deletes_the_ledger_it_can_now_find(tmp_path):
    """`_PURGE_FILENAMES` always listed coverage.json and `_run_purge` always looked in
    --history's parent — so under --data-dir purge was hunting for a file the writer had
    put somewhere else entirely."""
    _run(tmp_path, "--full")
    ledger = tmp_path / "store" / "coverage.json"
    assert ledger.exists()
    _run(tmp_path, "--purge", "--yes")
    assert not ledger.exists()


def test_the_store_dir_has_exactly_one_definition():
    """Source-level guard. The bug existed because two places computed "where local state
    lives" and one of them did not exist at all. If a third appears, it will drift the same
    way — and the next artifact added to the store will be the one that leaks."""
    src = (REPO_ROOT / "clawseccheck" / "cli.py").read_text(encoding="utf-8")
    assert src.count('Path(args.history).expanduser().parent') == 1, \
        "the store dir is computed somewhere other than _store_dir()"
    assert "def _store_dir(args)" in src


def test_an_explicit_history_path_takes_the_ledger_with_it(tmp_path):
    """--history wins over --data-dir by documented contract, and the ledger follows the
    history because that is where --purge looks for it. The alternative — the ledger
    staying behind — is this bug again in a narrower shape."""
    hist = tmp_path / "elsewhere" / "h.jsonl"
    hist.parent.mkdir(parents=True)
    _run(tmp_path, "--dryrun", "--history", str(hist))
    assert (hist.parent / "coverage.json").exists()
    assert not (tmp_path / "store" / "coverage.json").exists()


# ---------------------------------------------------------------------------
# B-599, second half: the READER. Added 2026-08-30.
#
# `d3bd32e` moved the WRITE side onto the run's own store and this file pinned it. One
# reader was left behind: `--analyze-trajectory` renders a self-test corroboration line
# from the coverage ledger, and it resolved that ledger from `$HOME` no matter what
# `--data-dir` said. So a scratch or CI run reported corroboration derived from the
# operator's real machine — the tool asserting an activity that did not happen in the
# store the run was using.
#
# The same shape as B-683 earlier in the week: a fix that closed one side of a symmetry
# and left the other, where each side alone looks complete.
# ---------------------------------------------------------------------------

def _analyze(home_dir, data_dir, openclaw_home):
    env = dict(os.environ)
    env["HOME"] = str(home_dir)
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--analyze-trajectory", "",
         "--home", str(openclaw_home), "--data-dir", str(data_dir)],
        cwd=REPO_ROOT, capture_output=True, text=True, env=env,
    )
    return proc.stdout + proc.stderr


def _ledger_fixture(tmp_path, *, home_says_run: bool, store_says_run: bool):
    fake_home = tmp_path / "fakehome"
    (fake_home / ".clawseccheck").mkdir(parents=True)
    store = tmp_path / "store"
    store.mkdir()
    openclaw = tmp_path / "oc"
    openclaw.mkdir()
    (openclaw / "openclaw.json").write_text('{"mcp": {"servers": {}}}', encoding="utf-8")
    ran = '{"self_test": "2026-08-30", "_schema": "1"}'
    idle = '{"_schema": "1"}'
    (fake_home / ".clawseccheck" / "coverage.json").write_text(
        ran if home_says_run else idle, encoding="utf-8")
    (store / "coverage.json").write_text(
        ran if store_says_run else idle, encoding="utf-8")
    return fake_home, store, openclaw


_LEDGER_CLAIM = "local ledger shows a self-test capability was run"


def test_the_reader_ignores_the_real_home_ledger(tmp_path):
    """The defect: `$HOME`'s ledger said a self-test ran, the run's own store said it did
    not, and the report believed `$HOME`."""
    fake_home, store, oc = _ledger_fixture(
        tmp_path, home_says_run=True, store_says_run=False)
    out = _analyze(fake_home, store, oc)
    assert _LEDGER_CLAIM not in out, out[:1200]


def test_the_reader_uses_the_store_this_run_was_given(tmp_path):
    """The other direction, and the control: a fix that simply stopped reading any ledger
    would pass the test above and fail this one."""
    fake_home, store, oc = _ledger_fixture(
        tmp_path, home_says_run=False, store_says_run=True)
    out = _analyze(fake_home, store, oc)
    assert _LEDGER_CLAIM in out, out[:1200]


def test_the_reader_and_the_writer_resolve_the_same_file(tmp_path):
    """Pinned as one question rather than two.

    `_coverage_path` is the single resolver; the write side, the freshness notice and now
    this reader all go through it. Two call sites resolving a store independently is how
    half of a redirect goes missing, which is the whole of B-599.
    """
    from clawseccheck.cli import _coverage_path

    args = SimpleNamespace(history=str(tmp_path / "s" / "history.jsonl"))
    assert _coverage_path(args) == str(tmp_path / "s" / "coverage.json")
