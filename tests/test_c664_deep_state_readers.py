"""C-664 slice B1b: flat files that OpenClaw or this tool writes take the 200-level bound.

A document nested past ``MAX_JSON_NESTING`` used to reach ``json.loads`` unchecked. On a
default stack that ends in a RecursionError (Python 3.12 from about 10,000 levels, 3.14 from
about 58,000), which no ``except ValueError`` catches, and where the reader runs outside the
per-check net it ends the whole run with "unexpected internal error". Each reader below
reads a flat file written by OpenClaw or by this tool (state, ledger, hint, pointer, journal,
health file) and now treats "nested too deeply" exactly like "not valid JSON": whatever
degraded state it already discloses for a malformed file.

Every hostile document is DICT-shaped, the type its reader expects, with the depth carried in
an extra ``pad`` field. A bare nested list would prove nothing: it parses to a non-dict and
lands in the degraded state on its own, with or without the bound. Hostile twins nest 201
levels (the first one past the bound) and 100,000; the clean twin nests exactly 200 levels
and must still be read, so the boundary is pinned from both sides. Each hostile test also
compares with the malformed file's outcome where the reader has one.

Not covered here on purpose, because a fixed limit on content that someone hostile can shape
is an evasion: trajectory / context.compiled lines (they carry model-supplied tool-call
arguments), judge verdict payloads and the judged bundle (model output a hostile skill can
steer), and the hash-chained events journal (a tamper-evidence store). They keep the raw
parse until the shallow reader lands (C-664 slice C).
"""
from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck import (
    configjournal,
    ledger,
    monitorstore,
    prescan,
    trajectory,
    update,
)
from clawseccheck.checks import check_config_health_integrity
from clawseccheck.collector import Context
from clawseccheck.configloader import MAX_JSON_NESTING, json_nesting_exceeds

REPO = Path(__file__).resolve().parent.parent
HOSTILE = [MAX_JSON_NESTING + 1, 100_000]
# A pointer file is capped at 64 KiB, so 100,000 levels never reach the parser there.
POINTER_HOSTILE = [MAX_JSON_NESTING + 1, 30_000]
_STACK = 64 * 1024 * 1024
_DEFAULT_STACK = 8 * 1024 * 1024


def _deep(n: int) -> str:
    return "[" * n + "]" * n


def _padded(doc: dict, depth: int) -> str:
    """JSON text of *doc* plus a ``pad`` field, the whole document nesting *depth* levels."""
    assert doc, "a padded document needs at least one real field"
    return json.dumps(doc)[:-1] + ', "pad": ' + _deep(depth - 1) + "}"


def test_padded_documents_nest_exactly_as_asked():
    doc = {"k": 1}
    assert not json_nesting_exceeds(_padded(doc, MAX_JSON_NESTING))
    assert json_nesting_exceeds(_padded(doc, MAX_JSON_NESTING + 1))
    assert json.loads(_padded(doc, MAX_JSON_NESTING))["k"] == 1


def _stack_limit(want: int) -> int:
    hard = resource.getrlimit(resource.RLIMIT_STACK)[1]
    return want if hard == resource.RLIM_INFINITY else min(want, hard)


def _run_cli(args, cwd, stack: int = _STACK):
    limit = _stack_limit(stack)

    def _pre():
        resource.setrlimit(resource.RLIMIT_STACK, (limit, limit))

    env = dict(os.environ, PYTHONPATH=str(REPO), PYTHONDONTWRITEBYTECODE="1",
               CLAWSECCHECK_NO_UPDATE_NOTICE="1", CLAWSECCHECK_NO_FRESHNESS_NOTICE="1")
    return subprocess.run([sys.executable, "-m", "clawseccheck", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=120, preexec_fn=_pre)


# ---------------------------------------------------------------------------- CLI site

_STATE = {"ts": "2026-01-01T00:00:00", "findings": []}


def _brief(tmp_path, state_text, stack: int = _STACK):
    state = tmp_path / "state.json"
    state.write_text(state_text, encoding="utf-8")
    os.utime(state, (1_767_225_600, 1_767_225_600))  # same mtime for every run compared
    return _run_cli(["--brief", "--state", str(state),
                     "--events", str(tmp_path / "no-events.jsonl"),
                     "--history", str(tmp_path / "no-history.jsonl"),
                     "--home", str(tmp_path), "--no-deptree", "--no-host"], tmp_path, stack)


# 8 MiB is the default stack (a 100,000-level parse overflows it); 64 MiB is a CI runner's.
@pytest.mark.parametrize("stack", [_DEFAULT_STACK, _STACK])
@pytest.mark.parametrize("depth", HOSTILE)
def test_brief_deep_state_reads_as_no_usable_state(tmp_path, depth, stack):
    got = _brief(tmp_path, _padded(_STATE, depth), stack)
    want = _brief(tmp_path, "[", stack)
    plain = _brief(tmp_path, json.dumps(_STATE), stack)
    assert "internal error" not in got.stdout + got.stderr
    assert got.returncode == want.returncode == 0
    assert got.stdout == want.stdout
    assert got.stdout != plain.stdout  # the state really does change the brief when it is read


def test_brief_state_at_the_bound_is_still_read(tmp_path):
    padded = _brief(tmp_path, _padded(_STATE, MAX_JSON_NESTING))
    assert padded.returncode == 0
    assert padded.stdout == _brief(tmp_path, json.dumps(_STATE)).stdout


# --------------------------------------------------------------- ~/.clawseccheck stores

@pytest.mark.parametrize("depth", HOSTILE)
def test_ledger_deep_file_reads_as_never_run(tmp_path, depth):
    p = tmp_path / "coverage.json"
    p.write_text(_padded({"self_test": "2026-01-01"}, depth), encoding="utf-8")
    assert ledger.load_ledger(path=str(p)) == {}


def test_ledger_file_at_the_bound_still_loads(tmp_path):
    p = tmp_path / "coverage.json"
    p.write_text(_padded({"self_test": "2026-01-01"}, MAX_JSON_NESTING), encoding="utf-8")
    assert ledger.load_ledger(path=str(p)) == {"self_test": "2026-01-01"}


@pytest.mark.parametrize("depth", HOSTILE)
def test_prescan_deep_file_falls_back_to_the_default_mode(tmp_path, depth):
    p = prescan._path(str(tmp_path))
    p.parent.mkdir(parents=True)
    p.write_text(_padded({"last_mode": "full"}, depth), encoding="utf-8")
    assert prescan.DEFAULT_MODE != "full"
    assert prescan.read_last_mode(str(tmp_path)) == prescan.DEFAULT_MODE


def test_prescan_file_at_the_bound_still_loads(tmp_path):
    p = prescan._path(str(tmp_path))
    p.parent.mkdir(parents=True)
    p.write_text(_padded({"last_mode": "full"}, MAX_JSON_NESTING), encoding="utf-8")
    assert prescan.read_last_mode(str(tmp_path)) == "full"


@pytest.mark.parametrize("depth", HOSTILE)
def test_update_hint_deep_file_stays_silent(tmp_path, depth):
    p = tmp_path / "latest.json"
    p.write_text(_padded({"version": "9.9.9"}, depth), encoding="utf-8")
    assert update.read_latest_hint(str(p)) is None


def test_update_hint_at_the_bound_still_loads(tmp_path):
    p = tmp_path / "latest.json"
    p.write_text(_padded({"version": "9.9.9"}, MAX_JSON_NESTING), encoding="utf-8")
    assert update.read_latest_hint(str(p)) == "9.9.9"


# ------------------------------------------------------------------------ monitorstore

_BASELINE = {"ts": "x", "skills": {"a": 1}}


@pytest.mark.parametrize("depth", HOSTILE)
def test_baseline_deep_state_is_corrupt_not_absent_and_not_ok(tmp_path, depth):
    p = tmp_path / "state.json"
    p.write_text(_padded(_BASELINE, depth), encoding="utf-8")
    assert monitorstore.read_baseline(p) == (monitorstore.BASELINE_CORRUPT, None)
    assert monitorstore.load_state(p) is None


def test_baseline_at_the_bound_still_loads(tmp_path):
    p = tmp_path / "state.json"
    p.write_text(_padded(_BASELINE, MAX_JSON_NESTING), encoding="utf-8")
    status, payload = monitorstore.read_baseline(p)
    assert status == monitorstore.BASELINE_OK and payload["skills"] == {"a": 1}


@pytest.mark.parametrize("depth", HOSTILE)
def test_baseline_reference_deep_state_is_unreadable(tmp_path, depth):
    p = tmp_path / "state.json"
    p.write_text(_padded(_BASELINE, depth), encoding="utf-8")
    assert monitorstore.baseline_reference(p) == ("", "unreadable")


def test_baseline_reference_at_the_bound_still_hashes(tmp_path):
    p = tmp_path / "state.json"
    p.write_text(_padded(_BASELINE, MAX_JSON_NESTING), encoding="utf-8")
    value, reason = monitorstore.baseline_reference(p)
    assert reason == "ok" and value


# ------------------------------------------------------------- trajectory pointer files

def _pointer_home(tmp_path: Path, depth: "int | None") -> "tuple[Path, Path]":
    home = tmp_path / "home"
    sessions = home / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True)
    # Outside agents/*/sessions/, so only the pointer can lead to it (the glob would find it
    # regardless, and the test could not tell a read pointer from an unread one).
    target = home / "elsewhere" / "s1.trajectory.jsonl"
    target.parent.mkdir()
    target.write_text("", encoding="utf-8")
    record = {"traceSchema": "openclaw-trajectory-pointer", "schemaVersion": 1,
              "sessionId": "s1", "runtimeFile": str(target)}
    text = json.dumps(record) if depth is None else _padded(record, depth)
    (sessions / "s1.trajectory-path.json").write_text(text, encoding="utf-8")
    return home, target


@pytest.mark.parametrize("depth", POINTER_HOSTILE)
def test_pointer_deep_file_counts_as_invalid_and_hides_nothing_quietly(tmp_path, depth):
    home, _target = _pointer_home(tmp_path, depth)
    stats: dict = {}
    assert trajectory.find_trajectory_files(home, stats=stats) == []
    assert stats["pointer_invalid"] == 1


def test_pointer_at_the_bound_still_resolves(tmp_path):
    home, target = _pointer_home(tmp_path, MAX_JSON_NESTING)
    stats: dict = {}
    assert trajectory.find_trajectory_files(home, stats=stats) == [target]
    assert stats["pointer_invalid"] == 0


# ------------------------------------------------------------- config journal / B78

def _journal_line(next_hash: str, depth: "int | None" = None) -> str:
    rec = {"ts": "2026-01-01T00:00:00Z", "pid": 1, "argv": ["openclaw"],
           "previousHash": "a" * 8, "nextHash": next_hash, "result": "ok"}
    return json.dumps(rec) if depth is None else _padded(rec, depth)


def _journal(tmp_path: Path, middle: str):
    path = configjournal.journal_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join([_journal_line("b" * 8), middle, _journal_line("d" * 8)]) + "\n",
                    encoding="utf-8")
    return configjournal.read_writes(tmp_path)


@pytest.mark.parametrize("depth", HOSTILE)
def test_config_journal_deep_line_is_counted_unparsable_and_neighbours_survive(tmp_path, depth):
    journal = _journal(tmp_path, _journal_line("c" * 8, depth))
    assert journal.unparsable_lines == 1
    assert [w.next_hash for w in journal.writes] == ["b" * 8, "d" * 8]


def test_config_journal_line_at_the_bound_is_still_a_write(tmp_path):
    journal = _journal(tmp_path, _journal_line("c" * 8, MAX_JSON_NESTING))
    assert journal.unparsable_lines == 0
    assert [w.next_hash for w in journal.writes] == ["b" * 8, "c" * 8, "d" * 8]


_HEALTH = {"entries": {"/c/openclaw.json": {}}}


def _b78(tmp_path: Path, text: str):
    (tmp_path / "logs").mkdir(exist_ok=True)
    (tmp_path / "logs" / "config-health.json").write_text(text, encoding="utf-8")
    return check_config_health_integrity(Context(home=tmp_path, config={}))


@pytest.mark.parametrize("depth", HOSTILE)
def test_b78_deep_file_is_unknown_never_pass(tmp_path, depth):
    got = _b78(tmp_path, _padded(_HEALTH, depth))
    want = _b78(tmp_path, "[")
    assert got.status == want.status == "UNKNOWN"
    assert got.detail == want.detail and "malformed" in got.detail


def test_b78_file_at_the_bound_still_passes(tmp_path):
    assert _b78(tmp_path, _padded(_HEALTH, MAX_JSON_NESTING)).status == "PASS"
