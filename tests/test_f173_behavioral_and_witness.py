"""F-173 — what the agent DID reaches the watch, and the baseline gets a witness.

Two problems, one task.

**Part A.** `--behavioral` and `--monitor` were mutually exclusive by construction: the
behavioural branch returns before the monitor one, so four of the `logs` subject's seven
checks never ran under a scheduled watch, and the all-clear covered none of that ground.
Cost was never the obstacle — measured on the live corpus, `behavioral.analyze(ctx)` is
0.176 s against a 4.9 s `run_all`.

The false positive this had to avoid is specific and was measured, not imagined: on this
machine `files_capped` is True (60 of 93 trajectory files read) and `behavioral.py`'s own
comment calls a bare B191 divergence under a rotated cap "expected, near-certain-benign
background noise". Consuming `result["findings"]` would put that in the drift stream on
every run forever. `grade_cap_signal` applies `_B191_STRONG_SUB_SIGNALS`; that filter is
the whole reason this dimension can exist, and it is pinned below.

Also measured before any of this was written: on the real `~/.openclaw`, T1 PASS / T2 PASS
/ T3 UNKNOWN / B191 PASS, so `fired` is EMPTY and the only live signal is T3's UNKNOWN.
That is why the undetermined arm is a first-class dimension here rather than an
afterthought — it is the one the real machine actually exercises.

**Part B.** `state.json` carries no chain and no signature, and signing it would be theatre:
the key would live in the same `$HOME`, behind the same 0700, so it defends against an
attacker the filesystem has already excluded. SECURITY_MODEL.md says so and that paragraph
stays. What helps instead is a witness the attacker cannot reach — one short value in the
event chain, on screen, and (via the F-172 cron recipe's `announce` delivery) in a message
the user already holds off the machine.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck import audit
from clawseccheck.behavioral import grade_cap_signal
from clawseccheck.catalog import Finding
from clawseccheck.cli import main
from clawseccheck.monitor import (
    BASELINE_DIGEST_CHARS,
    NOTE_CONFIG_BLIND,
    NOTE_INSPECTION_CAPPED,
    NOTE_UNDETERMINED,
    WATCHED_DIMENSIONS,
    baseline_reference,
    baseline_witness_event,
    diff_with_notes,
    snapshot,
    snapshot_reference,
    verify_baseline,
    verify_chain,
)

_SAFE = '{"gateway": {"bind": "127.0.0.1"}}'
_EXPOSED = '{"gateway": {"bind": "0.0.0.0"}}'


def _home(tmp_path: Path, body: str = _SAFE) -> Path:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text(body, encoding="utf-8")
    os.chmod(cfg, 0o600)
    return home


def _run(home: Path, store: Path, *extra) -> int:
    return main(["--monitor", "--home", str(home), "--data-dir", str(store), *extra])


def _snap(**over) -> dict:
    """A snapshot with the behavioural layer having run and found nothing."""
    base = {
        "version": 7,
        "watched": list(WATCHED_DIMENSIONS),
        "score": 90, "raw_score": 90, "raw_score_scope": "abc", "grade": "A",
        "checks": {"B1": "PASS"},
        "checks_not_applicable": [], "checks_degraded": [],
        "behavioral_fired": [], "behavioral_undetermined": [], "behavioral_capped": False,
        # F-182 follow-up: the severity gate reads the INCOMPLETENESS verdict, not the cap.
        # The cap is one of six reasons a replay cannot support a clean verdict, and an
        # unreadable sidecar leaves it False while nothing was parsed. This fixture stands
        # for a replay that really was complete, so it must say so with the key the gate
        # actually reads — otherwise its absence correctly reads as "incomplete" and the
        # tests below measure the advisory branch while claiming to measure the other one.
        "behavioral_incomplete": False,
    }
    base.update(over)
    return base


def _cats(notes) -> list:
    return [c for c, _ in notes]


def _b191(sub_signals) -> Finding:
    return Finding(id="B191", title="t", severity="MEDIUM", status="WARN", detail="d",
                   fix="f", framework="x", sub_signals=frozenset(sub_signals))


# ================================================================ Part A — the filter

def test_a_bare_b191_divergence_is_filtered_out_before_it_can_reach_the_snapshot():
    """THE false positive. `files_capped` is True on the maintainer's machine, and a B191
    WARN whose only sub-signal is `divergence` is that cap's documented benign noise. If it
    reached `behavioral_fired` it would fire on the transition and then sit in the baseline
    forever, so the filter is pinned at its source rather than downstream."""
    assert grade_cap_signal({"findings": [_b191({"divergence"})]}) == frozenset()


def test_a_b191_backed_by_a_strong_signal_is_not_filtered_out():
    """The other direction, without which the test above passes for a filter that drops
    everything."""
    assert grade_cap_signal(
        {"findings": [_b191({"divergence", "blocked"})]}) == frozenset({"B191"})


# ================================================================ Part A — the snapshot

def test_a_layer_that_did_not_run_writes_no_key_rather_than_an_empty_one():
    """The load-bearing absence. An empty list would read as "we looked and found nothing",
    and on the NEXT run a real signal disappearing into it would read as "it cleared" — a
    resolution nobody observed."""
    ctx, findings, score = audit(Path("fixtures") / "home_safe")
    bare = snapshot(ctx, findings, score)
    assert "behavioral_fired" not in bare
    assert "behavioral_undetermined" not in bare
    assert "behavioral_capped" not in bare


def test_the_three_keys_are_declared_in_the_coverage_manifest():
    """Otherwise a baseline predating them is silently skipped rather than disclosed — the
    exact blind spot C-417 built the manifest to close."""
    for key in ("behavioral_fired", "behavioral_undetermined", "behavioral_capped"):
        assert key in WATCHED_DIMENSIONS


def test_a_monitor_run_really_does_populate_them_end_to_end(tmp_path, capsys):
    """Not a trace: the real CLI, the real fixture home, reading the file off disk. A unit
    test of `snapshot(behavioral=...)` proves the parameter works and says nothing about
    whether anything ever passes it."""
    home, store = _home(tmp_path), tmp_path / "store"
    assert _run(home, store) == 0
    capsys.readouterr()
    saved = json.loads((store / "state.json").read_text(encoding="utf-8"))
    assert isinstance(saved.get("behavioral_fired"), list)
    assert isinstance(saved.get("behavioral_undetermined"), list)
    assert isinstance(saved.get("behavioral_capped"), bool)


def test_a_home_with_no_recorded_activity_is_disclosed_rather_than_passed(tmp_path, capsys):
    """Measured, after the first version of this test asserted the opposite and passed for
    the wrong reason.

    It claimed a trajectory-less home produces NO note — and went green because notes
    collapse to a bare count unless `--verbose`, so the strings it looked for could not
    have appeared either way. Run with `--verbose`, the truth is that `behavioral_
    undetermined == ["B191"]`: with no recorded activity B191 cannot settle, and saying so
    is exactly right. What must NOT happen is the layer being reported as unexamined (it
    ran) or a pattern being reported as firing (none did).

    The load-bearing assertion used to be `"could not be determined" in out` — that
    substring is `report._NOTE_HEADINGS["undetermined"]`, the GENERIC section heading
    `"Because the state of something could not be determined:"` that the renderer prints
    for ANY `NOTE_UNDETERMINED` note regardless of source, so this test passed even with
    the behavioural note itself suppressed entirely (confirmed by mutation: stubbing out
    the `_b_unknown` arm in `monitor.py`'s `diff_with_notes` left this test green). The
    fix asserts on the behavioural sentence's own wording instead — the one
    `diff_with_notes` builds from `behavioral_undetermined`, in `monitor.py`:
    `f"{len(_b_unknown)} thing(s) about how your agent has been behaving could not be
    determined — there may be too little recorded activity to judge yet. Run --behavioral
    to see which."`
    """
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    _run(home, store, "--verbose")
    out = capsys.readouterr().out
    saved = json.loads((store / "state.json").read_text(encoding="utf-8"))
    assert saved["behavioral_fired"] == []
    assert saved["behavioral_undetermined"] == ["B191"]
    assert "about how your agent has been behaving could not be determined" in out
    assert "what your agent actually did" not in out.lower(), "the layer DID run"
    assert "behaviour pattern(s) now appear" not in out, "nothing fired"


def test_the_undetermined_note_reads_as_english_rather_than_as_catalog_jargon(tmp_path,
                                                                             capsys):
    """The first wording spliced the check's catalog title into the sentence, producing
    "e.g. OpenClaw's runtime audit_events trail - coverage, policy-blocked tools, and
    evasive tool names" in a line aimed at someone who just wants to know if their agent is
    fine. It also said "from the activity log" on a home that has no activity log at all."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    _run(home, store, "--verbose")
    out = capsys.readouterr().out
    assert "audit_events" not in out
    assert "from the activity log" not in out


# ================================================================ Part A — the diff arms

def test_a_run_that_never_examined_behaviour_says_so():
    prev, curr = _snap(), _snap()
    for key in ("behavioral_fired", "behavioral_undetermined", "behavioral_capped"):
        curr.pop(key)
    alerts, notes = diff_with_notes(prev, curr)
    assert alerts == []
    assert NOTE_UNDETERMINED in _cats(notes)
    assert any("what your agent actually did" in m.lower() for _, m in notes)


def test_a_capped_replay_window_is_disclosed():
    """Live on the maintainer's machine: 60 of 93 trajectory files are read."""
    _, notes = diff_with_notes(_snap(), _snap(behavioral_capped=True))
    assert NOTE_INSPECTION_CAPPED in _cats(notes)


def test_an_undetermined_pattern_is_disclosed_and_routed_somewhere_useful():
    """T3 UNKNOWN is the real machine's actual state — measured — and the one thing the
    user is never currently told. The note carries a count and a next step rather than the
    check's catalog title; naming which one is `--behavioral`'s job, and it can afford the
    words this line cannot."""
    _, notes = diff_with_notes(_snap(), _snap(behavioral_undetermined=["T3"]))
    assert NOTE_UNDETERMINED in _cats(notes)
    assert any("--behavioral" in m for _, m in notes)
    assert not any("T3" in m for _, m in notes), "a bare check id is not an explanation"


def test_a_newly_appearing_pattern_is_reported():
    """`_snap()` records an UNCAPPED replay on both sides, so F-182's paging branch is the
    one this exercises: both runs read the trajectory in full, which makes a newly-fired
    detector newly DONE rather than newly visible. The capped branch keeps INFO and is
    covered next.
    """
    alerts, _ = diff_with_notes(_snap(), _snap(behavioral_fired=["T1"]))
    assert len(alerts) == 1
    level, msg = alerts[0]
    assert level == "MEDIUM"
    assert "Behavioral trifecta" in msg


def test_the_report_admits_the_window_may_only_be_newly_seen():
    """The evidence window rotates, so "it appeared" is not "it started". Saying otherwise
    would be a claim about when something happened, written into a tamper-evident journal
    on the strength of a file having been rotated out.

    **F-182 refined the condition rather than the principle, so this now pins the capped
    case explicitly.** The window rotates *when it was capped*; when both runs replayed the
    activity in full, nothing rotated out and there is no ambiguity to admit. The hedge is
    therefore required exactly here and would be false on the uncapped branch — which is
    why `behavioral_capped=True` is passed rather than relying on the fixture's default.
    """
    # A capped replay IS an incomplete one, so both keys say so. The gate reads the
    # incompleteness verdict — `behavioral_capped` alone stopped deciding severity when a
    # measurement showed an unreadable sidecar leaves the cap False while nothing parses.
    alerts, _ = diff_with_notes(
        _snap(behavioral_capped=True, behavioral_incomplete=True),
        _snap(behavioral_fired=["T1"], behavioral_capped=True, behavioral_incomplete=True))
    assert "newly seen rather than newly done" in alerts[0][1]


def test_a_pattern_that_stops_appearing_is_never_reported_as_cleared():
    """The asymmetry, stated as a property. A pattern leaving the replay window is not
    evidence it stopped happening — it is evidence the window moved."""
    alerts, _ = diff_with_notes(_snap(behavioral_fired=["T1", "T2"]),
                                _snap(behavioral_fired=["T1"]))
    assert alerts == []


def test_an_unchanged_set_is_silent():
    alerts, notes = diff_with_notes(_snap(behavioral_fired=["T1"]),
                                    _snap(behavioral_fired=["T1"]))
    assert alerts == []
    assert not [c for c in _cats(notes) if c == NOTE_INSPECTION_CAPPED]


def test_a_baseline_predating_the_layer_produces_no_alert_for_one_run():
    """The migration property every SNAPSHOT_VERSION bump owes: an older baseline lacks the
    key, so the arm stands down rather than reporting the whole set as new."""
    old = _snap()
    old.pop("behavioral_fired")
    alerts, _ = diff_with_notes(old, _snap(behavioral_fired=["T1", "T2", "T3"]))
    assert alerts == []


def test_the_arm_stands_down_when_either_run_was_blind():
    """Structural, and honest about its own evidence: T3's declared capability set is read
    out of the config, so a collapsed `ctx.config` could in principle widen "observed minus
    declared". The experiment was run on the real machine and could NOT discriminate — with
    `ctx.config = {}` the verdicts came back byte-identical, because its T3 is UNKNOWN in
    both views. An inconclusive experiment is not a licence to drop the guard."""
    alerts, notes = diff_with_notes(_snap(), _snap(behavioral_fired=["T1"],
                                                   config_parse_error=True))
    assert not [a for a in alerts if "behaviour pattern" in a[1]]
    assert NOTE_CONFIG_BLIND in _cats(notes)


def test_the_arm_does_not_need_the_scope_gate_and_this_is_why():
    """An independent pass noticed the arm is NOT gated on `_same_scope_flags` — which the
    score and vanished-check arms are, because `--no-host` alone turns five checks from
    WARN to UNKNOWN — and could not establish whether that matters.

    Answered structurally rather than by one machine's verdicts: the behavioural layer
    reads only `attestation`, `audit_events`, `config`, `exhaustive` and `home` off `ctx`,
    and none of those is controlled by a scope flag. Derived from the AST so it stays true:
    the day someone makes that module read `ctx.host`, this fails and the gate has to be
    added. (Measured too — toggling all four flags on the real machine left every verdict
    identical — but a single host where T1/T2/B191 are PASS could not have proved it.)
    """
    import ast
    import pathlib
    tree = ast.parse(pathlib.Path("clawseccheck/behavioral.py").read_text(encoding="utf-8"))
    read: set = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) \
                and n.value.id == "ctx":
            read.add(n.attr)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) \
                and n.func.id == "getattr" and n.args \
                and isinstance(n.args[0], ast.Name) and n.args[0].id == "ctx" \
                and len(n.args) > 1 and isinstance(n.args[1], ast.Constant):
            read.add(n.args[1].value)
    scope_controlled = {"include_host", "include_sockets", "include_deptree", "native",
                        "host", "sockets", "dep_tree"}
    assert read, "the AST walk found nothing — this guard would pass vacuously"
    assert not (read & scope_controlled), (
        f"behavioral.py now reads {sorted(read & scope_controlled)}, which a scope flag "
        f"controls — the diff arm needs the _same_scope_flags gate"
    )


def test_the_behavioural_arm_never_moves_the_score():
    """F-154's cap-only discipline, preserved: nothing here reaches `scoring.compute`, so
    score history stays comparable across the release that added the layer.

    The original assertion here — `curr["score"] == prev["score"]` — was vacuous: it is a
    property of `_snap()`, which hardcodes `score: 90` on both sides, and this test
    overrides only `behavioral_fired`. The two scores were equal before `diff_with_notes`
    ever ran and would stay equal even if the arm computed and discarded a brand-new score,
    or mutated its inputs. `diff_with_notes` doesn't return a score at all, so there was
    nothing in its actual output to check F-154 against.

    What IS mechanically checkable: `diff_with_notes` never references the name `scoring`
    anywhere in its body — not via a module-level import used inside it, not via a local
    `import scoring` (which would still show up as an `ast.Import`/`ast.ImportFrom` node in
    its subtree). That means the behavioural diff arm, which lives inside this function,
    cannot call `scoring.compute` at all — the actual claim the docstring makes."""
    import ast
    import inspect
    import textwrap

    # Read the function through the imported object, not through a relative path: a path
    # depends on the CWD pytest happened to start in, and it would keep parsing a file
    # named monitor.py after C-433 moves this function into a package submodule — passing
    # while testing the wrong thing. `getsource` follows the function wherever it lives.
    src = textwrap.dedent(inspect.getsource(diff_with_notes))
    diff_fn = next(n for n in ast.walk(ast.parse(src))
                   if isinstance(n, ast.FunctionDef) and n.name == "diff_with_notes")
    names_referenced = {n.id for n in ast.walk(diff_fn) if isinstance(n, ast.Name)}
    imported_in_fn: set = set()
    for n in ast.walk(diff_fn):
        if isinstance(n, ast.Import):
            imported_in_fn.update((a.asname or a.name).split(".")[0] for a in n.names)
        elif isinstance(n, ast.ImportFrom):
            imported_in_fn.update(a.asname or a.name for a in n.names)
    assert names_referenced, "the AST walk found nothing — this guard would pass vacuously"
    assert "scoring" not in names_referenced and "scoring" not in imported_in_fn, (
        "diff_with_notes now references `scoring` — the behavioural diff arm must not "
        "reach scoring.compute (F-154's cap-only discipline)"
    )

    # Anti-vacuity only: the AST assertions above are the F-154 claim, and this proves the
    # arm actually ran rather than the guard passing over a function that emitted nothing.
    # Deliberately severity-AGNOSTIC — the previous version asserted INFO here, which is a
    # claim about calibration owned by F-182, in a test about scoring. It reddened when that
    # calibration legitimately changed, which is a test failing for a reason it is not about.
    prev, curr = _snap(), _snap(behavioral_fired=["T1", "T2"])
    alerts, _ = diff_with_notes(prev, curr)
    assert alerts, "the behavioural arm produced nothing — the guard above proved nothing"
    assert all("score" not in m.lower() for _lvl, m in alerts), alerts


def test_a_behavioural_layer_that_raises_does_not_take_the_run_down(tmp_path, capsys,
                                                                    monkeypatch):
    """Containment lives in the shell, and this proves it is wired rather than intended.
    A monitor run that dies because the layer it just gained raised on a schema-drifted
    config is strictly worse than one that reports the gap."""
    import clawseccheck.cli as cli

    def _boom(*a, **k):
        raise RuntimeError("schema drift")

    monkeypatch.setattr(cli, "_behavioral_analyze", _boom)
    home, store = _home(tmp_path), tmp_path / "store"
    assert _run(home, store) == 0
    capsys.readouterr()
    saved = json.loads((store / "state.json").read_text(encoding="utf-8"))
    assert "behavioral_fired" not in saved, \
        "a failed layer must leave the key ABSENT, not empty"


# ================================================================ Part B — the witness

def test_two_runs_over_an_untouched_setup_give_the_SAME_reference(tmp_path, capsys):
    """THE test for Part B, and the one whose absence let the first version ship a lie.

    That version fingerprinted the state file's raw BYTES. `state.json` carries `ts`, so an
    independent pass got three different values from three runs against a completely
    untouched home, with a diff of two consecutive baselines showing the `ts` line and
    nothing else. The value that travels off the machine would have told the user to
    investigate a condition that holds after every scheduled run on a healthy machine, and
    `--verify-baseline` could only ever match inside one cron interval.
    """
    home, store = _home(tmp_path), tmp_path / "store"
    refs = []
    for _ in range(3):
        _run(home, store)
        refs.append(baseline_reference(store / "state.json")[0])
    capsys.readouterr()
    assert len(set(refs)) == 1, f"three runs, an untouched home, {len(set(refs))} values"
    assert refs[0], "and it must be a real value, not three empty strings"


def test_the_reference_moves_when_the_setup_moves(tmp_path, capsys):
    """The other direction, without which the test above passes for a constant."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    before = baseline_reference(store / "state.json")[0]
    _home(tmp_path, _EXPOSED)
    _run(home, store)
    capsys.readouterr()
    assert baseline_reference(store / "state.json")[0] != before


def test_the_run_clock_alone_never_moves_the_reference():
    """Stated directly on the primitive, so the property survives a future field that
    happens to be volatile: `ts` is excluded, everything else is not."""
    a = _snap(ts="2026-08-11T10:00:00")
    b = _snap(ts="2026-08-11T23:59:59")
    assert snapshot_reference(a) == snapshot_reference(b)
    assert snapshot_reference(_snap(score=90)) != snapshot_reference(_snap(score=91))


def test_key_order_and_whitespace_do_not_move_the_reference():
    """Canonical JSON, so a baseline rewritten by a different json.dumps call is not
    reported as a changed one."""
    a = {"version": 7, "score": 90, "grade": "A"}
    b = {"grade": "A", "score": 90, "version": 7}
    assert snapshot_reference(a) == snapshot_reference(b) != ""


def test_an_absent_baseline_and_an_unreadable_one_are_told_apart(tmp_path):
    """Collapsing them is what made the CLI say "no baseline has been saved yet" over a
    file that was sitting right there."""
    assert baseline_reference(tmp_path / "nothing.json") == ("", "absent")
    broken = tmp_path / "state.json"
    broken.write_text("{not json", encoding="utf-8")
    assert baseline_reference(broken) == ("", "unreadable")


def test_a_truncated_baseline_does_not_fingerprint_clean(tmp_path):
    """Why the value is read back from disk rather than taken from the dict in memory."""
    p = tmp_path / "state.json"
    p.write_text('{"version": 7, "score": 9', encoding="utf-8")
    assert baseline_reference(p)[0] == ""


def test_a_first_run_journals_nothing_and_still_prints_the_reference(tmp_path, capsys):
    """Both halves matter. "A first monitor run journals nothing" is a pre-existing
    property with two tests of its own, and the first version of this feature broke it by
    journaling the witness unconditionally. The reference still has to reach the user —
    the screen is where they get it, not the journal."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    out = capsys.readouterr().out
    assert not (store / "events.jsonl").exists()
    assert "Baseline reference:" in out
    assert baseline_reference(store / "state.json")[0][:BASELINE_DIGEST_CHARS] in out


def test_a_quiet_run_adds_no_journal_line(tmp_path, capsys):
    """A daily cron on a healthy machine must not report "365 event(s) recorded" over a
    timeline of nothing — which is what `--brief` showed when this was unconditional. It
    would also have evicted genuine drift alerts through the journal's 5,000-line
    retention."""
    home, store = _home(tmp_path), tmp_path / "store"
    for _ in range(4):
        _run(home, store)
    capsys.readouterr()
    assert not (store / "events.jsonl").exists()


def test_the_witness_is_journaled_when_the_reference_moves(tmp_path, capsys):
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    _home(tmp_path, _EXPOSED)
    _run(home, store)
    capsys.readouterr()
    text = (store / "events.jsonl").read_text(encoding="utf-8")
    assert "Baseline reference is now" in text
    on_disk = baseline_reference(store / "state.json")[0][:BASELINE_DIGEST_CHARS]
    assert on_disk in text


def test_the_chain_survives_both_writes_in_one_run(tmp_path, capsys):
    """Two `record_events` calls in one run — the drift alerts first (B-278's order), the
    witness after `save_state`. The chain has to survive both, which is the only thing that
    makes the second call safe at all."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    _home(tmp_path, _EXPOSED)
    _run(home, store)
    capsys.readouterr()
    ok, msg = verify_chain(store / "events.jsonl")
    assert ok, msg
    text = (store / "events.jsonl").read_text(encoding="utf-8")
    assert "Gateway bind" in text and "Baseline reference is now" in text


def test_the_chain_survives_a_rotation_between_the_two_writes(tmp_path, capsys):
    """The reviewer's un-run case: `_rotate_journal` prunes AND re-chains, and it can fire
    on the drift write, leaving the witness write to append onto a journal that was
    rewritten in between. Both calls read the last chain hash fresh under `journal_lock`,
    so this holds — but it holds by construction, which is exactly the kind of claim that
    deserves an actual run."""
    from clawseccheck.monitor import _JOURNAL_KEEP, _JOURNAL_MAX_LINES, record_events
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    journal = store / "events.jsonl"
    for start in range(0, _JOURNAL_MAX_LINES - 1, 200):
        record_events([("INFO", f"filler {i}") for i in
                       range(start, min(start + 200, _JOURNAL_MAX_LINES - 1))], journal)
    before = sum(1 for _ in journal.open(encoding="utf-8"))
    assert before == _JOURNAL_MAX_LINES - 1, "precondition: primed to just under the cap"

    _home(tmp_path, _EXPOSED)
    assert _run(home, store) == 0
    capsys.readouterr()
    after = sum(1 for _ in journal.open(encoding="utf-8"))
    assert after < before, f"precondition: rotation must have fired ({before} -> {after})"
    assert after <= _JOURNAL_KEEP + 4
    ok, msg = verify_chain(journal)
    assert ok, msg
    text = journal.read_text(encoding="utf-8")
    assert "Gateway bind changed" in text, "the drift alert must survive the rotation"
    assert "Baseline reference is now" in text, "and so must the witness"


def test_no_reference_is_printed_when_nothing_was_written(tmp_path, capsys):
    """A reference for a baseline that does not exist is worse than none: the user would
    keep it and later be told it does not match."""
    home, store = _home(tmp_path), tmp_path / "store"
    store.mkdir()
    (store / "state.json").mkdir()      # make the write fail without a symlink
    rc = _run(home, store)
    out = capsys.readouterr().out
    assert rc == 1
    assert "Baseline reference:" not in out


def test_a_witness_event_for_an_empty_reference_records_nothing():
    assert baseline_witness_event("") == []


def test_no_surface_claims_the_cron_recipe_delivers_the_reference(tmp_path):
    """D2. Three surfaces said the cron recipe's `announce` delivery "puts it in a message
    you already hold". It does not: the recipe instructs the agent to say nothing on exit 0,
    so a scheduled run carries this line only once the value has already MOVED — the runs
    where keeping it is worth least. Getting it off the machine is the user's action.

    Asserted against the recipe's own text rather than trusted, so the claim and the thing
    it describes cannot drift apart again."""
    from clawseccheck.guide import render_cron_recipe
    recipe = render_cron_recipe()
    assert "Exit 0" in recipe and "say nothing" in recipe.lower(), \
        "precondition: the recipe really does tell the agent to stay silent on a quiet run"

    root = Path(__file__).resolve().parent.parent
    for rel in ("SECURITY_MODEL.md", "docs/USAGE.md", "clawseccheck/report.py"):
        text = (root / rel).read_text(encoding="utf-8")
        assert "puts it in a message you already hold" not in text, rel
        assert "a message you already hold" not in text, rel


# ================================================================ Part B — verification

def test_verify_still_matches_after_a_later_run_changed_nothing(tmp_path, capsys):
    """The property that makes the mode usable at all: a reference kept from Monday still
    verifies on Friday if nothing changed in between. Under the byte-based first version
    this failed after the very next scheduled run."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    ref = baseline_reference(store / "state.json")[0][:BASELINE_DIGEST_CHARS]
    _run(home, store)
    _run(home, store)
    capsys.readouterr()
    rc = main(["--verify-baseline", ref, "--data-dir", str(store), "--home", str(home)])
    assert rc == 0
    assert "still matches your reference" in capsys.readouterr().out


def test_verify_reports_a_mismatch_as_a_fact_and_not_as_tampering(tmp_path, capsys):
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    capsys.readouterr()
    rc = main(["--verify-baseline", "0" * 32, "--data-dir", str(store),
               "--home", str(home)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "does NOT match" in out
    assert "tamper" not in out.lower(), \
        "an ordinary change produces this; naming it tampering sends the user hunting an " \
        "intruder who is not there"
    assert "the options you ran it with" in out, \
        "the run shape is the surprising cause and has to be named FIRST"
    assert "upgrade that adds checks" in out, \
        "our own release moves this value too, and the user has to be told so"
    assert "worth investigating only if none did" not in out, (
        "the first version's wording listed four causes as though they were exhaustive, "
        "and an independent pass moved the reference on a completely untouched machine "
        "with a flag none of the four covered — and THIS test pinned the false clause"
    )


def test_a_narrower_run_moves_the_reference_and_the_wording_covers_it(tmp_path, capsys):
    """D1, reproduced. `--no-host` changes `scope`, `host`, `checks` and the scores, so the
    same untouched machine fingerprints differently. That is correct — a narrower run
    recorded less — but the first version's mismatch text listed four causes, none of which
    was "you ran it with different options", so the honest answer looked unexplained.

    This is the E-077 run-shape family: static prose that presupposed every run has the
    same shape."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    wide = baseline_reference(store / "state.json")[0]
    _run(home, store, "--no-host")
    narrow = baseline_reference(store / "state.json")[0]
    capsys.readouterr()
    assert narrow != wide, "precondition: a narrower run really does move the value"
    rc = main(["--verify-baseline", wide[:BASELINE_DIGEST_CHARS],
               "--data-dir", str(store), "--home", str(home)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "--no-host" in out, "the flag that caused this must be named"
    assert "covering:" in out, "and the user must be able to see what the baseline covered"


def test_the_covering_line_reports_what_the_baseline_actually_recorded(tmp_path, capsys):
    """Without this the line above could print a constant and still satisfy the test."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    capsys.readouterr()
    ref = baseline_reference(store / "state.json")[0]
    main(["--verify-baseline", ref, "--data-dir", str(store), "--home", str(home)])
    wide_out = capsys.readouterr().out
    _run(home, store, "--no-host", "--no-sockets")
    capsys.readouterr()
    ref2 = baseline_reference(store / "state.json")[0]
    main(["--verify-baseline", ref2, "--data-dir", str(store), "--home", str(home)])
    narrow_out = capsys.readouterr().out
    assert "covering:" in wide_out and "covering:" in narrow_out
    assert wide_out.split("covering:")[1] != narrow_out.split("covering:")[1]


def test_verify_tells_could_not_check_apart_from_does_not_match(tmp_path, capsys):
    """Three outcomes, never two. An absent baseline reported as a mismatch is the single
    most damaging thing this could get wrong."""
    home, store = _home(tmp_path), tmp_path / "store"
    store.mkdir()
    rc = main(["--verify-baseline", "0" * 32, "--data-dir", str(store),
               "--home", str(home)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Cannot check" in out and "does NOT match" not in out
    assert "run --monitor first" in out


def test_an_unreadable_baseline_is_not_reported_as_a_missing_one(tmp_path, capsys):
    """Found by an independent pass. Telling the user "no baseline has been saved yet" over
    a file that is sitting right there sends them to run --monitor, which is the one action
    that overwrites the thing they would want to look at."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    capsys.readouterr()
    (store / "state.json").write_text("{not json", encoding="utf-8")
    os.chmod(store / "state.json", 0o600)
    rc = main(["--verify-baseline", "0" * 32, "--data-dir", str(store),
               "--home", str(home)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "could not be read or parsed" in out
    assert "no baseline has been saved yet" not in out
    assert "Do NOT re-run --monitor first" in out


def test_a_reference_too_short_to_mean_anything_is_refused_not_matched(tmp_path, capsys):
    """A one-character prefix matches one baseline in sixteen. Accepting it would let a
    typo report a clean verification."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    capsys.readouterr()
    actual = baseline_reference(store / "state.json")[0]
    verdict, _, why = verify_baseline(actual[:4], store / "state.json")
    assert verdict is None and why == "reference_too_short"
    rc = main(["--verify-baseline", actual[:4], "--data-dir", str(store),
               "--home", str(home)])
    assert rc == 1
    assert "Cannot check" in capsys.readouterr().out


def test_the_full_value_verifies_as_well_as_the_short_one(tmp_path, capsys):
    """A user who copied the whole value out of a JSON file must not be told it is wrong."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    capsys.readouterr()
    full = baseline_reference(store / "state.json")[0]
    assert verify_baseline(full, store / "state.json")[0] is True
    assert verify_baseline(full.upper(), store / "state.json")[0] is True, \
        "this value gets retyped by hand at least once"
    assert verify_baseline(f"  {full}  ", store / "state.json")[0] is True


def test_verify_writes_nothing(tmp_path, capsys):
    """It is a read-only mode; a check that advances the thing it is checking is worthless."""
    home, store = _home(tmp_path), tmp_path / "store"
    _run(home, store)
    capsys.readouterr()
    before = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in store.iterdir()}
    main(["--verify-baseline", baseline_reference(store / "state.json")[0],
          "--data-dir", str(store), "--home", str(home)])
    capsys.readouterr()
    assert {p.name: (p.stat().st_size, p.stat().st_mtime_ns)
            for p in store.iterdir()} == before
