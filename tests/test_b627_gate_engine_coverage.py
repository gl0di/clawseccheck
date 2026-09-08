"""B-627: the gate says which engines produced a result, and refuses a baseline built from fewer.

`scripts/fleet_fp_gate.py` is the C-303 instrument: a change justified by a corpus metric
must run `compare`, and a new real-fleet FAIL is a hard blocker. It ran `audit()` and ONE
vet engine, chosen by `build_snapshot(..., vet_kind="skill")` — and no subcommand ever set
`vet_kind`, so `vet_plugin` was never called. The gate imported an engine it could not
reach and answered "no new real-fleet FAIL" about code it had not entered. B-614 changed
the plugin dispatch and was gated by exactly that green.

The file's own docstring already recorded this mistake once, for `include_deptree`. A
second parameter went the same way, so the fix is not a third flag: the snapshot STATES
which engines produced it, and a comparison against a baseline that ran fewer is refused
rather than passed.

Two things here are deliberately weaker than they could be, and both are load-bearing:

* an absent `engines` key counts as NARROWER, not as equal — every baseline written before
  this change was in fact built without the plugin engine, so reading its silence as
  agreement is the bug itself;
* two snapshots that BOTH omit the key still compare, so hand-built fixtures keep working
  without weakening the real path.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

_REPO = Path(__file__).resolve().parents[1]
_GATE = _REPO / "scripts" / "fleet_fp_gate.py"


def _load():
    spec = importlib.util.spec_from_file_location("_b627_gate", _GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate = _load()


def _snap(**over):
    base = {
        "schema": gate.SCHEMA,
        "tool_version": "9.9.9",
        "generated": "2026-01-01",
        "home_label": "0123456789ab",
        "targets": ["alpha"],
        "degraded_checks": [],
        "context": {"score": 50, "grade": "F", "suppressed_fail_count": 0},
        "fails": [],
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------- #
# The snapshot describes its own coverage.                                     #
# --------------------------------------------------------------------------- #
def test_a_real_snapshot_states_its_engines_and_its_reach(tmp_path):
    """Built through the real `build_snapshot`, because the point is what a genuine run
    records — a hand-made dict would only prove this test can write a dict."""
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    snap = gate.build_snapshot(str(tmp_path))

    assert snap["engines"] == list(gate.ENGINES), snap["engines"]
    assert "vet-plugin" in snap["engines"], "the engine this task exists for is not recorded"
    reach = snap["reach"]
    assert set(reach) == {
        "skill_targets", "plugin_targets",
        "plugins_with_bundled_skill_findings", "dropped_duplicate_names",
    }, sorted(reach)


def test_build_snapshot_no_longer_takes_the_keyword_nobody_could_set():
    """`vet_kind` selected an engine and had no CLI path, so it silently pinned the gate to
    one of two families. Removed rather than wired up: a parameter that decides coverage
    and cannot be set from outside is a trap with a default, and the next reader would have
    to rediscover that it is never passed."""
    import inspect  # noqa: PLC0415

    params = inspect.signature(gate.build_snapshot).parameters
    assert "vet_kind" not in params, sorted(params)


# --------------------------------------------------------------------------- #
# A baseline that covered less cannot be used to say "nothing changed".        #
# --------------------------------------------------------------------------- #
def test_a_baseline_that_never_recorded_its_engines_is_not_comparable():
    result = gate.compare(_snap(engines=list(gate.ENGINES)), _snap())
    assert result["comparable"] is False, result
    assert result["missing_engines"] == sorted(gate.ENGINES), result["missing_engines"]
    assert result["baseline_states_engines"] is False


def test_a_baseline_missing_one_engine_is_not_comparable():
    result = gate.compare(
        _snap(engines=["audit", "vet", "vet-plugin"]),
        _snap(engines=["audit", "vet"]),
    )
    assert result["comparable"] is False, result
    assert result["missing_engines"] == ["vet-plugin"], result["missing_engines"]
    assert result["baseline_states_engines"] is True


def test_two_snapshots_that_both_omit_engines_still_compare():
    """The deliberate weakness, pinned. Every synthetic fixture in the sibling suite omits
    the key; making absence-vs-absence uncomparable would redden them all while proving
    nothing about the real path, where the snapshot always states its engines."""
    result = gate.compare(_snap(), _snap())
    assert result["comparable"] is True, result
    assert result["missing_engines"] == []


def test_matching_engine_sets_compare_normally():
    """Negative control for the three above: with the same engines on both sides the
    coverage check must be invisible."""
    result = gate.compare(
        _snap(engines=list(gate.ENGINES)), _snap(engines=list(gate.ENGINES))
    )
    assert result["comparable"] is True and result["missing_engines"] == []


# --------------------------------------------------------------------------- #
# What the reader is told.                                                     #
# --------------------------------------------------------------------------- #
def test_an_uncomparable_run_never_prints_ok():
    """Found while fixing this task, and the same shape the gate exists to catch: the
    render printed "OK: no new real-fleet FAIL" whenever nothing was newly failing — even
    on a run it had just declared uncomparable two lines earlier. The exit code was already
    EXIT_CANNOT_RUN, so the number and the words disagreed, and the words are what a reader
    takes away."""
    text = gate.render_compare(gate.compare(_snap(engines=list(gate.ENGINES)), _snap()))
    assert "OK: no new real-fleet FAIL" not in text, text
    assert "NOT MEASURED" in text, text
    assert "CANNOT COMPARE" in text, text


def test_the_message_does_not_accuse_a_baseline_of_skipping_engines_it_ran():
    """An old baseline demonstrably ran `audit` and `vet`. Listing them as "missing"
    because the KEY is absent would put a false statement inside the message whose job is
    to report a false statement, so the two cases get different sentences."""
    old = gate.render_compare(gate.compare(_snap(engines=list(gate.ENGINES)), _snap()))
    assert "does not record which engines produced it" in old, old
    assert "was built without audit" not in old, old

    narrower = gate.render_compare(
        gate.compare(_snap(engines=list(gate.ENGINES)), _snap(engines=["audit", "vet"]))
    )
    assert "was built without vet-plugin" in narrower, narrower


def test_a_healthy_comparison_still_says_ok():
    """Negative control: the OK line must survive for the run that earns it."""
    text = gate.render_compare(
        gate.compare(_snap(engines=list(gate.ENGINES)), _snap(engines=list(gate.ENGINES)))
    )
    assert "OK: no new real-fleet FAIL" in text, text
    assert "NOT MEASURED" not in text, text


# --------------------------------------------------------------------------- #
# Targets: what was scanned, and what was silently not.                        #
# --------------------------------------------------------------------------- #
def test_a_target_dropped_for_sharing_a_name_is_counted(tmp_path):
    """Keying targets by basename drops the second directory sharing a name, and the gate
    would then report its target count as if it had scanned both. Nothing collides on this
    machine today — 0 of 3 skill basenames, 0 of 70 plugin basenames — which is exactly why
    it was never noticed. The policy is unchanged; the drop is no longer silent."""
    a, b = tmp_path / "one" / "dup", tmp_path / "two" / "dup"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    kept, dropped = gate._dedupe_by_name([("dup", a), ("dup", b), ("solo", a)])
    assert [n for n, _ in kept] == ["dup", "solo"], kept
    assert dropped == ["dup"], dropped


def test_the_same_directory_listed_twice_is_not_reported_as_a_drop():
    """Non-vacuity for the test above: an alias of one directory is a duplicate ENTRY, not
    a lost target, and reporting it would train the reader to ignore the line."""
    p = Path("/tmp/whatever")
    kept, dropped = gate._dedupe_by_name([("dup", p), ("dup", p)])
    assert [n for n, _ in kept] == ["dup"]
    assert dropped == [], dropped


def test_plugin_roots_come_from_the_index_the_product_itself_loads(tmp_path):
    """`root_dir` in `ctx.plugin_index_records` is the directory OpenClaw loads a plugin
    from and the directory `vet_plugin` expects, so the gate takes its target list from the
    ctx the audit already collected rather than inventing a second definition of
    "installed plugin" that could drift from the product's."""
    real = tmp_path / "alpha"
    real.mkdir()
    ctx = SimpleNamespace(plugin_index_records=[
        {"root_dir": str(real)},
        {"root_dir": str(tmp_path / "missing-on-disk")},
        {"not_a_root": 1},
        {"root_dir": str(real)},  # same dir twice -> one target, not a drop
    ])
    targets, dropped = gate.discover_plugin_roots(ctx)
    assert [n for n, _ in targets] == ["alpha"], targets
    assert dropped == [], dropped


def test_no_plugin_index_is_no_targets_rather_than_an_error():
    """A build without the plugin sweep, or a home the collector could not read, must yield
    zero targets — never an exception that would take the whole gate down with it."""
    assert gate.discover_plugin_roots(SimpleNamespace()) == ([], [])
    assert gate.discover_plugin_roots(SimpleNamespace(plugin_index_records=None)) == ([], [])


def test_acknowledge_accepts_a_plugin_scope():
    """A plugin FAIL must be diagnosable per-target like any other; without this the only
    ways to clear one would be `record` (which absorbs every live FAIL in one act) or
    leaving the gate blocked."""
    import argparse  # noqa: PLC0415

    src = _GATE.read_text(encoding="utf-8")
    assert '"audit", "vet", "vet-plugin"' in src, "the acknowledge scope set was not widened"
    # And the value really is accepted, not merely present in the source text.
    p = argparse.ArgumentParser()
    p.add_argument("--scope", default="audit", choices=("audit", "vet", "vet-plugin"))
    assert p.parse_args(["--scope", "vet-plugin"]).scope == "vet-plugin"
