"""Guards for the monitor DETECTION gate (``scripts/monitor_detection_gate.py``).

`monitor_fp_gate.py` proves the watch stays quiet when nothing changed. That is the half a
broken detector passes trivially — a `--monitor` returning "no alerts" unconditionally sails
through it. The detection gate is the other half: one dangerous change per scenario, and the
watch has to say so.

The gate itself takes ~20 minutes (each scenario is two full audits through the CLI), so it
is a pre-release / on-demand gate like `fleet_fp_gate.py`, not a CI step. What runs here is
everything about it that CAN be checked in a second — and each of these pins a way the gate
could quietly stop meaning anything:

  * a mutation that does not actually change the home would make its scenario's "silent"
    verdict vacuous, and it would look like a detection gap;
  * an `expect_alert=False` entry with no filed task id is a shrug recorded as a fact;
  * a channel policy value outside OpenClaw's real vocabulary makes the config meaningless,
    the signature correctly does not move, and the result reads as a blind spot. That is not
    hypothetical: the first version of the gate wrote `dmPolicy: "all"`, and it reported the
    channel dimension blind until the value was grounded against the installed dist.

Offline, writes nothing outside ``tmp_path``, stdlib only.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = REPO_ROOT / "scripts" / "monitor_detection_gate.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("_monitor_detection_gate", GATE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_gate()

#: What the installed OpenClaw actually accepts for `channels.*.dmPolicy` / `groupPolicy`,
#: read out of the dist. `"all"` is NOT in it.
_POLICY_VALUES = {"allowlist", "disabled", "open", "pairing"}


def test_the_gate_has_scenarios_at_all():
    """Anti-vacuity: every guard below iterates these, so an empty dict would make the
    whole file pass while asserting nothing."""
    assert len(gate.DANGERS) >= 10, sorted(gate.DANGERS)
    assert len(gate.CONTROLS) >= 3, sorted(gate.CONTROLS)


def test_every_scenario_is_a_callable_and_an_expectation():
    for name, entry in gate.DANGERS.items():
        assert isinstance(entry, tuple) and len(entry) == 2, name
        mutate, expect = entry
        assert callable(mutate), name
        assert isinstance(expect, bool), name


@pytest.mark.parametrize("name", sorted(gate.DANGERS))
def test_every_danger_actually_changes_the_home(name, tmp_path):
    """A mutation that silently does nothing turns its scenario into a test of nothing.

    Worse, it fails in the direction that looks like a real finding: the watch reports
    silence, and silence over an unchanged home is correct behaviour being read as a gap.
    """
    home = tmp_path / "home"
    shutil.copytree(gate.BASE_HOME, home)
    for p in home.rglob("*"):
        if p.is_file():
            os.chmod(p, 0o600)
    before = {str(p.relative_to(home)): p.read_bytes()
              for p in sorted(home.rglob("*")) if p.is_file()}
    gate.DANGERS[name][0](home)
    after = {str(p.relative_to(home)): p.read_bytes()
             for p in sorted(home.rglob("*")) if p.is_file()}
    assert after != before, f"{name} left the home byte-identical"


def test_every_known_silence_names_the_task_that_tracks_it():
    """`expect_alert=False` records a KNOWN, FILED gap — never a shrug.

    The entry keeps the gate green today AND turns it red the day the gap is closed, which
    is only defensible if a reader can find out why. A silence with no task id belongs in
    the failure list, not in the table.
    """
    lines = GATE_PATH.read_text(encoding="utf-8").splitlines()
    for name, (_, expect) in gate.DANGERS.items():
        if expect:
            continue
        i = next(n for n, ln in enumerate(lines) if ln.strip().startswith('"%s":' % name))
        # The CONTIGUOUS comment block directly above this entry, and nothing else. A
        # character window instead of this passed while the id it found belonged to the
        # entry ABOVE — proven by flipping a different scenario to expected-silent and
        # watching the guard stay green.
        block, j = [], i - 1
        while j >= 0 and lines[j].strip().startswith("#"):
            block.append(lines[j])
            j -= 1
        assert re.search(r"\b[A-Z]-\d{2,4}\b", "\n".join(block)), (
            f"{name} is recorded as expected-silent with no task id in the comment "
            "immediately above it — that is a shrug written down as a fact"
        )


def test_channel_policies_use_the_real_vocabulary(tmp_path):
    """Ground the VALUES, not just the paths.

    A wrong enum never raises: OpenClaw simply never matches it, the signature correctly
    does not move, and the gate reports a detection gap that does not exist.
    """
    for name in ("new-open-channel", "channel-thrown-open", "trifecta-opened"):
        home = tmp_path / name
        shutil.copytree(gate.BASE_HOME, home)
        for p in home.rglob("*"):
            if p.is_file():
                os.chmod(p, 0o600)
        gate.DANGERS[name][0](home)
        cfg = json.loads((home / "openclaw.json").read_text(encoding="utf-8"))
        for chan, node in (cfg.get("channels") or {}).items():
            for key in ("dmPolicy", "groupPolicy"):
                if key in node:
                    assert node[key] in _POLICY_VALUES, (
                        f"{name}: channels.{chan}.{key}={node[key]!r} is not a value "
                        f"OpenClaw honours ({sorted(_POLICY_VALUES)})"
                    )


def test_the_marker_set_covers_every_glyph_the_renderer_uses():
    """Parsed out of `report.py`, so the two cannot drift apart.

    The gate reads a run's output as text. A severity whose glyph is missing here is a
    severity the gate cannot see: the first version omitted ⛔ and ⚠️ — CRITICAL and HIGH —
    and read its two loudest alerts only through the exit code.
    """
    src = (REPO_ROOT / "clawseccheck" / "report.py").read_text(encoding="utf-8")
    maps = re.findall(
        r'\{"CRITICAL": "([^"]+)", "HIGH": "([^"]+)", "MEDIUM": "([^"]+)", '
        r'"LOW": "([^"]+)", "INFO": "([^"]+)"\}', src)
    assert maps, "the severity->glyph map in report.py has moved; re-anchor this guard"
    for row in maps:
        for glyph in row:
            assert glyph in gate._ALERT_MARKS, (
                f"report.py renders a severity as {glyph!r} and the gate cannot see it"
            )


def test_the_info_glyph_counts_as_an_alert():
    """INFO sits below every `--fail-on` threshold by design (`_SEVERITY_RANK` has no INFO
    entry), so a scenario can warn on screen without paging. Dropping it from the marker set
    would report a working detector as broken — which it did, for `new-bootstrap-file`."""
    assert any("ℹ" in m for m in gate._ALERT_MARKS)


def test_the_baseline_failure_is_fatal_rather_than_reported_as_silence():
    """The first version reported all sixteen dangers SILENT because the CLI never started
    (`--fail-on` takes lowercase; the probe passed `MEDIUM`, so every run exited 2). A broken
    instrument is not biased toward caution — it reported the tool blind everywhere."""
    src = GATE_PATH.read_text(encoding="utf-8")
    assert "if rc0 != 0:" in src and "sys.exit" in src, (
        "a non-clean baseline run must abort the gate, not fall through into a verdict"
    )


def test_the_gate_never_writes_outside_a_temp_directory():
    """It drives the real CLI, which persists state — so every run must be pointed at a
    throwaway `--data-dir`. Writing to the user's `~/.clawseccheck/` would corrupt a real
    baseline as a side effect of testing."""
    src = GATE_PATH.read_text(encoding="utf-8")
    assert '"--data-dir", str(store)' in src
    assert "tempfile.mkdtemp" in src
    assert "shutil.rmtree" in src
