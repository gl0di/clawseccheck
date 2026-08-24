"""The judge packet must say what state the RUN was in, not only what each finding was.

B-623. `build_judge_packet` returns a per-item array, so the packet had nowhere to state
anything about the audit that produced it. On a config-blind run that is the difference
between an answerable question and an unanswerable one: measured before this change, a home
with an unparseable `openclaw.json` produced **174 packet items, every one UNKNOWN**, and the
single fact that explains why all 174 are UNKNOWN — the config could not be read — appeared
nowhere in the artifact. An adjudicator handed that can only answer from check titles.

The state rides the ENVELOPE, beside `judgePacket`, not each item: it is per-run, so
repeating it 174 times would be noise, and `build_judge_packet` does not need it to do its
job. Both envelopes carry it — the standalone `--judge-packet` artifact and the `--full`
adjudication phase — because a channel that reaches one surface out of two is the defect this
project has now filed six times (E-078).

Why these tests drive the REAL CLI rather than building a packet by hand: B-556 shipped with
20 green tests that constructed findings themselves, and by construction none of them could
notice that nothing populated the field. A test that hands the code its own input proves the
renderer renders; it cannot prove the producer produces.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import subprocess
import sys

REPO_ARGS = ["-m", "clawseccheck"]


def _run_packet(home, data_dir):
    out = subprocess.run(
        [sys.executable, *REPO_ARGS, "--home", str(home), "--data-dir", str(data_dir),
         "--no-history", "--judge-packet"],
        capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout)


def _blind_home(tmp_path):
    home = tmp_path / "blind"
    home.mkdir()
    (home / "openclaw.json").write_text("{ this is not json at all ", encoding="utf-8")
    return home


def _healthy_home(tmp_path):
    home = tmp_path / "ok"
    home.mkdir()
    (home / "openclaw.json").write_text(
        json.dumps({"channels": {}, "tools": {"allow": ["read_file"]}}), encoding="utf-8")
    return home


def test_a_config_blind_run_tells_the_judge_the_config_could_not_be_read(tmp_path):
    """The reproduction this task was filed on, asserted end to end."""
    packet = _run_packet(_blind_home(tmp_path), tmp_path / "d")
    state = packet["runState"]

    assert state["stated"] is True
    caps = {c["cap"] for c in state["capsFired"]}
    assert "config_blind_capped" in caps, state
    reason = next(c for c in state["capsFired"] if c["cap"] == "config_blind_capped")
    assert reason.get("reason") == "unreadable", reason

    # Non-vacuity: the items really are the undetermined band this exists to explain. A
    # green assertion over an empty packet would prove nothing about either.
    items = packet["judgePacket"]
    assert len(items) > 50, len(items)
    assert all(i["engine_disposition"] == "UNKNOWN" for i in items)


def test_a_healthy_run_states_its_state_without_inventing_a_cap(tmp_path):
    """The control. A block that says something alarming on every run is furniture, and a
    judge learns to skip it — so the healthy case has to be asserted, not assumed."""
    state = _run_packet(_healthy_home(tmp_path), tmp_path / "d")["runState"]
    assert state["stated"] is True
    assert state["capsFired"] == [], state
    assert state["degradedChecks"] == 0, state


def test_the_two_runs_differ_so_the_block_is_not_a_constant(tmp_path):
    """Guard the guard: both tests above could pass against a hardcoded dict."""
    blind = _run_packet(_blind_home(tmp_path), tmp_path / "d1")["runState"]
    healthy = _run_packet(_healthy_home(tmp_path), tmp_path / "d2")["runState"]
    assert blind != healthy
    assert blind["capsFired"] and not healthy["capsFired"]


def test_no_config_content_crosses_into_the_packet(tmp_path):
    """Golden Rule #1: the packet is pasted into a possibly third-party host agent, so only
    STATE may cross — never the config it was read from.

    The secret-shaped value is assembled at runtime from fragments so no contiguous literal
    exists in this file (Golden Rule #3, the `tests/test_logsafe.py` idiom).
    """
    marker = "sk" + "-live-" + "b623" + "canary" + "0000"
    home = tmp_path / "secretive"
    home.mkdir()
    (home / "openclaw.json").write_text(json.dumps({
        "channels": {"telegram": {"enabled": True, "token": marker}},
        "tools": {"allow": ["read_file", "web_fetch"]},
    }), encoding="utf-8")

    packet = _run_packet(home, tmp_path / "d")
    assert marker not in json.dumps(packet["runState"]), "config value reached runState"
    # and the control: the run really did read that config, so the absence means something
    assert packet["runState"]["stated"] is True


def test_an_unstated_run_says_so_rather_than_implying_health():
    """A caller that supplies no score must produce `stated: False`, never an empty-looking
    healthy block. Silence and health are different claims, and the whole point of this
    change is that the packet stops making the second one by omission."""
    from clawseccheck.adjudication import run_state

    assert run_state(None) == {"stated": False}


def test_the_full_pipeline_envelope_carries_it_too(tmp_path):
    """One surface out of two is the shape E-078 exists to stop."""
    from clawseccheck import audit
    from clawseccheck.pipeline import run_adjudication

    ctx, findings, score = audit(_blind_home(tmp_path))
    phase = run_adjudication(ctx, findings, version="test", score=score)
    state = (phase.data or {})["runState"]
    assert state["stated"] is True
    assert {c["cap"] for c in state["capsFired"]} >= {"config_blind_capped"}

    # Without a score the same envelope must still say so rather than omit the key.
    bare = (run_adjudication(ctx, findings, version="test").data or {})["runState"]
    assert bare == {"stated": False}
