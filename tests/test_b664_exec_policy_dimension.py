"""B-664 — the approval gate on unattended shell execution is a watched dimension.

Found by `scripts/monitor_detection_gate.py`, which applies one dangerous change and asks
whether the watch says anything. Fifteen of sixteen did. The silent one was
`tools.exec.mode: "ask" -> "auto"` — the field deciding whether the agent runs a shell
command without asking, one leg of the Lethal Trifecta — and it moved only
`config_file_sha256`, no check status, no score. The run printed "No new threats among what
was compared" and exited 0, so a scheduled job did not page.

**Direction is the calibration**, as it was for `plugins`. Only loosening speaks. Half this
file is the silence side, which is the half that decides whether the dimension is worth
having — and one of those silences is not obvious: `ask` -> `allowlist` REMOVES the human
prompt and is still a tightening, because under `allowlist` a miss is refused rather than
offered to anyone. The first draft of the arm alerted on it.

**The resolution is executed, not read.** `test_the_port_matches_the_installed_dist` runs
the REAL `resolveExecModePolicy` / `resolveExecPolicyForMode` / `resolveExecModeFromPolicy`
out of the installed OpenClaw over a 96-combination matrix and requires the port to agree on
every one. That test is local-only (it needs the dist and `node`); everything else runs
anywhere. Reading alone was not enough and executing alone was not either — see the module
docstring of `clawseccheck/monitordims/_execpolicy.py` for how the two disagree and why the
CALL SITE is what settles the default.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from clawseccheck import monitor
from clawseccheck.cli import main
from clawseccheck.monitor import _CONFIG_DIMENSIONS, WATCHED_DIMENSIONS, diff
from clawseccheck.monitordims._execpolicy import (
    _MODE_POLICY,
    _exec_policy_sig,
    _resolve_mode_from_policy,
)

_DIST = Path("/home/glodi/.npm-global/lib/node_modules/openclaw/dist")
_VENDOR = _DIST / "exec-approvals-BIKWP8_V.js"


class _Ctx:
    def __init__(self, config):
        self.config = config


def _sig(exec_cfg, **extra) -> dict:
    cfg = {"tools": {"exec": exec_cfg}} if exec_cfg is not None else {"tools": {}}
    cfg.update(extra)
    return _exec_policy_sig(_Ctx(cfg))


def _global(exec_cfg, **extra) -> dict:
    """The `global` scope's resolved record, for the single-scope assertions."""
    return _sig(exec_cfg, **extra)["scopes"]["global"]


def _snap(exec_policy=None, **kw) -> dict:
    base = {
        "version": monitor.SNAPSHOT_VERSION,
        "checks": {}, "graded": True, "score": 50, "raw_score": 50, "grade": "F",
        "scope": ["host"], "watched": list(WATCHED_DIMENSIONS),
        "config_ever_seen": True,
        "config_file_sha256": "a" * 64, "config_resolved_sha256": "b" * 64,
        "mcp": {}, "mcp_detail": {}, "channels": {}, "gateway_bind": "127.0.0.1",
        "plugins": {},
    }
    if exec_policy is not None:
        base["exec_policy"] = exec_policy
    base.update(kw)
    return base


def _exec_alerts(prev: dict, curr: dict):
    """Every alert this dimension produces names `tools.exec`.

    Matched on that rather than on the sentences, for the reason B-659's file records: an
    arm added later would otherwise be invisible to every silence assertion below, which is
    where the value of this file is.
    """
    return [(lvl, msg) for lvl, msg in diff(prev, curr) if "tools.exec" in msg]


def _p(exec_cfg, **extra):
    """The recorded policy for a `tools.exec` value, as the snapshot would store it."""
    return _sig(exec_cfg, **extra)


# ------------------------------------------------------------------ grounding

@pytest.mark.skipif(not _VENDOR.exists() or not shutil.which("node"),
                    reason="needs the installed OpenClaw dist and node — local-only layer")
def test_the_port_matches_the_installed_dist(tmp_path):
    """Execute the vendor's own resolver over every combination and require agreement.

    96 combinations: 6 modes (including absent) x 4 securities x 4 asks. A table copied by
    eye is exactly the kind of thing that is right in the cases someone thought about.
    """
    script = tmp_path / "vendor.mjs"
    script.write_text('''
import { readFileSync } from "node:fs";
const src = readFileSync(%s, "utf8");
const grab = (name) => {
  const i = src.indexOf(`function ${name}(`);
  if (i < 0) throw new Error("missing " + name);
  let d = 0;
  for (let k = src.indexOf("{", i); k < src.length; k++) {
    if (src[k] === "{") d++;
    else if (src[k] === "}") { d--; if (d === 0) return src.slice(i, k + 1); }
  }
  throw new Error("unbalanced " + name);
};
const fn = new Function([grab("resolveExecPolicyForMode"), grab("resolveExecModeFromPolicy"),
                         grab("resolveExecModePolicy")].join("\\n")
                        + "\\nreturn resolveExecModePolicy;")();
const out = [];
for (const mode of [undefined, "deny", "allowlist", "ask", "auto", "full"])
  for (const security of [undefined, "deny", "allowlist", "full"])
    for (const ask of [undefined, "off", "on-miss", "always"]) {
      const r = fn({ mode, security, ask });
      out.push({ in: { mode: mode ?? null, security: security ?? null, ask: ask ?? null },
                 out: { mode: r.mode ?? null, security: r.security ?? null,
                        ask: r.ask ?? null, autoReview: r.autoReview ?? null } });
    }
console.log(JSON.stringify(out));
''' % json.dumps(str(_VENDOR)), encoding="utf-8")
    proc = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr[-2000:]
    rows = json.loads(proc.stdout)
    assert len(rows) == 96, len(rows)

    for r in rows:
        mode, sec, ask = r["in"]["mode"], r["in"]["security"], r["in"]["ask"]
        if mode is None:
            got = {"mode": _resolve_mode_from_policy(sec, ask), "security": sec,
                   "ask": ask, "autoReview": False}
        else:
            s, a, ar = _MODE_POLICY[mode]
            got = {"mode": mode, "security": s, "ask": a, "autoReview": ar}
        assert got == r["out"], f"in={r['in']} vendor={r['out']} port={got}"


def test_the_dimension_is_registered_as_config_derived():
    assert "exec_policy" in WATCHED_DIMENSIONS
    assert "exec_policy" in _CONFIG_DIMENSIONS


def test_an_absent_tools_exec_resolves_to_the_permissive_default():
    """The call site applies `security ?? "full"` and `ask ?? "off"`, so a config that says
    nothing about exec is NOT gated. Reading the resolver alone suggests `"ask"`; that is
    the trap this pins."""
    assert _global(None) == {"mode": "full", "security": "full", "ask": "off",
                             "auto_review": False}


# ------------------------------------------------------------- loosening speaks

def test_the_filed_case_ask_to_auto_alerts():
    """B-664 itself: the confinement does not move, and the human leaves the loop."""
    alerts = _exec_alerts(_snap(_p({"mode": "ask"})), _snap(_p({"mode": "auto"})))
    assert len(alerts) == 1, alerts
    lvl, msg = alerts[0]
    assert lvl == "HIGH"
    assert "without you" in msg and "ask -> auto" in msg


def test_widening_the_confinement_alerts():
    alerts = _exec_alerts(_snap(_p({"mode": "allowlist"})), _snap(_p({"mode": "full"})))
    assert len(alerts) == 1 and alerts[0][0] == "HIGH", alerts
    assert "wider set" in alerts[0][1]


def test_deny_to_allowlist_is_medium_not_high():
    """Still confined to a list, so it is news without being an emergency."""
    alerts = _exec_alerts(_snap(_p({"mode": "deny"})), _snap(_p({"mode": "allowlist"})))
    assert len(alerts) == 1 and alerts[0][0] == "MEDIUM", alerts


def test_removing_tools_exec_entirely_alerts():
    """Deleting the section is not neutral — it resolves to `full`."""
    alerts = _exec_alerts(_snap(_p({"mode": "ask"})), _snap(_p(None)))
    assert alerts and any(lvl == "HIGH" for lvl, _ in alerts), alerts


def test_one_edit_is_reported_once():
    """`ask` -> `full` satisfies BOTH arms. Reporting an edit twice is a defect in this
    repo (the bootstrap/memory overlap, the new-file overlap, the args_pkg/args0 collapse),
    and the widening sentence already says 'full' means any command."""
    alerts = _exec_alerts(_snap(_p({"mode": "ask"})), _snap(_p({"mode": "full"})))
    assert len(alerts) == 1, alerts
    assert "wider set" in alerts[0][1]


# ---------------------------------------------------------------- silence side

def test_ask_to_allowlist_says_nothing_even_though_the_prompt_is_gone():
    """The non-obvious one, and the first draft got it wrong.

    `allowlist` removes the human prompt, which looks like the very thing the second arm
    watches for — but under `allowlist` a miss is REFUSED, so nothing new can run and there
    is no approval to lose. Alerting here would fire on an operator tightening their setup.
    """
    assert _exec_alerts(_snap(_p({"mode": "ask"})), _snap(_p({"mode": "allowlist"}))) == []


def test_restoring_the_human_says_nothing():
    assert _exec_alerts(_snap(_p({"mode": "auto"})), _snap(_p({"mode": "ask"}))) == []


def test_adding_oversight_says_nothing():
    assert _exec_alerts(_snap(_p({"mode": "allowlist"})), _snap(_p({"mode": "ask"}))) == []


def test_tightening_to_deny_says_nothing():
    assert _exec_alerts(_snap(_p({"mode": "full"})), _snap(_p({"mode": "deny"}))) == []


def test_the_same_policy_written_two_ways_says_nothing():
    """`{"mode": "ask"}` and `{"security": "allowlist", "ask": "on-miss"}` are one policy.

    This is why the RESOLVED triple is recorded rather than the raw fields: diffing the raw
    form would alert on a rewrite that changed nothing, which is what an OpenClaw upgrade or
    `doctor --fix` produces.
    """
    long_way = {"security": "allowlist", "ask": "on-miss"}
    assert _exec_alerts(_snap(_p({"mode": "ask"})), _snap(_p(long_way))) == []
    assert _exec_alerts(_snap(_p(long_way)), _snap(_p({"mode": "ask"}))) == []


def test_an_unchanged_policy_says_nothing():
    assert _exec_alerts(_snap(_p({"mode": "ask"})), _snap(_p({"mode": "ask"}))) == []


def test_a_baseline_predating_the_dimension_says_nothing():
    """No `exec_policy` key at all — the arm stands down rather than comparing against a
    default it invented."""
    assert _exec_alerts(_snap(), _snap(_p({"mode": "full"}))) == []


def test_a_damaged_record_is_disclosed_rather_than_skipped_quietly():
    """`pair_or_note`, not `_both_dims`: this dimension is high-consequence, so a
    comparison the run declined to make must be said. The two states it splits call for
    opposite actions — a baseline that predates the dimension heals itself next run, a
    damaged record stays damaged until the state file is deleted."""
    alerts, notes = monitor.diff_with_notes(_snap(_p({"mode": "ask"})), _snap(["junk"]))
    assert not [m for _, m in alerts if "tools.exec" in m], alerts
    assert any("shell-approval policy" in m for _, m in notes), notes


# ------------------------------------------------------------------ undetermined

def test_an_unresolved_substitution_is_undetermined_never_a_policy():
    """`tools.exec.mode: "${MODE}"` could expand to anything. Treating the literal text as
    a mode would compare as a policy nobody configured — the same hazard B-397 fixed for
    B326, caught by the same helper."""
    rec = _global({"mode": "${EXEC_MODE}"})
    assert "undetermined" in rec and "mode" not in rec


def test_a_mode_openclaw_would_reject_is_undetermined():
    """`resolveExecPolicyForMode` THROWS on an unknown mode, so OpenClaw would refuse to
    start. A config that cannot load has no effective policy to compare."""
    rec = _global({"mode": "yolo"})
    assert "undetermined" in rec


def test_an_explicit_sandbox_host_is_determined_not_undetermined():
    """The FIRST version of this guard had it backwards, and the C-135 pass caught it.

    An EXPLICIT target never enters `resolveExecTarget`'s `sandboxAvailable` ternary, so
    `host: "sandbox"` is fully determined — `defaultSecurity` is `deny`. Calling it
    undetermined silenced the dimension permanently for every sandbox user.
    """
    assert _global({"host": "sandbox"}) == {"mode": "deny", "security": "deny",
                                            "ask": "off", "auto_review": False}


def test_a_session_dependent_sandbox_is_undetermined():
    """`shouldSandboxSession` is unconditional for "all" and "off" and genuinely
    per-session for "non-main" — which is the one case that cannot be decided statically."""
    rec = _global(None, agents={"defaults": {"sandbox": {"mode": "non-main"}}})
    assert "undetermined" in rec, rec


def test_a_sandbox_that_always_applies_makes_the_default_deny():
    """`defaultSecurity = effectiveHost === "sandbox" ? "deny" : "full"`. Under
    `sandbox.mode: "all"` an absent `tools.exec` is the TIGHTEST policy, not the loosest —
    the inversion behind the worst false positive this dimension had."""
    assert _global(None, agents={"defaults": {"sandbox": {"mode": "all"}}})["security"] == "deny"


def test_a_mode_set_alongside_a_sandbox_is_still_determined():
    """The sandbox decides only the DEFAULT security, and a mode replaces the whole triple
    (`applyExecPolicyLayer`). Checking the sandbox unconditionally made every sandbox user
    with an explicit mode permanently silent."""
    assert _global({"host": "sandbox", "mode": "auto"})["auto_review"] is True
    assert _global({"mode": "deny"}, agents={"defaults": {"sandbox": {"mode": "non-main"}}}
                   )["security"] == "deny"


def test_an_empty_mode_is_treated_as_absent_the_way_the_dist_does():
    """`if (layer.mode)` is a truthiness test, so `""` is not a mode OpenClaw rejects — it
    is a mode OpenClaw ignores."""
    assert _global({"mode": ""})["security"] == "full"


def test_a_host_is_compared_raw_because_the_dist_does_not_trim():
    assert _global({"host": " sandbox "})["security"] == "full"


def test_a_non_string_value_is_undetermined_not_the_permissive_default():
    """The type of the garbage used to decide whether the arm stood down or fired HIGH: an
    unrecognised STRING reached `undetermined`, while a list or a bool fell past the
    isinstance guards to `full` — the top of the rank — and alerted."""
    for value in ([" deny"], 1, True, {"m": 1}):
        assert "undetermined" in _global({"mode": value}), value
        assert "undetermined" in _global({"security": value}), value


def test_an_undetermined_side_produces_a_note_and_no_alert():
    alerts, notes = monitor.diff_with_notes(_snap(_p({"mode": "ask"})),
                                            _snap(_p({"mode": "${X}"})))
    assert not [m for _, m in alerts if "tools.exec" in m], alerts
    assert any("shell-approval policy could not be determined" in m for _, m in notes), notes


def test_an_unparseable_config_records_nothing_rather_than_a_default():
    """`ctx.config` is not a dict — recording the permissive default here would say the
    gate is gone when the truth is that nothing was read."""
    assert _exec_policy_sig(_Ctx(None)) == {}


# ------------------------------------------- what the C-135 pass disproved

def test_dropping_a_redundant_allowlist_under_a_sandbox_says_nothing():
    """FP-A. With `sandbox.mode: "all"` the default is `deny`, so deleting a `tools.exec`
    block that the sandbox already subsumes TIGHTENS the policy. The first version reported
    it as `allowlist -> full` at HIGH — an inverted verdict."""
    sandbox = {"defaults": {"sandbox": {"mode": "all"}}}
    before = _snap(_p({"security": "allowlist"}, agents=sandbox))
    after = _snap(_p(None, agents=sandbox))
    assert _exec_alerts(before, after) == []


def test_changing_a_global_no_agent_uses_says_nothing():
    """FP-B. `agents.list[].tools.exec` REPLACES the global for that agent, so with every
    agent overridden the global is inert and an edit to it changes nothing."""
    agents = {"list": [{"id": "main", "tools": {"exec": {"mode": "ask"}}}]}
    before = _snap(_p({"mode": "deny"}, agents=agents))
    after = _snap(_p({"mode": "full"}, agents=agents))
    assert _exec_alerts(before, after) == []


def test_changing_a_global_one_agent_still_uses_does_alert():
    """The other side of FP-B, so the fix cannot be "go quiet whenever agents exist"."""
    agents = {"list": [{"id": "main"}, {"id": "b", "tools": {"exec": {"mode": "ask"}}}]}
    before = _snap(_p({"mode": "deny"}, agents=agents))
    after = _snap(_p({"mode": "full"}, agents=agents))
    alerts = _exec_alerts(before, after)
    assert len(alerts) == 1 and alerts[0][0] == "HIGH", alerts


def test_an_agents_own_override_loosening_alerts_and_names_it():
    agents_before = {"list": [{"id": "main", "tools": {"exec": {"mode": "ask"}}}]}
    agents_after = {"list": [{"id": "main", "tools": {"exec": {"mode": "auto"}}}]}
    alerts = _exec_alerts(_snap(_p({"mode": "deny"}, agents=agents_before)),
                          _snap(_p({"mode": "deny"}, agents=agents_after)))
    assert len(alerts) == 1, alerts
    assert "for agent 'main'" in alerts[0][1], alerts[0][1]


def test_dropping_an_allowlist_while_every_request_still_prompts_says_nothing():
    """FP-C. `ask: "always"` prompts a human on EVERY request, so the set of commands the
    agent can run unattended is empty either way. The old alert said 'any command, with no
    allow list at all' — and rendered as `(tools.exec: ask -> ask)`, refuting itself."""
    before = _snap(_p({"security": "allowlist", "ask": "always"}))
    after = _snap(_p({"security": "full", "ask": "always"}))
    assert _exec_alerts(before, after) == []


def test_a_non_string_value_appearing_says_nothing():
    """FP-D. OpenClaw would refuse to start on these, so nothing ran; the old code read
    them as the permissive default and reported `deny -> full`."""
    assert _exec_alerts(_snap(_p({"mode": "deny"})), _snap(_p({"mode": ["deny"]}))) == []
    assert _exec_alerts(_snap(_p({"security": "deny"})), _snap(_p({"security": True}))) == []


def test_the_sandbox_being_switched_off_does_alert():
    """`sandbox.mode: "all" -> "off"` moves the default from `deny` to `full` with no
    `tools.exec` in sight. Modelling the sandbox is what makes this visible at all."""
    before = _snap(_p(None, agents={"defaults": {"sandbox": {"mode": "all"}}}))
    after = _snap(_p(None, agents={"defaults": {"sandbox": {"mode": "off"}}}))
    alerts = _exec_alerts(before, after)
    assert len(alerts) == 1 and alerts[0][0] == "HIGH", alerts


# ---------------------------------------------------------- the blind-run guard

def _write(home: Path, body: dict) -> None:
    home.mkdir(exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps(body), encoding="utf-8")
    os.chmod(cfg, 0o600)


_POPULATED = {
    "gateway": {"bind": "127.0.0.1:8080",
                "auth": {"mode": "token", "token": "a-very-long-token-of-32-chars!!"}},
    "tools": {"exec": {"mode": "ask"}},
    "channels": {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
}


def test_the_blind_run_carries_the_policy_forward(tmp_path, capsys):
    """The guard with teeth, per B-659's measured lesson: this arm is presence-guarded, so a
    collapsed `{}` makes it silent IMMEDIATELY — the damage of a missing `_CONFIG_DIMENSIONS`
    entry is deferred to the run after recovery, which a "no alert this run" assertion cannot
    see. Dropping `exec_policy` from that tuple must redden THIS test."""
    home, store = tmp_path / "home", tmp_path / "store"
    _write(home, _POPULATED)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    capsys.readouterr()
    before = json.loads((store / "state.json").read_text(encoding="utf-8"))["exec_policy"]
    assert before["scopes"]["global"]["mode"] == "ask", before

    os.chmod(home / "openclaw.json", 0o000)
    try:
        main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    finally:
        os.chmod(home / "openclaw.json", 0o600)
    capsys.readouterr()
    after = json.loads((store / "state.json").read_text(encoding="utf-8"))["exec_policy"]
    assert after == before, f"the blind run overwrote the policy baseline: {before} -> {after}"


def test_a_blind_run_produces_no_exec_alert(tmp_path, capsys):
    home, store = tmp_path / "home", tmp_path / "store"
    _write(home, _POPULATED)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    capsys.readouterr()
    os.chmod(home / "openclaw.json", 0o000)
    try:
        main(["--monitor", "--home", str(home), "--data-dir", str(store)])
        out = capsys.readouterr().out
    finally:
        os.chmod(home / "openclaw.json", 0o600)
    assert "tools.exec" not in out, out


# ------------------------------------------------------------------ end to end

def test_the_filed_repro_now_pages(tmp_path, capsys):
    """Through the real CLI under the flags the shipped cron recipe uses. The bug was not
    only that the screen said nothing — it was that `--exit-code` returned 0, so a scheduled
    job never woke anyone."""
    home, store = tmp_path / "home", tmp_path / "store"
    _write(home, _POPULATED)
    rc0 = main(["--monitor", "--home", str(home), "--data-dir", str(store),
                "--exit-code", "--fail-on", "medium"])
    capsys.readouterr()
    assert rc0 == 0, "the baseline run was not clean"

    _write(home, {**_POPULATED, "tools": {"exec": {"mode": "auto"}}})
    rc1 = main(["--monitor", "--home", str(home), "--data-dir", str(store),
                "--exit-code", "--fail-on", "medium"])
    out = capsys.readouterr().out
    assert "without you" in out, out
    assert rc1 == 3, f"the watch printed the alert but exited {rc1} — a cron job stays asleep"
