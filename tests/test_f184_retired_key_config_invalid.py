"""B382 -- openclaw.json still holds a key the installed OpenClaw build removed.

The claim is deliberately narrow: the strict config schema rejects the file, so
`openclaw config validate` and CLI commands that load it report it invalid until
`openclaw doctor --fix` runs. The verdict and `detail` assert nothing about gateway
behaviour. Only the `fix` advice says who repairs the file, and it is version-aware
(C-645): through 2026.9.6 the gateway repaired a legacy file itself in memory (except
behind an `$include`); from 2026.9.7 startup repairs nothing and only Doctor does.

Two layers, matching test_b700: always-on behaviour tests, and a LOCAL-ONLY oracle that
EXECUTES the installed root schema over every key in the shipped table. A key the vendor
still accepts must not be in the table.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from _distgrounding import dist_file, require_dist
from test_b700_version_aware_advice import RETIRED_IN_2026_8_1, RETIRED_IN_2026_9_3

import clawseccheck.checks as C
from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks._config import check_retired_config_keys_invalid
from clawseccheck.checks._shared import (
    _RETIRED_CONFIG_KEYS,
    _STARTUP_REPAIR_REMOVED_MIN,
    _retired_keys_present,
)
from clawseccheck.collector import Context, collect
from clawseccheck.configloader import load_openclaw_config

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
MODERN = "2026.9.4"
LEGACY = "2026.7.1-2"

_BANNED = ("will not start", "refuses to start", "in effect", "unreliable")


def _ctx(cfg, installed, found=True):
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_found = found
    c.installed_dist_version = installed
    return c


def _run(cfg, installed):
    return check_retired_config_keys_invalid(_ctx(cfg, installed))


# --------------------------------------------------------------- verdicts

def test_retired_key_on_a_modern_build_warns_and_names_the_key():
    f = _run({"commands": {"useAccessGroups": False}}, MODERN)
    assert f.status == WARN
    assert "commands.useAccessGroups" in f.detail
    assert "openclaw doctor --fix" in f.fix
    assert f.evidence == ["commands.useAccessGroups"]


def test_presence_not_truthiness():
    for v in (False, None, 0, "", []):
        assert _run({"commands": {"useAccessGroups": v}}, MODERN).status == WARN


def test_older_build_is_quiet():
    f = _run({"commands": {"useAccessGroups": False}}, LEGACY)
    assert f.status == PASS
    assert "useAccessGroups" not in f.detail


def test_unknown_installed_version_is_not_adverse():
    f = _run({"commands": {"useAccessGroups": False}}, None)
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"
    assert "not determined" in f.detail


def test_clean_modern_config_passes_verified():
    f = _run({"logging": {"audit": {"enabled": True}}, "gateway": {"port": 1}}, MODERN)
    assert f.status == PASS
    assert f.pass_confidence != "no_signal"


def test_symlink_knob_is_build_scoped():
    cfg = {"skills": {"workshop": {"allowSymlinkTargetWrites": True}}}
    assert _run(cfg, "2026.9.2").status == PASS
    assert _run(cfg, "2026.9.3").status == WARN
    assert _run(cfg, MODERN).status == WARN


def test_stamp_never_substitutes_for_the_installed_build():
    cfg = {"meta": {"lastTouchedVersion": MODERN}, "commands": {"useAccessGroups": False}}
    assert _run(cfg, None).status != WARN
    assert _run(cfg, LEGACY).status != WARN


def test_unreadable_and_absent_config_is_unknown():
    assert check_retired_config_keys_invalid(_ctx({}, MODERN, found=False)).status == UNKNOWN


def test_never_fails_and_is_unscored():
    assert BY_ID["B382"].scored is False
    for cfg in ({}, {"audit": {"enabled": True}}, {"agents": {"list": []}}):
        for v in (MODERN, LEGACY, None):
            assert _run(cfg, v).status != FAIL


def test_warn_text_makes_no_gateway_claim_and_no_values():
    secret = "value-marker-" + "x9y8z7"
    cfg = {"logging": {"redactSensitive": secret}, "audit": {"enabled": True}}
    f = _run(cfg, MODERN)
    assert f.status == WARN
    blob = (f.detail + " " + f.fix + " " + " ".join(f.evidence or [])).lower()
    for phrase in _BANNED:
        assert phrase not in blob
    assert secret not in blob
    assert "logging.audit.enabled" in blob  # the replacement is named for audit.enabled


def test_names_every_key_and_a_dotted_key_needs_the_whole_path():
    cfg = {"marketplaces": {"feeds": {}, "sources": []},
           "gateway": {"nodes": {"allowCommands": []}},
           "logging": {"audit": {"enabled": True}}}
    f = _run(cfg, MODERN)
    assert set(f.evidence) == {"marketplaces.feeds", "marketplaces.sources",
                               "gateway.nodes.allowCommands"}
    # the same last segment elsewhere is not the retired key
    assert _run({"foo": {"enabled": True}, "x": {"list": []}}, MODERN).status == PASS


def test_non_dict_intermediate_does_not_crash():
    assert _run({"audit": "x", "agents": [1], "commands": None}, MODERN).status == PASS


def test_registered_in_the_run():
    assert check_retired_config_keys_invalid in C.CHECKS


def test_fixtures():
    for name, want in (("bad_f184_retired_key_config_invalid", WARN),
                       ("clean_f184_no_retired_keys", PASS)):
        ctx = collect(str(FIXTURES / name))
        ctx.installed_dist_version = MODERN
        f = next(x for x in C.run_all(ctx) if x.id == "B382")
        assert f.status == want, (name, f.detail)


# ----------------------------------------- C-645: tools.toolSearch.codeTimeoutMs (2026.9.7)

_TOOLSEARCH = {"tools": {"toolSearch": {"codeTimeoutMs": 5000}}}
NEW_BUILD = "2026.9.7"
PRE_REMOVAL_BUILD = "2026.9.6"


def test_code_timeout_key_warns_on_2026_9_7_and_names_the_key():
    f = _run(_TOOLSEARCH, NEW_BUILD)
    assert f.status == WARN
    assert f.evidence == ["tools.toolSearch.codeTimeoutMs"]
    assert "tools.toolSearch.codeTimeoutMs (removed)" in f.detail


def test_code_timeout_key_is_quiet_on_the_last_build_that_still_accepts_it():
    # EXECUTED against the extracted 2026.9.6 package's root zod schema: accepted.
    f = _run(_TOOLSEARCH, PRE_REMOVAL_BUILD)
    assert f.status == PASS
    assert "codeTimeoutMs" not in f.detail


def test_code_timeout_key_unknown_build_is_not_adverse():
    f = _run(_TOOLSEARCH, None)
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"


def test_live_toolsearch_siblings_are_not_flagged_on_2026_9_7():
    # `enabled` is accepted by both 2026.9.6 and 2026.9.7 (control for the measured reject).
    cfg = {"tools": {"toolSearch": {"enabled": True}}}
    assert _run(cfg, NEW_BUILD).status == PASS


def test_code_timeout_key_behind_include_warns_the_same(tmp_path):
    _write(tmp_path / "fragment.json5", '{"tools": {"toolSearch": {"codeTimeoutMs": 5000}}}')
    _write(tmp_path / "openclaw.json", '{"$include": "./fragment.json5"}')
    cfg = load_openclaw_config(tmp_path / "openclaw.json", root_byte_limit=5_000_000)
    assert _run(cfg, NEW_BUILD).evidence == ["tools.toolSearch.codeTimeoutMs"]


# ------------------------------------- C-645: the repair advice names who repairs the file
#
# The `fix` text used to say "A config that uses $include may be refused automatic repair",
# grounded on the gateway's startup self-heal. 2026.9.7 removed that self-heal, so on that
# build the sentence described something that no longer runs. It must say what is TRUE
# there -- startup repairs nothing, Doctor does, and Doctor's own automatic preflight repair
# may decline an $include config -- and keep the original wording for every other build.

_OLD_INCLUDE_HEDGE = "A config that uses $include may be refused automatic repair"
_NEW_STARTUP_SENTENCE = "does not repair a legacy config at startup"


def test_fix_on_2026_9_7_says_startup_no_longer_repairs_and_doctor_does():
    f = _run({"commands": {"useAccessGroups": False}}, NEW_BUILD)
    assert f.status == WARN
    assert _NEW_STARTUP_SENTENCE in f.fix
    assert "only Doctor does" in f.fix
    assert "openclaw doctor --fix" in f.fix
    assert "config validate" in f.fix
    # the include caveat survives, scoped to Doctor's own automatic preflight repair
    assert "$include" in f.fix
    assert "Doctor's automatic preflight repair" in f.fix
    # ... and the sentence that described the removed startup self-heal is gone
    assert _OLD_INCLUDE_HEDGE not in f.fix


def test_fix_on_older_builds_keeps_the_original_include_hedge():
    for installed in (MODERN, PRE_REMOVAL_BUILD):
        f = _run({"commands": {"useAccessGroups": False}}, installed)
        assert f.status == WARN
        assert _OLD_INCLUDE_HEDGE in f.fix, installed
        assert _NEW_STARTUP_SENTENCE not in f.fix, installed


def test_the_repair_advice_lives_in_fix_and_detail_is_identical_across_builds():
    # baseline.fingerprint() hashes `detail`: moving the sentence there would orphan a
    # user's .clawseccheckignore entry. Same key, same detail wording on 2026.9.6 and 2026.9.7
    # apart from the build number the sentence quotes.
    cfg = {"commands": {"useAccessGroups": False}}
    old = _run(cfg, PRE_REMOVAL_BUILD).detail
    new = _run(cfg, NEW_BUILD).detail
    assert new == old.replace(PRE_REMOVAL_BUILD, NEW_BUILD)
    assert "startup" not in new.lower()


def test_fix_advice_keeps_the_no_gateway_claim_vocabulary_out_of_detail_and_fix():
    cfg = {"commands": {"useAccessGroups": False}}
    for installed in (MODERN, NEW_BUILD):
        f = _run(cfg, installed)
        blob = (f.detail + " " + f.fix).lower()
        for phrase in _BANNED:
            assert phrase not in blob, (installed, phrase)


def test_repair_removal_constant_is_the_2026_9_7_boundary():
    assert _STARTUP_REPAIR_REMOVED_MIN == (2026, 9, 7)
    # and it is the same build that retired the toolSearch key, measured on the same day
    assert _RETIRED_CONFIG_KEYS["tools.toolSearch.codeTimeoutMs"][1] == _STARTUP_REPAIR_REMOVED_MIN


# ------------------------------------------------------- C-577: $include invariance
#
# F-184 deliberately left open whether the collector needs to know an `$include` is
# present, pending a reproduction. Answer: no. `_retired_keys_present` reads
# `ctx.config`, which `collector.collect()` populates from
# `configloader.load_openclaw_config()` -- already the fully `$include`-resolved,
# deep-merged dict -- so a retired key is exactly as visible behind an `$include` as it
# is in the root file. These tests load through the REAL configloader (not a hand-built
# dict) so the merge itself is exercised, not just the structural-presence check.


def _write(p, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_retired_key_behind_include_warns_the_same_as_direct(tmp_path):
    _write(tmp_path / "fragment.json5", '{"commands": {"useAccessGroups": false}}')
    _write(tmp_path / "openclaw.json", '{"$include": "./fragment.json5"}')
    cfg = load_openclaw_config(tmp_path / "openclaw.json", root_byte_limit=5_000_000)
    included = _run(cfg, MODERN)
    direct = _run({"commands": {"useAccessGroups": False}}, MODERN)
    assert included.status == direct.status == WARN
    assert included.evidence == direct.evidence == ["commands.useAccessGroups"]
    assert "commands.useAccessGroups" in included.detail


def test_clean_config_behind_include_still_passes(tmp_path):
    _write(tmp_path / "fragment.json5", '{"gateway": {"bind": "127.0.0.1"}}')
    _write(tmp_path / "openclaw.json", '{"$include": "./fragment.json5"}')
    cfg = load_openclaw_config(tmp_path / "openclaw.json", root_byte_limit=5_000_000)
    f = _run(cfg, MODERN)
    assert f.status == PASS
    assert f.pass_confidence != "no_signal"


def test_retired_key_as_an_include_sibling_still_warns(tmp_path):
    # The retired key sits beside the $include directive in the root file itself, rather
    # than inside the fragment -- the other authoring shape OpenClaw's own docs allow.
    _write(tmp_path / "fragment.json5", '{"gateway": {"bind": "127.0.0.1"}}')
    _write(tmp_path / "openclaw.json",
          '{"$include": "./fragment.json5", "commands": {"useAccessGroups": false}}')
    cfg = load_openclaw_config(tmp_path / "openclaw.json", root_byte_limit=5_000_000)
    f = _run(cfg, MODERN)
    assert f.status == WARN
    assert f.evidence == ["commands.useAccessGroups"]


# ---------------------------------------- C-577 / C-645: dist grounding for the repair hedge
#
# `check_retired_config_keys_invalid`'s `fix` text says who repairs a legacy file, and the
# answer changed between 2026.9.6 and 2026.9.7:
#
#   through 2026.9.6  the gateway's pre-bootstrap step ran `resolveStartupConfigSnapshot`
#                     and repaired the file IN MEMORY -- except behind an `$include`, where
#                     `admitAutomaticConfigRepairSnapshot` declined. That is where the
#                     "$include may be refused automatic repair" hedge came from (10d766a).
#   from 2026.9.7     `resolveStartupConfigSnapshot` is declared nowhere; startup validates
#                     without rewriting ("legacy imports and repair receipts belong to
#                     Doctor") and only Doctor's own preflight calls the repair planner.
#
# The first version of this pin globbed `automatic-startup-config-repair-*.mjs` and went red
# when 2026.9.7 renamed the file. Re-globbing the new name alone would have turned it green
# while pinning a claim -- the gateway-run bootstrap wires the gate -- that is FALSE on
# 2026.9.7. So the pin is re-grounded twice: the gate's body (located by SYMBOL, in either
# spelling of the file name), and the WIRING, asserted in both directions against
# `_STARTUP_REPAIR_REMOVED_MIN` so the constant cannot drift from the vendor.


def test_automatic_repair_gate_still_declines_on_include_present():
    require_dist()
    path = dist_file(
        "automatic-*config-repair-*.mjs",
        symbol="admitAutomaticConfigRepairSnapshot",
        contains="function admitAutomaticConfigRepairSnapshot",
    )
    text = path.read_text(encoding="utf-8", errors="replace")
    assert "containsConfigIncludeDirective" in text
    assert "includedPaths" in text


def test_startup_wiring_matches_the_removal_constant():
    """`_STARTUP_REPAIR_REMOVED_MIN` says startup repair is gone from 2026.9.7. Ask the
    installed dist: the bootstrap references the startup-repair resolver exactly when the
    installed build is OLDER than the constant, and never when it is at or above it. On a
    build at or above it, also read what replaced it: the startup preflight leaves legacy
    repair to Doctor, and the repair planner is committed from Doctor's flow."""
    require_dist()
    installed = _installed_tuple()
    assert installed is not None, "could not read the installed OpenClaw version"
    bootstrap = dist_file(
        "pre-bootstrap-*.mjs",
        symbol="prepareGatewayRunBootstrap (the gateway-run bootstrap)",
        contains="function prepareGatewayRunBootstrap",
    ).read_text(encoding="utf-8", errors="replace")
    wired = "resolveStartupConfigSnapshot" in bootstrap
    assert wired == (installed < _STARTUP_REPAIR_REMOVED_MIN), (installed, wired)
    if installed >= _STARTUP_REPAIR_REMOVED_MIN:
        preflight = dist_file(
            "startup-config-preflight-*.mjs",
            symbol="runStartupConfigPreflight",
            contains="function runStartupConfigPreflight",
        ).read_text(encoding="utf-8", errors="replace")
        assert "legacy imports and repair receipts belong to Doctor" in preflight
        doctor = dist_file(
            "doctor-config-flow-*.mjs",
            symbol="commitAutomaticConfigRepair (Doctor's preflight caller)",
            contains="commitAutomaticConfigRepair",
        ).read_text(encoding="utf-8", errors="replace")
        assert "planAutomaticConfigRepair" in doctor


# --------------------------------------------------- single table, two guards

def test_package_table_is_the_b700_tables_plus_the_measured_ssrf_and_toolsearch_keys():
    by_min = {}
    for key, (repl, minb) in _RETIRED_CONFIG_KEYS.items():
        by_min.setdefault(minb, {})[key] = repl
    assert by_min[(2026, 8, 1)] == RETIRED_IN_2026_8_1
    assert by_min[(2026, 9, 3)] == RETIRED_IN_2026_9_3
    assert by_min[(2026, 9, 1)] == {
        "browser.ssrfPolicy.hostnameAllowlist": "browser.ssrfPolicy.allowedHostnames"}
    # C-645: 2026.9.7 dropped `tools.toolSearch.codeTimeoutMs` ("Tool Search no longer
    # executes code"); removed outright, no replacement key.
    assert by_min[(2026, 9, 7)] == {"tools.toolSearch.codeTimeoutMs": None}
    assert len(_RETIRED_CONFIG_KEYS) == 14
    assert "marketplaces" not in _RETIRED_CONFIG_KEYS
    # only the KEY is listed: `tools.toolSearch.mode: "code"` is a retired VALUE, which a key
    # table cannot express, and the live sibling `enabled` must never be in it
    assert "tools.toolSearch.mode" not in _RETIRED_CONFIG_KEYS
    assert "tools.toolSearch.enabled" not in _RETIRED_CONFIG_KEYS


def test_helper_reads_only_the_installed_build():
    cfg = {"commands": {"useAccessGroups": True}}
    assert _retired_keys_present(_ctx(cfg, MODERN)) == [("commands.useAccessGroups", None)]
    assert _retired_keys_present(_ctx(cfg, None)) == []


# ------------------------------------------------------------ local-only oracle

_SCRIPT = """
const z = await import(process.env.OC_SCHEMA);
const cases = JSON.parse(process.env.OC_CASES);
const out = {};
for (const [key, kind] of Object.entries(cases)) {
  const cfg = {}; let node = cfg; const parts = key.split(".");
  for (const p of parts.slice(0, -1)) { node[p] = node[p] || {}; node = node[p]; }
  node[parts[parts.length - 1]] = kind === "array" ? [] : true;
  out[key] = z.t.safeParse(cfg).success;
}
console.log(JSON.stringify(out));
"""


def _oracle(keys):
    schema = dist_file("zod-schema-*.js", symbol="the root zod schema bundle (export `t`)")
    cases = {k: ("array" if k.endswith(("list", "Commands", "Allowlist")) else "bool")
             for k in keys}
    env = dict(os.environ, OC_SCHEMA=str(schema), OC_CASES=json.dumps(cases))
    proc = subprocess.run(["node", "--input-type=module", "-e", _SCRIPT],
                          capture_output=True, text=True, timeout=120, env=env)
    if proc.returncode != 0:
        pytest.skip(f"could not execute the dist schema: {proc.stderr.strip()[:200]}")
    return json.loads(proc.stdout)


def _installed_tuple():
    from clawseccheck.openclawdist import _numeric_parts, _read_version
    v = _read_version(require_dist().parent)
    return _numeric_parts(v) if v else None


def test_every_table_key_is_rejected_by_the_installed_schema():
    require_dist()
    installed = _installed_tuple()
    keys = [k for k, (_r, m) in _RETIRED_CONFIG_KEYS.items()
            if installed is not None and installed >= m]
    assert keys, "installed build older than every table entry -- nothing to ground"
    accepted = _oracle(keys)
    assert not [k for k, ok in accepted.items() if ok], accepted


def test_oracle_bites_on_a_still_valid_key():
    """Mutation control: a key the vendor accepts must be reported as accepted."""
    require_dist()
    assert _oracle(["logging.audit.enabled"])["logging.audit.enabled"] is True


def test_toolsearch_sibling_control_is_accepted_and_the_retired_key_is_not():
    """C-645 control pair for the 2026.9.7 row, in ONE oracle call: the live sibling
    `tools.toolSearch.enabled` is accepted while `codeTimeoutMs` is rejected, so a schema
    that simply rejected everything under `tools.toolSearch` could not pass this."""
    require_dist()
    installed = _installed_tuple()
    assert installed is not None
    got = _oracle(["tools.toolSearch.enabled", "tools.toolSearch.codeTimeoutMs"])
    assert got["tools.toolSearch.enabled"] is True
    assert got["tools.toolSearch.codeTimeoutMs"] is (
        installed < _RETIRED_CONFIG_KEYS["tools.toolSearch.codeTimeoutMs"][1])
