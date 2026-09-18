"""B382 -- openclaw.json still holds a key the installed OpenClaw build removed.

The claim is deliberately narrow: the strict config schema rejects the file, so
`openclaw config validate` and CLI commands that load it report it invalid until
`openclaw doctor --fix` runs. Nothing here asserts gateway behaviour -- that was measured on
one build only, and the gateway repairs a legacy file itself in the common case.

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
from clawseccheck.checks._shared import _RETIRED_CONFIG_KEYS, _retired_keys_present
from clawseccheck.collector import Context, collect

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


# --------------------------------------------------- single table, two guards

def test_package_table_is_the_b700_tables_plus_the_measured_ssrf_key():
    by_min = {}
    for key, (repl, minb) in _RETIRED_CONFIG_KEYS.items():
        by_min.setdefault(minb, {})[key] = repl
    assert by_min[(2026, 8, 1)] == RETIRED_IN_2026_8_1
    assert by_min[(2026, 9, 3)] == RETIRED_IN_2026_9_3
    assert by_min[(2026, 9, 1)] == {
        "browser.ssrfPolicy.hostnameAllowlist": "browser.ssrfPolicy.allowedHostnames"}
    assert len(_RETIRED_CONFIG_KEYS) == 13
    assert "marketplaces" not in _RETIRED_CONFIG_KEYS


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
