"""C-671 -- B382 and the four silent-reply keys whose removal build is unmeasured.

`agents.defaults.silentReply.direct`, `surfaces.<surface>.silentReply.direct`,
`agents.defaults.silentReplyRewrite` and `surfaces.<surface>.silentReplyRewrite` are rejected
by the strict root schema of every build that was executed (2026.9.7 and 2026.9.9), but they
sit in no saved generated-schema path list back to 2026.7.1-2, so the build that removed them
is not known. Owner ruling: the table carries the EARLIEST MEASURED rejecting build (2026.9.7)
as a FLOOR, and says so; and the PASS text says what was checked ("none of the N retired keys
this check tracks"), not that the file holds nothing OpenClaw ever removed.

Always-on behaviour tests, plus a LOCAL-ONLY oracle that executes the installed root schema
over a valid config, a live sibling and a bogus sibling for each of the four paths.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from _distgrounding import dist_file, require_dist

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks._config import check_retired_config_keys_invalid
from clawseccheck.checks._shared import _RETIRED_CONFIG_KEYS, _retired_keys_present
from clawseccheck.collector import Context

ROOT = Path(__file__).resolve().parents[1]
FLOOR = (2026, 9, 7)
FLOOR_BUILD = "2026.9.7"
BELOW = ("2026.9.6", "2026.9.4", "2026.8.1")
AT_OR_ABOVE = ("2026.9.7", "2026.9.8", "2026.9.9")

AGENT_DIRECT = "agents.defaults.silentReply.direct"
SURFACE_DIRECT = "surfaces.*.silentReply.direct"
AGENT_REWRITE = "agents.defaults.silentReplyRewrite"
SURFACE_REWRITE = "surfaces.*.silentReplyRewrite"
NEW_ROWS = (AGENT_DIRECT, SURFACE_DIRECT, AGENT_REWRITE, SURFACE_REWRITE)


def _ctx(cfg, installed):
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_found = True
    c.installed_dist_version = installed
    return c


def _run(cfg, installed):
    return check_retired_config_keys_invalid(_ctx(cfg, installed))


def _cfg(row, surface="webchat"):
    """A config holding exactly the retired key of ``row``."""
    parts = [surface if p == "*" else p for p in row.split(".")]
    cfg = {}
    node = cfg
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = {"direct": True} if parts[-1] == "silentReplyRewrite" else "disallow"
    return cfg


# ------------------------------------------------------------------ the table

def test_the_four_rows_carry_the_measured_floor_and_no_replacement():
    for row in NEW_ROWS:
        assert _RETIRED_CONFIG_KEYS[row] == (None, FLOOR), row
    assert len(_RETIRED_CONFIG_KEYS) == 20


def test_the_provenance_comment_says_floor_not_removal_build():
    src = (ROOT / "clawseccheck" / "checks" / "_shared.py").read_text(encoding="utf-8")
    comment = src[:src.index("_RETIRED_CONFIG_KEYS = {")]
    assert "C-671" in comment
    assert "FLOOR" in comment and "not the removal build" in comment


# -------------------------------------------------------------------- verdicts

@pytest.mark.parametrize("row", NEW_ROWS)
@pytest.mark.parametrize("build", AT_OR_ABOVE)
def test_each_row_warns_at_or_above_the_floor_and_names_the_real_path(row, build):
    f = _run(_cfg(row), build)
    assert f.status == WARN
    assert f.evidence == [row.replace("*", "webchat")]
    assert "openclaw doctor --fix" in f.fix


@pytest.mark.parametrize("row", NEW_ROWS)
@pytest.mark.parametrize("build", BELOW)
def test_each_row_is_quiet_below_the_floor(row, build):
    f = _run(_cfg(row), build)
    assert f.status == PASS
    assert _retired_keys_present(_ctx(_cfg(row), build)) == []


def test_surface_rows_name_every_surface_the_file_holds():
    cfg = {"surfaces": {"webchat": {"silentReply": {"direct": "x"}, "silentReplyRewrite": {}},
                        "telegram": {"silentReplyRewrite": True}}}
    f = _run(cfg, "2026.9.9")
    assert f.status == WARN
    assert sorted(f.evidence) == ["surfaces.telegram.silentReplyRewrite",
                                  "surfaces.webchat.silentReply.direct",
                                  "surfaces.webchat.silentReplyRewrite"]


def test_live_siblings_are_never_flagged():
    cfg = {"agents": {"defaults": {"silentReply": {"group": "allow"}}},
           "surfaces": {"webchat": {"silentReply": {"group": "allow"}}}}
    assert _run(cfg, "2026.9.9").status == PASS
    assert _retired_keys_present(_ctx(cfg, "2026.9.9")) == []


def test_b382_stays_advisory_warn_at_most():
    cfg = {}
    for row in NEW_ROWS:
        for k, v in _cfg(row).items():
            cfg.setdefault(k, {})
            for k2, v2 in v.items():
                cfg[k].setdefault(k2, {}).update(v2)
    f = _run(cfg, "2026.9.9")
    assert f.status == WARN
    assert len(f.evidence) == 4


# ------------------------------------------------------------------- PASS text

def test_pass_text_says_what_was_checked_not_that_the_file_is_complete():
    f = _run({"gateway": {"port": 1}}, "2026.9.9")
    assert f.status == PASS
    n = len(_RETIRED_CONFIG_KEYS)
    assert f"none of the {n} retired config keys this check tracks" in f.detail
    assert "holds no key that OpenClaw" not in f.detail
    # the advice must also stop short of "complete": the list is not the vendor's own
    assert "not every key" in f.fix
    assert "openclaw config validate" in f.fix


def test_pass_count_follows_the_table_not_a_literal():
    f = _run({}, "2026.9.9")
    assert f.status == PASS
    assert re.search(rf"none of the {len(_RETIRED_CONFIG_KEYS)} ", f.detail)


def test_threat_coverage_row_states_the_new_size_and_the_floor():
    row = next(line for line in (ROOT / "docs" / "THREAT_COVERAGE.md")
               .read_text(encoding="utf-8").splitlines() if "| B382 |" in line)
    stated = re.search(r"\((\d+) measured keys", row)
    assert stated and int(stated.group(1)) == len(_RETIRED_CONFIG_KEYS) == 20
    assert "silentReplyRewrite" in row and "silentReply.direct" in row
    assert "floor" in row


# ----------------------------------------------------------- local-only oracle

_CASES_SCRIPT = """
const z = await import(process.env.OC_SCHEMA);
const cases = JSON.parse(process.env.OC_CASES);
const out = {};
for (const [name, cfg] of Object.entries(cases)) out[name] = z.t.safeParse(cfg).success;
console.log(JSON.stringify(out));
"""


def _oracle_configs(cases):
    schema = dist_file("zod-schema-*.js", symbol="the root zod schema bundle (export `t`)")
    env = dict(os.environ, OC_SCHEMA=str(schema), OC_CASES=json.dumps(cases))
    proc = subprocess.run(["node", "--input-type=module", "-e", _CASES_SCRIPT],
                          capture_output=True, text=True, timeout=120, env=env)
    if proc.returncode != 0:
        pytest.skip(f"could not execute the dist schema: {proc.stderr.strip()[:200]}")
    return json.loads(proc.stdout)


def _installed_tuple():
    from clawseccheck.openclawdist import _numeric_parts, _read_version
    v = _read_version(require_dist().parent)
    return _numeric_parts(v) if v else None


def test_direct_and_rewrite_rows_match_the_installed_schema():
    """Valid config, live sibling and bogus sibling per path, in ONE oracle call. The retired
    key must be rejected exactly when the installed build is at or above the row's floor; the
    bare config, the live siblings and a free-form surface name are accepted (so a schema that
    rejected everything under the parent could not pass) and the bogus siblings are rejected
    (so one that accepted anything could not pass). Values are the right TYPE for the live
    sibling, and the retired keys are probed with both a string and an object so the verdict
    is the key, not the value type. Then the check runs on the same configs."""
    require_dist()
    installed = _installed_tuple()
    assert installed is not None
    roster = {"entries": {"main": {"default": True}}}

    def agents(**block):
        return {"agents": {**roster, "defaults": block}}

    def surface(name, **block):
        return {"agents": roster, "surfaces": {name: block}}

    configs = {
        "control": {"agents": roster},
        "agent_live_group": agents(silentReply={"group": "allow"}),
        "agent_direct": agents(silentReply={"direct": "disallow"}),
        "agent_silent_bogus": agents(silentReply={"zzzBogus": "allow"}),
        "agent_rewrite_obj": agents(silentReplyRewrite={"direct": True}),
        "agent_rewrite_empty": agents(silentReplyRewrite={}),
        "agent_defaults_bogus": agents(zzzBogus=True),
        "surface_live_group": surface("webchat", silentReply={"group": "allow"}),
        "surface_direct_webchat": surface("webchat", silentReply={"direct": "disallow"}),
        "surface_direct_telegram": surface("telegram", silentReply={"direct": "disallow"}),
        "surface_silent_bogus": surface("webchat", silentReply={"zzzBogus": "allow"}),
        "surface_rewrite_webchat": surface("webchat", silentReplyRewrite={"direct": True}),
        "surface_rewrite_telegram": surface("telegram", silentReplyRewrite={"direct": True}),
        "surface_rewrite_empty": surface("webchat", silentReplyRewrite={}),
        "surface_bogus": surface("webchat", zzzBogus=True),
        "surface_free_form": surface("zzzNoSuchSurface", silentReply={"group": "allow"}),
    }
    got = _oracle_configs(configs)
    assert set(got) == set(configs)
    for name in ("control", "agent_live_group", "surface_live_group", "surface_free_form"):
        assert got[name] is True, name
    for name in ("agent_silent_bogus", "agent_defaults_bogus", "surface_silent_bogus",
                 "surface_bogus"):
        assert got[name] is False, name
    retired = ("agent_direct", "agent_rewrite_obj", "agent_rewrite_empty",
               "surface_direct_webchat", "surface_direct_telegram", "surface_rewrite_webchat",
               "surface_rewrite_telegram", "surface_rewrite_empty")
    for name in retired:
        assert got[name] is (installed < FLOOR), name

    build = ".".join(str(n) for n in installed)
    for name in ("control", "agent_live_group", "surface_live_group", "surface_free_form",
                 *retired):
        flagged = bool(_retired_keys_present(_ctx(configs[name], build)))
        assert flagged is (not got[name]), (name, build)
