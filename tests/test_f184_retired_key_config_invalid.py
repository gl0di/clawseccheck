"""B382 -- openclaw.json still holds a key the installed OpenClaw build removed.

The claim is deliberately narrow: the strict config schema rejects the file, so
`openclaw config validate` and CLI commands that load it report it invalid until
`openclaw doctor --fix` runs. The verdict and `detail` assert nothing about gateway
behaviour; only the `fix` advice says who repairs the file, and it is version-aware (C-645).
The vendor's boot path changed underneath this claim: through 2026.9.6 the gateway repaired a
legacy file itself in memory and started (the common case; except behind an `$include`), and
from 2026.9.7 startup validates without rewriting and Doctor is the only repair path. The
dist-grounding section of this module pins that premise against the installed build, claim by
claim. 2026.9.7 also retired `tools.toolSearch.codeTimeoutMs`, and 2026.9.8 retired
`silentReply.internal` (agent defaults, and the per-surface block whose surface name is
free-form), which B382 now flags.

Two layers, matching test_b700: always-on behaviour tests, and a LOCAL-ONLY oracle that
EXECUTES the installed root schema over every key in the shipped table. A key the vendor
still accepts must not be in the table.
"""
from __future__ import annotations

import functools
import json
import os
import re
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
    _has_key_path,
    _present_key_paths,
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


# ------------------- 2026.9.8: silentReply.internal (agent defaults + the per-surface block)
#
# 2026.9.8 removed `internal` from the silent-reply policy block in two places: the agent
# defaults (`agents.defaults.silentReply`) and every surface's own block
# (`surfaces.<surface>.silentReply`, where the surface name is free-form). The second row of
# the table therefore carries a `*` segment, and the finding must name the CONCRETE surface
# keys the file holds, never the pattern. Measured by executing the root schema: see the
# local-only oracle at the end of this module.

SILENT_BUILD = "2026.9.8"
SILENT_PRE_BUILD = "2026.9.7"
_AGENT_SILENT_KEY = "agents.defaults.silentReply.internal"
_AGENT_SILENT = {"agents": {"defaults": {"silentReply": {"internal": "allow"}}}}


def _surface_silent(*names, **blocks):
    """``surfaces`` holding ``silentReply.internal`` for each name (blocks override a name)."""
    surfaces = {n: {"silentReply": {"internal": "allow"}} for n in names}
    surfaces.update(blocks)
    return {"surfaces": surfaces}


def test_agent_defaults_silent_reply_internal_warns_on_2026_9_8_and_later():
    for build in (SILENT_BUILD, "2026.9.9"):
        f = _run(_AGENT_SILENT, build)
        assert f.status == WARN, build
        assert f.evidence == [_AGENT_SILENT_KEY], build
        assert f"{_AGENT_SILENT_KEY} (removed)" in f.detail, build


def test_surface_silent_reply_internal_names_each_concrete_surface():
    f = _run(_surface_silent("webchat", "telegram"), SILENT_BUILD)
    assert f.status == WARN
    assert f.evidence == ["surfaces.telegram.silentReply.internal",
                          "surfaces.webchat.silentReply.internal"]
    assert "2 key(s)" in f.detail
    for path in f.evidence:
        assert f"{path} (removed)" in f.detail
    # the pattern itself is table-internal and must never reach the reader
    assert "surfaces.*" not in f.detail + " ".join(f.evidence)


def test_both_silent_reply_rows_in_one_file_are_all_named_in_table_order():
    cfg = {**_AGENT_SILENT, **_surface_silent("telegram")}
    f = _run(cfg, SILENT_BUILD)
    assert f.status == WARN
    assert f.evidence == [_AGENT_SILENT_KEY, "surfaces.telegram.silentReply.internal"]
    assert "2 key(s)" in f.detail


def test_silent_reply_internal_is_quiet_on_builds_that_still_accept_it():
    # EXECUTED against the extracted 2026.9.7 package's root zod schema: both accepted.
    for cfg in (_AGENT_SILENT, _surface_silent("telegram", "webchat")):
        for build in (SILENT_PRE_BUILD, MODERN, LEGACY):
            f = _run(cfg, build)
            assert f.status == PASS, build
            assert "silentReply" not in f.detail, build


def test_silent_reply_internal_unknown_build_is_not_adverse():
    for cfg in (_AGENT_SILENT, _surface_silent("telegram")):
        f = _run(cfg, None)
        assert f.status == PASS
        assert f.pass_confidence == "no_signal"
        assert "silentReply" not in f.detail


def test_live_silent_reply_siblings_are_not_flagged_on_2026_9_8():
    # `group` is accepted by both 2026.9.7 and 2026.9.8 (control for the measured reject).
    cfg = {"agents": {"defaults": {"silentReply": {"group": "allow"}}},
           "surfaces": {"webchat": {"silentReply": {"group": "allow"}}}}
    f = _run(cfg, SILENT_BUILD)
    assert f.status == PASS
    assert f.pass_confidence != "no_signal"


def test_only_the_internal_key_is_named_when_a_live_sibling_sits_beside_it():
    cfg = {"surfaces": {"webchat": {"silentReply": {"group": "allow", "internal": "allow"}}}}
    assert _run(cfg, SILENT_BUILD).evidence == ["surfaces.webchat.silentReply.internal"]


def test_silent_reply_internal_is_flagged_on_presence_not_truthiness_and_value_never_shown():
    for v in (False, None, 0, "", [], {}):
        assert _run({"surfaces": {"a": {"silentReply": {"internal": v}}}},
                    SILENT_BUILD).status == WARN, v
    marker = "value-marker-" + "k4m2p9"
    f = _run(_surface_silent("a", a={"silentReply": {"internal": marker}}), SILENT_BUILD)
    assert f.status == WARN
    assert marker not in (f.detail + " " + f.fix + " " + " ".join(f.evidence))


def test_malformed_silent_reply_shapes_are_neither_a_crash_nor_a_finding():
    for cfg in (
        {"surfaces": []}, {"surfaces": "x"}, {"surfaces": None}, {"surfaces": 3},
        {"surfaces": {}},
        {"surfaces": {"telegram": "x"}},
        {"surfaces": {"telegram": None, "webchat": [1], "slack": 5}},
        {"surfaces": {"telegram": {}}},
        {"surfaces": {"telegram": {"silentReply": "allow"}}},
        {"surfaces": {"telegram": {"silentReply": ["internal"]}}},
        {"surfaces": {"telegram": {"silentReply": None}}},
        {"agents": {"defaults": {"silentReply": "allow"}}},
        {"agents": {"defaults": None}},
        {"agents": []},
    ):
        f = _run(cfg, SILENT_BUILD)
        assert f.status == PASS, cfg


def test_a_malformed_surface_does_not_hide_a_well_formed_one():
    cfg = {"surfaces": {"bad": "x", "worse": None, "telegram": {"silentReply": {"internal": 1}}}}
    assert _run(cfg, SILENT_BUILD).evidence == ["surfaces.telegram.silentReply.internal"]


def test_a_literal_star_surface_is_an_ordinary_surface_name():
    f = _run(_surface_silent("*"), SILENT_BUILD)
    assert f.status == WARN
    assert f.evidence == ["surfaces.*.silentReply.internal"]
    # ... and beside a real surface both are named, each exactly once
    f = _run(_surface_silent("*", "webchat"), SILENT_BUILD)
    assert f.evidence == ["surfaces.*.silentReply.internal",
                          "surfaces.webchat.silentReply.internal"]
    # a star key does not act as a wildcard over its siblings: only a surface that really
    # holds the key is named
    cfg = {"surfaces": {"*": {"silentReply": {"group": "allow"}},
                        "webchat": {"silentReply": {"internal": "allow"}}}}
    assert _run(cfg, SILENT_BUILD).evidence == ["surfaces.webchat.silentReply.internal"]


def test_silent_reply_internal_behind_include_warns_the_same(tmp_path):
    _write(tmp_path / "fragment.json5",
           '{"surfaces": {"telegram": {"silentReply": {"internal": "allow"}}}}')
    _write(tmp_path / "openclaw.json", '{"$include": "./fragment.json5"}')
    cfg = load_openclaw_config(tmp_path / "openclaw.json", root_byte_limit=5_000_000)
    assert _run(cfg, SILENT_BUILD).evidence == ["surfaces.telegram.silentReply.internal"]


def test_a_surface_name_with_a_dot_or_an_empty_name_is_named_as_written():
    # A surface name is free-form, so it may hold a dot or be empty. The path is then joined
    # as written: it reads as one more level than the file has. Pinned, not prettified - the
    # entry is still unique per surface and still names the key that has to go.
    cfg = {"surfaces": {"a.b": {"silentReply": {"internal": "allow"}},
                        "": {"silentReply": {"internal": "allow"}}}}
    f = _run(cfg, SILENT_BUILD)
    assert f.status == WARN
    assert f.evidence == ["surfaces..silentReply.internal",
                          "surfaces.a.b.silentReply.internal"]


def test_threat_coverage_states_the_real_size_of_the_table():
    # The B382 row of the shipped coverage document gives the number of measured keys. Tie it
    # to the table, so a row added later cannot leave the document behind.
    row = next(line for line in (Path(__file__).resolve().parents[1] / "docs"
                                 / "THREAT_COVERAGE.md").read_text(encoding="utf-8").splitlines()
               if "| B382 |" in line)
    stated = re.search(r"\((\d+) measured keys", row)
    assert stated, "the B382 row no longer states how many keys the table holds"
    assert int(stated.group(1)) == len(_RETIRED_CONFIG_KEYS)


def test_wildcard_rows_have_exactly_one_whole_segment_star():
    """Tripwire for the table's own shape: the expander is only ever validated against a
    single whole-segment ``*``, so a row with a partial or a second star is a question."""
    starred = [k for k in _RETIRED_CONFIG_KEYS if "*" in k]
    assert starred == ["surfaces.*.silentReply.internal", "surfaces.*.silentReply.direct",
                       "surfaces.*.silentReplyRewrite"]
    for key in starred:
        parts = key.split(".")
        assert parts.count("*") == 1
        assert all(p == "*" or "*" not in p for p in parts)


# ------------------------------------------------ _present_key_paths (the wildcard expander)

def test_present_key_paths_without_a_star_agrees_with_has_key_path():
    cfg = {"a": {"b": {"c": None}, "d": False}, "e": 0, "f": [1], "g": {}}
    for dotted in ("a", "a.b", "a.b.c", "a.d", "e", "f", "g", "a.x", "a.b.c.d", "e.x", "f.0",
                   "g.x", "zz", "a.b.x.c"):
        assert _present_key_paths(cfg, dotted) == ([dotted] if _has_key_path(cfg, dotted) else []), dotted


def test_present_key_paths_expands_a_star_over_dict_keys_sorted():
    cfg = {"s": {"zeta": {"k": 1}, "alpha": {"k": 2}, "mid": {"other": 3}, "odd": "x", "nul": None}}
    assert _present_key_paths(cfg, "s.*.k") == ["s.alpha.k", "s.zeta.k"]
    assert _present_key_paths(cfg, "s.*") == ["s.alpha", "s.mid", "s.nul", "s.odd", "s.zeta"]
    assert _present_key_paths(cfg, "s.*.k.deeper") == []


def test_present_key_paths_star_over_a_non_dict_or_an_empty_dict_finds_nothing():
    for node in ([], "x", None, 5, True, {}, [{"k": 1}]):
        assert _present_key_paths({"s": node}, "s.*.k") == [], node
    assert _present_key_paths({}, "s.*.k") == []
    assert _present_key_paths([], "s.*.k") == []
    assert _present_key_paths(None, "s.*.k") == []


def test_present_key_paths_star_matches_a_whole_segment_only():
    cfg = {"s": {"a*": {"k": 1}, "b": {"k": 2}}}
    assert _present_key_paths(cfg, "s.a*.k") == ["s.a*.k"]       # literal, not a pattern
    assert _present_key_paths(cfg, "s.*.k") == ["s.a*.k", "s.b.k"]


def test_present_key_paths_does_not_mutate_or_alias_the_config():
    cfg = {"s": {"x": {"k": 1}}}
    before = json.dumps(cfg)
    out = _present_key_paths(cfg, "s.*.k")
    out.append("junk")
    assert json.dumps(cfg) == before
    assert _present_key_paths(cfg, "s.*.k") == ["s.x.k"]


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


# ------------------------- C-577 / C-645 / 2026.9.7: what the installed build does at startup
#
# `check_retired_config_keys_invalid`'s `fix` text hedges: "a config that uses $include may
# be refused automatic repair, so run the command explicitly." C-577 pinned the mechanism
# behind that hedge on the build then current: the vendor's AUTOMATIC config repair refuses to
# run whenever an `$include` is present, and that repair ran at every gateway start.
#
# 2026.9.7 changed the premise, not just the filename. The module was renamed
# (`automatic-startup-config-repair-*` -> `automatic-config-repair-*`) and, more to the
# point, the startup consumer is gone: `resolveStartupConfigSnapshot` and
# `isStartupConfigRepairResult` are declared nowhere in the package, gateway and CLI startup
# validate without rewriting, and the only remaining callers of the repair module are Doctor
# and the two backup modules. Re-globbing the old test would have kept it green while it
# stopped grounding its own sentence ("startup ... refuses to repair"), so the tests below
# pin each half of the new premise separately, each with the control that lets it fail:
#
#   * startup no longer repairs   -> the two startup-repair symbols are absent from the
#                                    whole dist, sealed bundle included, while a symbol that
#                                    exists is found by the very same scan;
#   * an invalid snapshot is left -> the gateway-run bootstrap records it and returns; the
#     for Doctor                     startup preflight returns it as read; neither imports
#                                    the repair module (grounded 2026.9.7:
#                                    pre-bootstrap-BOq1a3gm.mjs:220-224,
#                                    startup-config-preflight-gKbH1nbB.mjs:57,96);
#   * Doctor is the repair path   -> `doctor-config-flow` imports it and plans, then commits,
#                                    the repair (doctor-config-flow-DJTyZM_K.mjs:73,834);
#   * the $include gate survives  -> the gate (`admitAutomaticConfigRepairSnapshot` through
#                                    2026.9.9, automatic-config-repair-BKjdV4pT.mjs:22-24;
#                                    renamed `canPlanAutomaticConfigRepair` in 2026.10.1,
#                                    automatic-config-repair-mpgxrwwh.mjs:18-20) still
#                                    declines on an include, and `planConfigRepair` (:32 as
#                                    of 2026.10.1) still asks it. That is now Doctor's
#                                    automatic-repair leg only, which is what the fix text's
#                                    hedge can still mean;
#   * the constant tracks the     -> `_STARTUP_REPAIR_REMOVED_MIN` is what makes B382's `fix`
#     vendor                         build-aware, so `test_startup_wiring_matches_the_removal_
#                                    constant` asks the installed dist in BOTH directions
#                                    (resolver wired exactly when the build is older than it).
#
# Vendor docs shipped in the same build say the same thing in prose
# (docs/gateway/doctor/config-migrations.md:296: "Gateway and local CLI startup validate
# current config without rewriting legacy keys. Invalid legacy config remains unchanged and
# startup prints the `openclaw doctor --fix` hint"); the code below is the evidence, the
# prose is only a cross-check.

_REPAIR_MODULE = "automatic-config-repair-*.mjs"
_STARTUP_REPAIR_SYMBOLS = ("resolveStartupConfigSnapshot", "isStartupConfigRepairResult")
#: Not a startup-repair symbol: one the repair module still declares, used as the scan's
#: positive control -- a scan that finds nothing for ANY name proves nothing about these two.
#: It was `admitAutomaticConfigRepairSnapshot` through 2026.9.9 and is
#: `canPlanAutomaticConfigRepair` from 2026.10.1 (renamed; the include clauses are unchanged).
_CONTROL_SYMBOL = "canPlanAutomaticConfigRepair"
_REPAIR_CONSUMER_RE = re.compile(rb'from "\./(automatic-config-repair-[A-Za-z0-9_-]+)\.mjs"')


def _bundle_family(path: Path) -> str:
    """``doctor-config-flow-DJTyZM_K.mjs`` -> ``doctor-config-flow`` (the hash rotates)."""
    return re.sub(r"-[A-Za-z0-9_]{8}\.m?js$", "", path.name)


@functools.lru_cache(maxsize=None)
def _dist_scan(dist: Path) -> "tuple[dict, frozenset]":
    """One pass over every top-level bundle (the ~66 MB sealed updater helper included, since
    it is a closure of the whole codebase and so the strictest place to look for an absence):
    ``({symbol: (bundle names mentioning it)}, families importing the repair module)``."""
    mentions = {sym: [] for sym in _STARTUP_REPAIR_SYMBOLS + (_CONTROL_SYMBOL,)}
    consumers = set()
    for path in sorted({p for ext in (".js", ".mjs") for p in dist.glob("*" + ext)}):
        data = path.read_bytes()
        for sym in mentions:
            if sym.encode() in data:
                mentions[sym].append(path.name)
        if b"automatic-config-repair-" in data and _REPAIR_CONSUMER_RE.search(data):
            consumers.add(_bundle_family(path))
    return {k: tuple(v) for k, v in mentions.items()}, frozenset(consumers)


def test_startup_no_longer_carries_the_automatic_config_repair():
    """The removed mechanism: through 2026.9.6 the gateway-run bootstrap imported and called
    these two to repair an invalid snapshot in memory and boot on it. Absent from every
    bundle now. The control is the point: the same scan must still find a startup symbol."""
    mentions, _ = _dist_scan(require_dist())
    assert mentions[_CONTROL_SYMBOL], (
        f"the scan did not find {_CONTROL_SYMBOL}, which the installed build declares -- the "
        "absence below would mean nothing; fix the scan before reading it"
    )
    for symbol in _STARTUP_REPAIR_SYMBOLS:
        assert not mentions[symbol], (
            f"{symbol} is back in {mentions[symbol]}: startup may repair an invalid config "
            "again, so B382's fix text, B38's 'live bypass' wording and the risk chain that "
            "assume startup validates without rewriting need re-grounding"
        )


#: The gateway-run bootstrap branch for an invalid config: recorded, then handed back.
_INVALID_SNAPSHOT_BRANCH_RE = re.compile(
    r"const snapshot = await readGuardedGatewayRunConfig\(params\);\s*"
    r"if \(!snapshot\) return false;\s*"
    r"if \(!snapshot\.valid\) \{\s*"
    r"lastGuardedGatewayRunSnapshot = snapshot;\s*"
    r"return true;\s*\}"
)


def test_the_gateway_run_bootstrap_hands_an_invalid_snapshot_back_unrepaired():
    path = dist_file("pre-bootstrap-*.mjs", symbol="the gateway-run config guard",
                     contains="lastGuardedGatewayRunSnapshot = snapshot;")
    text = path.read_text(encoding="utf-8", errors="replace")
    assert _INVALID_SNAPSHOT_BRANCH_RE.search(text), (
        f"{path.name}: the invalid-snapshot branch no longer reads 'record it and return' "
        "(2026.9.7 pre-bootstrap:220-224) -- re-read what startup now does with an invalid "
        "config before trusting any claim that it is left for Doctor"
    )
    assert "automatic-config-repair" not in text and "RepairResult" not in text


def test_the_invalid_snapshot_branch_shape_bites_on_a_repair_call():
    """Control for the shape above: a branch that repairs before returning must not match."""
    plain = ("const snapshot = await readGuardedGatewayRunConfig(params);\n"
             "if (!snapshot) return false;\n"
             "if (!snapshot.valid) {\n\tlastGuardedGatewayRunSnapshot = snapshot;\n\treturn true;\n}\n")
    repaired = plain.replace("lastGuardedGatewayRunSnapshot = snapshot;",
                             "snapshot = await resolveStartupConfigSnapshot(snapshot);")
    assert _INVALID_SNAPSHOT_BRANCH_RE.search(plain)
    assert not _INVALID_SNAPSHOT_BRANCH_RE.search(repaired)


def test_the_startup_preflight_leaves_an_invalid_snapshot_to_doctor():
    path = dist_file("startup-config-preflight-*.mjs", symbol="runStartupConfigPreflight",
                     contains="function runStartupConfigPreflight")
    text = path.read_text(encoding="utf-8", errors="replace")
    assert "legacy imports and repair receipts belong to Doctor" in text
    # gateway mode: an invalid read is returned as read, before any state preparation
    assert re.search(r"if \(!read\.snapshot\.valid\) return result\(read\);", text)
    for repair in ("automatic-config-repair", "planAutomaticConfigRepair",
                   "commitAutomaticConfigRepair", "planAdmittedConfigRepair"):
        assert repair not in text, f"{path.name} now references {repair}"


def test_only_doctor_and_the_backup_modules_consume_the_automatic_repair_module():
    _, consumers = _dist_scan(require_dist())
    assert "doctor-config-flow" in consumers, (
        f"Doctor no longer imports the repair module (consumers: {sorted(consumers)}) -- "
        "find where legacy keys are repaired now"
    )
    startup = {"pre-bootstrap", "startup-config-preflight", "config-guard"}
    assert not (consumers & startup), (
        f"a startup module imports the repair module again: {sorted(consumers & startup)}"
    )


def test_automatic_repair_gate_still_declines_on_include_present():
    """C-577's original pin, now scoped to the only caller left: Doctor's automatic-repair leg."""
    require_dist()
    path = dist_file(
        _REPAIR_MODULE,
        symbol="canPlanAutomaticConfigRepair",
        contains="function canPlanAutomaticConfigRepair(",
    )
    text = path.read_text(encoding="utf-8", errors="replace")
    gate = re.search(r"function canPlanAutomaticConfigRepair\(snapshot\) \{(.*?)\n\}", text, re.S)
    assert gate, f"{path.name}: the gate's declaration moved"
    body = gate.group(1)
    assert "(snapshot.includedPaths?.length ?? 0) === 0" in body
    assert "!containsConfigIncludeDirective(snapshot.parsed)" in body
    # ...and the planner still asks it before doing anything
    assert re.search(
        r"function planConfigRepair\(.*?\) \{\s*if \(!canPlanAutomaticConfigRepair\(snapshot\)\) return null;",
        text, re.S), f"{path.name}: planConfigRepair no longer gates on the include check"


def test_startup_wiring_matches_the_removal_constant():
    """`_STARTUP_REPAIR_REMOVED_MIN` says startup repair is gone from 2026.9.7. Ask the
    installed dist: the bootstrap references the startup-repair resolver exactly when the
    installed build is OLDER than the constant, and never when it is at or above it. On a
    build at or above it, also read that the repair planner is committed from Doctor's flow
    (the startup preflight's half of the replacement is pinned above, once)."""
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
        doctor = dist_file(
            "doctor-config-flow-*.mjs",
            symbol="commitAutomaticConfigRepair (Doctor's preflight caller)",
            contains="commitAutomaticConfigRepair",
        ).read_text(encoding="utf-8", errors="replace")
        assert "planAutomaticConfigRepair" in doctor


# --------------------------------------------------- single table, two guards

def test_package_table_is_the_b700_tables_plus_the_measured_later_keys():
    by_min = {}
    for key, (repl, minb) in _RETIRED_CONFIG_KEYS.items():
        by_min.setdefault(minb, {})[key] = repl
    assert by_min[(2026, 8, 1)] == RETIRED_IN_2026_8_1
    assert by_min[(2026, 9, 3)] == RETIRED_IN_2026_9_3
    assert by_min[(2026, 9, 1)] == {
        "browser.ssrfPolicy.hostnameAllowlist": "browser.ssrfPolicy.allowedHostnames"}
    # C-645: 2026.9.7 dropped `tools.toolSearch.codeTimeoutMs` ("Tool Search no longer
    # executes code"); removed outright, no replacement key.
    # C-671: plus four silent-reply rows carrying 2026.9.7 as a measured FLOOR (the earliest
    # build executed and found rejecting them; the removal build is unmeasured).
    assert by_min[(2026, 9, 7)] == {"tools.toolSearch.codeTimeoutMs": None,
                                    "agents.defaults.silentReply.direct": None,
                                    "surfaces.*.silentReply.direct": None,
                                    "agents.defaults.silentReplyRewrite": None,
                                    "surfaces.*.silentReplyRewrite": None}
    # 2026.9.8 dropped `silentReply.internal` from the agent defaults and from every surface's
    # block (the surface name is free-form, hence the `*`); removed outright, no replacement.
    assert by_min[(2026, 9, 8)] == {"agents.defaults.silentReply.internal": None,
                                    "surfaces.*.silentReply.internal": None}
    assert len(_RETIRED_CONFIG_KEYS) == 20
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
    # A `*` row is a pattern, not a key: probe it under a concrete surface name. The probe's
    # value is a boolean, which the two `silentReply.internal` rows reject for their TYPE
    # whatever the build, so for those rows this test proves nothing about the key -- the typed
    # test below (`test_silent_reply_internal_rows_match_the_installed_schema`) grounds them.
    probe = {k: ".".join("webchat" if p == "*" else p for p in k.split(".")) for k in keys}
    accepted = _oracle(list(probe.values()))
    assert not [k for k, c in probe.items() if accepted[c]], accepted


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


# `_oracle` builds its config from the dotted key with a boolean (or an empty array), which is
# the wrong TYPE for `silentReply.internal`: the vendor would reject it on 2026.9.7 too, so it
# could not tell "the key was removed" from "the value was malformed". This one takes whole
# config objects, so each case is exactly the config the measurement used.
_CASES_SCRIPT = """
const z = await import(process.env.OC_SCHEMA);
const cases = JSON.parse(process.env.OC_CASES);
const out = {};
for (const [name, cfg] of Object.entries(cases)) out[name] = z.t.safeParse(cfg).success;
console.log(JSON.stringify(out));
"""


def _oracle_configs(cases):
    """``{case name: config object}`` -> ``{case name: accepted by the installed root schema}``."""
    schema = dist_file("zod-schema-*.js", symbol="the root zod schema bundle (export `t`)")
    env = dict(os.environ, OC_SCHEMA=str(schema), OC_CASES=json.dumps(cases))
    proc = subprocess.run(["node", "--input-type=module", "-e", _CASES_SCRIPT],
                          capture_output=True, text=True, timeout=120, env=env)
    if proc.returncode != 0:
        pytest.skip(f"could not execute the dist schema: {proc.stderr.strip()[:200]}")
    return json.loads(proc.stdout)


def test_silent_reply_internal_rows_match_the_installed_schema():
    """2026.9.8 control set for both `silentReply.internal` rows, in ONE oracle call.

    The retired key is rejected exactly when the installed build is at or above the row's min
    build; every control is build-independent: the bare config and the live sibling `group`
    (agent defaults, and under a surface) are accepted, a bogus sibling is rejected (so a
    schema that merely accepted anything under `silentReply` could not pass), and a surface
    name the vendor has never heard of is accepted (so the `*` really is free-form). Then the
    check itself is run on the same configs against the installed build and must flag
    precisely the ones the vendor rejected for a retired key."""
    require_dist()
    installed = _installed_tuple()
    assert installed is not None

    def agents(**block):
        return {"agents": {"entries": {"main": {"default": True}},
                           "defaults": {"silentReply": block}}}

    def surface(name, **block):
        return {"agents": {"entries": {"main": {"default": True}}},
                "surfaces": {name: {"silentReply": block}}}

    configs = {
        "control": {"agents": {"entries": {"main": {"default": True}}}},
        "agent_live_sibling": agents(group="allow"),
        "agent_internal": agents(internal="allow"),
        "agent_bogus_sibling": agents(zzzBogus="allow"),
        "surface_live_sibling": surface("webchat", group="allow"),
        "surface_internal_webchat": surface("webchat", internal="allow"),
        "surface_internal_telegram": surface("telegram", internal="allow"),
        "surface_free_form_name": surface("zzzNoSuchSurface", group="allow"),
        "surface_bogus_sibling": surface("webchat", zzzBogus="allow"),
    }
    got = _oracle_configs(configs)
    assert set(got) == set(configs)
    for name in ("control", "agent_live_sibling", "surface_live_sibling",
                 "surface_free_form_name"):
        assert got[name] is True, name
    for name in ("agent_bogus_sibling", "surface_bogus_sibling"):
        assert got[name] is False, name
    agent_min = _RETIRED_CONFIG_KEYS["agents.defaults.silentReply.internal"][1]
    surface_min = _RETIRED_CONFIG_KEYS["surfaces.*.silentReply.internal"][1]
    assert got["agent_internal"] is (installed < agent_min)
    assert got["surface_internal_webchat"] is (installed < surface_min)
    assert got["surface_internal_telegram"] is (installed < surface_min)

    build = ".".join(str(n) for n in installed)
    for name in ("control", "agent_live_sibling", "agent_internal", "surface_live_sibling",
                 "surface_internal_webchat", "surface_internal_telegram",
                 "surface_free_form_name"):
        flagged = bool(_retired_keys_present(_ctx(configs[name], build)))
        assert flagged is (not got[name]), (name, build)
