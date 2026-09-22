"""``clawseccheck/toolgrant.py`` grounded against the installed OpenClaw dist directly —
never against a sibling copy in this repo, and never against a literal of our own.

The brief this module answers named the exact failure mode to avoid: a guard that
compares ``toolpolicy.py``'s alias table against ``checks/_shared.py``'s alias table (or
vice versa) stays green when BOTH copies are equally wrong, because a peer is not a
producer. ``checks/_shared.py::_TOOL_NAME_ALIASES`` and ``toolpolicy.py``'s own copy both
carry only ``{"bash": "exec", "apply-patch": "apply_patch"}`` — missing the real dist's
third entry, ``"cron": "automations"``. Every test below reads the INSTALLED DIST, not
either of those files.

THE PROFILE/GROUP GUARD USED TO BE VACUOUS. It asserted five tool ids and ``group:fs``
against a literal in this same file, and went green on 2026.9.5 while ``toolgrant.py`` was
wrong about ``gateway`` (now in the minimal, coding AND messaging profiles), ``plugins``
(coding, ``group:automation``, ``group:openclaw``), ``ls`` (coding, ``group:fs``) and two
tool ids it had never seen, ``openclaw`` and ``pdf`` — 522 of 6,688 corpus cells. Five ids
out of ~55 cannot notice a sixth. It is replaced by WHOLE-table equality against a fresh
execution of the vendor (``tests/_toolgrantoracle.py``): every profile, every group, the
alias map, and the exact-key lookup semantics of ``resolveCoreToolProfilePolicy``. A table
entry on either side only, a member on either side only, and an order-only difference are
each a failure with the entry named; ``test_diff_tables_*`` prove the comparison itself
fails when one entry differs (a control that cannot fail controls nothing).

Local-only: skipped wherever the installed OpenClaw dist (or node) is absent (CI, a machine
without it) — never silently weakened into a false pass. The always-on tests at the bottom
need neither and pin the machinery. Ground truth is **openclaw@2026.9.5** (re-grounded
2026-09-19); a filename cited here rotates on upgrade (content-hashed bundles), and so, as
2026.9.2 showed, can the SHAPE of a literal — so re-locate a moved symbol with
``grep -rl '<symbolName>' dist/*.mjs``, not by trusting the literal glob below to still
resolve. **On an OpenClaw upgrade:** ``python3.12 tests/_toolgrantoracle.py --check`` says
whether the pinned battery still matches; ``--tables`` dumps the tables to re-transcribe;
``--write`` regenerates the battery.

B-728: the locator is ``tests/_distgrounding.py``, shared, and it distinguishes "OpenClaw
is not installed" (skip) from "installed, and this anchor no longer matches" (fail, naming
the symbol). Each citation below therefore passes ``contains=`` — a constant the right
bundle DECLARES — so the anchor is the symbol and the filename is only a prefilter. That
is not cosmetic: ``tool-policy-match-*.js`` matches two bundles on 2026.9.1 and
``agent-id-*.js`` four, exactly one of each declaring the symbol asserted here.
"""
from __future__ import annotations

import json
import re
import shutil

import pytest
from _distgrounding import dist_text, require_dist

import _toolgrantoracle as oracle
from clawseccheck import toolgrant


@pytest.fixture(autouse=True, scope="module")
def _oracle_scratch(tmp_path_factory):
    """Keep the oracle's throwaway directory inside pytest's own tmp tree."""
    previous = oracle.SCRATCH_ROOT
    oracle.SCRATCH_ROOT = tmp_path_factory.mktemp("toolgrant-oracle")
    yield
    oracle.SCRATCH_ROOT = previous


@pytest.fixture(scope="module")
def vendor() -> dict:
    """The vendor's tables, from ONE node execution shared by this module's live tests."""
    require_dist()
    if not shutil.which("node"):
        pytest.skip("node is not installed — the whole-table guards execute the vendor")
    return oracle.vendor_tables()


# --------------------------------------------------------------------- alias table (3, not 2)

def test_dist_tool_name_aliases_has_three_entries_including_cron():
    text = dist_text("tool-policy-shared-*.js", symbol="TOOL_NAME_ALIASES",
                     contains="TOOL_NAME_ALIASES")
    # BOTH declaration shapes, because the vendor changed the container without changing
    # the contract: 2026.9.1 declared an object literal, 2026.9.2 declares
    # `/* @__PURE__ */ new Map([["bash", "exec"], ...])`. The three pairs are byte-identical
    # across that move — verified 2026-09-06 — so a shape-only assertion would have reported
    # a drift that did not happen. The symbol is the anchor (B-728); its container is not.
    match = re.search(
        r"const TOOL_NAME_ALIASES = (?:/\*[^*]*\*/\s*)?(?:new Map\(\[(.*?)\]\)|\{(.*?)\})",
        text, re.S)
    assert match, "TOOL_NAME_ALIASES literal not found — re-ground toolgrant._TOOL_NAME_ALIASES"
    body = match.group(1) if match.group(1) is not None else match.group(2)
    # `"k": "v"` (object) and `["k", "v"]` (Map) both reduce to a quoted pair.
    entries = dict(re.findall(r'"([^"]+)"\s*[:,]\s*"([^"]+)"', body))
    assert entries == {"bash": "exec", "apply-patch": "apply_patch", "cron": "automations"}, entries
    assert toolgrant._TOOL_NAME_ALIASES == entries


def test_our_alias_table_disagrees_with_the_two_narrower_sibling_copies():
    """Not a bug in the siblings (each is scoped to what its own predicate needs) — pinned
    so nobody "fixes" this module by copying either narrower table back in."""
    from clawseccheck import toolpolicy
    from clawseccheck.checks import _shared

    assert toolpolicy._TOOL_NAME_ALIASES == {"bash": "exec", "apply-patch": "apply_patch"}
    assert _shared._TOOL_NAME_ALIASES == {"bash": "exec", "apply-patch": "apply_patch"}
    assert toolgrant._TOOL_NAME_ALIASES == {
        "bash": "exec", "apply-patch": "apply_patch", "cron": "automations",
    }


def test_cron_alias_resolves_the_same_as_automations():
    cfg = {"tools": {"allow": ["cron"]}}
    assert toolgrant.granted(cfg, "automations") is True
    assert toolgrant.granted(cfg, "cron") is True
    assert toolgrant.granted(cfg, "exec") is False


# --------------------------------------------------------------------- profile / group tables

def test_dist_profile_enum_matches_the_known_set():
    text = dist_text("zod-schema.agent-runtime-*.js", symbol="ToolProfileSchema",
                     contains="ToolProfileSchema")
    block = re.search(r"ToolProfileSchema = union\(\[(.*?)\]\)", text, re.S)
    assert block, "ToolProfileSchema not found — re-ground _CORE_TOOL_PROFILES's key set"
    found = set(re.findall(r'literal\("([a-z]+)"\)', block.group(1)))
    assert found == set(toolgrant._CORE_TOOL_PROFILES)


def _ours_profiles() -> dict:
    return {key: list(members) for key, members in toolgrant._CORE_TOOL_PROFILES.items()}


def test_profile_table_equals_the_vendors_whole(vendor):
    """Every profile, every member, in order — read through resolveCoreToolProfilePolicy,
    the function the resolver itself calls, not through a regex over the catalog source."""
    theirs = {key: policy["allow"] for key, policy in vendor["profiles"].items()}
    assert not oracle.diff_tables(_ours_profiles(), theirs, "profiles")
    for key, policy in vendor["profiles"].items():
        # toolgrant._profile_policy builds {"allow": [...], "deny": None}; a vendor profile
        # that ever carried a deny list would be invisible to it, so it must be absent.
        assert set(policy) == {"allow"}, (key, policy)
        assert isinstance(policy["allow"], list) and policy["allow"], key


def test_profile_keys_are_the_vendors_own_profile_options(vendor):
    """Three views of "which profiles exist" must agree: the object the runtime indexes,
    the options list the UI offers, and ours."""
    assert set(vendor["profile_options"]) == set(vendor["profiles"]) == set(toolgrant._CORE_TOOL_PROFILES)


@pytest.mark.parametrize("probe", ["", "MINIMAL", " coding ", "readonly", "constructor", "__proto__", "toString"])
def test_profile_lookup_is_an_exact_key_match_for_every_probe(vendor, probe):
    """resolveCoreToolProfilePolicy indexes an object: a near-miss, an empty string and the
    names on Object.prototype all resolve to nothing, and so do they here. An unrecognized
    profile restricts NOTHING (the permissive end), so getting this backwards inverts a verdict."""
    assert vendor["profile_probes"][probe] is None
    assert toolgrant._profile_policy(probe) is None


def test_group_table_equals_the_vendors_whole(vendor):
    """Every group and every member, in order, from the TOOL_GROUPS object expandToolGroups
    actually reads — and that object must still be a plain copy of CORE_TOOL_GROUPS."""
    assert vendor["groups"] == vendor["core_groups"]
    assert not oracle.diff_tables(toolgrant._CORE_TOOL_GROUPS, vendor["groups"], "groups")


def test_alias_table_equals_the_vendors_whole(vendor):
    """The executed Map, not a regex over its declaration (test_dist_tool_name_aliases_...
    above reads the text; this reads the object the predicate consults)."""
    assert not oracle.diff_tables(toolgrant._TOOL_NAME_ALIASES, vendor["aliases"], "aliases")


def test_no_alias_key_shadows_a_catalog_tool(vendor):
    """An alias whose key is also a catalog tool would silently redirect that tool; the
    table equality above cannot see that (it only says both sides agree), this can."""
    catalog = {t for members in vendor["groups"].values() for t in members}
    assert not (set(vendor["aliases"]) & catalog), set(vendor["aliases"]) & catalog


def test_the_canvas_and_update_plan_expansions_are_outside_the_grant_predicate(vendor):
    """NOT MODELLED, and pinned so that stays a decision rather than an accident.

    2026.9.5 promotes ``canvas`` -> [canvas, show_widget] and renames ``update_plan`` ->
    ``progress_card`` in ``expandShippedCoreToolPolicyNames`` (tool-policy bundle). That runs
    in the tool-CONSTRUCTION pipeline, after ``resolveConfiguredToolPolicies``; the predicate
    ``granted()`` ports (``isToolAllowedByPolicies`` over that resolver's output) never applies
    it, and ``TOOL_NAME_ALIASES`` is still the three-entry map. So an ``allow: ["canvas"]``
    config does NOT grant ``show_widget`` at the layer toolgrant.py answers for — measured
    below by execution — while the pipeline that builds the tool list would. If a check ever
    asks ``granted(cfg, "show_widget")`` this is the gap to close, with its own differential."""
    assert vendor["shipped_family"] == {"canvas": ["show_widget"]}
    assert vendor["shipped_renames"] == {"update_plan": "progress_card"}
    cfgs = [
        ("canvas", {"tools": {"allow": ["canvas"]}}, "show_widget"),
        ("update_plan", {"tools": {"allow": ["update_plan"]}}, "progress_card"),
    ]
    grants = oracle.vendor_grants([(f"probe/{name}", cfg) for name, cfg, _ in cfgs],
                                  tools=[tool for _, _, tool in cfgs])
    for (name, cfg, tool), row in zip(cfgs, grants):
        assert row["results"][tool]["global"] is False, (name, tool)
        assert toolgrant.granted(cfg, tool) is False, (name, tool)


def test_the_oracle_queries_a_roster_agent_literally_named_global_by_its_own_id():
    """CLAWSECCHECK-C-561 fixed ``GLOBAL_SCOPE`` in ``toolgrant.py`` itself; this module's own
    harness (``tests/_toolgrantoracle.py``) had the identical bug in its per-scope loop --
    ``const agentId = scope === "global" ? undefined : scope`` -- so a roster agent spelled
    ``global`` was never actually queried: the loop visits the string ``"global"`` twice (the
    true global scope, then that agent's own id), both compare equal to the literal, and both
    resolve as the global scope.

    Reproduced here exactly as found: a global ``tools.allow: [write]`` plus two roster agents,
    ``global`` and ``w``, both carrying the identical restrictive ``allow: [read]``. Before this
    fix, that config answered ``write=True`` for ``global`` (the global scope's own answer,
    leaking through) and ``write=False`` for ``w`` (correctly, its own) -- a mismatch between
    two agents with identical config. Confirmed by temporarily reverting the harness fix and
    re-running this exact probe: it printed ``{"global": True, "w": False}``. With the fix, the
    roster id ``"global"`` is looked up by ``resolveAgentConfig`` like any other id (a Symbol
    can never ``===`` a string), so the two agents now agree."""
    cfg = {
        "tools": {"allow": ["write"]},
        "agents": {"list": [
            {"id": "global", "tools": {"allow": ["read"]}},
            {"id": "w", "tools": {"allow": ["read"]}},
        ]},
    }
    rows = oracle.vendor_grants([("probe/global-collision", cfg)], tools=["write"])
    results = rows[0]["results"]["write"]
    assert results == {"global": False, "w": False}, results


# --------------------------------------------------------------------- the whole-catalog sweep

@pytest.fixture(scope="module")
def sweep(vendor):
    """(configs, tools, vendor answers) for every synthetic config x every catalog tool name."""
    rows = oracle.synthetic_configs(vendor)
    tools = oracle.all_tool_ids(vendor)
    return dict(rows), tools, oracle.vendor_grants(rows, tools)


def _scope_key(scope: str):
    """The vendor grants JSON spells the global scope as the plain string ``"global"`` -- a
    label, not a value ``toolgrant.granted`` accepts post-CLAWSECCHECK-C-561 (``GLOBAL_SCOPE``
    is a private sentinel type now, never that string). None of ``synthetic_configs``'s
    rosters names an agent literally "global" (checked: ids are "a"/"b"/"c" and similar), so
    this mapping is lossless for this sweep, same as tests/test_toolgrant_battery.py's copy."""
    return toolgrant.GLOBAL_SCOPE if scope == "global" else scope


def _sweep_mismatches(sweep) -> list:
    configs, _, grants = sweep
    wrong = []
    for row in grants:
        cfg = configs[row["label"]]
        for tool, per_scope in row["results"].items():
            for scope, expected in per_scope.items():
                if toolgrant.granted(cfg, tool, _scope_key(scope)) is not expected:
                    wrong.append((row["label"], scope, tool, expected))
    return wrong


def test_granted_matches_the_vendor_for_every_catalog_tool_on_synthetic_configs(sweep):
    """The pinned battery grades eleven tools; this grades ALL of them (every name any group,
    profile or alias mentions), live, over the configs built to reach every table entry."""
    _, tools, grants = sweep
    wrong = _sweep_mismatches(sweep)
    assert not wrong, f"{len(wrong)} cell(s) disagree with the installed vendor, first: {wrong[:8]}"
    # non-vacuity: a sweep over a handful of cells, or one that only ever saw one answer,
    # would pass a port that is wrong everywhere it did not look.
    cells = sum(len(per) for row in grants for per in row["results"].values())
    assert len(tools) >= 50 and cells >= 5000, (len(tools), cells)
    for tool in oracle.BATTERY_TOOLS:
        seen = {v for row in grants for v in row["results"][tool].values()}
        assert seen == {True, False}, (tool, seen)


def test_the_sweep_fails_when_a_table_entry_is_wrong(sweep, monkeypatch):
    """Positive control on the sweep itself: dropping ``pdf`` from group:media, or
    ``gateway`` from the minimal profile, must be seen — and named."""
    groups = dict(toolgrant._CORE_TOOL_GROUPS)
    groups["group:media"] = [t for t in groups["group:media"] if t != "pdf"]
    monkeypatch.setattr(toolgrant, "_CORE_TOOL_GROUPS", groups)
    assert {tool for *_, tool, _ in _sweep_mismatches(sweep)} == {"pdf"}
    monkeypatch.undo()

    profiles = dict(toolgrant._CORE_TOOL_PROFILES)
    profiles["minimal"] = [t for t in profiles["minimal"] if t != "gateway"]
    monkeypatch.setattr(toolgrant, "_CORE_TOOL_PROFILES", profiles)
    assert "gateway" in {tool for *_, tool, _ in _sweep_mismatches(sweep)}


def test_the_pinned_battery_is_what_the_installed_vendor_answers(vendor):
    """The upgrade signal. The pinned data was captured on one build; if the INSTALLED vendor
    now answers any pinned cell differently, the file is stale and ``--write`` is owed.
    Fixtures added since capture are not a disagreement (``recheck`` re-runs only pinned rows)."""
    pinned = json.loads(oracle.BATTERY.read_text(encoding="utf-8"))
    problems = oracle.recheck(pinned)
    assert not problems, f"{len(problems)} pinned cell(s) moved, first: {problems[:8]}"


# --------------------------------------------------------------------- write => apply_patch

def test_dist_still_lets_write_allow_apply_patch():
    text = dist_text("tool-policy-match-*.js", symbol="writeAllowsApplyPatch",
                     contains="writeAllowsApplyPatch")
    assert "writeAllowsApplyPatch" in text, "the implication flag moved — re-ground granted()"
    assert 'normalized === "apply_patch"' in text and 'matchesAnyGlobPattern("write", allow)' in text


def test_write_only_allowlist_grants_apply_patch_but_not_edit():
    cfg = {"tools": {"allow": ["write"]}}
    assert toolgrant.granted(cfg, "apply_patch") is True
    assert toolgrant.granted(cfg, "edit") is False
    assert toolgrant.granted(cfg, "write") is True


# ------------------------------------------------------------------- agents.defaults.tools

def test_dist_agent_tools_falls_back_to_agents_defaults_only_without_a_roster():
    text = dist_text("agent-tools.policy-*.js", symbol="implicitDefaultTools",
                     contains="implicitDefaultTools")
    assert "implicitDefaultTools" in text
    assert "hasAgentRosterProperty" in text


def test_agents_defaults_tools_is_a_real_scope_with_no_roster():
    """toolpolicy.py:47-49 calls agents.defaults.tools "deliberately NOT a scope" -- true
    for THAT module's read-confinement predicate (resolveAgentConfig never merges it), but
    wrong as a general claim: resolveEffectiveToolPolicy's own agentTools derivation reads
    it as a FALLBACK precisely when there is no roster to read instead."""
    cfg = {"agents": {"defaults": {"tools": {"allow": ["write"]}}}}
    assert "entries" not in cfg["agents"] and "list" not in cfg["agents"]
    assert toolgrant.granted(cfg, "write", toolgrant.GLOBAL_SCOPE) is True
    assert toolgrant.granted(cfg, "write", "main") is True
    assert toolgrant.granted(cfg, "write", "anything-at-all") is True
    assert toolgrant.granted(cfg, "read") is False


def test_agents_defaults_tools_is_ignored_once_a_roster_exists():
    cfg = {
        "agents": {
            "defaults": {"tools": {"allow": ["write"]}},
            "entries": {"main": {}},
        },
    }
    # the roster now governs; agents.defaults.tools is never consulted, so with no other
    # tools declared anywhere the permissive default applies (nothing restricts anything).
    assert toolgrant.granted(cfg, "read", "main") is True
    assert toolgrant.granted(cfg, "read", toolgrant.GLOBAL_SCOPE) is True


# --------------------------------------------------------------------- agent-id normalization

_AGENT_ID_CASES = [
    ("main", "main"),
    ("Main", "main"),
    ("MAIN ", "main"),
    ("a-", "a-"),
    ("a_", "a_"),
    ("-a", "a"),
    ("a b", "a-b"),
    ("", "main"),
    (" ", "main"),
    (None, "main"),
    ("a" * 70, "a" * 64),
    ("a@b", "a-b"),
    ("A-B_c9", "a-b_c9"),
    ("9start", "9start"),
    ("_x", "_x"),
    ("---", "main"),
]


@pytest.mark.parametrize("raw,expected", _AGENT_ID_CASES, ids=[repr(c[0]) for c in _AGENT_ID_CASES])
def test_normalize_agent_id_matches_our_own_port(raw, expected):
    """Pinned against the dist-measured table (agent-id-*.js, normalizeAgentId) captured
    once by executing the real function -- see the module docstring's citation. "a-" is
    the case that distinguishes the real two-branch resolver from a naive
    fold-then-strip-dashes port: an ALREADY-VALID id is lowercased and returned as-is,
    trailing dash included, while an invalid one goes through the fold/strip/truncate path."""
    assert toolgrant._normalize_agent_id(raw) == expected


def test_dist_normalize_agent_id_two_branch_shape_is_still_current():
    text = dist_text("agent-id-*.js", symbol="normalizeAgentIdStrict",
                     contains="normalizeAgentIdStrict")
    assert "VALID_ID_RE" in text and "normalizeAgentIdStrict" in text, (
        "normalizeAgentId's shape moved -- re-run the differential capture and re-pin "
        "_AGENT_ID_CASES above"
    )


# ------------------------------------------------------------------ always-on: the machinery
# Everything below needs neither node nor the dist. It pins the parts of the harness that, if
# they were wrong, would make the live guards above green for the wrong reason.

_TABLE = {"group:a": ["x", "y", "z"], "group:b": ["p"]}


def test_diff_tables_accepts_identical_tables_and_names_nothing():
    assert oracle.diff_tables(_TABLE, json.loads(json.dumps(_TABLE)), "groups") == []


@pytest.mark.parametrize("mutate,expect", [
    (lambda t: t["group:a"].append("w"), "vendor lacks"),          # we carry an extra member
    (lambda t: t["group:a"].remove("y"), "toolgrant.py lacks"),    # we dropped a member
    (lambda t: t["group:a"].reverse(), "different order"),         # order only
    (lambda t: t.pop("group:b"), "not in toolgrant.py"),           # a whole group missing
    (lambda t: t.update({"group:c": ["q"]}), "not in the vendor"), # a phantom group
    (lambda t: t.update({"group:b": ["p", "p"]}), "group:b"),      # a duplicated member
])
def test_diff_tables_fails_when_one_entry_differs(mutate, expect):
    """The positive control the whole-table guards rest on: a comparison that cannot fail
    controls nothing. Each mutation is one entry, and each must be reported and NAMED."""
    ours = json.loads(json.dumps(_TABLE))
    mutate(ours)
    problems = oracle.diff_tables(ours, _TABLE, "groups")
    assert problems, "a one-entry difference was not reported"
    assert any(expect in line for line in problems), problems


def test_diff_tables_reports_a_changed_scalar():
    assert oracle.diff_tables({"cron": "automation"}, {"cron": "automations"}, "aliases")


def _row(label, **results):
    return {"label": label, "agents": [], "results": {t: {"global": v} for t, v in results.items()}}


def test_diff_battery_names_a_moved_cell_and_ignores_an_unchanged_one():
    same = [_row("a", read=True, exec=False)]
    assert oracle.diff_battery(same, [_row("a", read=True, exec=False)]) == []
    moved = oracle.diff_battery(same, [_row("a", read=True, exec=True)])
    assert moved == ["a/global/exec: pinned False -> True"]
    assert oracle.diff_battery(same, [])  # a pinned row that vanished is reported too


def test_synthetic_configs_reach_every_group_and_profile_they_are_given():
    fake = {
        "profiles": {"minimal": {"allow": ["a"]}, "coding": {"allow": ["b"]}, "full": {"allow": ["*"]}},
        "groups": {"group:one": ["a"], "group:two": ["b"]},
    }
    rows = dict(oracle.synthetic_configs(fake))
    for group in fake["groups"]:
        for kind in ("allow", "deny", "minimal-also"):
            assert f"synthetic/group/{group}/{kind}" in rows, (group, kind)
    for profile in fake["profiles"]:
        assert f"synthetic/profile/{profile}" in rows, profile
    assert list(dict(oracle.synthetic_configs(fake))) == list(rows)  # deterministic order
    assert all(isinstance(cfg, dict) and cfg for cfg in rows.values())


def test_all_tool_ids_includes_names_the_catalog_only_mentions_indirectly():
    tables = {
        "groups": {"group:a": ["x"]}, "profiles": {"p": {"allow": ["y", "*"]}},
        "aliases": {"bash": "exec"}, "shipped_family": {"canvas": ["show_widget"]},
        "shipped_renames": {"update_plan": "progress_card"},
    }
    names = oracle.all_tool_ids(tables)
    assert names == sorted(set(names))
    for expected in ("x", "y", "bash", "exec", "canvas", "show_widget", "update_plan",
                     "progress_card", "nonexistent_tool"):
        assert expected in names
    assert "*" not in names


_BUNDLE = (
    'import { a as thing } from "./other-abc.mjs";\n'
    'import "./side-effect.mjs";\n'
    "const CORE_TOOL_PROFILES = { full: { allow: [\"*\"] } };\n"
    "function resolveCoreToolProfilePolicy(p) { return CORE_TOOL_PROFILES[p]; }\n"
    "export { resolveCoreToolProfilePolicy as a };\n"
)


def test_rewrite_points_imports_at_the_dist_and_exports_the_real_names(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    bundle = dist / "cat.mjs"
    bundle.write_text(_BUNDLE, encoding="utf-8")
    out = oracle._rewrite(bundle, ["CORE_TOOL_PROFILES", "resolveCoreToolProfilePolicy"], dist)
    assert f'from "file://{dist}/other-abc.mjs"' in out
    assert f'import "file://{dist}/side-effect.mjs"' in out
    assert out.rstrip().endswith("export { CORE_TOOL_PROFILES, resolveCoreToolProfilePolicy };")
    assert "as a }" not in out  # the minified export clause is gone
    assert "function resolveCoreToolProfilePolicy" in out  # the body is the vendor's, untouched


@pytest.mark.parametrize("text,why", [
    ("const CORE_TOOL_PROFILES = {};\nexport { CORE_TOOL_PROFILES };\n", "no relative import"),
    (_BUNDLE + "export { thing };\n", "expected one export clause"),
    (_BUNDLE.replace("const CORE_TOOL_PROFILES", "const RENAMED"), "no longer declares"),
])
def test_rewrite_refuses_a_bundle_shape_it_does_not_understand(tmp_path, text, why):
    """A rewrite that silently half-applied would import something other than the vendor's
    tables and let the equality guards grade the wrong object. Each shape fails for ITS reason."""
    bundle = tmp_path / "cat.mjs"
    bundle.write_text(text, encoding="utf-8")
    with pytest.raises(AssertionError, match=why):
        oracle._rewrite(bundle, ["CORE_TOOL_PROFILES"], tmp_path)


def _fake_dist(tmp_path, monkeypatch, files):
    dist = tmp_path / "dist"
    dist.mkdir()
    for name, text in files.items():
        (dist / name).write_text(text, encoding="utf-8")
    monkeypatch.setattr(oracle, "require_dist", lambda: dist)
    return dist


def test_locate_refuses_two_declaring_bundles_instead_of_taking_the_first(tmp_path, monkeypatch):
    decl = "function resolveConfiguredToolPolicies(params) {}\n"
    _fake_dist(tmp_path, monkeypatch, {"a.mjs": decl, "b.mjs": decl})
    with pytest.raises(AssertionError, match="2 bundle"):
        oracle.locate("policies")


def test_locate_refuses_a_symbol_that_moved(tmp_path, monkeypatch):
    _fake_dist(tmp_path, monkeypatch, {"a.mjs": "function somethingElse() {}\n"})
    with pytest.raises(AssertionError, match="0 bundle"):
        oracle.locate("policies")


def test_locate_takes_the_bundle_the_resolver_imports_when_the_symbol_is_declared_twice(tmp_path, monkeypatch):
    """resolveAgentConfig really is declared in two unrelated bundles on 2026.9.5 (a lookup
    by id, and the per-agent config builder). Declaring it is not enough; the resolver's own
    import clause says which one it runs."""
    decl = "function resolveAgentConfig(cfg, id) {}\n"
    _fake_dist(tmp_path, monkeypatch, {
        "policies.mjs": (
            'import { r as resolveAgentConfig } from "./real.mjs";\n'
            "function resolveConfiguredToolPolicies(params) {}\n"
        ),
        "real.mjs": decl,
        "decoy.mjs": decl,
    })
    assert oracle.locate("scope").name == "real.mjs"
    assert oracle.locate("policies").name == "policies.mjs"


def test_locate_refuses_an_import_from_a_bundle_that_no_longer_declares_the_symbol(tmp_path, monkeypatch):
    _fake_dist(tmp_path, monkeypatch, {
        "policies.mjs": (
            'import { r as resolveAgentConfig } from "./shim.mjs";\n'
            "function resolveConfiguredToolPolicies(params) {}\n"
        ),
        "shim.mjs": 'export { resolveAgentConfig } from "./elsewhere.mjs";\n',
    })
    with pytest.raises(AssertionError, match="no longer imports"):
        oracle.locate("scope")


def test_the_battery_tool_lists_do_not_overlap():
    assert not set(oracle.TOOL_FAMILY) & set(oracle.EXTENDED_TOOLS)
    assert oracle.BATTERY_TOOLS == oracle.TOOL_FAMILY + oracle.EXTENDED_TOOLS
