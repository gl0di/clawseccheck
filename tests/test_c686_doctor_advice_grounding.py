"""Every string that sends the user to ``openclaw doctor --fix`` re-grounded against the INSTALLED OpenClaw.

Local-only: skipped wherever the dist or node is absent (the one honest stand-down, see
``_distgrounding.py``). A present dist whose anchors moved FAILS, naming the symbol. The
offline pin of the wording is ``test_c686_doctor_advice_by_build.py``.

OpenClaw 2026.10.1 stopped migrating formats written before July 2026: Doctor and
``openclaw update`` throw on a config key the vendor's finder names
(``findRetiredConfigUpgradeRequirement``) and on a retired state file
(``assertNoRetiredStateFiles``), and name a bridge release to install first. Everything else
is still migrated by ``applyLegacyDoctorMigrations``. This file EXECUTES the vendor over one
config (or one state tree) per advised key and pins the classification:

* ``DOCTOR_FIXABLE`` -- keys our advice calls Doctor-fixable ("Doctor removes it"). The
  finder must name NONE of them, and the vendor's own migration must really remove or move
  each one. When the vendor puts one of them on the retired list this goes red, naming the
  key, before the advice goes quietly false.
* ``DOCTOR_REFUSES`` -- keys our advice (since C-686) says Doctor refuses on 2026.10.1 and
  later: the finder names exactly that path, the bridge release is the one the text names,
  and the migration that used to handle the key is gone (no change).
* state files -- the cron store, OAuth sidecars and delivery queues make ``assertNoRetired
  StateFiles`` throw with the bridge release ``_RETIRED_STATE_BRIDGE_VERSION``; the legacy
  allow-sender store and the device-auth file (B356) are on none of the retired lists.

Classification table (installed 2026.10.2, measured; "bridge" is what the vendor names):

  B38/RISK-05/RISK-15 browser.ssrfPolicy.allowPrivateNetwork   REFUSED  bridge 2026.9.5
  B382 silentReply.direct / silentReplyRewrite (defaults, surfaces)  REFUSED  bridge 2026.9.5
  B177 plugins.installs                                          REFUSED  bridge 2026.9.5
  B168 cron/jobs.json (+ jobs-state.json, runs/*.jsonl)          REFUSED  bridge 2026.9.7
  B382 the other table rows, B2 allowInsecureAuth, B48
       dangerouslyDisableDeviceAuth, B175 allowSymlinkTargetWrites,
       B9 logging.redactSensitive, the marketplaces block         MIGRATED by Doctor
  B356 credentials/<channel>-allowFrom.json, identity/device-auth.json  not retired; Doctor
       migrates them (but stops first if a retired file/key is also present)
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from _distgrounding import dist_declaring, require_dist

import _retiredformatsoracle as oracle
from clawseccheck import retiredformats as rf
from clawseccheck.checks import (
    _DOCTOR_REFUSES_RETIRED_MIN,
    _RETIRED_CONFIG_KEYS,
    _RETIRED_STATE_BRIDGE_VERSION,
)
from clawseccheck.checks._shared import _numeric_version

pytestmark = pytest.mark.skipif(not oracle.has_node(), reason="no node on this machine")

# --------------------------------------------------------------------------------------
# the advised keys
# --------------------------------------------------------------------------------------
#: label -> (dotted path that must be gone after Doctor's migration, one-key config).
DOCTOR_FIXABLE = {
    "B2 gateway.controlUi.allowInsecureAuth": (
        "gateway.controlUi.allowInsecureAuth",
        {"gateway": {"controlUi": {"allowInsecureAuth": True}}}),
    "B48 gateway.controlUi.dangerouslyDisableDeviceAuth": (
        "gateway.controlUi.dangerouslyDisableDeviceAuth",
        {"gateway": {"controlUi": {"dangerouslyDisableDeviceAuth": True}}}),
    "B175 skills.workshop.allowSymlinkTargetWrites": (
        "skills.workshop.allowSymlinkTargetWrites",
        {"skills": {"workshop": {"allowSymlinkTargetWrites": True}}}),
    "B9 logging.redactSensitive": (
        "logging.redactSensitive", {"logging": {"redactSensitive": "off"}}),
    "marketplaces block": ("marketplaces", {"marketplaces": {"feeds": ["x"]}}),
}

#: One sample value per B382 table row (a new table row without one fails the coverage test
#: below). A `*` segment is expanded to a concrete free-form surface name.
_TABLE_SAMPLE = {
    "audit.enabled": True,
    "gateway.nodes.allowCommands": ["a"],
    "gateway.nodes.denyCommands": ["a"],
    "skills.workshop.autonomous.enabled": True,
    "agents.list": [{"id": "main"}],
    "logging.redactSensitive": "off",
    "commands.useAccessGroups": True,
    "gateway.controlUi.allowInsecureAuth": True,
    "diagnostics.cacheTrace.filePath": "x",
    "marketplaces.feeds": ["x"],
    "marketplaces.sources": ["x"],
    "browser.ssrfPolicy.hostnameAllowlist": ["a.b"],
    "skills.workshop.allowSymlinkTargetWrites": True,
    "tools.toolSearch.codeTimeoutMs": 5000,
    "agents.defaults.silentReply.internal": "allow",
    "surfaces.*.silentReply.internal": "allow",
    "agents.defaults.silentReply.direct": "allow",
    "surfaces.*.silentReply.direct": "allow",
    "agents.defaults.silentReplyRewrite": {"id": "x"},
    "surfaces.*.silentReplyRewrite": {"id": "x"},
}
#: The table rows the vendor's finder names (Doctor refuses them on 2026.10.1 and later).
_TABLE_REFUSED = {
    "agents.defaults.silentReply.direct", "surfaces.*.silentReply.direct",
    "agents.defaults.silentReplyRewrite", "surfaces.*.silentReplyRewrite",
}
#: label -> (path the finder must name, one-key config).
DOCTOR_REFUSES = {
    "B38 browser.ssrfPolicy.allowPrivateNetwork": (
        "browser.ssrfPolicy.allowPrivateNetwork",
        {"browser": {"ssrfPolicy": {"allowPrivateNetwork": True}}}),
    "B177 plugins.installs": (
        "plugins.installs", {"plugins": {"installs": {"a": {"source": "npm"}}}}),
}


def _nest(dotted: str, value) -> dict:
    return oracle.nest(dotted.replace("*", "web").split("."), value)


def _has_path(obj, dotted: str) -> bool:
    node = obj
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return True


def _table_cases() -> "dict[str, tuple[str, dict]]":
    return {f"B382 {key}": (key.replace("*", "web"), _nest(key, value))
            for key, value in _TABLE_SAMPLE.items()}


# --------------------------------------------------------------------------------------
# node side
# --------------------------------------------------------------------------------------
_CONFIG_SCRIPT = r"""
import { readFileSync } from "node:fs";
const [, , finderMod, finderAlias, migMod, migAlias, casesPath] = process.argv;
const find = (await import(finderMod))[finderAlias];
const apply = (await import(migMod))[migAlias];
const cases = JSON.parse(readFileSync(casesPath, "utf8"));
const out = [];
for (const c of cases) {
  const rec = {};
  try {
    const r = find(structuredClone(c.cfg));
    rec.finder = r === undefined ? null : { message: r.message, nextAction: r.nextAction };
  } catch (e) { rec.finder = { error: String((e && e.message) || e).slice(0, 200) }; }
  try {
    const m = apply(structuredClone(c.cfg), { pluginContracts: false });
    rec.migration = { next: m.next, changes: m.changes };
  } catch (e) { rec.migration = { error: String((e && e.message) || e).slice(0, 200) }; }
  out.push(rec);
}
console.log("@@RESULT@@" + JSON.stringify(out));
"""

_BROWSER_SCRIPT = r"""
import { readFileSync } from "node:fs";
const [, , mod, alias, casesPath] = process.argv;
const resolve = (await import(mod))[alias];
const cases = JSON.parse(readFileSync(casesPath, "utf8"));
const out = cases.map((policy) => {
  try { return resolve({ ssrfPolicy: policy }, {}).ssrfPolicy ?? null; }
  catch (e) { return { error: String((e && e.message) || e).slice(0, 200) }; }
});
console.log("@@RESULT@@" + JSON.stringify(out));
"""

_STATE_SCRIPT = r"""
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
const [, , cronMod, cronAlias, assertMod, assertAlias, delMod, delAlias, oauthMod, oauthAlias,
  scenariosPath] = process.argv;
const listCron = (await import(cronMod))[cronAlias];
const assertNo = (await import(assertMod))[assertAlias];
const listDelivery = (await import(delMod))[delAlias];
const listOauth = (await import(oauthMod))[oauthAlias];
const scenarios = JSON.parse(fs.readFileSync(scenariosPath, "utf8"));
const root = fs.mkdtempSync(path.join(os.tmpdir(), "c686-state-"));
const out = [];
try {
  let n = 0;
  for (const files of scenarios) {
    const state = path.join(root, "s" + (n++));
    fs.mkdirSync(state, { recursive: true });
    for (const rel of files) {
      fs.mkdirSync(path.dirname(path.join(state, rel)), { recursive: true });
      fs.writeFileSync(path.join(state, rel), "{}");
    }
    const env = { OPENCLAW_STATE_DIR: state, HOME: root };
    const rec = {};
    const probes = {
      cron: async () => assertNo("Cron state", await listCron(path.join(state, "cron", "jobs.json"))),
      oauth: async () => assertNo("OAuth credential sidecars", listOauth(env, undefined, state)),
      delivery: async () => assertNo("JSON delivery queues", listDelivery(state)),
    };
    for (const [name, probe] of Object.entries(probes)) {
      try { await probe(); rec[name] = null; }
      catch (e) { rec[name] = { name: e.name, message: String(e.message).split(state).join("<state>") }; }
    }
    out.push(rec);
  }
} finally { fs.rmSync(root, { recursive: true, force: true }); }
console.log("@@RESULT@@" + JSON.stringify(out));
"""


def _node(script: str, args: "list[str]") -> list:
    work = Path(tempfile.mkdtemp(prefix="c686-"))  # mkdtemp: module-level helper outside any fixture; removed in the finally below
    try:
        (work / "run.mjs").write_text(script, encoding="utf-8")
        proc = subprocess.run(["node", str(work / "run.mjs"), *args],
                              capture_output=True, text=True, timeout=300, cwd=str(work))
        assert proc.returncode == 0, proc.stderr[-2000:]
        line = [ln for ln in proc.stdout.splitlines() if ln.startswith("@@RESULT@@")][-1]
        return json.loads(line[len("@@RESULT@@"):])
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _alias(path: Path, symbol: str) -> str:
    exports = oracle._exports(path)
    assert symbol in exports, (
        f"{path.name} no longer exports {symbol} -- re-ground; do NOT rebind by letter. "
        f"Exports: {sorted(exports)}")
    return exports[symbol]


def _run_config_cases(cases: "list[dict]") -> list:
    finder = oracle.finder_bundle()
    migrate = dist_declaring("function applyLegacyDoctorMigrations(",
                             symbol="applyLegacyDoctorMigrations")
    work = Path(tempfile.mkdtemp(prefix="c686-cases-"))  # mkdtemp: module-level helper outside any fixture; removed in the finally below
    try:
        (work / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
        return _node(_CONFIG_SCRIPT, [
            finder.as_uri(), _alias(finder, "findRetiredConfigUpgradeRequirement"),
            migrate.as_uri(), _alias(migrate, "applyLegacyDoctorMigrations"),
            str(work / "cases.json")])
    finally:
        shutil.rmtree(work, ignore_errors=True)


@pytest.fixture(scope="module")
def vendor_config_answers() -> "dict[str, dict]":
    require_dist()
    labelled: "dict[str, tuple[str, dict]]" = {}
    labelled.update(DOCTOR_FIXABLE)
    labelled.update(DOCTOR_REFUSES)
    labelled.update(_table_cases())
    labels = list(labelled)
    answers = _run_config_cases([{"cfg": labelled[label][1]} for label in labels])
    return dict(zip(labels, answers))


@pytest.fixture(scope="module")
def vendor_state_answers() -> "dict[str, dict]":
    require_dist()
    cron = dist_declaring("async function listRetiredCronStateFiles(",
                          symbol="listRetiredCronStateFiles")
    assert_no = dist_declaring("function assertNoRetiredStateFiles(",
                               symbol="assertNoRetiredStateFiles")
    delivery = dist_declaring("function listRetiredDeliveryQueueFiles(",
                              symbol="listRetiredDeliveryQueueFiles")
    oauth = dist_declaring("function listLegacyOAuthSidecarPaths(",
                           symbol="listLegacyOAuthSidecarPaths")
    scenarios = {
        "cron/jobs.json": ["cron/jobs.json"],
        "cron/jobs-state.json": ["cron/jobs-state.json"],
        "cron/runs/*.jsonl": ["cron/runs/a.jsonl"],
        "credentials/auth-profiles/<32hex>.json": [f"credentials/auth-profiles/{'a' * 32}.json"],
        "delivery-queue/*.json": ["delivery-queue/q.json"],
        "B356 allowFrom + device-auth": ["credentials/telegram-allowFrom.json",
                                         "identity/device-auth.json"],
        "auth-profiles file that is not a sidecar": ["credentials/auth-profiles/x.json"],
    }
    work = Path(tempfile.mkdtemp(prefix="c686-scn-"))  # mkdtemp: module-level helper outside any fixture; removed in the finally below
    try:
        (work / "scenarios.json").write_text(json.dumps(list(scenarios.values())),
                                             encoding="utf-8")
        answers = _node(_STATE_SCRIPT, [
            cron.as_uri(), _alias(cron, "listRetiredCronStateFiles"),
            assert_no.as_uri(), _alias(assert_no, "assertNoRetiredStateFiles"),
            delivery.as_uri(), _alias(delivery, "listRetiredDeliveryQueueFiles"),
            oauth.as_uri(), _alias(oauth, "listLegacyOAuthSidecarPaths"),
            str(work / "scenarios.json")])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return dict(zip(scenarios, answers))


# --------------------------------------------------------------------------------------
# config keys
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("label", sorted(DOCTOR_FIXABLE))
def test_doctor_fixable_key_is_not_on_the_retired_list_and_is_migrated(
        label, vendor_config_answers):
    path, _cfg = DOCTOR_FIXABLE[label]
    answer = vendor_config_answers[label]
    assert answer["finder"] is None, (
        f"{label}: OpenClaw's retired-format finder now names it -- Doctor and `openclaw "
        f"update` REFUSE this config on the installed build, so every sentence that says "
        f"`openclaw doctor --fix` removes it is false. Reword it like the ssrf alias: "
        f"{answer['finder']}")
    migration = answer["migration"]
    assert "error" not in migration, migration
    assert migration["changes"], f"{label}: Doctor's migration no longer changes this key"
    assert not _has_path(migration["next"], path), (
        f"{label}: Doctor's migration leaves {path} in place")


@pytest.mark.parametrize("key", sorted(_TABLE_SAMPLE))
def test_b382_table_row_classification(key, vendor_config_answers):
    answer = vendor_config_answers[f"B382 {key}"]
    path = key.replace("*", "web")
    if key in _TABLE_REFUSED:
        assert answer["finder"] is not None, f"{key}: the finder no longer names it"
        assert path in answer["finder"]["message"]
        assert f"Install OpenClaw {rf.BRIDGE_DEFAULT}," in answer["finder"]["nextAction"]
        return
    assert answer["finder"] is None, (
        f"{key}: now on the vendor's retired list -- B382's non-finder `fix` (\"Run "
        f"`openclaw doctor --fix`\") is false for it: {answer['finder']}")
    migration = answer["migration"]
    assert "error" not in migration, migration
    assert migration["changes"] and not _has_path(migration["next"], path), (
        f"{key}: Doctor's migration no longer handles it: {migration}")


def test_every_b382_table_row_has_a_sample():
    # A control that can fail: a row added to the table without a measurement here would
    # otherwise ride on advice nobody executed.
    assert set(_TABLE_SAMPLE) == set(_RETIRED_CONFIG_KEYS)


@pytest.mark.parametrize("label", sorted(DOCTOR_REFUSES))
def test_refused_key_is_named_by_the_finder_and_no_migration_handles_it(
        label, vendor_config_answers):
    path, _cfg = DOCTOR_REFUSES[label]
    answer = vendor_config_answers[label]
    assert answer["finder"] is not None, (
        f"{label}: the finder no longer names it -- the 2026.10.1 wording (Doctor refuses, "
        "delete by hand) is now false for the installed build")
    assert path in answer["finder"]["message"]
    # the bridge release our text names is the one the vendor names for this key
    assert f"Install OpenClaw {rf.BRIDGE_DEFAULT}," in answer["finder"]["nextAction"]
    migration = answer["migration"]
    assert "error" not in migration, migration
    assert not migration["changes"] and migration["next"] is None, (
        f"{label}: a Doctor migration now handles it: {migration}")


def test_our_refusal_boundary_matches_the_installed_build():
    require_dist()
    installed = _numeric_version(oracle.dist_version())
    assert installed is not None, "installed OpenClaw version could not be read"
    if installed < _DOCTOR_REFUSES_RETIRED_MIN:
        pytest.skip("installed OpenClaw predates the Doctor refusal; nothing to ground")
    # On an installed build at or above our boundary the finder must name the ssrf alias;
    # `_doctor_refuses_retired_formats` is true there and the wording relies on it.
    found = _run_config_cases(
        [{"cfg": {"browser": {"ssrfPolicy": {"allowPrivateNetwork": True}}}}])[0]
    assert found["finder"] is not None


# --------------------------------------------------------------------------------------
# state files
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("scenario, probe", [
    ("cron/jobs.json", "cron"),
    ("cron/jobs-state.json", "cron"),
    ("cron/runs/*.jsonl", "cron"),
    ("credentials/auth-profiles/<32hex>.json", "oauth"),
    ("delivery-queue/*.json", "delivery"),
])
def test_retired_state_file_makes_the_vendor_throw_naming_the_bridge(
        scenario, probe, vendor_state_answers):
    thrown = vendor_state_answers[scenario][probe]
    assert thrown is not None, f"{scenario}: no longer a retired state file"
    assert thrown["name"] == "RetiredStateFormatError"
    assert f"Upgrade through OpenClaw {_RETIRED_STATE_BRIDGE_VERSION}," in thrown["message"]


def test_b356_files_are_on_no_retired_list(vendor_state_answers):
    # B356's allow-sender and device-auth files are migrated by Doctor, not refused.
    assert vendor_state_answers["B356 allowFrom + device-auth"] == {
        "cron": None, "oauth": None, "delivery": None}
    # and the sidecar rule is the 32-hex shape, not any file under auth-profiles/
    assert vendor_state_answers["auth-profiles file that is not a sidecar"]["oauth"] is None


# --------------------------------------------------------------------------------------
# the installed browser and the retired SSRF alias
# --------------------------------------------------------------------------------------
def test_installed_browser_ignores_the_retired_ssrf_alias_but_not_the_canonical_flag():
    """B38 / RISK-05 / RISK-15 say, from 2026.10.1, that the alias alone opens nothing on the
    installed build (``_LEGACY_SSRF_ALIAS_1010_INERT``) and that the canonical flag still does.
    EXECUTED: the vendor's ``resolveBrowserConfig`` over the three shapes."""
    require_dist()
    # two bundles declare a `resolveBrowserConfig`; the one that also declares the SSRF-policy
    # resolver (the code that reads `ssrfPolicy`) is the citation.
    bundle = dist_declaring("function resolveBrowserSsrFPolicy(",
                            symbol="resolveBrowserSsrFPolicy")
    cases = [{"allowPrivateNetwork": True},
             {"allowPrivateNetwork": True, "dangerouslyAllowPrivateNetwork": False},
             {"dangerouslyAllowPrivateNetwork": True}]
    work = Path(tempfile.mkdtemp(prefix="c686-browser-"))  # mkdtemp: module-level helper outside any fixture; removed in the finally below
    try:
        (work / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
        alias_only, alias_and_false, canonical = _node(_BROWSER_SCRIPT, [
            bundle.as_uri(), _alias(bundle, "resolveBrowserConfig"), str(work / "cases.json")])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    assert not (alias_only or {}).get("dangerouslyAllowPrivateNetwork"), alias_only
    assert not (alias_only or {}).get("allowPrivateNetwork"), alias_only
    assert alias_and_false == {"dangerouslyAllowPrivateNetwork": False}
    assert canonical == {"dangerouslyAllowPrivateNetwork": True}
