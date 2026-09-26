"""``clawseccheck/harnessruntime.py`` re-grounded against the INSTALLED OpenClaw, live.

Local-only: skipped wherever the dist (or node) is absent -- CI, a machine without OpenClaw.
That is the only stand-down; a present dist whose anchors moved FAILS, naming the symbol
(B-728, ``tests/_distgrounding.py``). The offline replay of the same battery, which is what
CI runs, is ``test_harnessruntime_battery.py``.

Three jobs, in order of how much they would cost to lose:

1. **Soundness, live.** Re-execute the vendor over every battery case and require the port to
   be sound against the FRESH answer -- so a vendor release that moves the chain turns this
   red on the developer's machine, before the pinned battery goes quietly stale.
2. **Drift.** On the build the battery was generated for, the fresh oracle must equal the
   pinned one row for row. A mismatch means the battery (or the case tables) changed without
   a regeneration: ``python3.12 tests/_harnessoracle.py --write``.
3. **Anchors.** The four functions the oracle binds are exported by their real names.
"""
from __future__ import annotations

import copy
import json
import subprocess

import pytest
from _distgrounding import require_dist

import _harnessoracle as oracle
from clawseccheck import harnessruntime as hr

pytestmark = pytest.mark.skipif(not oracle.has_node(), reason="no node on this machine")


@pytest.fixture(scope="module")
def live():
    require_dist()
    cases = oracle.all_cases()
    return cases, oracle.run_oracle(copy.deepcopy(cases))


def _version():
    ver = oracle.dist_version()
    assert ver, "could not read the installed OpenClaw version"
    return ver, tuple(int(x) for x in ver.split(".")[:3])


def test_port_is_sound_against_the_live_vendor(live):
    cases, results = live
    _, numeric = _version()
    # clamp INTO the window: on a build newer than the validated one the port would answer
    # `unknown` to everything, which is trivially sound and would hide the drift this test is for
    version = min(max(numeric, hr.ORACLE_MIN), hr.ORACLE_MAX)
    bad = []
    counts = {hr.YES: 0, hr.NO: 0, hr.UNKNOWN: 0}
    for case, res in zip(cases, results):
        got = hr.codex_harness_reach(case["cfg"], version, environ=case["env"]).answer
        counts[got] += 1
        if "error" in res:
            if got != hr.UNKNOWN:
                bad.append((case["label"], got, res["error"]))
            continue
        has = "codex" in res["runtimes"]
        if (got == hr.YES and not has) or (got == hr.NO and has):
            bad.append((case["label"], got, res["runtimes"]))
    assert not bad, bad[:10]
    assert counts[hr.YES] and counts[hr.NO] and counts[hr.UNKNOWN], counts


def test_the_installed_build_is_inside_the_validated_window():
    """The drift ALARM. Outside ``ORACLE_MIN..ORACLE_MAX`` the runtime answers `unknown` and
    the B353 / B333 gate silently goes back to the old WARN -- safe, but a feature that has
    quietly stopped working. This turns that into a red test on the developer's machine, so
    the upgrade protocol re-runs the battery and raises ``ORACLE_MAX`` deliberately."""
    require_dist()
    ver, numeric = _version()
    assert hr.ORACLE_MIN <= numeric <= hr.ORACLE_MAX, (
        f"installed OpenClaw {ver} is outside the window the Codex-harness determination was "
        f"validated on {hr.ORACLE_MIN}..{hr.ORACLE_MAX}: re-run the live soundness test, "
        f"regenerate the battery (`python3.12 tests/_harnessoracle.py --write`) and raise "
        f"ORACLE_MAX -- until then B353/B333 fall back to the pre-gate WARN")


def test_pinned_battery_has_not_drifted_from_the_vendor(live):
    ver, _ = _version()
    if ver != oracle.ORACLE_BUILD:
        pytest.skip(f"installed OpenClaw {ver} is not the build the battery is pinned to "
                    f"({oracle.ORACLE_BUILD}); the live soundness test above is the check "
                    f"for this build, and re-baselining is a deliberate step")
    cases, results = live
    pinned = json.loads(oracle.BATTERY_PATH.read_text(encoding="utf-8"))
    assert pinned["build"] == ver
    fresh = [{"label": c["label"], "cfg": c["cfg"], "env": c["env"], "oracle": r}
             for c, r in zip(cases, results)]
    assert pinned["rows"] == fresh, (
        "tests/data/harnessruntime_battery.json is stale against the case tables or the "
        "vendor -- regenerate with `python3.12 tests/_harnessoracle.py --write` and review "
        "the diff")


def test_model_refs_equal_the_live_vendor_enumeration(live):
    cases, results = live
    for case, res in zip(cases, results):
        if "error" in res:
            continue
        assert [v for _, v in hr.model_refs(case["cfg"])] == res["refs"], case["label"]


def test_the_bound_symbols_are_still_exported_by_name():
    """`run_oracle` asserts each export by real name and raises with the moved symbol; this
    just makes that a named, greppable test rather than a side effect of the others."""
    require_dist()
    assert oracle.run_oracle([{"cfg": {}, "env": {}}]) == [
        {"collect": [], "refs": [], "runtimes": []}]


def test_the_legacy_codex_provider_set_equals_the_vendors():
    """``hr._LEGACY_CODEX_PROVIDERS`` is what stops a ``no`` over ``openai-codex/*``, ``codex/*``
    and ``codex-cli/*`` refs, which the vendor migrates onto the Codex harness (and which the
    runtime collector the battery is graded against never sees). TWO vendor tables feed it, so
    ground the set against BOTH, executed, over spellings on both sides of each boundary:
    ``isLegacyCodexProviderId`` (codex-route-model-ref) and
    ``resolveLegacyRuntimeModelProviderAlias`` (legacy-runtime-model-providers) restricted to
    the aliases whose runtime is ``codex``."""
    require_dist()
    from _distgrounding import dist_file
    a = dist_file("codex-route-model-ref-*.mjs", symbol="isLegacyCodexProviderId",
                  contains="const LEGACY_CODEX_PROVIDER_IDS")
    b = dist_file("legacy-*.mjs", symbol="resolveLegacyRuntimeModelProviderAlias",
                  contains="const LEGACY_RUNTIME_MODEL_PROVIDER_ALIASES")
    ea, eb = oracle._exports(a), oracle._exports(b)
    for path, ex, name in ((a, ea, "isLegacyCodexProviderId"),
                           (b, eb, "resolveLegacyRuntimeModelProviderAlias")):
        assert name in ex, (f"{path.name} no longer exports {name} -- re-ground; do NOT rebind "
                            f"by letter. Exports: {sorted(ex)}")
    probes = ["codex", "openai-codex", "codex-cli", "Codex", " OpenAI-Codex ", "CODEX", " Codex-CLI ",
              "openai", "openai-compat", "codex-app-server", "openai-codex2", "xcodex",
              "claude-cli", "google-gemini-cli", "anthropic-cli", "anthropic", "", "  "]
    script = ("Promise.all([import(process.argv[1]), import(process.argv[2])]).then(([a, b]) => {"
              " const legacy = a[process.argv[3]]; const alias = b[process.argv[4]];"
              " const p = JSON.parse(process.argv[5]);"
              " console.log('@@R@@' + JSON.stringify(p.map(x => Boolean(legacy(x)) || "
              "(alias(x) || {}).runtime === 'codex'))); });")
    proc = subprocess.run(
        ["node", "-e", script, a.as_uri(), b.as_uri(), ea["isLegacyCodexProviderId"],
         eb["resolveLegacyRuntimeModelProviderAlias"], json.dumps(probes)],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr[-1500:]
    line = [ln for ln in proc.stdout.splitlines() if ln.startswith("@@R@@")][-1]
    vendor = json.loads(line[len("@@R@@"):])
    port = [hr._trim(p).lower() in hr._LEGACY_CODEX_PROVIDERS for p in probes]
    assert vendor == port, list(zip(probes, vendor, port))
    assert any(vendor) and not all(vendor)


def test_the_legacy_codex_provider_set_is_every_codex_entry_in_the_vendors_tables():
    """The probe test above only compares over a hand-written probe list, so a vendor table that
    GAINS a codex alias not on the list would slip past it. Read both table literals out of the
    dist source and require the port's set to equal their union (codex runtime only): a new alias
    the vendor migrates onto Codex turns this red, naming the provider."""
    import re
    require_dist()
    from _distgrounding import dist_file
    a = dist_file("codex-route-model-ref-*.mjs", symbol="LEGACY_CODEX_PROVIDER_IDS",
                  contains="const LEGACY_CODEX_PROVIDER_IDS")
    b = dist_file("legacy-*.mjs", symbol="LEGACY_RUNTIME_MODEL_PROVIDER_ALIASES",
                  contains="const LEGACY_RUNTIME_MODEL_PROVIDER_ALIASES")
    text_a = a.read_text(encoding="utf-8", errors="replace")
    text_b = b.read_text(encoding="utf-8", errors="replace")
    ids = re.search(r"const LEGACY_CODEX_PROVIDER_IDS\s*=\s*(?:/\*.*?\*/\s*)?new Set\(\[(.*?)\]\)",
                    text_a, re.S)
    assert ids, "LEGACY_CODEX_PROVIDER_IDS no longer has the literal shape this test reads"
    vendor = {v.lower() for v in re.findall(r'"([^"]+)"', ids.group(1))}
    start = text_b.index("const LEGACY_RUNTIME_MODEL_PROVIDER_ALIASES")
    table = text_b[start:text_b.index("];", start)]
    entries = re.findall(r"\{[^{}]*\}", table)
    assert entries, "LEGACY_RUNTIME_MODEL_PROVIDER_ALIASES no longer has the literal shape read here"
    for entry in entries:
        legacy = re.search(r'legacyProvider:\s*"([^"]+)"', entry)
        runtime = re.search(r'runtime:\s*"([^"]+)"', entry)
        assert legacy and runtime, entry
        if runtime.group(1) == "codex":
            vendor.add(legacy.group(1).lower())
    assert vendor == set(hr._LEGACY_CODEX_PROVIDERS), (
        f"the vendor migrates {sorted(vendor)} onto the Codex harness; the port refuses "
        f"{sorted(hr._LEGACY_CODEX_PROVIDERS)} -- add the missing spelling to "
        f"harnessruntime._LEGACY_CODEX_PROVIDERS")


def test_a_picker_runtime_is_counted_by_the_live_collector_and_never_a_no():
    """The collector counts ``models[ref].pickerRuntimes`` like a pin; the port declines to
    answer over one rather than modelling what an OFFERED runtime means."""
    require_dist()
    cfg = {"agents": {"defaults": {"model": "anthropic/c",
                                   "models": {"anthropic/c": {"pickerRuntimes": ["codex"]}}}}}
    res = oracle.run_oracle([{"cfg": cfg, "env": {}}])[0]
    assert "codex" in res["runtimes"], res
    assert hr.codex_harness_reach(cfg, hr.ORACLE_MIN, environ={}).answer == hr.UNKNOWN
