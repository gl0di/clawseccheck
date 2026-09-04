"""B-700 — no finding may tell a user to write a config key their OpenClaw rejects.

The defect this pins: OpenClaw 2026.8.1 removed or moved nine settings this tool hands out
fix instructions for, and the instructions were not updated. Proven by executing the real
schema on what our own strings said to write::

    logging.redactSensitive: "tools"   (B9's fix)   => REJECTED unrecognized_keys@logging
    audit.enabled: true                (B10's fix)  => REJECTED unrecognized_keys@<root>
    logging.audit.enabled: true        (the real path)  => valid

Two layers, ranked by how much they know, matching `test_schema_grounding.py`'s own
arrangement:

* ALWAYS ON — the rendered `detail`/`fix` of every finding is swept for a retired key. A
  retired key may appear only when it is version-qualified, or when the user's own config
  actually contains it (telling someone to REMOVE a key they have is never wrong; telling
  them to ADD one their build rejects is the bug).
* LOCAL ONLY — the retired table itself is checked against the installed dist, so the
  table cannot rot the way the advice did.

The table is deliberately explicit rather than "any dotted token": a generic path
extractor trips over `openclaw.json`, `clawhub.ai` and `system.run`, and a guard that
cries wolf gets weakened until it means nothing.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

import clawseccheck.checks as C
from clawseccheck.checks._agents import _disk_subagent_disclosure
from clawseccheck.collector import Context, collect

REPO = Path(__file__).resolve().parent.parent

# key -> replacement on 2026.8.1, or None when it was removed outright.
# Every entry was verified by `safeParse` against BOTH installed schemas, each with a
# bogus-key control at the same parent (`gateway.tls` is a passthrough and accepts junk,
# so an ACCEPTED probe alone proves nothing).
RETIRED_IN_2026_8_1 = {
    "audit.enabled": "logging.audit.enabled",
    "gateway.nodes.allowCommands": "gateway.nodes.commands.allow",
    "gateway.nodes.denyCommands": "gateway.nodes.commands.deny",
    "skills.workshop.autonomous.enabled": "skills.workshop.autonomous.mode",
    "agents.list": "agents.entries",
    "logging.redactSensitive": None,
    "commands.useAccessGroups": None,
    "gateway.controlUi.allowInsecureAuth": None,
    "diagnostics.cacheTrace.filePath": None,
    "marketplaces.feeds": None,
    "marketplaces.sources": None,
}

# A string that names a retired key is fine when it also says WHICH BUILD it applies to.
# Deliberately version tokens only: an earlier draft also accepted phrases like "removed"
# and "openclaw doctor", which any unrelated sentence can contain -- that turns the escape
# hatch into a hole wide enough to walk a real defect through.
_QUALIFIERS = ("2026.8.1", "2026.7")

_MODERN = "2026.8.1"
_LEGACY = "2026.7.1-2"


def _findings(cfg: dict, installed):
    home = Path(tempfile.mkdtemp(prefix="b700-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg))
    os.chmod(path, 0o600)
    ctx = collect(str(home))
    ctx.installed_dist_version = installed
    return C.run_all(ctx)


def _seg_char(c: str) -> bool:
    """Is *c* a character that can continue a config path segment?"""
    return bool(c) and (c.isalnum() or c == "_")


def _names_key(text: str, key: str) -> bool:
    """True when *text* names exactly *key*, not a longer path that ends with it.

    B-714 correction. The original rule was `after not in "."`, which is False for BOTH a
    trailing "." and the empty string — `"" in "."` is True in Python — so a key that ENDED
    A SENTENCE, or ended the text, was never matched. Measured on six cases when the risk
    sweep's positive control failed: three wrong, including the real defect string
    `...explicit browser.ssrfPolicy.hostnameAllowlist. Breaking either leg...`. That is the
    most natural way advice names a key, so the guard was blind precisely where its subject
    lives — and it stayed green for it.

    The distinction that was being reached for is a longer PATH, not any following dot:
    `audit.enabled.sub` must not match `audit.enabled`, while `Delete audit.enabled.` must.
    So a "." only disqualifies when another segment character follows it.
    """
    start = 0
    while True:
        i = text.find(key, start)
        if i == -1:
            return False
        before = text[i - 1] if i else ""
        rest = text[i + len(key):]
        longer_prefix = before == "." or _seg_char(before)
        longer_suffix = _seg_char(rest[:1]) or (rest[:1] == "." and _seg_char(rest[1:2]))
        if not longer_prefix and not longer_suffix:
            return True
        start = i + 1


def _config_has(cfg, key: str) -> bool:
    """Does the config actually contain this dotted key?

    Walked structurally, not string-matched. A `key in json.dumps(cfg)` test, or worse a
    test on the last segment, excuses `audit.enabled` for any config that happens to
    contain some other `"enabled"` -- which is most of them, and would have made this
    whole guard decorative.
    """
    node = cfg
    for part in key.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return True


def _offending(findings, cfg):
    """Retired keys named in advice without a qualifier and without being in the config."""
    out = []
    for f in findings:
        for field in ("detail", "fix"):
            text = getattr(f, field, None)
            if not isinstance(text, str):
                continue
            for key in RETIRED_IN_2026_8_1:
                # Whole-path match. A plain substring test reports `audit.enabled` inside
                # `logging.audit.enabled` -- i.e. it flags the very fix as the defect,
                # which is how a guard teaches you to weaken it.
                if not _names_key(text, key):
                    continue
                if any(q in text for q in _QUALIFIERS):
                    continue
                if _config_has(cfg, key):
                    continue  # the user has this key; naming it is correct
                out.append(f"{f.id}.{field}: {key}")
    return out


# The configs are chosen to REACH the branches that hand out advice. A guard that only
# ever runs the empty config proves nothing about the texts that matter.
_CONFIGS = [
    ("empty", {}),
    ("gateway-open", {"gateway": {"bind": "0.0.0.0:8080"}}),
    ("channels-open", {"channels": {"telegram": {"dmPolicy": "open"}}}),
    ("workshop-auto", {"skills": {"workshop": {"autonomous": {"mode": "auto"},
                                               "approvalPolicy": "auto"}}}),
    ("node-commands", {"gateway": {"nodes": {"commands": {"allow": ["system.run"],
                                                          "deny": ["a b"]}}}}),
    ("cache-trace", {"diagnostics": {"cacheTrace": {"enabled": True}}}),
    ("commands-privileged", {"commands": {"enabled": True}}),
    ("agents-record", {"agents": {"entries": {"main": {"tools": {"profile": "full"}}}}}),
    # B-700 reopen: these two reach B351/B352's fix strings, which still named the
    # retired `agents.list` unqualified -- the sample list above reached neither
    # `tools.codeMode` nor `tools.exec.pathPrepend`, so the always-on sweep never saw
    # them even though its own `_offending()` flags both once asked.
    ("code-mode", {"tools": {"codeMode": {"enabled": True}}}),
    ("exec-path-prepend", {"tools": {"exec": {"pathPrepend": ["/tmp/bin"]}}}),
]


@pytest.mark.parametrize("label,cfg", _CONFIGS, ids=[n for n, _c in _CONFIGS])
def test_no_advice_names_a_retired_key_on_a_modern_build(label, cfg):
    """The headline. On a build we can see is 2026.8.1, nothing may name a key it rejects."""
    offenders = _offending(_findings(cfg, _MODERN), cfg)
    assert not offenders, (
        "advice names a key OpenClaw 2026.8.1 rejects, unqualified:\n  "
        + "\n  ".join(offenders)
        + "\n\nName the 2026.8.1 key, or route the text through "
          "checks/_shared.py::_key_advice / _retired_key_note."
    )


@pytest.mark.parametrize("label,cfg", _CONFIGS, ids=[n for n, _c in _CONFIGS])
def test_a_legacy_build_still_gets_the_key_it_has(label, cfg):
    """The mirror image, and the reason this is not just a find-and-replace.

    Telling a 2026.7.x user to write `logging.audit.enabled` is the same defect pointing
    the other way. On a legacy build the legacy key must survive.
    """
    findings = _findings(cfg, _LEGACY)
    assert findings, "no findings — the sweep would be vacuous"
    blob = " ".join(f"{f.detail or ''} {f.fix or ''}" for f in findings)
    assert "logging.audit.enabled" not in blob or "2026.8.1" in blob


def test_an_undeterminable_build_is_told_both():
    """A hermetic run cannot see the version. It must not silently pick a story."""
    b10 = next(f for f in _findings({}, None) if f.id == "B10")
    text = f"{b10.detail} {b10.fix}"
    assert "logging.audit.enabled" in text and "audit.enabled" in text
    assert "2026.8.1" in text


def test_the_guard_is_not_vacuous():
    """A guard that scans no text, or whose qualifier list swallows everything, passes
    silently. This proves the sweep can actually fail."""
    class Fake:
        id = "FAKE"
        detail = "Set audit.enabled to true."
        fix = "Set audit.enabled to true."
    assert _offending([Fake()], {}), "the sweep cannot detect a retired key"


def test_naming_a_retired_key_the_user_actually_has_is_allowed():
    """The carve-out, pinned so nobody 'fixes' it away: a config that CONTAINS a retired
    key may be told to remove it by name."""
    class Fake:
        id = "FAKE"
        detail = "logging.redactSensitive is set."
        fix = "Delete logging.redactSensitive."
    assert not _offending([Fake()], {"logging": {"redactSensitive": "off"}})


def test_disk_subagent_disclosure_names_the_modern_key():
    """B18's disk-grounded disclosure (`_disk_subagent_disclosure`) fires only when the
    state DB's `subagent_runs` table has rows the config does not explain -- unreachable
    from a plain config sample, so `_CONFIGS` cannot exercise it. Pin it directly instead
    of faking a state DB: this is the B18 fix string the B-700 reopen named as a live
    offender (unqualified `agents.list` in `_agents.py`'s B18 fix)."""
    cfg = {}
    ctx = Context(home=Path("/nonexistent"), config=cfg)
    ctx.installed_dist_version = _MODERN
    ctx.subagent_runs_found = True
    ctx.subagent_runs = [{
        "child_session_key": "abc123",
        "model": "gpt-x",
        "agent_dir": "/tmp/agent",
        "workspace_dir": "/tmp/ws",
        "spawn_mode": "detached",
        "outcome": None,
    }]
    finding = _disk_subagent_disclosure(ctx)
    assert finding is not None, "the disclosure did not fire -- test setup is wrong"
    offenders = _offending([finding], cfg)
    assert not offenders, offenders


# ---------------------------------------------------------------- local-only layer

def _dist_root() -> "Path | None":
    import shutil
    exe = shutil.which("openclaw")
    if not exe:
        return None
    # `which` gives a bin shim that resolves INTO the package (…/openclaw/openclaw.mjs),
    # so walk up from the resolved entry point rather than from the shim's directory.
    here = Path(os.path.realpath(exe)).parent
    for candidate in (here, *here.parents):
        if (candidate / "dist").is_dir() and (candidate / "package.json").is_file():
            return candidate
    return None


@pytest.mark.skipif(_dist_root() is None, reason="no installed OpenClaw dist")
def test_the_retired_table_matches_the_installed_dist():
    """The table is ours; this asks OpenClaw. Without it the table rots exactly the way
    the advice it guards did — an in-source list nobody re-grounds."""
    root = _dist_root()
    script = """
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
    schema = next(iter((root / "dist").glob("zod-schema-*.js")), None)
    if schema is None:
        pytest.skip("no root zod schema bundle in the installed dist")
    cases = {k: ("array" if k.endswith(("list", "Commands")) else "bool")
             for k in RETIRED_IN_2026_8_1}
    # Arguments go through the environment, not argv: `node -e` does not lay out extra
    # argv the way a script file does, and the first version of this silently handed the
    # JSON to `import()` and skipped itself with a module-not-found message.
    env = dict(os.environ, OC_SCHEMA=str(schema), OC_CASES=json.dumps(cases))
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        capture_output=True, text=True, timeout=120, env=env)
    if proc.returncode != 0:
        pytest.skip(f"could not execute the dist schema: {proc.stderr.strip()[:200]}")
    accepted = json.loads(proc.stdout)
    still_valid = sorted(k for k, ok in accepted.items() if ok)
    assert not still_valid, (
        "these keys are listed as retired but the installed OpenClaw still accepts "
        f"them: {still_valid}. Either the table is wrong, or this machine is on a build "
        "older than 2026.8.1 — check `openclaw --version` before editing the table."
    )


# ---------------------------------------------------- the regression the gate caught

@pytest.mark.parametrize("installed", [_MODERN, _LEGACY, None],
                         ids=["modern", "legacy", "unknown"])
def test_b9_still_distinguishes_off_from_tools(installed):
    """A present `logging.redactSensitive` keeps its own verdict on EVERY build.

    The first version of the B-700 fix collapsed "off" and "tools" into one WARN on a
    modern build, reasoning that an unrecognized key is not in effect anyway.
    `scripts/monitor_detection_gate.py` caught it: `redaction-off: expected an alert, got
    silence` — a watch cannot see a change between two states that render identically, so
    a user turning redaction off stopped raising an alert.

    That gate is a ~20-minute manual step. This is the always-on pin for the same fact.
    """
    off = next(f for f in _findings({"logging": {"redactSensitive": "off"}}, installed)
               if f.id == "B9")
    tools = next(f for f in _findings({"logging": {"redactSensitive": "tools"}}, installed)
                 if f.id == "B9")
    assert off.status != tools.status, (
        f"B9 renders 'off' and 'tools' identically on {installed!r} — a monitor cannot "
        "alert on a change it cannot see"
    )
    assert off.status == "FAIL"
    assert tools.status == "PASS"


def test_b9_absent_is_the_only_thing_that_changed_on_a_modern_build():
    """The scope of the fix, asserted rather than described: absent moves, present does not."""
    modern = {f.id: f.status for f in _findings({}, _MODERN)}
    legacy = {f.id: f.status for f in _findings({}, _LEGACY)}
    assert modern["B9"] == "PASS" and legacy["B9"] == "WARN"
    for value in ("off", "tools"):
        cfg = {"logging": {"redactSensitive": value}}
        a = next(f for f in _findings(cfg, _MODERN) if f.id == "B9").status
        b = next(f for f in _findings(cfg, _LEGACY) if f.id == "B9").status
        assert a == b, f"a present {value!r} must render the same verdict on both builds"


# ---------------------------------------------------------------------------------------
# B-714: the same sweep, over risk.py's advice — the surface it did not cover
#
# `_offending` above walks `Finding.detail` / `Finding.fix`. RiskPath advice never becomes a
# Finding, so RISK-15's `fix=` string named `browser.ssrfPolicy.hostnameAllowlist` for as long
# as it existed and every guard in this file stayed green.
#
# Why that one mattered and RISK-25's equally stale `marketplaces.feeds` did not: RISK-15's own
# trigger key (`browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`) is still accepted by the
# 2026.9.1 schema, so the rule FIRES on a modern build and hands the reader a key that build
# rejects. RISK-25 fires on `marketplaces.feeds`, which the same schema rejects outright — a
# modern reader cannot have it, so the rule cannot reach them. Reachability is what separates a
# live harmful advice string from a dormant one, and it is why this sweep runs the real engine
# on configs chosen to FIRE each rule rather than reading the source.

# Measured 2026-09-04 by EXECUTING the installed 2026.9.1 root schema's `safeParse`, each with
# a bogus-key control at the same parent (an ACCEPTED probe alone proves nothing — a passthrough
# parent accepts junk). Kept SEPARATE from RETIRED_IN_2026_8_1 on purpose: that table's contract
# is "verified against BOTH installed schemas", and only 2026.9.1 was available here. Claiming
# an 8.1 measurement that was never taken is the defect this whole file exists to catch.
#
#   browser.ssrfPolicy.hostnameAllowlist  -> REJECTED  unrecognized_keys@browser.ssrfPolicy
#   browser.ssrfPolicy.zzzBogusControl    -> REJECTED  unrecognized_keys@browser.ssrfPolicy
#   browser.ssrfPolicy.allowedHostnames   -> ACCEPTED
REJECTED_BY_2026_9_1 = {
    "browser.ssrfPolicy.hostnameAllowlist": "browser.ssrfPolicy.allowedHostnames",
}

# Configs chosen to FIRE a risk rule, not merely to parse. A sweep over rules that never
# trigger reports nothing and looks green.
_RISK_CONFIGS = [
    ("ssrf-untrusted-context", {
        "channels": {"telegram": {"enabled": True, "contextVisibility": "all",
                                   "dmPolicy": "open"}},
        "browser": {"ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}},
    }),
    ("trifecta-open", {
        "channels": {"telegram": {"enabled": True, "dmPolicy": "open"}},
        "tools": {"profile": "full", "exec": {"security": "full"}},
        "gateway": {"bind": "0.0.0.0:8080", "auth": {"mode": "none"},
                     "tools": {"allow": ["exec", "fs_read", "fs_write", "email_send"]}},
    }),
]


def _risk_paths(cfg: dict, installed):
    from clawseccheck.risk import risk_paths
    home = Path(tempfile.mkdtemp(prefix="b714-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg))
    os.chmod(path, 0o600)
    ctx = collect(str(home))
    ctx.installed_dist_version = installed
    return ctx, risk_paths(ctx, C.run_all(ctx))


def _offending_risk(paths, cfg):
    """`_offending`, over RiskPath advice instead of Finding advice."""
    out = []
    table = dict(RETIRED_IN_2026_8_1)
    table.update(REJECTED_BY_2026_9_1)
    for p in paths:
        for field in ("why", "fix"):
            text = getattr(p, field, None)
            if not isinstance(text, str):
                continue
            for key in table:
                if not _names_key(text, key):
                    continue
                if any(q in text for q in _QUALIFIERS):
                    continue
                if _config_has(cfg, key):
                    continue
                out.append(f"{p.id}.{field}: {key}")
    return out


@pytest.mark.parametrize("label,cfg", _RISK_CONFIGS, ids=[n for n, _c in _RISK_CONFIGS])
def test_no_risk_advice_names_a_key_a_modern_build_rejects(label, cfg):
    _ctx, paths = _risk_paths(cfg, _MODERN)
    assert paths, "no risk path fired — the sweep would be vacuous"
    offenders = _offending_risk(paths, cfg)
    assert not offenders, (
        "a RiskPath names a key OpenClaw 2026.8.1+ rejects, unqualified:\n  "
        + "\n  ".join(offenders)
        + "\n\nRoute it through checks/_shared.py::_key_advice, as RISK-15 does."
    )


@pytest.mark.parametrize("label,cfg", _RISK_CONFIGS, ids=[n for n, _c in _RISK_CONFIGS])
def test_a_legacy_build_still_gets_the_risk_key_it_has(label, cfg):
    """The mirror image. Telling a 2026.7.x reader to write `allowedHostnames` is the same
    defect pointing the other way, and `_key_advice` is what prevents both."""
    _ctx, paths = _risk_paths(cfg, _LEGACY)
    blob = " ".join(f"{p.why} {p.fix}" for p in paths)
    for legacy, modern in REJECTED_BY_2026_9_1.items():
        if modern in blob:
            assert legacy in blob or any(q in blob for q in _QUALIFIERS), (
                f"a legacy build was told to write {modern}, which its schema does not have"
            )


def test_risk15_resolves_the_ssrf_key_against_the_readers_build():
    """The specific defect, pinned in all three directions rather than just the fixed one."""
    cfg = dict(_RISK_CONFIGS[0][1])
    seen = {}
    for label, ver in (("modern", _MODERN), ("legacy", _LEGACY), ("unknown", None)):
        _ctx, paths = _risk_paths(cfg, ver)
        r15 = next((p for p in paths if p.id == "RISK-15"), None)
        assert r15 is not None, f"RISK-15 did not fire on the {label} build"
        seen[label] = r15.fix
    assert "allowedHostnames" in seen["modern"] and "hostnameAllowlist" not in seen["modern"]
    assert "hostnameAllowlist" in seen["legacy"]
    assert "allowedHostnames" in seen["unknown"] and "hostnameAllowlist" in seen["unknown"]
    assert "2026.8.1" in seen["unknown"]


def test_the_risk_sweep_bites_on_the_string_it_replaced():
    """Positive control. Without it, both sweeps above pass against a matcher that finds
    nothing — which is exactly the state this file was in before B-714."""
    class FakePath:
        id = "RISK-FAKE"
        why = ""
        fix = ("set browser.ssrfPolicy.dangerouslyAllowPrivateNetwork to false with an "
               "explicit browser.ssrfPolicy.hostnameAllowlist")
    assert _offending_risk([FakePath()], {}), (
        "the risk sweep cannot detect the very string B-714 was filed for"
    )
