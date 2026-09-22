"""B353 (F-185) — an MCP server set to pre-approve every tool it exposes.

``mcp.servers.<name>.codex.defaultToolsApprovalMode`` takes "auto" | "prompt" | "approve",
and **"approve" means pre-approved**: `requiresMcpCodexToolApproval` returns false for every
tool on that server before any annotation is consulted. The consumer is unattended
execution — a scheduled run drops every MCP tool that would need approval, so this keeps all
of them. The value's name reads like the safe one and is the dangerous one.

Three shapes the task's own description asked for are deliberately NOT read, because the
schema and the consumer disproved them; each has a test below so nobody re-adds them.
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from _distgrounding import dist_files

import clawseccheck.checks as C
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

MODERN = "2026.8.1"
LEGACY = "2026.7.1-2"


def _finding(cfg, installed=MODERN):
    home = Path(tempfile.mkdtemp(prefix="b353-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    ctx.installed_dist_version = installed
    return next(f for f in C.run_all(ctx) if f.id == "B353")


def _server(**kw):
    return {"mcp": {"servers": {"ops": dict({"command": "c"}, **kw)}}}


# ======================================================================================
# 1. The verdict
# ======================================================================================

def test_approve_is_reported():
    f = _finding(_server(codex={"defaultToolsApprovalMode": "approve"}))
    assert f.status == WARN
    detail = f.detail or ""
    assert "pre-approve every tool" in detail
    assert "does not mean" in detail, "the name inversion is the whole point of the finding"


@pytest.mark.parametrize("codex", [
    {"defaultToolsApprovalMode": "prompt"},
    {"defaultToolsApprovalMode": "auto"},
    {},
    None,
], ids=["prompt", "auto", "empty-codex", "no-codex"])
def test_every_other_setting_is_clean(codex):
    """Three separate controls, not one. Without them "always WARN" satisfies the test
    above, and `auto` in particular must stay clean — it is the default, and reporting the
    default would make this fire on every server anyone has."""
    kw = {} if codex is None else {"codex": codex}
    assert _finding(_server(**kw)).status == PASS


def test_no_mcp_servers_is_unknown():
    assert _finding({}).status == UNKNOWN


def test_a_disabled_server_is_not_reported():
    """`bundle-mcp-config-*.js` filters on `server.enabled !== false`, so a disabled server
    never reaches the runtime and its approval mode cannot apply. The same reachability
    lesson B-706's C-135 rounds taught, applied here from the start rather than after."""
    assert _finding(_server(enabled=False,
                            codex={"defaultToolsApprovalMode": "approve"})).status == PASS
    # The control: the same server, enabled.
    assert _finding(_server(enabled=True,
                            codex={"defaultToolsApprovalMode": "approve"})).status == WARN


# ======================================================================================
# 2. The loopback pair — the discriminator, and the false positive this check invites
# ======================================================================================

def test_openclaws_own_loopback_server_is_not_an_operator_mistake():
    """OpenClaw implicitly pre-approves its OWN loopback MCP server, so reporting it would
    report the vendor's default as the user's error — the false positive this check was
    always going to have if the exemption were skipped."""
    cfg = {"mcp": {"servers": {"openclaw": {
        "url": "http://127.0.0.1:8080/mcp",
        "codex": {"defaultToolsApprovalMode": "approve"}}}}}
    assert _finding(cfg).status == PASS


@pytest.mark.parametrize("url", [
    "https://evil.example/mcp",
    "http://10.0.0.5:8080/mcp",
    "http://127.0.0.1:8080/mcp/extra",
    "http://127.0.0.1/mcp",
], ids=["remote-host", "lan-host", "trailing-path", "no-port"])
def test_a_server_merely_NAMED_openclaw_gets_no_exemption(url):
    """The half that makes the exemption safe, and the one that would be cheapest to get
    wrong: the exemption is the vendor's own server, not the vendor's own NAME. Without
    this pair the loopback carve-out is a hole a hostile server walks through by choosing
    its name."""
    cfg = {"mcp": {"servers": {"openclaw": {
        "url": url, "codex": {"defaultToolsApprovalMode": "approve"}}}}}
    assert _finding(cfg).status == WARN


# ======================================================================================
# 3. What the schema disproved — the three shapes NOT read, each pinned
# ======================================================================================

def test_a_nodehost_server_is_not_reported():
    """`nodeHost.mcp.servers.<name>.codex` PARSES, and the task's description said to read
    it. The consumer disproves that: the bundle-MCP path that reaches the approval
    predicate reads `normalizeConfiguredMcpServers(params.cfg?.mcp?.servers)` and nothing
    else, so a nodeHost server's codex block never gets there. Reporting it would be a
    finding about an inert key."""
    cfg = {"nodeHost": {"mcp": {"servers": {"ops": {
        "command": "c", "codex": {"defaultToolsApprovalMode": "approve"}}}}}}
    assert _finding(cfg).status == UNKNOWN, "no mcp.servers at all — nothing to inspect"


def test_the_retired_snake_case_spelling_is_not_reported():
    """The runtime still reads `default_tools_approval_mode` as a fallback, so it is
    tempting to report it. But 2026.8.1's schema REJECTS the key, so a config carrying it
    does not load at all — it is a broken config, not a dangerous one, and that is a
    different check's subject."""
    assert _finding(_server(codex={"default_tools_approval_mode": "approve"})).status == PASS


def test_the_legacy_top_level_shape_is_not_reported():
    """`mcpServers` at the top level is rejected by the 2026.8.1 schema. This check reads
    `mcp.servers` directly rather than the merged `_mcp_servers()` helper, because that
    helper unions shapes whose codex block this build never consults."""
    cfg = {"mcpServers": {"ops": {"command": "c",
                                  "codex": {"defaultToolsApprovalMode": "approve"}}}}
    assert _finding(cfg).status == UNKNOWN


@pytest.mark.skipif(shutil.which("node") is None, reason="no node on this machine")
def test_the_three_exclusions_are_what_the_schema_actually_says():
    """The exclusions above rest on measured schema behaviour, so measure it — including a
    BOGUS-KEY CONTROL, because an ACCEPTED result on a passthrough object proves nothing
    (the upgrade protocol's own rule, learned from `gateway.tls`).

    This test exists because the first version of this grounding was never run: the probe
    named a dist module that does not exist, and the plausible-looking table it appeared to
    produce went straight into the check's docstring. The conclusions turned out to be
    right, which is luck, not method.
    """
    # B-728: zero matches with the dist INSTALLED is a renamed bundle, not a missing
    # install — `dist_files` fails and names the symbol instead of standing down.
    hits = dist_files("zod-schema-*.js", symbol="OpenClawSchema")
    script = """
const z = await import(process.argv[2]);
const P = Object.values(z).find(v => v && typeof v.safeParse === "function"
                             && v.safeParse({mcp:{servers:{s:{command:"c"}}}}).success);
if (!P) { console.log(JSON.stringify({usable:false})); process.exit(0); }
const ok = (cfg) => P.safeParse(cfg).success;
console.log(JSON.stringify({
  usable: true,
  subject:   ok({mcp:{servers:{s:{command:"c",codex:{defaultToolsApprovalMode:"approve"}}}}}),
  bogus:     ok({mcp:{servers:{s:{command:"c",codex:{zzzBogusKey123:"x"}}}}}),
  snake:     ok({mcp:{servers:{s:{command:"c",codex:{default_tools_approval_mode:"approve"}}}}}),
  outOfEnum: ok({mcp:{servers:{s:{command:"c",codex:{defaultToolsApprovalMode:"zzz"}}}}}),
  legacyTop: ok({mcpServers:{s:{command:"c"}}}),
}));
"""
    work = Path(tempfile.mkdtemp(prefix="b353-schema-"))
    (work / "p.mjs").write_text(script, encoding="utf-8")
    found = None
    for candidate in hits:
        proc = subprocess.run(["node", str(work / "p.mjs"), str(candidate)],
                              capture_output=True, text=True, timeout=120)
        if proc.returncode == 0 and proc.stdout.strip():
            payload = json.loads(proc.stdout)
            if payload.get("usable"):
                found = payload
                break
    # B-728, the same defect one level in: this used to skip, so a dist that stopped
    # EXPORTING a parseable schema object turned the probe off silently and the three
    # exclusions below went back to resting on the unrun first version this test exists to
    # replace. 2026.9.1 builds the schema in a factory (`buildConfigSchemaCore`) rather
    # than exporting it ready-made, so the shape this probe depends on is exactly the kind
    # that moves. If it moves, say so.
    assert found is not None, (
        f"none of {[h.name for h in hits]} exports an object whose safeParse accepts a "
        "minimal mcp config — the schema is no longer reachable the way this probe "
        "assumes (2026.9.1 already moved it behind `buildConfigSchemaCore`). Re-ground "
        "the probe; a skip here would leave the three exclusions below ungrounded while "
        "reading as verified."
    )

    assert found["subject"] is True, "the key this check reads must be a real schema key"
    assert found["bogus"] is False, (
        "the parent accepts unknown keys, so ACCEPTED proves nothing here — this control "
        "is what makes the line above evidence rather than a passthrough")
    assert found["outOfEnum"] is False, "the value must be a real enum member"
    assert found["snake"] is False, "a config with the retired spelling does not load"
    assert found["legacyTop"] is False, "the legacy top-level shape does not load either"


# ======================================================================================
# 4. Fixtures, and the reach caveat the finding must carry
# ======================================================================================

def test_the_bad_fixture_fires_and_the_clean_one_does_not():
    for name, expected in (("bad_b353_mcp_preapproved_tools", WARN),
                           ("clean_b353_mcp_approval_prompt", PASS)):
        ctx = collect(FIXTURES / name)
        ctx.installed_dist_version = MODERN
        assert next(f for f in C.run_all(ctx) if f.id == "B353").status == expected, name


def test_the_finding_says_what_this_audit_cannot_determine():
    """The mechanism is on the Codex app-server path only — OpenClaw's own schema calls the
    block "projection metadata for Codex app-server threads only" — and this audit does not
    yet determine whether any configured agent runs that harness (B-708). Asserting a live
    grant regardless is exactly the defect C-135 found in B333's first version, so the
    condition is named here from the start."""
    f = _finding(_server(codex={"defaultToolsApprovalMode": "approve"}))
    assert "does not determine" in (f.detail or "")
    assert "inert" in (f.fix or ""), "the fix must say when it would change nothing"


def test_the_fix_recommends_only_values_the_schema_accepts():
    """A wrong recommended VALUE fails silently: a bad enum member in a config is rejected
    at load, so the user's setup breaks instead of hardening. Both recommended options are
    real enum members, and the dangerous one is never recommended."""
    fix = _finding(_server(codex={"defaultToolsApprovalMode": "approve"})).fix or ""
    assert '"prompt"' in fix
    assert '"auto"' in fix
    assert 'to "approve"' not in fix


@pytest.mark.parametrize("installed", [MODERN, LEGACY, None], ids=["modern", "legacy", "unknown"])
def test_the_verdict_does_not_depend_on_the_generation(installed):
    """Deliberately NOT version-split, unlike the six checks the 2026.8.1 upgrade did split.
    The path is in both builds' schemas, and the value means the same thing in both; the
    reach caveat this finding carries is about the HARNESS, not the build. Asserted so
    nobody adds a split by analogy with its neighbours."""
    assert _finding(_server(codex={"defaultToolsApprovalMode": "approve"}),
                    installed).status == WARN


# ======================================================================================
# 5. What the C-135 adversarial pass found
# ======================================================================================

def test_a_per_requester_oauth_server_is_not_reported():
    """C-135, major. `partitionMcpServersByConnectionScope` splits configured servers into
    `staticServers` and `requesterScopedServerNames`, and `codex-mcp-config-*.js` builds the
    Codex MCP config from the STATIC half only. A per-requester OAuth server is never in it,
    so its codex block — approval mode included — never reaches the approval predicate.
    """
    cfg = {"mcp": {"servers": {"teamdocs": {
        "url": "https://docs.example/mcp", "auth": "oauth",
        "oauth": {"identity": "per-requester"},
        "codex": {"defaultToolsApprovalMode": "approve"}}}}}
    assert _finding(cfg).status == PASS


@pytest.mark.parametrize("spec_extra", [
    {"auth": "oauth", "oauth": {"identity": "shared"}},
    {"auth": "oauth", "oauth": {}},
    {"oauth": {"identity": "per-requester"}},          # identity WITHOUT auth=oauth
    {"auth": "none", "oauth": {"identity": "per-requester"}},
], ids=["shared", "no-identity", "identity-without-oauth-auth", "auth-none"])
def test_only_the_real_per_requester_shape_is_excluded(spec_extra):
    """The exclusion needs BOTH `auth: "oauth"` AND `identity: "per-requester"` — measured,
    not read. `identity` alone leaves the server STATIC, so excluding on it would be the
    mirror-image false negative:

        auth=oauth  identity=per-requester -> static=false
        NO auth     identity=per-requester -> static=true      <- this row
    """
    cfg = {"mcp": {"servers": {"s": dict(
        {"url": "u", "codex": {"defaultToolsApprovalMode": "approve"}}, **spec_extra)}}}
    assert _finding(cfg).status == WARN


@pytest.mark.parametrize("extra", [
    {"enabled": False},
    {"auth": "oauth", "oauth": {"identity": "per-requester"}},
], ids=["disabled", "per-requester"])
def test_the_pass_text_does_not_enumerate_reasons_it_cannot_cover(extra):
    """C-135, and a repeat of a defect fixed in B333 hours earlier: the PASS sentence listed
    three ways a config could reach it ("unset, prompt, or the loopback server") and a
    server that is disabled — or per-requester — reaches it and is none of the three. One
    verifier found four such shapes.

    An enumeration inside a verdict is a completeness promise. This sentence states the
    property and declines to enumerate, and says why.
    """
    cfg = {"mcp": {"servers": {"s": dict(
        {"command": "c", "codex": {"defaultToolsApprovalMode": "approve"}}, **extra)}}}
    f = _finding(cfg)
    assert f.status == PASS
    detail = f.detail or ""
    assert "either leaves the approval mode unset" not in detail
    assert "not enumerated here" in detail


# ======================================================================================
# 6. B-831 — the Codex plugin's OWN appServer posture pre-approves un-moded servers
# ======================================================================================
#
# A second, independent mechanism to the same effect as this check's explicit-"approve"
# branch above: no server says "approve", but `plugins.entries.codex.config.appServer`'s
# OWN posture (approvalPolicy="never" + sandbox="danger-full-access", the implicit
# default) pre-approves every server that says NOTHING. Grounded against the installed
# `@openclaw/codex@2026.9.5` plugin bundle (docs/research/openclaw-schema-recon.md §44) —
# a separate npm package from `openclaw` core.

def _codex_cfg(appserver=None, plugin_extra=None, servers=None):
    cfg = {"mcp": {"servers": servers if servers is not None else {
        "ops-mcp": {"command": "c"},
    }}}
    if appserver is not None or plugin_extra is not None:
        entry = dict({"enabled": True}, **(plugin_extra or {}))
        if appserver is not None:
            entry = dict(entry, config=dict(entry.get("config", {}), appServer=appserver))
        cfg["plugins"] = {"entries": {"codex": entry}}
    return cfg


def test_no_codex_plugin_is_unaffected():
    """No `plugins.entries.codex` at all — the appServer mechanism cannot fire, and the
    un-moded server (no codex block of its own either) is reported exactly as it always
    was: PASS, generic wording."""
    f = _finding(_codex_cfg())
    assert f.status == PASS
    assert "not enumerated here" in (f.detail or "")


def test_a_disabled_codex_plugin_is_unaffected():
    assert _finding(_codex_cfg(appserver={"mode": "yolo"},
                               plugin_extra={"enabled": False})).status == PASS


def test_explicit_yolo_mode_fires_without_needing_the_system_default_hedge():
    """`mode: "yolo"` is an EXPLICIT operator choice — `resolveDefaultCodexAppServerPolicy`
    (the local-system-requirements-file reader) is never even called for it, so this is a
    definite "yes", not "unknown"."""
    f = _finding(_codex_cfg(appserver={"mode": "yolo"}))
    assert f.status == WARN
    detail = f.detail or ""
    assert "pre-approves every tool on every MCP server" in detail
    assert "ops-mcp" in detail
    assert "local Codex system requirements file" not in detail


def test_explicit_approval_and_sandbox_fire_even_with_mode_unset():
    """Both leaf fields explicit and unsafe, `mode` never mentioned at all: the explicit
    fields win over whatever the (unread) local system requirements file would have said,
    so this is also a definite "yes"."""
    f = _finding(_codex_cfg(appserver={"approvalPolicy": "never",
                                       "sandbox": "danger-full-access"}))
    assert f.status == WARN
    assert "local Codex system requirements file" not in (f.detail or "")


def test_a_nonstdio_transport_skips_the_system_default_read_too():
    """`resolveDefaultCodexAppServerPolicy` returns "yolo" unconditionally for a
    non-"stdio" transport — no local file read at all — so this needs no hedge even
    though nothing else is set explicitly."""
    f = _finding(_codex_cfg(appserver={"transport": "websocket"}))
    assert f.status == WARN
    assert "local Codex system requirements file" not in (f.detail or "")


def test_the_pure_implicit_default_is_unknown_not_yes():
    """Nothing set at all (mode/approvalPolicy/sandbox all unset, default "stdio"
    transport): the implicit YOLO default applies UNLESS a local Codex system
    requirements file silently withholds it, which this audit cannot read."""
    f = _finding(_codex_cfg(appserver={}))
    assert f.status == WARN
    assert "local Codex system requirements file" in (f.detail or "")


@pytest.mark.parametrize("appserver", [
    {"mode": "guardian"},
    {"approvalPolicy": "on-request"},
    {"sandbox": "workspace-write"},
    {"networkProxy": {"enabled": True}},
], ids=["guardian-mode", "safe-approval", "safe-sandbox", "network-proxy"])
def test_a_safe_posture_never_fires(appserver):
    """Any one of these keeps the config away from the YOLO waiver -- a safe value on
    either axis (explicit, or guardian's own default), or an active network proxy.
    Vendor eval: guardian alone resolves on-request/workspace-write, network proxy
    attaches `networkProxy`; auto=false both.

    Round 1 also listed an explicit non-"user" reviewer here. That was wrong: whether it
    changes anything depends on the model, so it is "unknown", not "no" -- see
    `test_d6iv_a_model_backed_reviewer_is_unknown_not_no`."""
    assert _finding(_codex_cfg(appserver=appserver)).status == PASS


@pytest.mark.parametrize("exec_mode", ["auto", "ask", "deny", "allowlist"])
def test_every_non_full_exec_mode_blocks_it(exec_mode):
    """Not just "auto": `resolveCodexPolicyModeForOpenClawExecMode` forces guardian for
    "ask" exactly like "auto", and "deny"/"allowlist" make the Codex app-server
    unavailable outright. Only unset or "full" preserves the appServer's own posture --
    the naive reading the ticket warned against would have false-WARNed on every one of
    these."""
    cfg = _codex_cfg(appserver={"mode": "yolo"})
    cfg["tools"] = {"exec": {"mode": exec_mode}}
    assert _finding(cfg).status == PASS


def test_exec_mode_full_does_not_block_it():
    cfg = _codex_cfg(appserver={"mode": "yolo"})
    cfg["tools"] = {"exec": {"mode": "full"}}
    assert _finding(cfg).status == WARN


def test_exec_ask_always_blocks_it():
    cfg = _codex_cfg(appserver={"mode": "yolo"})
    cfg["tools"] = {"exec": {"ask": "always"}}
    assert _finding(cfg).status == PASS


def test_a_per_requester_server_IS_exposed_here_unlike_the_explicit_branch():
    """The opposite asymmetry from this check's explicit-"approve" branch above: the
    appServer-level waiver is fed to BOTH the static and the requester-scoped
    materializers, so a per-requester OAuth server that sets NO mode of its own is exposed
    to it. (One that sets its own mode is not -- round 1 claimed no config field could opt
    it out, which was false; see `test_d3_a_per_requester_server_with_its_own_mode_is_
    not_unmoded`.)"""
    cfg = _codex_cfg(appserver={"mode": "yolo"}, servers={"teamdocs": {
        "url": "https://docs.example/mcp", "auth": "oauth",
        "oauth": {"identity": "per-requester"},
    }})
    f = _finding(cfg)
    assert f.status == WARN
    assert "teamdocs" in (f.detail or "")


def test_the_loopback_server_is_still_excluded():
    cfg = _codex_cfg(appserver={"mode": "yolo"}, servers={"openclaw": {
        "url": "http://127.0.0.1:8080/mcp",
    }})
    assert _finding(cfg).status == PASS


def test_an_explicit_per_server_mode_of_any_kind_removes_it_from_the_unmoded_set():
    """A server does not need to say "prompt" specifically -- ANY resolved mode (here,
    the default-shaped "auto") takes it out of the un-moded population, because the
    vendor's own `?? "auto"` chain never consults `fullPermission` once `mode` itself is
    already defined."""
    cfg = _codex_cfg(appserver={"mode": "yolo"}, servers={"ops-mcp": {
        "command": "c", "codex": {"defaultToolsApprovalMode": "auto"},
    }})
    assert _finding(cfg).status == PASS


def test_no_unmoded_servers_at_all_is_still_pass():
    """The appServer posture is YOLO, but every server already has its own explicit mode
    -- nothing is left exposed to THIS mechanism specifically."""
    cfg = _codex_cfg(appserver={"mode": "yolo"}, servers={
        "a": {"command": "c", "codex": {"defaultToolsApprovalMode": "prompt"}},
        "b": {"command": "c", "codex": {"defaultToolsApprovalMode": "auto"}},
    })
    assert _finding(cfg).status == PASS


def test_the_explicit_approve_branch_takes_priority_and_is_unaffected():
    """When a server explicitly says "approve", this check's ORIGINAL branch already
    WARNs correctly -- the new appServer mechanism is not additionally consulted, and the
    wording stays exactly what it was before B-831 existed."""
    cfg = _codex_cfg(appserver={"mode": "guardian"}, servers={
        "ops-mcp": {"command": "c", "codex": {"defaultToolsApprovalMode": "approve"}},
    })
    f = _finding(cfg)
    assert f.status == WARN
    assert "does not mean" in (f.detail or "")


def test_the_bad_appserver_fixture_fires_and_the_clean_one_does_not():
    for name, expected in (("bad_b831_codex_appserver_yolo", WARN),
                           ("clean_b831_codex_appserver_guardian", PASS)):
        ctx = collect(FIXTURES / name)
        ctx.installed_dist_version = MODERN
        assert next(f for f in C.run_all(ctx) if f.id == "B353").status == expected, name


# ======================================================================================
# 7. B-831 round 1 — the appServer fields are RESOLVED before the predicate sees them
# ======================================================================================
#
# One test (or parametrized pair) per defect the targeted review found, each pinned at the
# answer the vendor gives and paired with a control on the other side of the same line.
# "vendor" below is the result of evaluating the installed `@openclaw/codex@2026.9.5`
# resolvers in memory with node (`resolveOpenClawExecPolicyForCodexAppServer` ->
# `resolveCodexAppServerRuntimeOptions` -> `shouldAutoApproveCodexAppServerApprovals`;
# scratch HOME, no gateway, `requirementsToml: null`, model openai/gpt-5.4 unless noted).
# Each test asserts BOTH the finding and the helper's own three-valued answer, because a
# hedged "unknown" still WARNs and the status alone cannot tell it from a "yes".

def _b831(tmp_path, cfg, approvals=None, approvals_raw=None, installed=MODERN):
    path = tmp_path / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    if approvals is not None or approvals_raw is not None:
        store = tmp_path / "exec-approvals.json"
        store.write_text(approvals_raw if approvals_raw is not None else json.dumps(approvals),
                         encoding="utf-8")
        os.chmod(store, 0o600)
    ctx = collect(tmp_path)
    ctx.installed_dist_version = installed
    finding = next(f for f in C.run_all(ctx) if f.id == "B353")
    return finding, C._codex_appserver_yolo_reach(ctx)[0]


def _yolo(**top):
    cfg = _codex_cfg(appserver={"mode": "yolo"})
    cfg.update(top)
    return cfg


# ---- defect 1: tools.exec.security / ask derive the mode when `mode` is absent --------

@pytest.mark.parametrize("exec_block", [
    {"security": "allowlist"},
    {"security": "deny"},
    {"security": "allowlist", "ask": "on-miss"},
    {"ask": "always"},
], ids=["security-allowlist", "security-deny", "allowlist-on-miss", "ask-always"])
def test_d1_exec_security_and_ask_derive_a_non_full_mode(tmp_path, exec_block):
    """vendor: allowlist/deny THROW (`effective tools.exec.mode=allowlist` -- the
    app-server refuses to start); allowlist+on-miss derives "ask" -> on-request /
    workspace-write; ask "always" alone derives "ask" -> untrusted. auto=false in all four.
    Round 1 read only `tools.exec.mode` and WARNed on the first three."""
    f, answer = _b831(tmp_path, _yolo(tools={"exec": exec_block}))
    assert (f.status, answer) == (PASS, "no")


@pytest.mark.parametrize("exec_block", [
    {"security": "full"},
    {"security": "full", "ask": "on-miss"},
], ids=["security-full", "full-on-miss"])
def test_d1_control_a_derivation_that_lands_on_full_keeps_it(tmp_path, exec_block):
    """vendor: both derive "full" -> never / danger-full-access, auto=true. The control
    that stops `test_d1_...` from passing on "any tools.exec.security means no"."""
    f, answer = _b831(tmp_path, _yolo(tools={"exec": exec_block}))
    assert (f.status, answer) == (WARN, "yes")


# ---- defect 2: each roster agent's own tools.exec is layered over the global one -------

@pytest.mark.parametrize("agents", [
    {"entries": {"main": {"tools": {"exec": {"mode": "ask"}}}}},
    {"list": [{"id": "main", "tools": {"exec": {"mode": "ask"}}}]},
], ids=["agents.entries", "legacy-agents.list"])
def test_d2_a_per_agent_exec_mode_is_layered_over_the_global_one(tmp_path, agents):
    """vendor: execMode "ask" for agent main in BOTH roster shapes -> auto=false. Round 1
    read only the global `tools.exec` and WARNed."""
    f, answer = _b831(tmp_path, _yolo(agents=agents))
    assert (f.status, answer) == (PASS, "no")


def test_d2_control_a_per_agent_full_keeps_it(tmp_path):
    """vendor: agent main mode "full" -> auto=true."""
    f, answer = _b831(tmp_path, _yolo(agents={"entries": {
        "main": {"tools": {"exec": {"mode": "full"}}}}}))
    assert (f.status, answer) == (WARN, "yes")


def test_d2_agents_that_disagree_are_unknown_not_no(tmp_path):
    """vendor: as agent main (mode "ask") auto=false, as agent work (nothing set) auto=true.
    Which of them runs the Codex harness is not something this audit decides, so the
    honest answer is "unknown" -- and the finding says why."""
    f, answer = _b831(tmp_path, _yolo(agents={"entries": {
        "main": {"tools": {"exec": {"mode": "ask"}}}, "work": {}}}))
    assert (f.status, answer) == (WARN, "unknown")
    assert "differs between agents" in (f.detail or "")


# ---- defect 3: a per-requester server with its own mode is not "un-moded" --------------

_PER_REQUESTER = {"url": "https://docs.example/mcp", "auth": "oauth",
                  "oauth": {"identity": "per-requester"}}


def test_d3_a_per_requester_server_with_its_own_mode_is_not_unmoded(tmp_path):
    """The runtime catalog sets `codexApprovalMode` from the raw server for requester-
    scoped runtimes too (`agent-bundle-mcp-runtime.js:564`), so "prompt" still prompts and
    `fullPermission` is never consulted. Round 1 named this server as one "that sets no
    approval mode of its own" -- a finding that contradicted itself. Control: the same
    server with no mode IS exposed."""
    moded = dict(_PER_REQUESTER, codex={"defaultToolsApprovalMode": "prompt"})
    assert C._codex_unmoded_server_names({"teamdocs": moded}) == []
    assert C._codex_unmoded_server_names({"teamdocs": dict(_PER_REQUESTER)}) == ["teamdocs"]
    f, _ = _b831(tmp_path, _codex_cfg(appserver={"mode": "yolo"},
                                      servers={"teamdocs": moded}))
    assert f.status == PASS
    assert "teamdocs" not in (f.detail or "")


# ---- defect 4: plugin activation (plugins.enabled / deny / allow) ----------------------

@pytest.mark.parametrize("plugins_top", [
    {"enabled": False},
    {"deny": ["codex"]},
    {"allow": ["telegram"]},
], ids=["plugins-disabled", "denied", "not-in-allowlist"])
def test_d4_a_deactivated_codex_plugin_is_no(tmp_path, plugins_top):
    """`resolvePluginActivationDecisionShared` deactivates the plugin in all three. The
    gate is the one B-421 already grounded for memory-core, now shared
    (`_plugin_activation_blocked`) rather than re-implemented."""
    cfg = _yolo()
    cfg["plugins"].update(plugins_top)
    f, answer = _b831(tmp_path, cfg)
    assert (f.status, answer) == (PASS, "no")


@pytest.mark.parametrize("plugins_top", [
    {"enabled": True},
    {"deny": ["telegram"]},
    {"allow": ["codex", "telegram"]},
], ids=["plugins-enabled", "other-denied", "in-allowlist"])
def test_d4_control_an_activated_codex_plugin_still_fires(tmp_path, plugins_top):
    cfg = _yolo()
    cfg["plugins"].update(plugins_top)
    f, answer = _b831(tmp_path, cfg)
    assert (f.status, answer) == (WARN, "yes")


def test_d4_the_shared_gate_answers_memory_core_exactly_as_before():
    """The memory-core caller keeps its old boolean contract on the same four legs."""
    assert C._memory_default_owner_blocked({"allow": ["trentclaw"]}) is True
    assert C._memory_default_owner_blocked({"deny": [" memory-core "]}) is True
    assert C._memory_default_owner_blocked({"entries": {"memory-core": {"enabled": False}}})
    assert C._memory_default_owner_blocked({"allow": ["memory-core"]}) is False
    assert C._memory_default_owner_blocked({}) is False


# ---- defect 5: an exec-approvals floor can only tighten, so it hedges a "yes" ----------

@pytest.mark.parametrize("approvals", [
    {"version": 1, "defaults": {"security": "allowlist", "ask": "on-miss"}},
    {"version": 1, "agents": {"main": {"security": "allowlist"}}},
], ids=["defaults-floor", "agent-floor"])
def test_d5_an_exec_approvals_floor_hedges_a_yes(tmp_path, approvals):
    """vendor: defaults floor -> execMode "ask", auto=false; agent floor -> effective mode
    allowlist, THROWS. The floor is hedged, not modelled: newer builds keep the live store
    in their state database, which is not read, so the legacy file cannot settle a "no"."""
    f, answer = _b831(tmp_path, _yolo(), approvals=approvals)
    assert (f.status, answer) == (WARN, "unknown")
    assert "exec-approvals.json" in (f.detail or "")


@pytest.mark.parametrize("approvals", [
    {"version": 1, "defaults": {"security": "full", "ask": "off"}},
    {"version": 1, "defaults": {}, "agents": {}},
], ids=["neutral-defaults", "empty-store"])
def test_d5_control_a_store_with_no_tightening_floor_leaves_yes(tmp_path, approvals):
    """vendor: both auto=true (`minSecurity(x, "full")` / `maxAsk(x, "off")` are x)."""
    f, answer = _b831(tmp_path, _yolo(), approvals=approvals)
    assert (f.status, answer) == (WARN, "yes")


def test_d5_the_collector_reads_the_store_defaults(tmp_path):
    (tmp_path / "exec-approvals.json").write_text(json.dumps(
        {"version": 1, "defaults": {"security": "allowlist", "ask": 3}}), encoding="utf-8")
    ctx = collect(tmp_path)
    assert ctx.exec_approvals_defaults == {"security": "allowlist", "ask": None}


def test_d5_an_unreadable_store_hedges_too(tmp_path):
    f, answer = _b831(tmp_path, _yolo(), approvals_raw="{not json")
    assert (f.status, answer) == (WARN, "unknown")


# ---- defect 6: the four shapes round 1 folded into an asserted PASS ---------------------

def test_d6i_a_per_agent_full_over_a_global_ask_is_live(tmp_path):
    """vendor: global "ask" + agent main "full" -> execMode "full", auto=true."""
    f, answer = _b831(tmp_path, _yolo(
        tools={"exec": {"mode": "ask"}},
        agents={"entries": {"main": {"tools": {"exec": {"mode": "full"}}}}}))
    assert (f.status, answer) == (WARN, "yes")


def test_d6ii_mode_wins_over_ask(tmp_path):
    """vendor: `mode: "full"` + `ask: "always"` -> execMode "full" (a valid mode wins and
    the ask beside it is ignored), auto=true. Control: `ask: "always"` ALONE derives "ask"
    and is a PASS -- `test_d1_...[ask-always]`."""
    f, answer = _b831(tmp_path, _yolo(tools={"exec": {"mode": "full", "ask": "always"}}))
    assert (f.status, answer) == (WARN, "yes")


def test_d6iii_guardian_that_explicitly_asks_for_never_and_full_access_is_yes(tmp_path):
    """vendor: guardian + never + danger-full-access + reviewer "user" -> auto=true,
    deterministically (an explicit mode skips the requirements-file default and a "user"
    reviewer forces nothing). Round 1 read every guardian as "no"."""
    f, answer = _b831(tmp_path, _codex_cfg(appserver={
        "mode": "guardian", "approvalPolicy": "never", "sandbox": "danger-full-access",
        "approvalsReviewer": "user"}))
    assert (f.status, answer) == (WARN, "yes")


def test_d6iii_control_the_same_without_a_user_reviewer_depends_on_the_model(tmp_path):
    """vendor: model openai -> reviewer auto_review, auto=TRUE; model anthropic ->
    forced on-request / workspace-write, auto=FALSE. Unknown here."""
    f, answer = _b831(tmp_path, _codex_cfg(appserver={
        "mode": "guardian", "approvalPolicy": "never", "sandbox": "danger-full-access"}))
    assert (f.status, answer) == (WARN, "unknown")


def test_d6iv_a_model_backed_reviewer_is_unknown_not_no(tmp_path):
    """vendor: yolo + approvalsReviewer "auto_review" -> openai auto=TRUE, anthropic
    auto=FALSE (forced on-request). Round 1 read it as "no"."""
    f, answer = _b831(tmp_path, _codex_cfg(appserver={
        "mode": "yolo", "approvalsReviewer": "auto_review"}))
    assert (f.status, answer) == (WARN, "unknown")


def test_d6iv_control_an_explicit_prompting_policy_settles_it(tmp_path):
    """vendor: the same + approvalPolicy "on-request" -> auto=false on any model: an
    explicit field outranks every default, and a forced policy is never "never"."""
    f, answer = _b831(tmp_path, _codex_cfg(appserver={
        "mode": "yolo", "approvalsReviewer": "auto_review", "approvalPolicy": "on-request"}))
    assert (f.status, answer) == (PASS, "no")


# ---- values this audit cannot resolve read "unknown", never "full"/"not full" -----------

def test_an_unresolved_exec_value_is_unknown(tmp_path):
    """An unresolved `${VAR}` could become any mode; round 1's reading treated it as
    unset, i.e. "full"."""
    f, answer = _b831(tmp_path, _yolo(tools={"exec": {"mode": "${EXEC_MODE}"}}))
    assert (f.status, answer) == (WARN, "unknown")


def test_an_unresolved_appserver_value_is_unknown_unless_something_else_settles_it(tmp_path):
    f, answer = _b831(tmp_path, _codex_cfg(appserver={"mode": "${CODEX_MODE}"}))
    assert (f.status, answer) == (WARN, "unknown")
    f, answer = _b831(tmp_path, _codex_cfg(appserver={
        "mode": "${CODEX_MODE}", "approvalPolicy": "on-request"}))
    assert (f.status, answer) == (PASS, "no")


def test_every_appserver_warn_names_the_run_time_inputs_it_cannot_read(tmp_path):
    f, _ = _b831(tmp_path, _yolo())
    detail = f.detail or ""
    assert "OPENCLAW_CODEX_APP_SERVER_" in detail
    assert "state database" in detail
    assert "per-session permission mode" in detail


# ======================================================================================
# 7. B-831 ROUND 2 -- the six minor-fix defects the second targeted review found.
# One test (or parametrized pair) per defect, each pinned at the reviewer's own repro
# config, paired with a control on the other side of the same line, plus a mutation-style
# check where a silent regression would otherwise slip back in unnoticed.
# ======================================================================================

from clawseccheck import harnessruntime as _hr  # noqa: E402

#: The installed-build stamp the harness-reach oracle is validated on (see
#: test_b708_codex_harness_gate.py) -- distinct from this file's own MODERN/LEGACY, which
#: predate the harness-reach window and so always read as "unknown" reach.
_VALIDATED = ".".join(str(x) for x in _hr.ORACLE_MAX)


# ---- items 1 & 2: plugins.allow/deny/entries fold case, like the real activation gate --

def test_b831r2_item1_an_allow_case_variant_still_activates_codex(tmp_path):
    """Reviewer's exact repro: appServer {mode: "yolo"}, an un-moded stdio server,
    plugins.allow=["Codex"] (case variant). The real gate compares through
    normalizePluginPolicyId (trim + lowercase) before the allowlist membership check, so
    "codex" IS in the folded allowlist and the plugin stays activated -> auto=true ->
    "yes". Pre-fix, the plain `.strip()` compare missed this and read "no"."""
    cfg = _yolo()
    cfg["plugins"]["allow"] = ["Codex"]
    f, answer = _b831(tmp_path, cfg)
    assert (f.status, answer) == (WARN, "yes")


def test_b831r2_item1_control_a_real_non_member_allowlist_still_blocks(tmp_path):
    """Control: an allowlist that genuinely omits codex in every case stays a block."""
    cfg = _yolo()
    cfg["plugins"]["allow"] = ["Telegram"]
    f, answer = _b831(tmp_path, cfg)
    assert (f.status, answer) == (PASS, "no")


def test_b831r2_item2_a_deny_case_variant_still_blocks_codex(tmp_path):
    """Reviewer's exact repro: plugins.deny=["Codex"] with codex yolo. The real gate
    lowercases deny too, so "codex" IS in the folded denylist -> blocked -> "no".
    Pre-fix, the plain `.strip()` compare missed this and read "yes" (a false positive:
    WARN on a setup where the plugin cannot actually run)."""
    cfg = _yolo()
    cfg["plugins"]["deny"] = ["Codex"]
    f, answer = _b831(tmp_path, cfg)
    assert (f.status, answer) == (PASS, "no")


def test_b831r2_item2_control_a_real_non_member_denylist_does_not_block(tmp_path):
    cfg = _yolo()
    cfg["plugins"]["deny"] = ["Telegram"]
    f, answer = _b831(tmp_path, cfg)
    assert (f.status, answer) == (WARN, "yes")


def test_b831r2_items1_2_mutation_the_helper_itself_folds_case_on_all_three_legs():
    """Mutation check on `_plugin_activation_blocked` directly: removing the case fold
    (back to a plain `.strip()` compare) would flip every one of these three back to the
    pre-fix (wrong) answer."""
    assert C._plugin_activation_blocked({"allow": ["Codex"]}, "codex") is None
    assert (C._plugin_activation_blocked({"deny": ["Codex"]}, "codex")
            == "plugins.deny lists 'codex'")
    assert (C._plugin_activation_blocked({"entries": {"Codex": {"enabled": False}}}, "codex")
            == "plugins.entries.codex.enabled=false")


def test_b831r2_memory_core_gate_shares_the_same_fold():
    """`_plugin_activation_blocked` is SHARED with the memory-core gate (B342/B421): this
    is not a codex-only change. The B342 suite (test_b341_b342_plugin_advisories.py)
    stays green because none of its existing fixtures use a case-varying deny/allow/
    entries id for the activation gate -- only for the UNRELATED alias-based allow/deny
    CONTRADICTION check, which `_normalize_plugin_id` still handles unchanged."""
    assert C._memory_default_owner_blocked({"deny": ["Memory-Core"]}) is True
    assert C._memory_default_owner_blocked({"allow": ["MEMORY-CORE"]}) is False


# ---- item 3 (reviewed, NOT changed): a mixed roster stays a hedged "unknown" ----------

def test_b831r2_item3_regression_mixed_roster_stays_unknown_not_no(tmp_path):
    """Reviewer's exact repro: tools.exec.mode="ask"; agents.entries.main has an
    anthropic model with its own exec "full"; agents.entries.coder has an openai model
    and no exec override (inherits the global "ask"). Round 2 called the resulting hedge
    defensible -- /model can move an agent onto the Codex harness at run time -- and this
    task explicitly said do NOT change it. This is a pure regression pin."""
    f, answer = _b831(tmp_path, _yolo(
        tools={"exec": {"mode": "ask"}},
        agents={"entries": {
            "main": {"model": "anthropic/claude-x", "tools": {"exec": {"mode": "full"}}},
            "coder": {"model": "openai/gpt-5"},
        }}))
    assert (f.status, answer) == (WARN, "unknown")
    assert "differs between agents" in (f.detail or "")


# ---- item 4: a valid per-agent tools.exec.mode wins over an unresolved global base ----

def test_b831r2_item4_a_valid_agent_mode_wins_over_an_unresolved_base(tmp_path):
    """Reviewer's exact repro: tools.exec={security: "${EXEC_SEC}"} (unresolved) +
    agents.entries.main.tools.exec.mode="ask". The real
    applyOpenClawExecPolicyLayer returns straight from the agent's own valid `mode`
    without ever reading `base` -- execMode "ask" -> auto=false -> "no". Pre-fix, the
    helper checked the unresolved base FIRST and returned "unknown" without even looking
    at the agent's mode."""
    f, answer = _b831(tmp_path, _yolo(
        tools={"exec": {"security": "${EXEC_SEC}"}},
        agents={"entries": {"main": {"tools": {"exec": {"mode": "ask"}}}}}))
    assert (f.status, answer) == (PASS, "no")


def test_b831r2_item4_control_no_agent_override_stays_unresolved(tmp_path):
    """Control: with no per-agent override at all, an unresolved global base still
    propagates as "unknown" -- the fix only lets a VALID agent mode override it, it does
    not make an unresolved base stop mattering on its own."""
    f, answer = _b831(tmp_path, _yolo(tools={"exec": {"security": "${EXEC_SEC}"}}))
    assert (f.status, answer) == (WARN, "unknown")


def test_b831r2_item4_mutation_an_invalid_agent_mode_still_reads_unresolved():
    """Mutation check on `_codex_exec_policy_layer` directly: an agent value that is
    PRESENT but not a real mode must still come out unresolved -- the fix must not
    accidentally treat "any mode key present" as a free pass."""
    assert C._codex_exec_policy_layer("?", {"mode": "not-a-real-mode"}) == "?"
    # "ask" derives (security="allowlist", ask="on-miss") per _CODEX_EXEC_MODE_POLICY.
    assert C._codex_exec_policy_layer("?", {"mode": "ask"}) == (
        "ask", "allowlist", "on-miss", True)


# ---- item 5: no plugins.entries.codex block at all, but a Codex harness is reachable --

def test_b831r2_item5_no_codex_entry_with_a_reachable_harness_is_unknown(tmp_path):
    """Reviewer's exact repro: NO plugins.entries.codex block at all, an openai model
    (harness reach YES), one un-moded stdio server. Absence of the entry does not prove
    the plugin is not installed -- a non-bundled plugin with no entry can still activate
    on the implicit default -- so this must read "unknown", the same as an explicit,
    empty appServer {}, never a confident "no"."""
    cfg = _codex_cfg()  # no "plugins" key at all
    cfg["agents"] = {"defaults": {"model": "openai/gpt-5"}}
    f, answer = _b831(tmp_path, cfg, installed=_VALIDATED)
    assert (f.status, answer) == (WARN, "unknown")


def test_b831r2_item5_control_no_codex_entry_with_no_reachable_harness_stays_no(tmp_path):
    """Control: the same missing entry, but no configured model would ever reach the
    Codex harness -- nothing points to the plugin being in play at all, so "no" remains
    the honest reading."""
    cfg = _codex_cfg()
    cfg["agents"] = {"defaults": {"model": "anthropic/claude-x"}}
    f, answer = _b831(tmp_path, cfg, installed=_VALIDATED)
    assert (f.status, answer) == (PASS, "no")


def test_b831r2_item5_control_an_explicitly_disabled_entry_is_still_a_plain_no(tmp_path):
    """Control: an EXPLICIT plugins.entries.codex.enabled=false is a real, stated fact --
    unlike a missing block, harness reach must not override it back to "unknown"."""
    cfg = _codex_cfg(plugin_extra={"enabled": False})
    cfg["agents"] = {"defaults": {"model": "openai/gpt-5"}}
    f, answer = _b831(tmp_path, cfg, installed=_VALIDATED)
    assert (f.status, answer) == (PASS, "no")


def test_b831r2_item5_mutation_matches_the_explicit_empty_appserver_answer(tmp_path):
    """Mutation-style check: the whole point of the fix is that a missing entry (harness
    reach YES) and an explicit, empty appServer {} must resolve identically."""
    cfg_missing = _codex_cfg()
    cfg_missing["agents"] = {"defaults": {"model": "openai/gpt-5"}}
    cfg_explicit_empty = _codex_cfg(appserver={})
    cfg_explicit_empty["agents"] = {"defaults": {"model": "openai/gpt-5"}}
    home_a, home_b = tmp_path / "a", tmp_path / "b"
    home_a.mkdir()
    home_b.mkdir()
    f1, a1 = _b831(home_a, cfg_missing, installed=_VALIDATED)
    f2, a2 = _b831(home_b, cfg_explicit_empty, installed=_VALIDATED)
    assert (f1.status, a1) == (f2.status, a2) == (WARN, "unknown")


# ---- item 6: the exec-approvals hedge omits fields the record never set --------------

def test_b831r2_item6_hedge_omits_a_field_that_was_never_set(tmp_path):
    """Reviewer's exact repro: exec-approvals.json agents.work={ask: "always"} -- only
    `ask` is actually in the record, so the hedge text must not claim "security=None": a
    field the record never set is not the same thing as a JSON null."""
    f, answer = _b831(tmp_path, _yolo(), approvals={
        "version": 1, "agents": {"work": {"ask": "always"}}})
    assert (f.status, answer) == (WARN, "unknown")
    detail = f.detail or ""
    assert "security=None" not in detail
    assert "security=" not in detail
    assert f"ask={'always'!r}" in detail


def test_b831r2_item6_control_both_fields_set_still_names_both(tmp_path):
    """Control: when the record genuinely sets both fields, both still appear."""
    f, answer = _b831(tmp_path, _yolo(), approvals={
        "version": 1, "agents": {"work": {"security": "allowlist", "ask": "always"}}})
    assert (f.status, answer) == (WARN, "unknown")
    detail = f.detail or ""
    assert f"security={'allowlist'!r}" in detail
    assert f"ask={'always'!r}" in detail


def test_b831r2_item6_mutation_the_floor_helper_itself_omits_unset_fields():
    """Mutation check directly on `_codex_exec_approvals_floor`: a record setting only
    `security` must not mention `ask` either (and vice versa, covered by the repro test
    above)."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.exec_approvals_found = True
    ctx.exec_approvals_defaults = None
    ctx.exec_approvals_grants = [{"agent_id": "work", "security": "allowlist"}]
    reason = C._codex_exec_approvals_floor(ctx)
    assert reason is not None
    assert "ask=" not in reason
    assert f"security={'allowlist'!r}" in reason
