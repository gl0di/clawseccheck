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

import clawseccheck.checks as C
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_DIST = Path("/home/glodi/.npm-global/lib/node_modules/openclaw/dist")

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
    hits = sorted(_DIST.glob("zod-schema-*.js")) if _DIST.is_dir() else []
    if not hits:
        pytest.skip("no installed OpenClaw dist")
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
    if found is None:
        pytest.skip("no usable OpenClawSchema export in the installed dist")

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
