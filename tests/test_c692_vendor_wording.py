"""Wording that rests on a vendor behaviour, pinned against the vendor itself.

B321: an unset or "npx" ``mcpCommand`` is NOT an npx download; the vendor runs the
chrome-devtools-mcp copy bundled in the OpenClaw package (normalizeChromeMcpOptions executed on
openclaw@2026.10.2, 2026-10-12). B391: a config-only audit cannot see the node CLI flags that
force worker hosting. B172: an exec-approvals entry in the pre-2026.10.1 shape is refused by the
current parser. The dist-reading tests skip when node or the dist is absent; the wording tests
are always on.
"""
from __future__ import annotations

import json
from pathlib import Path

from _c692oracle import call_vendor
from _distgrounding import dist_file, require_dist

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_browser_executable_path, check_nodehost_workerruns_isolation
from clawseccheck.collector import collect


def _home(tmp_path: Path, config: dict) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps(config))
    cfg.chmod(0o600)
    return home


# ---- always on ---------------------------------------------------------------------------

def test_b321_warn_evidence_does_not_claim_an_npx_download(tmp_path):
    home = _home(tmp_path, {"browser": {"profiles": {
        "u": {"driver": "existing-session", "mcpCommand": "/opt/pinned-mcp", "color": "#00AA00"}}}})
    f = check_browser_executable_path(collect(home))
    assert f.status == WARN
    text = " ".join(f.evidence)
    assert "npx" not in text and "@latest" not in text
    assert "bundled with OpenClaw" in text


def test_b391_pass_detail_is_hedged_about_node_cli_flags(tmp_path):
    f = check_nodehost_workerruns_isolation(collect(_home(tmp_path, {"nodeHost": {}})))
    assert f.status == PASS
    assert "--session-host" in f.detail and "--ephemeral" in f.detail
    assert "does not enable" in f.detail and "does not host" not in f.detail


# ---- vendor-executed (local-only) --------------------------------------------------------

def test_vendor_treats_unset_and_npx_mcp_command_as_the_bundled_copy():
    require_dist()
    bundle = dist_file("chrome-mcp-options-*.mjs", symbol="normalizeChromeMcpOptions",
                       contains="function normalizeChromeMcpOptions")
    for options in ({}, {"mcpCommand": "npx"}):
        out = call_vendor(bundle, "normalizeChromeMcpOptions", options)
        assert out["command"].endswith("node") or "node" in Path(out["command"]).name
        assert out["args"][0].endswith("chrome-devtools-mcp.js"), out["args"]
        assert "npx" not in json.dumps(out)
    custom = call_vendor(bundle, "normalizeChromeMcpOptions", {"mcpCommand": "/opt/x/mcp"})
    assert custom["command"] == "/opt/x/mcp"


def test_vendor_refuses_each_pre_10_1_exec_approvals_entry_shape():
    require_dist()
    bundle = dist_file("exec-approvals-migration-gate-*.mjs", symbol="parsePersistedExecApprovals",
                       contains="function parsePersistedExecApprovals")
    gid = "3f1c9d5e-8a4b-4c2d-9e61-7b0a5d2c4e18"
    grant = {"id": gid, "pattern": "/usr/bin/git", "source": "allow-always"}

    def parse(agents):
        return call_vendor(bundle, "parsePersistedExecApprovals", {"version": 1, "agents": agents})

    assert parse({"main": {"allowlist": [grant]}})["ok"] is True
    for agents in (
        {"main": {"allowlist": [{k: v for k, v in grant.items() if k != "id"}]}},
        {"main": {"allowlist": [dict(grant, commandText="git status")]}},
        {"main": {"allowlist": ["/usr/bin/git"]}},
        {"default": {"allowlist": [grant]}},
    ):
        out = parse(agents)
        assert out["ok"] is False and out["error"].startswith("Legacy exec approval policy requires")


# ---- B381 / B9: the per-key redaction scope the advice states ---------------------------

def test_vendor_log_redactor_scope_matches_the_b381_advice():
    """`fix` says: Authorization/key are masked like token (first six + last four), a bearer
    field and a plural token array are not, a plain `key=` text line is not."""
    require_dist()
    bundle = dist_file("redact-*.mjs", symbol="redactSecrets",
                       contains="function redactSecrets(")
    secret = "".join(["Zq8rT2", "vK9xLm", "4NpW7y", "Bc3HdF", "5gJs6Q"])  # assembled at run time

    def masked(payload) -> bool:
        return secret not in json.dumps(call_vendor(bundle, "redactSecrets", payload))

    for key in ("Authorization", "key", "token"):
        assert masked({key: secret}), key
    assert not masked({"bearer": secret})
    assert not masked({"tokens": [secret, secret]})
    assert not masked({"note": "key=" + secret})


def test_b381_fix_scopes_the_log_half_per_key_and_detail_is_unchanged():
    from clawseccheck.checks import check_redactor_blind_secret_paths
    from clawseccheck.collector import Context

    secret = "".join(["Zq8rT2", "vK9xLm", "4NpW7y", "Bc3HdF", "5gJs6Q"])
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {"headers": {"Authorization": "Bearer " + secret}}
    ctx.config_found = True
    f = check_redactor_blind_secret_paths(ctx)
    assert f.status == WARN
    # `detail` is fingerprinted: the wording that moved scoping into `fix` leaves it as it was.
    assert f.detail == (
        "1 secret-shaped value(s) at a config path OpenClaw's own redactor does not "
        "recognize, so it will not be masked in config-get output, trajectory logs, or a "
        "relayed message channel: headers.Authorization"
    )
    for needle in ("first six and last four", "bearer field", "plural token array",
                   "`key=...` text line", "was not verified"):
        assert needle in f.fix, needle


def test_b9_modern_pass_fix_names_the_chunk_boundary_limit():
    from test_b09 import _modern_ctx

    from clawseccheck.checks import check_leak
    f = check_leak(_modern_ctx({}))
    assert f.status == PASS
    assert "16 KiB" in f.fix and "32 KiB" in f.fix and "straddles" in f.fix
    assert "whole text" in f.fix


def test_vendor_chunks_operator_patterns_only_above_32_kib():
    require_dist()
    import re
    text = "".join(path.read_text(errors="replace") for path in [
        dist_file("redact-*.mjs", symbol="replacePatternBounded",
                  contains="function replacePatternBounded")])
    assert re.search(r"REDACT_REGEX_CHUNK_THRESHOLD = 32768;", text)
    assert re.search(r"REDACT_REGEX_CHUNK_SIZE = 16384;", text)
    assert "!builtInResolvedPatterns.has(pattern)" in text  # built-ins are scanned whole
