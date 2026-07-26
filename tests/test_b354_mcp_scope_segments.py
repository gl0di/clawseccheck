"""B-354 — the broad-oauth-scope probe matched raw SUBSTRINGS.

`_VET_MCP_BROAD_SCOPE_RE` was `\\*|all|admin|write|full` applied with `.search()` to the
whole scope string, with no boundary of any kind, so every alternative fired inside
ordinary scope names a real MCP server declares: `install:packages` ("all"), `rewrite` /
`writeup` ("write"), `fullscreen` / `fullname` ("full"), `administrative-contact` /
`subadmin` ("admin").

Severity, established rather than assumed: this signal lands in `suspicious`, which
`vet_mcp` renders as WARN, not FAIL. So it was noise rather than a Golden-Rule-#5 release
blocker — but noise on exactly the field an OAuth-scoped server is most likely to declare.

The fix is a segment classifier, not a denylist: an OAuth scope is a whitespace-delimited
LIST of tokens (RFC 6749 §3.3) and a token is conventionally a delimited path, so the
string is split and each SEGMENT compared whole. That removes the false-positive class;
a denylist would only ever chase the instances that happened to be reported.

Both directions are pinned, because killing an FP by killing the detection is a
regression: the true positives below are the baseline this change may not spend.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck.checks import vet_mcp
from clawseccheck.checks._mcp import _vet_mcp_scope_is_broad, _vet_mcp_server

BENIGN_SCOPES = [
    "install:packages",          # the reported one — "all" inside "install"
    "uninstall:packages",
    "rewrite",
    "writeup",
    "rewrite:article",
    "fullscreen",
    "fullname",
    "fullscreen:toggle",
    "administrative-contact",
    "subadmin",
    "smallwrite",
    "repo:status",
    "user:email",
    "calendar.events.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
    "read:org read:user repo:status",
]

BROAD_SCOPES = [
    "*",
    "all",
    "admin",
    "write",
    "full",
    "admin:*",
    "scope.write",
    "repo:write",
    "Files.ReadWrite.All",
    "full-access",
    "read+write",
    "read:org admin:org",
    "https://www.googleapis.com/auth/admin.directory.user",
    # recall gaps closed in round 2 — vendors write a broad permission as ONE token
    "**",
    "Mail.ReadWrite",
    "readWrite",
    "fullAccess",
    "fullControl",
    "adminAll",
    "Sites.FullControl.All",
]


@pytest.mark.parametrize("scope", BENIGN_SCOPES)
def test_benign_scope_segments_are_not_broad(scope):
    assert not _vet_mcp_scope_is_broad(scope), scope


@pytest.mark.parametrize("scope", BROAD_SCOPES)
def test_broad_scope_segments_still_register(scope):
    assert _vet_mcp_scope_is_broad(scope), scope


@pytest.mark.parametrize("scope", BENIGN_SCOPES)
def test_benign_scope_produces_no_finding_at_all(scope):
    dangerous, suspicious = _vet_mcp_server("srv", {
        "command": "npx", "args": ["-y", "@acme/mcp@1.0.0"],
        "oauth": {"scope": scope},
    })
    assert dangerous == []
    assert not any("oauth.scope" in s for s in suspicious), suspicious


@pytest.mark.parametrize("scope", BROAD_SCOPES)
def test_broad_scope_still_produces_the_signal(scope):
    _, suspicious = _vet_mcp_server("srv", {
        "command": "npx", "args": ["-y", "@acme/mcp@1.0.0"],
        "oauth": {"scope": scope},
    })
    assert any("oauth.scope" in s for s in suspicious), (scope, suspicious)


def _spec_file(tmp_path: Path, scope: str) -> Path:
    p = tmp_path / "spec.json"
    p.write_text(json.dumps({"mcp": {"servers": {"srv": {
        "command": "npx", "args": ["-y", "@acme/mcp@1.0.0"],
        "oauth": {"scope": scope},
    }}}}), encoding="utf-8")
    return p


def test_end_to_end_benign_scope_is_a_clean_pass(tmp_path):
    findings = vet_mcp(_spec_file(tmp_path, "install:packages"))
    assert [f.status for f in findings] == ["PASS"], [f.detail for f in findings]


@pytest.mark.parametrize("scope", ["fullscreen", "fullname", "fullName", "installPackages",
                                   "readOnly", "adminContact"])
def test_camelcase_compounds_are_not_split_into_broad_segments(scope):
    """Splitting camelCase into segments was considered and rejected: it would read
    `fullName` / `fullScreen` as "full" and reintroduce the substring class this fixed.
    The compound broad names are enumerated as WHOLE tokens instead."""
    assert not _vet_mcp_scope_is_broad(scope), scope


@pytest.mark.parametrize("scope", [["admin", "*"], ["repo:status", "write"], ["all"]])
def test_list_valued_scope_is_flattened_not_stringified(scope):
    """`str(["admin", "*"])` is `"['admin', '*']"`, whose tokens carry stray brackets and
    quotes and match nothing — a broad scope reading as clean, the failure direction that
    matters. Hand-written MCP configs commonly use a list."""
    assert _vet_mcp_scope_is_broad(scope), scope


@pytest.mark.parametrize("scope", [["install:packages"], ["repo:status", "user:email"]])
def test_list_valued_benign_scope_still_clean(scope):
    assert not _vet_mcp_scope_is_broad(scope), scope


def test_list_valued_scope_reaches_the_finding(tmp_path):
    _, suspicious = _vet_mcp_server("srv", {
        "command": "npx", "args": ["-y", "@acme/mcp@1.0.0"],
        "oauth": {"scope": ["admin", "*"]},
    })
    assert any("oauth.scope" in s for s in suspicious), suspicious
    # the rendered value is the flattened list, not a Python repr
    assert not any("['admin'" in s for s in suspicious), suspicious


def test_end_to_end_broad_scope_is_a_warn_not_a_fail(tmp_path):
    """Establishes the blast radius this check actually has: WARN, never FAIL."""
    findings = vet_mcp(_spec_file(tmp_path, "admin:*"))
    assert [f.status for f in findings] == ["WARN"], [f.detail for f in findings]
