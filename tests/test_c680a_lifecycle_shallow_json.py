"""C-680a: the lifecycle checks read agent- and user-owned JSON with `loads_shallow`.

Each converted reader (B138 devices/pending.json, B357 restart handoff, B182 ClawHub token
store, B135/B158/B181/B184 `.clawhub` records, B79 turn_context lines, B396 legacy paired
stores) gets a hostile twin: the evidence-bearing record plus a pad key nested 100, 201 and
100,000 levels deep.  The evidence in the part that was read stands (at least as severe as the
previous head's verdict), the clean padded twin is UNKNOWN (never a PASS for the part that was
not read), a whole document nested 100,000 levels is the check's unreadable state, and no
check raises.  The previous head raised RecursionError on a 100,000-level document on 3.12 and on 3.14
with the default stack (it parses them under `ulimit -s 65536` on 3.14, where the verdicts
for the padded-evidence cases equal these).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    check_clawhub_lock_verification,
    check_clawhub_registry_provenance,
    check_clawhub_token_store,
    check_declared_skill_reconciliation,
    check_pending_device_pairing_scope,
    check_restart_handoff_stale,
    check_session_approval_policy,
    check_skill_install_tamper,
)
from clawseccheck.collector import Context

PADS = [100, 201, 100_000]


def _deep(n: int, inner: str = "0") -> str:
    return "[" * n + inner + "]" * n


def _doc(obj: dict, pad: "str | None", key: str = "pad") -> str:
    """JSON text of *obj* with one extra key holding the (already serialised) deep value."""
    text = json.dumps(obj)
    if pad is None:
        return text
    return text[:-1] + (", " if obj else "") + json.dumps(key) + ": " + pad + "}"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _ctx(home: Path) -> Context:
    return Context(home=Path(home))


# ---- per-site builders: (tmp_path, evidence: bool, pad: str | None) -> Context ----------

def _b138(tmp, evidence, pad):
    scope = "operator.admin" if evidence else "operator.read"
    reqs = {"r1": {"deviceId": "d1", "platform": "linux", "isRepair": False, "scopes": [scope]}}
    _write(tmp / "devices" / "pending.json", _doc(reqs, pad))
    return _ctx(tmp)


def _b357(tmp, evidence, pad):
    expires = 1_000 if evidence else 4_102_444_800_000
    _write(tmp / "gateway-supervisor-restart-handoff.json", _doc({"expiresAt": expires}, pad))
    return _ctx(tmp)


def _b182(tmp, evidence, pad):
    user = tmp / "u"
    store = user / ".config" / "clawhub" / "config.json"
    _write(store, _doc({"token": "t" * 12}, pad))
    store.chmod(0o644 if evidence else 0o600)
    store.parent.chmod(0o700)
    return _ctx(user / ".openclaw")


def _b135(tmp, evidence, pad):
    ver = ({"ok": False, "decision": "fail", "reasons": ["signature-invalid"]} if evidence
           else {"ok": True, "decision": "pass"})
    _write(tmp / ".clawhub" / "lock.json", _doc({"skills": {"foo": {"verification": ver}}}, pad))
    return _ctx(tmp)


def _b158(tmp, evidence, pad):
    skills = {"foo": {"skillFile": "skills/foo/SKILL.md"}}
    _write(tmp / ".clawhub" / "lock.json", _doc({"skills": skills}, pad))
    if not evidence:
        (tmp / "skills" / "foo").mkdir(parents=True)
    ctx = _ctx(tmp)
    ctx.config_found = True
    ctx.config = {}
    return ctx


def _b181(tmp, evidence, pad):
    _write(tmp / "skills" / "foo" / "SKILL.md", "x")
    digest = "0" * 64 if evidence else hashlib.sha256(b"x").hexdigest()
    skills = {"foo": {"skillFile": {"path": "SKILL.md", "sha256": digest}}}
    _write(tmp / ".clawhub" / "lock.json", _doc({"skills": skills}, pad))
    return _ctx(tmp)


def _b184(tmp, evidence, pad):
    registry = "https://evil.example" if evidence else "https://clawhub.ai"
    _write(tmp / ".clawhub" / "lock.json", _doc({"skills": {"foo": {"registry": registry}}}, pad))
    return _ctx(tmp)


def _b79(tmp, evidence, pad):
    sessions = tmp / "agents" / "main" / "agent" / "codex-home" / "sessions"
    never = {"type": "turn_context", "payload": {"approval_policy": "never"}}
    other = {"type": "turn_context", "payload": {"approval_policy": "on-request"}}
    lines = [_doc(never, pad, "pad"), json.dumps(never if evidence else other)]
    if pad is not None:  # the pad sits INSIDE the payload on the padded line
        lines[0] = ('{"type": "turn_context", "payload": {"approval_policy": "never", "pad": '
                    + pad + "}}")
    _write(sessions / "s.jsonl", "\n".join(lines) + "\n")
    return _ctx(tmp)


#: name -> (builder, check, status with evidence, status for the clean twin)
SITES = {
    "B138": (_b138, check_pending_device_pairing_scope, WARN, PASS),
    "B357": (_b357, check_restart_handoff_stale, WARN, PASS),
    "B182": (_b182, check_clawhub_token_store, FAIL, PASS),
    "B135": (_b135, check_clawhub_lock_verification, WARN, PASS),
    "B158": (_b158, check_declared_skill_reconciliation, WARN, PASS),
    "B181": (_b181, check_skill_install_tamper, FAIL, PASS),
    "B184": (_b184, check_clawhub_registry_provenance, WARN, PASS),
    "B79": (_b79, check_session_approval_policy, WARN, PASS),
}
#: the whole-document file each site reads
WHOLE_DOC = {
    "B138": ["devices/pending.json"],
    "B357": ["gateway-supervisor-restart-handoff.json"],
    "B182": ["u/.config/clawhub/config.json"],
    "B135": [".clawhub/lock.json"],
    "B158": [".clawhub/lock.json"],
    "B181": [".clawhub/lock.json"],
    "B184": [".clawhub/lock.json"],
    "B79": ["agents/main/agent/codex-home/sessions/s.jsonl"],
}

SITE = pytest.mark.parametrize("site", sorted(SITES))


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch):
    for var in ("CLAWHUB_CONFIG_PATH", "CLAWDHUB_CONFIG_PATH", "XDG_CONFIG_HOME", "APPDATA"):
        monkeypatch.delenv(var, raising=False)


@SITE
def test_unpadded_twins_keep_their_verdicts(site, tmp_path):
    build, check, bad, clean = SITES[site]
    assert check(build(tmp_path / "a", True, None)).status == bad
    assert check(build(tmp_path / "b", False, None)).status == clean


@SITE
@pytest.mark.parametrize("n", PADS)
def test_evidence_in_the_read_part_stands_when_padded(site, n, tmp_path):
    build, check, bad, _clean = SITES[site]
    assert check(build(tmp_path, True, _deep(n))).status == bad


@SITE
@pytest.mark.parametrize("n", PADS)
def test_clean_padded_twin_is_unknown_not_pass(site, n, tmp_path):
    build, check, _bad, _clean = SITES[site]
    finding = check(build(tmp_path, False, _deep(n)))
    assert finding.status == UNKNOWN
    assert not finding.detail.startswith("ERR:")
    assert "not read" in finding.fix or "not read" in finding.detail or "nested" in finding.detail


@SITE
def test_evidence_buried_at_depth_100_is_never_a_pass(site, tmp_path):
    build, check, _bad, clean = SITES[site]
    buried = _deep(100, '{"scopes": ["operator.admin"], "token": "x", "expiresAt": 1}')
    assert check(build(tmp_path, False, buried)).status != clean


@SITE
def test_whole_document_100000_levels_is_unreadable_not_a_crash(site, tmp_path):
    build, check, _bad, _clean = SITES[site]
    ctx = build(tmp_path, False, None)
    for rel in WHOLE_DOC[site]:
        target = tmp_path / rel
        if site == "B79":
            target.write_text("[" * 100_000 + "]" * 100_000 + "\n", encoding="utf-8")
        else:
            target.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    assert check(ctx).status == UNKNOWN


def test_b138_every_field_padded_keeps_the_admin_warn(tmp_path):
    deep = _deep(100)
    req = {"deviceId": "@D", "platform": "@P", "isRepair": "@R", "scopes": ["operator.admin", "@S"]}
    text = json.dumps({"r1": req}).replace('"@D"', deep).replace('"@P"', deep)
    text = text.replace('"@R"', deep).replace('"@S"', deep)
    _write(tmp_path / "devices" / "pending.json", text)
    finding = check_pending_device_pairing_scope(_ctx(tmp_path))
    assert finding.status == WARN
    assert "ELIDED" not in finding.detail


def test_b135_every_field_padded_keeps_the_warn(tmp_path):
    deep = _deep(100)
    ver = {"ok": False, "decision": "fail", "reasons": ["signature-invalid", "@X"],
           "signature": {"status": "@X"}}
    entry = {"version": "@X", "verification": ver}
    text = json.dumps({"skills": {"foo": entry}}).replace('"@X"', deep)
    _write(tmp_path / ".clawhub" / "lock.json", text)
    finding = check_clawhub_lock_verification(_ctx(tmp_path))
    assert finding.status == WARN
    assert "ELIDED" not in finding.detail


def test_b181_origin_slug_padded_is_not_a_marker_slug(tmp_path):
    skill = tmp_path / "skills" / "foo"
    digest = hashlib.sha256(b"x").hexdigest()
    _write(skill / "SKILL.md", "x")
    text = json.dumps({"slug": "@X", "skillFile": {"path": "SKILL.md", "sha256": "0" * 64}})
    _write(skill / ".clawhub" / "origin.json", text.replace('"@X"', _deep(100)))
    finding = check_skill_install_tamper(_ctx(tmp_path))
    assert finding.status == FAIL
    assert "ELIDED" not in finding.detail and "foo:" in finding.detail
    assert digest  # the digest of the real bytes differs from the recorded one


def test_b396_padded_legacy_store_is_disclosed_and_does_not_crash(tmp_path):
    from clawseccheck.checks import _b396_read_legacy_store
    from clawseccheck.checks._lifecycle import _c680_has_elided as _has_elided

    _write(tmp_path / "devices" / "paired.json", _doc({"d1": {"role": "node"}}, _deep(201)))
    data, reason = _b396_read_legacy_store(_ctx(tmp_path), "devices", "paired.json")
    assert data["d1"] == {"role": "node"}
    assert not _has_elided(data), "an unread subtree reaches the consumers as null, not as the marker"
    assert reason and "read only in part" in reason
    _write(tmp_path / "nodes" / "paired.json", "[" * 100_000 + "]" * 100_000)
    assert _b396_read_legacy_store(_ctx(tmp_path), "nodes", "paired.json")[0] is None


def test_b184_padded_empty_lock_keeps_the_base_detail_byte_identical(tmp_path):
    _write(tmp_path / ".clawhub" / "lock.json", _doc({"skills": {}}, _deep(201)))
    finding = check_clawhub_registry_provenance(_ctx(tmp_path))
    assert finding.status == UNKNOWN
    assert finding.detail == (
        "No ClawHub install record (.clawhub/lock.json or a skill's .clawhub/origin.json) "
        "recorded which registry it came from, and no persistent endpoint override was "
        "readable, so it cannot be determined which host issued the supply-chain verdicts "
        "that B135, B177 and B181 report on."
    )
    assert "nested deeper" in finding.fix
    assert "Every recorded" not in finding.detail


def test_b135_padded_decision_and_ok_never_print_the_marker(tmp_path):
    ver = {"ok": "@X", "decision": "@X", "reasons": ["signature-invalid"]}
    text = json.dumps({"skills": {"foo": {"verification": ver}}}).replace('"@X"', _deep(201))
    _write(tmp_path / ".clawhub" / "lock.json", text)
    finding = check_clawhub_lock_verification(_ctx(tmp_path))
    assert "ELIDED" not in finding.detail and "ELIDED" not in finding.fix
