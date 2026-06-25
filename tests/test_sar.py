"""Tests for F-020: Structured Attestation Request (SAR).

Covers:
- build_sars() returns a SAR for a skill with a B62 mismatch (declared_purpose,
  capability_set, mismatches, question all present and correct).
- build_sars() returns an empty list when there is no mismatch.
- SAR contains no raw secrets (logsafe.redact is applied).
- No network call is made (structural guarantee: no socket/http in sar.py).
- render_json() includes 'intentAttestationRequests' key; its value is a list.
- render_json() with ctx=None produces an empty intentAttestationRequests list.
- render_json() with a mismatch ctx produces a non-empty list.
- Existing top-level render_json keys are unchanged.
- CLI --json output includes intentAttestationRequests.

All tests are offline, read-only, stdlib-only.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck.collector import Context
from clawseccheck.report import render_json
from clawseccheck.sar import build_sars
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_HOME_FAKE = Path("/nonexistent/home")

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _ctx_mismatch() -> Context:
    """A Context whose single skill is a 'formatter' with network capability."""
    skill_name = "md_fmt"
    blob = (
        "# file: SKILL.md\n"
        "---\nname: md_fmt\ndescription: A markdown formatter.\n---\n"
        "\n# file: md_fmt.py\nimport socket\ndef run(x): pass\n"
    )
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {skill_name: blob}
    ctx.installed_skill_py = {skill_name: [("md_fmt.py", "import socket\ndef run(x): pass")]}
    ctx.effect_profiles = {
        skill_name: [{"entry_point": "run", "reachable_effects": ["network"],
                      "guarding_conditions": [], "guarded_effects": [],
                      "unshielded_effects": ["network"], "file": "md_fmt.py"}]
    }
    return ctx


def _ctx_no_mismatch() -> Context:
    """A Context whose single skill is a 'downloader' with network (expected)."""
    skill_name = "fetcher"
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {
        skill_name: (
            "# file: SKILL.md\n"
            "---\nname: fetcher\ndescription: A file downloader.\n---\n"
        )
    }
    ctx.installed_skill_py = {
        skill_name: [("fetcher.py", "import socket\ndef run(url): pass")]
    }
    ctx.effect_profiles = {
        skill_name: [{"entry_point": "run", "reachable_effects": ["network"],
                      "guarding_conditions": [], "guarded_effects": [],
                      "unshielded_effects": ["network"], "file": "fetcher.py"}]
    }
    return ctx


def _ctx_empty() -> Context:
    """A Context with no installed skills."""
    return Context(home=_HOME_FAKE)


# ---------------------------------------------------------------------------
# build_sars: mismatch case
# ---------------------------------------------------------------------------

def test_build_sars_mismatch_returns_one_entry():
    sars = build_sars(_ctx_mismatch())
    assert len(sars) == 1


def test_build_sars_mismatch_has_required_keys():
    sar = build_sars(_ctx_mismatch())[0]
    for key in ("skill", "declared_purpose", "capability_set", "mismatches",
                "computed_risk", "question"):
        assert key in sar, f"SAR missing key: {key}"


def test_build_sars_mismatch_skill_name():
    sar = build_sars(_ctx_mismatch())[0]
    assert sar["skill"] == "md_fmt"


def test_build_sars_mismatch_declared_purpose():
    sar = build_sars(_ctx_mismatch())[0]
    assert "formatter" in sar["declared_purpose"].lower()


def test_build_sars_mismatch_capability_set_contains_network():
    sar = build_sars(_ctx_mismatch())[0]
    assert "network" in sar["capability_set"]


def test_build_sars_mismatch_mismatches_list_nonempty():
    sar = build_sars(_ctx_mismatch())[0]
    assert len(sar["mismatches"]) >= 1


def test_build_sars_mismatch_mismatch_entry_structure():
    mis = build_sars(_ctx_mismatch())[0]["mismatches"][0]
    assert "capability" in mis
    assert "declared" in mis
    assert "evidence" in mis
    assert mis["declared"] is False


def test_build_sars_mismatch_network_capability_in_mismatches():
    mis = build_sars(_ctx_mismatch())[0]["mismatches"]
    caps = [m["capability"] for m in mis]
    assert "network" in caps


def test_build_sars_mismatch_computed_risk_is_high():
    # network is a high-surprise family → computed_risk = "high"
    sar = build_sars(_ctx_mismatch())[0]
    assert sar["computed_risk"] == "high"


def test_build_sars_mismatch_question_is_nonempty_string():
    sar = build_sars(_ctx_mismatch())[0]
    assert isinstance(sar["question"], str)
    assert len(sar["question"]) > 20


def test_build_sars_mismatch_question_names_skill():
    sar = build_sars(_ctx_mismatch())[0]
    assert "md_fmt" in sar["question"]


def test_build_sars_mismatch_question_names_capability():
    sar = build_sars(_ctx_mismatch())[0]
    assert "network" in sar["question"]


def test_build_sars_mismatch_question_asks_yes_no():
    sar = build_sars(_ctx_mismatch())[0]
    q = sar["question"].lower()
    assert "yes" in q or "no" in q


# ---------------------------------------------------------------------------
# build_sars: no-mismatch cases
# ---------------------------------------------------------------------------

def test_build_sars_no_mismatch_empty_list():
    assert build_sars(_ctx_no_mismatch()) == []


def test_build_sars_no_skills_empty_list():
    assert build_sars(_ctx_empty()) == []


def test_build_sars_permissive_skill_empty_list():
    """A vague 'helper' skill must not produce a SAR."""
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {
        "myhelper": (
            "# file: SKILL.md\n"
            "---\nname: myhelper\ndescription: A general-purpose helper utility.\n---\n"
        )
    }
    ctx.installed_skill_py = {
        "myhelper": [("myhelper.py", "import socket\ndef run(x): pass")]
    }
    ctx.effect_profiles = {}
    assert build_sars(ctx) == []


# ---------------------------------------------------------------------------
# SAR must contain no raw secrets
# ---------------------------------------------------------------------------

def test_build_sars_no_raw_secrets_in_output():
    """A skill blob that contains a secret-shaped token must not leak it in the SAR."""
    # Build a blob where the description contains a token-looking string.
    # logsafe.redact must strip it before it reaches the SAR.
    secret_fragment = "sk-ant-api03-AAABBBCCC"
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {
        "md_fmt": (
            "# file: SKILL.md\n"
            f"---\nname: md_fmt\ndescription: A markdown formatter. Token={secret_fragment}\n---\n"
        )
    }
    ctx.installed_skill_py = {
        "md_fmt": [("md_fmt.py", "import socket\ndef run(x): pass")]
    }
    ctx.effect_profiles = {}
    sars = build_sars(ctx)
    # Serialise to JSON and check the raw token does not appear
    serialised = json.dumps(sars)
    assert secret_fragment not in serialised


# ---------------------------------------------------------------------------
# No network: structural check
# ---------------------------------------------------------------------------

def test_sar_module_has_no_network_imports():
    """sar.py must not import any network module (socket, urllib, requests, etc.)."""
    import ast
    import importlib.util
    spec = importlib.util.find_spec("clawseccheck.sar")
    assert spec is not None
    source = Path(spec.origin).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {"socket", "urllib", "http", "requests", "aiohttp", "httpx",
                 "ftplib", "smtplib", "imaplib", "poplib", "paramiko"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else ([node.module] if node.module else [])
            )
            for name in names:
                root = (name or "").split(".")[0]
                assert root not in forbidden, (
                    f"sar.py imports network module '{name}' — not allowed"
                )


# ---------------------------------------------------------------------------
# render_json: intentAttestationRequests is always present
# ---------------------------------------------------------------------------

def _minimal_findings_score():
    from clawseccheck.catalog import Finding, PASS, LOW
    f = Finding("B99", "test", LOW, PASS, "ok", "ok", "fw")
    score = compute([f])
    return [f], score


def test_render_json_has_intent_attestation_requests_key_no_ctx():
    findings, score = _minimal_findings_score()
    data = json.loads(render_json(findings, score))
    assert "intentAttestationRequests" in data


def test_render_json_no_ctx_produces_empty_list():
    findings, score = _minimal_findings_score()
    data = json.loads(render_json(findings, score))
    assert data["intentAttestationRequests"] == []


def test_render_json_with_mismatch_ctx_produces_nonempty_list():
    ctx = _ctx_mismatch()
    findings, score = _minimal_findings_score()
    data = json.loads(render_json(findings, score, ctx=ctx))
    assert len(data["intentAttestationRequests"]) == 1


def test_render_json_with_no_mismatch_ctx_produces_empty_list():
    ctx = _ctx_no_mismatch()
    findings, score = _minimal_findings_score()
    data = json.loads(render_json(findings, score, ctx=ctx))
    assert data["intentAttestationRequests"] == []


def test_render_json_sar_entry_structure_in_payload():
    ctx = _ctx_mismatch()
    findings, score = _minimal_findings_score()
    data = json.loads(render_json(findings, score, ctx=ctx))
    sar = data["intentAttestationRequests"][0]
    for key in ("skill", "declared_purpose", "capability_set", "mismatches",
                "computed_risk", "question"):
        assert key in sar, f"SAR entry missing key '{key}' in render_json output"


# ---------------------------------------------------------------------------
# render_json: existing keys must not change
# ---------------------------------------------------------------------------

def test_render_json_existing_keys_unchanged():
    findings, score = _minimal_findings_score()
    data = json.loads(render_json(findings, score))
    for key in ("score", "grade", "capped", "raw_score", "trifecta",
                "findings", "next_actions"):
        assert key in data, f"render_json missing pre-existing key '{key}'"


def test_render_json_findings_list_unchanged():
    findings, score = _minimal_findings_score()
    data = json.loads(render_json(findings, score))
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "B99"


# ---------------------------------------------------------------------------
# CLI integration: --json output includes intentAttestationRequests
# ---------------------------------------------------------------------------

def test_cli_json_includes_intent_attestation_requests(tmp_path, capsys):
    from clawseccheck.cli import main
    # Minimal valid OpenClaw home (no skills → empty SAR list, but key must be present)
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    rc = main(["--home", str(tmp_path), "--json", "--no-native", "--no-host"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "intentAttestationRequests" in data
    assert isinstance(data["intentAttestationRequests"], list)


def test_cli_json_mismatch_skill_produces_sar(tmp_path, capsys):
    """CLI --json with a mismatch skill fixture produces a non-empty SAR list."""
    from clawseccheck.cli import main
    fixture = FIXTURES / "bad_b62_cap_mismatch"
    if not fixture.exists():
        pytest.skip("bad_b62_cap_mismatch fixture not found")
    main(["--home", str(fixture), "--json", "--no-native", "--no-host"])
    data = json.loads(capsys.readouterr().out)
    assert "intentAttestationRequests" in data
    sars = data["intentAttestationRequests"]
    assert len(sars) >= 1, "Expected at least one SAR entry for the mismatch fixture"
    sar = sars[0]
    assert sar["computed_risk"] in ("high", "medium")
    assert isinstance(sar["question"], str) and len(sar["question"]) > 0
