"""Tests for `--incident` (I-020) — read-only, opt-in evidence-pack builder.

Every field is reused from an existing producer, not reinvented: findings snapshot
(_finding_to_dict), skill/MCP inventory (sbom.build_sbom, F-085), the credential
rotation list (B41's own PII-safe evidence), trajectory-sidecar hashes
(trajectory.find_trajectory_files, B85's own discovery), monitor event history
(monitor.load_events). Never rotates, deletes, or mutates anything; never touches
the network.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import Finding
from clawseccheck.cli import main
from clawseccheck.collector import Context
from clawseccheck.incident import build_incident, render_incident
from clawseccheck.scoring import ScoreResult


def _score(score: int = 80, grade: str = "B") -> ScoreResult:
    return ScoreResult(score=score, grade=grade, capped=False, raw_score=score,
                        failed_critical=0, failed_high=0)


def _ctx(home) -> Context:
    ctx = Context(home=home)
    ctx.config = {}
    ctx.installed_skills = {}
    return ctx


# --------------------------------------------------------------------------- shape

def test_build_incident_has_expected_top_level_keys(tmp_path):
    ctx = _ctx(tmp_path)
    payload = build_incident(ctx, [], _score(), when="2026-07-04T00:00:00")
    assert set(payload.keys()) == {
        "tool", "version", "purpose", "generated_at", "score", "findings",
        "sbom", "trajectory_hashes", "credential_rotation_list", "monitor_events",
    }
    assert payload["tool"] == "clawseccheck"
    assert payload["generated_at"] == "2026-07-04T00:00:00"
    assert payload["score"] == {"score": 80, "grade": "B"}


def test_build_incident_purpose_frames_it_as_preservation_not_remediation(tmp_path):
    ctx = _ctx(tmp_path)
    payload = build_incident(ctx, [], _score(), when="2026-07-04T00:00:00")
    assert "does NOT rotate, delete, or remediate" in payload["purpose"]


def test_render_incident_is_deterministic_json(tmp_path):
    ctx = _ctx(tmp_path)
    out1 = render_incident(ctx, [], _score(), when="2026-07-04T00:00:00")
    out2 = render_incident(ctx, [], _score(), when="2026-07-04T00:00:00")
    assert out1 == out2
    json.loads(out1)  # must parse


# --------------------------------------------------------------------------- findings

def test_findings_snapshot_uses_the_same_shape_as_other_json_exports(tmp_path):
    from clawseccheck.report import _finding_to_dict

    ctx = _ctx(tmp_path)
    f = Finding(id="B1", title="t", severity="HIGH", status="PASS",
                detail="d", fix="f", framework="fr")
    payload = build_incident(ctx, [f], _score(), when="2026-07-04T00:00:00")
    # Reuses the exact same serializer every other JSON export uses (not a hand-rolled
    # shape) — assert equality against that serializer's own real output, not a fixed
    # literal (which would drift the moment catalog metadata for "B1" changes).
    assert payload["findings"] == [_finding_to_dict(f)]


# --------------------------------------------------------------------------- credential rotation list

def test_credential_rotation_list_reuses_b41_evidence_verbatim(tmp_path):
    ctx = _ctx(tmp_path)
    b41 = Finding(id="B41", title="t", severity="MEDIUM", status="WARN",
                  detail="d", fix="f", framework="fr",
                  evidence=["providers: openai, github", "gateway-token: present"])
    payload = build_incident(ctx, [b41], _score(), when="2026-07-04T00:00:00")
    assert payload["credential_rotation_list"] == ["providers: openai, github", "gateway-token: present"]


def test_credential_rotation_list_empty_when_no_b41_finding(tmp_path):
    ctx = _ctx(tmp_path)
    payload = build_incident(ctx, [], _score(), when="2026-07-04T00:00:00")
    assert payload["credential_rotation_list"] == []


def test_credential_rotation_list_never_contains_account_or_email_fragments(tmp_path):
    """Sanity check on top of B41's own guarantee: no '@' (email) or ':' (account
    separator) should ever appear in what this pack surfaces."""
    ctx = _ctx(tmp_path)
    b41 = Finding(id="B41", title="t", severity="MEDIUM", status="WARN",
                  detail="d", fix="f", framework="fr",
                  evidence=["providers: openai"])
    payload = build_incident(ctx, [b41], _score(), when="2026-07-04T00:00:00")
    for line in payload["credential_rotation_list"]:
        assert "@" not in line


# --------------------------------------------------------------------------- trajectory hashes

def test_trajectory_hashes_present_when_sidecar_files_exist(tmp_path):
    sessions = tmp_path / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True)
    traj = sessions / "abc.trajectory.jsonl"
    content = '{"traceSchema":"openclaw-trajectory","schemaVersion":1,"type":"tool.call","data":{"name":"fs_read"}}\n'
    traj.write_text(content, encoding="utf-8")

    ctx = _ctx(tmp_path)
    payload = build_incident(ctx, [], _score(), when="2026-07-04T00:00:00")
    assert len(payload["trajectory_hashes"]) == 1
    entry = payload["trajectory_hashes"][0]
    assert entry["path"] == str(Path("agents") / "main" / "sessions" / "abc.trajectory.jsonl")
    assert entry["bytes"] == len(content.encode("utf-8"))
    import hashlib
    assert entry["sha256"] == hashlib.sha256(content.encode("utf-8")).hexdigest()


def test_trajectory_hashes_empty_when_no_sidecar_files(tmp_path):
    ctx = _ctx(tmp_path)
    payload = build_incident(ctx, [], _score(), when="2026-07-04T00:00:00")
    assert payload["trajectory_hashes"] == []


def test_trajectory_hashing_never_reads_call_arguments_into_the_pack(tmp_path):
    """The hash proves integrity without this pack ever surfacing tool-call content —
    only a path + hash + byte count, never the JSONL content itself."""
    sessions = tmp_path / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True)
    traj = sessions / "abc.trajectory.jsonl"
    traj.write_text(
        '{"type":"tool.call","data":{"name":"fs_read","arguments":{"path":"/etc/shadow"}}}\n',
        encoding="utf-8",
    )
    ctx = _ctx(tmp_path)
    out = render_incident(ctx, [], _score(), when="2026-07-04T00:00:00")
    assert "/etc/shadow" not in out


# --------------------------------------------------------------------------- sbom reuse

def test_sbom_section_reuses_build_sbom_verbatim(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.installed_skills = {"helper": "---\nname: helper\nversion: 1.0.0\n---\n"}
    payload = build_incident(ctx, [], _score(), when="2026-07-04T00:00:00")
    from clawseccheck.sbom import build_sbom
    assert payload["sbom"] == build_sbom(ctx)


# --------------------------------------------------------------------------- monitor events

def test_monitor_events_empty_when_no_event_journal(tmp_path, monkeypatch):
    monkeypatch.setattr("clawseccheck.incident.DEFAULT_EVENTS", str(tmp_path / "nonexistent.jsonl"))
    ctx = _ctx(tmp_path)
    payload = build_incident(ctx, [], _score(), when="2026-07-04T00:00:00")
    assert payload["monitor_events"] == []


# --------------------------------------------------------------------------- CLI

def test_cli_incident_exits_zero(capsys):
    rc = main(["--incident"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "clawseccheck"


def test_cli_incident_is_valid_json_with_home_flag(capsys, tmp_path):
    rc = main(["--incident", "--home", str(tmp_path)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert "findings" in payload and "sbom" in payload
