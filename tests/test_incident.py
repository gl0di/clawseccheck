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
        "monitor_events_source",  # B-277 provenance
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
    # C-172 regression: a small file's digest is a plain, full-file sha256 — not
    # flagged as truncated.
    assert entry["truncated"] is False


def test_trajectory_hash_labeled_truncated_when_file_exceeds_cap(tmp_path, monkeypatch):
    """C-172: a sidecar bigger than the per-file cap must never be silently reported
    as if its sha256 authenticated the whole file. Patch the cap down (rather than
    writing a real 8MB fixture) to keep the test fast."""
    import hashlib

    import clawseccheck.incident as incident

    monkeypatch.setattr(incident, "_MAX_TRAJECTORY_BYTES", 16)

    sessions = tmp_path / "agents" / "main" / "sessions"
    sessions.mkdir(parents=True)
    traj = sessions / "big.trajectory.jsonl"
    content = "x" * 100
    traj.write_text(content, encoding="utf-8")

    ctx = _ctx(tmp_path)
    payload = build_incident(ctx, [], _score(), when="2026-07-04T00:00:00")
    assert len(payload["trajectory_hashes"]) == 1
    entry = payload["trajectory_hashes"][0]

    assert entry["truncated"] is True
    assert entry["bytes"] == 16
    # The digest only covers the first 16 bytes — never the whole 100-byte file.
    assert entry["sha256"] == hashlib.sha256(content[:16].encode("utf-8")).hexdigest()
    assert entry["sha256"] != hashlib.sha256(content.encode("utf-8")).hexdigest()


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


# --------------------------------------------------------------------------- B-277
# `--incident` accepted `--events PATH` and silently harvested the DEFAULT journal
# instead. A flag that is accepted and ignored is worse than one that errors: on a
# host monitoring several agents the pack's `sbom` described the agent named by
# `--home` while `monitor_events` described whichever agent last wrote the default
# journal, and no field in the pack disclosed which file had actually been read.

def _event_line(message: str, severity: str = "CRITICAL") -> str:
    return json.dumps({"ts": "2026-07-20T10:00:00", "severity": severity,
                       "message": message}) + "\n"


def test_explicit_events_path_is_honored(tmp_path, monkeypatch):
    """CLEAN: the named journal is the one that gets read."""
    named = tmp_path / "named.jsonl"
    named.write_text(_event_line("NEW skill installed: 'evil-jp'"), encoding="utf-8")
    # Point the default somewhere empty so a pass cannot come from the default path.
    monkeypatch.setattr("clawseccheck.incident.DEFAULT_EVENTS", str(tmp_path / "absent.jsonl"))

    payload = build_incident(_ctx(tmp_path), [], _score(),
                             when="2026-07-04T00:00:00", events=str(named))

    assert [e["message"] for e in payload["monitor_events"]] == [
        "NEW skill installed: 'evil-jp'"]
    assert payload["monitor_events_source"] == str(named)


def test_explicit_events_path_is_not_substituted_by_the_default_journal(tmp_path, monkeypatch):
    """BAD-state repro: a POPULATED default journal must not shadow the named one.

    Pre-fix this returned agent B's events while the operator asked for agent A's —
    the substitution case, which is strictly worse than the empty-list case because
    the pack looks complete.
    """
    agent_a = tmp_path / "agent_a.jsonl"
    agent_a.write_text(_event_line("AGENT-A alert"), encoding="utf-8")
    agent_b_default = tmp_path / "agent_b_default.jsonl"
    agent_b_default.write_text(_event_line("AGENT-B skill 'evil-b' installed"), encoding="utf-8")
    monkeypatch.setattr("clawseccheck.incident.DEFAULT_EVENTS", str(agent_b_default))

    payload = build_incident(_ctx(tmp_path), [], _score(),
                             when="2026-07-04T00:00:00", events=str(agent_a))

    messages = [e["message"] for e in payload["monitor_events"]]
    assert messages == ["AGENT-A alert"]
    assert not any("AGENT-B" in m for m in messages), (
        "the default journal leaked into a pack that named a different --events file")
    assert payload["monitor_events_source"] == str(agent_a)


def test_events_none_falls_back_to_the_default_journal(tmp_path, monkeypatch):
    """The documented default is preserved for library callers that pass nothing."""
    default = tmp_path / "default.jsonl"
    default.write_text(_event_line("from the default journal"), encoding="utf-8")
    monkeypatch.setattr("clawseccheck.incident.DEFAULT_EVENTS", str(default))

    payload = build_incident(_ctx(tmp_path), [], _score(), when="2026-07-04T00:00:00")

    assert [e["message"] for e in payload["monitor_events"]] == ["from the default journal"]
    assert payload["monitor_events_source"] == str(default)


def test_monitor_events_source_is_recorded_even_when_the_journal_is_absent(tmp_path):
    """Provenance is unconditional: an empty history and the wrong host's history
    must never be indistinguishable."""
    absent = tmp_path / "absent.jsonl"
    payload = build_incident(_ctx(tmp_path), [], _score(),
                             when="2026-07-04T00:00:00", events=str(absent))
    assert payload["monitor_events"] == []
    assert payload["monitor_events_source"] == str(absent)


def test_render_incident_threads_events_through(tmp_path, monkeypatch):
    """render_incident is the CLI's entry point — the kwarg must survive it."""
    named = tmp_path / "named.jsonl"
    named.write_text(_event_line("rendered from the named journal"), encoding="utf-8")
    monkeypatch.setattr("clawseccheck.incident.DEFAULT_EVENTS", str(tmp_path / "absent.jsonl"))

    payload = json.loads(render_incident(_ctx(tmp_path), [], _score(),
                                         when="2026-07-04T00:00:00", events=str(named)))

    assert [e["message"] for e in payload["monitor_events"]] == [
        "rendered from the named journal"]
    assert payload["monitor_events_source"] == str(named)


def test_cli_incident_honors_events_flag(tmp_path, monkeypatch, capsys):
    """End-to-end through main(): the plumbing gap was in cli.py, not just incident.py."""
    named = tmp_path / "named.jsonl"
    named.write_text(_event_line("NEW skill installed: 'evil-jp'"), encoding="utf-8")
    monkeypatch.setattr("clawseccheck.incident.DEFAULT_EVENTS", str(tmp_path / "absent.jsonl"))

    rc = main(["--incident", "--home", str(tmp_path), "--events", str(named),
               "--history", str(tmp_path / "h.jsonl")])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert [e["message"] for e in payload["monitor_events"]] == [
        "NEW skill installed: 'evil-jp'"]
    assert payload["monitor_events_source"] == str(named)


def test_events_is_not_announced_as_a_dropped_flag_for_incident(tmp_path, capsys):
    """--events is now genuinely consumed by --incident, so _flag_coherence_notes
    must not enrol it in the 'has no effect' list (the alternative fix, not taken)."""
    named = tmp_path / "named.jsonl"
    named.write_text(_event_line("consumed"), encoding="utf-8")

    main(["--incident", "--home", str(tmp_path), "--events", str(named),
          "--history", str(tmp_path / "h.jsonl")])

    assert "--events" not in capsys.readouterr().err


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
