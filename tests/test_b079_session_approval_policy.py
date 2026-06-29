import json
from pathlib import Path
from clawseccheck.catalog import CATALOG, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_session_approval_policy
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(home):
    return Context(home=Path(home))


def _write_session(sessions_dir: Path, filename: str, turns: list) -> None:
    """Write a .jsonl session file with the given list of turn dicts."""
    sessions_dir.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(t) for t in turns]
    (sessions_dir / filename).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _never_turn(turn_id: str) -> dict:
    return {
        "timestamp": "2026-06-27T11:00:00.000Z",
        "type": "turn_context",
        "payload": {"turn_id": turn_id, "approval_policy": "never",
                    "sandbox_policy": {"type": "danger-full-access"}},
    }


def _safe_turn(turn_id: str) -> dict:
    return {
        "timestamp": "2026-06-27T11:00:00.000Z",
        "type": "turn_context",
        "payload": {"turn_id": turn_id, "approval_policy": "on-request",
                    "sandbox_policy": {"type": "workspace-write"}},
    }


# ---------------------------------------------------------------------------
# Existing fixture-based tests (must stay green)
# ---------------------------------------------------------------------------

def test_b79_unknown_when_no_sessions():
    f = check_session_approval_policy(_ctx("/nonexistent"))
    assert f.id == "B79" and f.status == UNKNOWN


def test_b79_pass_mixed_policy():
    f = check_session_approval_policy(_ctx(FIXTURES / "clean_b79_sessions"))
    assert f.status == PASS


def test_b79_warn_all_never():
    f = check_session_approval_policy(_ctx(FIXTURES / "bad_b79_sessions"))
    assert f.status == WARN
    assert any("approval_policy=never" in e for e in f.evidence)
    assert any("turns sampled" in e for e in f.evidence)


def test_b79_meta_advisory_tools():
    m = next(c for c in CATALOG if c.id == "B79")
    assert m.scored is False
    assert m.severity == "MEDIUM"
    assert m.surface == "tools"


# ---------------------------------------------------------------------------
# New tests — multi-agent discovery (the bug fix)
# ---------------------------------------------------------------------------

def test_b79_warn_non_main_agent_never(tmp_path):
    """B79 must FIRE when a non-'main' agent runs entirely with approval_policy='never'."""
    sessions = tmp_path / "agents" / "analyst" / "agent" / "codex-home" / "sessions"
    _write_session(sessions, "session-analyst.jsonl", [
        _never_turn("t1"),
        _never_turn("t2"),
    ])
    f = check_session_approval_policy(_ctx(tmp_path))
    assert f.status == WARN, f"expected WARN, got {f.status}: {f.detail}"
    assert any("approval_policy=never" in e for e in f.evidence)


def test_b79_pass_non_main_agent_safe(tmp_path):
    """B79 must PASS when a non-'main' agent uses safe (mixed) approval policy."""
    sessions = tmp_path / "agents" / "analyst" / "agent" / "codex-home" / "sessions"
    _write_session(sessions, "session-safe.jsonl", [
        _safe_turn("t1"),
        _never_turn("t2"),
    ])
    f = check_session_approval_policy(_ctx(tmp_path))
    assert f.status == PASS, f"expected PASS, got {f.status}: {f.detail}"


def test_b79_unknown_empty_agents_dir(tmp_path):
    """B79 must stay UNKNOWN when the agents dir exists but contains no session files."""
    (tmp_path / "agents").mkdir()
    f = check_session_approval_policy(_ctx(tmp_path))
    assert f.status == UNKNOWN


def test_b79_warn_non_main_agent_ignored_before_fix(tmp_path):
    """Regression: only non-'main' agent present with all-never must not be silenced."""
    # No 'main' agent at all — only 'codegen'
    sessions = tmp_path / "agents" / "codegen" / "agent" / "codex-home" / "sessions"
    _write_session(sessions, "run.jsonl", [_never_turn("t1")])
    f = check_session_approval_policy(_ctx(tmp_path))
    assert f.status == WARN, (
        f"B79 silently missed non-main agent; got {f.status}"
    )


def test_b79_warn_dangerous_agent_not_diluted_by_safe_agent(tmp_path):
    """Cross-agent dilution test (per-agent worst-case).

    agent 'codegen' runs ALL-never (dangerous).
    agent 'main'    runs ALL safe / on-request.
    The dangerous agent must NOT be averaged away — B79 must still WARN.
    """
    codegen_sessions = (
        tmp_path / "agents" / "codegen" / "agent" / "codex-home" / "sessions"
    )
    main_sessions = (
        tmp_path / "agents" / "main" / "agent" / "codex-home" / "sessions"
    )
    _write_session(codegen_sessions, "run-never.jsonl", [
        _never_turn("t1"),
        _never_turn("t2"),
    ])
    _write_session(main_sessions, "run-safe.jsonl", [
        _safe_turn("t1"),
        _safe_turn("t2"),
    ])
    f = check_session_approval_policy(_ctx(tmp_path))
    assert f.status == WARN, (
        f"dangerous 'codegen' agent was diluted by safe 'main' agent; got {f.status}"
    )
    assert any("approval_policy=never" in e for e in f.evidence)
    assert any("turns sampled" in e for e in f.evidence)
