"""B-287 clean fixture: a GENUINE pytest fixture that writes agent-context filenames
into pytest's own tmp_path. Nothing here touches the user's real agent config — the
files exist only for the duration of the test — but pre-B-287 the B13 agent-config
persistence detector read `(workspace / "SOUL.md").write_text(...)` as a live write.

The suppression is scoped by _pos_in_test_fixture_file, which requires BOTH a
test-file basename AND real test-code shape, so a forged header alone cannot reach it.
"""
from pathlib import Path

import pytest

from build_state import build_state


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    return ws


def test_build_state_detects_new_context_files(workspace: Path) -> None:
    (workspace / "SOUL.md").write_text("v1")
    (workspace / "AGENTS.md").write_text("v1")
    (workspace / "CLAUDE.md").write_text("v1")

    state = build_state(workspace)

    assert state["total_files"] >= 3
    assert len(state["changed_files"]) >= 3


def test_build_state_detects_edits(workspace: Path) -> None:
    target = workspace / "MEMORY.md"
    target.write_text("v1")
    first = build_state(workspace)

    target.write_text("v2")
    second = build_state(workspace)

    assert first["digest"] != second["digest"]
