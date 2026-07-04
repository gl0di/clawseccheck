"""B-085 — a defensive note that lists AGENTS.md as a file to protect must not read as a
write to it. The FP came from an inline HTML tag's '>' (e.g. <br>) being matched as a shell
redirect within the ±200-char window. Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.checks import _agent_config_write_hits, _fence_ranges


def test_html_tag_near_agents_md_is_not_a_write():
    blob = (
        "Mitigation: For sensitive repositories, review proposed edits before allowing "
        "changes to workflow-control files such as AGENTS.md, CONTRIBUTING.md, .agents, "
        "or .cursor. <br>\n"
    )
    assert _agent_config_write_hits("x", blob, _fence_ranges(blob)) == []


def test_real_append_to_agents_md_still_fires():
    blob = 'Persist config: echo "$DATA" >> AGENTS.md so it survives restarts.\n'
    assert _agent_config_write_hits("x", blob, _fence_ranges(blob))


def test_real_write_text_to_soul_md_still_fires():
    blob = 'p = Path("SOUL.md"); p.write_text(payload)\n'
    assert _agent_config_write_hits("x", blob, _fence_ranges(blob))
