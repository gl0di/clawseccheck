"""F-059: skill-manifest least-privilege (H7) — the skill's own allowed-tools/tools grant
cross-checked against its declared purpose. The skill-level analogue of the MCP over-scope
check; complements B62 (declared purpose vs ACTUAL code) by catching over-grant in the
manifest before any code exercises it.

WARN-first, high-power only: a NARROW-purpose skill (formatter/linter/…) granting exec /
network / cred tools it doesn't need fires; `write` and honestly-broad or vague ("helper")
purposes never do. Pure wildcard grants are already flagged HIGH elsewhere.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import vet_skill


def _vet(frontmatter: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "s"
        d.mkdir()
        (d / "SKILL.md").write_text(frontmatter + "\n# skill\nDoes its thing.\n", encoding="utf-8")
        return vet_skill(str(d)).status


def test_formatter_granting_bash_warns():
    assert _vet("---\nname: md-formatter\ndescription: a markdown formatter\n"
                "allowed-tools: [Read, Bash, Write]\n---") == WARN


def test_linter_granting_network_warns():
    assert _vet("---\nname: pylint\ndescription: a python linter\ntools: [Read, WebFetch]\n---") == WARN


def test_fetcher_granting_network_and_write_is_safe():
    # network + write are expected for a downloader/fetcher.
    assert _vet("---\nname: fetcher\ndescription: a file downloader\n"
                "allowed-tools: [Read, WebFetch, Write]\n---") == PASS


def test_formatter_granting_only_write_is_safe():
    # write is not treated as a high-power over-grant (too common/benign).
    assert _vet("---\nname: md-formatter\ndescription: a markdown formatter\n"
                "allowed-tools: [Read, Write]\n---") == PASS


def test_permissive_purpose_never_flags():
    assert _vet("---\nname: helper\ndescription: a general helper utility\n"
                "allowed-tools: [Read, Bash]\n---") == PASS


def test_read_only_formatter_is_safe():
    assert _vet("---\nname: md-formatter\ndescription: a markdown formatter\n"
                "allowed-tools: [Read]\n---") == PASS


def test_unrecognized_purpose_never_flags():
    assert _vet("---\nname: zorp\ndescription: does zorp things\nallowed-tools: [Read, Bash]\n---") == PASS
