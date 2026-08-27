"""B-632: the published vet envelope must be the one the renderer actually emits.

`docs/OUTPUT_SCHEMA.md` §11 once listed `grade` and `score` -- two fields C427 had
deliberately removed from `render_vet_json`. A consumer coding against the document
got a KeyError. The prose has since been corrected twice by hand; this is the guard
that stops it drifting a third time.

Measured end-to-end through the CLI rather than by calling the renderer, because
the envelope a consumer receives is the one that came out of the process. The mode
split is the point: `coverage` and the install-decision keys belong to `--advise`
only, so a single union of every key would pass while a plain `--vet` still lacked
half of them.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SCHEMA = (_ROOT / "docs" / "OUTPUT_SCHEMA.md").read_text(encoding="utf-8")

_SKILL_MD = """---
name: demo
version: 0.1.0
description: A harmless demo skill used to measure the published vet envelope.
---

# Demo

Does nothing.
"""

_MCP_JSON = '{"mcpServers": {"demo": {"command": "npx", "args": ["-y", "demo-mcp"]}}}'


def _table_fields(section: str) -> set[str]:
    """Field names from the first `| Field | Type | Description |` table in a section."""
    rows = re.findall(r"^\|\s*`([A-Za-z_][A-Za-z0-9_]*)`\s*\|", section, re.MULTILINE)
    assert rows, "no field rows parsed -- the table shape changed"
    return set(rows)


def _section(start: str, end: str) -> str:
    assert start in _SCHEMA, f"missing section anchor: {start!r}"
    body = _SCHEMA.split(start, 1)[1]
    return body.split(end, 1)[0]


@pytest.fixture(scope="module")
def documented() -> tuple[set[str], set[str]]:
    base = _table_fields(_section("## 11. `--vet` Mode Output", "### Axis object"))
    extra = _table_fields(_section("### `--advise` keys", "## 12."))
    return base, extra


@pytest.fixture(scope="module")
def target(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("vet_target")
    (d / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (d / "mcp.json").write_text(_MCP_JSON, encoding="utf-8")
    return d


def _emitted(args: list[str]) -> set[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", *args, "--json"],
        capture_output=True,
        text=True,
        cwd=_ROOT,
        timeout=300,
    )
    assert proc.stdout.strip(), f"no stdout for {args}: {proc.stderr[-800:]}"
    return set(json.loads(proc.stdout).keys())


@pytest.mark.parametrize(
    "flag",
    ["--vet-skill", "--vet-plugin", "--vet-mcp"],
)
def test_vet_modes_emit_exactly_the_documented_base_envelope(flag, documented, target) -> None:
    base, extra = documented
    arg = str(target / "mcp.json") if flag == "--vet-mcp" else str(target)
    emitted = _emitted([flag, arg])
    assert emitted == base, (
        f"{flag}: documented-but-absent={sorted(base - emitted)}, "
        f"emitted-but-undocumented={sorted(emitted - base)}"
    )
    assert not (emitted & extra), (
        f"{flag} emits --advise-only keys: {sorted(emitted & extra)}"
    )


def test_vet_source_emits_exactly_the_documented_base_envelope(documented) -> None:
    base, _ = documented
    emitted = _emitted(["--vet-source", "some-slug-that-is-not-in-the-ioc-dataset"])
    assert emitted == base, (
        f"vet-source: documented-but-absent={sorted(base - emitted)}, "
        f"emitted-but-undocumented={sorted(emitted - base)}"
    )


def test_advise_emits_the_base_envelope_plus_exactly_the_documented_extras(documented, target) -> None:
    base, extra = documented
    emitted = _emitted(["--advise", str(target)])
    assert emitted == base | extra, (
        f"advise: documented-but-absent={sorted((base | extra) - emitted)}, "
        f"emitted-but-undocumented={sorted(emitted - (base | extra))}"
    )


def test_grade_and_score_stay_out_of_every_vet_surface(documented) -> None:
    """The specific regression: C427 removed them from the payload on purpose."""
    base, extra = documented
    assert not ({"grade", "score"} & (base | extra)), (
        "OUTPUT_SCHEMA §11 documents a grade/score the renderer deliberately withholds"
    )
    section = _section("## 11. `--vet` Mode Output", "## 12.")
    skeleton = section.split("```json", 1)[1].split("```", 1)[0]
    payload = json.loads(skeleton)
    assert "grade" not in payload and "score" not in payload, (
        "the §11 skeleton -- the part a consumer copies -- still shows grade/score"
    )
    assert set(payload) <= base, f"skeleton invents keys: {sorted(set(payload) - base)}"
