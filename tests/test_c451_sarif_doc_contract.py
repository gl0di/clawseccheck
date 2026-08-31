"""C-451: pin `docs/OUTPUT_SCHEMA.md` §10 against a SARIF artifact we generate.

B-585 corrected the SARIF section by hand and its own test plan proposed this guard,
which was never written -- so the section was correct only for as long as the next
person remembered. `docs/OUTPUT_SCHEMA.md` is what a CI consumer parses our machine
output against; a drifted schema doc is a claim about what the tool emits that the
tool does not honour.

Derivable direction only. The tables name keys, so the keys are pinned; a sentence
about *why* a key exists is not mechanizable and is deliberately left to review.

Writing this found real drift: `analysis_completeness` was emitting `disclosures`
and `config_parse_error`, neither documented, and the block's stated condition
("only ... a full audit") was contradicted by every `--vet --sarif` run.
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

# Every key the completeness block emits only when it has a `ScoreResult` — the block
# returns early without one, so these are exactly the keys a `--vet` run cannot carry.
#
# The name says "layer" and the membership never did: `configBlind` has been here since
# before B-690 and is a cap signal, not a layer. B-690 added `capsFired` for the same
# reason — it is built from the score, so a vet run has nothing to build it from.
# Restating the count rather than widening the criterion: the criterion was always
# "needs a score", and it is what the vet-leak assertion below actually tests.
_LAYER_KEYS = {"graded", "layersRan", "layersTotal", "missingLayers", "notChecked",
               "configBlind", "capsFired"}


def _section(start: str, end: str) -> str:
    assert start in _SCHEMA, f"missing anchor: {start!r}"
    return _SCHEMA.split(start, 1)[1].split(end, 1)[0]


def _rows(section: str) -> list[tuple[str, ...]]:
    out = []
    for line in section.splitlines():
        m = re.match(r"^\|\s*`([A-Za-z_][A-Za-z0-9_.]*)`\s*\|(.*)\|\s*$", line)
        if m:
            out.append((m.group(1), *[c.strip() for c in m.group(2).split("|")]))
    return out


def _fields(section: str) -> set[str]:
    names = {r[0] for r in _rows(section)}
    assert names, "no field rows parsed -- the table shape changed"
    return names


def _sarif(tmp: Path, args: list[str]) -> dict:
    out = tmp / "out.sarif"
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", *args, "--sarif", str(out)],
        capture_output=True, text=True, cwd=_ROOT, timeout=600,
    )
    assert out.exists(), f"no SARIF written for {args}: {proc.stderr[-800:]}"
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def audit_run(tmp_path_factory) -> dict:
    return _sarif(tmp_path_factory.mktemp("sarif_audit"), ["--home", str(_ROOT / "fixtures" / "home_vuln")])


@pytest.fixture(scope="module")
def vet_run(tmp_path_factory) -> dict:
    d = tmp_path_factory.mktemp("sarif_vet")
    (d / "SKILL.md").write_text(
        "---\nname: demo\nversion: 0.1.0\ndescription: A harmless demo skill.\n---\n\n# Demo\n",
        encoding="utf-8",
    )
    return _sarif(d, ["--vet-skill", str(d)])


def test_driver_fields_match(audit_run) -> None:
    documented = _fields(_section("### `runs[0].tool.driver` fields", "### Rule object"))
    assert set(audit_run["runs"][0]["tool"]["driver"]) == documented


def test_rule_fields_match(audit_run) -> None:
    documented = _fields(_section("### Rule object", "### Result object"))
    rule = audit_run["runs"][0]["tool"]["driver"]["rules"][0]
    flat = set(rule) | {
        f"{k}.{sub}" for k, v in rule.items() if isinstance(v, dict) for sub in v
    }
    missing = {d for d in documented if d not in flat}
    assert not missing, f"documented rule fields absent from a real rule: {sorted(missing)}"
    top = {d.split(".", 1)[0] for d in documented}
    assert set(rule) == top, f"undocumented rule fields: {sorted(set(rule) - top)}"


def test_result_fields_match(audit_run) -> None:
    documented = _fields(_section("### Result object", "### Fix object"))
    results = audit_run["runs"][0]["results"]
    assert results, "the vulnerable fixture produced no SARIF results"
    seen: set[str] = set()
    for r in results:
        seen |= set(r)
        seen |= {f"properties.{k}" for k in r.get("properties", {})}
        seen |= {f"message.{k}" for k in r.get("message", {})}
    top = {d.split(".", 1)[0] for d in documented}
    assert set().union(*(set(r) for r in results)) <= top, "undocumented result field"
    always = {d for d, *rest in _rows(_section("### Result object", "### Fix object")) if rest[1] == "yes"}
    for r in results:
        flat = set(r) | {f"properties.{k}" for k in r.get("properties", {})} | {
            f"message.{k}" for k in r.get("message", {})
        }
        missing = always - flat
        assert not missing, f"result {r.get('ruleId')} missing always-present fields: {sorted(missing)}"


def test_analysis_completeness_camel_matches_the_audit_artifact(audit_run) -> None:
    section = _section("### `runs[0].properties.analysisCompleteness`", "### Top-level structure")
    documented = _fields(section)
    emitted = set(audit_run["runs"][0]["properties"]["analysisCompleteness"])
    assert emitted == documented, (
        f"documented-but-absent={sorted(documented - emitted)}, "
        f"emitted-but-undocumented={sorted(emitted - documented)}"
    )


def test_the_documented_audit_only_condition_holds_on_a_vet_run(vet_run, audit_run) -> None:
    """The doc says the five-layer keys are absent on --vet. Both halves measured."""
    section = _section("### `runs[0].properties.analysisCompleteness`", "### Top-level structure")
    audit_only = {name for name, *rest in _rows(section) if rest[1] == "audit runs only"}
    assert audit_only == _LAYER_KEYS, (
        f"the table's audit-only set drifted from the five-layer state: {sorted(audit_only)}"
    )
    vet_keys = set(vet_run["runs"][0]["properties"]["analysisCompleteness"])
    assert not (vet_keys & audit_only), f"--vet leaked audit-only keys: {sorted(vet_keys & audit_only)}"
    always = {name for name, *rest in _rows(section) if rest[1] == "always"}
    assert vet_keys == always, (
        f"--vet: documented-always-but-absent={sorted(always - vet_keys)}, "
        f"emitted-but-undocumented={sorted(vet_keys - always)}"
    )
    assert set(audit_run["runs"][0]["properties"]["analysisCompleteness"]) == always | audit_only


def test_analysis_completeness_snake_matches_the_artifact(audit_run, vet_run) -> None:
    section = _section("### `runs[0].properties.analysis_completeness`", "### `runs[0].properties.effectProfile`")
    documented = _fields(section)
    for label, run in (("audit", audit_run), ("vet", vet_run)):
        emitted = set(run["runs"][0]["properties"]["analysis_completeness"])
        assert emitted == documented, (
            f"{label}: documented-but-absent={sorted(documented - emitted)}, "
            f"emitted-but-undocumented={sorted(emitted - documented)}"
        )
