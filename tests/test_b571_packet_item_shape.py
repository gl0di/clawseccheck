"""B-571 — one judge-packet producer omitted `safe_facts` entirely.

`docs/OUTPUT_SCHEMA.md` §12 documents the field as an object that is "`{}` when neither
could be safely extracted". `{}` is a value, so the key exists — but only
`_item_from_finding` built it. The sink, taint and kwarg producers never set it, so a
consumer reading `item["safe_facts"]` raised KeyError on exactly one item out of 73.

That is the same ambiguity B-560 removed from SARIF's `selfExcludedSkills`: an absent key
cannot be told apart from "nothing to report".

The invariant asserted here is the KEY SET, not `safe_facts` by name. A per-key assertion
would pass the moment a fifth producer forgets a different field, which is the shape this
whole series keeps hitting — a contract honoured by some producers and not others.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from clawseccheck.cli import main

_EXEC_SKILL = 'import os\nos.system("echo hi")\n'
_MANIFEST = "---\nname: evil-helper\ndescription: t\n---\n# H\n"


@pytest.fixture
def home_with_both_producers(tmp_path: Path) -> Path:
    """A home that exercises the finding producer AND the skill-sink producer.

    A config-only home produces no sink items at all — which is exactly why the real
    machine looked clean while a fixture home did not, and why the defect survived.
    """
    home = tmp_path / "home"
    skill = home / "workspace" / "skills" / "evil-helper"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(_MANIFEST, encoding="utf-8")
    (skill / "run.py").write_text(_EXEC_SKILL, encoding="utf-8")
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps(
        {"agents": {"defaults": {"workspace": str(home / "workspace")}}}), encoding="utf-8")
    os.chmod(cfg, 0o600)
    return home


def _packet(home: Path, tmp_path: Path, capsys) -> list:
    rc = main(["--home", str(home), "--data-dir", str(tmp_path / "state"),
               "--no-history", "--full", "--json"])
    assert rc in (0, 1, 2), rc
    return json.loads(capsys.readouterr().out)["judgePacket"]


def test_the_fixture_really_exercises_both_producers(home_with_both_producers, tmp_path, capsys):
    """Positive control. Without a sink item present, every assertion below is vacuous —
    the defect only ever appeared on an item this producer makes."""
    items = _packet(home_with_both_producers, tmp_path, capsys)
    ids = {i["finding_id"] for i in items}
    assert "DANGEROUS_SINK" in ids, f"sink producer never ran; got {sorted(ids)}"
    assert any(i["finding_id"].startswith("B") for i in items), "finding producer never ran"


def test_every_packet_item_has_an_identical_key_set(home_with_both_producers, tmp_path, capsys):
    """The invariant, stated as the whole key set rather than one field's name."""
    items = _packet(home_with_both_producers, tmp_path, capsys)
    keysets = {tuple(sorted(i.keys())) for i in items}
    assert len(keysets) == 1, (
        "judge-packet items disagree on their shape — a consumer indexing any key that is "
        f"not in every item raises KeyError: {sorted(keysets)}"
    )


def test_safe_facts_is_present_and_a_dict_on_every_item(home_with_both_producers, tmp_path, capsys):
    """The specific field that was missing, and its documented empty form."""
    items = _packet(home_with_both_producers, tmp_path, capsys)
    for i in items:
        assert "safe_facts" in i, i["finding_id"]
        assert isinstance(i["safe_facts"], dict), i["finding_id"]


def test_the_sink_item_carries_an_empty_safe_facts_not_an_invented_one(
        home_with_both_producers, tmp_path, capsys):
    """Filling the key must not manufacture content.

    The point of the schema's "`{}` when neither could be safely extracted" is that an
    empty object is an honest answer; a default that invented a value would be worse than
    the missing key.
    """
    items = _packet(home_with_both_producers, tmp_path, capsys)
    sink = [i for i in items if i["finding_id"] == "DANGEROUS_SINK"]
    assert sink, "positive control failed"
    assert all(i["safe_facts"] == {} for i in sink)
