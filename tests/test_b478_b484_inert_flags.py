"""B-478 … B-484 — flags that did nothing, and help text that described something else.

The tail of E-070. Each is a flag whose documented behaviour and actual behaviour had
come apart:

- B-478 `--apply-ignore-proposals` listed every entry under "will be appended to ..." and
  then reported "Applied 0" — `append_entries` skips entries already in the file, so a
  second apply of the same proposals read as a failed write rather than as idempotency.
- B-479 `--log PATH` on its own created NO FILE. The default level is WARNING, this tool
  warns almost never, and the handler creates the file lazily on the first record.
- B-480 `--self-test`'s help named three harnesses; the mode renders four.
- B-481 `--full`'s help said the extra sections are "skipped in --json / --card mode".
  `--json` runs the whole pipeline and merges its output as additional top-level keys;
  only `--card` drops them.
- B-482 the judge packet reported "1 evidence entry in the full report" for findings with
  ZERO evidence entries — on a real `--full` run of home_vuln, 86 of 87 items.
- B-483 `--yes` outside `--purge`/`--apply-ignore-proposals` was silently accepted, though
  its own help already said it has no effect there.
- B-484 six ASCII-folding sites, two mapping tables, four bare `.encode("ascii",
  "replace")` calls: `--ascii` turned every em dash into a literal `?` across
  `--self-test`/`--dryrun`/`--multiturn`/`--next`/the PDF, `·` became `?` everywhere, and
  `--advise` ignored `--ascii` altogether.

Offline; writes only under pytest's tmp_path.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest

from clawseccheck.cli import main
from clawseccheck.logsafe import get_logger
from clawseccheck.textnorm import asciify

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")
VULN = str(FIXTURES / "home_vuln")


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def _proposals(tmp_path: Path, entries: list[str]) -> str:
    p = tmp_path / "proposals.json"
    p.write_text(json.dumps({"proposedIgnoreEntries": [{"entry": e} for e in entries]}),
                 encoding="utf-8")
    return str(p)


def _home(tmp_path: Path) -> str:
    h = tmp_path / "home"
    h.mkdir()
    (h / "openclaw.json").write_text("{}", encoding="utf-8")
    return str(h)


# ---- B-478: account for every proposed entry ----

def test_reapplying_the_same_proposals_says_they_are_already_there(tmp_path, capsys):
    home, props = _home(tmp_path), _proposals(tmp_path, ["B50:aabbccdd", "B51:11223344"])
    _run(capsys, "--apply-ignore-proposals", props, "--home", home, "--yes")
    code, out, _ = _run(capsys, "--apply-ignore-proposals", props, "--home", home, "--yes")
    assert code == 0
    assert "already in" in out
    assert "Applied 0" not in out
    # ...and it must not claim it is about to write them.
    assert "will be appended" not in out


def test_a_partial_reapply_reports_both_numbers(tmp_path, capsys):
    home = _home(tmp_path)
    _run(capsys, "--apply-ignore-proposals", _proposals(tmp_path, ["B50:aabbccdd"]),
         "--home", home, "--yes")
    props3 = tmp_path / "p3.json"
    props3.write_text(json.dumps({"proposedIgnoreEntries": [
        {"entry": "B50:aabbccdd"}, {"entry": "B52:99887766"}]}), encoding="utf-8")
    _, out, _ = _run(capsys, "--apply-ignore-proposals", str(props3), "--home", home, "--yes")
    assert "Applied 1" in out
    assert "1 more were already present" in out
    # The confirmation listing shows only what will really be written.
    assert "B52:99887766" in out
    listing = out.split("Applied")[0]
    assert "B50:aabbccdd" not in listing


def test_a_first_apply_is_unchanged(tmp_path, capsys):
    home = _home(tmp_path)
    _, out, _ = _run(capsys, "--apply-ignore-proposals",
                     _proposals(tmp_path, ["B50:aabbccdd"]), "--home", home, "--yes")
    assert "will be appended" in out
    assert "Applied 1" in out
    assert "already present" not in out


# ---- B-479: a requested log file is never empty ----

def test_log_writes_a_file_without_being_asked_twice(tmp_path, capsys):
    dest = tmp_path / "run.log"
    _run(capsys, "--home", SAFE, "--log", str(dest), "--card", "--no-history")
    assert dest.is_file(), "--log created no file at all"
    assert dest.read_text(encoding="utf-8").strip(), "--log created an empty file"


def test_log_does_not_turn_on_console_verbosity(tmp_path, capsys):
    """--log names a FILE. Raising the console level too would be a second, unrequested
    behaviour change riding along on it."""
    dest = tmp_path / "run.log"
    _, _, err = _run(capsys, "--home", SAFE, "--log", str(dest), "--card", "--no-history")
    assert "INFO clawseccheck" not in err
    assert "INFO clawseccheck" in dest.read_text(encoding="utf-8")


def test_verbose_still_reaches_the_console(tmp_path, capsys):
    dest = tmp_path / "run.log"
    _, _, err = _run(capsys, "--home", SAFE, "--log", str(dest), "--verbose", "--card",
                     "--no-history")
    assert "INFO clawseccheck" in err


def test_without_log_nothing_is_written_and_the_level_is_untouched():
    """The 'writes nothing by default' promise is the reason this flag is opt-in."""
    lg = get_logger()
    assert lg.level == logging.WARNING
    assert len(lg.handlers) == 1
    assert lg.handlers[0].level == logging.WARNING


def test_debug_still_wins_over_the_log_implication(tmp_path):
    lg = get_logger(debug=True, logfile=str(tmp_path / "x.log"))
    assert lg.level == logging.DEBUG


# ---- B-480 / B-481: help text that describes what the flag does ----

def _help_block(capsys, flag: str, next_flag: str) -> str:
    """The help text for one option, isolated. argparse wraps prose across lines and other
    options mention these flag names in their own help, so anchor on the option LINE."""
    with pytest.raises(SystemExit):
        main(["--help"])
    text = capsys.readouterr().out
    start = re.search(rf"^\s+{re.escape(flag)}\b", text, re.M)
    assert start, f"{flag} not found in --help"
    rest = text[start.end():]
    end = re.search(rf"^\s+{re.escape(next_flag)}\b", rest, re.M)
    return " ".join((rest[:end.start()] if end else rest).split())


def test_self_test_help_names_every_harness_it_renders(capsys):
    block = _help_block(capsys, "--self-test", "--full")
    for harness in ("canary", "red-team", "dry-run", "multi-turn"):
        assert harness in block, f"--self-test help does not mention {harness}: {block!r}"


def test_self_test_really_renders_all_four(capsys):
    _, out, _ = _run(capsys, "--self-test", "--seed", "b480", "--ascii", "--no-color",
                     "--no-history")
    for marker in ("canary", "Red-Team", "Dry-Run", "Multi-turn"):
        assert marker.lower() in out.lower(), f"{marker} section missing from --self-test"


def test_full_help_does_not_claim_json_skips_the_extra_sections(capsys):
    block = _help_block(capsys, "--full", "--quiet")
    assert "skipped in --json" not in block
    assert "--card drops them" in block, block


def test_full_json_really_carries_the_extra_sections(capsys):
    """The claim the help now makes, checked against the payload."""
    _, out, _ = _run(capsys, "--full", "--fast", "--home", SAFE, "--json", "--no-history")
    doc = json.loads(out)
    for key in ("judgePacket", "coveragePage"):
        assert key in doc, f"--full --json is missing {key}"


# ---- B-482: never report evidence that does not exist ----

def test_an_evidence_free_finding_is_not_credited_with_one_entry(capsys):
    _, out, _ = _run(capsys, "--full", "--fast", "--home", VULN, "--json", "--no-history")
    doc = json.loads(out)
    items = doc["judgePacket"]
    assert items, "no judge packet items to check"
    evidence_by_id = {f["id"]: len(f.get("evidence") or []) for f in doc["findings"]}
    liars = []
    for i in items:
        m = re.match(r"^(\d+) evidence entr", i.get("redacted_evidence", ""))
        if not m:
            continue
        real = evidence_by_id.get(i["finding_id"])
        if real is not None and int(m.group(1)) != real:
            liars.append((i["finding_id"], m.group(1), real))
    assert not liars, f"packet claims an evidence count the finding does not have: {liars}"
    # The honest replacement is present and says what the judge will actually find.
    honest = [i for i in items
              if i.get("redacted_evidence", "").startswith("no evidence entries")]
    assert honest, "expected the evidence-free wording on a fixture that produces it"


def test_a_finding_with_real_evidence_still_reports_its_count():
    from clawseccheck.adjudication import _evidence_locations
    from clawseccheck.catalog import Finding

    f = Finding(id="B1", title="t", status="WARN", severity="LOW",
                detail="d", fix="f", framework="", evidence=["one", "two"])
    assert _evidence_locations(f) == (
        "2 evidence entries in the full report (not reproduced here)")


def test_a_finding_with_neither_evidence_nor_detail_says_nothing():
    from clawseccheck.adjudication import _evidence_locations
    from clawseccheck.catalog import Finding

    f = Finding(id="B1", title="t", status="WARN", severity="LOW", detail="", fix="f",
                framework="")
    assert _evidence_locations(f) == ""


# ---- B-483: --yes must not be silently accepted where it does nothing ----

@pytest.mark.parametrize("argv", [
    ["--home", SAFE, "--card", "--no-history"],
    ["--home", SAFE, "--menu"],
    ["--home", SAFE, "--json", "--no-history"],
])
def test_yes_outside_its_two_consumers_is_reported(argv, capsys):
    _, _, err = _run(capsys, *argv, "--yes")
    assert "--yes" in err and "no effect" in err


def test_yes_is_silent_where_it_is_honored(tmp_path, capsys):
    home, props = _home(tmp_path), _proposals(tmp_path, ["B50:aabbccdd"])
    _, _, err = _run(capsys, "--apply-ignore-proposals", props, "--home", home, "--yes")
    assert "--yes" not in err


def test_no_yes_means_no_note(capsys):
    _, _, err = _run(capsys, "--home", SAFE, "--card", "--no-history")
    assert "--yes" not in err


# ---- B-484: one ASCII folding, applied everywhere ----

def test_the_folding_table_covers_what_we_actually_emit():
    assert asciify("a — b") == "a - b"
    assert asciify("a · b") == "a - b"
    assert asciify("a → b") == "a -> b"
    assert asciify("x … y") == "x ... y"
    # A glyph with no ASCII spelling still degrades honestly, not silently.
    assert asciify("✓") == "?"


#: The one place a bare `.encode("ascii", "replace")` is NOT output folding: the
#: bootstrap-digest fold, which hashes an already-ASCII "<size>:<sha>" marker and renders
#: nothing to anyone.
_NON_RENDERING_ENCODE_SITES = {"collector.py"}


def test_every_folding_site_uses_the_shared_table():
    """The defect was seven rendering sites, three tables, and five with none at all.

    Pinned structurally, not by output sampling, because that is how the seventh site
    (`canary.py`) and the third table (`pdf.py`'s `_ASCII_FOLD`) were found — both after
    the output-level fix looked complete. A new renderer must not be able to quietly
    reintroduce a bare encode."""
    import clawseccheck
    pkg = Path(clawseccheck.__file__).parent
    offenders = []
    for py in sorted(pkg.rglob("*.py")):
        if py.name in _NON_RENDERING_ENCODE_SITES:
            continue
        for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            if 'encode("ascii", "replace")' in line and not line.lstrip().startswith("#"):
                offenders.append(f"{py.name}:{i}")
    assert [o.split(":")[0] for o in offenders] == ["textnorm.py"], (
        f"ascii folding must live only in textnorm.asciify; found {offenders}")


def test_no_module_carries_a_second_fold_table():
    """`report.py` and `risk.py` had drifted into two different tables and `pdf.py` a
    third — the same class of defect one level up from the bare encodes."""
    import clawseccheck
    pkg = Path(clawseccheck.__file__).parent
    tables = [f"{py.name}"
              for py in sorted(pkg.rglob("*.py"))
              for line in py.read_text(encoding="utf-8").splitlines()
              if "str.maketrans({" in line and py.name != "textnorm.py"]
    assert not tables, f"a second output-folding table reappeared in {tables}"


@pytest.mark.parametrize("argv", [
    ["--home", VULN, "--no-color", "--no-history", "--ascii"],
    ["--dashboard", "--home", VULN, "--no-color", "--no-history", "--ascii"],
    ["--advise", SAFE, "--no-color", "--ascii"],
    ["--self-test", "--seed", "b484", "--no-color", "--no-history", "--ascii"],
    ["--next", "--home", VULN, "--no-color", "--no-history", "--ascii"],
    ["--functions", "--no-color", "--ascii"],
    ["--menu", "--home", SAFE, "--no-color", "--ascii"],
    ["--canary", "--seed", "b484", "--no-color", "--ascii", "--no-history"],
    ["--dryrun", "--seed", "b484", "--no-color", "--ascii", "--no-history"],
    ["--multiturn", "--seed", "b484", "--no-color", "--ascii", "--no-history"],
    ["--redteam", "--seed", "b484", "--no-color", "--ascii", "--no-history"],
    ["--vet", SAFE, "--no-color", "--ascii"],
])
def test_ascii_mode_emits_pure_ascii(argv, capsys):
    _, out, _ = _run(capsys, *argv)
    leaked = sorted({ch for ch in out if ord(ch) > 127})
    assert not leaked, f"--ascii still emitted {leaked!r}"


def test_advise_ascii_folds_its_hardcoded_dashes(capsys):
    """--advise read `ascii_only` for its icons and its `dash` variable, then emitted a
    hardcoded em dash in the verdict headline anyway."""
    _, uni, _ = _run(capsys, "--advise", SAFE, "--no-color")
    _, asc, _ = _run(capsys, "--advise", SAFE, "--no-color", "--ascii")
    assert "—" in uni, "fixture no longer exercises the em-dash path"
    assert "—" not in asc
    assert asc.isascii()


def test_self_test_harness_material_is_not_corrupted(capsys):
    """This output is pasted verbatim to an agent under test; a stray `?` mid-bracket
    corrupts the test material itself."""
    _, out, _ = _run(capsys, "--self-test", "--seed", "b484", "--no-color", "--ascii",
                     "--no-history")
    assert "[UNTRUSTED INPUT ? " not in out
    assert "[UNTRUSTED INPUT - " in out
