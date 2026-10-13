"""SKILL.md wording that promised more (or less) than the tool does.

Each test pins one claim to the code that makes it true, so the sentence cannot drift
away from the behaviour again:

  1. the front-matter ``description`` / ``metadata.display_description`` said "Only two
     opt-in flags write anything"; the CLI has several flags that write a file or keep
     state. The writing flags are DERIVED from the argparse definitions in ``cli.py``,
     and no manifest copy may claim an exact number of writers or name a closed list that
     omits one.
  2. the Step 4 menu tag "read-only (no side effects)" sat on two items that write the
     tool's own files.
  3. "Full check" / "Full pipeline in one go" next to a grade that also needs the opt-in
     live test.
  4. "Short of all five there is no number at all" next to the "Tamper posture" sub-score
     line the text report still prints.
  5. "Behavioural and Second opinion are always shown once computed" next to the compact
     card's 4096-character cut.
  6. the standard delivery flow uses ``--pdf``, which writes a file.

Stdlib-only, offline; nothing is written outside pytest's tmp dirs.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The control: flags a reader of cli.py can see write a file. If the derivation below ever
# stops finding these, every "no claim omits a writer" assertion would pass vacuously.
_KNOWN_OUTPUT_FLAGS = {"--save", "--badge", "--html", "--sarif", "--pdf"}
_KNOWN_PERSIST_FLAGS = {"--save-run", "--save-sbom-run"}

_NEGATED = re.compile(r"writes (none|nothing)|creates nothing|read-only", re.I)


def _norm(text: str) -> str:
    return " ".join(text.split())


def _skill_text() -> str:
    return (ROOT / "SKILL.md").read_text(encoding="utf-8")


def _manifest() -> tuple[str, str]:
    """(frontmatter description, metadata.display_description.en)."""
    front = _skill_text().split("---\n")[1]
    desc = re.search(r"^description: (.*)$", front, re.M).group(1)
    meta = json.loads(re.search(r"^metadata: (.*)$", front, re.M).group(1))
    return desc, meta["display_description"]["en"]


def _parser():
    """The real argparse parser, captured before it parses anything."""
    import clawseccheck.cli as cli

    box: list = []

    def grab(self, *_a, **_k):
        box.append(self)
        raise SystemExit(0)

    original = cli._SuggestingParser.parse_args
    cli._SuggestingParser.parse_args = grab
    try:
        try:
            cli._main([])
        except SystemExit:
            pass
    finally:
        cli._SuggestingParser.parse_args = original
    assert box, "could not capture the CLI parser"
    return box[0]


def _derived_writers() -> tuple[set, set]:
    output, persist = set(), set()
    for action in _parser()._actions:
        if not action.option_strings:
            continue
        flag = max(action.option_strings, key=len)
        help_text = _norm(action.help or "")
        if _NEGATED.search(help_text):
            continue
        if re.match(r"(also )?write\b", help_text, re.I):
            output.add(flag)
        if re.search(r"\bpersist(ed)?\b", help_text, re.I):
            persist.add(flag)
    return output, persist


_COUNT_CLAIM = re.compile(
    r"\b(only|just|exactly)\s+(one|two|three|four|five|six|\d+)\s+(opt-in\s+)?"
    r"(flags?|options?|switches)\b",
    re.I,
)
_CLOSED_LIST_SENTENCE = re.compile(r"\bonly\b[^.]*\bflags?\b[^.]*\bwrite", re.I)


def _claim_surfaces() -> dict[str, str]:
    desc, display = _manifest()
    return {"description": desc, "display_description": display, "SKILL.md": _norm(_skill_text())}


def test_control_the_derivation_finds_the_flags_a_reader_can_see():
    output, persist = _derived_writers()
    assert _KNOWN_OUTPUT_FLAGS <= output, sorted(_KNOWN_OUTPUT_FLAGS - output)
    assert _KNOWN_PERSIST_FLAGS <= persist, sorted(_KNOWN_PERSIST_FLAGS - persist)
    # more than the two the old sentence named: that is the bug.
    assert len(output | persist) > 2


def test_no_manifest_copy_claims_an_exact_number_of_writing_flags():
    for where, text in _claim_surfaces().items():
        hit = _COUNT_CLAIM.search(text)
        assert hit is None, f"{where}: {hit.group(0)!r} counts the writing flags"


def test_no_manifest_copy_names_a_closed_writer_list_that_omits_one():
    output, persist = _derived_writers()
    every = output | persist | {"--apply-ignore-proposals"}
    for where, text in _claim_surfaces().items():
        for sentence in re.split(r"(?<=[.;:])\s", text):
            if _CLOSED_LIST_SENTENCE.search(sentence):
                missing = sorted(f for f in every if f not in sentence)
                assert not missing, f"{where}: closed list omits {missing}: {sentence!r}"


def test_description_states_where_the_tools_own_state_lives_and_how_to_remove_it():
    desc, display = _manifest()
    for where, text in (("description", desc), ("display_description", display)):
        assert "~/.clawseccheck" in text, where
        assert "--purge" in text, where
        assert "--no-history" in text, where
        assert "writes only its own local report/history" not in text, where
    assert "Only two opt-in flags write anything" not in desc


def test_description_keeps_its_length_and_charset_contract():
    desc, display = _manifest()
    assert 0 < len(desc.strip()) <= 1024
    assert max(map(ord, desc)) <= 0xFF
    assert len(display) >= len(desc)


def test_display_description_does_not_count_its_writers():
    _desc, display = _manifest()
    assert "only two opt-in flags" not in display
    # it still discloses the two writes that can land inside the OpenClaw home.
    assert "--apply-ignore-proposals" in display and "--pdf" in display


def test_menu_read_only_tag_means_not_changing_the_openclaw_setup():
    text = _norm(_skill_text())
    assert "(no side effects)" not in text
    assert "does not change your OpenClaw setup" in text
    monitoring = re.search(r"\| b Turn on monitoring \|[^|]*\|([^|]*)\|", text).group(1)
    save = re.search(r"\| c Save full report \|[^|]*\|([^|]*)\|", text).group(1)
    assert "ClawSecCheck's own" in monitoring and "~/.clawseccheck" in monitoring
    assert "writes" in save and "file you name" in save


def test_full_check_row_says_what_it_leaves_out():
    text = _norm(_skill_text())
    row = re.search(r"\| 1 Full check \(mode A.*?\|\s*\n?", text).group(0)
    assert "Full pipeline in one go" not in text
    assert "every layer that needs no live test" in text
    assert "a letter grade also needs the opt-in live test" in text
    assert "stays a separate, opt-in step" in text, row


def test_the_no_number_promise_matches_the_tamper_posture_line():
    from clawseccheck import report

    src = Path(report.__file__).read_text(encoding="utf-8")
    assert "a sub-score of one" in src and "not this run's verdict" in src
    for rel in ("SKILL.md", "docs/FAQ.md", "docs/USAGE.md", "README.md"):
        text = _norm((ROOT / rel).read_text(encoding="utf-8"))
        assert "no number at all" not in text, rel
        assert "no security score or grade is printed" in text, rel
        if rel != "README.md":
            assert "Tamper posture" in text, rel


def test_the_compact_card_exception_is_stated_and_the_cut_marker_exists():
    from clawseccheck import report

    src = Path(report.__file__).read_text(encoding="utf-8")
    assert "...(dropped:" in src and "truncated to fit budget" in src
    for rel in ("SKILL.md", "docs/USAGE.md"):
        text = _norm((ROOT / rel).read_text(encoding="utf-8"))
        assert "always shown once computed" not in text, rel
        assert re.search(r"--compact[^.]*4096[^.]*dropped", text), rel


def test_pdf_delivery_flow_says_pdf_writes_a_file_and_how_to_opt_out():
    text = _norm(_skill_text())
    assert "`--pdf` writes a file" in text
    assert re.search(
        r"read-only or no-files run, omit `--pdf` and add `--no-history`, and say the full "
        r"detail is available on request",
        text,
    )
