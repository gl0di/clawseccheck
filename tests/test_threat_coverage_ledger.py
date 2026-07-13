"""CLAWSECCHECK-C-193: threat-coverage closure-ledger completeness guard.

`docs/THREAT_COVERAGE.md` is the human-readable map of what ClawSecCheck checks today.
Nothing enforced that a newly-added `CheckMeta` id, or a newly-described threat category,
actually got classified there — coverage could silently drift: a category with no check,
no attestation, no judge-packet coverage, and no declared ceiling reads as "covered" when
it is a silent gap.

This test parses the ledger's two canonical, machine-tagged sections and checks two things,
deliberately kept lightweight (no claim-grounding, no correctness-of-bucket-choice judgment
— that's an architect/human call, made in the doc itself):

  (a) every `CheckMeta` id in `clawseccheck/catalog.py` appears inside some `[CHECK: ...]`
      tag in the "## Covered" table;
  (b) every row in "## Covered" and every bullet in "## Non-static coverage" carries
      exactly one of the four tags — `[CHECK: ...]`, `[ATTEST]`, `[JUDGE: ...]`, `[CEILING]`
      — never zero (a silent gap) and never more than one (an ambiguous classification).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.catalog import BY_ID

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER_PATH = REPO_ROOT / "docs" / "THREAT_COVERAGE.md"

_TAG_RE = re.compile(r"\[(CHECK|ATTEST|JUDGE|CEILING)(?::\s*([^\]]+))?\]")


def _section_body(doc: str, heading: str) -> str:
    """Text between a top-level '## <heading>' line and the next '## ' heading (or EOF)."""
    pat = re.compile(
        r"^## " + re.escape(heading) + r".*?\n(.*?)(?=^## |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    m = pat.search(doc)
    assert m, f"'## {heading}' section not found in {LEDGER_PATH}"
    return m.group(1)


def _table_data_rows(section: str) -> list[str]:
    """Markdown table rows in *section*, skipping the header and separator rows."""
    rows = [ln for ln in section.splitlines() if ln.strip().startswith("|")]
    # First row = header, second = '|---|---|...' alignment separator.
    return rows[2:]


def _bulleted_items(section: str) -> list[str]:
    """Top-level '- ...' bullets in *section*, each joined across its wrapped continuation
    lines (indented, non-bullet, non-blank lines immediately following a '- ' line)."""
    items: list[str] = []
    current: list[str] = []
    for ln in section.splitlines():
        if ln.startswith("- "):
            if current:
                items.append(" ".join(current))
            current = [ln]
        elif ln.strip() and current:
            current.append(ln.strip())
        elif not ln.strip() and current:
            items.append(" ".join(current))
            current = []
    if current:
        items.append(" ".join(current))
    return items


def _check_ids_in(text: str) -> set[str]:
    ids: set[str] = set()
    for m in _TAG_RE.finditer(text):
        if m.group(1) != "CHECK":
            continue
        for tok in (m.group(2) or "").split(","):
            tok = tok.strip()
            if tok:
                ids.add(tok)
    return ids


def _tag_count(text: str) -> int:
    return len(_TAG_RE.findall(text))


# --------------------------------------------------------------------------- fixtures

def _doc() -> str:
    return LEDGER_PATH.read_text(encoding="utf-8")


def _covered_rows() -> list[str]:
    return _table_data_rows(_section_body(_doc(), "Covered"))


def _non_static_items() -> list[str]:
    return _bulleted_items(_section_body(_doc(), "Non-static coverage (ATTEST / JUDGE / CEILING)"))


# --------------------------------------------------------------------------- (a) catalog-id completeness

def test_every_catalog_id_appears_in_a_check_tag():
    documented: set[str] = set()
    for row in _covered_rows():
        documented |= _check_ids_in(row)

    catalog_ids = set(BY_ID.keys())
    missing = sorted(catalog_ids - documented)
    assert not missing, (
        f"{len(missing)} CheckMeta id(s) in catalog.py have no [CHECK: ...] tag in "
        f"docs/THREAT_COVERAGE.md's Covered table — a silent gap: {missing}"
    )


def test_no_non_catalog_ids_inside_check_tags():
    """A CHECK tag should only ever name real catalog ids — anything else is a typo or a
    stale reference (e.g. a RISK-* id, which belongs in prose, not a CHECK tag)."""
    documented: set[str] = set()
    for row in _covered_rows():
        documented |= _check_ids_in(row)

    catalog_ids = set(BY_ID.keys())
    extra = sorted(documented - catalog_ids)
    assert not extra, f"CHECK tag(s) reference non-catalog token(s), likely a typo: {extra}"


# --------------------------------------------------------------------------- (b) row/bullet completeness

def test_every_covered_row_has_exactly_one_tag():
    untagged, multi = [], []
    for row in _covered_rows():
        n = _tag_count(row)
        if n == 0:
            untagged.append(row)
        elif n > 1:
            multi.append(row)
    assert not untagged, f"{len(untagged)} Covered row(s) carry no closure tag at all: {untagged}"
    assert not multi, f"{len(multi)} Covered row(s) carry more than one closure tag: {multi}"


def test_every_covered_row_tag_is_check():
    """The Covered table is, by construction, the CHECK-bucket table — every row's one tag
    must be CHECK (an ATTEST/JUDGE/CEILING-only category belongs in Non-static coverage)."""
    non_check = [row for row in _covered_rows() if _TAG_RE.search(row) and _TAG_RE.search(row).group(1) != "CHECK"]
    assert not non_check, f"Covered row(s) tagged with a non-CHECK bucket: {non_check}"


def test_every_non_static_item_has_exactly_one_tag():
    untagged, multi = [], []
    for item in _non_static_items():
        n = _tag_count(item)
        if n == 0:
            untagged.append(item)
        elif n > 1:
            multi.append(item)
    assert not untagged, f"{len(untagged)} Non-static item(s) carry no closure tag at all: {untagged}"
    assert not multi, f"{len(multi)} Non-static item(s) carry more than one closure tag: {multi}"


def test_non_static_items_are_not_tagged_check():
    """A category with a real CheckMeta id belongs in Covered, not here — Non-static
    coverage is specifically for categories with no catalog id."""
    tagged_check = [item for item in _non_static_items() if _TAG_RE.search(item) and _TAG_RE.search(item).group(1) == "CHECK"]
    assert not tagged_check, f"Non-static item(s) wrongly tagged CHECK: {tagged_check}"


def test_ledger_sections_are_non_empty():
    assert len(_covered_rows()) >= 40, "Covered table looks truncated or unparsed"
    assert len(_non_static_items()) >= 5, "Non-static coverage list looks truncated or unparsed"


# --------------------------------------------------------------------------- negative test (parser sanity)

def test_parser_catches_an_untagged_row():
    """Sanity/negative test for the parsing machinery itself (not the real doc): a
    deliberately-unclassified row must be caught by the same logic the real assertions use."""
    section = (
        "\n"
        "| Threat | Covered by | Notes |\n"
        "|---|---|---|\n"
        "| Tagged threat | B1 | fine `[CHECK: B1]` |\n"
        "| Untagged threat | B2 | no tag at all -- this is the silent gap |\n"
    )
    rows = _table_data_rows(section)
    assert len(rows) == 2
    tag_counts = [_tag_count(r) for r in rows]
    assert tag_counts == [1, 0], "parser failed to distinguish the tagged row from the untagged one"


def test_parser_catches_a_double_tagged_row():
    section = (
        "\n"
        "| Threat | Covered by | Notes |\n"
        "|---|---|---|\n"
        "| Ambiguous threat | B1 | conflicting `[CHECK: B1]` and `[CEILING]` |\n"
    )
    rows = _table_data_rows(section)
    assert _tag_count(rows[0]) == 2


def test_parser_joins_wrapped_bullets():
    section = (
        "\n"
        "Some intro prose.\n"
        "\n"
        "- A bullet that wraps across\n"
        "  a second physical line and ends here `[CEILING]`\n"
        "- A second, single-line bullet `[ATTEST]`\n"
    )
    items = _bulleted_items(section)
    assert len(items) == 2
    assert "[CEILING]" in items[0]
    assert "[ATTEST]" in items[1]
