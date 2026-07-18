"""Shipped docs must not drift from the code they describe.

Version coherence (`test_version_coherence.py`) pins the four *version* spots. This pins
the other countable claims a reader takes at face value — how many checks there are, which
release the threat matrix was last ground against, how far the RISK engine goes.

Why a test and not a release checklist: a checklist runs when someone remembers, at the
moment they are most eager to ship. v3.50.0 went out saying "Updated 2026-07-16 for
v3.49.0 — 130 checks" while shipping 134 checks, because the release step only touched
CHANGELOG.md. CI runs on every commit and does not get eager.

Direction matters: truth is DERIVED FROM CODE and the DOCS are asserted against it. The
inverse (pinning `len(CATALOG) == 134`) would only force someone to update a magic number
in this file and would leave the docs just as stale.

CHANGELOG.md is deliberately exempt — its historical entries must keep quoting the counts
that were true when they were written.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck import __released__, __version__
from clawseccheck.catalog import CATALOG

REPO = Path(__file__).resolve().parents[1]

# Every shipped surface a reader can believe. The SVG badges matter as much as the prose:
# their numbers are baked into an image, so a text-only grep sails straight past them.
SHIPPED_TEXT = (
    [REPO / "README.md", REPO / "SKILL.md"]
    + sorted((REPO / "docs").glob("*.md"))
    + sorted((REPO / "docs" / "assets").glob("stats-*.svg"))
    + [p for p in [REPO / "CONTRIBUTING.md"] if p.exists()]
)

# A claim of "N checks" is only about the catalog when N is catalog-scale; prose like
# "these 3 checks" is not a coverage claim.
_CATALOG_SCALE = 50

_BARE_COUNT_RE = re.compile(r"(?<![+\w])(\d{2,4})\s+checks\b", re.IGNORECASE)
_OPEN_COUNT_RE = re.compile(r"(\d{2,4})\+\s*(?:security\s+)?checks\b", re.IGNORECASE)
_RISK_RANGE_RE = re.compile(r"RISK-01\.\.RISK-(\d+)")

# An "N+" claim buys slack on purpose — it should not churn the badge SVGs on every added
# check. It must still be true, and it must not be allowed to rot indefinitely: once the
# real count reaches the next multiple of ten, the doc has to be restated.
_OPEN_CLAIM_SLACK = 10


def _shipped_files():
    return [p for p in SHIPPED_TEXT if p.exists()]


def test_bare_check_counts_match_the_catalog():
    """"134 checks" must mean len(CATALOG) — no "+", no wiggle room."""
    actual = len(CATALOG)
    wrong = []
    for path in _shipped_files():
        text = path.read_text(encoding="utf-8")
        for m in _BARE_COUNT_RE.finditer(text):
            claimed = int(m.group(1))
            if claimed < _CATALOG_SCALE:
                continue
            if claimed != actual:
                line = text[: m.start()].count("\n") + 1
                wrong.append(f"{path.relative_to(REPO)}:{line} says {claimed}, catalog has {actual}")
    assert not wrong, "stale check-count claims in shipped docs:\n  " + "\n  ".join(wrong)


def test_open_ended_check_counts_are_true_and_not_a_decade_stale():
    """"130+ checks" must be true, and must be restated once the count reaches 140."""
    actual = len(CATALOG)
    wrong = []
    for path in _shipped_files():
        text = path.read_text(encoding="utf-8")
        for m in _OPEN_COUNT_RE.finditer(text):
            claimed = int(m.group(1))
            if claimed < _CATALOG_SCALE:
                continue
            line = text[: m.start()].count("\n") + 1
            where = f"{path.relative_to(REPO)}:{line}"
            if claimed > actual:
                wrong.append(f"{where} claims {claimed}+ but the catalog only has {actual}")
            elif actual - claimed >= _OPEN_CLAIM_SLACK:
                wrong.append(
                    f"{where} says {claimed}+ while the catalog has {actual} — "
                    f"restate it (nearest ten at or below {actual})"
                )
    assert not wrong, "open-ended check-count claims need attention:\n  " + "\n  ".join(wrong)


def test_threat_coverage_header_names_the_current_release():
    """The threat matrix asserts when it was last ground against the catalog. If that
    line still names an older release, the matrix below it is unverified for the release
    actually shipping — exactly the v3.50.0 miss this test exists to prevent."""
    path = REPO / "docs" / "THREAT_COVERAGE.md"
    text = path.read_text(encoding="utf-8")
    m = re.search(r"Updated (\d{4}-\d{2}-\d{2}) for v(\d+\.\d+\.\d+)", text)
    assert m, "docs/THREAT_COVERAGE.md must carry an 'Updated <date> for v<X.Y.Z>' line"
    doc_date, doc_version = m.group(1), m.group(2)
    assert doc_version == __version__, (
        f"docs/THREAT_COVERAGE.md is ground against v{doc_version}, but this is "
        f"v{__version__} — re-verify the matrix and restate the line"
    )
    assert doc_date == __released__, (
        f"docs/THREAT_COVERAGE.md says {doc_date}, but __released__ is {__released__}"
    )


def test_risk_range_claims_match_the_risk_engine():
    """"RISK-01..RISK-19" must end where risk.py actually ends."""
    risk_src = (REPO / "clawseccheck" / "risk.py").read_text(encoding="utf-8")
    highest = max(int(n) for n in re.findall(r"RISK-(\d+)", risk_src))
    wrong = []
    for path in _shipped_files():
        text = path.read_text(encoding="utf-8")
        for m in _RISK_RANGE_RE.finditer(text):
            claimed = int(m.group(1))
            if claimed != highest:
                line = text[: m.start()].count("\n") + 1
                wrong.append(
                    f"{path.relative_to(REPO)}:{line} says RISK-01..RISK-{claimed:02d}, "
                    f"engine goes to RISK-{highest:02d}"
                )
    assert not wrong, "stale RISK range claims:\n  " + "\n  ".join(wrong)


def test_changelog_is_exempt_from_the_count_pins():
    """Guard the guard: a past entry legitimately quotes the count that was true then, so
    CHANGELOG.md must never be swept into the files above."""
    assert not any(p.name == "CHANGELOG.md" for p in _shipped_files())
