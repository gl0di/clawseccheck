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
from clawseccheck.behavioral import BEHAVIORAL_CHECK_IDS
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

# One optional adjective may sit between the number and the noun — "143 security checks",
# "143 individual checks". Without it the badge text (the single most-read claim) and the
# README prose both sail past this guard: found the hard way, when a deliberately-wrong 146
# passed a run that was supposed to go red.
_BARE_COUNT_RE = re.compile(r"(?<![+\w])(\d{2,4})\s+(?:[a-z]+\s+)?checks\b", re.IGNORECASE)
_OPEN_COUNT_RE = re.compile(r"(\d{2,4})\+\s*(?:security\s+)?checks\b", re.IGNORECASE)
# Every spelling a writer reaches for, not just the one the first stale claim happened to
# use. Pinning `..` alone is what let "RISK-01 through RISK-18" sit in docs/USAGE.md while
# the engine built 21 — the guard was live, the doc was stale, and the two never met. The
# separator set is deliberately narrow (no `/`, no `,`) so enumerations like
# "RISK-01/02/03" in THREAT_COVERAGE.md stay out; the closing `RISK-` is required so a
# CHECKS.md heading ("### RISK-01 - Untrusted sender …") cannot match either.
_RISK_RANGE_RE = re.compile(
    r"RISK-01\s*(?:\.\.|through|to|[-–—])\s*RISK-(\d+)", re.IGNORECASE
)

# An "N+" claim buys slack on purpose — it should not churn the badge SVGs on every added
# check. It must still be true, and it must not be allowed to rot indefinitely: once the
# real count reaches the next multiple of ten, the doc has to be restated.
_OPEN_CLAIM_SLACK = 10

# "6,236 automated tests" — with or without the thousands comma, and "549 test files":
# a bare three-to-six-digit count (not just four-to-six — a claim like "549 test files"
# is a real, currently-shipped shape and a three-digit count never matched before
# C-445), followed by either "tests" or "test files".
# The `files` group is what keeps the two claim KINDS apart. Widening the regex to see
# "561 test files" without it fed a file count into the guard that compares against the
# test count, and the full suite went red with "docs/USAGE.md says 561 while the suite has
# 15,594 — restate it (drifted by 15,033)". It passed review because the value guard skips
# below `_FULL_SUITE_FLOOR`, so a partial run — the only kind anyone runs while editing this
# file — never exercised it. Seeing a claim and knowing what it claims are two jobs.
_TEST_COUNT_RE = re.compile(
    r"(\d{1,3}(?:,\d{3})+|\d{3,6})\+?\s*(?:automated\s+)?test(?:s|(?P<files>\s+files))\b",
    re.IGNORECASE,
)

# Below this, the run is a subset rather than the suite, so the collected count says
# nothing about the true total.
_FULL_SUITE_FLOOR = 3000

# How far the stated figure may fall behind before it stops informing the reader. Wide
# enough that ordinary commits do not redden CI, narrow enough that a stale claim cannot
# survive to a release.
_TEST_CLAIM_SLACK = 400

# The same two rules, at the magnitude a file count actually moves: never overstate,
# and restate once the gap stops informing. 400 would let a claim of 161 stand against
# 561 files, which is the open-ended rot this guard exists to prevent.
_TEST_FILE_CLAIM_SLACK = 40


def _shipped_files():
    return [p for p in SHIPPED_TEXT if p.exists()]


def _runnable_check_count():
    """How many checks a DEFAULT audit actually runs.

    Not `len(CATALOG)`. The T-series is catalogued but only executes under
    `--behavioral`, so counting the catalog advertises three checks an ordinary run never
    performs. A reader takes "N security checks" to mean N things that ran — measured on a
    real `--json` audit, exactly this many ids appear.
    """
    return len(CATALOG) - len(BEHAVIORAL_CHECK_IDS)


def test_bare_check_counts_match_what_a_default_audit_runs():
    """"143 checks" must mean the checks that actually execute — no "+", no wiggle room."""
    actual = _runnable_check_count()
    wrong = []
    for path in _shipped_files():
        text = path.read_text(encoding="utf-8")
        for m in _BARE_COUNT_RE.finditer(text):
            claimed = int(m.group(1))
            if claimed < _CATALOG_SCALE:
                continue
            if claimed != actual:
                line = text[: m.start()].count("\n") + 1
                wrong.append(f"{path.relative_to(REPO)}:{line} says {claimed}, a default audit runs {actual}")
    assert not wrong, "stale check-count claims in shipped docs:\n  " + "\n  ".join(wrong)


def test_open_ended_check_counts_are_true_and_not_a_decade_stale():
    """"130+ checks" must be true, and must be restated once the count reaches 140."""
    actual = _runnable_check_count()
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
                wrong.append(f"{where} claims {claimed}+ but a default audit only runs {actual}")
            elif actual - claimed >= _OPEN_CLAIM_SLACK:
                wrong.append(
                    f"{where} says {claimed}+ while a default audit runs {actual} — "
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
    """"RISK-01..RISK-19" must end where risk.py actually ends — however it is spelled."""
    risk_src = (REPO / "clawseccheck" / "risk.py").read_text(encoding="utf-8")
    highest = max(int(n) for n in re.findall(r"RISK-(\d+)", risk_src))
    wrong = []
    for path in _shipped_files():
        text = path.read_text(encoding="utf-8")
        for m in _RISK_RANGE_RE.finditer(text):
            claimed = int(m.group(1))
            if claimed != highest:
                line = text[: m.start()].count("\n") + 1
                # Quote the claim VERBATIM rather than restating it in the `..` spelling:
                # a message that renames what it found sends the reader grepping for text
                # that is not in the file.
                wrong.append(
                    f"{path.relative_to(REPO)}:{line} says {m.group(0)!r}, "
                    f"engine goes to RISK-{highest:02d}"
                )
    assert not wrong, "stale RISK range claims:\n  " + "\n  ".join(wrong)


def test_risk_range_guard_reads_every_spelling_a_writer_uses():
    """Guard the guard: the `..`-only regex was live while a `through` claim rotted.

    Pins the separator set in both directions — the four accepted spellings must match,
    and the enumeration/heading forms that share the `RISK-01` prefix must NOT, or the
    guard would fire on `RISK-01/02/03` and on every CHECKS.md section heading.
    """
    for spelling in (
        "RISK-01..RISK-18",
        "RISK-01 through RISK-18",
        "RISK-01 to RISK-18",
        "RISK-01–RISK-18",
        "RISK-01 - RISK-18",
    ):
        m = _RISK_RANGE_RE.search(spelling)
        assert m is not None, f"{spelling!r} is a range claim the guard cannot see"
        assert m.group(1) == "18"
    for not_a_range in (
        "combined with RISK-01/02/03 this is also",
        "### RISK-01 - Untrusted sender can reach host execution",
        "RISK-01, RISK-18",
    ):
        assert _RISK_RANGE_RE.search(not_a_range) is None, (
            f"{not_a_range!r} is not a range claim, but the guard reads one"
        )


_CHAIN_COUNT_RE = re.compile(r"(\d+) attack[- ]chain detectors")


def test_attack_chain_count_claims_match_the_risk_engine():
    """The bare "N attack-chain detectors" figure, not just the RISK-01..RISK-NN form.

    This drifted unnoticed to 20 while the engine built 21, because the sibling test
    above only pins the *range* spelling and nothing pinned the badge figure. It lives in
    the README alt text and inside both stats SVGs -- a title, an aria-label and a bare
    <text> element -- which is exactly the shape a prose grep sails past.
    """
    risk_src = (REPO / "clawseccheck" / "risk.py").read_text(encoding="utf-8")
    highest = max(int(n) for n in re.findall(r"RISK-(\d+)", risk_src))
    wrong = []
    for path in _shipped_files():
        text = path.read_text(encoding="utf-8")
        for m in _CHAIN_COUNT_RE.finditer(text):
            claimed = int(m.group(1))
            if claimed != highest:
                line = text[: m.start()].count("\n") + 1
                wrong.append(
                    f"{path.relative_to(REPO)}:{line} claims {claimed} attack-chain "
                    f"detectors, risk.py builds {highest}"
                )
    assert not wrong, "stale attack-chain count claims:\n  " + "\n  ".join(wrong)


# Each badge states its five figures three times: as visible <text class="num"> elements,
# and again inside aria-label and <title>. `[\d,]+` and not `\d+` -- the test-count slot is
# comma-grouped ("15,400"), and a `\d+` pattern silently matches the "15" of it, which is
# how that position stayed unguarded while reading as covered.
_SVG_NUM_RE = re.compile(r'<text class="num" x="([\d.]+)"[^>]*>([\d,]+)</text>')
_SVG_LABEL_RE = re.compile(r'aria-label="([^"]*)"')
_SVG_TITLE_RE = re.compile(r"<title>([^<]*)</title>")
# "184 security checks - 26 attack-chain detectors - ..." -> the figure opening each segment.
_SVG_STAT_RE = re.compile(r"([\d,]+)\s+[A-Za-z]")


def _svg_self_disagreements(svg: str, name: str) -> list:
    """Every way *svg* contradicts itself across its three statements of the same figures.

    Deliberately derives the number of stats FROM THE FILE rather than asserting five, so a
    sixth stat added later is covered the day it is added -- the previous guard hardcoded a
    single x position and therefore could only ever watch the one figure it was written for.
    """
    out = []
    nums = [v for _, v in sorted(_SVG_NUM_RE.findall(svg), key=lambda p: float(p[0]))]
    if not nums:
        return [f"{name}: no <text class=\"num\"> elements at all"]
    for what, rx in (("aria-label", _SVG_LABEL_RE), ("title", _SVG_TITLE_RE)):
        m = rx.search(svg)
        if not m:
            out.append(f"{name}: no {what}")
            continue
        stated = _SVG_STAT_RE.findall(m.group(1))
        if len(stated) != len(nums):
            out.append(
                f"{name}: {len(nums)} number element(s) but {what} states {len(stated)} figure(s)"
            )
            continue
        for i, (drawn, said) in enumerate(zip(nums, stated)):
            if drawn != said:
                out.append(f"{name}: position {i} shows {drawn}, its {what} says {said}")
    return out


def test_the_svg_badge_numbers_match_their_own_label():
    """Every figure the badge draws must equal what its aria-label and title say it draws.

    The failure this pins really happened: on 2026-08-13 the test-count slot read 14,400
    while the label beside it said 15,000 -- a 600 disagreement inside one file that no
    guard could see, because the guard watched only the attack-chain position."""
    wrong = []
    for name in ("stats-light.svg", "stats-dark.svg"):
        svg = (REPO / "docs" / "assets" / name).read_text(encoding="utf-8")
        wrong.extend(_svg_self_disagreements(svg, name))
    assert not wrong, "SVG badge disagrees with itself:\n  " + "\n  ".join(wrong)


def test_the_badge_guard_bites_on_a_previously_unguarded_position():
    """Guard the guard, on a position the OLD one structurally could not reach.

    Mutating the attack-chain slot would prove nothing -- that is the one slot the previous
    regex already watched. So mutate the test-count slot (x=620.0) and the checks slot
    (x=124.0) instead, and require a complaint naming each."""
    svg = (REPO / "docs" / "assets" / "stats-light.svg").read_text(encoding="utf-8")
    assert not _svg_self_disagreements(svg, "control"), "the real file must start clean"

    positions = [x for x, _ in sorted(_SVG_NUM_RE.findall(svg), key=lambda p: float(p[0]))]
    assert len(positions) >= 3, "badge should carry several figures"

    for idx in (0, 2):  # security checks, automated tests -- neither is x=372.0
        x, value = sorted(_SVG_NUM_RE.findall(svg), key=lambda p: float(p[0]))[idx]
        broken = svg.replace(
            f'<text class="num" x="{x}"', f'<text class="num" x="{x}" data-mutated="1"', 1
        )
        # rewrite only that element's value, leaving the label and title untouched
        broken = re.sub(
            r'(<text class="num" x="' + re.escape(x) + r'"[^>]*>)[\d,]+(</text>)',
            r"\g<1>999999\g<2>",
            broken,
        )
        complaints = _svg_self_disagreements(broken, "mutant")
        assert complaints, f"guard is blind to position {idx} (x={x}, was {value})"
        assert any("999999" in c for c in complaints), complaints


def test_changelog_is_exempt_from_the_count_pins():
    """Guard the guard: a past entry legitimately quotes the count that was true then, so
    CHANGELOG.md must never be swept into the files above."""
    assert not any(p.name == "CHANGELOG.md" for p in _shipped_files())


def test_test_count_claims_are_true_and_not_badly_stale(request):
    """"6,236 automated tests" must not overstate, and must not rot the way "5,000+" did.

    Why a band and not equality: the suite grows on ordinary commits, so pinning the exact
    number would turn every added test into a red build — the doc would be accurate and the
    project unworkable. Why not leave it open-ended: "5,000+" stayed technically true while
    the real figure passed 6,200, which is how a claim becomes useless without ever becoming
    a lie. So the rule is the one that actually protects a reader: never claim more tests
    than exist, and restate once the gap gets wide enough to mislead.

    Skips on a partial run, where the collected count is not the suite total. CI runs the
    whole suite, so the guard is live exactly where a release is cut.
    """
    actual = len(request.session.items)
    file_total = len(list((REPO / "tests").glob("test_*.py")))
    if actual < _FULL_SUITE_FLOOR:
        import pytest

        pytest.skip(f"partial run ({actual} collected) — count claims need the full suite")

    wrong = []
    for path in _shipped_files():
        text = path.read_text(encoding="utf-8")
        for m in _TEST_COUNT_RE.finditer(text):
            claimed = int(m.group(1).replace(",", ""))
            line = text[: m.start()].count("\n") + 1
            where = f"{path.relative_to(REPO)}:{line}"
            # "561 test files" and "15,200 tests" are both test-count claims and they are
            # measured against different truths. Comparing a file count to the suite total
            # produces a demand to "restate it (drifted by 15,033)" about a figure that was
            # exactly right.
            is_files = m.group("files") is not None
            truth = file_total if is_files else actual
            noun = "test files" if is_files else "tests"
            slack = _TEST_FILE_CLAIM_SLACK if is_files else _TEST_CLAIM_SLACK
            if claimed > truth:
                wrong.append(f"{where} claims {claimed:,} {noun} but only {truth:,} exist")
            elif truth - claimed >= slack:
                wrong.append(
                    f"{where} says {claimed:,} {noun} while there are {truth:,} — "
                    f"restate it (drifted by {truth - claimed:,})"
                )
    assert not wrong, "test-count claims need attention:\n  " + "\n  ".join(wrong)


def test_test_count_guard_reads_three_digit_counts_and_the_test_files_phrasing():
    """Guard the guard: C-445 found "549 test files" invisible to `_TEST_COUNT_RE` for
    two independent reasons — the numeric alternation admitted only a comma-thousands
    form or four-to-six bare digits (never a bare three-digit count like 549), and the
    trailing literal was `tests\\b`, which "test files" never satisfies. Pins both
    widenings in both directions, same idiom as the RISK-range guard-the-guard test.
    """
    for claim, count in (
        ("549 test files", "549"),
        ("561 test files", "561"),
        ("6,236 automated tests", "6,236"),
        ("15,200 tests", "15,200"),
    ):
        m = _TEST_COUNT_RE.search(claim)
        assert m is not None, f"{claim!r} is a test-count claim the guard cannot see"
        assert m.group(1) == count
    for not_a_claim in (
        "99 test files",  # stays two digits — out of this widening's scope
        "a broader test harness",
        "the testsuite ran clean",
    ):
        assert _TEST_COUNT_RE.search(not_a_claim) is None, (
            f"{not_a_claim!r} is not a test-count claim, but the guard reads one"
        )
