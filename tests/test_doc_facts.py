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

import ast
import importlib.util
import re
import sys
import sysconfig
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


# --- The two badge figures that nothing derived -------------------------------------
#
# `_svg_self_disagreements` above pins that the badge agrees with ITSELF, and it caught a
# real 600-unit drift. But self-consistency is not truth. Three of the badge's five figures
# are checked against code elsewhere in this file -- the check count against CATALOG, the
# attack-chain count against the RISK engine, the test count against the collected suite --
# and two were checked against nothing at all:
#
#     "0 dependencies"    "0 network calls"
#
# Those two are the badge's load-bearing claims. They restate CLAUDE.md's stdlib-only
# constraint and Golden Rule #1 (local-only, forever), which is the whole reason a reader
# is asked to run a security tool against their own agent config. Until this section they
# rested on someone having typed a zero and never revisited it: one `import requests`, or
# one `urllib.request`, and every guard in this file would still have gone green while the
# badge went on promising zero.
#
# Same direction as the rest of the module: truth is DERIVED FROM THE TREE, the badge is
# asserted against it. Each guard has a negative control that feeds it synthetic sources,
# so nothing here needs to mutate the repository to prove it bites.

_PACKAGE = REPO / "clawseccheck"

# Stdlib modules that only EXIST on another platform, so `find_spec` cannot resolve them
# here. Naming them beats letting the running platform decide what counts as a dependency:
# on a Linux CI leg `winreg` (imported twice, for the Windows host checks) is unresolvable
# and would be reported as third-party; on Windows the same would happen to fcntl/grp/pwd.
_PLATFORM_STDLIB = frozenset({
    "winreg", "msvcrt", "fcntl", "grp", "pwd", "termios", "posix", "nt",
})

# Modules that perform network I/O. `urllib.parse` is deliberately ABSENT -- it parses
# strings and opens nothing, and it is the only urllib this package imports (ten files).
# `socket` is absent for a different reason: it is imported once, purely for inet_aton /
# inet_ntoa address conversion, so it is policed by ATTRIBUTE below rather than by import.
_NETWORK_MODULES = frozenset({
    "aiohttp", "asyncio", "ftplib", "http", "httplib2", "httpx", "imaplib", "nntplib",
    "poplib", "requests", "smtplib", "socketserver", "ssl", "telnetlib", "urllib3",
    "urllib.error", "urllib.request", "webbrowser", "xmlrpc",
})

# The only `socket` names that convert an address. Anything else -- socket(), connect(),
# create_connection(), getaddrinfo() -- reaches the network or a resolver and must not
# appear in a tool whose badge says zero.
_SOCKET_ADDRESS_ONLY = frozenset({
    "inet_aton", "inet_ntoa", "inet_pton", "inet_ntop",
    "htons", "htonl", "ntohs", "ntohl",
    "AF_INET", "AF_INET6", "error",
})

_SPAWN_ATTRS = {
    "subprocess": {"run", "Popen", "call", "check_call", "check_output", "getoutput",
                   "getstatusoutput"},
    "os": {"system", "popen", "execv", "execve", "execvp", "execvpe", "spawnv", "spawnve",
           "spawnl", "spawnlp", "posix_spawn", "posix_spawnp", "fork", "forkpty"},
}


def _package_sources():
    """`(repo-relative path, source)` for every shipped module.

    Returned rather than walked in place so each guard below can be pointed at synthetic
    sources by its own negative control, instead of mutating the tree to prove it bites.
    """
    return [
        (str(p.relative_to(REPO)), p.read_text(encoding="utf-8"))
        for p in sorted(_PACKAGE.rglob("*.py"))
    ]


def _imported_modules(sources):
    """`[(dotted module, file)]` for every ABSOLUTE import in *sources*.

    A relative import is this package importing itself and is skipped. `from urllib.parse
    import urlparse` yields both `urllib.parse` and `urllib.parse.urlparse`, so a ban list
    can name a submodule (`urllib.request`) without also banning its parent.
    """
    out = []
    for name, text in sources:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    out.append((alias.name, name))
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue
                module = node.module or ""
                if not module:
                    continue
                out.append((module, name))
                for alias in node.names:
                    out.append((f"{module}.{alias.name}", name))
    return out


def _is_stdlib(top: str) -> bool:
    if top in _PLATFORM_STDLIB or top in sys.builtin_module_names or top == "__future__":
        return True
    try:
        spec = importlib.util.find_spec(top)
    except (ImportError, ValueError):
        return False
    if spec is None:
        return False
    origin = spec.origin or ""
    if origin in ("built-in", "frozen"):
        return True
    if not origin:
        return False
    paths = sysconfig.get_paths()
    where = Path(origin).resolve()
    # site-packages lives UNDER the stdlib prefix, so it has to be excluded first or every
    # third-party package would answer "yes, I am stdlib".
    for key in ("purelib", "platlib"):
        if key in paths and where.is_relative_to(Path(paths[key]).resolve()):
            return False
    return where.is_relative_to(Path(paths["stdlib"]).resolve())


def _third_party_imports(sources=None):
    """Top-level module names this package imports that are not in the standard library."""
    sources = _package_sources() if sources is None else sources
    tops = {m.split(".")[0] for m, _ in _imported_modules(sources) if m != "clawseccheck"}
    return sorted(t for t in tops if t and not _is_stdlib(t))


def _declared_runtime_dependencies():
    """The `[project] dependencies` array from pyproject.toml.

    Parsed by hand because `tomllib` is 3.11+ and the CI floor is 3.9 -- and adding a TOML
    library to read the file that proves there are no libraries would be its own joke.
    """
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    body = re.search(r"^\[project\]\s*$(.*?)^\[", text, re.S | re.M)
    section = body.group(1) if body else text
    array = re.search(r"^dependencies\s*=\s*\[(.*?)\]", section, re.S | re.M)
    if not array:
        return []
    return [item for item in re.findall(r'"([^"]+)"', array.group(1)) if item.strip()]


def _network_surfaces(sources=None):
    """Every construct in *sources* through which this package could reach the network."""
    sources = _package_sources() if sources is None else sources
    out = []
    for module, where in _imported_modules(sources):
        for banned in _NETWORK_MODULES:
            if module == banned or module.startswith(banned + "."):
                out.append(f"{where} imports {module}")
                break
    for name, text in sources:
        tree = ast.parse(text)
        imported_socket = any(
            isinstance(n, ast.Import) and any(a.name == "socket" for a in n.names)
            for n in ast.walk(tree)
        )
        for node in ast.walk(tree):
            if (
                imported_socket
                and isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "socket"
                and node.attr not in _SOCKET_ADDRESS_ONLY
            ):
                out.append(f"{name}:{node.lineno} uses socket.{node.attr}")
            elif isinstance(node, ast.ImportFrom) and node.module == "socket":
                for alias in node.names:
                    if alias.name not in _SOCKET_ADDRESS_ONLY:
                        out.append(f"{name}:{node.lineno} imports socket.{alias.name}")
    return sorted(set(out))


def _spawn_sites(sources=None):
    """`(file, line, [literal argv strings])` for every place this package starts a program."""
    sources = _package_sources() if sources is None else sources
    out = []
    for name, text in sources:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)):
                continue
            if func.attr not in _SPAWN_ATTRS.get(func.value.id, ()):
                continue
            argv = []
            for arg in node.args:
                if isinstance(arg, (ast.List, ast.Tuple)):
                    argv += [e.value for e in arg.elts
                             if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    argv.append(arg.value)
            out.append((name, node.lineno, argv))
    return sorted(out)


def _badge_figures():
    """`{stat phrase: figure}` read off a badge's aria-label."""
    svg = (REPO / "docs" / "assets" / "stats-light.svg").read_text(encoding="utf-8")
    label = _SVG_LABEL_RE.search(svg)
    assert label, "badge has no aria-label"
    out = {}
    for segment in label.group(1).split(" - "):
        m = re.match(r"([\d,]+)\s+(.+)", segment.strip())
        if m:
            out[m.group(2).strip().lower()] = int(m.group(1).replace(",", ""))
    return out


def test_the_zero_dependencies_figure_is_derived_from_the_tree():
    """The badge's dependency count must equal what the tree actually pulls in.

    Two independent sources, because either alone can lie: `pyproject.toml` can declare
    nothing while a module imports a package the developer happens to have installed, and
    an import audit alone would miss a dependency declared for the installer's benefit.
    """
    declared = _declared_runtime_dependencies()
    third_party = _third_party_imports()
    real = len(declared) + len(third_party)
    figure = _badge_figures().get("dependencies")
    assert figure is not None, "badge no longer states a dependency count"
    assert real == figure, (
        f"badge claims {figure} dependencies but the tree has {real}: "
        f"declared={declared}, imported={third_party}"
    )


def test_the_dependency_guard_bites_on_a_third_party_import():
    """Guard the guard. A zero that cannot go non-zero is decoration, not a check."""
    assert _third_party_imports() == [], "the real package must start clean"
    planted = _third_party_imports([
        ("clawseccheck/_synthetic.py", "import requests\nfrom yaml import safe_load\n"),
    ])
    assert planted == ["requests", "yaml"], planted
    # …and a stdlib-only file of the same shape must stay silent, or the guard is just
    # reporting every import it sees.
    assert _third_party_imports([
        ("clawseccheck/_synthetic.py", "import json\nfrom urllib.parse import urlparse\n"),
    ]) == []


def test_the_zero_network_calls_figure_is_derived_from_the_tree():
    """The badge's network-call count must equal the reachable network surfaces.

    Scope, stated rather than implied: this is an audit of what the PACKAGE does. It cannot
    speak for a program the package spawns, which is why the single spawn site is pinned
    separately below.
    """
    surfaces = _network_surfaces()
    figure = _badge_figures().get("network calls")
    assert figure is not None, "badge no longer states a network-call count"
    assert len(surfaces) == figure, (
        f"badge claims {figure} network calls but the tree has {len(surfaces)}:\n  "
        + "\n  ".join(surfaces)
    )


def test_the_network_guard_bites_on_an_import_and_on_a_socket_that_connects():
    """Guard the guard, in both directions.

    The socket half matters most: `socket` IS imported by this package, for inet_aton and
    inet_ntoa, so a ban on the import would have to be lifted and the whole module would go
    unwatched. Policing the attribute keeps the address conversion and still catches a
    connect() added beside it.
    """
    assert _network_surfaces() == [], "the real package must start clean"

    by_import = _network_surfaces([
        ("clawseccheck/_synthetic.py",
         "import urllib.request\nfrom http.client import HTTPSConnection\n"),
    ])
    assert len(by_import) == 3, by_import

    by_attribute = _network_surfaces([
        ("clawseccheck/_synthetic.py",
         "import socket\n"
         "def f(host):\n"
         "    s = socket.socket(socket.AF_INET)\n"
         "    s.connect((host, 443))\n"
         "    return socket.inet_ntoa(socket.inet_aton(host))\n"),
    ])
    assert any("socket.socket" in s for s in by_attribute), by_attribute
    assert not any("inet_aton" in s or "inet_ntoa" in s or "AF_INET" in s
                   for s in by_attribute), by_attribute

    assert _network_surfaces([
        ("clawseccheck/_synthetic.py",
         "import socket\nfrom urllib.parse import urlparse\n"
         "def f(x):\n    return socket.inet_aton(x)\n"),
    ]) == []


def test_the_only_program_this_package_spawns_is_the_users_own_openclaw_cli():
    """"0 network calls" is an import-level claim, and an import audit cannot see a network
    call made by a program we START. So the one place this package starts anything is pinned
    by argv shape: `openclaw security audit --json`, the user's own already-installed CLI
    reading their own machine.

    A second spawn site, or a changed argv, reddens the build -- which is the point. It
    forces whoever adds it to re-examine the badge's promise rather than inherit it.
    """
    sites = _spawn_sites()
    assert len(sites) == 1, "\n".join(f"{f}:{ln} argv={argv}" for f, ln, argv in sites)
    where, _, argv = sites[0]
    assert where == "clawseccheck/native.py", where
    assert argv == ["security", "audit", "--json"], argv


def test_the_spawn_guard_bites_on_a_second_call_site():
    """Guard the guard: the assertion above is `== 1`, so it must be shown to reach 2."""
    planted = _spawn_sites([
        ("clawseccheck/_synthetic.py",
         "import subprocess, os\n"
         "def f():\n"
         "    subprocess.run(['curl', 'https://example.invalid'])\n"
         "    os.system('wget https://example.invalid')\n"),
    ])
    assert len(planted) == 2, planted
    assert planted[0][2] == ["curl", "https://example.invalid"], planted


# A static import audit is only as complete as the absence of a dynamic one. `_is_stdlib`
# can classify every name it is handed and still miss a dependency loaded by string.
_DYNAMIC_IMPORT_CALLS = {"import_module", "__import__", "find_spec", "module_from_spec"}

# Programs whose whole job is to reach the network. This package spawns exactly one thing
# today; the ban exists for the site nobody has added yet, so that adding it collides with
# the badge instead of quietly outdating it.
_NETWORK_CLIENT_BINARIES = frozenset({
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "ftp",
    "telnet", "rsync", "git", "pip", "npm", "npx", "openssl",
})


def _dynamic_import_sites(sources=None):
    """Every construct that could load a module whose name is not in the source text.

    Written against the AST rather than by grep on purpose: this package is a scanner, so
    `"importlib"` and `exec(...)` appear all over it as DETECTION SIGNATURES -- string
    literals naming what a malicious skill does. A grep reports those and is useless; an
    AST walk sees that a string constant is not an import.
    """
    sources = _package_sources() if sources is None else sources
    out = []
    for name, text in sources:
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "importlib":
                        out.append(f"{name}:{node.lineno} imports {alias.name}")
            elif isinstance(node, ast.ImportFrom) and not node.level:
                if (node.module or "").split(".")[0] == "importlib":
                    out.append(f"{name}:{node.lineno} imports from {node.module}")
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "__import__":
                    out.append(f"{name}:{node.lineno} calls __import__()")
                elif isinstance(func, ast.Attribute) and func.attr in _DYNAMIC_IMPORT_CALLS:
                    out.append(f"{name}:{node.lineno} calls .{func.attr}()")
    return sorted(set(out))


def test_the_import_audit_is_complete_because_nothing_imports_by_string():
    """What makes the two guards above trustworthy, rather than merely green.

    `_imported_modules` walks the whole AST, so a lazy import inside a function is already
    covered -- and that is not academic here: `report.py` alone carries 27 of them. What a
    static walk genuinely cannot see is a module named by a runtime string. So the claim is
    closed from the other end: this package contains no dynamic-import construct at all,
    which makes the static list exhaustive rather than merely long.
    """
    assert _dynamic_import_sites() == [], (
        "a dynamic import makes the dependency audit incomplete:\n  "
        + "\n  ".join(_dynamic_import_sites())
    )


def test_the_dynamic_import_guard_bites_and_ignores_detection_signatures():
    """Guard the guard, in both directions -- the second half is the load-bearing one.

    This module lists `"importlib"` as a dangerous name a scanned skill might use, and
    `catalog.py` describes `exec()/eval()` payload loaders in plain prose. A guard that
    reported those would be untrustworthy noise on day one and would be deleted by day two.
    """
    planted = _dynamic_import_sites([
        ("clawseccheck/_synthetic.py",
         "import importlib\n"
         "def f(name):\n"
         "    __import__(name)\n"
         "    return importlib.import_module(name)\n"),
    ])
    assert len(planted) == 3, planted

    assert _dynamic_import_sites([
        ("clawseccheck/_synthetic.py",
         '_DANGEROUS = ["importlib", "__import__", "marshal"]\n'
         'NOTE = "payload executed via exec()/eval() after import_module()"\n'),
    ]) == []


def test_no_spawn_site_starts_a_network_client():
    """The other half of the spawn claim: not just how many, but WHAT.

    "subprocess is imported" is not "there is a network call" -- the same distinction that
    makes `socket` in `_egress.py` harmless, since it only converts addresses. So the
    binaries are named. Today the single site runs the user's own `openclaw`; a future site
    running `curl` would be the badge's claim going false, not this guard being incomplete.
    """
    offenders = []
    for where, line, argv in _spawn_sites():
        for word in argv:
            if Path(word).name in _NETWORK_CLIENT_BINARIES:
                offenders.append(f"{where}:{line} runs {word}")
    assert not offenders, "\n  ".join(offenders)

    planted = [
        f"{w}:{ln} runs {word}"
        for w, ln, argv in _spawn_sites([
            ("clawseccheck/_synthetic.py",
             "import subprocess\n"
             "def f():\n"
             "    subprocess.run(['/usr/bin/curl', '-fsSL', 'https://example.invalid'])\n"),
        ])
        for word in argv
        if Path(word).name in _NETWORK_CLIENT_BINARIES
    ]
    assert len(planted) == 1, planted


# `_TEST_COUNT_RE` and friends above cover the countable claims that were rotting at the
# time they were written -- check counts, test counts, the RISK range, the release stamp.
# They are not a general rule, and a claim outside the shapes they know is exactly as
# unguarded as those were. This one was: OUTPUT_SCHEMA.md said "the five not-ran statuses"
# while `layers.INCOMPLETE_LAYER_STATUSES` held six.
#
# The drift is worth reading, because it is not the usual kind. The row's own TABLE CELL
# enumerated all seven statuses correctly; only the prose beside it undercounted, so the
# figure and the list it summarises disagreed inside one sentence. And it was not the last
# commit's mistake either: `aa68205^` already said "the four not-ran statuses" while
# `STATUS_NOT_REACHED` already existed, so B-603 added one for the status it introduced and
# inherited an off-by-one that was older than it.
_NUMBER_WORDS = {
    "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10,
}
_NOT_RAN_COUNT_RE = re.compile(r"\bthe\s+([a-z]+)\s+not-ran statuses\b", re.IGNORECASE)


def test_not_ran_status_counts_match_the_layer_ledger():
    """Any doc that counts the not-ran layer statuses must agree with `layers.py`.

    Derived, not pinned: the truth is `len(INCOMPLETE_LAYER_STATUSES)`, so adding a seventh
    status reddens the prose that undercounts it instead of leaving the doc to be corrected
    by whoever next happens to read both.
    """
    from clawseccheck.layers import INCOMPLETE_LAYER_STATUSES

    truth = len(INCOMPLETE_LAYER_STATUSES)
    wrong = []
    for path in _shipped_files():
        text = path.read_text(encoding="utf-8")
        for m in _NOT_RAN_COUNT_RE.finditer(text):
            word = m.group(1).lower()
            claimed = _NUMBER_WORDS.get(word)
            line = text[: m.start()].count("\n") + 1
            where = f"{path.relative_to(REPO)}:{line}"
            if claimed is None:
                wrong.append(f"{where} counts the not-ran statuses as {word!r}, not a number")
            elif claimed != truth:
                wrong.append(f"{where} says {word} ({claimed}) not-ran statuses, code has {truth}")
    assert not wrong, "not-ran status counts drifted:\n  " + "\n  ".join(wrong)


def test_every_layer_status_is_named_in_the_output_schema():
    """A count alone is half a claim -- six is still wrong if it summarises the wrong six.

    So the names are pinned too: a consumer reading OUTPUT_SCHEMA.md to build against
    `missing_layers[].status` must find every value the code can actually emit.
    """
    from clawseccheck.layers import LAYER_STATUSES

    schema = (REPO / "docs" / "OUTPUT_SCHEMA.md").read_text(encoding="utf-8")
    missing = sorted(s for s in LAYER_STATUSES if f"`{s}`" not in schema)
    assert not missing, f"layer statuses the output schema never names: {missing}"


def test_the_not_ran_count_guard_bites():
    """Guard the guard, on the exact sentence that was wrong."""
    truth = 6
    assert _NUMBER_WORDS["six"] == truth, "update this control if the ledger grows"
    m = _NOT_RAN_COUNT_RE.search("…and the five not-ran statuses are deliberately distinct:")
    assert m is not None and _NUMBER_WORDS[m.group(1)] != truth
    m = _NOT_RAN_COUNT_RE.search("…and the six not-ran statuses are deliberately distinct:")
    assert m is not None and _NUMBER_WORDS[m.group(1)] == truth
    assert _NOT_RAN_COUNT_RE.search("statuses that did not run are listed above") is None
