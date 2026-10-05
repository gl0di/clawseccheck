"""C-649 - B33 against the advisories the vendor had published and the table did not hold.

Until 2026-10-05 the table ended at 2026.6.6, so every build from 2026.6.6 up read as "at or past
all known-advisory fixes" while the vendor's repository endpoint listed 70 published advisories on
the core package that reach them (9 published 2026-06-30, 61 published 2026-09-11). This file pins:

* the table: 95 rows, the batch's ranges encoded faithfully (checked against the published range
  strings below, evaluated by a small comparator written HERE - not by the check's own matcher),
  the two side tables (lower bounds, the one exact-build row);
* the per-build verdict: every published final from 2026.6.5 to 2026.9.8, the two 2026.7.1
  correction releases and the nine extended-stable builds;
* the range shapes (`<`, `<=`, `=`, `>= , <`, the exact build) and the lower bounds;
* the extended-stable rule (PASS / FAIL naming only confirmed advisories / UNKNOWN);
* which version is judged: the installed build when the audited home is this machine's own home,
  otherwise the config stamp - every cell of the truth table in `check_known_vulns`'s docstring;
* the unchanged wording (stamp-only PASS / FAIL / UNKNOWN texts, byte for byte).

Hermetic: no network, nothing outside `tmp_path`, no dependence on what is installed on the
machine running the suite (`HOME` and every `OPENCLAW_*` path variable are controlled).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import _KNOWN_ADVISORIES, _lifecycle, _parse_version, check_known_vulns
from clawseccheck.collector import Context

# ---------------------------------------------------------------------------
# The published ranges, verbatim from the vendor's repository advisory endpoint (npm package
# `openclaw`, every advisory whose range reaches 2026.6.6 or later) - GENERATED from the saved
# dump, not typed.
# ---------------------------------------------------------------------------
_PUBLISHED = (  # (advisory id, vulnerable_version_range, first stable patched version)
    ("GHSA-jhfx-v2j8-x3m6", "<= 2026.6.6", "2026.6.8"),
    ("GHSA-3fp5-v549-9v66", "<= 2026.6.6", "2026.6.9"),
    ("GHSA-3pmr-x9g8-m55r", "= 2026.6.6", "2026.6.9"),
    ("GHSA-7vrr-rp4x-4g76", ">= 2026.5.20, < 2026.6.9", "2026.6.9"),
    ("GHSA-f6p7-6326-vf7v", "< 2026.6.9", "2026.6.9"),
    ("GHSA-m38g-vpwj-mpg9", "<= 2026.6.6", "2026.6.9"),
    ("GHSA-mm9g-83wh-mhwj", ">= 2026.6.1, < 2026.6.9", "2026.6.9"),
    ("GHSA-v7hx-r36p-f68m", "= 2026.6.6", "2026.6.9"),
    ("GHSA-wgq8-x5wm-g4rw", ">= 2026.6.5, < 2026.6.9", "2026.6.9"),
    ("GHSA-224w-vfr9-h35c", ">= 2026.5.1 < 2026.7.1", "2026.7.1"),
    ("GHSA-22v4-33m3-8p7m", ">= 2026.4.10 < 2026.7.1", "2026.7.1"),
    ("GHSA-4hwv-rj92-h7rp", "< 2026.7.1", "2026.7.1"),
    ("GHSA-4wvr-f35r-f8w4", "< 2026.7.1", "2026.7.1"),
    ("GHSA-5j27-v2pw-cj9m", "< 2026.7.1", "2026.7.1"),
    ("GHSA-89cw-7452-cfrf", "< 2026.7.1", "2026.7.1"),
    ("GHSA-8xxh-v4vc-qvm4", "< 2026.7.1", "2026.7.1"),
    ("GHSA-9p6m-2872-xm7x", "< 2026.7.1", "2026.7.1"),
    ("GHSA-9x88-f7rh-4c83", "< 2026.7.1", "2026.7.1"),
    ("GHSA-crg9-c62w-j2p5", "< 2026.7.1", "2026.7.1"),
    ("GHSA-jghr-xp78-995p", "< 2026.7.1", "2026.7.1"),
    ("GHSA-p5g8-m35v-7m82", "< 2026.7.1", "2026.7.1"),
    ("GHSA-pjjr-5qhr-5w6r", "< 2026.7.1", "2026.7.1"),
    ("GHSA-q9j5-4xr6-xqqw", "< 2026.7.1", "2026.7.1"),
    ("GHSA-qw7m-h363-33qw", "< 2026.7.1", "2026.7.1"),
    ("GHSA-r88x-r7jj-f2cf", "< 2026.7.1", "2026.7.1"),
    ("GHSA-rgjw-6v73-php6", ">= 2026.2.26 < 2026.7.1", "2026.7.1"),
    ("GHSA-wwx7-573h-pqwc", "< 2026.7.1", "2026.7.1"),
    ("GHSA-xw9g-7xvv-gcjc", "< 2026.7.1", "2026.7.1"),
    ("GHSA-356g-m7rx-7pm3", "= 2026.7.1-2", "2026.8.1"),
    ("GHSA-39hf-qg99-f4qv", "< 2026.8.1", "2026.8.1"),
    ("GHSA-3mq7-q27j-mq7q", "< 2026.8.1", "2026.8.1"),
    ("GHSA-4g58-43jr-6738", "< 2026.8.1", "2026.8.1"),
    ("GHSA-4r25-35qc-fr6j", "< 2026.8.1", "2026.8.1"),
    ("GHSA-5fwv-rrvp-8xvr", "< 2026.8.1", "2026.8.1"),
    ("GHSA-5m4g-88rg-69pj", "< 2026.8.1", "2026.8.1"),
    ("GHSA-5mrc-77hj-xjxv", ">= 2026.3.28, < 2026.8.1", "2026.8.1"),
    ("GHSA-5rx7-34fw-64qg", "< 2026.8.1", "2026.8.1"),
    ("GHSA-62qm-6fjj-6g23", ">= 2026.4.5, < 2026.8.1", "2026.8.1"),
    ("GHSA-66hm-hxq3-5pfh", ">= 2026.3.28, < 2026.8.1", "2026.8.1"),
    ("GHSA-6xpv-wwr5-265h", ">= 2026.5.28, < 2026.8.1", "2026.8.1"),
    ("GHSA-72p2-79fg-pvph", "< 2026.8.1", "2026.8.1"),
    ("GHSA-74gc-hg2m-79p9", "< 2026.8.1", "2026.8.1"),
    ("GHSA-7cp7-87pj-p32v", "< 2026.8.1", "2026.8.1"),
    ("GHSA-7jfq-rmfm-29wp", "< 2026.8.1", "2026.8.1"),
    ("GHSA-8938-r7c6-54vq", "< 2026.8.1", "2026.8.1"),
    ("GHSA-9f86-pvv5-rxfw", "< 2026.8.1", "2026.8.1"),
    ("GHSA-cf95-m4jv-59rc", ">= 2026.7.1, < 2026.8.1", "2026.8.1"),
    ("GHSA-chr6-w4m5-57fv", "< 2026.8.1", "2026.8.1"),
    ("GHSA-fphf-69cp-h5xw", "< 2026.8.1", "2026.8.1"),
    ("GHSA-fvxr-9g24-x3hf", "< 2026.8.1", "2026.8.1"),
    ("GHSA-fw6q-2frm-jxxr", ">= 2026.3.25, < 2026.8.1", "2026.8.1"),
    ("GHSA-g24w-m94m-59qc", "< 2026.8.1", "2026.8.1"),
    ("GHSA-g697-vv6h-r8hv", ">= 2026.5.12, < 2026.8.1", "2026.8.1"),
    ("GHSA-ghpx-6xwq-2w4w", ">= 2026.3.22, < 2026.8.1", "2026.8.1"),
    ("GHSA-h9jh-75j7-7hhx", ">= 2026.6.9, < 2026.8.1", "2026.8.1"),
    ("GHSA-hpg5-cq3m-phqp", "< 2026.8.1", "2026.8.1"),
    ("GHSA-j4mm-p864-vx7f", "< 2026.8.1", "2026.8.1"),
    ("GHSA-mm7m-wcgh-8mfq", ">= 2026.5.2, < 2026.8.1", "2026.8.1"),
    ("GHSA-p3h6-v2h4-36q2", ">= 2026.4.5, < 2026.8.1", "2026.8.1"),
    ("GHSA-pfrw-r5vr-89hw", ">= 2026.4.25, < 2026.8.1", "2026.8.1"),
    ("GHSA-qgj5-6x35-9g6f", "< 2026.8.1", "2026.8.1"),
    ("GHSA-rm45-4jx5-2927", "< 2026.8.1", "2026.8.1"),
    ("GHSA-vhpg-cq3w-v8p9", "< 2026.8.1", "2026.8.1"),
    ("GHSA-w5x7-c87m-3jpc", "< 2026.8.1", "2026.8.1"),
    ("GHSA-wjfv-5qch-m5vj", "< 2026.8.1", "2026.8.1"),
    ("GHSA-wwcw-jfpp-gpxw", "< 2026.8.1", "2026.8.1"),
    ("GHSA-xw48-j584-r73h", ">= 2026.6.6, < 2026.8.1", "2026.8.1"),
    ("GHSA-xx9p-hc9w-6p5h", "< 2026.8.1", "2026.8.1"),
    ("GHSA-m78m-7h3q-q938", "< 2026.8.2", "2026.8.2"),
    ("GHSA-5x6q-wg56-rxg8", ">= 2026.7.2, < 2026.9.2", "2026.9.2"),
)

_EXACT_ID = "GHSA-356g-m7rx-7pm3"  # the only exact-build range: `= 2026.7.1-2`
_NOT_AFFECTED_ID = "GHSA-5x6q-wg56-rxg8"  # `>= 2026.7.2, < 2026.9.2`; back-ported on the 2026.8 line
_OLD_TABLE_LEN = 25  # rows that predate the batch: ids[24] is CVE-2026-62195, fixed 2026.6.6
_GENERIC_FIX = "Keep OpenClaw updated and re-check after new advisories are published."


def _vkey(v: str) -> tuple:
    """Vendor ordering for the shapes that occur: a correction release `X-N` sorts just ABOVE its
    base `X` (and below the next version). Deliberately NOT `_parse_version`, which collapses them."""
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-(\d+))?", v.strip())
    assert m, v
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0))


def _in_range(version: str, rng: str) -> bool:
    clauses = re.findall(r"(<=|>=|<|>|=)\s*(\d+\.\d+\.\d+(?:-\d+)?)", rng)
    assert clauses, rng
    v = _vkey(version)
    for op, bound in clauses:
        b = _vkey(bound)
        if not {"<": v < b, "<=": v <= b, ">=": v >= b, ">": v > b, "=": v == b}[op]:
            return False
    return True


def _published_ids(version: str) -> set:
    """Ids of the published ranges that contain *version* (numerically; no extended-stable rule)."""
    return {i for i, rng, _fixed in _PUBLISHED if _in_range(version, rng)}


def _shape(rng: str):
    """(max_vulnerable tuple, first_vulnerable tuple | None, exact build | None) for one range."""
    hi = lo = exact = None
    for op, y, m, p, corr in re.findall(r"(<=|>=|<|>|=)\s*(\d+)\.(\d+)\.(\d+)(?:-(\d+))?", rng):
        t = (int(y), int(m), int(p))
        if op == "<":
            hi = (t[0], t[1], t[2] - 1)
        elif op == "<=":
            hi = t
        elif op == ">=":
            lo = t
        elif op == "=":
            lo = hi = t
            exact = f"{y}.{m}.{p}-{corr}" if corr else None
        else:
            raise AssertionError(rng)
    return hi, lo, exact


def _stamp_ctx(version) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = {} if version is None else {"meta": {"lastTouchedVersion": version}}
    return c


@pytest.fixture
def all_ids(monkeypatch):
    """Lift the evidence cap so a result names EVERY matched id (the cap is a presentation limit)."""
    monkeypatch.setattr(_lifecycle, "_B33_EVIDENCE_CAP", 10_000)


def _ids(version) -> list:
    return list(check_known_vulns(_stamp_ctx(version)).evidence)


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------

def test_table_has_95_unique_plain_rows_and_the_batch_is_exactly_the_published_70():
    ids = [row[0] for row in _KNOWN_ADVISORIES]
    assert len(_KNOWN_ADVISORIES) == 95
    assert len(set(ids)) == 95
    assert all(len(row) == 4 for row in _KNOWN_ADVISORIES), "the batch adds plain 4-tuples only"
    assert ids[_OLD_TABLE_LEN - 1] == "CVE-2026-62195"
    assert set(ids[_OLD_TABLE_LEN:]) == {i for i, _r, _f in _PUBLISHED}
    assert len(_PUBLISHED) == 70
    for row in _KNOWN_ADVISORIES:
        assert isinstance(row[3], str) and row[3].strip(), row[0]
    for row in _KNOWN_ADVISORIES[_OLD_TABLE_LEN:]:
        assert row[3].isascii(), row[0]  # the batch's titles are plain ASCII, as published


def test_every_batch_row_encodes_its_published_range_and_fix():
    rows = {row[0]: row for row in _KNOWN_ADVISORIES}
    for ident, rng, fixed in _PUBLISHED:
        hi, lo, exact = _shape(rng)
        row = rows[ident]
        assert row[1] == hi, (ident, rng, row[1])
        assert row[2] == fixed, ident
        assert _lifecycle._ADVISORY_FIRST_VULNERABLE.get(ident) == lo, (ident, rng)
        want_exact = frozenset({exact}) if exact else None
        assert _lifecycle._ADVISORY_EXACT_BUILDS.get(ident) == want_exact, (ident, rng)
        # the boundary sits strictly below the fix: no row can FAIL the build that fixed it
        assert _parse_version(fixed) > row[1], ident


def test_side_tables_are_keyed_by_table_ids_and_their_bounds_are_sane():
    rows = {row[0]: row for row in _KNOWN_ADVISORIES}
    first = _lifecycle._ADVISORY_FIRST_VULNERABLE
    exact = _lifecycle._ADVISORY_EXACT_BUILDS
    assert len(first) == 23
    for ident, lo in first.items():
        assert ident in rows, ident
        assert lo <= rows[ident][1], f"{ident}: first_vulnerable {lo} above max_vulnerable"
    assert set(exact) == {_EXACT_ID}
    assert exact[_EXACT_ID] == frozenset({"2026.7.1-2"})
    # the base and the first correction release must NOT be in the set
    assert "2026.7.1" not in exact[_EXACT_ID] and "2026.7.1-1" not in exact[_EXACT_ID]


def test_extended_stable_data_refers_to_table_ids():
    ids = {row[0] for row in _KNOWN_ADVISORIES}
    assert _lifecycle._EXTENDED_STABLE_MIN_PATCH == 33
    assert _lifecycle._EXTENDED_STABLE_NOT_AFFECTED <= ids
    assert set(_lifecycle._EXTENDED_STABLE_LINES) == {(2026, 6), (2026, 7), (2026, 8)}
    for (_year, _minor), (newest, confirmed) in _lifecycle._EXTENDED_STABLE_LINES.items():
        assert newest == 35
        assert set(confirmed) <= ids
        assert len(set(confirmed)) == len(confirmed)
        assert not set(confirmed) & _lifecycle._EXTENDED_STABLE_NOT_AFFECTED


def test_the_correction_release_rule_still_holds_for_every_row():
    """The mechanized half of the warning above the table (also in test_b33.py): no row's
    max_vulnerable tuple is the base tuple of its own fixed version."""
    for ident, max_vuln, fixed, *_rest in _KNOWN_ADVISORIES:
        assert _parse_version(fixed) != max_vuln, ident


# ---------------------------------------------------------------------------
# Per-build verdicts: (version, status, number of ids, `fix` target)
# ---------------------------------------------------------------------------

_MAINLINE = [
    ("2026.6.5", FAIL, 64, "2026.9.2"),  # 63 published ranges + the older CVE-2026-62195 row
    ("2026.6.6", FAIL, 66, "2026.9.2"),
    ("2026.6.8", FAIL, 61, "2026.9.2"),
    ("2026.6.9", FAIL, 58, "2026.9.2"),
    ("2026.6.10", FAIL, 58, "2026.9.2"),
    ("2026.6.11", FAIL, 58, "2026.9.2"),
    ("2026.7.1", FAIL, 40, "2026.9.2"),
    ("2026.8.1", FAIL, 2, "2026.9.2"),
    ("2026.8.2", FAIL, 1, "2026.9.2"),
    ("2026.9.1", FAIL, 1, "2026.9.2"),
    ("2026.9.2", PASS, 0, None),
    ("2026.9.3", PASS, 0, None),
    ("2026.9.4", PASS, 0, None),
    ("2026.9.5", PASS, 0, None),
    ("2026.9.6", PASS, 0, None),
    ("2026.9.7", PASS, 0, None),
    ("2026.9.8", PASS, 0, None),
]
_CORRECTIONS = [
    ("2026.7.1-1", FAIL, 40, "2026.9.2"),  # same id set as the base ...
    ("2026.7.1-2", FAIL, 41, "2026.9.2"),  # ... plus the exact-build row
]
_EXTENDED = [
    ("2026.6.33", FAIL, 2, "2026.9.2"),
    ("2026.6.34", FAIL, 2, "2026.9.2"),
    ("2026.6.35", FAIL, 2, "2026.9.2"),
    ("2026.7.33", FAIL, 3, "2026.9.2"),
    ("2026.7.34", FAIL, 3, "2026.9.2"),
    ("2026.7.35", FAIL, 3, "2026.9.2"),
    ("2026.8.33", PASS, 0, None),
    ("2026.8.34", PASS, 0, None),
    ("2026.8.35", PASS, 0, None),
]


def _n_and_target(result):
    m = re.search(r"affected by (\d+) known", result.detail)
    t = re.search(r">=\s*(\S+?)\s+to remediate", result.fix)
    return (int(m.group(1)) if m else 0), (t.group(1) if t else None)


@pytest.mark.parametrize("version,status,n,target", _MAINLINE + _CORRECTIONS + _EXTENDED)
def test_verdict_for_every_published_build(version, status, n, target):
    result = check_known_vulns(_stamp_ctx(version))
    assert result.status == status
    assert _n_and_target(result) == (n, target)
    if status == PASS:
        assert result.detail == f"OpenClaw {version} is at or past all known-advisory fixes."


@pytest.mark.parametrize("version,status,n,_target", _MAINLINE + _CORRECTIONS)
def test_counts_agree_with_the_published_ranges_for_every_non_extended_build(version, status, n, _target):
    """Cross-check that does not use the check's matcher: the number of published ranges that
    contain the build. 2026.6.5 additionally matches one older row (CVE-2026-62195)."""
    older_rows = 1 if version == "2026.6.5" else 0
    assert len(_published_ids(version)) + older_rows == n


@pytest.mark.parametrize(
    "version,target", [(v, t) for v, status, _n, t in _MAINLINE + _CORRECTIONS if status == FAIL]
)
def test_the_fix_target_of_an_ordinary_build_clears_the_finding_in_one_step(version, target):
    """Upgrading to the named version must itself PASS - lower bounds trim the id list but never
    the target, so the advice is never a still-vulnerable version (the B-332 treadmill)."""
    assert check_known_vulns(_stamp_ctx(target)).status == PASS


@pytest.mark.parametrize("version,target", [(v, t) for v, status, _n, t in _EXTENDED if status == FAIL])
def test_the_fix_target_of_an_extended_stable_build_clears_the_finding_in_one_step(version, target):
    """The same property for the six extended-stable FAIL builds: the named version, fed back as a
    stamp, is a PASS. It is the highest fixed version over every row that reaches the build, listed or
    not - not the highest among the LISTED ids, which is 2026.8.1 and itself FAILs."""
    assert target == "2026.9.2"
    assert check_known_vulns(_stamp_ctx(target)).status == PASS
    assert check_known_vulns(_stamp_ctx("2026.8.1")).status == FAIL  # what the old, listed-ids-only target was
    assert f">= {target} to remediate" in check_known_vulns(_stamp_ctx(version)).fix


@pytest.mark.parametrize("version", ["2026.6.8", "2026.7.1", "2026.7.1-2", "2026.8.1", "2026.9.1"])
def test_exact_id_set_equals_the_published_ranges(all_ids, version):
    """The full id set for five builds, computed from the published range strings written out
    above with the comparator in this file - not by re-running the table's matcher."""
    result = check_known_vulns(_stamp_ctx(version))
    assert result.status == FAIL
    assert set(result.evidence) == _published_ids(version)
    assert len(result.evidence) == len(set(result.evidence))
    assert f"affected by {len(result.evidence)} known" in result.detail


def test_without_lifting_the_cap_only_the_first_20_ids_are_shown_with_a_truncation_note():
    result = check_known_vulns(_stamp_ctx("2026.6.8"))
    expected = [row[0] for row in _KNOWN_ADVISORIES if row[0] in _published_ids("2026.6.8")]
    assert len(expected) == 61
    assert result.evidence == expected[:20]
    assert result.detail == (
        f"OpenClaw 2026.6.8 is affected by 61 known advisories: {', '.join(expected[:20])} "
        "(showing 20 of 61)."
    )


# ---------------------------------------------------------------------------
# Range shapes and the exact-build row
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "ident,shape,inside,outside",
    [
        ("GHSA-8xxh-v4vc-qvm4", "< 2026.7.1", ["2026.6.11", "2026.6.5"], ["2026.7.1", "2026.7.1-2", "2026.8.1"]),
        ("GHSA-xx9p-hc9w-6p5h", "< 2026.8.1", ["2026.7.1", "2026.7.1-2", "2026.6.8"], ["2026.8.1", "2026.8.2"]),
        ("GHSA-jhfx-v2j8-x3m6", "<= 2026.6.6", ["2026.6.5", "2026.6.6"], ["2026.6.7", "2026.6.8"]),
        ("GHSA-v7hx-r36p-f68m", "= 2026.6.6", ["2026.6.6"], ["2026.6.5", "2026.6.7", "2026.6.8"]),
        ("GHSA-mm9g-83wh-mhwj", ">= 2026.6.1, < 2026.6.9", ["2026.6.1", "2026.6.8"], ["2026.5.28", "2026.6.9"]),
        ("GHSA-224w-vfr9-h35c", ">= 2026.5.1 < 2026.7.1", ["2026.5.1", "2026.6.11"], ["2026.4.30", "2026.7.1"]),
        ("GHSA-5x6q-wg56-rxg8", ">= 2026.7.2, < 2026.9.2", ["2026.7.2", "2026.8.2", "2026.9.1"], ["2026.7.1", "2026.9.2"]),
        (_EXACT_ID, "= 2026.7.1-2", ["2026.7.1-2", " 2026.7.1-2 "], ["2026.7.1", "2026.7.1-1", "2026.7.1-3", "2026.7.2", "2026.8.1"]),
    ],
)
def test_range_shape_boundaries(all_ids, ident, shape, inside, outside):
    assert dict((i, r) for i, r, _f in _PUBLISHED)[ident] == shape  # the shape under test is the published one
    for v in inside:
        assert ident in _ids(v), f"{ident} ({shape}) must be named at {v!r}"
    for v in outside:
        assert ident not in _ids(v), f"{ident} ({shape}) must not be named at {v!r}"


def test_the_exact_build_row_is_the_only_difference_inside_the_correction_family(all_ids):
    base, first, second = (set(_ids(v)) for v in ("2026.7.1", "2026.7.1-1", "2026.7.1-2"))
    assert base == first
    assert second - base == {_EXACT_ID}
    assert base < second


def test_exact_build_matches_the_stripped_string_only(all_ids):
    assert _EXACT_ID in _ids("2026.7.1-2")
    assert _EXACT_ID in _ids("\t2026.7.1-2\n")
    assert _EXACT_ID not in _ids("2026.7.1-2.1")  # a different string, even though it parses the same


def test_a_prerelease_still_reads_as_its_release(all_ids):
    """`_parse_version` stays the parser: 2026.8.1-beta.2 is judged exactly as 2026.8.1 (existing
    behaviour, noted here so a change to it is a decision, not an accident)."""
    assert _ids("2026.8.1-beta.2") == _ids("2026.8.1")
    assert check_known_vulns(_stamp_ctx("2026.9.2-beta.1")).status == PASS


def test_lower_bounds_keep_a_build_below_them_out_of_the_list(all_ids):
    bounded = [(i, _shape(r)[1]) for i, r, _f in _PUBLISHED if _shape(r)[1] is not None and i != _EXACT_ID]
    assert len(bounded) == 22  # 23 bounded ranges, minus the exact-build one (tested above)
    for ident, lo in bounded:
        below = f"{lo[0]}.{lo[1]}.{lo[2] - 1}"
        at = f"{lo[0]}.{lo[1]}.{lo[2]}"
        assert ident not in _ids(below), f"{ident} named below its lower bound {lo} (at {below})"
        assert ident in _ids(at), f"{ident} not named at its own lower bound {at}"


def test_a_lower_bound_never_changes_the_verdict(all_ids):
    """Every build below a lower bound is covered by an unbounded row, so the status of every
    published final from 2026.1.29 to 2026.6.5 stays FAIL and only the id list is trimmed."""
    for v in ("2026.1.29", "2026.2.14", "2026.3.28", "2026.4.25", "2026.5.12", "2026.6.1", "2026.6.5"):
        assert check_known_vulns(_stamp_ctx(v)).status == FAIL, v


# ---------------------------------------------------------------------------
# Extended-stable builds
# ---------------------------------------------------------------------------

_CONFIRMED_6 = ("GHSA-8xxh-v4vc-qvm4", "GHSA-66hm-hxq3-5pfh")
_CONFIRMED_7 = ("GHSA-66hm-hxq3-5pfh", "GHSA-xx9p-hc9w-6p5h", "GHSA-7cp7-87pj-p32v")


def _in_table_order(ids):
    return [row[0] for row in _KNOWN_ADVISORIES if row[0] in set(ids)]


@pytest.mark.parametrize("version", ["2026.6.33", "2026.6.34", "2026.6.35"])
def test_extended_stable_2026_6_lists_only_confirmed_advisories(all_ids, version):
    result = check_known_vulns(_stamp_ctx(version))
    assert result.status == FAIL
    assert result.evidence == _in_table_order(_CONFIRMED_6)
    assert result.detail == f"OpenClaw {version} is affected by 2 known advisories: {', '.join(result.evidence)}."
    assert "Upgrade OpenClaw to >= 2026.9.2 to remediate all 2 listed advisories." in result.fix
    # 58 published ranges reach it numerically (the cross-check below), 2 are listed -> 56 further
    assert len(_published_ids(version)) == 58
    assert " 56 further published advisories cover this build by version range" in result.fix
    assert (
        "the vendor back-ports some fixes to extended-stable lines, and some affected code was never on "
        "them, without recording either in the advisory"
    ) in result.fix
    assert "back-ports" not in result.detail  # the disclosure lives in `fix`, never in `detail`


@pytest.mark.parametrize("version", ["2026.7.33", "2026.7.34", "2026.7.35"])
def test_extended_stable_2026_7_lists_only_confirmed_advisories(all_ids, version):
    result = check_known_vulns(_stamp_ctx(version))
    assert result.status == FAIL
    assert result.evidence == _in_table_order(_CONFIRMED_7)
    assert "Upgrade OpenClaw to >= 2026.9.2 to remediate all 3 listed advisories." in result.fix
    # 41 published ranges contain it numerically - the not-affected id's range is one of them and is
    # COUNTED, because the text says "published" - and 3 are listed -> 38 further
    assert len(_published_ids(version)) == 41 and _NOT_AFFECTED_ID in _published_ids(version)
    assert " 38 further published advisories cover this build by version range" in result.fix


@pytest.mark.parametrize("version", ["2026.8.33", "2026.8.34", "2026.8.35"])
def test_extended_stable_2026_8_passes_although_a_published_range_reaches_it(version):
    assert _published_ids(version) == {_NOT_AFFECTED_ID}  # the one range that reaches the line numerically
    result = check_known_vulns(_stamp_ctx(version))
    assert result.status == PASS
    assert result.detail == f"OpenClaw {version} is at or past all known-advisory fixes."


@pytest.mark.parametrize(
    "version,n_published",
    [("2026.7.36", 41), ("2026.6.36", 58), ("2026.7.99", 41)],
)
def test_an_unexamined_newer_build_on_a_known_line_is_unknown(version, n_published):
    assert len(_published_ids(version)) == n_published  # independent comparator, not the table's matcher
    result = check_known_vulns(_stamp_ctx(version))
    assert result.status == UNKNOWN
    assert result.detail.startswith(
        f"OpenClaw {version} is an extended-stable build that has not been checked against the advisory table: "
        f"{n_published} published advisory ranges cover it numerically"
    )
    assert "back-ports fixes to extended-stable lines without recording it" in result.detail
    assert result.evidence == []


@pytest.mark.parametrize("version", ["2026.6.33", "2026.6.35", "2026.7.33", "2026.7.35"])
def test_the_further_count_is_every_published_range_containing_the_build_minus_the_listed(version):
    """The words are "published ... by version range", so the count must be the published ranges that
    contain the build, the not-affected id's range included - checked with the test's own comparator."""
    result = check_known_vulns(_stamp_ctx(version))
    m = re.search(r" (\d+) further published advisories cover this build by version range", result.fix)
    assert m, result.fix
    assert int(m.group(1)) == len(_published_ids(version)) - len(result.evidence)


@pytest.mark.parametrize("version", ["2026.6.36", "2026.7.36", "2026.7.99"])
def test_the_unknown_count_is_every_published_range_containing_the_build(version):
    result = check_known_vulns(_stamp_ctx(version))
    m = re.search(r"(\d+) published advisory ranges cover it numerically", result.detail)
    assert m, result.detail
    assert int(m.group(1)) == len(_published_ids(version))


def test_2026_8_36_matches_no_row_once_the_not_affected_advisory_is_removed_so_it_passes():
    """Pinned decision: the rule is 'matching rows minus the not-affected set; none left -> the
    normal PASS', and that comes BEFORE the unexamined-build test, so 2026.8.36 is PASS - not
    UNKNOWN - because no other published range reaches it. The only range that does is the one
    the vendor back-ported on the 2026.8 line."""
    assert _published_ids("2026.8.36") == {_NOT_AFFECTED_ID}
    assert check_known_vulns(_stamp_ctx("2026.8.36")).status == PASS


def test_an_unknown_line_is_unknown_when_rows_match_and_pass_when_none_do():
    assert check_known_vulns(_stamp_ctx("2026.5.33")).status == UNKNOWN  # line 5 was never examined
    assert check_known_vulns(_stamp_ctx("2026.9.33")).status == PASS  # nothing reaches it
    assert check_known_vulns(_stamp_ctx("2026.12.34")).status == PASS


@pytest.mark.parametrize(
    "version,status,ids",
    [
        ("2026.8.32", FAIL, [_NOT_AFFECTED_ID]),  # patch below 33
        ("2026.13.33", PASS, []),  # minor outside 1-12: past every row
    ],
)
def test_near_misses_of_the_extended_stable_predicate_take_the_ordinary_path(all_ids, version, status, ids):
    result = check_known_vulns(_stamp_ctx(version))
    assert (result.status, list(result.evidence)) == (status, ids)
    if status == FAIL:
        assert "extended-stable" not in result.fix  # no disclosure: it is not treated as extended-stable
        assert ">= 2026.9.2" in result.fix


@pytest.mark.parametrize("version", ["2026.8.33-1", "2026.8.33-beta.1", "2026.8.35-2", "2026.8.34.1"])
def test_a_variant_on_the_2026_8_reserved_patch_loses_the_not_affected_id_and_passes(all_ids, version):
    """The vendor reserves every patch >= 33, including correction/build variants, and the one advisory
    the model says does not apply to the 2026.8 line must not be listed against them either (this was a
    guessed FAIL listing GHSA-5x6q when a suffix made the string 'not extended-stable')."""
    result = check_known_vulns(_stamp_ctx(version))
    assert result.status == PASS
    assert result.evidence == []
    assert result.detail == f"OpenClaw {version} is at or past all known-advisory fixes."


_VARIANT_UNKNOWN = [  # (variant, the exact released build whose published-range count it must share)
    ("2026.7.35-1", "2026.7.35"),
    ("2026.7.35-beta.1", "2026.7.35"),
    ("2026.6.35-2", "2026.6.35"),
    ("2026.7.35.1", "2026.7.35"),
    ("2026.7.33-1", "2026.7.33"),  # a patch the exact build would be FAIL on: a variant is never a FAIL
    ("2026.7.36-1", "2026.7.36"),  # a patch newer than any examined one
]


@pytest.mark.parametrize("version,exact", _VARIANT_UNKNOWN)
def test_a_variant_on_a_reserved_patch_with_rows_left_is_unknown_with_its_own_wording(version, exact):
    n_published = len(_published_ids(exact))  # independent comparator, same count as the exact build
    result = check_known_vulns(_stamp_ctx(version))
    assert result.status == UNKNOWN
    assert result.detail.startswith(
        f"OpenClaw {version} has an extended-stable patch number but is not a released extended-stable build, "
        f"and has not been checked against the advisory table: {n_published} published advisory ranges "
        "cover it numerically"
    )
    assert "is an extended-stable build that has not been checked" not in result.detail
    assert "back-ports fixes to extended-stable lines without recording it" in result.detail
    assert result.evidence == []
    assert n_published in (41, 58)  # the 2026.7 and 2026.6 lines


def test_the_unknown_for_an_exact_unexamined_final_keeps_its_wording():
    result = check_known_vulns(_stamp_ctx("2026.7.36"))
    assert result.status == UNKNOWN
    assert result.detail.startswith(
        "OpenClaw 2026.7.36 is an extended-stable build that has not been checked against the advisory table: "
        "41 published advisory ranges cover it numerically"
    )


def test_a_variant_on_a_line_no_row_reaches_passes():
    assert check_known_vulns(_stamp_ctx("2026.9.33-1")).status == PASS
    assert check_known_vulns(_stamp_ctx("2026.12.34.2")).status == PASS



def test_minor_zero_is_not_extended_stable_and_matches_the_ordinary_way(all_ids):
    """2026.0.33 parses to (2026, 0, 33): minor 0 is outside 1-12, so it is not extended-stable
    and is simply below nearly every row."""
    result = check_known_vulns(_stamp_ctx("2026.0.33"))
    assert result.status == FAIL
    assert "extended-stable" not in result.fix


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2026.6.33", True), ("2026.8.35", True), (" 2026.8.33 ", True), ("2026.12.40", True),
        ("2026.1.33", True), ("1000.8.33", True), ("9999.8.33", True), ("2026.8.100", True),
        ("2026.7.32", False), ("2026.8.33-1", False), ("2026.8.33-beta.1", False),
        ("2026.8.33+build", False), ("2026.13.33", False), ("2026.0.33", False),
        ("999.8.33", False), ("10000.8.33", False), ("2026.08.33", False), ("2026.8.033", False),
        ("2026.8.33.1", False), ("2026.7.1-2", False), ("2026.7.1", False), ("2026.8", False),
        ("2026", False), ("", False), ("nightly", False),
    ],
)
def test_the_exact_released_build_predicate(raw, expected):
    """`_extended_stable_build` is the vendor's `isExtendedStableReleaseVersion` (exact final).
    Measured 2026-10-05: the vendor function, extracted verbatim from the installed dist and run in
    node against the dist's semver, over 53 strings (padding, separators, full-width digits, 2^53,
    prefixes, suffixes), agrees with this predicate on 46 and differs on 7, in four classes:
    (1) a leading "v" (vendor accepts, we do not; unreachable here, `_parse_version("v2026.8.35")` is
    None so B33 says UNKNOWN before this is asked); (2) a BOM (U+FEFF) around the version (the vendor's
    JS trim strips it, Python's strip does not: vendor True, ours False); (3) control characters
    U+001C-U+001F around it (Python's strip removes them, JS trim does not: ours True, vendor False);
    (4) a patch above 2**53 (the vendor's number arithmetic rejects it, ours accepts it). None is a
    realistic stamp. Every other string here is identical."""
    assert (_lifecycle._extended_stable_build(raw) is not None) is expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2026.6.33", True), ("2026.8.35", True), (" 2026.8.33 ", True), ("2026.12.40", True),
        ("2026.1.33", True), ("1000.8.33", True), ("9999.8.33", True), ("2026.8.100", True),
        # a suffix or a fourth part does not take a version off the reserved patch
        ("2026.8.33-1", True), ("2026.8.33-beta.1", True), ("2026.8.33+build", True),
        ("2026.7.35.1", True), ("2026.6.35-2", True), ("2026.8.35-rc.2", True),
        # the parsed tuple, not the spelling
        ("2026.08.33", True), ("2026.8.033", True), ("2026.8.33.0", True),
        ("2026.7.32", False), ("2026.8.32-1", False), ("2026.13.33", False), ("2026.0.33", False),
        ("999.8.33", False), ("10000.8.33", False), ("2026.8", False), ("2026", False),
        ("", False), ("nightly", False), ("2026.7.1-2", False), ("2026.7.1", False),
        ("v2026.8.33", False),  # unparseable: _parse_version is None
    ],
)
def test_on_the_extended_stable_line_is_decided_on_the_parsed_tuple(raw, expected):
    """`_on_extended_stable_line` is the vendor's `hasExtendedStablePatch` on the parsed tuple.
    Measured 2026-10-05 over 34 strings against the vendor function (extracted verbatim, run in node
    on the dist's semver parse): identical on every suffix shape semver accepts (`-1`, `-beta.1`,
    `+build`, `-rc.2`) and on every bound (year 999/1000/9999/10000, minor 0/12/13, patch 32/33).
    It differs on 8 strings semver cannot parse or reads differently - a fourth part (`2026.7.35.1`,
    `2026.8.33.1`, `2026.8.33.0`), leading zeros (`2026.08.33`, `2026.8.033`), an empty prerelease
    (`2026.8.33-`), a patch above 2**53, and a leading "v" - where `_parse_version` (the parser B33's
    table is written against) reads a tuple and so decides, as the ruling for this change requires."""
    assert _lifecycle._on_extended_stable_line(raw) is expected


def test_every_exact_released_build_is_on_the_line():
    for v in ("2026.6.33", "2026.7.35", "2026.8.33", "2026.12.40", "1000.1.33", "9999.12.33"):
        assert _lifecycle._extended_stable_build(v) is not None
        assert _lifecycle._on_extended_stable_line(v)


def test_the_product_has_no_dead_predicate():
    assert not hasattr(_lifecycle, "_is_extended_stable")


def test_a_leading_v_is_unparseable_not_extended_stable():
    assert _parse_version("v2026.8.35") is None
    assert check_known_vulns(_stamp_ctx("v2026.8.35")).status == UNKNOWN


def test_a_line_whose_confirmed_advisories_are_not_among_the_matching_rows_is_unknown(monkeypatch):
    monkeypatch.setattr(_lifecycle, "_EXTENDED_STABLE_LINES", {(2026, 7): (35, ("GHSA-0000-0000-0000",))})
    result = check_known_vulns(_stamp_ctx("2026.7.35"))
    assert result.status == UNKNOWN


def test_a_build_newer_than_the_newest_examined_patch_is_unknown(monkeypatch):
    lines = dict(_lifecycle._EXTENDED_STABLE_LINES)
    lines[(2026, 7)] = (34, lines[(2026, 7)][1])
    monkeypatch.setattr(_lifecycle, "_EXTENDED_STABLE_LINES", lines)
    assert check_known_vulns(_stamp_ctx("2026.7.34")).status == FAIL
    assert check_known_vulns(_stamp_ctx("2026.7.35")).status == UNKNOWN


def test_without_the_not_affected_set_the_2026_8_line_would_be_unknown_not_fail(monkeypatch):
    """Rule 3: rows match numerically but the line has no confirmed-unfixed advisory -> UNKNOWN
    (never a guessed FAIL). The not-affected set is what turns the shipped answer into PASS."""
    monkeypatch.setattr(_lifecycle, "_EXTENDED_STABLE_NOT_AFFECTED", frozenset())
    assert check_known_vulns(_stamp_ctx("2026.8.35")).status == UNKNOWN


# ---------------------------------------------------------------------------
# Which version is judged (the truth table in check_known_vulns's docstring)
# ---------------------------------------------------------------------------

@pytest.fixture
def machine(monkeypatch, tmp_path):
    """A hermetic 'this machine': HOME is tmp_path, no OPENCLAW_* path variable, ~/.openclaw exists."""
    for var in ("OPENCLAW_HOME", "OPENCLAW_STATE_DIR", "OPENCLAW_CONFIG_PATH", "USERPROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".openclaw").mkdir()
    return tmp_path


def _run(stamp, installed, home):
    c = Context(home=home)
    c.config = {} if stamp is None else {"meta": {"lastTouchedVersion": stamp}}
    c.installed_dist_version = installed
    return check_known_vulns(c)


_I_AFF, _I_OK, _I_EXT, _I_UNEX, _I_BAD = "2026.7.1", "2026.9.7", "2026.7.35", "2026.7.36", "nightly"
_S_AFF, _S_OK, _S_UNEX = "2026.6.8", "2026.9.2", "2026.6.36"

# (installed, stamp) -> (status, detail prefix) when the audited home IS this machine's home.
_THIS_HOME = {
    (_I_AFF, _S_AFF): (FAIL, "OpenClaw 2026.7.1 (installed) is affected by 40 known advisories: "),
    (_I_AFF, _S_OK): (FAIL, "OpenClaw 2026.7.1 (installed) is affected by 40 known advisories: "),
    (_I_AFF, None): (FAIL, "OpenClaw 2026.7.1 (installed) is affected by 40 known advisories: "),
    (_I_AFF, "nightly"): (FAIL, "OpenClaw 2026.7.1 (installed) is affected by 40 known advisories: "),
    (_I_AFF, _I_AFF): (FAIL, "OpenClaw 2026.7.1 is affected by 40 known advisories: "),  # same string: today's form
    (_I_OK, _S_AFF): (WARN, "The installed OpenClaw build (2026.9.7) is at or past all known-advisory fixes, "
                            "but the build that last wrote this config (2026.6.8) is affected by 61 known advisories "
                            "(the evidence lists the first 20). "),
    (_I_OK, _S_UNEX): (WARN, "The installed OpenClaw build (2026.9.7) is at or past all known-advisory fixes, "
                             "but the build that last wrote this config (2026.6.36) is an extended-stable build "
                             "the table has not checked (58 published advisory ranges cover it numerically). "),
    (_I_OK, _S_OK): (PASS, "OpenClaw 2026.9.7 (installed) is at or past all known-advisory fixes."),
    (_I_OK, None): (PASS, "OpenClaw 2026.9.7 (installed) is at or past all known-advisory fixes."),
    (_I_OK, "nightly"): (PASS, "OpenClaw 2026.9.7 (installed) is at or past all known-advisory fixes."),
    (_I_OK, _I_OK): (PASS, "OpenClaw 2026.9.7 is at or past all known-advisory fixes."),  # same string: today's form
    (_I_EXT, _I_EXT): (FAIL, "OpenClaw 2026.7.35 is affected by 3 known advisories: "),  # same string: today's form
    (_I_UNEX, _I_UNEX): (UNKNOWN, "OpenClaw 2026.7.36 is an extended-stable build that has not been checked"),
}
# Fill in the remaining cells so EVERY (installed, stamp) pair is pinned: whenever the installed
# build itself matches rows (or is an unexamined extended-stable build) it decides, whatever the stamp.
for _stamp in (_S_AFF, _S_OK, None, "nightly", _S_UNEX):
    _THIS_HOME.setdefault((_I_AFF, _stamp), (FAIL, "OpenClaw 2026.7.1 (installed) is affected by 40 known advisories: "))
    _THIS_HOME.setdefault((_I_EXT, _stamp), (FAIL, "OpenClaw 2026.7.35 (installed) is affected by 3 known advisories: "))
    _THIS_HOME.setdefault(
        (_I_UNEX, _stamp), (UNKNOWN, "OpenClaw 2026.7.36 (installed) is an extended-stable build that has not been checked")
    )

# (installed, stamp) -> (status, detail prefix) when the installed build does not count:
# another home, no installed build, or an installed string that does not parse. The stamp decides.
_STAMP_DECIDES = {
    _S_AFF: (FAIL, "OpenClaw 2026.6.8 is affected by 61 known advisories: "),
    _S_OK: (PASS, "OpenClaw 2026.9.2 is at or past all known-advisory fixes."),
    None: (UNKNOWN, "OpenClaw version unknown (meta.lastTouchedVersion / lastTouchedVersion not set)"),
    "nightly": (UNKNOWN, "OpenClaw version 'nightly' could not be parsed"),
    _S_UNEX: (UNKNOWN, "OpenClaw 2026.6.36 is an extended-stable build that has not been checked"),
}


def test_the_table_covers_every_installed_x_stamp_cell():
    installed_builds = (_I_AFF, _I_OK, _I_EXT, _I_UNEX)
    stamps = (_S_AFF, _S_OK, None, "nightly", _S_UNEX)
    for i in installed_builds:
        for st in stamps:
            assert (i, st) in _THIS_HOME, (i, st)
    # ... and the cells where the stamp string equals the installed string (today's detail form)
    assert {k for k in _THIS_HOME if k[0] == k[1]} == {(i, i) for i in installed_builds}
    assert len(_THIS_HOME) == len(installed_builds) * len(stamps) + len(installed_builds)


@pytest.mark.parametrize("installed,stamp", sorted(_THIS_HOME, key=repr))
def test_truth_table_when_the_audited_home_is_this_machines_home(machine, installed, stamp):
    status, prefix = _THIS_HOME[(installed, stamp)]
    result = _run(stamp, installed, machine / ".openclaw")
    assert result.status == status
    assert result.detail.startswith(prefix), result.detail


@pytest.mark.parametrize("stamp", [_S_AFF, _S_OK, None, "nightly", _S_UNEX])
@pytest.mark.parametrize("installed", [_I_AFF, _I_OK, _I_EXT, _I_UNEX])
def test_another_home_lets_the_stamp_decide_whatever_is_installed(machine, installed, stamp):
    """`installed_dist_version` is filled in even when --home points at a copied home or a
    fixture; it describes the auditing machine, not that home, so it must not be used."""
    other = machine / "copied-home"
    other.mkdir()
    status, prefix = _STAMP_DECIDES[stamp]
    result = _run(stamp, installed, other)
    assert result.status == status
    assert result.detail.startswith(prefix), result.detail


@pytest.mark.parametrize("stamp", [_S_AFF, _S_OK, None, "nightly", _S_UNEX])
@pytest.mark.parametrize("installed", [None, "", "nightly", "latest", "2026"])
def test_no_usable_installed_build_lets_the_stamp_decide_even_on_this_machines_home(machine, installed, stamp):
    status, prefix = _STAMP_DECIDES[stamp]
    result = _run(stamp, installed, machine / ".openclaw")
    assert result.status == status
    assert result.detail.startswith(prefix), result.detail


def test_the_warn_says_what_to_do_and_names_the_stamps_advisories(machine):
    result = _run(_S_AFF, _I_OK, machine / ".openclaw")
    assert result.status == WARN
    assert result.detail.endswith("This check does not determine which of the two the running gateway is.")
    assert "Nothing local" not in result.detail  # a limit of the check, not a claim about the machine
    assert "openclaw --version" in result.fix
    assert "Confirm the running build" not in result.fix  # --version prints the installed build only
    assert "can differ from the build a gateway started before the upgrade is still running" in result.fix
    assert "restart" in result.fix
    assert "next time OpenClaw saves its config" in result.fix
    assert len(result.evidence) == 20 and all(i.startswith(("GHSA-", "CVE-")) for i in result.evidence)


def test_the_warn_counts_published_ranges_for_an_unexamined_extended_stable_stamp(machine):
    """2026.7.36 is contained in 41 published ranges (the not-affected id's among them), and the WARN
    says "published advisory ranges", so it must say 41 - not the 40 left after the not-affected set."""
    stamp = "2026.7.36"
    assert len(_published_ids(stamp)) == 41
    result = _run(stamp, _I_OK, machine / ".openclaw")
    assert result.status == WARN
    assert "(41 published advisory ranges cover it numerically)" in result.detail
    assert result.evidence == []


def test_the_warn_for_a_variant_stamp_follows_the_variant_wording(machine):
    result = _run("2026.7.35-1", _I_OK, machine / ".openclaw")
    assert result.status == WARN
    assert (
        "the build that last wrote this config (2026.7.35-1) has an extended-stable patch number but is not "
        "a released extended-stable build, and the table has not checked it "
        "(41 published advisory ranges cover it numerically)."
    ) in result.detail
    assert "is an extended-stable build the table has not checked" not in result.detail
    assert result.evidence == []


def test_an_installed_variant_with_rows_left_is_unknown_and_is_labelled_installed(machine):
    result = _run(_S_OK, "2026.7.35-1", machine / ".openclaw")
    assert result.status == UNKNOWN
    assert result.detail.startswith(
        "OpenClaw 2026.7.35-1 (installed) has an extended-stable patch number but is not a released "
        "extended-stable build, and has not been checked against the advisory table: "
    )


def test_a_rolled_back_build_is_not_hidden_by_a_newer_stamp(machine):
    """The reverse of the stale-stamp case: the stamp says 2026.9.7 but the installed package is the
    affected 2026.7.1 (a rollback). The installed build decides -> FAIL; the stamp alone said PASS."""
    assert _run("2026.9.7", None, machine / ".openclaw").status == PASS
    assert _run("2026.9.7", "2026.7.1", machine / ".openclaw").status == FAIL


def test_whitespace_around_the_installed_string_is_ignored(machine):
    result = _run(None, "  2026.9.7 \n", machine / ".openclaw")
    assert result.status == PASS
    assert result.detail == "OpenClaw 2026.9.7 (installed) is at or past all known-advisory fixes."


def test_installed_equal_to_the_stamp_keeps_todays_detail_byte_for_byte(machine):
    """The stamp string is shown as written (today's `{raw_ver}`), padding included."""
    result = _run(" 2026.9.2 ", "2026.9.2", machine / ".openclaw")
    assert result.status == PASS
    assert result.detail == "OpenClaw  2026.9.2  is at or past all known-advisory fixes."


# --- the home predicate: its inputs are HOME and the OPENCLAW_* path variables ---------------

def test_state_dir_variable_pointing_at_the_audited_home_makes_it_this_machines_home(machine, monkeypatch):
    custom = machine / "profile-work"
    custom.mkdir()
    monkeypatch.setenv("OPENCLAW_STATE_DIR", str(custom))
    assert _run(_S_AFF, _I_OK, custom).status == WARN  # installed decides (clear), stamp is affected


def test_state_dir_variable_pointing_elsewhere_makes_the_default_home_a_foreign_one(machine, monkeypatch):
    elsewhere = machine / "profile-work"
    elsewhere.mkdir()
    monkeypatch.setenv("OPENCLAW_STATE_DIR", str(elsewhere))
    result = _run(_S_AFF, _I_OK, machine / ".openclaw")
    assert result.status == FAIL  # not this machine's home -> the stamp (affected) decides
    assert result.detail.startswith("OpenClaw 2026.6.8 is affected by")


def test_openclaw_home_variable_moves_the_default_home(machine, monkeypatch):
    moved = machine / "elsewhere"
    (moved / ".openclaw").mkdir(parents=True)
    monkeypatch.setenv("OPENCLAW_HOME", str(moved))
    assert _run(_S_AFF, _I_OK, moved / ".openclaw").status == WARN
    assert _run(_S_AFF, _I_OK, machine / ".openclaw").status == FAIL


def test_a_symlink_to_the_state_dir_is_this_machines_home(machine):
    link = machine / "link-to-home"
    link.symlink_to(machine / ".openclaw")
    assert _run(_S_AFF, _I_OK, link).status == WARN


def test_a_failure_to_resolve_the_home_is_treated_as_not_this_machines_home(machine, monkeypatch):
    monkeypatch.delenv("HOME", raising=False)

    def _no_home(cls=None):
        raise RuntimeError("could not determine home directory")

    monkeypatch.setattr(Path, "home", classmethod(_no_home))
    result = _run(_S_AFF, _I_OK, machine / ".openclaw")
    assert result.status == FAIL  # the stamp decided, as it always did
    assert result.detail.startswith("OpenClaw 2026.6.8 is affected by")


# --- a --profile home: <effective home>/.openclaw-<name> ---------------------------------------
# The vendor's `--profile <name>` serves `<effective home>/.openclaw-<name>` with the SAME installed
# package (dist node-host-launcher-bootstrap.js resolveProfileStateDir: suffix "" for the profile
# "default" in any case, "-" + name otherwise; PROFILE_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/i).

def test_a_profile_home_under_the_effective_home_is_this_machines_home(machine):
    home = machine / ".openclaw-work"
    home.mkdir()
    warn = _run(_S_AFF, _I_OK, home)  # installed clear, stamp affected: the stale-stamp case
    assert warn.status == WARN
    assert warn.detail.startswith("The installed OpenClaw build (2026.9.7) is at or past all known-advisory fixes")
    fail = _run(_S_OK, _I_AFF, home)  # installed affected: the installed build decides
    assert fail.status == FAIL
    assert fail.detail.startswith("OpenClaw 2026.7.1 (installed) is affected by 40 known advisories: ")


def test_a_profile_home_under_a_moved_effective_home_follows_openclaw_home(machine, monkeypatch):
    moved = machine / "elsewhere"
    (moved / ".openclaw-work").mkdir(parents=True)
    (machine / ".openclaw-work").mkdir()
    monkeypatch.setenv("OPENCLAW_HOME", str(moved))
    assert _run(_S_AFF, _I_OK, moved / ".openclaw-work").status == WARN
    assert _run(_S_AFF, _I_OK, machine / ".openclaw-work").status == FAIL  # no longer under the effective home


# (directory name, accepted as a profile home) - the right column is what the vendor's own functions say:
# the profile pattern, extracted from the installed dist and run in node over these names (2026-10-05):
# resolveProfileStateDir gives `.openclaw-<name>` for every accepted name and the plain `.openclaw` for
# "default" in any case; a non-ASCII letter, a dot, an empty name and 65 characters are invalid there.
_PROFILE_NAMES = [
    (".openclaw-work", True), (".openclaw-Work", True), (".openclaw-WORK", True), (".openclaw-a", True),
    (".openclaw-0", True), (".openclaw-x_y", True), (".openclaw-x-y", True), (".openclaw-x-", True),
    (".openclaw-defaultx", True), (".openclaw-default-2", True), (".openclaw-" + "x" * 64, True),
    (".openclaw-" + "x" * 65, False),
    (".openclaw-", False),
    (".openclaw-default", False), (".openclaw-Default", False), (".openclaw-DEFAULT", False),
    (".openclaw-dEfAuLt", False),
    (".openclaw_work", False), (".openclaw-_x", False), (".openclaw--x", False),
    (".openclaw-my.work", False), (".openclaw-my work", False), (".openclaw-work\n", False),
    (".openclaw-\u00dcn\u00ef", False), (".openclaw-x\u212a", False),
    ("openclaw-work", False), (".claw-work", False),  # (".openclaw" itself is the state dir, tested above)
]


@pytest.mark.parametrize("name,accepted", _PROFILE_NAMES)
def test_profile_home_names_follow_the_vendors_pattern(machine, name, accepted):
    home = machine / name
    home.mkdir()  # the directory exists in BOTH arms, so a rejected name is rejected for its name
    if accepted:
        assert _lifecycle._b33_is_this_machines_home(home) is True
        assert _run(_S_AFF, _I_OK, home).status == WARN
        assert _run(_S_OK, _I_AFF, home).status == FAIL
    else:
        # "another home": the stamp decides, whichever way it points
        assert _lifecycle._b33_is_this_machines_home(home) is False
        stale = _run(_S_AFF, _I_OK, home)
        assert (stale.status, stale.detail.startswith("OpenClaw 2026.6.8 is affected by 61 known")) == (FAIL, True)
        assert _run(_S_OK, _I_AFF, home).status == PASS


def test_a_profile_named_directory_that_is_not_directly_under_the_effective_home_is_another_home(machine):
    nested = machine / "elsewhere" / ".openclaw-work"
    nested.mkdir(parents=True)
    deeper = machine / ".openclaw-work" / ".openclaw-work"
    deeper.mkdir(parents=True)
    for home in (nested, deeper):
        assert _lifecycle._b33_is_this_machines_home(home) is False
        assert _run(_S_AFF, _I_OK, home).status == FAIL
        assert _run(_S_OK, _I_AFF, home).status == PASS


def test_a_profile_home_that_is_a_symlink_is_still_this_machines_home(machine):
    """`<effective home>/.openclaw-<name>` is what the vendor's `--profile <name>` opens, symlink or
    not (it joins the path and never resolves it), so a profile home kept elsewhere and linked into
    place is served by the local installation - the same way a symlinked `~/.openclaw` is."""
    target = machine / "elsewhere" / "data"
    target.mkdir(parents=True)
    link = machine / ".openclaw-work"
    link.symlink_to(target)
    twin = machine / "elsewhere" / ".openclaw-work"
    twin.mkdir()
    link2 = machine / ".openclaw-other"
    link2.symlink_to(twin)
    for home in (link, link2):
        assert _lifecycle._b33_is_this_machines_home(home) is True
        assert _run(_S_AFF, _I_OK, home).status == WARN
        assert _run(_S_OK, _I_AFF, home).status == FAIL
    # ... but the directory it points at, audited under its own name, is not a profile home:
    # "data" is not profile-shaped, and `<home>/.openclaw-work` resolves to "data", not to the twin.
    for home in (target, twin):
        assert _lifecycle._b33_is_this_machines_home(home) is False
    assert _run(_S_AFF, _I_OK, twin).status == FAIL  # the stamp decides


def test_a_home_directory_reached_through_a_symlink_is_resolved_on_both_sides(machine, monkeypatch, tmp_path_factory):
    """HOME itself may be a symlink (a relocated home). The vendor side of the comparison is
    resolved too, so the default home and a profile home are still recognised when the audited
    path is given in its resolved form."""
    real_home = tmp_path_factory.mktemp("realhome")
    (real_home / ".openclaw").mkdir()
    (real_home / ".openclaw-work").mkdir()
    link_home = machine / "linkhome"
    link_home.symlink_to(real_home)
    monkeypatch.setenv("HOME", str(link_home))
    for home in (real_home / ".openclaw", link_home / ".openclaw", real_home / ".openclaw-work", link_home / ".openclaw-work"):
        assert _lifecycle._b33_is_this_machines_home(home) is True, home
        assert _run(_S_AFF, _I_OK, home).status == WARN


def test_a_profile_named_symlink_loop_is_not_this_machines_home_on_any_interpreter(machine):
    """`Path.resolve()` raises for a symlink loop on Python 3.9 and 3.12 and returns the path on
    3.14; the predicate stats the home first so the answer does not depend on that."""
    loop = machine / ".openclaw-loop"
    loop.symlink_to(loop)
    assert _lifecycle._b33_is_this_machines_home(loop) is False
    dangling = machine / ".openclaw-gone"
    dangling.symlink_to(machine / "nowhere")
    assert _lifecycle._b33_is_this_machines_home(dangling) is False
    assert _lifecycle._b33_is_this_machines_home(machine / ".openclaw-absent") is False


def test_a_symlink_to_a_profile_home_is_this_machines_home(machine):
    (machine / ".openclaw-work").mkdir()
    alias = machine / "alias"
    alias.symlink_to(machine / ".openclaw-work")
    assert _run(_S_AFF, _I_OK, alias).status == WARN


@pytest.mark.parametrize("bad_home", [None, "", str(Path("/nonexistent")), 0, b"x", object()])
def test_a_home_that_cannot_be_judged_is_not_this_machines_home_and_never_raises(machine, bad_home):
    """The predicate is total: None, a str, an int, bytes, any object - not a Path - is 'another
    home', and the check answers from the stamp (no exception, so no ERR finding upstream)."""
    assert _lifecycle._b33_is_this_machines_home(bad_home) is False
    c = Context(home=machine / ".openclaw")
    c.home = bad_home
    c.config = {"meta": {"lastTouchedVersion": _S_AFF}}
    c.installed_dist_version = _I_OK
    result = check_known_vulns(c)
    assert result.status == FAIL
    assert result.detail.startswith("OpenClaw 2026.6.8 is affected by 61 known advisories: ")


def test_a_context_whose_home_is_none_with_an_installed_version_lets_the_stamp_decide(machine):
    c = Context(home=machine / ".openclaw")
    c.home = None
    c.config = {"meta": {"lastTouchedVersion": _S_OK}}
    c.installed_dist_version = _I_AFF  # would FAIL if it counted; it must not, the home is unknown
    assert check_known_vulns(c).status == PASS
    c.config = {}
    assert check_known_vulns(c).status == UNKNOWN  # no stamp, the installed build still does not count


def test_a_failure_while_resolving_the_effective_home_is_not_this_machines_home(machine, monkeypatch):
    (machine / ".openclaw-work").mkdir()

    def _boom(env=None):
        raise RuntimeError("could not determine home directory")

    monkeypatch.setattr(_lifecycle, "openclaw_effective_home", _boom)
    assert _lifecycle._b33_is_this_machines_home(machine / ".openclaw-work") is False
    assert _run(_S_AFF, _I_OK, machine / ".openclaw-work").status == FAIL


def test_a_wrong_yes_never_turns_a_fail_into_a_pass(machine):
    """Why misjudging a home as this machine's cannot hide a vulnerable build: an affected stamp beside
    a clear installed build is a WARN (never a PASS), and an affected installed build is a FAIL."""
    home = machine / ".openclaw-work"
    home.mkdir()
    for stamp in ("2026.6.8", "2026.7.1", "2026.8.1", "2026.9.1", "2026.6.36", "2026.7.35-1"):
        assert check_known_vulns(_stamp_ctx(stamp)).status in (FAIL, UNKNOWN)
        assert _run(stamp, _I_OK, home).status == WARN
        assert _run(stamp, _I_AFF, home).status == FAIL


def test_the_warn_says_when_its_evidence_list_is_capped(machine):
    """The WARN names the full count in `detail` and lists at most 20 ids in the evidence; it says
    so when the list is shorter than the count, and says nothing when it is not."""
    home = machine / ".openclaw"
    many = _run("2026.6.8", _I_OK, home)  # 61 advisories for the stamp
    assert many.status == WARN and len(many.evidence) == 20
    assert "is affected by 61 known advisories (the evidence lists the first 20). " in many.detail
    few = _run("2026.8.1", _I_OK, home)  # 2 advisories for the stamp
    assert few.status == WARN and len(few.evidence) == 2
    assert "is affected by 2 known advisories. This check does not determine" in few.detail
    assert "the evidence lists" not in few.detail


def test_the_unknown_tells_the_user_what_to_do():
    result = check_known_vulns(_stamp_ctx("2026.7.36"))
    assert result.status == UNKNOWN
    assert result.fix == (
        "Move to a current OpenClaw release and re-run this check; extended-stable "
        "builds are examined against the table one build at a time."
    )


def test_an_extended_stable_fail_with_nothing_further_does_not_claim_further_advisories(monkeypatch):
    """The "N further published advisories" sentence appears only when there are some: with every
    matching row confirmed for the line, the `fix` is the plain upgrade sentence."""
    every = tuple(sorted(_published_ids("2026.7.35")))
    assert len(every) == 41
    lines = dict(_lifecycle._EXTENDED_STABLE_LINES)
    lines[(2026, 7)] = (35, every)
    monkeypatch.setattr(_lifecycle, "_EXTENDED_STABLE_LINES", lines)
    monkeypatch.setattr(_lifecycle, "_EXTENDED_STABLE_NOT_AFFECTED", frozenset())
    result = check_known_vulns(_stamp_ctx("2026.7.35"))
    assert result.status == FAIL
    assert result.fix == "Upgrade OpenClaw to >= 2026.9.2 to remediate all 41 listed advisories."


def test_hermetic_default_context_never_sees_an_installed_build():
    c = Context(home=Path("/nonexistent"))
    c.config = {"meta": {"lastTouchedVersion": "2026.9.2"}}
    assert c.installed_dist_version is None
    assert check_known_vulns(c).status == PASS


# ---------------------------------------------------------------------------
# Wording that must not move (existing ignore-file fingerprints hash `detail`)
# ---------------------------------------------------------------------------

def test_stamp_only_pass_text_is_unchanged():
    result = check_known_vulns(_stamp_ctx("2026.9.2"))
    assert result.status == PASS
    assert result.detail == "OpenClaw 2026.9.2 is at or past all known-advisory fixes."
    assert result.fix == _GENERIC_FIX


def test_stamp_only_fail_texts_are_unchanged_in_form():
    one = check_known_vulns(_stamp_ctx("2026.9.1"))
    assert one.detail == "OpenClaw 2026.9.1 is affected by 1 known advisory: GHSA-5x6q-wg56-rxg8."
    assert one.fix == "Upgrade OpenClaw to >= 2026.9.2 to remediate this advisory in a single upgrade."
    assert one.evidence == ["GHSA-5x6q-wg56-rxg8"]
    two = check_known_vulns(_stamp_ctx("2026.8.1"))
    assert two.detail == (
        "OpenClaw 2026.8.1 is affected by 2 known advisories: GHSA-m78m-7h3q-q938, GHSA-5x6q-wg56-rxg8."
    )
    assert two.fix == "Upgrade OpenClaw to >= 2026.9.2 to remediate all 2 matched advisories in a single upgrade."


def test_stamp_only_unknown_texts_are_unchanged():
    absent = check_known_vulns(_stamp_ctx(None))
    assert absent.status == UNKNOWN
    assert absent.detail == (
        "OpenClaw version unknown (meta.lastTouchedVersion / lastTouchedVersion not set) "
        "— cannot check against known advisories."
    )
    assert absent.fix == (
        "Set meta.lastTouchedVersion in openclaw.json (or upgrade to a current release) "
        "and keep OpenClaw current."
    )
    bad = check_known_vulns(_stamp_ctx("nightly"))
    assert bad.status == UNKNOWN
    assert bad.detail == "OpenClaw version 'nightly' could not be parsed — cannot check against known advisories."
    assert bad.fix == (
        "Verify your version string (expected dotted-integer format like '2026.1.29') "
        "and keep OpenClaw current."
    )


def test_the_root_alias_is_still_read_when_meta_has_no_version():
    c = Context(home=Path("/nonexistent"))
    c.config = {"lastTouchedVersion": "2026.9.1"}
    assert check_known_vulns(c).status == FAIL
    c.config = {"meta": {"lastTouchedVersion": "2026.9.2"}, "lastTouchedVersion": "2026.1.1"}
    assert check_known_vulns(c).status == PASS  # meta wins over the root alias, as before


def test_an_integer_stamp_does_not_crash():
    assert check_known_vulns(_stamp_ctx(2026)).status == UNKNOWN
