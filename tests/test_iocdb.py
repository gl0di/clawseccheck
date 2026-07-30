"""iocdb.py (CLAWSECCHECK-F-157) — the dated, provenance-bound IOC dataset that
replaced the 8-entry hardcoded `_SOURCE_KNOWN_BAD` in checks/_vet.py.

Golden Rule #4 (no fabricated IOCs) is mechanically enforced here: every shipped
record must carry a complete provenance trail (value/type/first_seen/source_url/
source_name) and a parseable, non-future first_seen date. Golden Rule #1 (no
network) is structural for this module — it is pure static data with zero I/O.

Offline, read-only, stdlib only. Nothing here touches the network or writes
outside tmp_path.
"""
from __future__ import annotations

import datetime

from clawseccheck import iocdb


# --------------------------------------------------------------------------- #
# Schema validation — the mechanical enforcement of Golden Rule #4.            #
# --------------------------------------------------------------------------- #
def test_shipped_dataset_is_well_formed():
    assert iocdb.validate_dataset() == []


def test_every_shipped_record_has_complete_provenance():
    required = ("value", "type", "first_seen", "source_url", "source_name")
    for rec in iocdb.all_records():
        for field in required:
            assert str(rec.get(field) or "").strip(), f"{rec!r} missing {field!r}"


def test_every_shipped_first_seen_is_iso_and_not_future():
    today = datetime.date.today()
    for rec in iocdb.all_records():
        parsed = datetime.date.fromisoformat(rec["first_seen"])  # raises if malformed
        assert parsed <= today, rec


def test_revision_parses_as_iso_date_and_is_not_future():
    rev = iocdb.revision_date()
    assert isinstance(rev, datetime.date)
    assert rev <= datetime.date.today()


def test_all_records_combines_every_table():
    assert iocdb.all_records() == iocdb.SOURCES + iocdb.PUBLISHERS + iocdb.HOSTS


# --------------------------------------------------------------------------- #
# The validator MECHANISM itself: a record missing provenance must fail —      #
# tested against a synthetic record, never by mutating the shipped tables.     #
# --------------------------------------------------------------------------- #
def test_validator_catches_missing_field():
    bad = {
        "value": "evil.example", "type": "domain", "first_seen": "2026-01-01",
        "source_url": "", "source_name": "Nobody",  # empty source_url
    }
    problems = iocdb._validate_record("TEST", 0, bad)
    assert any("source_url" in p for p in problems)


def test_validator_catches_unparseable_first_seen():
    bad = {
        "value": "evil.example", "type": "domain", "first_seen": "not-a-date",
        "source_url": "https://example.org/advisory", "source_name": "Nobody",
    }
    problems = iocdb._validate_record("TEST", 0, bad)
    assert any("not ISO YYYY-MM-DD" in p for p in problems)


def test_validator_catches_future_first_seen():
    bad = {
        "value": "evil.example", "type": "domain", "first_seen": "2099-01-01",
        "source_url": "https://example.org/advisory", "source_name": "Nobody",
    }
    problems = iocdb._validate_record("TEST", 0, bad)
    assert any("is in the future" in p for p in problems)


def test_validator_accepts_a_well_formed_synthetic_record():
    good = {
        "value": "evil.example", "type": "domain", "first_seen": "2026-01-01",
        "source_url": "https://example.org/advisory", "source_name": "Example CERT",
        "note": "test fixture",
    }
    assert iocdb._validate_record("TEST", 0, good) == []


def test_validator_never_raises_on_a_non_dict_record():
    assert iocdb._validate_record("TEST", 0, "not-a-dict")  # non-empty problem list, no crash


# --------------------------------------------------------------------------- #
# Freshness — mandatory, not decorative (mirrors ledger.freshness_notice /      #
# update.update_notice).                                                       #
# --------------------------------------------------------------------------- #
def test_freshness_notice_empty_when_current():
    assert iocdb.freshness_notice(today=iocdb.revision_date()) == []


def test_freshness_notice_empty_one_day_before_threshold():
    d = iocdb.revision_date() + datetime.timedelta(days=iocdb.STALE_AFTER_DAYS - 1)
    assert iocdb.freshness_notice(today=d) == []


def test_freshness_notice_fires_at_exact_threshold():
    d = iocdb.revision_date() + datetime.timedelta(days=iocdb.STALE_AFTER_DAYS)
    notice = iocdb.freshness_notice(today=d)
    assert notice != []
    assert str(iocdb.STALE_AFTER_DAYS) in notice[0]
    assert iocdb.REVISION in notice[0]


def test_freshness_notice_mentions_no_network_call():
    d = iocdb.revision_date() + datetime.timedelta(days=iocdb.STALE_AFTER_DAYS + 30)
    notice = iocdb.freshness_notice(today=d)
    assert any("no network call was made" in ln for ln in notice)


def test_freshness_notice_defaults_to_real_clock_when_today_omitted():
    # No `today=` override -- exercises the real date.today() branch. The shipped
    # REVISION is recent, so this must be silent right now.
    assert iocdb.freshness_notice() == []


# --------------------------------------------------------------------------- #
# known_bad_sources(): backward-compatible view over the former literal dict.  #
# --------------------------------------------------------------------------- #
def test_known_bad_sources_has_every_expected_ecosystem_key():
    pools = iocdb.known_bad_sources()
    assert set(pools) == {"npm", "pypi", "clawhub", "git", "url", "any"}
    assert all(isinstance(v, frozenset) for v in pools.values())


def test_known_bad_sources_round_trips_the_former_hardcoded_values():
    # Every value that used to live in the inline _SOURCE_KNOWN_BAD dict is still
    # matched after the move to iocdb.py — no silent coverage loss (test plan).
    pools = iocdb.known_bad_sources()
    assert pools["clawhub"] == frozenset({
        "omnicogg", "money-radar", "letssendit",
        "ai-tradingview-assistant-for-macos", "tradingview-ai-indicator-assistant",
    })
    assert pools["url"] == frozenset({"91.92.242.30", "laosji.net", "letssendit.fun"})
    assert pools["any"] == pools["url"]
    assert pools["npm"] == pools["pypi"] == pools["git"] == frozenset()


def test_known_bad_sources_values_are_lowercased():
    for pool in iocdb.known_bad_sources().values():
        assert all(v == v.lower() for v in pool)


# --------------------------------------------------------------------------- #
# known_bad_hosts() / known_bad_publishers() / is_known_bad_host().            #
# --------------------------------------------------------------------------- #
def test_known_bad_hosts_matches_the_hosts_table():
    assert iocdb.known_bad_hosts() == {rec["value"].lower() for rec in iocdb.HOSTS}


def test_known_bad_publishers_is_empty_in_v1():
    # v1 scope deliberately ships no publisher record (none independently verified
    # with a matchable field yet) — see the PUBLISHERS docstring in iocdb.py.
    assert iocdb.known_bad_publishers() == frozenset()


def test_is_known_bad_host_exact_match():
    assert iocdb.is_known_bad_host("laosji.net") is True
    assert iocdb.is_known_bad_host("91.92.242.30") is True


def test_is_known_bad_host_subdomain_match():
    assert iocdb.is_known_bad_host("cdn.laosji.net") is True
    assert iocdb.is_known_bad_host("a.b.letssendit.fun") is True


def test_is_known_bad_host_is_case_insensitive():
    assert iocdb.is_known_bad_host("LAOSJI.NET") is True
    assert iocdb.is_known_bad_host("CDN.Laosji.Net") is True


def test_is_known_bad_host_clean_host_is_false():
    # Zero-FP: an unrelated host, and a near-miss (not a real subdomain), are both False.
    assert iocdb.is_known_bad_host("example.com") is False
    assert iocdb.is_known_bad_host("notlaosji.net") is False  # not a true subdomain
    assert iocdb.is_known_bad_host("laosji.net.evil.example") is False  # dataset host as prefix


def test_is_known_bad_host_never_raises_on_bad_input():
    assert iocdb.is_known_bad_host(None) is False
    assert iocdb.is_known_bad_host("") is False
    assert iocdb.is_known_bad_host("   ") is False


# --------------------------------------------------------------------------- #
# Offline / read-only discipline (Golden Rule #1): a pure-data leaf module.    #
# --------------------------------------------------------------------------- #
def test_module_imports_nothing_from_the_package():
    import ast
    from pathlib import Path

    src = Path(iocdb.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not (node.module or "").startswith("."), (
                "iocdb.py is a Layer 1 leaf (CLAUDE.md §3) — it must import nothing "
                "from the clawseccheck package, only stdlib."
            )
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("clawseccheck"), (
                    "iocdb.py must not import clawseccheck.* — leaf modules depend "
                    "only on each other's absence and stdlib."
                )
