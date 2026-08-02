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
# CLAWSECCHECK-B-384 item 1: `type` is a pinned vocabulary, not free text.     #
# --------------------------------------------------------------------------- #
def test_validator_rejects_out_of_vocabulary_source_type():
    # The exact typo shape from the ticket: a mis-cased ecosystem key. Pre-fix this
    # passed validate_dataset() (non-empty was all that was checked) while silently
    # minting a dead "Clawhub" pool in known_bad_sources() that no ecosystem-scoped
    # lookup could ever reach.
    bad = {
        "value": "evil-pkg", "type": "Clawhub", "first_seen": "2026-01-01",
        "source_url": "https://example.org/advisory", "source_name": "Nobody",
    }
    problems = iocdb._validate_record("SOURCES", 0, bad)
    assert any("not in the allowed vocabulary" in p for p in problems)


def test_validator_rejects_space_padded_source_type():
    bad = {
        "value": "evil-pkg", "type": " clawhub", "first_seen": "2026-01-01",
        "source_url": "https://example.org/advisory", "source_name": "Nobody",
    }
    problems = iocdb._validate_record("SOURCES", 0, bad)
    assert any("not in the allowed vocabulary" in p for p in problems)


def test_validator_accepts_every_vocabulary_word_for_sources():
    for t in ("npm", "pypi", "clawhub", "git", "url", "any"):
        good = {
            "value": "x", "type": t, "first_seen": "2026-01-01",
            "source_url": "https://example.org/advisory", "source_name": "Nobody",
        }
        assert iocdb._validate_record("SOURCES", 0, good) == []


def test_validator_rejects_out_of_vocabulary_hosts_type():
    bad = {
        "value": "evil.example", "type": "domains", "first_seen": "2026-01-01",
        "source_url": "https://example.org/advisory", "source_name": "Nobody",
    }
    problems = iocdb._validate_record("HOSTS", 0, bad)
    assert any("not in the allowed vocabulary" in p for p in problems)


def test_validator_accepts_every_vocabulary_word_for_hosts():
    for t in ("ip", "domain"):
        good = {
            "value": "x", "type": t, "first_seen": "2026-01-01",
            "source_url": "https://example.org/advisory", "source_name": "Nobody",
        }
        assert iocdb._validate_record("HOSTS", 0, good) == []


def test_validator_type_vocab_check_never_raises_on_unhashable_type():
    bad = {
        "value": "x", "type": ["not", "a", "string"], "first_seen": "2026-01-01",
        "source_url": "https://example.org/advisory", "source_name": "Nobody",
    }
    problems = iocdb._validate_record("SOURCES", 0, bad)
    assert any("not in the allowed vocabulary" in p for p in problems)


def test_validator_type_vocab_is_scoped_to_sources_and_hosts_labels_only():
    # An arbitrary label (as the existing synthetic-record tests above already use)
    # is not subject to a vocabulary check -- only SOURCES/HOSTS are.
    ok = {
        "value": "x", "type": "not-a-real-vocab-word", "first_seen": "2026-01-01",
        "source_url": "https://example.org/advisory", "source_name": "Nobody",
    }
    assert iocdb._validate_record("TEST", 0, ok) == []
    assert iocdb._validate_record("PUBLISHERS", 0, ok) == []


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
    # CLAWSECCHECK-F-157 (C-135 regression): pre-commit, the hardcoded "any" pool was
    # an explicit, always-empty frozenset() — NOT the same set as "url". HOSTS values
    # are a host IOC (matched via vet_source's url/registry-host path), not a bare
    # name to be checked against every ecosystem, so "any" must stay empty exactly
    # like the former literal — never widen to equal "url" again.
    assert pools["any"] == frozenset()
    assert pools["npm"] == pools["pypi"] == pools["git"] == frozenset()


def test_known_bad_sources_any_pool_excludes_every_hosts_value():
    # CLAWSECCHECK-F-157 regression pin: none of the 3 HOSTS literals may leak into
    # the "any" pool, or a pypi/npm/git/clawhub package whose bare NAME happens to
    # collide with a host literal (e.g. a pypi package literally named "laosji.net")
    # would wrongly FAIL vet_source's exact-name match (eco_keys = [eco, "any"])
    # as a "known-bad source", despite having nothing to do with the actual IOC host.
    pools = iocdb.known_bad_sources()
    hosts_values = {rec["value"].lower() for rec in iocdb.HOSTS}
    assert hosts_values, "sanity: HOSTS must be non-empty for this test to mean anything"
    assert not (hosts_values & pools["any"])
    # And confirm the true positive is preserved: every HOSTS value IS still in "url",
    # so a real url/registry-host IOC match keeps firing (no real detection lost).
    assert hosts_values <= pools["url"]


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
# CLAWSECCHECK-B-436 item 4: is_known_bad_host() strips a trailing DNS root    #
# dot before comparison -- "laosji.net." resolves to the identical server as  #
# "laosji.net" and must not silently evade the match.                        #
# --------------------------------------------------------------------------- #
def test_is_known_bad_host_strips_trailing_root_dot_exact():
    assert iocdb.is_known_bad_host("laosji.net.") is True
    assert iocdb.is_known_bad_host("91.92.242.30.") is True


def test_is_known_bad_host_strips_trailing_root_dot_subdomain():
    assert iocdb.is_known_bad_host("cdn.laosji.net.") is True


def test_is_known_bad_host_all_dots_is_false_not_a_crash():
    # A host that is nothing but dots must not match an empty-string bad value.
    assert iocdb.is_known_bad_host(".") is False
    assert iocdb.is_known_bad_host("...") is False


# --------------------------------------------------------------------------- #
# CLAWSECCHECK-B-384 item 2: is_known_bad_host() honors `type` -- exact-only    #
# for "ip" records, exact-or-subdomain for "domain" records.                  #
# --------------------------------------------------------------------------- #
def test_is_known_bad_host_ip_record_is_exact_only_not_suffix():
    # The 91.92.242.30 dataset record is type="ip". Pre-fix, is_known_bad_host()
    # discarded `type` entirely and applied the domain endswith-subdomain rule
    # uniformly, so a longer numeric string ending in the exact IP text would wrongly
    # match as though it were a "subdomain" of an IP -- which is not a meaningful
    # concept for an IP record at all.
    assert iocdb.is_known_bad_host("1.91.92.242.30") is False
    assert iocdb.is_known_bad_host("991.92.242.30") is False
    assert iocdb.is_known_bad_host("91.92.242.300") is False
    # The exact IP itself must still match.
    assert iocdb.is_known_bad_host("91.92.242.30") is True


def test_is_known_bad_host_domain_record_still_does_subdomain_match():
    # The type-honoring fix must not regress the (correct, pre-existing) domain
    # subdomain-match behavior -- only the IP leg changes.
    assert iocdb.is_known_bad_host("cdn.laosji.net") is True
    assert iocdb.is_known_bad_host("a.b.letssendit.fun") is True


def test_known_bad_host_records_carries_the_type_field():
    records = iocdb.known_bad_host_records()
    by_value = dict(records)
    assert by_value["91.92.242.30"] == "ip"
    assert by_value["laosji.net"] == "domain"
    assert by_value["letssendit.fun"] == "domain"


# --------------------------------------------------------------------------- #
# CLAWSECCHECK-B-384 item 4: the HOSTS lookup structure is built once at       #
# import time, not rebuilt on every call.                                     #
# --------------------------------------------------------------------------- #
def test_known_bad_hosts_returns_the_same_object_on_repeated_calls():
    first = iocdb.known_bad_hosts()
    second = iocdb.known_bad_hosts()
    assert first is second


def test_known_bad_host_records_returns_the_same_object_on_repeated_calls():
    assert iocdb.known_bad_host_records() is iocdb.known_bad_host_records()


def test_known_bad_host_records_is_the_module_level_constant():
    assert iocdb.known_bad_host_records() is iocdb._KNOWN_BAD_HOST_RECORDS


# --------------------------------------------------------------------------- #
# CLAWSECCHECK-B-384 item 1 (round-trip): every SOURCES record must be         #
# reachable via vet_source's ecosystem-scoped exact-match path -- catches a    #
# dead pool (a typo'd/mis-cased type) mechanically, not just via validation.   #
# --------------------------------------------------------------------------- #
def test_every_sources_record_round_trips_through_vet_source():
    from clawseccheck.catalog import FAIL
    from clawseccheck.checks._vet import vet_source

    for rec in iocdb.SOURCES:
        target = f"{rec['type']}:{rec['value']}"
        f = vet_source(target)
        assert f.status == FAIL, (
            f"{target!r} did not round-trip through vet_source (got {f.status}: "
            f"{f.detail}) -- the SOURCES record's ecosystem pool may be dead "
            f"(unreachable type)."
        )


# --------------------------------------------------------------------------- #
# CLAWSECCHECK-B-384 item 3: checks/_shared.py's _KNOWN_EXFIL_HOST_RE now has  #
# the IOC dataset's hosts spliced into its own alternation (replacing the      #
# former, separately-compiled _IOCDB_HOST_RE) -- it must agree with            #
# iocdb.is_known_bad_host() on every iocdb-dataset-derived verdict.            #
# --------------------------------------------------------------------------- #
def test_known_exfil_host_re_agrees_with_is_known_bad_host_on_a_small_corpus():
    from clawseccheck.checks._shared import _KNOWN_EXFIL_HOST_RE

    corpus = {
        "91.92.242.30": True,  # exact match (ip)
        "laosji.net": True,  # exact match (domain)
        "cdn.laosji.net": True,  # subdomain match (domain)
        "a.b.letssendit.fun": True,  # subdomain match (domain)
        "1.91.92.242.30": False,  # ip: not a subdomain concept, must not match
        "91.92.242.300": False,  # exact-only: not the same string
        "evil-laosji.net": False,  # hyphen-prefixed: not a real subdomain
        "notlaosji.net": False,  # hyphen/letter-prefixed: not a real subdomain
        "laosji.net.evil.example": False,  # dataset host as prefix (path-suffixed)
        "example.com": False,  # unrelated host
    }
    for host, expected in corpus.items():
        precise = iocdb.is_known_bad_host(host)
        regex = bool(_KNOWN_EXFIL_HOST_RE.search(host))
        assert precise == expected, f"{host!r}: iocdb.is_known_bad_host = {precise}, want {expected}"
        assert regex == expected, f"{host!r}: _KNOWN_EXFIL_HOST_RE match = {regex}, want {expected}"
        assert precise == regex, (
            f"{host!r}: iocdb.is_known_bad_host ({precise}) and _KNOWN_EXFIL_HOST_RE "
            f"({regex}) disagree"
        )


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
