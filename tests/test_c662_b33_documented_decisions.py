"""B33 (`check_known_vulns`) - the nine open points were ruled as DOCUMENTED STATUS QUO.

For each point the behaviour B33 has today is the decision, and one test below pins its cell, so
a later change has to be a deliberate one:

  a  a stamp-only affected result stays FAIL (another home, `--no-dist`, no usable installed build)
  b  plugin-package and iOS advisories are not tabulated; every verdict's `fix` says so
  c  a pre-release reads as its release (so a beta of a patched build reads as patched)
  d  the WARN for an affected extended-stable stamp carries the "N further published advisories" note
  e  C4's rollback WARN keeps its `detail`; its `fix` says when B33 reads the stamp
  f  the WARN advice names `openclaw --version` and NOT `openclaw gateway status`
  g  a table row's title is documentation only (one row's title is pinned)
  h  the fixture `reliability/clean_b33_version_patched` FAILs B33 despite its name (documented)
  i  a `.openclaw-<name>` directory nothing runs as a profile is judged this machine's home

Hermetic: no network, nothing outside `tmp_path`; HOME and every OPENCLAW_* path variable are set.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _KNOWN_ADVISORIES,
    _lifecycle,
    _parse_version,
    check_known_vulns,
    check_version,
)
from clawseccheck.collector import Context

_ROOT = Path(__file__).resolve().parent.parent
_NOTE = (
    "Advisories on separately versioned plugin packages and on the iOS app are not tabulated "
    "here, so this result says nothing about them."
)
_INSTALLED_OK = "2026.9.7"  # patched: no row reaches it


@pytest.fixture
def machine(monkeypatch, tmp_path):
    """A hermetic 'this machine': HOME is tmp_path, no OPENCLAW_* path variable, ~/.openclaw exists."""
    for var in ("OPENCLAW_HOME", "OPENCLAW_STATE_DIR", "OPENCLAW_CONFIG_PATH", "USERPROFILE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".openclaw").mkdir()
    return tmp_path


@pytest.fixture
def all_ids(monkeypatch):
    monkeypatch.setattr(_lifecycle, "_B33_EVIDENCE_CAP", 10_000)


def _run(stamp, installed, home):
    c = Context(home=home)
    c.config = {} if stamp is None else {"meta": {"lastTouchedVersion": stamp}}
    c.installed_dist_version = installed
    return check_known_vulns(c)


def _stamp_only(stamp):
    return _run(stamp, None, Path("/nonexistent"))


# ---- a: the stamp-only FAIL is kept ----------------------------------------------------------

def test_a_stamp_only_affected_result_stays_fail_on_every_path_without_an_installed_verdict(machine):
    """A stamp can be stale (only a config write rewrites it), yet where the installed build does not
    decide it is the only evidence about the home, so the result is FAIL - never WARN."""
    other = machine / "backup-plain"
    other.mkdir()
    for home, installed in (
        (other, _INSTALLED_OK),  # another home: the installed build describes the auditing machine
        (machine / ".openclaw", None),  # --no-dist / no installed package found
        (machine / ".openclaw", "nightly"),  # an installed string that does not parse
    ):
        r = _run("2026.7.1", installed, home)
        assert r.status == FAIL, (home, installed)
        assert r.detail.startswith("OpenClaw 2026.7.1 is affected by 40 known advisories: ")
        assert ">= 2026.9.2" in r.fix


def test_a_the_same_stamp_is_only_a_warn_when_the_installed_build_decides(machine):
    r = _run("2026.7.1", _INSTALLED_OK, machine / ".openclaw")
    assert r.status == WARN
    assert "(2026.7.1) is affected by 40 known advisories" in r.detail


# ---- b: plugin-package and iOS advisories are not tabulated ------------------------------------

_UNTABULATED = (  # the 14 advisories of the 2026-09-11 batch that are not on the core package
    "GHSA-35wj-hm2r-ghgw", "GHSA-xvwp-wmh2-fq48", "GHSA-rx8p-qcpv-c7vr", "GHSA-58qx-6m8p-wh2j",
    "GHSA-v7hh-7676-rg67", "GHSA-9m4p-cqp4-jppq", "GHSA-h2qg-fxpv-82v6", "GHSA-hgv5-f2r3-6v9r",
    "GHSA-rrxp-5mx8-mvhh", "GHSA-fgwg-c3wv-8f45", "GHSA-g7fw-3gjp-g5hf", "GHSA-5j57-84cx-r295",
    "GHSA-gcm4-fmcp-2f9r", "GHSA-jjpc-p3xf-8g7p",
)


def test_b_the_untabulated_plugin_and_ios_advisories_are_not_rows():
    assert len(set(_UNTABULATED)) == 14
    assert not set(_UNTABULATED) & {row[0] for row in _KNOWN_ADVISORIES}


def test_b_every_verdict_that_judged_a_version_says_plugins_and_ios_are_not_tabulated(machine):
    results = {
        "pass": _stamp_only("2026.9.2"),
        "fail": _stamp_only("2026.7.1"),
        "fail-extended": _stamp_only("2026.7.35"),
        "unknown-unexamined": _stamp_only("2026.7.36"),
        "warn": _run("2026.7.1", _INSTALLED_OK, machine / ".openclaw"),
    }
    assert [r.status for r in results.values()] == [PASS, FAIL, FAIL, UNKNOWN, WARN]
    for name, r in results.items():
        assert r.fix.endswith(" " + _NOTE), name
        assert "plugin" not in r.detail and "iOS" not in r.detail, name  # `detail` is hashed: untouched


def test_b_a_version_that_could_not_be_judged_has_nothing_to_disclose():
    assert _NOTE not in _stamp_only(None).fix
    assert _NOTE not in _stamp_only("nightly").fix


# ---- c: a pre-release reads as its release -------------------------------------------------------

def test_c_a_prerelease_collapses_onto_its_release():
    assert _parse_version("2026.8.1-beta.2") == (2026, 8, 1)
    assert _parse_version("2026.7.1-2") == (2026, 7, 1)


@pytest.mark.parametrize("stamp", ["2026.9.2-beta.1", "2026.9.3-beta.1"])
def test_c_a_beta_of_the_newest_fixed_build_reads_as_patched(stamp):
    """In the vendor's order such a beta is below the fixed build; B33 judges it as the release and
    PASSes. No such build is published; ordering it below its release would move verdicts."""
    r = _stamp_only(stamp)
    assert r.status == PASS
    assert r.detail == f"OpenClaw {stamp} is at or past all known-advisory fixes."


def test_c_a_beta_of_an_affected_build_fails_with_the_ids_of_its_release(all_ids):
    beta, final = _stamp_only("2026.8.1-beta.2"), _stamp_only("2026.8.1")
    assert beta.status == final.status == FAIL
    assert beta.evidence == final.evidence


def test_c_a_beta_of_a_lower_bounded_rows_first_version_lists_that_row(all_ids):
    """The documented difference in id lists: `2026.7.2-beta.N` parses onto 2026.7.2, where
    GHSA-5x6q-wg56-rxg8 (>= 2026.7.2, < 2026.9.2) starts."""
    assert "GHSA-5x6q-wg56-rxg8" in _stamp_only("2026.7.2-beta.1").evidence


# ---- d: the WARN for an extended-stable stamp discloses the further advisories ----------------

@pytest.mark.parametrize("stamp", ["2026.6.35", "2026.7.35"])
def test_d_the_warn_for_an_affected_extended_stable_stamp_counts_the_further_advisories(machine, stamp):
    warn = _run(stamp, _INSTALLED_OK, machine / ".openclaw")
    fail = _stamp_only(stamp)
    assert warn.status == WARN and fail.status == FAIL
    n = re.search(r"(\d+) further published advisories", fail.fix).group(1)
    assert int(n) > 0
    assert (
        f"{n} further published advisories cover the build that last wrote this config by version "
        "range; they are not listed because the table has not confirmed them for the build that "
        "last wrote this config:"
    ) in warn.fix
    assert "further" not in warn.detail  # the detail is hashed and is unchanged


def test_d_the_2026_7_35_numbers_are_the_measured_ones(machine):
    warn = _run("2026.7.35", _INSTALLED_OK, machine / ".openclaw")
    assert "is affected by 3 known advisories. This check does not determine" in warn.detail
    assert "38 further published advisories cover" in warn.fix


def test_d_no_further_note_where_it_does_not_apply(machine):
    ordinary = _run("2026.7.1", _INSTALLED_OK, machine / ".openclaw")  # not an extended-stable stamp
    unexamined = _run("2026.7.36", _INSTALLED_OK, machine / ".openclaw")  # detail already counts ranges
    for r in (ordinary, unexamined):
        assert r.status == WARN
        assert "further published advisories" not in r.fix


# ---- e: C4's rollback WARN ----------------------------------------------------------------------

def test_e_c4_rollback_warn_keeps_its_detail_and_says_in_fix_when_b33_reads_the_stamp():
    c = Context(home=Path("/nonexistent"))
    c.config = {"meta": {"lastTouchedVersion": "2026.9.7"}}
    c.installed_dist_version = "2026.9.2"
    r = check_version(c)
    assert r.status == WARN
    assert r.detail.endswith(
        "This is not a vulnerability claim — B33 checks the installed version against real advisories."
    )
    assert "B33 judges the installed build only when you audit this machine's own OpenClaw home" in r.fix
    assert "with --no-dist, or on another home, it judges the version recorded in the config" in r.fix


# ---- f: the WARN advice names one command --------------------------------------------------------

def test_f_the_warn_advice_names_openclaw_version_and_not_gateway_status(machine):
    """`openclaw --version` was executed. `openclaw gateway status` exists in the installed dist, but
    what it prints with the gateway down was read, not executed, so the advice does not name it."""
    r = _run("2026.7.1", _INSTALLED_OK, machine / ".openclaw")
    assert r.status == WARN
    assert "`openclaw --version`" in r.fix
    assert "gateway status" not in r.fix and "gateway status" not in r.detail
    assert "restart it" in r.fix


# ---- g: a row's title is documentation -----------------------------------------------------------

def test_g_the_title_of_a_batch_row_is_pinned_and_every_title_is_text():
    titles = {row[0]: row[3] for row in _KNOWN_ADVISORIES}
    assert titles["GHSA-5x6q-wg56-rxg8"] == "Discord realtime transcripts could inherit another speaker's owner status"
    assert all(isinstance(t, str) and t.strip() for t in titles.values())


# ---- h: the fixture whose name claims B33 -------------------------------------------------------

def test_h_fixture_clean_b33_version_patched_fails_b33_and_the_readme_says_so():
    """The name is historical (it was created when a single seeded advisory was patched at its stamp)
    and is NOT changed, because fixtures feed manifests. At stamp 2026.2.14 the table reaches it."""
    fixture = _ROOT / "fixtures" / "reliability" / "clean_b33_version_patched" / "openclaw.json"
    cfg = json.loads(fixture.read_text(encoding="utf-8"))
    assert cfg["meta"]["lastTouchedVersion"] == "2026.2.14"
    c = Context(home=fixture.parent)
    c.config = cfg
    r = check_known_vulns(c)
    assert r.status == FAIL
    assert r.detail.startswith("OpenClaw 2026.2.14 is affected by ")
    readme = (_ROOT / "fixtures" / "README.md").read_text(encoding="utf-8")
    assert "reliability/clean_b33_version_patched/" in readme and "B33" in readme


# ---- i: a profile-shaped directory is judged this machine's home --------------------------------

@pytest.mark.parametrize(
    "name,stamp,status",
    [
        (".openclaw-backup", "2026.7.1", WARN),  # an ordinary backup copy: the installed build decides
        ("backup-plain", "2026.7.1", FAIL),  # same config, not profile-shaped: the stamp decides
        (".openclaw-nostamp", None, PASS),  # a wrong "yes" turns UNKNOWN into a verdict on the install
        ("nostamp-plain", None, UNKNOWN),
        (".openclaw-nope", None, UNKNOWN),  # does not exist: not this machine's home
    ],
)
def test_i_the_judged_version_follows_the_directory_name(machine, name, stamp, status):
    home = machine / name
    if name != ".openclaw-nope":
        home.mkdir()
    assert _run(stamp, _INSTALLED_OK, home).status == status


def test_i_no_profile_shaped_directory_turns_a_stamp_only_fail_into_a_pass(machine):
    home = machine / ".openclaw-backup"
    home.mkdir()
    assert _run("2026.7.1", _INSTALLED_OK, home).status == WARN  # FAIL -> WARN is the accepted shift
    assert _run("2026.7.1", None, home).status == FAIL  # --no-dist: the stamp decides again


# ---- the docs state the decisions ----------------------------------------------------------------

def test_the_docs_record_the_decisions():
    usage = (_ROOT / "docs" / "USAGE.md").read_text(encoding="utf-8")
    coverage = (_ROOT / "docs" / "THREAT_COVERAGE.md").read_text(encoding="utf-8")
    for phrase in (
        "A stale recorded version still fails",
        "Plugin packages and the iOS app are not tabulated",
        "A pre-release reads as its release",
        "Extended-stable builds list only what is confirmed",
        "The WARN names one command",
        "A directory named `.openclaw-<name>` counts as this machine's home",
    ):
        assert phrase in usage, phrase
    row = next(line for line in coverage.splitlines() if line.startswith("| Known-vulnerable version gate"))
    for phrase in ("stays a FAIL", "judged as its release", "further published ranges", "`.openclaw-<name>`", "not tabulated"):
        assert phrase in row, phrase
