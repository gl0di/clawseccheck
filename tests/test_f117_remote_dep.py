"""F-117 — B157: non-registry / remote-code dependency source in a skill package.json.

FAIL only for a remote-code source with unverifiable provenance (plaintext http/ftp, raw
public IP, .onion — mirrors B103); every other non-registry source (git+https, https tarball,
github shorthand, file:/link:/npm:) is WARN. Registry versions — including the ubiquitous
caret/tilde float — are clean.
"""

from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_remote_code_dependency
from clawseccheck.checks._content import _bad_provenance_url
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(pkgjson):
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = {"skill": "# file: package.json\n" + pkgjson}
    return c


def test_b157_unknown_no_skills():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = {}
    assert check_remote_code_dependency(c).status == UNKNOWN


def test_b157_pass_pinned_and_caret():
    """Registry versions — exact pins AND the ubiquitous caret/tilde float — are clean."""
    for pj in (
        '{"dependencies":{"dayjs":"1.11.10","zod":"3.22.4"}}',
        '{"dependencies":{"react":"^18.2.0","x":"~1.0.0"}}',
        '{"dependencies":{"a":">=1.0.0","b":"workspace:*"}}',
    ):
        assert check_remote_code_dependency(_ctx(pj)).status == PASS, pj


def test_b157_warn_non_registry_sources():
    """git+https / https tarball / github shorthand / file: / link: are WARN (legitimate for
    forks & monorepos, but bypass registry integrity)."""
    for pj in (
        '{"dependencies":{"lib":"git+https://github.com/x/y#abc"}}',
        '{"dependencies":{"lib":"https://ex.tld/x.tgz"}}',
        '{"dependencies":{"lib":"user/repo"}}',
        '{"dependencies":{"shared":"file:../shared"}}',
        '{"dependencies":{"lib":"link:../lib"}}',
    ):
        assert check_remote_code_dependency(_ctx(pj)).status == WARN, pj


def test_b157_fail_bad_provenance():
    """A remote-code source with unverifiable provenance — plaintext http, raw public IP, or
    .onion — is a FAIL."""
    for pj in (
        '{"dependencies":{"lib":"git+http://1.2.3.4/repo.git"}}',
        '{"dependencies":{"lib":"https://8.8.8.8/x.tgz"}}',
        '{"dependencies":{"lib":"git+https://abcdefghijklmnop.onion/r.git"}}',
    ):
        assert check_remote_code_dependency(_ctx(pj)).status == FAIL, pj


def test_bad_provenance_url_predicate():
    assert _bad_provenance_url("git+http://1.2.3.4/r.git") is True
    assert _bad_provenance_url("https://9.9.9.9/x.tgz") is True
    assert _bad_provenance_url("git+https://github.com/x/y") is False  # named host, https
    assert _bad_provenance_url("git+https://192.168.1.10/r.git") is False  # private IP = homelab
    assert _bad_provenance_url("file:../shared") is False  # not a URL


def test_b157_clean_fixture_passes():
    f = check_remote_code_dependency(collect(FIXTURES / "clean_f117_registry"))
    assert f.status == PASS, f"Expected PASS, got {f.status}: {f.detail}"


def test_b157_bad_fixture_fails():
    f = check_remote_code_dependency(collect(FIXTURES / "bad_f117_http_git"))
    assert f.status == FAIL, f"Expected FAIL, got {f.status}: {f.detail}"


def test_b157_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_f117_http_git", include_native=False)
    assert "B157" in {f.id for f in findings}
