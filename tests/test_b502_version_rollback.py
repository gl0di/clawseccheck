"""B-502 — C4 (``check_version``) version-rollback comparison.

C4 used to print ``meta.lastTouchedVersion`` and PASS unconditionally whenever it was
present, so a rollback onto an older OpenClaw build (a downgrade that re-opens whatever
a newer build had fixed) stayed PASS. It now compares the SELF-REPORTED version (which
build last wrote the config) against the INSTALLED version
(``ctx.installed_dist_version``), in the same run:

* installed OLDER than self-reported -> WARN (a rollback signature, never a
  vulnerability claim -- B33 owns that).
* the two cannot be reliably ordered (pre-release / non-numeric) -> UNKNOWN, never a
  fabricated PASS.
* equal, or installed newer -> PASS.
* ``installed_dist_version`` absent -> the ORIGINAL presence-only PASS, byte-identical
  to what HEAD produced before this change -- this is what keeps the fixture-corpus
  fingerprint manifest (``tests/test_finding_fingerprint_manifest.py``) stable, since
  the manifest is built by ``audit()`` with ``include_dist`` left at its hermetic
  default (False).

Every test below drives ``check_version`` by setting ``ctx.installed_dist_version``
directly (or leaving it at the dataclass default). None of them touch PATH or any real
OpenClaw install, so the suite's verdict never depends on whatever happens to be
installed on the machine running it.
"""
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_version
from clawseccheck.collector import Context


def _ctx(last_touched_version="2026.7.1", installed_dist_version=None):
    """A bare Context with just what check_version reads.

    ``last_touched_version=None`` omits ``meta.lastTouchedVersion`` from the config
    entirely, for the pre-existing "not recorded" branch (case 5 below).
    """
    c = Context(home=Path("/nonexistent"))
    if last_touched_version is None:
        c.config = {}
    else:
        c.config = {"meta": {"lastTouchedVersion": last_touched_version}}
    c.installed_dist_version = installed_dist_version
    return c


# ---------------------------------------------------------------- 1. downgrade -> WARN
def test_downgrade_warns():
    """Installed build older than the version that last wrote the config -> WARN."""
    result = check_version(_ctx(last_touched_version="2026.7.1",
                                 installed_dist_version="2026.3.0"))
    assert result.id == "C4"
    assert result.status == WARN
    assert "2026.3.0" in result.detail
    assert "2026.7.1" in result.detail
    assert "OLDER" in result.detail
    assert "rollback" in result.detail.lower()


# ---------------------------------------------------------------- 2. upgrade / equal -> PASS
def test_upgrade_passes():
    """Installed build newer than the config's self-reported version -> PASS."""
    result = check_version(_ctx(last_touched_version="2026.3.0",
                                 installed_dist_version="2026.7.1"))
    assert result.id == "C4"
    assert result.status == PASS
    assert "2026.3.0" in result.detail
    assert "2026.7.1" in result.detail
    assert "newer" in result.detail.lower()


def test_equal_versions_pass():
    """Self-reported and installed versions match -> PASS, no rollback signal."""
    result = check_version(_ctx(last_touched_version="2026.7.1",
                                 installed_dist_version="2026.7.1"))
    assert result.id == "C4"
    assert result.status == PASS
    assert "2026.7.1" in result.detail
    assert "matching the installed" in result.detail


# ---------------------------------------------------------------- 3. unorderable -> UNKNOWN
def test_unorderable_pair_is_unknown_not_pass():
    """A pre-release token on one side cannot be reliably ordered -> UNKNOWN.

    This is the exact bug class C4 exists to fix: fabricating confidence (a PASS or a
    WARN) about a comparison that cannot actually be made.
    """
    result = check_version(_ctx(last_touched_version="1.0.0-rc1",
                                 installed_dist_version="1.0.0"))
    assert result.id == "C4"
    assert result.status == UNKNOWN
    assert result.status != PASS
    assert "1.0.0-rc1" in result.detail
    assert "1.0.0" in result.detail


# ---------------------------------------------------------------- 4. no dist version -> byte-identical PASS
def test_no_installed_dist_version_matches_head_byte_for_byte():
    """``installed_dist_version`` unset (the hermetic default) -> the ORIGINAL
    presence-only PASS, with a detail string byte-identical to what HEAD produced
    before B-502 -- protecting the finding-fingerprint manifest.

    Exact string as of ``git show HEAD:clawseccheck/checks/_lifecycle.py``:
        f"OpenClaw config last touched by version {ver}. Known-vulnerable releases "
        "are gated by B33; this is an update-hygiene reminder, not a vulnerability claim."
    """
    ver = "2026.7.1-2"
    result = check_version(_ctx(last_touched_version=ver, installed_dist_version=None))
    assert result.id == "C4"
    assert result.status == PASS
    expected_detail = (
        f"OpenClaw config last touched by version {ver}. Known-vulnerable releases "
        "are gated by B33; this is an update-hygiene reminder, not a vulnerability claim."
    )
    assert result.detail == expected_detail
    assert result.fix == "Keep OpenClaw updated and re-run the checks after upgrading."


# ---------------------------------------------------------------- 5. no lastTouchedVersion -> UNKNOWN
def test_no_last_touched_version_is_unknown():
    """meta.lastTouchedVersion absent from the config entirely -> UNKNOWN
    (pre-existing behaviour, must not regress)."""
    result = check_version(_ctx(last_touched_version=None, installed_dist_version="2026.7.1"))
    assert result.id == "C4"
    assert result.status == UNKNOWN
    assert result.detail == "OpenClaw version not recorded in config."
    assert result.fix == "—"


# ---------------------------------------------------------------- 6. hermetic default
def test_audit_without_include_dist_leaves_installed_dist_version_none(tmp_path):
    """``audit(include_dist=False)`` (the default) leaves
    ``ctx.installed_dist_version`` as None -- the seam every branch above rests on."""
    ctx, _findings, _score = audit(tmp_path)
    assert ctx.include_dist is False
    assert ctx.installed_dist_version is None
