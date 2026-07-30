"""B-365: BOOT.md is a real OpenClaw workspace file executed automatically on every
gateway restart (the bundled `boot-md` hook, `gateway:startup` event — grounded against
the installed dist's own docs: docs/concepts/agent-workspace.md:85, docs/automation/
hooks.md:229,280, docs/cli/hooks.md:31,101, docs/reference/templates/BOOT.md). Before
this fix `collector.BOOTSTRAP_FILES` never listed it, so it was invisible to the whole
content-security ring (B6/B7/B9 and friends, which all iterate `ctx.bootstrap`) — an
attacker who could write one file into the workspace got an uncollected, auto-executed
instruction-injection surface, the same boot-persistence class B-203 already exists for
in the installed-skill domain.

Fix: add "BOOT.md" to `BOOTSTRAP_FILES`. No new check id — the existing generic
bootstrap-injection check (B6, `check_bootstrap_injection`) already scans every
`ctx.bootstrap` entry by filename, so BOOT.md is now covered by the SAME detection as
SOUL.md/AGENTS.md/TOOLS.md with no additional machinery. These tests pin: (1) BOOT.md is
collected into `ctx.bootstrap`, (2) B6 stays silent on a benign BOOT.md checklist, (3) B6
fires FAIL on a BOOT.md carrying an injected directive, and (4) the UNKNOWN path — a
workspace with no BOOT.md (and no other bootstrap file) at all — degrades honestly with
no crash.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import check_bootstrap_injection
from clawseccheck.collector import BOOTSTRAP_FILES, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_boot_md_is_in_bootstrap_files():
    """B-365: BOOT.md must be a recognized bootstrap filename."""
    assert "BOOT.md" in BOOTSTRAP_FILES


def test_boot_md_collected_from_clean_fixture():
    ctx = collect(FIXTURES / "clean_b365_boot_md")
    keys = list(ctx.bootstrap.keys())
    assert any(k.endswith("BOOT.md") for k in keys), (
        f"Expected a BOOT.md entry in ctx.bootstrap; got: {keys}"
    )


def test_boot_md_collected_from_bad_fixture():
    ctx = collect(FIXTURES / "bad_b365_boot_md")
    keys = list(ctx.bootstrap.keys())
    assert any(k.endswith("BOOT.md") for k in keys), (
        f"Expected a BOOT.md entry in ctx.bootstrap; got: {keys}"
    )


def test_clean_boot_md_does_not_fire_b6():
    """A benign BOOT.md startup checklist must not trip the bootstrap-injection check."""
    ctx = collect(FIXTURES / "clean_b365_boot_md")
    finding = check_bootstrap_injection(ctx)
    assert finding.status == PASS, (
        f"Expected PASS on a benign BOOT.md checklist; got {finding.status}: "
        f"{finding.detail}"
    )


def test_bad_boot_md_fires_b6():
    """A BOOT.md carrying an injected 'obey all' directive must FAIL B6, naming BOOT.md."""
    ctx = collect(FIXTURES / "bad_b365_boot_md")
    finding = check_bootstrap_injection(ctx)
    assert finding.status == FAIL, (
        f"Expected FAIL on an injected BOOT.md directive; got {finding.status}: "
        f"{finding.detail}"
    )
    assert any("BOOT.md" in e for e in finding.evidence), finding.evidence


def test_no_boot_md_present_is_not_a_crash(tmp_path):
    """UNKNOWN path: a workspace with no bootstrap files at all (BOOT.md included) must
    degrade honestly to UNKNOWN, never crash and never fabricate a finding."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")

    ctx = collect(home)

    assert not any(k.endswith("BOOT.md") for k in ctx.bootstrap)
    finding = check_bootstrap_injection(ctx)
    assert finding.status == UNKNOWN


def test_boot_md_absent_but_other_bootstrap_present_is_not_unknown(tmp_path):
    """If OTHER bootstrap files exist but BOOT.md specifically does not, B6 must still
    reach a confident PASS/FAIL over the files it does have — absence of BOOT.md alone
    must never manufacture a finding about it."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    (home / "SOUL.md").write_text(
        "You are a careful, security-minded assistant.", encoding="utf-8"
    )

    ctx = collect(home)

    assert not any(k.endswith("BOOT.md") for k in ctx.bootstrap)
    finding = check_bootstrap_injection(ctx)
    assert finding.status == PASS


@pytest.mark.parametrize(
    "fixture_name,expected",
    [("clean_b365_boot_md", PASS), ("bad_b365_boot_md", FAIL)],
)
def test_boot_md_fixture_pair_end_to_end(fixture_name, expected):
    """Verify end-to-end (§ real fixture, not a hand-built Context), matching the
    project's existing clean/bad fixture-pair convention for content-ring checks."""
    ctx = collect(FIXTURES / fixture_name)
    assert check_bootstrap_injection(ctx).status == expected
