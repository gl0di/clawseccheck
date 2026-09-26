"""Subprocess CLI hermeticity: every audit-path spawn of the real clawseccheck CLI must
carry --no-host.

THE BUG THIS GUARDS (CLAWSECCHECK-B-881). `cli.py` enables real host-filesystem
scanning by default (`include_host=not args.no_host`, wired into `build_context()`/
`audit()` at the same three call sites as `--no-deptree` -- see
`test_subprocess_deptree_hermeticity.py`). `conftest.py`'s autouse `_stub_host_detect`
fixture neutralizes this FOR THE IN-PROCESS TEST INTERPRETER via
`monkeypatch.setattr(clawseccheck, "_host_detect", ...)` -- but monkeypatch cannot cross
a process boundary, the exact same bug `_stub_deptree_scan` has. Every test that spawns
the CLI as a real subprocess on the audit path without `--no-host` therefore still makes
real, absolute-path reads of this machine's own cron/systemd/firewall configuration
(`/etc/cron.d`, `/etc/cron.daily`, `/etc/cron.hourly`, `/etc/cron.monthly`,
`/etc/crontab`, `/etc/systemd/system`, `/etc/default/ufw`, `/etc/ufw/ufw.conf`,
`/etc/nftables.conf` -- the exact surface the hermeticity ledger recorded, see
`tests/hermeticity_allowlist.txt`'s git history for the entry this guard's fix retired).

WHY --no-deptree'S OWN FIX DOES NOT COVER THIS. Unlike the deptree hole, this one is not
closed by overriding the child's `$HOME`: `hostpersist.py`'s cron/systemd/firewall
probes are hardcoded absolute OS paths, entirely independent of `$HOME`. A different,
already-existing flag closes it: `--no-host` (`cli.py` `p.add_argument("--no-host", ...)`
~line 3441) was already wired to `include_host` at every `build_context()` call site --
it simply was not being PASSED by the test suite's own subprocess spawns, the same
"flag exists, tests don't pass it" shape as the original deptree gap.

WHAT THIS GUARD DOES AND DOES NOT PROVE, AND HOW IT WORKS. Shares the exact same
AST-resolution engine as `test_subprocess_deptree_hermeticity.py` (see
`tests/_subprocess_argv.py`'s module docstring for the full rationale, and that
sibling module's docstring for the guard's design in detail) -- only the required flag
and this module's own exemption lists differ. Proving these two guards actually target
the same set of "audit-path" call sites: an earlier run of this exact engine against
this repo (2026-09-21, while the sibling deptree guard was designed) measured 224
call sites across 47 files needing `--no-deptree` on the audit path; adding `--no-host`
alongside `--no-deptree` at those same call sites, plus two files the original
CLAWSECCHECK-B-881 fix missed (`tests/test_b870_journal_lock_tilde.py`,
`tests/test_b877_a1_warn_wording.py` -- both already carried `--no-deptree` but not
`--no-host`, found by running THIS guard rather than trusting the point-in-time file
list), is what closes this guard to zero offenders.
"""
from __future__ import annotations

from _subprocess_argv import REPO_ROOT, analyze_file, list_test_files

_THIS_FILE = "test_subprocess_host_hermeticity.py"
_SIBLING_GUARD_FILE = "test_subprocess_deptree_hermeticity.py"
_EXCLUDED_FILES = frozenset({_THIS_FILE, _SIBLING_GUARD_FILE})

_REQUIRED_FLAG = "--no-host"

# Identical gating to test_subprocess_deptree_hermeticity.py's own _SAFE_MODE_FLAGS --
# see that module for the full per-flag reasoning (each proven by reading cli.py's own
# dispatch table). `include_host` and `include_deptree` are set together at the same
# three `build_context()` call sites, so a `main()` branch that bypasses one bypasses
# the other identically. Kept as its own module-level constant rather than a shared
# import so each guard file stays independently readable -- see that module's own note
# on why this duplication is deliberate.
_SAFE_MODE_FLAGS = frozenset({
    "--vet", "--vet-skill", "--vet-plugin", "--vet-mcp", "--vet-source", "--vet-all",
    "--advise", "--canary", "--redteam", "--dryrun", "--multiturn", "--self-test",
    "--verify-history", "--verify-events", "--verify-baseline", "--watch-log",
    "--version",
})

# Call sites that must NOT carry --no-host, because the test's whole point is a real
# host-posture scan. No subprocess test currently exercises the cron/systemd/firewall
# checks (checks/_host.py) end-to-end against real machine state -- every existing test
# of those checks fakes the posture in-process (monkeypatch / a fixture Context), never
# through a real subprocess spawn. Keyed "relative/path.py:function_qualname", same
# shape as the deptree guard's _DELIBERATE_DEPTREE_WALK.
_DELIBERATE_HOST_SCAN: dict[str, str] = {
    # Same guard blind spot as the deptree guard's own _DELIBERATE_DEPTREE_WALK entry
    # for this exact test (not a real deliberate scan): `_emitted([flag, arg])` spreads
    # a `pytest.mark.parametrize("flag", [...])` value into the argv, which this guard
    # cannot look inside. Hand-verified 2026-09-23 by reading the decorator two lines
    # above the test: the only three values are '--vet-skill', '--vet-plugin',
    # '--vet-mcp', all already in _SAFE_MODE_FLAGS. Re-check this entry if that
    # parametrize list ever grows a new flag.
    "tests/test_b632_vet_envelope_schema.py:"
    "test_vet_modes_emit_exactly_the_documented_base_envelope":
        "Guard blind spot, not a real host scan -- see the comment above this entry.",
}

# Call sites whose argv this guard cannot statically resolve at all, cleared BY HAND.
# Shared root cause with the deptree guard's own _UNTRACEABLE_ARGV (same call sites,
# same opacity reason -- this guard's classification of "unresolved" does not depend on
# which flag is being looked for, only on whether the argv itself can be traced at all),
# duplicated here rather than imported so this file states its own exemptions plainly
# without a reader having to cross-reference the sibling module to know what is exempt
# from THIS guard.
_UNTRACEABLE_ARGV: dict[str, str] = {
    "tests/test_b728_dist_locator.py:_fails_rather_than_skips":
        "False positive, not a real gap: `_fails_rather_than_skips(call, what)` takes a "
        "PARAMETER named `call` (an arbitrary callable the test passes in) and invokes it "
        "as `call()` -- this guard's own call-site detection treats any bare `Name` "
        "matching {run,Popen,check_output,check_call,call} as `subprocess.call` (to "
        "support `from subprocess import run` style imports), so a local variable that "
        "merely happens to be named `call` collides with that heuristic. Hand-verified "
        "2026-09-21 (deptree guard) / re-confirmed 2026-09-23 (this guard, CLAWSECCHECK-"
        "B-881): the function never imports or calls `subprocess.call`, it is a generic "
        "'run this and expect an AssertionError, not a skip' helper used on ordinary "
        "Python callables in this file.",
    "tests/test_publish_workflow.py:_replay_staged_tree":
        "Real gap in the guard's own argv resolution, not the test: the call is "
        "`subprocess.run([\"git\", \"ls-files\", ..., \"--\", *staged], ...)` -- argv[0] is "
        "the literal 'git', never `sys.executable`, so this can never be a "
        "`python -m clawseccheck[.cli]` spawn no matter what the opaque `staged` spread "
        "contains. Hand-verified 2026-09-21 (deptree guard) / re-confirmed 2026-09-23 "
        "(this guard) by reading both `_replay_staged_tree` and `_staged_paths`.",
}


def test_every_subprocess_cli_spawn_on_the_audit_path_passes_no_host() -> None:
    offenders = []
    for path in list_test_files(_EXCLUDED_FILES):
        for lineno, qualname, verdict, detail in analyze_file(path, _REQUIRED_FLAG, _SAFE_MODE_FLAGS):
            if verdict not in ("needs-flag", "unresolved"):
                continue
            key = f"{path.relative_to(REPO_ROOT)}:{qualname}"
            if verdict == "needs-flag" and key in _DELIBERATE_HOST_SCAN:
                continue
            if verdict == "unresolved" and key in _UNTRACEABLE_ARGV:
                continue
            loc = f"{path.relative_to(REPO_ROOT)}:{lineno} ({qualname})"
            if verdict == "needs-flag":
                offenders.append(
                    f"{loc}: spawns the CLI on the audit path without --no-host "
                    f"({detail}). This makes real reads of this machine's own "
                    "cron/systemd/firewall configuration -- a hermeticity break "
                    "(CLAWSECCHECK-B-881; see this module's docstring). Add --no-host "
                    f"to the argv, or if the test genuinely needs a real host scan, add "
                    f"{key!r} to _DELIBERATE_HOST_SCAN with a reason."
                )
            else:
                offenders.append(
                    f"{loc}: {detail} -- this guard cannot prove --no-host is (or "
                    "isn't) present. Simplify the argv construction so it can, or, if "
                    f"that's not practical, add {key!r} to _UNTRACEABLE_ARGV stating how "
                    "you verified it by hand and when."
                )
    assert not offenders, (
        f"{len(offenders)} subprocess CLI spawn(s) fail the host hermeticity guard "
        "(CLAUDE.md §4 -- tests must be offline and hermetic):\n" + "\n".join(offenders)
    )


def test_host_exemption_lists_are_not_stale() -> None:
    """Mirror of test_module_layout's staleness guards / the deptree guard's own
    test_deptree_exemption_lists_are_not_stale: an entry naming a call site that no
    longer exists, or no longer needs the exemption, is dead weight that hides the next
    real regression behind a stale "already handled" -- remove it."""
    needs_flag_keys: set[str] = set()
    unresolved_keys: set[str] = set()
    for path in list_test_files(_EXCLUDED_FILES):
        for _lineno, qualname, verdict, _detail in analyze_file(path, _REQUIRED_FLAG, _SAFE_MODE_FLAGS):
            if verdict in ("needs-flag", "unresolved"):
                key = f"{path.relative_to(REPO_ROOT)}:{qualname}"
                (needs_flag_keys if verdict == "needs-flag" else unresolved_keys).add(key)
    stale_deliberate = [k for k in _DELIBERATE_HOST_SCAN if k not in needs_flag_keys]
    stale_untraceable = [k for k in _UNTRACEABLE_ARGV if k not in unresolved_keys]
    assert not stale_deliberate, (
        "_DELIBERATE_HOST_SCAN entries no longer matching a real "
        f"missing-flag call site (stale, remove them): {stale_deliberate}"
    )
    assert not stale_untraceable, (
        "_UNTRACEABLE_ARGV entries no longer matching a call site this guard actually "
        f"finds opaque (stale, remove them): {stale_untraceable}"
    )
