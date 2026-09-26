"""Subprocess CLI hermeticity: every audit-path spawn of the real clawseccheck CLI must
carry --no-deptree.

THE BUG THIS GUARDS. `cli.py` enables the npm dependency-tree walk by default
(`include_deptree=not args.no_deptree`, wired into `build_context()`/`audit()` at its
three call sites -- the default report path, `--explain`/`--retest`'s
`_run_single_check`, and the `.clawseccheckignore` match-listing path). `conftest.py`'s
autouse `_stub_deptree_scan` fixture neutralizes this FOR THE IN-PROCESS TEST
INTERPRETER via `monkeypatch.setattr(clawseccheck, "_deptree_scan", ...)` -- but
monkeypatch cannot cross a process boundary. Every test that spawns the CLI as a real
subprocess (`sys.executable -m clawseccheck[.cli] ...`) on the audit path therefore
still walks whatever npm tree happens to be installed on the machine running the suite.

WHY THIS IS A HERMETICITY BUG, NOT (ONLY) A SPEED ONE. `_stub_deptree_scan`'s own
docstring already makes the point about the in-process case: "the same hermeticity
break `_stub_host_detect` below exists to prevent -- a test reading real machine state
it never set up." A subprocess spawn missing `--no-deptree` reads that exact same real
machine state; its result depends on what is globally `npm install -g`'d on the box
running the suite, not on anything the test set up. The speed cost is a visible SYMPTOM
(measured: same invocation, subprocess, wall 3.29s default vs. 0.79s with
`--no-deptree`, ~97% of the difference inside `_deptree_scan -> scan_dep_tree ->
walk_dir_safely` per cProfile) -- a future reader who assumes that is the whole story
and exempts themselves from this guard "because it's just slow here" has missed why it
exists.

WHAT THIS GUARD DOES AND DOES NOT PROVE, AND HOW IT WORKS. See
``tests/_subprocess_argv.py``'s module docstring and this repo's git history for the
full AST-resolution rationale (the module used to live entirely in this file; it was
split out for CLAWSECCHECK-B-881 so ``test_subprocess_host_hermeticity.py`` could reuse
the identical argv-resolution engine for a second required flag, ``--no-host``, rather
than re-implementing and re-diverging from it). In short: it is a static, cooperative
reader of this repo's own test sources -- same spirit as test_module_layout.py /
test_public_boundary.py -- not a dataflow engine. For each
`subprocess.run/Popen/check_call/check_output/call(...)` call site (direct, or reached
through exactly one local helper function), it collects every argv element it can prove
is a string literal and asks: (1) is this even a `clawseccheck`/`clawseccheck.cli`
**module** spawn? (2) if so, does `_SAFE_MODE_FLAGS` below already prove this run takes
a `main()` branch that returns before ever reaching `build_context()`/`audit()`? (3) if
neither, is `--no-deptree` one of the literals? A `*spread` this guard truly cannot
trace at all is reported as UNRESOLVED rather than NEEDS THE FLAG -- both are hard
failures, never a silent skip.

Measured against this repo's real suite while designing this guard: 313 subprocess call
sites, 78 safe (vet-path / not a CLI spawn / -c script), 224 missing --no-deptree on the
audit path (47 files), 11 unresolved (8 files) -- a point-in-time measurement, not a
live invariant; the corpus has since shrunk/changed and today's counts differ.
"""
from __future__ import annotations

from _subprocess_argv import REPO_ROOT, analyze_file, list_test_files

_THIS_FILE = "test_subprocess_deptree_hermeticity.py"
# Excluded from analysis alongside this file for the same reason this file always
# excluded itself: neither guard module contains a real subprocess call site outside
# its own docstrings, and a guard should never need to reason about its sibling.
_SIBLING_GUARD_FILE = "test_subprocess_host_hermeticity.py"
_EXCLUDED_FILES = frozenset({_THIS_FILE, _SIBLING_GUARD_FILE})

_REQUIRED_FLAG = "--no-deptree"

# Argparse flags dispatched in cli.py's main() BEFORE any of its three
# build_context()/audit() call sites -- grep `include_deptree=not args.no_deptree` for
# the three call sites; each name below is an `if _mode == "...": ... return N` block
# (the vet family goes through the shared `_vet_route` block) that main() takes
# strictly earlier. Proven by reading the dispatch table directly, not guessed. Note
# `--judge-packet` (bare) is deliberately ABSENT here even though `--vet-judge-packet`
# looks similar: the bare flag runs through the ordinary default audit path and only
# adds a rendering step afterward (`_mode == "judge_packet"` is dispatched well after
# the default `audit()` call), so it still needs --no-deptree like any other bare run.
#
# If a future flag is added that ALSO bypasses build_context()/audit(), the worst this
# causes is a false "needs-flag" here, fixed by adding it to this set with a comment
# naming the cli.py block that proves the bypass -- the guard errs toward
# re-investigating a new flag, never toward silently trusting one.
#
# Shared verbatim with test_subprocess_host_hermeticity.py's own _SAFE_MODE_FLAGS: both
# flags are consulted at the exact same `main()` dispatch point (build_context()'s
# include_deptree/include_host kwargs are set together, from the same three call
# sites), so a mode that bypasses one bypasses the other identically. Kept as two
# separate module-level constants (not one shared import) so each file stays
# independently readable and a future divergence between the two flags' gating would
# have to edit both, not silently apply to a shared object neither file's reader sees.
_SAFE_MODE_FLAGS = frozenset({
    "--vet", "--vet-skill", "--vet-plugin", "--vet-mcp", "--vet-source", "--vet-all",
    "--advise", "--canary", "--redteam", "--dryrun", "--multiturn", "--self-test",
    # The four below returned real "needs-flag" offenders the first time this guard ran
    # against the live corpus (tests/test_b580_trend_discloses_pruning.py,
    # tests/test_b775_audit_shim_no_bytecode.py) -- each verified by reading cli.py's own
    # dispatch table, not guessed:
    "--verify-history",  # `if _mode == "verify_history":` (cli.py ~4091) returns rc
                          # before the ignore-list audit() call (~4727) or the default
                          # report path (~4927).
    "--verify-events",   # `if _mode == "verify_events":` (cli.py ~4100), same shape,
                          # returns immediately after verify_history's block.
    "--verify-baseline",  # `if _mode == "verify_baseline":` (cli.py ~4114) returns 0/1
                          # from `_verify_baseline()` alone, no audit() call.
    "--watch-log",       # `if _mode == "watch_log":` (cli.py ~4797) renders the events
                          # journal and returns 0 (~4838), strictly before the shared
                          # attestation/bundle prelude that leads into the default
                          # audit() call at ~4927.
    "--version",         # `p.add_argument("--version", action="version", ...)`
                          # (cli.py ~3400): argparse's own "version" action prints and
                          # calls `sys.exit(0)` during `parse_args()`, before `main()`'s
                          # body -- and therefore before any `_mode ==` dispatch at all
                          # -- ever runs.
    # NOTE: top-level `--watch` (cli.py ~3950, `_run_watch_cli`) is DELIBERATELY not
    # listed here even though its own dispatch block never calls build_context()/
    # audit() either ("needs no audit() of its own", per its comment). Each debounce
    # cycle spawns a NESTED `--monitor` subprocess (watch.py's `_run_monitor_once`)
    # that DOES take the default, deptree-walking path, and that nested spawn has no
    # way to receive this test's own `--no-deptree` today (a production-code gap,
    # tracked separately -- see tests/test_watch.py's two subprocess-spawn call sites,
    # which pass `--no-deptree` on the OUTER process for forward-compatibility and
    # cleanliness, but it is currently a no-op for the inner one). Calling `--watch`
    # "safe" here would hide exactly the hermeticity gap this guard exists to catch.
})

# Call sites that must NOT carry --no-deptree, because the test's whole point is the
# real dependency-tree walk. Empty today: no subprocess test currently exercises B349
# end-to-end (tests/test_f167_deptree_hooks.py does that in-process, against a fixture
# tree, and never touches subprocess). Keyed "relative/path.py:function_qualname", each
# entry reasoned -- same shape as test_b661's _INDEPENDENT_OF_CONFIG / test_module_
# layout's _EXEMPT.
_DELIBERATE_DEPTREE_WALK: dict[str, str] = {
    # "test_bNNN_real_deptree_e2e.py:test_walks_a_real_npm_tree":
    #     "BNNN: the one end-to-end proof that scan_dep_tree() finds a real tree "
    #     "outside a fixture; builds its own throwaway node_modules under tmp_path so "
    #     "it stays hermetic despite not passing --no-deptree.",
    "tests/test_b632_vet_envelope_schema.py:"
    "test_vet_modes_emit_exactly_the_documented_base_envelope":
        "Not actually a deliberate walk -- a guard blind spot. `_emitted([flag, arg])` "
        "spreads a `pytest.mark.parametrize(\"flag\", [...])` value into the argv; this "
        "guard has no way to look inside a parametrize decorator, so `flag` is opaque to "
        "it. Hand-verified 2026-09-21 by reading the decorator two lines above the test: "
        "the only three values are '--vet-skill', '--vet-plugin', '--vet-mcp', all "
        "already in _SAFE_MODE_FLAGS. Re-check this entry if that parametrize list ever "
        "grows a new flag.",
}

# Call sites whose argv this guard cannot statically resolve at all, cleared BY HAND
# instead of by the guard's own logic. Each entry must name HOW it was checked and
# WHEN -- an unreviewed "trust me" entry here defeats the guard as completely as a
# missing --no-deptree would. Prefer simplifying the test's argv construction (usually
# a couple of lines) over adding an entry; this dict is for the genuine remainder.
_UNTRACEABLE_ARGV: dict[str, str] = {
    "tests/test_b728_dist_locator.py:_fails_rather_than_skips":
        "False positive, not a real gap: `_fails_rather_than_skips(call, what)` takes a "
        "PARAMETER named `call` (an arbitrary callable the test passes in) and invokes it "
        "as `call()` -- this guard's own `_is_subprocess_call` treats any bare `Name` "
        "matching {run,Popen,check_output,check_call,call} as `subprocess.call` (to "
        "support `from subprocess import run` style imports), so a local variable that "
        "merely happens to be named `call` collides with that heuristic. Hand-verified "
        "2026-09-21 by reading the function: it never imports or calls `subprocess.call`, "
        "it is a generic 'run this and expect an AssertionError, not a skip' helper used "
        "on ordinary Python callables in this file.",
    "tests/test_publish_workflow.py:_replay_staged_tree":
        "Real gap surfaced by the B-623 opacity-propagation fix (a local variable built "
        "from a function-call result, `staged = sorted(_staged_paths(...))`, used to be "
        "silently treated as 'resolved to zero contributions' -- see _resolve_local's "
        "docstring -- so this call site was invisible to the guard before; now it is "
        "correctly opaque). The call is `subprocess.run([\"git\", \"ls-files\", ..., \"--\", "
        "*staged], ...)`: argv[0] is the literal 'git', never `sys.executable`, so this can "
        "never be a `python -m clawseccheck[.cli]` spawn no matter what `staged` contains. "
        "`staged` itself only ever holds repo-relative path strings parsed out of the "
        "publish workflow's own `cp`/`rm -rf` lines by `_staged_paths()` (e.g. 'SKILL.md', "
        "'clawseccheck') -- there is no code path that could make an element equal '-m' or "
        "'clawseccheck'. Hand-verified 2026-09-21 by reading both `_replay_staged_tree` and "
        "`_staged_paths`.",
}


def test_every_subprocess_cli_spawn_on_the_audit_path_passes_no_deptree() -> None:
    offenders = []
    for path in list_test_files(_EXCLUDED_FILES):
        for lineno, qualname, verdict, detail in analyze_file(path, _REQUIRED_FLAG, _SAFE_MODE_FLAGS):
            if verdict not in ("needs-flag", "unresolved"):
                continue
            key = f"{path.relative_to(REPO_ROOT)}:{qualname}"
            if verdict == "needs-flag" and key in _DELIBERATE_DEPTREE_WALK:
                continue
            if verdict == "unresolved" and key in _UNTRACEABLE_ARGV:
                continue
            loc = f"{path.relative_to(REPO_ROOT)}:{lineno} ({qualname})"
            if verdict == "needs-flag":
                offenders.append(
                    f"{loc}: spawns the CLI on the audit path without --no-deptree "
                    f"({detail}). This walks whatever npm tree is actually installed on "
                    "the machine running the suite -- a hermeticity break, not just a "
                    "~2.5s slowdown per invocation (see this module's docstring). Add "
                    f"--no-deptree to the argv, or if the test genuinely needs the real "
                    f"walk, add {key!r} to _DELIBERATE_DEPTREE_WALK with a reason."
                )
            else:
                offenders.append(
                    f"{loc}: {detail} -- this guard cannot prove --no-deptree is (or "
                    "isn't) present. Simplify the argv construction so it can, or, if "
                    f"that's not practical, add {key!r} to _UNTRACEABLE_ARGV stating how "
                    "you verified it by hand and when."
                )
    assert not offenders, (
        f"{len(offenders)} subprocess CLI spawn(s) fail the deptree hermeticity guard "
        "(CLAUDE.md §4 -- tests must be offline and hermetic):\n" + "\n".join(offenders)
    )


def test_deptree_exemption_lists_are_not_stale() -> None:
    """Mirror of test_module_layout's staleness guards: an entry naming a call site
    that no longer exists, or no longer needs the exemption, is dead weight that hides
    the next real regression behind a stale "already handled" -- remove it."""
    needs_flag_keys: set[str] = set()
    unresolved_keys: set[str] = set()
    for path in list_test_files(_EXCLUDED_FILES):
        for _lineno, qualname, verdict, _detail in analyze_file(path, _REQUIRED_FLAG, _SAFE_MODE_FLAGS):
            if verdict in ("needs-flag", "unresolved"):
                key = f"{path.relative_to(REPO_ROOT)}:{qualname}"
                (needs_flag_keys if verdict == "needs-flag" else unresolved_keys).add(key)
    stale_deliberate = [k for k in _DELIBERATE_DEPTREE_WALK if k not in needs_flag_keys]
    stale_untraceable = [k for k in _UNTRACEABLE_ARGV if k not in unresolved_keys]
    assert not stale_deliberate, (
        "_DELIBERATE_DEPTREE_WALK entries no longer matching a real "
        f"missing-flag call site (stale, remove them): {stale_deliberate}"
    )
    assert not stale_untraceable, (
        "_UNTRACEABLE_ARGV entries no longer matching a call site this guard actually "
        f"finds opaque (stale, remove them): {stale_untraceable}"
    )
