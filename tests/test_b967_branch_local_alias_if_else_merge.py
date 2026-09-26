"""Regression tests for CLAWSECCHECK-B-967.

`_b863_process_one`'s `ast.If` branch-merge (clawseccheck/skillast.py) walks
each arm of an `if`/`else` on its own copy of `names`/`shapes_of`, then
re-threads only the names that were already in the OUTER, pre-if `names`
set: `{n: body_shapes_of[n] + orelse_shapes_of[n] for n in names}`. A name
first discovered as an alias of a tracked value INSIDE a branch (`y = x`)
used to be silently dropped right there -- its post-if mutation
(`y.append(payload)`) then matched no tracked receiver and was treated as a
benign no-op, losing a genuine crit detection. Confirmed real with the exact
repro below: forcing the `else` arm causes actual shell command injection
that was reported only TT5_ARG_INJECTION/info instead of crit.

The fix propagates a branch-local alias past the merge ONLY when the SAME
name was independently discovered as an alias in BOTH arms -- the one case
that is unambiguous regardless of which arm actually ran. A name discovered
in only ONE arm is deliberately left unpropagated (the pre-existing,
narrower scope limit): on the other arm it may be an unrelated, untracked
binding, or that arm may not reach the merge point at all (a guard-clause
raise). Propagating that case would risk inventing a false alias chain and
a brand-new false-positive crit on ordinary code -- see
`test_asymmetric_alias_only_one_branch_stays_unresolved` below, which pins
that this narrower gap is unchanged by this fix (byte-identical verdict to
the pre-fix behaviour, confirmed against the base commit).

Offline, deterministic. No network calls, no writes outside pytest's
tmp_path (none of these tests touch the filesystem at all).
"""
from __future__ import annotations

import textwrap

from clawseccheck.skillast import analyze_python

_HEADER = "import os, subprocess, random\n"


def _tt5(src: str) -> set[str]:
    """The set of TT5 (rule, severity) pairs `analyze_python` reports."""
    findings = analyze_python(textwrap.dedent(src), "t.py")
    return {(f.rule, f.severity) for f in findings if f.rule.startswith("TT5")}


def _severity(src: str) -> str | None:
    """'crit' if any TT5 finding is crit, 'info' if only info TT5 findings,
    None if there is no TT5 finding at all."""
    tt5 = _tt5(src)
    if not tt5:
        return None
    sevs = {sev for _, sev in tt5}
    return "crit" if "crit" in sevs else "info"


def _assert_crit(src: str) -> None:
    assert _severity(src) == "crit", _tt5(src)


def _assert_info(src: str) -> None:
    assert _severity(src) == "info", _tt5(src)


# ---------------------------------------------------------------------------
# (a) the confirmed-real repro: an alias discovered independently in BOTH
# arms of the if/else must propagate past the merge.
# ---------------------------------------------------------------------------

def test_alias_discovered_in_both_branches_now_crit():
    """The ticket's own executable repro, verbatim: `y` is created as an
    alias of the tracked vararg in BOTH the `if` arm (via `args`, itself
    freshly reassigned there) and the `else` arm (via `x`, aliased before
    the `if`). Forcing either arm, `y.append(payload)` genuinely mutates the
    object `subprocess.check_output(args)` goes on to read. Before the fix
    this was TT5_ARG_INJECTION/info (the append was invisible); it must now
    be crit."""
    src = f"""
        {_HEADER}
        def sh(*args):
            payload = os.environ["P"]
            args = list(args)
            x = args
            if random.random() > 0.5:
                args = ["ls"]
                y = args
            else:
                y = x
            y.append(payload)
            return subprocess.check_output(args)

        def main():
            sh("sh", "-c")
    """
    _assert_crit(src)


def test_alias_discovered_in_both_branches_minimal_form_is_crit():
    """A smaller shape of the same symmetric case: `y` aliases the tracked
    name in both arms directly (no intermediate `x`/reassign), just to
    confirm the merge propagation itself, independent of the ticket's exact
    wrapper dressing."""
    src = f"""
        {_HEADER}
        def sh(*args):
            payload = os.environ["P"]
            if random.random() > 0.5:
                y = args
            else:
                y = args
            y.append(payload)
            return subprocess.check_output(args)

        def main():
            sh("sh", "-c")
    """
    _assert_crit(src)


# ---------------------------------------------------------------------------
# (b) regression: the existing B-863 branch-merge for names already in the
# OUTER, pre-if `names` set must be completely unaffected by this change.
# ---------------------------------------------------------------------------

def test_preexisting_outer_name_branch_merge_still_crit():
    """`args` itself (the tracked vararg, already in the outer `names` set
    before the `if`) is reassigned in BOTH arms -- the ORIGINAL B-863
    branch-merge case this fix must not disturb. Confirmed byte-identical to
    the pre-fix verdict (crit) against the base commit."""
    src = f"""
        {_HEADER}
        def sh(*args):
            payload = os.environ["P"]
            args = list(args)
            if len(payload) > 3:
                args = ["ls"]
            else:
                args = list(args)
            args.append(payload)
            return subprocess.check_output(args)

        def main():
            sh("sh", "-c")
    """
    _assert_crit(src)


# ---------------------------------------------------------------------------
# (c) the "alias discovered in only one branch" edge case.
# ---------------------------------------------------------------------------

def test_asymmetric_alias_only_one_branch_stays_unresolved():
    """`y` is created as an alias of the tracked vararg ONLY in the `if`
    arm; the `else` arm does something unrelated and never touches `y` or
    `args`. This is the asymmetric case this fix deliberately does NOT
    propagate (see the module docstring above): on the untaken arm, `y`
    might be an unrelated binding, so inventing an alias for it there would
    fabricate a false alias chain. This is a real, narrower residual gap (at
    runtime, taking the `if` arm DOES alias `y` to `args`), but propagating
    it risks a brand-new false positive on the common guard-clause idiom
    (see the next test) -- so it is left exactly as unresolved as it was
    before this fix. Confirmed byte-identical (info, not crit) against the
    base commit -- this test pins "unchanged", not "fixed"."""
    src = f"""
        {_HEADER}
        def sh(*args):
            payload = os.environ["P"]
            if random.random() > 0.5:
                y = args
            else:
                print("nothing to do here")
            y.append(payload)
            return subprocess.check_output(args)

        def main():
            sh("sh", "-c")
    """
    _assert_info(src)


def test_asymmetric_alias_guard_clause_idiom_does_not_regress():
    """The concrete false-positive risk that ruled out propagating the
    asymmetric case unconditionally: a common, entirely ordinary
    guard-clause idiom where a name is bound in only ONE arm because the
    other arm always raises before the merge point is ever reached. This
    must not gain a NEW crit finding as a side effect of this fix -- and in
    fact this exact shape was already crit before this change too (a
    separate, coarser detection layer independent of the branch-merge this
    ticket touches), confirming this fix introduces no new verdict here
    either way."""
    src = f"""
        {_HEADER}
        def run(ok, *args):
            payload = os.environ["P"]
            if ok:
                cmd = list(args)
            else:
                raise ValueError("bad")
            cmd.append(payload)
            return subprocess.check_output(cmd)

        def main():
            run(True, "git", "status")
    """
    _assert_crit(src)


# ---------------------------------------------------------------------------
# (d) the pre-existing `_B863OutOfDomain` escape hatch, inside an `if` arm,
# is untouched by this change (this fix adds no NEW raise site -- it only
# widens what the branch-merge propagates on a successful, exception-free
# walk of both arms).
# ---------------------------------------------------------------------------

def test_out_of_domain_inside_a_branch_still_escalates_to_crit():
    """A subscript store into the tracked name inside the `if` arm
    (`args[0] = payload`) is unrecognised grammar -> `_B863OutOfDomain` ->
    crit unconditionally, exactly as before this change. Pins that the new
    merge-time propagation loop (which only ever runs on values returned by
    a successful, non-raising `_b863_process_stmts` call for both arms)
    cannot mask or otherwise interfere with the existing out-of-domain
    escalation path."""
    src = f"""
        {_HEADER}
        def sh(*args):
            payload = os.environ["P"]
            args = list(args)
            if random.random() > 0.5:
                args[0] = payload
            return subprocess.check_output(args)

        def main():
            sh("sh", "-c")
    """
    _assert_crit(src)
