"""Regression tests for CLAWSECCHECK-B-863.

Three prior rounds on this bug (8e43fe22, c7c2df9c, c07fe53e) each widened or
narrowed a single whitelist trying to answer two different questions with one
list: "can attacker data reach the wrapper's parameter at all" (content) and
"does a body transform move that data into argv[0]" (position). Every widening
fixed a false positive and reopened a false negative, or the reverse — see the
module comment above `_B863OutOfDomain` in clawseccheck/skillast.py for the
two-tier replacement (content-independent tier 1, position-only tier 2).

This file turns every row of the architect's test matrix into its own test,
grouped the same way the matrix names them (O/C/A/B/R3/N/BENIGN/UNCHANGED).
One row (a variant of `N9`) does NOT reach the verdict the matrix names, for a
documented reason that is NOT this bug's own grammar — see
`test_new_n9_conditional_reassign_pinned_to_current_pre_existing_gap` below,
which pins the CURRENT (pre-existing-bug-limited) behaviour rather than assert
a verdict this change cannot reach, so the suite stays green without an xfail.
That gap is filed in Pulse for 4.3.1, not fixed here (out of B-863's own
scope: the wrapper-parameter-reassignment gate) — see CLAWSECCHECK-B-941. A
second row (a variant of `O2b`) had the identical treatment for the same
reason, citing a "CLAWSECCHECK-B-940" that turned out to be the wrong task id
(that id is a real, unrelated, still-open bug — see
`test_o2b_inline_env_now_resolved_by_b906`'s own docstring for the
correction), but CLAWSECCHECK-B-906 closed the underlying gap as a side effect
of its own, unrelated os.environ/os.getenv resolution work — see that test
below, which now pins the FIXED behaviour instead.

Offline, deterministic. No network calls, no writes outside pytest's tmp_path
(none of these tests touch the filesystem at all).
"""
from __future__ import annotations

import textwrap

import pytest

from clawseccheck.skillast import analyze_python

_HEADER = "import os, sys, subprocess, shlex\n"


def _va(body: list[str], call: str = 'sh("git", "status")', sig: str = "*args",
        sink: str = "subprocess.check_output(args)") -> str:
    """A vararg wrapper: `def sh(*args): ...body...; return sink` called once
    from `main()` as `call`. Mirrors the architect's harness `va()` builder.
    `body` is a list of statement lines at the function's own indent level."""
    lines = "\n".join("    " + line for line in body)
    return (
        f"{_HEADER}def sh({sig}):\n"
        f"    payload = os.environ['P']\n"
        f"{lines}\n"
        f"    return {sink}\n\n"
        f"def main():\n"
        f"    p = os.environ['P']\n"
        f"    {call}\n"
    )


def _np(body: list[str], call: str = 'run(["git", "status"])', sig: str = "cmd",
        sink: str = "subprocess.check_output(cmd)") -> str:
    """A named-parameter wrapper: `def run(cmd): ...body...; return sink`."""
    lines = "\n".join("    " + line for line in body)
    return (
        f"{_HEADER}def run({sig}):\n"
        f"    payload = os.environ['P']\n"
        f"{lines}\n"
        f"    return {sink}\n\n"
        f"def main():\n"
        f"    p = os.environ['P']\n"
        f"    {call}\n"
    )


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


def _assert_info(src: str) -> None:
    assert _severity(src) == "info", _tt5(src)


def _assert_crit(src: str) -> None:
    assert _severity(src) == "crit", _tt5(src)


def _assert_none(src: str) -> None:
    assert _severity(src) is None, _tt5(src)


# ---------------------------------------------------------------------------
# O*, INLINE, C* — the original report, its inline-equivalent control, and the
# two retracted/control shapes the three prior rounds already got right.
# ---------------------------------------------------------------------------

def test_o1_vararg_extend_sh_c_payload_is_info_under_p1():
    """The headline repro. P1 (the owner-approved default, CLAUDE.md
    `owner_decision_needed`): the same verdict as the byte-identical INLINE
    call below, per the module's own B13 argument-injection rule."""
    src = _va(["args = list(args)", "args.extend(['sh', '-c', payload])"])
    _assert_info(src)


def test_inline_equivalent_is_info():
    src = _HEADER + (
        "def main():\n"
        "    payload = os.environ['P']\n"
        "    subprocess.check_output(['git', 'status', 'sh', '-c', payload])\n"
    )
    _assert_info(src)


def test_o1_pinned_equal_to_inline():
    o1 = _va(["args = list(args)", "args.extend(['sh', '-c', payload])"])
    inline = _HEADER + (
        "def main():\n"
        "    payload = os.environ['P']\n"
        "    subprocess.check_output(['git', 'status', 'sh', '-c', payload])\n"
    )
    assert _severity(o1) == _severity(inline) == "info"


def test_o2a_concat_reassign_is_crit():
    """R2: a fresh literal under a shell a0 with ANY non-constant element is
    crit by construction, independent of taint."""
    src = _va(["args = ['sh', '-c'] + [payload]"], sink="subprocess.check_output(list(args))")
    _assert_crit(src)


def test_o2b_inline_env_now_resolved_by_b906():
    """The matrix names this crit (R2). At B-863 time it stayed info instead, for
    a reason outside B-863 entirely: `args = ['sh', '-c', os.environ['X']]` is a
    SINGLE assign to a literal, so `_single_list_bindings_local` (pre-B-863 code,
    resolves a wrapper's OWN single-literal-bound local before layer 2 / B-863
    ever run) resolves it FIRST -- and the shell-indirect-exec tail-taint check
    that then applies (`_subprocess_taint_is_command_injection`'s literal-List
    branch) tested taint via a bare `_names_in(elt) & tainted`, which found only
    the bare Name `os` inside `os.environ['X']` -- not itself a taint source --
    and never applied the `_rhs_has_subscript_environ`/`_value_is_tainted_source`
    predicates that would recognise the subscript form. The original B-863 round
    cited "CLAWSECCHECK-B-940" as the Pulse task tracking this gap, out of scope
    for B-863 since the gap lives entirely in the pre-existing single-binding/
    shell-tail check, not in B-863's own wrapper-parameter-reassignment gate --
    that citation was WRONG (CLAWSECCHECK-B-940 is a real, unrelated, still-open
    toolpolicy._scope_rows bug; verified directly via pulse_get_task). The real
    tracking task was CLAWSECCHECK-B-906 all along -- its own title is this
    exact shape (`run([os.environ["P"], "x"])` misread as argument injection).

    CLAWSECCHECK-B-906 closes the gap it was filed for: `ref_res.source_in(elt)`
    is now threaded into that exact literal-List branch as an additional `or`
    disjunct (see `_subprocess_taint_is_command_injection`'s own docstring), and
    `_RefResolver.source_in()` positively recognises `os.environ['X']`'s
    subscript form directly -- no change to `_single_list_bindings_local`, the
    tail-taint check's bare-Name test, or B-863's own grammar was needed. This
    test now pins the FIXED behaviour."""
    src = _va(["args = ['sh', '-c', os.environ['X']]"], sink="subprocess.check_output(list(args))")
    _assert_crit(src)  # matrix's own "crit (R2)" -- now reached, via B-906


def test_o2c_env_string_is_crit_out_of_domain():
    src = _va(["args = os.environ['P']"], sink="subprocess.check_output(list(args))")
    _assert_crit(src)


def test_o4_named_extend_is_info_under_p1():
    """Same fork as O1, named-parameter form: a0 from the call site ("git") is
    not a shell, so the appended `['sh', '-c', payload]` tail is ordinary argv
    data to git, not code -- info, matching the byte-identical inline call."""
    src = _np(["cmd = list(cmd)", "cmd.extend(['sh', '-c', payload])"])
    _assert_info(src)


def test_o5_named_tainted_var_list_is_crit_unchanged():
    """Already correct before B-863 (a single literal assign resolves via the
    pre-existing `_single_list_bindings_local`, independent of this fix) --
    pinned so a future change cannot regress it."""
    src = _va(["args = ['sh', '-c', payload]"])
    _assert_crit(src)


def test_c_py_round1_python_c_append_payload_is_crit():
    src = _va(["args = list(args)", "args.append(payload)"], call='sh("python3", "-c")')
    _assert_crit(src)


def test_c_retracted_sh_dash_c_callsite_is_crit_unchanged():
    """No body channel at all -- decided entirely by the pre-existing,
    unchanged `_all_call_sites_bind_fixed_argv` path."""
    src = _va(["pass"], call='sh("sh", "-c", p)')
    _assert_crit(src)


def test_c_literal_all_literal_untouched_is_info_unchanged():
    src = _va(["pass"], call='sh("git", "describe")')
    _assert_info(src)


# ---------------------------------------------------------------------------
# A* — round-1/2/3 "side A": literal call sites, every reassignment/mutation
# is content-safe (tier 1 fires; position never has to be judged at all).
# ---------------------------------------------------------------------------

def test_a1_slice_copy_is_info():
    _assert_info(_np(["cmd = cmd[:]"]))


def test_a2_copy_append_is_info():
    _assert_info(_np(["cmd = cmd.copy()", "cmd.append('--quiet')"]))


def test_a3_list_plus_flag_is_info():
    _assert_info(_va(["args = list(args) + ['--no-pager']"]))


def test_a4_str_comp_is_info():
    _assert_info(_va(["args = [str(a) for a in args]"]))


def test_a5_isinstance_shlex_guard_is_info():
    _assert_info(_np(["if isinstance(cmd, str):", "    cmd = shlex.split(cmd)"]))


def test_a6_ternary_default_is_info():
    _assert_info(_np(["cmd = ['ls'] if cmd is None else cmd"]))


def test_a7_plus_str_path_local_is_info():
    _assert_info(_np(["path = os.path.join('/tmp', 'x')", "cmd = cmd + [str(path)]"]))


def test_a8_extend_local_extra_is_info():
    _assert_info(_np(["extra = ['--verbose']", "cmd.extend(extra)"]))


def test_a8b_extend_coparam_literal_callsite_is_info():
    """A co-param's own taint (`extra` is a plain parameter, unconditionally
    tainted from run's own view) reaches `cmd` via `.extend`, so tier 1 (T1b)
    does NOT clear it -- but tier 2 does, since a0 ("git", from the literal
    call site) is not a shell: the tail is ordinary argv data regardless."""
    _assert_info(_np(["cmd.extend(extra)"], sig="cmd, extra", call='run(["git", "status"], ["--short"])'))


def test_fix_r1_own_or_default_info_variant():
    _assert_info(_np(["cmd = cmd or ['ls']"]))


def test_fix_r1_own_or_default_crit_variant():
    """The matrix's second `cmd = cmd or [...]` case: the `or`-join's OTHER
    branch is a fresh shell literal with a non-constant element -> R2 fires
    for that branch, and one dangerous branch is enough."""
    src = _np(["cmd = cmd or ['sh', '-c', payload]"])
    _assert_crit(src)


def test_r2_a9_identity_comp_is_info():
    _assert_info(_va(["args = [a for a in args]"]))


def test_r2_a10_filtered_comp_literal_callsite_is_info():
    """Same body shape as `N1` below; the DIFFERENCE that keeps this info is
    entirely at the call site (literal + untainted -> tier 1 fires before
    tier 2 ever has to judge the filter's position-shifting effect)."""
    _assert_info(_va(["args = [a for a in args if a]"]))


def test_r2_a11_insert_len_literal_is_info():
    _assert_info(_va(["args = list(args)", "args.insert(len(args), '--flag')"]))


def test_r2_a11_insert_len_tainted_body_content_is_crit():
    src = _va(
        ["args = list(args)", "args.insert(len(args), payload)"],
        call='sh("python3", "-c")',
    )
    _assert_crit(src)


def test_r2_a11_insert_0_with_tainted_callsite_is_crit():
    """`insert(0, ...)` is position-unsafe (not `len(args)`) -> out of domain
    in tier 2; the tainted call site (`p`) means tier 1 cannot clear it first."""
    src = _va(["args = list(args)", "args.insert(0, '--flag')"], call='sh("sh", "-c", p)')
    _assert_crit(src)


def test_r3_a12_list_of_comp_is_info():
    _assert_info(_va(["args = list([a for a in args])"]))


def test_r3_a13_tuple_of_comp_is_info():
    _assert_info(_va(["args = tuple([a for a in args])"]))


def test_r3_a14_slice_then_copy_is_info():
    _assert_info(_va(["args = list(args)", "args = args[:].copy()"]))


def test_new_a15_pop0_with_literal_callsite_is_info():
    """`pop(0)` is out of domain for TIER 2 -- but the call site
    (`"x","git","status"`) is fully literal and untainted, so TIER 1 fires
    first and position never has to be judged (contrast `test_r1_b3a_pop0`)."""
    src = _va(["args = list(args)", "args.pop(0)"], call='sh("x", "git", "status")')
    _assert_info(src)


def test_new_a16_tmp_build_assign_back_is_info():
    """`x = list(args)` registers `x` as a plain alias of `args` (H-preserving,
    not an escape); `.append` on the alias, then `args = x`, must not lose the
    accumulated tail content."""
    src = _va(["x = list(args)", "x.append('--flag')", "args = x"])
    _assert_info(src)


def test_new_b1c_tuple_prepend_literal_callsite_is_info():
    src = _va(["args = ('sh',) + args"], call='sh("-c", "echo hi")')
    _assert_info(src)


# ---------------------------------------------------------------------------
# B* — round-1 "side B": the call site's OWN content is tainted; every one of
# these transforms must stay (or become) crit.
# ---------------------------------------------------------------------------

def test_r1_b1_tuple_prepend_is_crit():
    _assert_crit(_va(["args = ('sh',) + args"], call='sh("-c", p)'))


def test_r1_b2_insert0_is_crit():
    _assert_crit(_va(["args = list(args)", "args.insert(0, 'sh')"], call='sh("-c", p)'))


def test_r1_b3a_pop0_is_crit():
    _assert_crit(_va(["args = list(args)", "args.pop(0)"], call='sh("x", "sh", "-c", p)'))


def test_r1_b3b_remove_is_crit():
    _assert_crit(_np(["cmd = list(cmd)", "cmd.remove('x')"], call='run(["x", "sh", "-c", p])'))


def test_r1_b3c_reverse_is_crit():
    _assert_crit(_np(["cmd = list(cmd)", "cmd.reverse()"], call='run(["x", p, "-c", "sh"])'))


def test_r1_b3d_del0_is_crit():
    _assert_crit(_np(["cmd = list(cmd)", "del cmd[0]"], call='run(["x", "sh", "-c", p])'))


def test_r1_b4a_slice_store_is_crit():
    _assert_crit(_va(["args = list(args)", "args[:] = ['sh', '-c', payload]"]))


def test_r1_b4b_index_store_is_crit():
    _assert_crit(_np(["cmd = list(cmd)", "cmd[0] = payload"]))


def test_r1_b5a_iadd_dunder_is_crit():
    _assert_crit(_np(["cmd = list(cmd)", "cmd.__iadd__(['sh', '-c', payload])", "cmd.reverse()"]))


def test_r1_b5b_setitem_dunder_is_crit():
    _assert_crit(_np(["cmd = list(cmd)", "cmd.__setitem__(0, payload)"]))


def test_r1_b5c_unbound_list_extend_is_crit():
    _assert_crit(
        _np(["cmd = list(cmd)", "list.extend(cmd, ['-c', payload])", "cmd.insert(0, 'sh')"], call='run(["x"])')
    )


def test_r1_b6a_alias_is_crit():
    _assert_crit(_np(["cmd = list(cmd)", "c2 = cmd", "c2[:0] = ['sh', '-c', payload]"]))


def test_r1_b6b_closure_is_crit():
    """A nested closure that mutates the tracked name BY REFERENCE (no
    rebinding in its own signature) must still be walked -- the false
    negative all three prior rounds shared."""
    src = _np(["cmd = list(cmd)", "def f():", "    cmd.insert(0, payload)", "f()"])
    _assert_crit(src)


# ---------------------------------------------------------------------------
# R3 — the `sys.argv` FN (an accepted, pre-existing, out-of-scope engine gap)
# and its pinned git+TOKEN sibling.
# ---------------------------------------------------------------------------

def test_r3_sysargv_tail_stays_info_pre_existing_engine_gap():
    """`sys.argv` is not a taint source ANYWHERE in this engine -- a pre-
    existing, whole-engine gap (CLAUDE.md CLAWSECCHECK-B-863 design's own
    `residual_proof`), not something this task's grammar can or should paper
    over. Pinned so a future change does not silently start relying on it."""
    src = _va(["extra = sys.argv[1]", "args = list(args)", "args.extend([extra])"])
    _assert_info(src)


def test_r3_git_tainted_token_tail_is_info_under_p1():
    """Same fork as O1/O4: a0 ("git") is not a shell, so the appended tainted
    `os.environ['TOKEN']` is ordinary argv data, not code."""
    src = _va(["args = list(args)", "args.extend(['-c', os.environ['TOKEN']])"])
    _assert_info(src)


# ---------------------------------------------------------------------------
# N* — the architect's own new repros for this round.
# ---------------------------------------------------------------------------

def test_new_n1_filtered_comp_drops_empty_argv0_is_crit():
    """Contrast `test_r2_a10`: same filtered comprehension, but the call site
    itself is tainted (`p`), so tier 1 cannot clear it and tier 2 must judge
    position -- a filter can drop elements, which shifts position, so it is
    out of domain."""
    src = _va(["args = [a for a in args if a]"], call='sh("", "sh", "-c", p)')
    _assert_crit(src)


def test_new_n2_append_smuggle_rebuild_is_crit():
    """A `for` loop building `rest` via `.append`, then `args = [...] + rest`:
    `rest`'s own construction touches `args` (out of domain for tier 2's
    channel walk), and the tainted call site (`p`) means tier 1 cannot clear
    it first either."""
    src = _va(
        ["rest = []", "for a in args[1:]:", "    rest.append(a)", "args = ['sh', '-c'] + rest"],
        call='sh("x", p)',
    )
    _assert_crit(src)


def test_new_n3_clear_then_append_is_crit():
    src = _va(
        ["args = list(args)", "tmp = []", "for a in args:", "    tmp.append(a)",
         "args.clear()", "args.extend(tmp[1:])"],
        call='sh("x", "sh", "-c", p)',
    )
    _assert_crit(src)


def test_new_n7_callsite_append_then_body_pop_is_crit():
    """The call site's OWN local (`c`) is built with a literal head then
    mutated with `.append` before being forwarded -- call-site resolution
    must be append-aware (not just the initial-literal-binding view a naive
    `_single_list_bindings_local`-style resolution would give) to see the
    tainted tail at all; `cmd.pop(0)` in the body is independently out of
    domain regardless."""
    src = "".join([
        _HEADER,
        "def run(cmd):\n",
        "    cmd = list(cmd)\n",
        "    cmd.pop(0)\n",
        "    return subprocess.check_output(cmd)\n\n",
        "def main():\n",
        "    c = ['git']\n",
        "    c.append(os.environ['P'])\n",
        "    run(c)\n",
    ])
    _assert_crit(src)


def test_new_n9_conditional_reassign_pinned_to_current_pre_existing_gap():
    """The matrix names this crit: `if DEBUG: args = ['echo']` must not clear
    the danger on the "branch not taken" path, where the call site's own
    tainted, shell-shaped argv (`sh('sh', '-c', p)`) still reaches the sink.
    B-863's OWN branch-merge grammar gets this right (verified directly
    against `_b863_tier1_tier2_verdict` in isolation: it returns crit). It
    stays info end-to-end for a reason entirely OUTSIDE B-863's own code: the
    pre-existing `_single_list_bindings_local` (used by
    `_subprocess_taint_is_command_injection` to resolve the SINK's own
    argument BEFORE the wrapper/vararg gate this task changes ever runs)
    counts `args = ['echo']` as "assigned exactly once to a literal" without
    any awareness that the assignment is inside an `if` -- so it resolves
    `args` to `['echo']` unconditionally and clears the call before B-863's
    branch-aware grammar is ever reached. True on every tree, including the
    three retracted rounds ("info on all three trees" in the matrix). Filed
    as CLAWSECCHECK-B-941 for 4.3.1; out of scope here for the same reason as
    `test_o2b_inline_env_pinned_to_current_pre_existing_gap` above."""
    src = "".join([
        "import os, subprocess\n",
        "DEBUG = False\n",
        "def sh(*args):\n",
        "    if DEBUG:\n",
        "        args = ['echo']\n",
        "    return subprocess.check_output(args)\n\n",
        "def main():\n",
        "    p = os.environ['P']\n",
        "    sh('sh', '-c', p)\n",
    ])
    _assert_info(src)  # NOT the matrix's "crit" -- see docstring


def test_new_n13_helper_mutates_is_crit():
    """`poison(cmd)` forwards the tracked parameter, bare, to an IN-FILE
    function -- out of domain for tier 2, and disproves tier 1's T1c (a
    content-independence proof cannot assume an in-file callee never mutates
    what it was handed) regardless of what `poison` actually does."""
    src = "".join([
        _HEADER,
        "def poison(c):\n",
        "    c.append(os.environ['P'])\n\n",
        "def run(cmd):\n",
        "    cmd = list(cmd)\n",
        "    poison(cmd)\n",
        "    cmd.reverse()\n",
        "    return subprocess.check_output(cmd)\n\n",
        "def main():\n",
        "    run(['-c', 'sh'])\n",
    ])
    _assert_crit(src)


# ---------------------------------------------------------------------------
# BENIGN-N* — the forwarded-parameter idiom must stay clear.
# ---------------------------------------------------------------------------

def test_benign_n4_forwarded_param_is_info():
    src = _HEADER + (
        "def run(cmd):\n"
        "    cmd = list(cmd)\n"
        "    return subprocess.check_output(cmd)\n\n"
        "def log(branch):\n"
        "    return run(['git', 'log', branch])\n\n"
        "log('main')\n"
    )
    _assert_info(src)


def test_benign_n5_forwarded_param_isinstance_shlex_is_info():
    src = _HEADER + (
        "def run(cmd):\n"
        "    if isinstance(cmd, str):\n"
        "        cmd = shlex.split(cmd)\n"
        "    return subprocess.check_output(cmd)\n\n"
        "def log(branch):\n"
        "    return run(['git', 'log', branch])\n\n"
        "log('main')\n"
    )
    _assert_info(src)


def test_benign_n6_forwarded_coparam_tail_is_info_under_p1():
    src = _HEADER + (
        "def run(cmd, cwd=None):\n"
        "    if cwd:\n"
        "        cmd = cmd + ['-C', cwd]\n"
        "    return subprocess.check_output(cmd)\n\n"
        "def status(repo):\n"
        "    return run(['git', 'status'], repo)\n\n"
        "status('.')\n"
    )
    _assert_info(src)


def test_benign_n12_forwarded_param_logging_is_info():
    src = _HEADER + (
        "import logging\n"
        "log = logging.getLogger()\n"
        "def run(cmd):\n"
        "    cmd = list(cmd)\n"
        "    log.info('run %s', ' '.join(cmd))\n"
        "    return subprocess.check_output(cmd)\n\n"
        "def st(repo):\n"
        "    return run(['git', '-C', repo, 'status'])\n\n"
        "st('.')\n"
    )
    _assert_info(src)


# ---------------------------------------------------------------------------
# UNCHANGED-N* — three pre-existing shapes B-863 must not disturb either way.
# ---------------------------------------------------------------------------

def test_unchanged_n10_zero_callers_literal_reassign_is_info():
    """Decided entirely by the pre-existing `_single_list_bindings_local`
    (a single literal assign resolves before the wrapper/vararg gate this
    task changes ever runs) -- pinned so B-863 cannot regress it."""
    src = _HEADER + "def run(cmd):\n    cmd = ['ls', '-l']\n    return subprocess.check_output(cmd)\n"
    _assert_info(src)


def test_unchanged_n11_starred_sink_is_crit_pre_existing():
    """`check_output([*args, '--flag'])` is a pre-existing false positive
    (the blanket per-function vararg taint reaches the FIRST literal-list
    branch directly, before this task's `is_named_param` gate is ever
    reached) -- unrelated to B-863, not fixed here; the architect's own
    design already names it a residual to file (see risks item 6)."""
    src = _va(["pass"], sink="subprocess.check_output([*args, '--flag'])")
    _assert_crit(src)


def test_unchanged_n8_local_list_extend_bash_c_reports_no_tt5():
    """A local variable's OWN `.extend` at a DIRECT (non-wrapper) sink is
    invisible to the taint engine entirely -- unrelated to B-863's wrapper/
    vararg gate, not fixed here; already named in the architect's design."""
    src = (
        "import os, subprocess\n"
        "def main():\n"
        "    c = ['bash']\n"
        "    c.extend(['-c', os.environ['P']])\n"
        "    subprocess.run(c)\n"
    )
    _assert_none(src)


# ---------------------------------------------------------------------------
# MECH — perf memoization, engine equivalence, and the non-convergence default.
# ---------------------------------------------------------------------------

def test_mech_perf_channel_walk_and_m_are_memoized_per_function():
    """500-line padded wrapper body: `_b863_tier1_tier2_verdict` is invoked
    once per TT5 sink call in the SAME file, but the (expensive) channel walk
    and the T1b mutation-fixpoint must each run at most ONCE per (fn,
    param_name) -- verified by counting real invocations through a
    monkeypatch, not by wall-clock timing (deterministic, no flakiness)."""
    import clawseccheck.skillast as skillast_mod

    padding = "\n".join(f"    _pad_{i} = {i}" for i in range(500))
    src = (
        _HEADER
        + "def sh(*args):\n"
        + "    payload = os.environ['P']\n"
        + padding
        + "\n    args = list(args)\n"
        + "    args.extend(['sh', '-c', payload])\n"
        + "    return subprocess.check_output(args)\n\n"
        + "def main():\n"
        + "    sh('git', 'status')\n"
        + "    sh('git', 'log')\n"
        + "    sh('git', 'diff')\n"
    )

    calls = {"collect": 0, "m_for": 0}
    real_collect = skillast_mod._b863_collect_channels
    real_m_for = skillast_mod._b863_m_for

    def counting_collect(*a, **kw):
        calls["collect"] += 1
        return real_collect(*a, **kw)

    def counting_m_for(*a, **kw):
        calls["m_for"] += 1
        return real_m_for(*a, **kw)

    skillast_mod._b863_collect_channels = counting_collect
    skillast_mod._b863_m_for = counting_m_for
    try:
        findings = skillast_mod.analyze_python(src, "t.py")
    finally:
        skillast_mod._b863_collect_channels = real_collect
        skillast_mod._b863_m_for = real_m_for

    assert any(f.rule == "TT5_ARG_INJECTION" for f in findings)
    # Three sink calls into the SAME `sh`, but only one (fn, param) pair.
    assert calls["collect"] == 1, calls
    assert calls["m_for"] <= 1, calls


def test_mech_equivalence_m_with_nothing_deseeded_matches_ext_taint_map():
    """`_b863_m_for` with a parameter name that never appears in
    `func_param_taint[fn]` at all (nothing to de-seed) must compute the exact
    same tainted-name set `_external_tainted_names` itself would -- the
    fixpoint's own mutation-propagation additions aside, de-seeding nothing
    changes nothing about the SOURCE side."""
    import ast

    from clawseccheck.skillast import (
        _b863_m_for,
        _build_toplevel_owner_map,
        _external_tainted_names,
        _func_param_taint_by_scope,
    )

    src = (
        "import os\n\n"
        "def helper(unrelated):\n"
        "    x = os.environ['A']\n"
        "    return x\n"
    )
    tree = ast.parse(src)
    funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    owner_map, parent_scope = _build_toplevel_owner_map(funcs, [])
    shadow_cache: dict = {}
    fpt = _func_param_taint_by_scope(tree, owner_map, parent_scope)
    ext_taint_map = _external_tainted_names(tree, fpt, owner_map, parent_scope, shadow_cache)
    fn = funcs[0]
    m = _b863_m_for(fn, "not_a_real_param", owner_map, parent_scope, shadow_cache, fpt, ext_taint_map)
    assert m.get(fn, set()) == ext_taint_map.get(fn, set())


def test_mech_module_level_source_not_visible_through_deseeded_param():
    """A module-level `args = os.environ[...]` is not visible through a
    de-seeded param named `args` inside an UNRELATED function -- de-seeding
    only ever removes `param_name` from `fn`'s OWN bucket, never adds a
    same-named module-level binding's taint into it."""
    import ast

    from clawseccheck.skillast import (
        _b863_m_for,
        _build_toplevel_owner_map,
        _external_tainted_names,
        _func_param_taint_by_scope,
        _tainted_names_visible,
    )

    src = (
        "import os\n"
        "args = os.environ['SHADOWED']\n\n"
        "def sh(args):\n"
        "    return args\n"
    )
    tree = ast.parse(src)
    funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    owner_map, parent_scope = _build_toplevel_owner_map(funcs, [])
    shadow_cache: dict = {}
    fpt = _func_param_taint_by_scope(tree, owner_map, parent_scope)
    ext_taint_map = _external_tainted_names(tree, fpt, owner_map, parent_scope, shadow_cache)
    fn = funcs[0]
    m = _b863_m_for(fn, "args", owner_map, parent_scope, shadow_cache, fpt, ext_taint_map)
    sink = fn.body[0].value  # `return args`
    assert "args" not in _tainted_names_visible(sink, m, owner_map, parent_scope, shadow_cache)


def test_t1b_does_not_leak_taint_between_unrelated_call_siblings():
    """A real-fleet false positive caught by this task's own corpus
    differential (`~/.openclaw` + stdlib + dist-packages; see
    cloudinit/cmd/devel/logs.py's `_stream_command_output_to_file`), not by
    the crafted 57-case matrix: `subprocess.call(cmd, stdout=f, stderr=f)`
    with `f` independently sourced (`open(path, "w")` -- a file-open is
    itself a generic taint SOURCE for `_external_tainted_names`'s broader TT4
    rule) must NOT taint the unrelated sibling argument `cmd`. The
    architect's own proto2.py prototype's T1b fixpoint taints every bare-Name
    ARGUMENT of a call whenever ANY one of its arguments is sourced -- sound
    for a receiver (`x.append(sourced)` really does taint `x`), unsound for
    co-arguments of an ordinary call. `_b863_m_for` restricts propagation to
    the call's own receiver (see its own comment)."""
    src = (
        "import os, subprocess\n\n"
        "def run(cmd, path):\n"
        "    with open(path, 'w') as f:\n"
        "        try:\n"
        "            subprocess.call(cmd, stdout=f, stderr=f)\n"
        "        except OSError:\n"
        "            pass\n\n"
        "def main():\n"
        "    run(['journalctl', '--boot=0'], '/tmp/out.txt')\n"
    )
    _assert_info(src)


def test_sys_executable_module_invocation_is_info():
    """A second real-fleet false positive from this task's own corpus
    differential (an OpenClaw plugin script): `[sys.executable, str(script),
    "--output", str(out), ...]` is an ordinary re-invocation of the CURRENT
    interpreter to run a separate script -- no `-c`/`-m` eval flag anywhere
    -- and must not convict merely because `sys.executable` is an Attribute,
    not a literal string."""
    src = (
        "import sys, subprocess\n\n"
        "def run(command):\n"
        "    return subprocess.run(command)\n\n"
        "def main():\n"
        "    command = [sys.executable, 'script.py', '--output', 'out.json']\n"
        "    run(command)\n"
    )
    _assert_info(src)


def test_sys_executable_carveout_is_a_disclosed_narrow_residual():
    """Unit-level (not `analyze_python()`): both existing, pre-B-863 argv0-
    taint checks this carve-out mirrors (`_all_call_sites_bind_fixed_argv`'s
    program-name check, and `_subprocess_taint_is_command_injection`'s own
    literal-list branch) can ONLY read a literal `ast.Constant` program name,
    so `[sys.executable, "-c", tainted]` was already not recognised as
    shell-indirect-exec by either of them before B-863 touched anything --
    verified directly: `_argv0_is_shell_indirect_exec` itself returns False
    for a `sys.executable` Attribute node regardless of an eval flag being
    present, the same limitation `_b863_shape_triggers_crit`'s own carve-out
    explicitly disclose in its docstring rather than trying to paper over
    with a synthetic stand-in Constant (a prior draft's approach, reverted:
    it worked for the narrow case tested but does not change what
    `_argv0_is_shell_indirect_exec` can see in the SHARED pre-existing
    checks, so the disclosed residual is the honest description either way)."""
    import ast

    from clawseccheck.skillast import _argv0_is_shell_indirect_exec

    tainted_tail = ast.parse("[sys.executable, '-c', payload]").body[0].value
    assert _argv0_is_shell_indirect_exec(tainted_tail.elts) is False


def test_shadowed_sys_name_does_not_get_the_executable_carveout():
    """Unit-level: `_b863_a0_is_verified_sys_executable` must refuse the
    moment `sys` is locally rebound anywhere in the file (same discipline as
    B-753's `_path_module_aliases` for `os`) -- a local object with its own
    unrelated `.executable` attribute must not silently inherit the carve-
    out. (An `analyze_python()`-level integration test would not actually
    exercise this: a wrapper whose OWN body never re-touches its parameter
    resolves earlier, through the pre-existing, unrelated
    `_all_call_sites_bind_fixed_argv` path -- see the module-level
    `_b863_shape_triggers_crit` docstring on why that path shares the same
    non-Constant-argv0 blind spot regardless of this carve-out.)"""
    import ast

    from clawseccheck.skillast import _b863_a0_is_verified_sys_executable

    genuine_tree = ast.parse("import sys\nsys.executable\n")
    genuine = genuine_tree.body[1].value
    assert _b863_a0_is_verified_sys_executable(genuine, genuine_tree) is True

    shadowed_tree = ast.parse("class sys:\n    executable = '/x'\nsys.executable\n")
    shadowed_a0 = shadowed_tree.body[-1].value
    assert _b863_a0_is_verified_sys_executable(shadowed_a0, shadowed_tree) is False


def test_call_site_merges_conditional_append_branches_sharing_one_a0():
    """A real-fleet shape (same corpus pass as the `sys.executable` case
    above): the call site's OWN local is built with a literal/verified head
    and then extended by several INDEPENDENT `if opt: cmd.append(...)`
    guards. Requiring the call-site resolver to see a single, un-branched
    shape would make each (individually harmless) conditional collapse
    resolution to "unresolvable" -> crit; merging branches that share the
    same a0 keeps this info, matching the byte-identical unconditional
    equivalent."""
    src = (
        "import sys, subprocess\n\n"
        "def run(command):\n"
        "    return subprocess.run(command)\n\n"
        "def build_and_run(verbose, quiet):\n"
        "    command = [sys.executable, 'script.py']\n"
        "    if verbose:\n"
        "        command.append('--verbose')\n"
        "    if quiet:\n"
        "        command.append('--quiet')\n"
        "    run(command)\n"
    )
    _assert_info(src)


def test_call_site_merges_many_independent_conditional_branches():
    """A second, larger real-fleet shape from the same corpus pass: a CLI-
    argument builder with SIX independent `if opt: command.append/extend(...)`
    guards (2^6 = 64 shapes) plus two `for` loops -- an entirely ordinary,
    common idiom. Must still resolve to info, confirming `_B863_MAX_SHAPES`
    (512) comfortably covers this real shape rather than merely the smaller
    2-conditional case above."""
    opts = "\n".join(f"    if opt{i}:\n        command.append('--opt{i}')" for i in range(6))
    src = (
        "import sys, subprocess\n\n"
        "def run(command):\n"
        "    return subprocess.run(command)\n\n"
        "def build_and_run(opt0, opt1, opt2, opt3, opt4, opt5, extras):\n"
        "    command = [sys.executable, 'script.py']\n"
        f"{opts}\n"
        "    for e in extras:\n"
        "        command.append(e)\n"
        "    run(command)\n"
    )
    _assert_info(src)


def test_call_site_branch_cap_falls_back_to_crit_conservatively():
    """Past `_B863_MAX_SHAPES`, the channel walk stops branching and treats
    the call site as unresolvable (crit) rather than let a pathological file
    with many independent conditionals reach an unbounded shape count -- a
    deliberate conservative-by-default cost cap, not a correctness target
    (none of this task's real evidence needs more than 6 independent
    conditionals; this pins the cap's OWN existence and safe-by-default
    direction, not a specific real-world shape)."""
    opts = "\n".join(f"    if opt{i}:\n        command.append('--opt{i}')" for i in range(10))
    params = ", ".join(f"opt{i}" for i in range(10))
    src = (
        "import sys, subprocess\n\n"
        "def run(command):\n"
        "    return subprocess.run(command)\n\n"
        f"def build_and_run({params}):\n"
        "    command = [sys.executable, 'script.py']\n"
        f"{opts}\n"
        "    run(command)\n"
    )
    _assert_crit(src)


def test_mech_nonconvergence_default_path_is_unaffected():
    """`_b863_m_for`'s own fixpoint caps at 6 iterations and simply returns
    its current M when it has not converged (mirrors `_external_tainted_names`'s
    own cap) -- it can only ever ADD names to the tainted set on a further
    iteration, so an early return is conservative (more likely to disprove
    T1b, i.e. fall through to tier 2), never a route to a false "info". This
    is a property test, not a crafted non-converging input (none of the 57
    matrix shapes fail to converge) -- verified by shrinking the cap to 0
    iterations and confirming the wrapper case that depends on convergence
    (O1) still resolves via tier 2 instead of silently going info."""
    import clawseccheck.skillast as skillast_mod

    src = _va(["args = list(args)", "args.extend(['sh', '-c', payload])"])
    real_m_for = skillast_mod._b863_m_for

    def zero_iteration_m_for(fn, param_name, owner_map, parent_scope, shadow_cache, fpt, ext_taint_map):
        # Force the very first M (seeds only, no fixpoint growth) -- the
        # weakest possible M, i.e. the LEAST likely to disprove T1b.
        seeds = {k: set(v) for k, v in ext_taint_map.items()}
        return skillast_mod._external_tainted_names(fn, seeds, owner_map, parent_scope, shadow_cache)

    skillast_mod._b863_m_for = zero_iteration_m_for
    try:
        # Even with a deliberately weakened M, O1 must not become crit (tier 2
        # still correctly says info via the non-shell a0 rule) NOR silently
        # start reporting nothing.
        findings = skillast_mod.analyze_python(textwrap.dedent(src), "t.py")
    finally:
        skillast_mod._b863_m_for = real_m_for
    tt5 = {(f.rule, f.severity) for f in findings if f.rule.startswith("TT5")}
    assert tt5 == {("TT5_ARG_INJECTION", "info")}, tt5


# ---------------------------------------------------------------------------
# FR1 -- fix round 1 (C-135, 2026-09-23) against fix/b-863 @ 338e9f5a: the
# tier-2 channel walk shared ONE `shapes` list across every name `names`
# considered an alias, so once two tracked names DIVERGED (one of them
# reassigned to a genuinely new value while the other kept the old one), a
# later mutation of either name got attributed to the wrong object. Fixed by
# giving every tracked name its own shapes-list slot in a dict, sharing the
# SAME list only between names that are still aliases of one another (see
# `_b863_process_one`'s and `_B863Shape`'s module comments). Both cases below
# are mutation-checked: reverting `clawseccheck/skillast.py` to the shared-
# list model makes each go red (see `b-863-fix1.md` in the wave-20 scratch
# directory for the mutation-check transcript).
# ---------------------------------------------------------------------------

def test_fr1_side_a_stale_alias_mutation_after_rebind_is_info():
    """Reviewer's side-A repro (BLOCKER, introduced by 338e9f5a): `x = args`
    aliases `x` to the wrapper's own vararg tuple-as-list; `args` is then
    REBOUND to a fresh, fully-literal `["sh", "-c"]` (untainted on its own);
    `x` still refers to the OLD (pre-rebind) list, so `x.append(payload)`
    cannot reach the value `args` actually holds at the sink -- provably
    inert. The pre-fix shared-list model folded `x`'s mutation onto the NEW
    `args` value anyway (wrongly reporting TT5_CMD_INJECTION/crit); the call
    site is fully literal (`sh("git", "status")`), so this must resolve
    exactly like `INLINE` / `O1` -- info, never crit."""
    src = _va(["args = list(args)", "x = args", "args = ['sh', '-c']", "x.append(payload)"])
    _assert_info(src)


def test_fr1_side_b_tracked_param_mutation_after_sibling_alias_rebind_is_crit():
    """Reviewer's side-B repro (lost detection): `x = args` aliases `x` to
    `args`; `x` is then rebound to an UNRELATED fresh literal (`["ls"]`,
    never used again); `args` itself is untouched by that rebind and is then
    genuinely mutated (`args.append(payload)`) before reaching the sink. The
    call site (`sh("sh", "-c")`) makes the real runtime value of `args` at
    the sink `["sh", "-c", payload]` -- genuine shell command injection. The
    pre-fix shared-list model let `x`'s unrelated rebind clobber the ONE
    shared list that was supposed to still represent `args`'s own untouched
    identity, so the later `args.append(payload)` landed on the wrong
    (fresh, non-shell `["ls"]`) shape and TT5 never fired at crit at all
    (info instead of the correct TT5_CMD_INJECTION/crit)."""
    src = _va(["args = list(args)", "x = args", "x = ['ls']", "args.append(payload)"], call='sh("sh", "-c")')
    _assert_crit(src)


# ---------------------------------------------------------------------------
# FR2 -- fix round 2 (C-135, 2026-09-23) against fix/b-863 @ 4c46d6c9: round
# 1 gave every tracked name its own `shapes_of[...]` slot, but
# `_b863_classify_assign_value` still MANUFACTURED a brand-new, unrelated
# blank shape for a reassignment whose RHS was itself a bare already-tracked
# Name or a `_b863_classify_head`-resolved expression, instead of reading
# that resolved name's own current `shapes_of[...]` entry -- so a reassign
# that (at runtime) re-evaluates a name STILL aliased by a third, live name
# silently detached from it in the analysis. Fixed by threading `shapes_of`
# through and returning `list(shapes_of[resolved_name])` (see
# `_b863_classify_assign_value`'s own docstring and the module comment above
# `_B863OutOfDomain`). Mutation-checked: reverting `skillast.py` to the
# fix-round-1 version makes `test_fr2_ternary_selfref_stale_alias_mutation...`
# go red (see `b863-fix2.md` in the wave-20 scratch directory).
# ---------------------------------------------------------------------------

def test_fr2_ternary_selfref_stale_alias_mutation_is_crit():
    """Reviewer's round-2 repro (BLOCKER, introduced by 4c46d6c9): `x = args`
    aliases `x` to the wrapper's own vararg tuple-as-list; `args` is then
    reassigned to an IfExp whose `else` arm is the bare Name `args` itself --
    at runtime that arm re-evaluates the CURRENT `args`, i.e. the exact
    object `x` still refers to (the ternary's `then` arm, a fresh `['ls']`,
    is only taken on the OTHER path). `x.append(payload)` afterwards mutates
    that shared object, so on the `len(payload) <= 3` path `args` ends up
    `['sh', '-c', payload]` at the sink -- genuine shell command injection.
    The fix-round-1 code fabricated a fresh, unrelated blank shape for the
    `else` arm (since it is a bare already-tracked Name), detaching it from
    `x`'s later mutation and losing the finding entirely (info instead of
    the correct TT5_CMD_INJECTION/crit)."""
    src = _va(
        ["args = list(args)", "x = args", "args = ['ls'] if len(payload) > 3 else args", "x.append(payload)"],
        call='sh("sh", "-c")',
    )
    _assert_crit(src)


def test_fr2_augassign_after_full_literal_divergence_is_info():
    """Control for the fix above, so it does not overreach: `args` is
    reassigned to a fresh, fully-literal `['ls']` (a plain Assign, not an
    IfExp `else`-arm self-reference) -- a genuine, unconditional divergence.
    `x` is now a stale reference to the OLD (pre-rebind) list; `x += [
    payload]` (AugAssign, in-place list extend) mutates that stale object,
    never the NEW `args`. Must stay info: the fix must not make EVERY later
    mutation of a former alias retroactively visible to a name that has
    since diverged via an ordinary (non-self-referential) reassign -- only
    an alias-creation or a resolved self-reference should ever share a
    `_B863Shape` object."""
    src = _va(
        ["args = list(args)", "x = args", "args = ['ls']", "x += [payload]"],
        call='sh("sh", "-c")',
    )
    _assert_info(src)


def test_fr2_if_else_alias_lost_past_branch_merge_pinned_to_current_pre_existing_gap():
    """Reviewer's round-2 side-B finding (lost detection, NOT fixed by this
    round -- filed as CLAWSECCHECK-B-967 for 4.3.1): a name (`y`) first
    discovered as an alias INSIDE one arm of an `ast.If` is dropped once the
    branch-merge completes (`_b863_process_one`'s `ast.If` handling only
    re-threads names that were already tracked BEFORE the `if`), so the
    post-if `y.append(payload)` matches no tracked receiver and is a silent
    no-op even though, at runtime, the `else` arm's `y = x` truly aliases
    the ORIGINAL `args` object that `args` itself still refers to on that
    same path (the `if` arm reassigns `args` to a new `['ls']`, but the
    `else` arm never touches `args` at all). Real value at the sink on the
    `else` path: `['sh', '-c', payload]` -- should be
    TT5_CMD_INJECTION/crit. This is a DIFFERENT root cause from this round's
    fix (branch-merge alias re-threading, not reassignment-value
    classification) and hits a different function
    (`_b863_process_one`'s `ast.If` branch, not
    `_b863_classify_assign_value`); confirmed NOT touched by this round's
    change (both before and after this round's fix give the same info
    verdict here). Pinned rather than asserted-and-xfailed so the suite
    stays green, per this file's own convention for CLAWSECCHECK-B-940/941
    above."""
    src = _va(
        [
            "import random",
            "args = list(args)",
            "x = args",
            "if random.random() > 0.5:",
            "    args = ['ls']",
            "    y = args",
            "else:",
            "    y = x",
            "y.append(payload)",
        ],
        call='sh("sh", "-c")',
    )
    _assert_info(src)  # NOT the real reachable crit on the else-path -- see docstring; CLAWSECCHECK-B-967


# ---------------------------------------------------------------------------
# FR3 -- fix round 3 (C-135, 2026-09-24) against fix/b-863 @ ca710fdb: round 2
# generalized "a reassignment returns the resolved name's own current shapes"
# to BOTH branches of `_b863_classify_assign_value` alike, but only the
# bare-Name branch (`args = x`) is a true same-object case. The `head_src`
# branch is reached only via `_b863_classify_head`'s non-Name grammar --
# `list(H)`/`tuple(H)`, `H.copy()`, a full slice `H[:]`, `H+X`, `[*H, ...]`,
# an identity-map comprehension -- and every one of those constructs a BRAND
# NEW object at runtime, so reference-sharing shapes there wrongly kept a
# freshly-rebound name coupled to whatever a stale alias of the OLD object
# went on to mutate. Fixed by giving the `head_src` branch its own
# independent snapshot (a fresh `_B863Shape` per entry, the same per-shape
# copy idiom `_b863_copy_shapes_of` already uses for branch merges) instead
# of reference-sharing. Mutation-checked: reverting `skillast.py`'s
# `head_src` branch to `list(shapes_of[head_src])` makes
# `test_fr3_list_wrap_after_alias_decouples_is_info` and its sibling shapes
# below go red (all report crit instead of info).
# ---------------------------------------------------------------------------

def test_fr3_list_wrap_after_alias_decouples_is_info():
    """Reviewer's round-3 repro (BLOCKER, introduced by ca710fdb): `x = args`
    aliases `x` to the wrapper's own vararg-as-list; `args` is then rebound
    to `list(args)` -- a COPY, a genuinely NEW list object at runtime,
    decoupled from `x`. `x.append(payload)` afterwards mutates the OLD
    object only; the new `args` cannot see it. Real value at the sink is
    `['sh', '-c']` -- `payload` never reaches it. Must be info."""
    src = _va(
        ["args = list(args)", "x = args", "args = list(args)", "x.append(payload)"],
        call='sh("sh", "-c")',
    )
    _assert_info(src)


@pytest.mark.parametrize(
    "wrap_stmt",
    [
        "args = args[:]",
        "args = args.copy()",
        "args = tuple(args)",
        "args = [*args]",
        "args = list(tuple(args))",
    ],
)
def test_fr3_every_identity_wrap_after_alias_decouples_is_info(wrap_stmt):
    """Same shape as the repro above, for every OTHER `_b863_classify_head`
    non-Name grammar member (full slice, `.copy()`, `tuple()`, star-unpack,
    a nested wrap) -- each constructs its own brand-new object at runtime,
    so each must decouple from a pre-existing alias exactly like `list()`
    does. `tuple(args)` needs `list(...)` at the sink because
    `subprocess.check_output` needs a sequence type argv, not because the
    taint question changes."""
    sink = "subprocess.check_output(list(args))" if "tuple" in wrap_stmt else "subprocess.check_output(args)"
    src = _va(
        ["args = list(args)", "x = args", wrap_stmt, "x.append(payload)"],
        call='sh("sh", "-c")',
        sink=sink,
    )
    _assert_info(src)


def test_fr3_taint_before_identity_wrap_is_still_crit():
    """Control for the fix above, so it does not overreach: the mutation
    happens BEFORE the identity wrap, not through a stale alias afterwards --
    the wrap must carry the taint FORWARD, not erase it. Real value at the
    sink is `['sh', '-c', payload]`. This is the reviewer's own verified
    "not a Side-B loss" check (`.copy()` after taint stays crit)."""
    src = _va(
        ["args = list(args)", "args.append(payload)", "args = args.copy()"],
        call='sh("sh", "-c")',
    )
    _assert_crit(src)


def test_fr3_alias_of_the_new_object_still_convicts():
    """A THIRD name (`y`) created as a bare-Name alias of the freshly-wrapped
    `args` (a true same-object alias of the NEW list, per the bare-Name
    branch fix-round-3 leaves untouched) must still convict when mutated --
    this fix must decouple a STALE alias of the OLD object, never every
    alias whatsoever. Real value at the sink is `['sh', '-c', payload]`."""
    src = _va(
        ["args = list(args)", "x = args", "args = list(args)", "y = args", "y.append(payload)"],
        call='sh("sh", "-c")',
    )
    _assert_crit(src)


def test_fr3_b965_case2_unaffected_by_this_round():
    """Control: `args = args + [payload]` (the pre-existing, separately-filed
    CLAWSECCHECK-B-965 case 2 gap -- `_b863_classify_head`'s `BinOp(Add)`
    branch recurses into `.left` only and never looks at `.right`) must stay
    exactly as it was before this round's fix: still info, still filed,
    not newly broken or newly fixed by the head_src snapshot change (this
    round never touches `_b863_classify_head`, only what
    `_b863_classify_assign_value` does with an ALREADY-resolved head_src)."""
    src = _va(["args = args + [payload]"], call='sh("sh", "-c")')
    _assert_info(src)


# ---------------------------------------------------------------------------
# Parametrized sanity sweep -- every case above, run twice more (with the
# zero-based `sink=` and `sig=` combinations already covered) to confirm
# `analyze_python` never raises on any of them, catching a crash a narrower
# unit test could miss.
# ---------------------------------------------------------------------------

_ALL_MATRIX_SOURCES = [
    _va(["args = list(args)", "args.extend(['sh', '-c', payload])"]),
    _va(["args = ['sh', '-c'] + [payload]"], sink="subprocess.check_output(list(args))"),
    _va(["args = ['sh', '-c', os.environ['X']]"], sink="subprocess.check_output(list(args))"),
    _va(["args = os.environ['P']"], sink="subprocess.check_output(list(args))"),
    _np(["cmd = list(cmd)", "cmd.extend(['sh', '-c', payload])"]),
    _va(["args = ['sh', '-c', payload]"]),
    _va(["args = list(args)", "x = args", "args = ['sh', '-c']", "x.append(payload)"]),
    _va(["args = list(args)", "x = args", "x = ['ls']", "args.append(payload)"], call='sh("sh", "-c")'),
    _va(
        ["args = list(args)", "x = args", "args = ['ls'] if len(payload) > 3 else args", "x.append(payload)"],
        call='sh("sh", "-c")',
    ),
    _va(["args = list(args)", "x = args", "args = ['ls']", "x += [payload]"], call='sh("sh", "-c")'),
]


@pytest.mark.parametrize("src", _ALL_MATRIX_SOURCES)
def test_no_crash_on_matrix_sources(src):
    analyze_python(src, "t.py")
