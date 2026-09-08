"""A call site that can truncate must take the argument that records the truncation.

## The class this guards

Four security defects found in one month share a single shape: **the correct call already
exists a few lines away, and one call site does not take it.** None was a design error; each
was an asymmetry a grep can see and human review did not.

| defect | the sibling that does it right | the site that did not |
| --- | --- | --- |
| B-458 | `checks/_vet.py:3858` passes `engine_degraded=True` | its sibling omitted it — an unreadable file exited 0 |
| `aa471d1` | `collector.py` `_skill_signature` passes `capped=` | `collect_skill_files` omitted it — 600 inert files hid a `curl \\| sh` |

Both were live fail-opens, both fixes were one line, and both sat for days behind a green
suite. Neither `fleet_fp_gate.py` nor `monitor_fp_gate.py` can see this class: they are
false-*positive* gates, and an omitted disclosure loses a signal rather than inventing one.

## Why the guard is conditional, and what that bought

The raw signal is unusable. Measured over `clawseccheck/` on 2026-08-14:

    any callee, >=1 sibling passes the keyword ........ 8531
    + only callees defined in clawseccheck/ ........... 5535
    + only >=2 siblings pass .......................... 3872
    + only disclosure-shaped keyword names .............   43
    + CONDITIONAL: only when the trigger is present ....   11

Most asymmetry is legitimate — optional arguments exist to be optional. What is never
legitimate is passing the argument that lets a scan stop early and omitting the one that
records that it did. `walk_dir_safely` without `max_files=` cannot truncate, so `capped=`
is meaningless there; with it, the omission is a silent completeness claim. Its own docstring
says so: *"GR#4: no silent completeness claim over a capped scan."*

That conditional form is the whole design, and it is what takes the list from 3,872 unreadable
hits to 11 that are all one bug.

Offline, reads only the shipped package, stdlib only.
"""
from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "clawseccheck"

# (callee, trigger keyword, recorder keyword)
#   "if a call passes <trigger>, it must also pass <recorder>"
_PAIRS = (
    ("walk_dir_safely", "max_files", "capped"),
)

# Sites that take the trigger and not the recorder, each with the subject it scans and the
# `LIMIT_DOMAIN_*` its disclosure would belong to. **This is debt, not design.** Every entry
# is a surface that can stop reading and report nothing about having stopped; the domain
# vocabulary these would feed already exists in `collector.py:233-241` and was built for
# exactly this. Tracked as a task; do not add to this list to make a new omission pass.
_EXEMPT = {
    ("checks/_lifecycle.py", "check_backups"):        "backup tree walk (_C3_MAX_WALK_FILES)",
    ("collector.py", "_collect_cron"):                "cron job store — LIMIT_DOMAIN_CRON",
    ("collector.py", "_flag_shadowed_cron_store"):    "shadowed cron store — LIMIT_DOMAIN_CRON",
    ("collector.py", "_collect_cron_run_logs"):       "cron execution trail — LIMIT_DOMAIN_CRON",
    ("collector.py", "_collect_capture_state"):       "capture state store",
    ("collector.py", "_collect_plugin_trust"):        "plugin trust index — LIMIT_DOMAIN_PLUGIN",
    ("collector.py", "_collect_subagent_runs"):       "subagent run disclosure — LIMIT_DOMAIN_AGENTS",
    ("collector.py", "_collect_audit_events"):        "audit event trail — LIMIT_DOMAIN_AUDIT",
    ("logdiscovery.py", "_memory_sinks"):             "memory sink discovery",
    ("logdiscovery.py", "_backup_sinks"):             "backup sink discovery",
}


def _callee(node: ast.Call) -> str | None:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _offenders(tree: ast.AST, rel: str) -> list[tuple[str, str, str, str, int]]:
    """(rel, enclosing def, callee, missing kw, lineno) for each conditional violation.

    Keyed on the enclosing function rather than the line number: a line number rots on the
    next edit above it, and an exemption list nobody can trust is worse than none.
    """
    out: list[tuple[str, str, str, str, int]] = []
    stack: list[str] = []

    class V(ast.NodeVisitor):
        def visit_FunctionDef(self, node):  # noqa: N802
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815

        def visit_Call(self, node):  # noqa: N802
            name = _callee(node)
            if name:
                kws = {k.arg for k in node.keywords if k.arg}
                for callee, trigger, recorder in _PAIRS:
                    if name == callee and trigger in kws and recorder not in kws:
                        out.append((rel, stack[-1] if stack else "<module>",
                                    callee, recorder, node.lineno))
            self.generic_visit(node)

    V().visit(tree)
    return out


def _scan_package() -> list[tuple[str, str, str, str, int]]:
    found: list[tuple[str, str, str, str, int]] = []
    for path in sorted(PKG.rglob("*.py")):
        rel = str(path.relative_to(PKG))
        found += _offenders(ast.parse(path.read_text(encoding="utf-8"), filename=rel), rel)
    return found


# ------------------------------------------------------------------ the guard itself

def test_no_new_site_can_truncate_without_recording_it():
    """The live guard. A call that can stop early must take the sentinel that says it did."""
    unexpected = [
        (rel, fn, callee, kw, ln)
        for rel, fn, callee, kw, ln in _scan_package()
        if (rel, fn) not in _EXEMPT
    ]
    assert not unexpected, (
        "a call site passes the truncating argument but not the one that records the "
        "truncation — a silent completeness claim:\n  "
        + "\n  ".join(f"{r}:{ln} in {fn}(): {c}() missing {kw}=" for r, fn, c, kw, ln in unexpected)
        + "\n\nEither pass it, or add the site to _EXEMPT with the subject it scans and the "
          "LIMIT_DOMAIN_* its disclosure belongs to."
    )


def test_every_exemption_is_still_a_real_site():
    """Guard the guard. An exemption for a site that no longer exists is dead weight that
    makes the list look considered when it is stale — the failure mode
    `test_module_layout.py::test_exempt_line_claims_match_reality` exists to prevent."""
    live = {(rel, fn) for rel, fn, _c, _k, _l in _scan_package()}
    stale = sorted(set(_EXEMPT) - live)
    assert not stale, (
        "these exemptions no longer match any offending call site — the site was fixed or "
        "moved, so remove the entry:\n  " + "\n  ".join(f"{r} :: {f}" for r, f in stale)
    )


def test_the_exempt_list_is_debt_and_says_so():
    """Every entry names its subject, so the follow-up work is readable from the list alone
    rather than requiring the reader to open eleven call sites."""
    for key, reason in _EXEMPT.items():
        assert reason and len(reason) > 12, f"{key} carries no usable reason: {reason!r}"


# ------------------------------------------------------------------ the historical cases

def test_it_catches_the_shape_of_the_defect_that_shipped():
    """Reconstructed `aa471d1`: `collect_skill_files` capped its walk and dropped the
    sentinel, so 600 inert files hid a `curl | sh` payload behind a `Danger PASS`.

    A guard that cannot be shown to catch its own motivating defect is decoration."""
    before = (
        "def collect_skill_files(skill_dir, ctx=None):\n"
        "    _skips = []\n"
        "    files = walk_dir_safely(base_dir, exclude_pycache=True,\n"
        "                            max_files=_MAX_FILES_PER_SKILL, skips=_skips)\n"
    )
    hits = _offenders(ast.parse(before), "collector.py")
    assert hits, "the guard does not catch the defect it was written for"
    assert hits[0][1] == "collect_skill_files" and hits[0][3] == "capped"


def test_it_stays_quiet_on_the_fixed_form():
    """The other direction, so the guard is not merely always-on for this callee."""
    after = (
        "def collect_skill_files(skill_dir, ctx=None):\n"
        "    _skips, _capped = [], []\n"
        "    files = walk_dir_safely(base_dir, max_files=_MAX_FILES_PER_SKILL,\n"
        "                            skips=_skips, capped=_capped)\n"
    )
    assert not _offenders(ast.parse(after), "collector.py")


def test_a_call_that_cannot_truncate_is_not_flagged():
    """The conditional half — the narrowing that took 3,872 hits down to 11. Without a cap
    there is nothing to record, and flagging it would make the guard unreadable again."""
    uncapped = (
        "def check_self_integrity(root):\n"
        "    files = walk_dir_safely(root, exclude_pycache=True, exclude_vcs=True)\n"
    )
    assert not _offenders(ast.parse(uncapped), "integrity.py")
