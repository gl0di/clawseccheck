"""B-743 — the JS warn bucket's advice must name the cause that actually fired.

`check_installed_skills` routes `analyze_javascript` findings by severity alone: `crit` to
the FAIL bucket, everything else to `warns_js`. That bucket then rendered a single hardcoded
remediation naming `child_process` and `require()`. The analyzer has **three** warn rules,
not two.

Measured before the fix, on a skill whose only JS is `process.dlopen(module, "./addon.node")`::

    detail: "... process.dlopen() loads a native addon (.node) directly — a native-boundary
             escape that bypasses JS-level analysis"
    fix   : "A bundled .js/.ts file runs child_process with an interpolated command or
             require()s a non-literal module path — a command-injection / arbitrary-module
             surface. Read the flagged call and confirm the inputs are trusted."

The remediation contradicts the finding directly above it. A reader who follows it hunts for
a `child_process` call that is not in the file, and the actual issue — a native binary loaded
where no JS-level scan can see inside it — goes unaddressed. That is the B-714 / B-738 class:
advice that cannot clear the condition its own finding describes.

The same literal reached the adjudication packet. `_B13_WINNER_SUBSIGNAL["warns_js"]` is one
fixed string, so the judge was asked about a "dynamic JS/TS execution surface" when the signal
was a dlopen.

WHY THE LAST TEST IS THE ONE THAT MATTERS
-----------------------------------------
This drifted because the prose was written when the bucket had two feeders and nothing
noticed when a third arrived — the routing comment above it still enumerated two. Fixing the
three strings fixes today. The guard below extracts every warn-severity rule from
`analyze_javascript`'s own `add(...)` call sites and requires a remediation entry for each, so
a fourth rule fails the build at its definition instead of silently inheriting someone else's
advice.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
from pathlib import Path

from clawseccheck.checks._vet import (
    _JS_WARN_REMEDIATION,
    _js_warn_fix,
    _js_warn_sub_signals,
)
from clawseccheck.checks import vet_skill

REPO = Path(__file__).resolve().parent.parent

_DLOPEN = 'process.dlopen(module, "./addon.node");\n'
_CHILD_PROC = 'require("child_process").execSync(`git tag ${v}`);\n'
_DYN_REQUIRE = 'const m = require(modName);\n'


def _skill(tmp_path: Path, name: str, js: str) -> Path:
    d = tmp_path / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A skill.\n---\nsee run.js\n", encoding="utf-8"
    )
    (d / "run.js").write_text(js, encoding="utf-8")
    return d


def test_a_dlopen_only_skill_is_not_told_to_inspect_child_process(tmp_path):
    """The reported case. The advice named a call that is not in the file."""
    f = vet_skill(_skill(tmp_path, "nativeload", _DLOPEN))

    assert "dlopen" in f.detail, f.detail  # precondition: the right rule fired
    assert "process.dlopen()" in f.fix, f.fix
    assert "child_process" not in f.fix, f.fix
    assert "require()" not in f.fix, f.fix


def test_the_child_process_case_keeps_its_correct_advice(tmp_path):
    """Non-regression. The old text was right for the rule it was written for."""
    f = vet_skill(_skill(tmp_path, "gittag", _CHILD_PROC))

    assert "child_process" in f.fix, f.fix
    assert "interpolated" in f.fix, f.fix
    assert "dlopen" not in f.fix, f.fix


def test_two_causes_at_once_are_both_named(tmp_path):
    """A skill can trip several. Naming one and leaving the other unmentioned in the same
    finding is the same defect one notch smaller, so every fired rule is rendered."""
    f = vet_skill(_skill(tmp_path, "both", _DLOPEN + _CHILD_PROC))

    assert "child_process" in f.fix, f.fix
    assert "process.dlopen()" in f.fix, f.fix


def test_the_adjudication_packet_is_asked_about_what_fired(tmp_path):
    """`sub_signals` is the question the E-038 judge is handed. It was a constant."""
    dl = vet_skill(_skill(tmp_path, "a", _DLOPEN))
    cp = vet_skill(_skill(tmp_path, "b", _CHILD_PROC))
    both = vet_skill(_skill(tmp_path, "c", _DLOPEN + _CHILD_PROC))

    assert getattr(dl, "sub_signals", None) == {"native addon loaded past the JS analysis boundary"}
    assert getattr(cp, "sub_signals", None) == {"interpolated child_process command"}
    assert getattr(both, "sub_signals", None) == {
        "interpolated child_process command",
        "native addon loaded past the JS analysis boundary",
    }


def test_the_derivation_is_ordered_and_never_invents_a_cause():
    """Unit-level properties of the two derivations.

    Order comes from the table, not from set iteration, so the rendered text is stable
    across runs. And an unrecognised rule id must produce a situation, never a guessed
    cause — the whole defect was prose asserting a cause that had not fired.
    """
    both = _js_warn_fix({"JS_NATIVE_DLOPEN", "JS_CHILD_PROCESS_DYNAMIC"})
    assert both.index("child_process") < both.index("process.dlopen()"), both

    unknown = _js_warn_fix({"JS_SOMETHING_NEW"})
    assert "child_process" not in unknown and "dlopen" not in unknown, unknown
    assert "require()" not in unknown, unknown
    # and the packet keeps its field rather than losing it
    assert _js_warn_sub_signals({"JS_SOMETHING_NEW"}, {"one"}) == {"dynamic JS/TS execution surface"}


def _js_rules_by_severity() -> dict:
    """Every (rule id -> severity) `analyze_javascript` can emit, from its own source.

    Its findings are all built through one local helper, ``add(rule, sev, ln, reason)``,
    with both leading arguments as string literals — so the pairs are extractable exactly,
    without running the analyzer over a battery of payloads that would itself need
    maintaining.
    """
    tree = ast.parse((REPO / "clawseccheck" / "skillast.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "analyze_javascript")
    out = {}
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "add"):
            continue
        if len(node.args) < 2:
            continue
        rule, sev = node.args[0], node.args[1]
        if isinstance(rule, ast.Constant) and isinstance(sev, ast.Constant):
            out[rule.value] = sev.value
    return out


def test_every_warn_rule_has_its_own_remediation():
    """The class guard, and the reason this file exists rather than three fixed strings.

    The bucket's advice was written when two rules fed it. `JS_NATIVE_DLOPEN` arrived, the
    routing comment above it still said two, and the prose became false without any test
    noticing. This makes the next such addition fail here.
    """
    by_sev = _js_rules_by_severity()
    assert by_sev, "could not extract any rule from analyze_javascript — re-ground this guard"

    warn_rules = {r for r, sev in by_sev.items() if sev != "crit"}
    assert warn_rules, "expected at least one warn-severity JS rule"

    missing = sorted(warn_rules - set(_JS_WARN_REMEDIATION))
    assert not missing, (
        "these analyze_javascript rules land in the `warns_js` bucket but have no "
        f"remediation of their own, so they would render another rule's advice: {missing}. "
        "Add an entry to _JS_WARN_REMEDIATION naming what the reader should actually do."
    )

    stale = sorted(set(_JS_WARN_REMEDIATION) - warn_rules)
    assert not stale, (
        "_JS_WARN_REMEDIATION has entries for rules that are not warn-severity (or no "
        f"longer exist), i.e. advice nothing can reach: {stale}"
    )


def test_the_class_guard_bites_on_the_shape_it_replaced():
    """Positive control. Without it the guard passes both on a correct tree and on one
    where the AST extraction quietly matched nothing.

    Uses the real pre-B-743 shape: three warn rules, a table covering two.
    """
    by_sev = _js_rules_by_severity()
    assert by_sev.get("JS_NATIVE_DLOPEN") == "warn", by_sev
    assert by_sev.get("JS_EVAL_REMOTE") == "crit", by_sev

    warn_rules = {r for r, sev in by_sev.items() if sev != "crit"}
    pre_b743_table = {"JS_CHILD_PROCESS_DYNAMIC", "JS_DYNAMIC_REQUIRE"}
    assert sorted(warn_rules - pre_b743_table) == ["JS_NATIVE_DLOPEN"], (
        "the guard must flag the rule that had no advice of its own — this is exactly "
        "the state the tree shipped in"
    )


def test_dynamic_require_is_covered_too(tmp_path):
    """The third feeder, asserted rather than assumed present."""
    f = vet_skill(_skill(tmp_path, "dynreq", _DYN_REQUIRE))
    assert "require()" in f.fix, f.fix
    assert "dlopen" not in f.fix, f.fix


def test_the_dlopen_advice_claims_no_silence_the_scan_does_not_have(tmp_path):
    """C-135 BLOCKER, fixed here — the first draft of this advice was false.

    It said "Nothing in a JS-level scan — this tool's included — can see inside a .node
    binary, so the scan's silence about it is not evidence." The scan is not silent: on the
    same skill with the addon and no JS, the tool reports
    ``native executable(s) bundled in the skill (stowaway): addon.node (ELF)`` (F-054,
    collector). Adding the dlopen line makes the JS bucket win the cascade and that alarm
    is computed and then dropped — CLAWSECCHECK-B-745. So the sentence asserted a blind
    spot where there is a dropped alarm, which is worse than the text it replaced: that one
    was visibly about the wrong thing, this one was plausibly about the right thing and
    wrong.

    The advice must therefore never characterise what the scan did or did not see. It may
    say only what is true of any JS-level analysis — it cannot read compiled code — and
    give the reader a test they can actually apply.
    """
    f = vet_skill(_skill(tmp_path, "nativeload", _DLOPEN))

    assert "silence" not in f.fix, f.fix
    assert "not evidence" not in f.fix, f.fix
    # and it must give a criterion, not a shrug — both sibling entries do
    assert "binding.gyp" in f.fix or "checksummed" in f.fix, f.fix


def test_the_child_process_advice_fits_the_shell_less_forms_too(tmp_path):
    """C-135: the rule matches more than shell commands, so the advice must not say
    "command injection" as if it were the only hazard.

    Executed: `JS_CHILD_PROCESS_DYNAMIC` fires on ``execFile(`${bin}`, ["--version"])`` and
    ``spawn(`${bin}`, ["--v"])``, which take an argv array and start no shell. There the
    hazard is which PROGRAM runs, not injection into a command string.

    The criterion moved for the same reason. "Confirm every interpolated value is one the
    skill controls" is answered *yes* for ``execSync(`git tag ${tag}`)`` where `tag` comes
    from model output — the skill does control the interpolation site — so a reader
    following it clears a real injection.
    """
    for src, label in ((r'require("child_process");execFile(`${bin}`, ["--v"]);', "execFile"),
                       (r'require("child_process");spawn(`${bin}`, ["--v"]);', "spawn")):
        f = vet_skill(_skill(tmp_path / label, "s", src))
        assert "child_process" in f.fix, (label, f.fix)
        assert "which program runs" in f.fix, (label, f.fix)
        # the retired criterion must not come back: it is answerable "yes" while unsafe
        assert "is one the skill controls" not in f.fix, (label, f.fix)


def test_the_detail_headline_follows_what_fired(tmp_path):
    """C-135 PARTIAL-FIX finding: the fix and sub-signal were derived, the headline was
    not — leaving one label for many causes on the line the reader meets first, which is
    the defect this task exists to remove."""
    dl = vet_skill(_skill(tmp_path, "a", _DLOPEN))
    cp = vet_skill(_skill(tmp_path, "b", _CHILD_PROC))
    both = vet_skill(_skill(tmp_path, "c", _DLOPEN + _CHILD_PROC))

    assert "native addon loaded past the JS analysis boundary" in dl.detail, dl.detail
    assert "interpolated child_process command" in cp.detail, cp.detail
    assert "Several runtime JS/TS signals" in both.detail, both.detail
    # the retired literal named one cause for all of them
    for f in (dl, cp, both):
        assert "Dynamic JS/TS execution surface" not in f.detail, f.detail


def test_the_packet_claim_is_withheld_when_more_than_one_skill_contributed(tmp_path, capsys):
    """C-135 BLOCKER, and one this change INTRODUCED — the sharper claim was misattributed.

    `sub_signals` is the only field here bound to a NAMED subject: the packet's `target`
    comes from the first evidence line's skill, while B13 is one finding spanning every
    installed skill. The question shipped beside it says "flagged THIS SKILL for the
    specific sub-signal recorded in safe_facts.sub_signals — that is what fired, not the
    others B13 can report."

    Measured on a home with `alpha` (dlopen only) and `bravo` (child_process only), the
    union was published under `target: alpha`, telling the judge that alpha had an
    interpolated child_process command. It does not. The old constant was vague and so
    true of any contributor; making it specific without scoping it to the subject turned
    vagueness into a false statement about a named skill.
    """
    home = tmp_path / "home"
    skills = home / "workspace" / "skills"
    for name, js in (("alpha", _DLOPEN), ("bravo", _CHILD_PROC)):
        d = skills / name
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: A skill.\n---\nsee run.js\n", encoding="utf-8"
        )
        (d / "run.js").write_text(js, encoding="utf-8")

    from clawseccheck.checks import check_installed_skills
    from clawseccheck.collector import collect

    f = check_installed_skills(collect(home))
    assert f.status == "WARN", f.status
    signals = getattr(f, "sub_signals", None) or set()

    # both skills fed the bucket, so no per-skill claim may be made
    assert signals == {"dynamic JS/TS execution surface"}, signals
    # specifically: bravo's cause must not be attached to a packet naming alpha
    assert "interpolated child_process command" not in signals, signals


def test_a_sole_contributor_still_gets_the_precise_claim(tmp_path):
    """The other side of the bound — scoping must not silence the case it was built for.

    Without this, the guard above also passes on a tree that withheld the precise label
    unconditionally, which would undo the whole change.
    """
    home = tmp_path / "home"
    d = home / "workspace" / "skills" / "solo"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: solo\ndescription: A skill.\n---\nsee run.js\n", encoding="utf-8"
    )
    (d / "run.js").write_text(_DLOPEN, encoding="utf-8")

    from clawseccheck.checks import check_installed_skills
    from clawseccheck.collector import collect

    f = check_installed_skills(collect(home))
    assert getattr(f, "sub_signals", None) == {
        "native addon loaded past the JS analysis boundary"
    }, getattr(f, "sub_signals", None)
