"""B-636: --vet-plugin must read the Python a plugin ships outside its declared skills.

`vet_plugin`'s tree sweep analysed .json, native-executable headers and .js/.ts. Python
was analysed only inside a dispatched bundled-skill directory, so a plugin whose dangerous
Python sat anywhere else was opened by no reader, and the DANGER axis — the one a
pre-install gate exists for — printed an affirmative "no malware signature or known-bad
indicator" over it.

Measured before the fix, holding the payload byte-identical and varying only its location
(the shipped `bad_b13_fetch_to_exec` loader: urlopen -> exec(compile(...))):

    payload at the plugin root            -> CAUTION, Danger PASS
    payload beside the dispatched skill   -> CAUTION, Danger PASS
    payload inside the dispatched skill   -> DO-NOT-INSTALL, Danger FAIL
    no Python at all          [control]   -> CAUTION, Danger PASS

The control is what makes the first two damning: the verdict for a plugin shipping a
remote code loader was identical to the verdict for a plugin shipping nothing, so it
carried no information about the loader at all.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import vet_plugin
from clawseccheck.dossier import build_profile

REPO = Path(__file__).resolve().parent.parent
PAYLOAD = (REPO / "fixtures" / "bad_b13_fetch_to_exec" / "skills" / "bootstrap-helper"
           / "scripts" / "post_install.py")

_BENIGN_PY = '''#!/usr/bin/env python3
"""Write a default config file next to this plugin."""
import json
import pathlib


def main():
    target = pathlib.Path(__file__).with_name("settings.json")
    target.write_text(json.dumps({"theme": "light", "indent": 2}, indent=2))
'''

_SKILL_MD = """---
name: text-tool
description: Formats text.
---

# text-tool

Formats text locally. No network access, no shell.
"""


def _plugin(root: Path, *, py_at: str | None = None, py_body: str | None = None) -> Path:
    """A plugin with one clean bundled skill, optionally shipping one Python file.

    `py_at` is plugin-relative, so the SAME body can be placed at the root, beside the
    dispatched skill dir, or inside it — which is the whole experiment.
    """
    root.mkdir(parents=True, exist_ok=True)
    # A slug, not root.name: the directory names below encode the payload's location and
    # would land in the manifest as e.g. "install.py", tripping an unrelated "invalid
    # manifest" WARN. A fixture that fires a second, irrelevant signal makes every verdict
    # in this file harder to attribute.
    (root / "openclaw.plugin.json").write_text(
        json.dumps({"name": "b636-case", "version": "1.0.0", "skills": ["skills"]})
    )
    skill = root / "skills" / "text-tool"
    skill.mkdir(parents=True, exist_ok=True)
    (skill / "SKILL.md").write_text(_SKILL_MD)
    if py_at is not None:
        target = root / py_at
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(py_body if py_body is not None else PAYLOAD.read_text())
    return root


def _danger(out) -> object:
    profile = build_profile(out, "t", "plugin")
    return next(a for a in profile.axes if a.axis == "danger")


def test_the_payload_fixture_is_the_shipped_one():
    """Non-vacuity for every case below: if this file ever stops containing the loader,
    the location experiment would compare two harmless plugins and pass for free."""
    body = PAYLOAD.read_text()
    assert "urlopen" in body and "exec(compile(" in body


# ---------------------------------------------------------------------------
# The experiment: identical bytes, three locations
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("where", ["install.py", "skills/shared_helper.py",
                                   "skills/text-tool/install.py"])
def test_the_same_payload_convicts_wherever_it_sits(tmp_path, where):
    """The defect in one line: location decided the verdict, content did not."""
    out = vet_plugin(_plugin(tmp_path / where.replace("/", "_"), py_at=where))
    assert out.status == FAIL, f"{where}: {out.status} — {out.detail[:120]}"
    axis = _danger(out)
    assert axis.status == FAIL, f"{where}: danger={axis.status} — {axis.reason}"
    assert "remote code loader" in axis.reason


def test_the_control_plugin_with_no_python_stays_clean(tmp_path):
    """The measurement that made this a bug rather than a nitpick, kept as a test: without
    it, "the loader plugin reports CAUTION" says nothing, because a clean plugin of this
    shape reports CAUTION too."""
    out = vet_plugin(_plugin(tmp_path / "clean"))
    assert out.status != FAIL
    assert _danger(out).status == PASS


def test_benign_python_outside_a_skill_gains_no_fail(tmp_path):
    """The false-positive gate. The reader must convict the loader and nothing else — a
    plugin whose only Python writes a settings file is the ordinary case."""
    out = vet_plugin(_plugin(tmp_path / "benign", py_at="install.py", py_body=_BENIGN_PY))
    assert out.status != FAIL, out.detail[:200]
    assert _danger(out).status == PASS, _danger(out).reason


# ---------------------------------------------------------------------------
# What the reader cannot read must still be disclosed
# ---------------------------------------------------------------------------

def test_python_over_the_size_cap_is_disclosed_not_silently_clean(tmp_path):
    """A file past the input cap is not analysed — the same F-148 bound the JS pass has.
    It is a real bypass (pad the loader past the cap) and it is DISCLOSED rather than
    silently passed, which is the whole difference from the state before this fix."""
    from clawseccheck.checks._mcp import _PLUGIN_PY_MAX_BYTES

    body = PAYLOAD.read_text() + ("# pad\n" * ((_PLUGIN_PY_MAX_BYTES // 6) + 1000))
    root = _plugin(tmp_path / "oversized", py_at="install.py", py_body=body)
    assert (root / "install.py").stat().st_size > _PLUGIN_PY_MAX_BYTES, "control: over cap"

    out = vet_plugin(root)
    assert out.status != PASS, "an unread file must not leave a clean PASS"
    assert getattr(out, "unanalysed_code", None) == ["install.py"]
    assert any("was not analysed" in e and "scan cap" in e for e in (out.evidence or [])), \
        out.evidence


def test_unparseable_python_is_disclosed_not_silently_clean(tmp_path):
    """F-057's contract, reached from the plugin path: a parse failure must read as
    "could not look", never as "looked and found nothing"."""
    root = _plugin(tmp_path / "py2", py_at="install.py",
                   py_body='print "python 2 syntax"\nexec "danger"\n')
    out = vet_plugin(root)
    assert out.status != PASS
    assert getattr(out, "unanalysed_code", None) == ["install.py"]


# ---------------------------------------------------------------------------
# The axes must not swap one false sentence for another
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body,label", [(None, "payload"), (_BENIGN_PY, "benign")])
def test_axes_do_not_claim_there_is_no_code_when_python_was_read(tmp_path, body, label):
    """Adding the reader emptied `unanalysed_code`, and the Persistence/Connections axes
    fell through to "no executable code to analyze" — a claim about the ARTIFACT, and false
    for a plugin shipping install.py. Those axes are computed from bundled-skill Contexts
    and still cannot see this file, so the honest state is a fourth one, not one of three.
    """
    out = vet_plugin(_plugin(tmp_path / f"axes_{label}", py_at="install.py", py_body=body))
    profile = build_profile(out, "t", "plugin")
    for name in ("persistence", "connections"):
        axis = next(a for a in profile.axes if a.axis == name)
        assert axis.status == UNKNOWN, f"{name}: {axis.status} — {axis.reason}"
        assert "no executable code" not in axis.reason, axis.reason
        assert "read for dangerous patterns only" in axis.reason, axis.reason


# ---------------------------------------------------------------------------
# One classifier, not two
# ---------------------------------------------------------------------------

def test_never_fail_rules_match_the_guards_in_the_classifier():
    """Staleness control tying `_AST_NEVER_FAIL_RULES` to the code it describes.

    The set exists so `checks/_mcp.py` can ask which AST rules may FAIL instead of
    re-deriving it — a second hand-written copy of a policy this calibrated is the B-497
    shape. A declared set that nothing checks would be exactly the copy it replaces, so it
    is compared here against the `if af.rule == "...": ...; continue` arms of the loop it
    summarises.

    The loop is in `check_installed_skills`, NOT in `vet_skill` — `vet_skill` reaches it by
    calling it. Written down because the first draft of this guard looked for it inside
    `vet_skill`, found zero loops, and would have compared the registry against an empty
    set. The `assert loops` below is why that cannot happen quietly.
    """
    # Imported HERE, not at module scope. On the pre-fix tree these names do not exist,
    # and a module-level import turns every behavioural test in this file into a COLLECTION
    # ERROR — none of them run, so none of them demonstrate anything about the defect. That
    # is the second time in one day the same shape hid a guard's real reach (see
    # tests/test_b565_coverage_page_accounts_every_check.py, whose first draft failed on a
    # missing constant instead of on its own census).
    from clawseccheck.checks._vet import _AST_NEVER_FAIL_RULES

    tree = ast.parse((REPO / "clawseccheck" / "checks" / "_vet.py").read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "check_installed_skills")
    loops = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.For) and isinstance(n.target, ast.Name) and n.target.id == "af"
        and isinstance(n.iter, ast.Call)
        and (getattr(n.iter.func, "id", None)
             or getattr(n.iter.func, "attr", None)) == "analyze_python"
    ]
    assert loops, "non-vacuity: the analyze_python loop this set describes was not found"

    guarded = set()
    guard_lines: list[int] = []
    predicate_line = None
    for loop in loops:
        for stmt in loop.body:
            if not isinstance(stmt, ast.If):
                continue
            test = stmt.test
            if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Attribute)
                    and test.left.attr == "rule"
                    and isinstance(test.comparators[0], ast.Constant)
                    and any(isinstance(b, ast.Continue) for b in stmt.body)):
                guarded.add(test.comparators[0].value)
                guard_lines.append(stmt.lineno)
            elif (isinstance(test, ast.Call)
                  and getattr(test.func, "id", None) == "ast_finding_is_fail_capable"):
                predicate_line = stmt.lineno

    # ORDER, not just membership. Adopting the predicate inside this loop is only
    # behaviour-preserving because every never-FAIL arm `continue`s BEFORE it runs. Set
    # equality alone would still pass if an arm were moved below the predicate — and that
    # move would silently start FAILing skills on rules this project decided not to
    # convict on, on the audit path, with no test complaining.
    assert predicate_line is not None, "the predicate call was not found in the loop"
    late = [ln for ln in guard_lines if ln > predicate_line]
    assert not late, (
        f"never-FAIL arm(s) at line(s) {late} run AFTER the fail-capable test at line "
        f"{predicate_line} — those rules would now FAIL instead of being routed to WARN"
    )

    assert guarded == set(_AST_NEVER_FAIL_RULES), (
        "the never-FAIL registry and the classifier's own guards disagree — "
        f"only in code: {sorted(guarded - set(_AST_NEVER_FAIL_RULES))}; "
        f"only in the registry: {sorted(set(_AST_NEVER_FAIL_RULES) - guarded)}"
    )


def test_fail_capable_predicate_respects_both_halves():
    from clawseccheck.checks._vet import ast_finding_is_fail_capable

    class _AF:
        def __init__(self, rule, severity):
            self.rule, self.severity = rule, severity

    assert ast_finding_is_fail_capable(_AF("REMOTE_EXEC", "crit"))
    assert not ast_finding_is_fail_capable(_AF("REMOTE_EXEC", "info"))
    # a rule the project decided is never FAIL-capable, whatever its severity label
    assert not ast_finding_is_fail_capable(_AF("CHUNKED_FILE_EXEC", "crit"))
    assert not ast_finding_is_fail_capable(_AF("AST_UNANALYZABLE", "crit"))
