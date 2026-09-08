"""Every artifact this module emits crosses the boundary, rather than being trusted across it.

`report.render_json` ends `return json.dumps(_sanitize_tree(payload), ...)`.
`PipelineResult.to_json` ends `return _sanitize_tree(payload)`, and its docstring states
the rule: *"the producer already sanitized it" is not a property this boundary may assume
— it enforces it.*

Every emitter in `adjudication.py` ended at a bare `json.dumps`. That is the module whose
artifacts travel FURTHEST from the machine that made them: `--judge-packet` and
`--vet-judge-packet` are the ones `SKILL.md` tells the agent to paste into a possibly
third-party judge panel. Safety rested on a dozen independent producers each remembering —
B-570 gates `target`, B-556 reduces content-ring evidence to a location,
`live_test_cap_signal` allow-lists tools and regex-gates ids. All careful; none of it a
structure. B-689 had just shown what happens to a rule kept by hand in more than one place.

The fix is one exit point, `_emit_json`, so the guard below can be a census rather than a
list of remembered call sites.

**Inertness was measured before shipping, not assumed.** Against a `git archive` of the
pre-change HEAD, on `fixtures/home_vuln` and `fixtures/home_safe`: `--judge-packet` and
`--propose-ignore` byte-identical, `--judged` byte-identical once the tool's own install
path is normalised (the two trees live at different paths and `invocation.py` correctly
names its own — 7 occurrences, +3 bytes each, +21 total, which is the whole diff).

Offline, no network, writes nothing outside tmp_path.
"""
from __future__ import annotations

import ast
import copy
import json
from pathlib import Path

import pytest

from clawseccheck.adjudication import _MAX_CAP_REASON_LEN, _emit_json, render_judge_packet_json
from clawseccheck.catalog import Finding
from clawseccheck.checks import run_all
from clawseccheck.collector import collect
from clawseccheck.report import _sanitize_tree
from clawseccheck.scoring import compute

REPO_ROOT = Path(__file__).resolve().parents[1]
_ADJUDICATION_SRC = (REPO_ROOT / "clawseccheck" / "adjudication.py").read_text(encoding="utf-8")

_FINDINGS = [Finding(id="B2", title="ok", severity="LOW", status="PASS",
                     detail="d", fix="f", framework="x")]


def _packet_with_reason(reason: str) -> dict:
    """A real judge packet whose `capsFired` carries `reason`, emitted the shipping way."""
    score = copy.copy(compute(_FINDINGS))
    object.__setattr__(score, "graded", False)
    object.__setattr__(score, "config_blind_capped", True)
    object.__setattr__(score, "config_blind_reason", reason)
    return json.loads(render_judge_packet_json(None, [], version="t", score=score))


def _reason_out(reason: str) -> str:
    caps = _packet_with_reason(reason)["runState"]["capsFired"]
    entry, = [c for c in caps if c["cap"] == "config_blind_capped"]
    return entry["reason"]


# ------------------------------------------------------------------ the boundary bites

@pytest.mark.parametrize("hostile,forbidden", [
    ("first line\nsecond line", "\n"),
    ("carriage\rreturn", "\r"),
    ("tab\tseparated", "\t"),
    ("colour \x1b[31mred\x1b[0m here", "\x1b"),
    ("bell\x07inside", "\x07"),
    ("bidi ‮override", "‮"),
], ids=["newline", "cr", "tab", "ansi", "control", "bidi"])
def test_a_hostile_reason_cannot_reach_the_packet_intact(hostile, forbidden):
    """`run_state` copies a reason verbatim -- it applies no bound and no filter, and that
    is fine now that the emitter does. Driven through the REAL emitter rather than through
    `run_state`, because the emitter is where the property lives."""
    assert forbidden in hostile          # the case is really hostile before it is emitted
    assert forbidden not in _reason_out(hostile)


def test_a_long_reason_comes_out_bounded_and_single_line():
    """The task's own repro (5,000 'A's + an embedded newline): the first pass closed
    the "no filter" half (the newline case above) but left "no bound" untouched, so a
    5,000-char reason still reached the packet verbatim at 5,012 chars. This is the
    long-input case the task's own test plan demanded and the shipped fix skipped --
    both the bound AND the single-line properties, from one repro."""
    hostile = "A" * 5000 + "\n" + "second line"
    out = _reason_out(hostile)
    assert "\n" not in out, out
    assert len(out) <= _MAX_CAP_REASON_LEN + len("...[truncated]"), len(out)
    assert out.endswith("...[truncated]"), out
    assert len(out) < len(hostile), (len(out), len(hostile))


def test_a_secret_shaped_value_is_redacted_at_the_boundary():
    """`_sanitize` ends in `logsafe.redact`, so the boundary is not only about control
    characters: a secret that reached a reason through some future producer is removed
    here rather than pasted into a third-party agent.

    The value is assembled at runtime from fragments so no contiguous secret-shaped literal
    exists in this file (CLAUDE.md §2.3) -- the same discipline `tests/test_logsafe.py` uses.
    """
    shaped = "sk" + "-" + ("A" * 32)
    out = _reason_out("token " + shaped)
    assert shaped not in out, out
    assert "redacted" in out.lower(), out


def test_the_whole_emitted_tree_is_a_fixed_point():
    """Not just the field this test file drives: re-sanitising the emitted artifact must
    change nothing anywhere in it, which is what "the boundary was applied to the tree"
    means as opposed to "to the key I remembered"."""
    tree = _packet_with_reason("a\nb")
    assert json.dumps(_sanitize_tree(tree), sort_keys=True) == json.dumps(tree, sort_keys=True)


# ------------------------------------------------------- and is inert on real content

@pytest.mark.parametrize("fixture", ["home_vuln", "home_safe"])
def test_a_real_packet_carries_no_redaction_marker(fixture):
    """The inertness control. A boundary that mangles legitimate content would show up as
    redaction markers appearing in an ordinary packet; measured against the pre-change tree
    these two fixtures are byte-identical, and this is the part of that measurement a test
    can carry forward."""
    ctx = collect(str(REPO_ROOT / "fixtures" / fixture))
    findings = run_all(ctx)
    emitted = render_judge_packet_json(ctx, findings, version="t",
                                       score=compute(findings, ctx))
    assert "<redacted>" not in emitted
    assert json.loads(emitted)["judgePacket"], "vacuous: this fixture produced no items"


# --------------------------------------------------------------------- the census

def _module_level_functions():
    tree = ast.parse(_ADJUDICATION_SRC)
    return [n for n in tree.body if isinstance(n, ast.FunctionDef)]


def test_no_emitter_bypasses_the_helper():
    """A census, not a list of call sites. Four emitters each remembering to sanitise is
    four chances to diverge -- which is precisely the shape of B-689, one module over."""
    offenders = []
    for fn in _module_level_functions():
        if fn.name == "_emit_json":
            continue
        for node in ast.walk(fn):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "dumps"
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "json"):
                offenders.append((fn.name, node.lineno))
    assert not offenders, offenders


def test_every_public_json_renderer_returns_through_the_helper():
    """The other direction: a new `render_*_json` that builds its own string, or returns a
    bare payload, would pass the test above by never calling `json.dumps` at all."""
    renderers = [fn for fn in _module_level_functions()
                 if fn.name.startswith("render_") and fn.name.endswith("_json")]
    assert len(renderers) >= 4, [fn.name for fn in renderers]
    for fn in renderers:
        returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value is not None]
        assert returns, fn.name
        for ret in returns:
            assert isinstance(ret.value, ast.Call), (fn.name, ret.lineno)
            assert isinstance(ret.value.func, ast.Name), (fn.name, ret.lineno)
            assert ret.value.func.id == "_emit_json", (fn.name, ret.lineno, ret.value.func.id)


def test_the_helper_is_the_one_the_module_actually_exports():
    """Guards the guard: if `_emit_json` were renamed or shadowed, the AST checks above
    would still pass against a function that no longer sanitises anything."""
    out = _emit_json({"k": "a\nb"})
    assert json.loads(out)["k"] == "a b", out
