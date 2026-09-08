"""Every evidence line that leads with a skill name must use a separator the attribution
understands.

C-453. The bundled-skill attribution in `checks/_mcp.py` rewrites a finding's leading
`"<bare name>"` token to the plugin-relative path, so two bundled skills sharing a basename
cannot derive the same judge target. It recognises the separator between the name and the
rest of the line from a hand-kept list, and that list has now been wrong three times:

* `": "` only                 — the original; missed everything else.
* `" ("` added (B-614 C-135)  — `checks/_content.py`'s B66/B156 prose scanners. Until then a
  single DANGEROUS judge verdict escalated two different bundled skills, reproduced end to
  end through the real CLI.
* `" ["` added (round 2)      — `check_instruction_hierarchy_override` (B64) tags a language,
  `f'{source_name} [{lang}]: "{snippet}"'`. B64 is on `SKILL_CONTENT_RING`, so it rides the
  ring exactly like the other two.

Each time the list was extended by someone finding one more producer by hand. This guard
inverts that: it reads the producers and requires the LIST to cover them, so a fourth
convention fails the build on the commit that introduces it rather than on the day someone
happens to look.

Why the fixture corpus cannot do this job. Measured 2026-08-24 by running `vet_skill` over
all 292 fixture skill directories: 341 findings, 734 evidence lines, 209 leading with the
skill name — `": "` 207, `" ("` 2, `" ["` **zero**. A property test that builds its own input
can only cover the shapes someone thought of, which is precisely how the third convention
survived two rounds of review. This guard reads code, so it does not depend on the corpus
containing an example.

Three things the next person to touch this will otherwise rediscover the hard way.

**Why the separator list is IMPORTED and must not be copied here.** A test that *iterates* a
list imported from the module it guards is vacuous: the list is the domain of the sweep, so
deleting an entry deletes what gets checked and the mutant passes. That is a real defect and
it happened in this feature's own tests. This guard is the opposite direction — the list is
the SUBJECT and the producers in source are the domain, so shrinking the list makes three
B64 sites unknown and turns this red. Measured: dropping `" ["` yields exactly the 3 sites,
dropping `" ("` as well yields 5. A second hand-written copy here could drift from the
runtime list, and then this guard would be green while the attribution was holed.
Rule of thumb: **import when shrinking the list should break the test; declare it in the test
when shrinking it would make the test vacuous.**

**A leading `': "'` is NOT a fourth convention.** It starts with `": "`. Classifying by "the
first one-to-three non-word characters" says otherwise and produces 21 phantom conventions —
the first draft of this guard did exactly that. Classify with `startswith` against the known
separators, never by slicing punctuation.

**`checks/_vet.py` holds a SECOND consumer of the same assumption, and that one moves a
verdict.** `_prefix = f"{name}:"` feeds `_has_other_signal`, which decides between
"the skill's own declared purpose" (WARN) and `high.append(evidence)` (HIGH FAIL). A
language-tagged line does not start with `f"{name}:"`, so the check would read "no other
signal" while a critical one sits in the bucket. It is latent only because all **18**
producers appending a name-prefixed line into `crit`/`high` in that file use `": "` —
verified by enumeration, not by assumption. Fixing the attribution alone would leave this,
which is exactly how one repair creates the impression that a class is closed.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from clawseccheck.checks._mcp import _BUNDLED_EVIDENCE_SEPARATORS

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "clawseccheck"

# The variables that hold a scanned subject's own name. Deliberately narrow: a broader
# pattern pulls in env-var names, function names and directory names, which is most of what
# the registry below has to excuse.
_NAME_VARS = re.compile(r"(^|_|\.)(name|skill_name|source_name)$", re.I)

# Collections whose contents become a Finding's evidence.
_EVIDENCE_SINKS = re.compile(
    r"(^|_)(ev|evidence|crit|high|hits|warns?|fail_ev|warn_ev|persist_warn|out|rows|lines)"
    r"([0-9_]|$)",
    re.I,
)

#: Sites the scan reaches whose leading substitution is NOT a scanned subject's name. Each
#: was read before being listed; a real producer parked here would be the guard writing its
#: own excuse. `test_no_registered_exception_is_stale` deletes the list's ability to rot.
#: Keys are matched with a plain `startswith` against the literal EXACTLY as it appears in
#: source — leading space included. An earlier draft matched leniently here and strictly in
#: the staleness control, so the two disagreed and the lenient half would have excused
#: entries the strict half said did not exist. One rule, or the registry lies.
_NOT_A_SUBJECT_NAME = {
    ("checks/_config.py", " is on ("): "env var name — `f\"{name} is on ({path})\"`, B190",
    ("checks/_egress.py", " is on ("): "env var name, dotenv_override(ctx, name)",
    ("checks/_egress.py", " is set ("): "env var name from _B190_VALUE_VARS",
    ("checks/_content.py", "<->"): "synthetic boundary label `f\"{a_name}<->{b_name}\"`",
    ("checks/_mcp.py", "/hooks.json: "): "connector DIRECTORY name in a path, not a skill",
    ("skillast.py", "() runs a non-literal command"): "function name (exec_name), not a skill",
}


def _is_name_var(node) -> bool:
    if isinstance(node, ast.Name):
        return bool(_NAME_VARS.search(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_NAME_VARS.search(node.attr))
    return False


def _sink_name(node, parents) -> str | None:
    """The collection this expression is appended/extended into, if any."""
    cur = parents.get(id(node))
    while cur is not None:
        if (
            isinstance(cur, ast.Call)
            and isinstance(cur.func, ast.Attribute)
            and cur.func.attr in ("append", "extend")
        ):
            recv = cur.func.value
            return recv.id if isinstance(recv, ast.Name) else getattr(recv, "attr", "")
        cur = parents.get(id(cur))
    return None


def _leading_evidence_literals():
    """`(relpath, lineno, literal)` per f-string that opens with a subject name and lands in
    an evidence collection."""
    out = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[id(child)] = node
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr) or len(node.values) < 2:
                continue
            head, tail = node.values[0], node.values[1]
            if not (isinstance(head, ast.FormattedValue) and _is_name_var(head.value)):
                continue
            if not (isinstance(tail, ast.Constant) and isinstance(tail.value, str)):
                continue
            sink = _sink_name(node, parents)
            if not (sink and _EVIDENCE_SINKS.search(sink)):
                continue
            out.append((str(path.relative_to(PACKAGE)), node.lineno, tail.value))
    return out


def _registered(relpath: str, literal: str):
    """Exactly the predicate `test_no_registered_exception_is_stale` uses — see the note on
    the registry. Two matching rules for one registry is how an exception outlives its
    subject."""
    for (reg_path, reg_lit), reason in _NOT_A_SUBJECT_NAME.items():
        if relpath.endswith(reg_path) and literal.startswith(reg_lit):
            return reason
    return None


def _unknown_convention_sites():
    out = []
    for relpath, lineno, literal in _leading_evidence_literals():
        if any(literal.startswith(sep) for sep in _BUNDLED_EVIDENCE_SEPARATORS):
            continue
        if _registered(relpath, literal):
            continue
        out.append((relpath, lineno, literal))
    return out


def test_every_evidence_prefix_uses_a_separator_the_attribution_understands():
    """A producer the attribution cannot parse silently defeats bundled-skill disambiguation.

    The consequence is not cosmetic: `adjudication._target_from_evidence` partitions on
    `": "`, so an unrewritten line yields a target shared by every bundled skill with that
    basename, and `_parse_verdicts` keys its map on `(finding_id, target)`.
    """
    wrong = [
        f"{relpath}:{lineno} opens an evidence line with a subject name followed by "
        f"{literal[:40]!r} — not a separator `_BUNDLED_EVIDENCE_SEPARATORS` understands, so "
        f"the bundled-skill attribution will pass it through unrewritten"
        for relpath, lineno, literal in _unknown_convention_sites()
    ]
    assert not wrong, (
        "evidence-prefix conventions the attribution cannot parse:\n  " + "\n  ".join(wrong)
    )


def test_the_scan_is_not_vacuous():
    """The load-bearing control. If `_NAME_VARS` or `_EVIDENCE_SINKS` ever stops matching,
    every assertion above passes over an empty list and this guard silently stops guarding —
    which is the failure it exists to prevent, one level up."""
    sites = _leading_evidence_literals()
    assert len(sites) > 80, f"the producer scan found only {len(sites)} sites — predicate broke"
    seps = {
        sep
        for _p, _l, lit in sites
        for sep in _BUNDLED_EVIDENCE_SEPARATORS
        if lit.startswith(sep)
    }
    assert seps == set(_BUNDLED_EVIDENCE_SEPARATORS), (
        f"the scan sees {sorted(seps)} but the attribution lists "
        f"{sorted(_BUNDLED_EVIDENCE_SEPARATORS)} — a listed separator no longer has a "
        "producer the scan can see, so the scan and the list have drifted apart"
    )


def test_the_guard_bites_on_a_fourth_convention():
    """Guard the guard. Pinned as source text: pointing at the live tree would stop
    exercising anything the moment the tree is clean."""
    planted = ast.parse(
        'def scan(name, blob):\n'
        '    ev = []\n'
        '    ev.append(f"{name} <<{blob}>>: something happened")\n'
        '    return ev\n'
    )
    parents = {}
    for node in ast.walk(planted):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    found = [
        n.values[1].value
        for n in ast.walk(planted)
        if isinstance(n, ast.JoinedStr)
        and isinstance(n.values[0], ast.FormattedValue)
        and _is_name_var(n.values[0].value)
        and isinstance(n.values[1], ast.Constant)
        and _EVIDENCE_SINKS.search(_sink_name(n, parents) or "")
    ]
    assert found, "the scan cannot see a planted producer"
    assert not any(found[0].startswith(s) for s in _BUNDLED_EVIDENCE_SEPARATORS), (
        "the planted convention must be unknown, or this control proves nothing"
    )


def test_no_registered_exception_is_stale():
    """An entry that no longer matches anything must be deleted, not left to excuse the next
    producer that happens to land on the same literal."""
    literals = [(p, lit) for p, _l, lit in _leading_evidence_literals()]
    stale = sorted(
        key for key in _NOT_A_SUBJECT_NAME
        if not any(p.endswith(key[0]) and lit.startswith(key[1]) for p, lit in literals)
    )
    assert not stale, f"registered exceptions that match nothing any more: {stale}"
