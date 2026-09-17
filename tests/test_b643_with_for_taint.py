"""Regression tests for CLAWSECCHECK-B-643.

`_external_tainted_names` (clawseccheck/skillast.py, feeds TT4/TT5/SSRF) propagated
taint through assignment, comprehension `for`, and walrus targets (B-414), but had NO
case at all for `ast.With`/`ast.AsyncWith` or for a statement-level `ast.For`/
`ast.AsyncFor` -- so `with open(p) as fh: exec(fh.read())`, the idiomatic form every
style guide recommends, silently never tainted `fh`, while the byte-identical
`fh = open(p); exec(fh.read())` did. Measured before the fix:

    with open(p) as fh: exec(fh.read())   ->  ['DANGEROUS_SINK']
    fh = open(p);        exec(fh.read())  ->  ['DANGEROUS_SINK', 'TT5_CMD_INJECTION']

Offline, deterministic. No network calls, no writes outside tmp_path.
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python


def _rules(src: str) -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, "t.py")}


# ---------------------------------------------------------------------------
# The ticket's own repro: `with` and the equivalent plain assignment must agree
# ---------------------------------------------------------------------------

def test_with_and_assignment_produce_the_same_rule_set():
    src_with = (
        "def run(p):\n"
        "    with open(p) as fh:\n"
        "        exec(fh.read())\n"
    )
    src_assign = (
        "def run(p):\n"
        "    fh = open(p)\n"
        "    exec(fh.read())\n"
    )
    with_rules = set(_rules(src_with))
    assign_rules = set(_rules(src_assign))
    assert with_rules == assign_rules, (with_rules, assign_rules)
    assert "TT5_CMD_INJECTION" in with_rules


def test_for_and_comprehension_produce_the_same_rule_set():
    """Sibling gap: a statement-level `for` over a tainted iterable, vs. the
    equivalent comprehension B-414 already covers."""
    src_for = (
        "import os\n"
        "import subprocess\n\n"
        'raw = os.environ.get("SKILL_BATCH_CMDS", "")\n'
        'cmds = raw.split(";")\n'
        "for c in cmds:\n"
        "    subprocess.run(c, shell=True)\n"
    )
    src_comp = (
        "import os\n"
        "import subprocess\n\n"
        'raw = os.environ.get("SKILL_BATCH_CMDS", "")\n'
        'cmds = raw.split(";")\n'
        "[subprocess.run(c, shell=True) for c in cmds]\n"
    )
    for_rules = set(_rules(src_for))
    comp_rules = set(_rules(src_comp))
    assert for_rules == comp_rules, (for_rules, comp_rules)
    assert "TT5_CMD_INJECTION" in for_rules


# ---------------------------------------------------------------------------
# Positive controls
# ---------------------------------------------------------------------------

def test_with_tuple_target_taints_both_names():
    """`with a() as (x, y):` -- Tuple/List unpacking, mirroring `_assign_target_names`."""
    src = (
        "import subprocess\n\n"
        "def run(spawn):\n"
        "    with spawn() as (cmd, env):\n"
        "        subprocess.run(cmd, shell=True)\n"
    )
    # `spawn` is a function parameter -- B-413 taints every parameter unconditionally,
    # so `spawn()`'s return is a tainted-source read via the visible-name predicate.
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


def test_async_with_taints_target():
    src = (
        "import subprocess\n\n"
        "async def run(p):\n"
        "    async with open(p) as fh:\n"
        "        subprocess.run(fh.read(), shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


def test_async_for_taints_target():
    src = (
        "import subprocess\n\n"
        "async def run(stream):\n"
        "    async for line in stream:\n"
        "        subprocess.run(line, shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r


# ---------------------------------------------------------------------------
# Negative controls -- a non-tainted source must NOT become tainted
# ---------------------------------------------------------------------------

def test_with_over_non_source_does_not_taint():
    """A `with` block over a context manager that is not one of the four documented
    taint sources (not a function param, not open/read/getenv/requests/input/a
    tool-result call) must not fire TT5 -- otherwise the fix trades a false negative
    for a false positive. (`open(...)` itself is ALWAYS a source regardless of the
    path argument being a literal -- pre-existing, unrelated to this fix -- so the
    negative control here uses a plainly unrelated helper instead.)"""
    src = (
        "import subprocess\n\n"
        "def make_resource():\n"
        '    return "fixed-command"\n\n'
        "def run():\n"
        "    with make_resource() as fh:\n"
        "        subprocess.run(fh, shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_with_lock_no_as_target_is_a_noop():
    """A bare `with lock:` (no `as` clause) binds nothing; must not crash and must
    not spuriously taint anything in the body."""
    src = (
        "import threading\n"
        "import subprocess\n\n"
        "lock = threading.Lock()\n\n"
        "def run(cmd):\n"
        "    with lock:\n"
        "        subprocess.run(cmd)\n"
    )
    r = _rules(src)
    # `cmd` is a function parameter (always tainted per B-413), independent of the
    # `with` block -- this only proves the bare `with` did not crash or misattribute.
    assert "TT5_CMD_INJECTION" in r


def test_for_over_literal_list_does_not_taint():
    src = (
        "import subprocess\n\n"
        "def run():\n"
        '    for c in ["/bin/ls", "/bin/pwd"]:\n'
        "        subprocess.run(c, shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
