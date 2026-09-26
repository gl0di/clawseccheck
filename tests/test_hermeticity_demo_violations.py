"""Demo-only violating tests for the hermeticity gate's OWN regression tests --
``test_parent_side_read_violation_caught_same_invocation`` and
``test_parent_side_write_violation_caught_same_invocation`` in
``tests/test_hermeticity_gate.py``.

These two functions never run on their own. They are skipped unless ``CSC_HERM_DEMO``
is set, which only that meta-test's own ``subprocess.run`` sets, deliberately, in an
isolated child pytest invocation. Do not remove the skip guard: unguarded,
``test_demo_inprocess_open_violation`` reads real machine state
(``/etc/hostname``) and ``test_demo_inprocess_mkdir_violation`` writes into
``/var/tmp`` -- exactly the kind of undeclared machine dependency CLAUDE.md's testing
protocol ("Offline & read-only... write nothing outside pytest's tmp_path") forbids in
the default suite. They exist purely so the meta-test has a real, in-process (no
subprocess) filesystem call to prove the hermeticity ledger's PARENT half actually
catches -- see conftest.py's ``pytest_runtest_teardown`` for the fix these exercise.
"""
from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("CSC_HERM_DEMO"),
    reason="demo-only fixture for test_hermeticity_gate.py's own meta-test; "
           "never runs on its own",
)


def test_demo_inprocess_open_violation():
    """An in-process (no subprocess) READ-shaped event outside repo/tmp/interpreter
    roots -- classify() has nothing to bucket "/etc/hostname" as, so it is a
    read_violation once recorded."""
    with open("/etc/hostname"):
        pass


def test_demo_inprocess_mkdir_violation():
    """An in-process (no subprocess) WRITE-shaped event outside repo/tmp. A fresh,
    unique name per run avoids colliding with a leftover directory from an earlier
    interrupted run; removed immediately after (its own os.rmdir is a second
    WRITE-shaped event at the same path, which the ledger simply dedupes)."""
    target = os.path.join("/var/tmp", f"csc-herm-demo-mkdir-{uuid.uuid4().hex}")
    os.mkdir(target)
    os.rmdir(target)
