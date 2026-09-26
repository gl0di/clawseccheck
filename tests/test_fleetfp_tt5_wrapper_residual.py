"""Accepted §2.5 residual: TT5 configured-executable class, wrapper/table shape
(Dave ruling 2026-09-26 — folded into the existing TT5 configured-executable
residual; same root cause, see the retracted-fix note next to the argv[0] taint
check in skillast.py, `_subprocess_taint_is_command_injection`).

Real target: dynamo-interconnect-check
(~/.openclaw/agents/main/agent/codex-home/.tmp/plugins/plugins/nvidia/skills/
dynamo-interconnect-check/scripts/check_interconnect.py:121). Its `check_node()`
runs `run(prefix + argv)` inside a loop over a module-level command table
(`NODE_PROBES: list[tuple[str, list[str]]]`), with `prefix` built by a
same-module helper (`exec_prefix()`). Statically that is THE SAME vector as the
canonical TT5 true positive `subprocess.run([os.environ["C2_BIN"]])`: argv[0] is
not a literal at the call site, and no source-level table or helper binding can
be proven fixed without whole-program analysis (a dedicated resolver on branch
fix/fleetfp-argv0-resolver went through four C-135 rounds — a for-target/with-as/
subscript-augassign rebind bypass, a globals()/setattr/exec table-rebind bypass,
and a `__globals__`-omission bypass of the fix for that — and was dropped,
never merged).

Verdict does NOT change: the reduced benign shape below still stays
CRITICAL/FAIL, exactly like the configured-executable (env/CLI-derived) case in
tests/test_fleetfp_tt5_configured_executable_residual.py. This test module only
pins that the wrapper/table shape is (a) still convicted and (b) covered by the
widened disclosure text, without touching `detail` or the fingerprint manifest.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL
from clawseccheck.checks import vet_skill
from clawseccheck.skillast import analyze_python

# Present in the ORIGINAL configured-executable disclosure sentence too — the
# widened text keeps this substring intact so existing
# .clawseccheckignore-adjacent expectations and the sibling test file's mark
# both still match.
DISCLOSURE_MARK = "operator-configured executable path from an attacker-chosen one"

# New, wrapper/table-specific fragment added by the widened disclosure.
WRAPPER_DISCLOSURE_MARK = "module-level command table and a same-module prefix helper"

# Minimal replica of the real dynamo-interconnect-check shape: a `run()` sink
# wrapper, a same-module `exec_prefix()` prefix helper, a module-level command
# table, and a loop that composes argv as `prefix + argv` before calling the
# sink. No env/CLI-derived value anywhere -- purely a table/helper composition.
WRAPPER_TABLE_SRC = (
    "import subprocess\n"
    "\n"
    "\n"
    "def run(cmd, timeout=20):\n"
    "    return subprocess.run(\n"
    "        cmd, capture_output=True, timeout=timeout, check=False\n"
    "    )\n"
    "\n"
    "\n"
    "def exec_prefix(pod):\n"
    "    return ['kubectl', 'exec', pod, '--']\n"
    "\n"
    "\n"
    "NODE_PROBES = [\n"
    "    ('ib-devices', ['ls', '/dev/infiniband']),\n"
    "    ('ibv-devinfo', ['ibv_devinfo', '-l']),\n"
    "]\n"
    "\n"
    "\n"
    "def check_node(pod):\n"
    "    prefix = exec_prefix(pod) if pod else []\n"
    "    for name, argv in NODE_PROBES:\n"
    "        run(prefix + argv)\n"
)


def _skill(tmp_path: Path, name: str, py_body: str) -> str:
    root = tmp_path / name
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: d\n---\n\nSee scripts/run.py.\n",
        encoding="utf-8",
    )
    (root / "scripts" / "run.py").write_text(py_body, encoding="utf-8")
    for p in root.rglob("*"):
        if p.is_file():
            p.chmod(0o644)
    return str(root)


# ---------------------------------------------------------------------------
# Unit level: the AST rule still convicts the wrapper/table shape (unresolved,
# not falsely cleared).
# ---------------------------------------------------------------------------


def test_wrapper_table_shape_still_convicts_tt5():
    rules = {f.rule: f for f in analyze_python(WRAPPER_TABLE_SRC, "run.py")}
    assert "TT5_CMD_INJECTION" in rules
    assert rules["TT5_CMD_INJECTION"].severity == "crit"


# ---------------------------------------------------------------------------
# End-to-end: vet_skill() on a real skill directory, widened disclosure routing.
# ---------------------------------------------------------------------------


def test_wrapper_table_shape_end_to_end_fails_with_widened_disclosure(tmp_path: Path):
    p = _skill(tmp_path, "wrapper-table-argv", WRAPPER_TABLE_SRC)
    f = vet_skill(p)
    assert f.status == FAIL
    assert f.severity == CRITICAL
    assert DISCLOSURE_MARK in f.fix
    assert WRAPPER_DISCLOSURE_MARK in f.fix
    assert DISCLOSURE_MARK not in f.detail
    assert WRAPPER_DISCLOSURE_MARK not in f.detail


def test_configured_executable_disclosure_still_present_alongside_widened_text(
    tmp_path: Path,
):
    """The env/CLI-derived (non-wrapper) configured-executable shape from the
    sibling residual test keeps getting the SAME disclosure sentence, now also
    carrying the wrapper/table fragment (one sentence, unconditioned either
    way — no sound static rule tells the two shapes apart from an attacker's
    twin, exactly like the original residual's own reasoning)."""
    env_derived_src = (
        "import os\n"
        "import subprocess\n"
        "\n"
        "\n"
        "def run():\n"
        "    subprocess.run([os.environ['C2_BIN']])\n"
    )
    p = _skill(tmp_path, "env-derived-argv", env_derived_src)
    f = vet_skill(p)
    assert f.status == FAIL
    assert f.severity == CRITICAL
    assert DISCLOSURE_MARK in f.fix
    assert WRAPPER_DISCLOSURE_MARK in f.fix
