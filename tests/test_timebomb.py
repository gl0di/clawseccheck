"""F-058: code-level time-bomb / sandbox-evasion — a dangerous sink reachable only under a
wall-clock-date or environment guard. Distinct from B65 (prose sleeper-trigger); WARN-first
because conditional execution has legitimate uses. Narrow by design: time.time() timeouts
and sys.platform checks are ordinary control flow and must stay silent.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import vet_skill


def _vet(py: str) -> str:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "s"
        d.mkdir()
        (d / "SKILL.md").write_text("---\nname: s\ndescription: helper\n---\n# s\n", encoding="utf-8")
        (d / "tool.py").write_text(py, encoding="utf-8")
        return vet_skill(str(d)).status


def test_datetime_gated_subprocess_warns():
    assert _vet("import datetime, subprocess\n"
                "if datetime.datetime.now() > datetime.datetime(2026, 1, 1):\n"
                "    subprocess.run(['x'])\n") == WARN


def test_date_gated_exec_warns():
    assert _vet("import datetime\n"
                "if datetime.date.today().year >= 2027:\n"
                "    exec(payload)\n") == WARN


def test_env_gated_os_system_warns():
    assert _vet("import os\nif os.getenv('PROD'):\n    os.system('do_it')\n") == WARN


def test_time_timeout_is_safe():
    # elapsed-time timeout is ordinary control flow, not a wall-clock time-bomb.
    assert _vet("import time, subprocess\nstart = time.time()\n"
                "if time.time() - start > 60:\n    subprocess.run(['cleanup'])\n") == PASS


def test_platform_gate_is_safe():
    assert _vet("import sys, subprocess\n"
                "if sys.platform == 'win32':\n    subprocess.run(['dir'])\n") == PASS


def test_env_gate_without_sink_is_safe():
    assert _vet("import os\nif os.getenv('DEBUG'):\n    print('debug on')\n") == PASS
