"""C-199 (SkillTrustBench T09 "insecure skill coding, no clear attack intent"):
ClawSecCheck is intent-driven and under-covers this quadrant — code that is
genuinely vulnerable but carries no exfil/malice signal of its own. Two WARN-only
additions, neither ever escalated to FAIL by its own rule:

  (a) shell-injection-prone subprocess/os.system shape (skillast.py's
      SHELL_INJECTION_RISK, wired into check_installed_skills / B13) — a
      subprocess.*(shell=True, ...) or bare os.system()/os.popen() call whose
      command is not a provable compile-time constant. Distinct from TT5_CMD_
      INJECTION (crit -> FAIL), which requires PROVEN external taint; this fires
      on the unsafe SHAPE alone, mirroring standard static-analysis practice
      (Bandit B602/B605).

  (b) insecure temp-file handling (checks/_vet.py's _insecure_tempfile_write_hits) —
      a hardcoded, predictable filename opened for write directly under /tmp
      (CWE-377): any other local process/user can pre-create that exact path
      before the skill writes to it. tempfile.mkstemp()/NamedTemporaryFile() are
      never flagged (they generate a random, collision-resistant name).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, WARN
from clawseccheck.checks import check_installed_skills
from clawseccheck.collector import Context
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(skills: dict[str, str]) -> Context:
    c = Context(home=Path("/nonexistent-c199"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = skills
    return c


def _md(body: str) -> str:
    return f"---\nname: t\ndescription: A test skill.\n---\n{body}\n"


# ---------------------------------------------------------------------------
# (a) shell-injection-prone subprocess/os.system shape — unit level (skillast.py)
# ---------------------------------------------------------------------------


def test_subprocess_shell_true_with_fstring_command_flags():
    src = (
        "import subprocess\n"
        "def run(user_input):\n"
        '    cmd = f"ls {user_input}"\n'
        "    subprocess.run(cmd, shell=True)\n"
    )
    rules = {f.rule for f in analyze_python(src, "t.py")}
    assert "SHELL_INJECTION_RISK" in rules


def test_os_system_string_concat_flags():
    src = "import os\ndef run(name):\n    os.system('echo ' + name)\n"
    rules = {f.rule for f in analyze_python(src, "t.py")}
    assert "SHELL_INJECTION_RISK" in rules


def test_argv_list_with_shell_true_still_flags():
    """shell=True makes even a list-form command shell-injection-prone (POSIX
    subprocess semantics: args[0] is still passed through the shell)."""
    src = 'import subprocess\ndef run(name):\n    subprocess.run(["ls", name], shell=True)\n'
    rules = {f.rule for f in analyze_python(src, "t.py")}
    assert "SHELL_INJECTION_RISK" in rules


def test_safe_argv_list_no_shell_does_not_flag():
    src = 'import subprocess\ndef run(user_input):\n    subprocess.run(["ls", user_input])\n'
    rules = {f.rule for f in analyze_python(src, "t.py")}
    assert "SHELL_INJECTION_RISK" not in rules


def test_fully_literal_shell_true_does_not_flag():
    """Zero-FP: shell=True with an entirely literal command has nothing an
    attacker could inject through."""
    src = 'import subprocess\nsubprocess.run("ls -la /tmp", shell=True)\n'
    rules = {f.rule for f in analyze_python(src, "t.py")}
    assert "SHELL_INJECTION_RISK" not in rules


def test_variable_bound_to_single_literal_shell_true_does_not_flag():
    src = 'import subprocess\nCMD = "ls -la"\nsubprocess.run(CMD, shell=True)\n'
    rules = {f.rule for f in analyze_python(src, "t.py")}
    assert "SHELL_INJECTION_RISK" not in rules


def test_split_produced_argv_no_shell_does_not_flag():
    """Regression guard: `name.split()` (a Call, not a List literal) with shell not
    True is a common, actually-safe idiom -- must not false-WARN just because the
    first arg isn't a syntactic list literal."""
    src = "import subprocess\ndef run(name):\n    subprocess.Popen(name.split())\n"
    rules = {f.rule for f in analyze_python(src, "t.py")}
    assert "SHELL_INJECTION_RISK" not in rules


def test_os_system_literal_does_not_flag():
    src = 'import os\nos.system("ls -la")\n'
    rules = {f.rule for f in analyze_python(src, "t.py")}
    assert "SHELL_INJECTION_RISK" not in rules


def test_bare_exec_eval_out_of_scope():
    """The dynamic-evaluation builtins are a different rule's territory (OBFUSCATED_EXEC
    etc.) -- this rule only covers subprocess/os.system shell interpretation."""
    src = 'def run(x):\n    exec(x)\n'
    rules = {f.rule for f in analyze_python(src, "t.py")}
    assert "SHELL_INJECTION_RISK" not in rules


# ---------------------------------------------------------------------------
# (a) integration through check_installed_skills / B13
# ---------------------------------------------------------------------------


def _mk_skill(root: Path, py_body: str) -> Path:
    """check_installed_skills only runs the AST engine over ctx.installed_skill_py,
    which is populated from real files by vet_skill()'s directory-walk — a hand-
    built Context with only .installed_skills set never reaches analyze_python."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(_md(""), encoding="utf-8")
    (root / "tool.py").write_text(py_body, encoding="utf-8")
    return root


def test_vet_shell_injection_risk_warns_not_fails(tmp_path):
    """Uses a module-level value derived from time.time() (not a function parameter
    or any other recognized external-taint source) so ONLY the new WARN-grade rule
    fires — isolating it from the existing crit TT5_CMD_INJECTION rule, which
    requires PROVEN external taint and would otherwise also fire and mask this
    test (verified empirically: a function-parameter-derived command triggers
    BOTH rules, since every function parameter is treated as externally tainted)."""
    from clawseccheck.checks import vet_skill

    d = _mk_skill(
        tmp_path / "risky-skill",
        "import subprocess\n"
        "import time\n"
        "SUFFIX = str(time.time())\n"
        'subprocess.run(f"ls /tmp/report-{SUFFIX}.txt", shell=True)\n',
    )
    f = vet_skill(d)
    assert f.status == WARN
    assert "shell-injection" in (f.detail or "").lower() or "shell-injection" in " ".join(
        f.evidence or []
    ).lower()
    assert f.status != FAIL


def test_vet_safe_subprocess_usage_stays_pass(tmp_path):
    from clawseccheck.checks import vet_skill

    d = _mk_skill(
        tmp_path / "safe-skill",
        "import subprocess\n"
        "def run(user_input):\n"
        '    subprocess.run(["ls", user_input])\n',
    )
    f = vet_skill(d)
    assert f.status == PASS


# ---------------------------------------------------------------------------
# (b) insecure temp-file handling — integration through check_installed_skills
# ---------------------------------------------------------------------------


def test_hardcoded_tmp_open_write_warns():
    blob = _md("") + 'open("/tmp/output.txt", "w").write("data")\n'
    f = check_installed_skills(_ctx({"tmp-writer": blob}))
    assert f.status == WARN
    assert any("temp-file" in e.lower() for e in (f.evidence or []))


def test_hardcoded_tmp_path_write_text_warns():
    blob = _md("") + 'from pathlib import Path\nPath("/tmp/cache.json").write_text(data)\n'
    f = check_installed_skills(_ctx({"tmp-writer2": blob}))
    assert f.status == WARN


def test_hardcoded_var_tmp_append_warns():
    blob = _md("") + 'open("/var/tmp/state.log", "a").write(line)\n'
    f = check_installed_skills(_ctx({"tmp-writer3": blob}))
    assert f.status == WARN


def test_tempfile_mkstemp_does_not_warn():
    blob = _md("") + "import tempfile\nfd, path = tempfile.mkstemp()\n"
    f = check_installed_skills(_ctx({"safe-tmp": blob}))
    assert f.status == PASS


def test_tempfile_named_temporary_file_does_not_warn():
    blob = _md("") + (
        "import tempfile\n"
        "with tempfile.NamedTemporaryFile() as fh:\n"
        "    fh.write(b'x')\n"
    )
    f = check_installed_skills(_ctx({"safe-tmp2": blob}))
    assert f.status == PASS


def test_readonly_tmp_open_does_not_warn():
    """Reading (not writing) a /tmp path is not the CWE-377 pattern -- no mode
    flag at all means open() defaults to read, never matched by the write-only
    regex."""
    blob = _md("") + 'data = open("/tmp/config.json").read()\n'
    f = check_installed_skills(_ctx({"tmp-reader": blob}))
    assert f.status == PASS


def test_tmp_write_in_fenced_doc_example_does_not_warn():
    blob = _md(
        '```python\nopen("/tmp/output.txt", "w").write("data")\n```\n'
        "Documented example above, not executed by this skill.\n"
    )
    f = check_installed_skills(_ctx({"doc-only": blob}))
    assert f.status == PASS


def test_tmp_write_never_escalates_to_fail_even_with_other_content():
    """Advisory doctrine: this rule alone never FAILs, even paired with other
    unrelated but still-benign content."""
    blob = _md("") + (
        'open("/tmp/a.txt", "w").write("x")\n'
        "def helper():\n"
        "    return 42\n"
    )
    f = check_installed_skills(_ctx({"multi": blob}))
    assert f.status != FAIL
