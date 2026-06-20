"""Unit tests for the read-only Python AST analyzer (clawseccheck/skillast.py).

The analyzer parses with stdlib `ast` (parse only — never compile/exec) and flags
malware-grade obfuscation as 'crit' while leaving ordinary shell sinks as 'info'.
All offline, deterministic.
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python


def _rules(src):
    return {f.rule for f in analyze_python(src, "t.py")}


def _by_rule(src):
    return {f.rule: f for f in analyze_python(src, "t.py")}


# ---------------------------------------------------------------------------
# crit (malware-grade) detections
# ---------------------------------------------------------------------------

def test_obfuscated_exec_inline_decode():
    src = 'import base64\nexec(base64.b64decode("eA=="))\n'
    assert "OBFUSCATED_EXEC" in _rules(src)
    assert _by_rule(src)["OBFUSCATED_EXEC"].severity == "crit"


def test_obfuscated_exec_via_tainted_variable():
    src = 'import base64\np = base64.b64decode("eA==")\nexec(p)\n'
    assert "OBFUSCATED_EXEC" in _rules(src)


def test_eval_of_decoded_is_crit():
    src = 'import codecs\neval(codecs.decode("eA", "hex"))\n'
    assert "OBFUSCATED_EXEC" in _rules(src)


def test_getattr_indirection_dynamic_name():
    src = 'import os\ngetattr(os, "sys" + "tem")("id")\n'
    assert "GETATTR_INDIRECTION" in _rules(src)


def test_getattr_indirection_dangerous_literal():
    src = 'import os\ngetattr(os, "system")("id")\n'
    assert "GETATTR_INDIRECTION" in _rules(src)


def test_getattr_safe_literal_not_flagged():
    # dynamic dispatch to a benign literal attribute is legitimate
    src = 'obj = object()\ngetattr(obj, "strip")()\n'
    assert "GETATTR_INDIRECTION" not in _rules(src)


def test_getattr_dynamic_dispatch_on_object_is_not_crit():
    # ordinary plugin/dispatch pattern: getattr(obj, runtime_name)() must NOT be crit
    src = 'def run(obj, name):\n    return getattr(obj, name)()\n'
    assert all(f.severity != "crit" for f in analyze_python(src, "t.py"))


def test_getattr_dynamic_on_dangerous_module_is_crit():
    src = 'import os\nfn = "system"\ngetattr(os, fn)("id")\n'
    assert _by_rule(src)["GETATTR_INDIRECTION"].severity == "crit"


def test_dynamic_import_exec():
    src = '__import__("os").system("whoami")\n'
    assert "DYNAMIC_IMPORT_EXEC" in _rules(src)


# ---------------------------------------------------------------------------
# info (escalate-only) detections — must NOT be 'crit'
# ---------------------------------------------------------------------------

def test_plain_subprocess_is_info_only():
    src = 'import subprocess\nsubprocess.run(["ls"])\n'
    by = _by_rule(src)
    assert "DANGEROUS_SINK" in by
    assert by["DANGEROUS_SINK"].severity == "info"
    assert all(f.severity != "crit" for f in analyze_python(src, "t.py"))


def test_os_system_is_info_only():
    src = 'import os\nos.system("ls")\n'
    assert _by_rule(src)["DANGEROUS_SINK"].severity == "info"


def test_marshal_loads_is_info():
    src = 'import marshal\nmarshal.loads(b"x")\n'
    assert _by_rule(src)["DESERIALIZE_CODE"].severity == "info"


def test_plain_exec_without_decode_is_info():
    src = 'exec("print(1)")\n'
    assert all(f.severity != "crit" for f in analyze_python(src, "t.py"))


# ---------------------------------------------------------------------------
# FP-safety: legitimate code produces no crit findings
# ---------------------------------------------------------------------------

def test_legit_argparse_subprocess_no_crit():
    src = (
        "import argparse, subprocess\n"
        "def main():\n"
        "    p = argparse.ArgumentParser()\n"
        "    subprocess.run(['echo', 'hi'], check=True)\n"
    )
    assert all(f.severity != "crit" for f in analyze_python(src, "t.py"))


def test_legit_env_plus_network_no_finding():
    # env -> network is exactly what naive taint would false-positive on; we don't
    # flag it (taint is deferred), and urlopen is not in our sink set.
    src = (
        "import os, urllib.request\n"
        "key = os.environ['API_KEY']\n"
        "urllib.request.urlopen('https://api.example.com')\n"
    )
    assert analyze_python(src, "t.py") == []


# ---------------------------------------------------------------------------
# robustness
# ---------------------------------------------------------------------------

def test_syntax_error_returns_empty():
    assert analyze_python("def (: not python", "broken.py") == []


def test_empty_source_returns_empty():
    assert analyze_python("", "e.py") == []


def test_findings_carry_line_numbers():
    src = '\n\nimport base64\nexec(base64.b64decode("eA=="))\n'
    f = next(x for x in analyze_python(src, "t.py") if x.rule == "OBFUSCATED_EXEC")
    assert f.lineno == 4


def test_never_executes_or_raises_on_hostile_input():
    # a module that *would* be dangerous if run must only be parsed, never executed
    src = 'import os\nos.system("rm -rf /tmp/should-not-run-xyz")\n'
    # the marker file must never appear; analyze just returns findings
    findings = analyze_python(src, "t.py")
    assert any(f.rule == "DANGEROUS_SINK" for f in findings)
