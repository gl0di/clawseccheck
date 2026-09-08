"""B-639 / B-640 — two false-positive FAILs narrowed in clawseccheck/skillast.py.

B-639: GETATTR_INDIRECTION's literal-attribute branch, and DYNAMIC_IMPORT_EXEC,
matched on a dangerous-shaped NAME ("run"/"call"/"system"/...) alone, with no check
that the base object/module was actually dangerous — so an ordinary plugin
dispatch table (`getattr(handler, "run")(x)`) or a dynamic plugin loader
(`importlib.import_module(plugin_name).run(x)`) FAILed identically to
`getattr(os, "system")(x)`.

B-640: OBFUSCATED_EXEC treated any bare `.decode(...)` as "hidden payload
execution", so the canonical `setup.py` idiom (`exec(fh.read().decode("utf-8"),
about)` reading a sibling `__version__.py`) FAILed identically to a base64-decoded
payload.

Both fixes NARROW a FAIL. Every case below is asserted in BOTH directions: the
named false positives must no longer FAIL, and every true-positive control named
in the task brief must still FAIL (or, for DYNAMIC_IMPORT_EXEC, must not be
silenced -- downgraded to 'info', which still surfaces via B91 and still
escalates alongside a cred/exfil signal, never dropped outright).
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python


def _rules(src):
    return {f.rule for f in analyze_python(src, "t.py")}


def _by_rule(src):
    return {f.rule: f for f in analyze_python(src, "t.py")}


def _crit_rules(src):
    return {f.rule for f in analyze_python(src, "t.py") if f.severity == "crit"}


# ---------------------------------------------------------------------------
# B-639 — getattr literal branch
# ---------------------------------------------------------------------------


def test_getattr_plugin_dispatch_run_is_not_flagged():
    src = (
        "def dispatch(name, payload):\n"
        "    handler = REGISTRY[name]()\n"
        '    if hasattr(handler, "run"):\n'
        '        return getattr(handler, "run")(payload)\n'
        '    return getattr(handler, "call")(payload)\n'
    )
    assert "GETATTR_INDIRECTION" not in _rules(src)


def test_getattr_plugin_dispatch_execute_still_clean():
    # The rule was already selective for these -- must stay clean (regression guard).
    src = 'def dispatch(h, p):\n    return getattr(h, "execute")(p)\n'
    assert "GETATTR_INDIRECTION" not in _rules(src)
    src2 = 'def dispatch(h, p):\n    return getattr(h, "start")(p)\n'
    assert "GETATTR_INDIRECTION" not in _rules(src2)


def test_getattr_os_system_true_positive_still_fails():
    src = 'def run(p):\n    return getattr(os, "system")(p)\n'
    by = _by_rule(src)
    assert "GETATTR_INDIRECTION" in by
    assert by["GETATTR_INDIRECTION"].severity == "crit"


# ---------------------------------------------------------------------------
# B-639 — DYNAMIC_IMPORT_EXEC (the same defect, module-name side)
# ---------------------------------------------------------------------------


def test_dynamic_import_to_ordinary_module_is_not_fail_capable():
    src = 'import importlib\ndef run(p):\n    return importlib.import_module("a.b").run(1)\n'
    by = _by_rule(src)
    # Downgraded, not silenced: still visible for B91 / cred-exfil escalation.
    assert by["DYNAMIC_IMPORT_EXEC"].severity == "info"
    assert "DYNAMIC_IMPORT_EXEC" not in _crit_rules(src)


def test_dynamic_import_plugin_loader_shape_is_not_fail_capable():
    src = (
        "import importlib\n"
        "def dispatch(plugin_name, x):\n"
        "    return importlib.import_module(plugin_name).run(x)\n"
    )
    assert "DYNAMIC_IMPORT_EXEC" not in _crit_rules(src)


def test_dynamic_import_os_true_positive_still_fails():
    src = 'import importlib\ndef run(x):\n    return importlib.import_module("os").system(x)\n'
    by = _by_rule(src)
    assert by["DYNAMIC_IMPORT_EXEC"].severity == "crit"


def test_dunder_import_os_true_positive_still_fails():
    # The literal __import__("os").system(...) shape named in the module's own docstring.
    src = '__import__("os").system("whoami")\n'
    by = _by_rule(src)
    assert by["DYNAMIC_IMPORT_EXEC"].severity == "crit"


# ---------------------------------------------------------------------------
# B-640 — OBFUSCATED_EXEC / .decode("utf-8") on a local sibling-file read
# ---------------------------------------------------------------------------

_SETUP_PY_SHAPE = (
    "import os\n"
    "here = os.path.abspath(os.path.dirname(__file__))\n"
    "about = {}\n"
    'with open(os.path.join(here, "demo_plugin", "__version__.py"), "rb") as fh:\n'
    '    exec(fh.read().decode("utf-8"), about)\n'
)


def test_setup_py_sibling_version_read_is_not_fail_capable():
    assert "OBFUSCATED_EXEC" not in _crit_rules(_SETUP_PY_SHAPE)


def test_setup_py_shape_direct_chain_no_with_statement():
    src = (
        "import os\n"
        "def load():\n"
        '    return open(os.path.join(os.path.dirname(__file__), "v.py"), "rb").read().decode("utf-8")\n'
        "exec(load(), {})\n"
    )
    assert "OBFUSCATED_EXEC" not in _crit_rules(src)


def test_dropper_absolute_path_still_fails():
    # The exact shape B-640's fix must NOT create a hole for: a decoded read from a
    # path with no relation to the artifact being scanned.
    src = 'with open("/tmp/dropped.py", "rb") as fh:\n    exec(fh.read().decode("utf-8"), {})\n'
    by = _by_rule(src)
    assert by["OBFUSCATED_EXEC"].severity == "crit"


def test_dropper_absolute_path_assign_form_still_fails():
    src = 'fh = open("/tmp/dropped.py", "rb")\nexec(fh.read().decode("utf-8"), {})\n'
    by = _by_rule(src)
    assert by["OBFUSCATED_EXEC"].severity == "crit"


def test_relative_non_dunder_file_path_still_fails():
    # Relative but NOT anchored on __file__ -- stays conservative (still convicted).
    src = 'with open("config.py", "rb") as fh:\n    exec(fh.read().decode("utf-8"), {})\n'
    by = _by_rule(src)
    assert by["OBFUSCATED_EXEC"].severity == "crit"


def test_cross_function_handle_name_collision_still_convicts():
    # The scope-resolution control: an UNRELATED function reusing the same handle
    # name `fh` for a genuinely dangerous path must not be laundered by a sibling
    # function's own __file__-anchored read.
    src = (
        "import os\n"
        "def safe_reader():\n"
        "    here = os.path.dirname(__file__)\n"
        '    with open(os.path.join(here, "v.py")) as fh:\n'
        "        return fh.read()\n"
        "def evil(malicious_path, ns):\n"
        '    with open(malicious_path, "rb") as fh:\n'
        '        exec(fh.read().decode("utf-8"), ns)\n'
    )
    by = _by_rule(src)
    assert by["OBFUSCATED_EXEC"].severity == "crit"


def test_base64_decode_true_positive_still_fails():
    src = "import base64\ndef run(payload):\n    exec(base64.b64decode(payload))\n"
    by = _by_rule(src)
    assert by["OBFUSCATED_EXEC"].severity == "crit"


def test_urlopen_decode_true_positive_still_fails():
    src = (
        "from urllib.request import urlopen\n"
        "def run(url):\n"
        "    exec(urlopen(url).read().decode())\n"
    )
    by = _by_rule(src)
    assert by["OBFUSCATED_EXEC"].severity == "crit"
