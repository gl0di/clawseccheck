"""C-202: decode->exec generalization past inline base64.

The pre-existing OBFUSCATED_EXEC rule only saw a decode primitive written inline in
the exec/eval argument (or a variable assigned directly from one). Real malicious
skills route the decoded payload through a local `_decode()`-style helper first,
sometimes layering xor/zlib/hex, sometimes chaining a second helper -- all of which
evaded the inline-only check. This suite locks in the wrapper-indirection fix and
proves it doesn't over-trigger on a decode helper that never reaches exec/eval.
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python


def _rules(src: str) -> set[str]:
    return {f.rule for f in analyze_python(src, "t.py")}


def _crit_rules(src: str) -> set[str]:
    return {f.rule for f in analyze_python(src, "t.py") if f.severity == "crit"}


def test_exec_of_local_decode_wrapper_flags():
    src = (
        "import base64\n"
        "def _decode(x):\n"
        "    return base64.b64decode(x)\n"
        'exec(_decode("eA=="))\n'
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_exec_of_xor_decode_wrapper_flags():
    src = (
        "def _decode(x):\n"
        "    return bytes(b ^ 0x42 for b in x)\n"
        "exec(_decode(blob))\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_exec_of_layered_zlib_base64_wrapper_flags():
    src = (
        "import base64, zlib\n"
        "def _decode(x):\n"
        "    return zlib.decompress(base64.b64decode(x))\n"
        "exec(_decode(blob))\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_exec_of_chained_two_stage_wrapper_flags():
    # `_decode` has no decode primitive of its own -- it only calls `_step2`, which
    # does the actual base64 work. Must resolve transitively (multi-stage wrapper).
    src = (
        "import base64\n"
        "def _step2(b):\n"
        "    return base64.b64decode(b)\n"
        "def _decode(x):\n"
        "    return _step2(x)\n"
        "exec(_decode(blob))\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_assign_from_wrapper_then_exec_flags():
    # payload = _decode(blob); exec(payload) -- the _tainted_names path, not the
    # direct-argument path.
    src = (
        "import base64\n"
        "def _decode(x):\n"
        "    return base64.b64decode(x)\n"
        "payload = _decode(blob)\n"
        "exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_compile_of_wrapper_then_exec_flags():
    # exec(compile(_decode(blob), "<runtime>", "exec"), {}) -- the real-world
    # case_01307/case_03133 shape (watchdog-style runtime loader).
    src = (
        "import base64\n"
        "def _decode(x):\n"
        "    return base64.b64decode(x)\n"
        'exec(compile(_decode(blob), "<runtime>", "exec"), {})\n'
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_method_style_wrapper_not_flagged():
    # self._decode(...) -- deliberately NOT matched. Composing-function resolution is
    # scoped to module-level bare-name calls only; see the C-135 collision tests below
    # for why method/attribute matching was dropped.
    src = (
        "import base64\n"
        "class Loader:\n"
        "    def _decode(self, x):\n"
        "        return base64.b64decode(x)\n"
        "    def run(self, blob):\n"
        "        exec(self._decode(blob))\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


# ---------------------------------------------------------------------------
# C-135 adversarial-review regressions: name-collision false positives found against
# the first version of this fix (method names matched by bare string with no
# receiver/scope resolution). All four must stay silent permanently.
# ---------------------------------------------------------------------------

def test_c135_unrelated_method_named_resolve_not_flagged():
    # PathBuilder.resolve() does an ordinary os.path.join(); TemplateEngine.resolve()
    # is an unrelated trusted lookup whose result reaches exec(). Sharing the name
    # "resolve" must not cross-contaminate.
    src = (
        "import os\n"
        "class PathBuilder:\n"
        "    def resolve(self, base, name):\n"
        "        return os.path.join(base, name)\n"
        "class TemplateEngine:\n"
        "    def __init__(self):\n"
        "        self._templates = {'greet': \"print('hi')\"}\n"
        "    def resolve(self, template_name):\n"
        "        return self._templates[template_name]\n"
        "    def render(self, template_name, context):\n"
        "        code = self.resolve(template_name)\n"
        "        exec(code, context)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_c135_transitive_method_chain_via_decode_not_flagged():
    # ConfigChain.load() -> _step_b -> _step_c -> _step_d does an ordinary
    # bytes.decode('utf-8') on a local log file. RuleEngine.load() is unrelated and
    # feeds eval(). Must not correlate.
    src = (
        "class ConfigChain:\n"
        "    def load(self):\n"
        "        return self._step_b()\n"
        "    def _step_b(self):\n"
        "        return self._step_c()\n"
        "    def _step_c(self):\n"
        "        return self._step_d()\n"
        "    def _step_d(self):\n"
        "        with open('app.log', 'rb') as fh:\n"
        "            raw = fh.read()\n"
        "        return raw.decode('utf-8')\n"
        "class RuleEngine:\n"
        "    def load(self, rule_source):\n"
        "        return 'True' if rule_source == 'default' else rule_source\n"
        "    def evaluate(self, rule_source):\n"
        "        rule = self.load(rule_source)\n"
        # eval() here is test DATA proving a name-collision false positive does NOT
        # fire -- this module never calls eval, only feeds source strings to
        # analyze_python()'s read-only parser.
        "        return eval(rule)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_c135_join_method_name_collision_not_flagged():
    # PathTool.compose() is "/".join(); RuleEngine.compose() is unrelated and feeds
    # eval(). Must not correlate.
    src = (
        "class PathTool:\n"
        "    def compose(self, parts):\n"
        "        return '/'.join(parts)\n"
        "class RuleEngine:\n"
        "    def compose(self, rule_name):\n"
        "        return 'True' if rule_name == 'always' else 'False'\n"
        "    def evaluate(self, rule_name):\n"
        "        return eval(self.compose(rule_name))\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_c135_decode_in_dead_branch_not_flagged():
    # Round 2: a decode call sitting in a discarded/dead branch, whose result never
    # reaches the function's return value, must not taint the whole function name.
    src = (
        "import base64\n"
        "def build(debug=False):\n"
        "    if debug:\n"
        "        base64.b64decode(b'x')\n"
        "    return 'class Stub: pass'\n"
        "exec(build())\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_c135_decode_in_nested_closure_never_returned_not_flagged():
    # Round 2: a decode call inside a NESTED closure whose result is only logged
    # (never returned by the closure, and the closure itself is never returned by the
    # outer function) must not taint the outer function.
    src = (
        "import base64\n"
        "def build_stub():\n"
        "    def _debug_peek(x):\n"
        "        print(base64.b64decode(x))\n"
        "    _debug_peek(b'eA==')\n"
        "    return 'class Stub: pass'\n"
        "exec(build_stub())\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_c135_parameter_shadowing_composing_name_not_flagged():
    # Round 3: `run`'s own parameter is ALSO named `_decode` -- it shadows the
    # module-level wrapper for run()'s entire body. The exec'd value has zero causal
    # connection to base64.b64decode.
    src = (
        "import base64\n"
        "def _decode(x):\n"
        "    return base64.b64decode(x)\n"
        "def run(_decode):\n"
        "    cmd = _decode('safe_cmd')\n"
        "    exec(cmd)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_c135_nested_def_shadowing_composing_name_not_flagged():
    # Round 3: a nested closure inside `run` redefines `_decode` locally.
    src = (
        "import base64\n"
        "def _decode(x):\n"
        "    return base64.b64decode(x)\n"
        "def run():\n"
        "    def _decode(y):\n"
        "        return y.upper()\n"
        "    cmd = _decode('safe_cmd')\n"
        "    exec(cmd)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_c135_local_rebind_shadowing_composing_name_not_flagged():
    # Round 3: `run` locally reassigns `_decode` to something unrelated before using it.
    src = (
        "import base64\n"
        "def _decode(x):\n"
        "    return base64.b64decode(x)\n"
        "def run():\n"
        "    _decode = str.upper\n"
        "    cmd = _decode('safe_cmd')\n"
        "    exec(cmd)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_c135_real_decode_method_name_shared_with_unrelated_method_not_flagged():
    # JWTHelper.decode_payload() genuinely base64-decodes an (untrusted) JWT segment.
    # PluginLoader.decode_payload() is an unrelated trusted-registry lookup whose
    # result reaches exec(). Sharing the method name must not correlate them --
    # PluginLoader.decode_payload never performs any decode primitive itself.
    src = (
        "import base64, json\n"
        "class JWTHelper:\n"
        "    def decode_payload(self, token):\n"
        "        payload_b64 = token.split('.')[1]\n"
        "        padded = payload_b64 + '=' * (-len(payload_b64) % 4)\n"
        "        return json.loads(base64.urlsafe_b64decode(padded))\n"
        "class PluginLoader:\n"
        "    def decode_payload(self, plugin_name):\n"
        "        return PLUGIN_REGISTRY[plugin_name]\n"
        "    def load(self, plugin_name):\n"
        "        src = self.decode_payload(plugin_name)\n"
        "        exec(src)\n"
        "PLUGIN_REGISTRY = {'noop': 'pass'}\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


# ---------------------------------------------------------------------------
# FP-safety: a decode helper that never reaches exec/eval must stay silent.
# ---------------------------------------------------------------------------

def test_decode_wrapper_never_reaching_exec_is_silent():
    src = (
        "import base64\n"
        "def _decode_config(x):\n"
        "    return base64.b64decode(x)\n"
        "value = _decode_config(some_icon_b64)\n"
        "print(value)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_wrapper_result_written_to_file_not_exec_is_silent():
    src = (
        "import base64\n"
        "def _decode(x):\n"
        "    return base64.b64decode(x)\n"
        "open('out.bin', 'wb').write(_decode(blob))\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_unrelated_function_named_like_decode_but_no_decode_body_not_composing():
    # A function whose body has no decode primitive at all must not be treated as
    # decode-composing just because it's later passed to exec -- exec should still
    # only flag when SOME real decode signal is present.
    src = (
        "def build_message(x):\n"
        "    return 'hello ' + x\n"
        "exec(build_message(name))\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)
