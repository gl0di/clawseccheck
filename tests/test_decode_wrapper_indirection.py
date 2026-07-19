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


# ---------------------------------------------------------------------------
# B-205: _tainted_names cross-function variable-name collision (found during
# C-202's own C-135 review, filed separately as a pre-existing bug -- reproduces
# against the pre-C-202 baseline too). The same class of collision rounds 1/3 fixed
# for decode-COMPOSING FUNCTION names, but left open for a variable assigned
# directly from an inline decode primitive.
# ---------------------------------------------------------------------------

def test_b205_unrelated_same_named_local_in_different_function_not_flagged():
    # `payload` is genuinely decode-tainted in setup(), but unrelated()'s own
    # `payload` is a plain string literal local to unrelated() -- must not collide.
    src = (
        "import base64\n"
        "def setup():\n"
        "    payload = base64.b64decode(x)\n"
        "    return payload\n"
        "def unrelated():\n"
        "    payload = 'safe literal'\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b205_same_scope_taint_still_flags():
    # Positive control: the genuinely tainted case (assignment and exec in the SAME
    # scope) must still fire -- the fix must not over-correct into a false negative.
    src = (
        "import base64\n"
        "def run():\n"
        "    payload = base64.b64decode(x)\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b205_module_level_taint_still_reaches_function_scope_exec():
    # A module-level tainted assignment is genuinely visible inside every function
    # (real Python global-scope lookup) -- must stay flagged, distinct from the
    # cross-FUNCTION collision this fix closes.
    src = (
        "import base64\n"
        "payload = base64.b64decode(x)\n"
        "def run():\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b205_wrapper_taint_still_scoped_correctly_per_function():
    # The composing-wrapper path (_tainted_names' `composing` extension) must remain
    # scope-correct alongside the base-case fix: a wrapper-derived taint in one
    # function must not leak into an unrelated same-named local elsewhere.
    src = (
        "import base64\n"
        "def _decode(x):\n"
        "    return base64.b64decode(x)\n"
        "def setup():\n"
        "    payload = _decode(blob)\n"
        "    return payload\n"
        "def unrelated():\n"
        "    payload = 'safe literal'\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


# ---------------------------------------------------------------------------
# B-205 / C-135 round 1: real bugs found in the FIRST version of the per-function
# scoping fix. Both confirmed via a disposable git-worktree diff against the pre-fix
# baseline before being fixed here.
# ---------------------------------------------------------------------------

def test_b205_c135_global_declared_taint_still_crosses_functions():
    # Finding 1 (HIGH, real regression): `global`-declared taint genuinely IS
    # module-scope in real Python, regardless of which function syntactically
    # contains the assignment -- per-function scoping must not blind itself to a
    # `global` declaration and silently stop catching this real obfuscation shape.
    src = (
        "import base64\n"
        "def loader():\n"
        "    global secret\n"
        "    secret = base64.b64decode(b'eA==')\n"
        "def runner():\n"
        "    exec(secret)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b205_c135_class_method_taint_not_leaked_to_unrelated_function():
    # Finding 2 (MEDIUM-HIGH FP, common OOP-skill shape): a class method's own
    # decode-tainted local must not fall through to the "not in owner_map" bucket
    # (treated as module-level / visible everywhere) and collide with an unrelated
    # same-named local in a totally different top-level function.
    src = (
        "import base64\n"
        "class Loader:\n"
        "    def load(self, blob):\n"
        "        payload = base64.b64decode(blob)\n"
        "        return payload\n"
        "def run_report(title):\n"
        "    payload = 'just a benign report title'\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b205_c135_class_method_same_scope_taint_still_flags():
    # Positive control for Finding 2's fix: a class method's OWN exec() call on its
    # OWN decode-tainted local must still fire -- the fix must isolate a method's
    # scope from OTHER scopes, not blind detection within the method itself.
    src = (
        "import base64\n"
        "class Loader:\n"
        "    def load(self, blob):\n"
        "        payload = base64.b64decode(blob)\n"
        "        exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


# ---------------------------------------------------------------------------
# B-205 / C-135 round 2: a nested class-within-a-class reopened Finding 2's
# collision (owner_map's class handling only recursed one level into cls.body).
# ---------------------------------------------------------------------------

def test_b205_c135_nested_class_within_class_taint_not_leaked():
    src = (
        "import base64\n"
        "class Outer:\n"
        "    class Inner:\n"
        "        def load(self):\n"
        "            payload = base64.b64decode(b'eA==')\n"
        "            return payload\n"
        "def unrelated():\n"
        "    payload = 'safe literal, totally unrelated'\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b205_c135_nested_class_method_same_scope_taint_still_flags():
    src = (
        "import base64\n"
        "class Outer:\n"
        "    class Inner:\n"
        "        def load(self):\n"
        "            payload = base64.b64decode(b'eA==')\n"
        "            exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


# ---------------------------------------------------------------------------
# B-213: same collision as B-209, but for a class METHOD's own nested closure.
# _map_class_methods previously folded a method's entire subtree into ONE flat
# bucket (ast.walk), unlike plain top-level functions which already got a real
# per-nested-scope chain via B-210 -- so a `global x` inside a helper closure
# NESTED WITHIN a method still wrongly promoted the method's own unrelated
# same-named local to the module-wide taint bucket.
# ---------------------------------------------------------------------------

def test_b213_global_in_methods_nested_closure_does_not_promote_methods_own_local():
    src = (
        "import base64\n"
        "class Foo:\n"
        "    def method(self):\n"
        "        def inner():\n"
        "            global x\n"
        "            x = 1\n"
        "        x = base64.b64decode(b'eA==')\n"
        "        inner()\n"
        "        return x\n"
        "exec(x)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b213_methods_nested_closure_genuine_module_global_still_flags():
    # Positive control: a method's nested closure genuinely writing a
    # decode-tainted value to a REAL module global must still fire.
    src = (
        "import base64\n"
        "class Foo:\n"
        "    def method(self):\n"
        "        def inner():\n"
        "            global x\n"
        "            x = base64.b64decode(b'eA==')\n"
        "        inner()\n"
        "exec(x)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b213_methods_own_nested_closure_reading_own_local_still_flags():
    # A method's nested closure reading the METHOD's own tainted local via
    # ordinary closure semantics (no global involved) must still fire -- the
    # per-nested-scope chain must not blind detection within the method itself.
    src = (
        "import base64\n"
        "class Foo:\n"
        "    def method(self):\n"
        "        key = base64.b64decode(b'eA==')\n"
        "        def inner():\n"
        "            exec(key)\n"
        "        inner()\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


# ---------------------------------------------------------------------------
# B-209 / B-210 / B-211: follow-ups discovered during B-205's own C-135 rounds
# (all safe-direction FPs, non-blocking -- B-205 shipped as-is). All three share the
# same root cause: owner_map only distinguished "top-level function" as a scope unit,
# with no real parent-scope-chain. Fixed together via a genuine lexical scope chain
# (each nested function gets its own bucket, chained to its immediate enclosing
# function) plus shadow-subtraction for ancestor buckets.
# ---------------------------------------------------------------------------

def test_b209_global_in_nested_function_does_not_promote_enclosing_functions_own_local():
    # A `global x` declared inside a NESTED function must not sweep the ENCLOSING
    # function's own separate, non-global local `x` into the module-wide bucket too.
    src = (
        "import base64\n"
        "def outer():\n"
        "    x = base64.b64decode(b'eA==')\n"
        "    def inner():\n"
        "        global x\n"
        "        x = 'unrelated module global'\n"
        "    inner()\n"
        "    return x\n"
        "def user():\n"
        "    x = 'safe literal, unrelated name collision'\n"
        "    exec(x)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b210_sibling_nested_functions_under_same_parent_do_not_collide():
    src = (
        "import base64\n"
        "def outer():\n"
        "    def inner1():\n"
        "        payload = base64.b64decode(b'eA==')\n"
        "        return payload\n"
        "    def inner2():\n"
        "        payload = 'safe literal, unrelated closure var'\n"
        "        exec(payload)\n"
        "    inner1()\n"
        "    inner2()\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b210_genuine_closure_read_of_enclosing_functions_taint_still_flags():
    # Positive control for B-210's fix: giving nested functions their own scope
    # bucket must not blind detection when a nested function reads a REAL tainted
    # local from its enclosing function via ordinary Python closure semantics.
    src = (
        "import base64\n"
        "def outer():\n"
        "    key = base64.b64decode(b'eA==')\n"
        "    def inner():\n"
        "        exec(key)\n"
        "    inner()\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b210_three_level_nesting_intermediate_shadow_blocks_outer_taint():
    # Deeper correctness check beyond B-210's own repro: a THIRD level (innermost)
    # closure-reading a name must resolve to the NEAREST enclosing binding (`mid`'s
    # own unrelated local), not skip past it to the grandparent's tainted one.
    src = (
        "import base64\n"
        "def outer():\n"
        "    key = base64.b64decode(b'eA==')\n"
        "    def mid():\n"
        "        key = 'mid own different unrelated key, not tainted'\n"
        "        def inner():\n"
        "            exec(key)\n"
        "        inner()\n"
        "    mid()\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b211_module_level_taint_shadowed_by_same_named_parameter_not_flagged():
    src = (
        "import base64\n"
        "payload = base64.b64decode(b'eA==')\n"
        "def render(payload):\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b211_module_level_taint_shadowed_by_local_reassignment_not_flagged():
    src = (
        "import base64\n"
        "payload = base64.b64decode(b'eA==')\n"
        "def render():\n"
        "    payload = 'a totally different, safe, local string'\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b211_positive_control_real_module_level_taint_still_flags():
    # Positive control for B-211's fix: an unrelated function with NO local/parameter
    # shadowing of the same name must still see genuine module-level taint.
    src = (
        "import base64\n"
        "payload = base64.b64decode(b'eA==')\n"
        "def render():\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


# ---------------------------------------------------------------------------
# C-135 (on B-210): a nested function that writes a decoded payload into an
# ENCLOSING function's own variable via `nonlocal` (not `global`), read back and
# exec'd there right after -- genuine runtime taint flow that silently stopped
# firing once nested functions got their own scope bucket. Real regression found
# during C-135's own review of the B-210 fix, fixed in the same change.
# ---------------------------------------------------------------------------

def test_c135_nonlocal_write_from_nested_function_still_flags():
    src = (
        "import base64\n"
        "def outer():\n"
        "    payload = 'safe default'\n"
        "    def inner():\n"
        "        nonlocal payload\n"
        "        payload = base64.b64decode(b'eA==')\n"
        "    inner()\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_c135_nonlocal_write_across_two_nesting_levels_still_flags():
    # `nonlocal` in `inner` skips its immediate parent `mid` (which never touches
    # `payload` at all) and binds to `outer`'s own `payload` two levels up -- the
    # fix must not assume "immediate parent only".
    src = (
        "import base64\n"
        "def outer():\n"
        "    payload = 'safe'\n"
        "    def mid():\n"
        "        def inner():\n"
        "            nonlocal payload\n"
        "            payload = base64.b64decode(b'eA==')\n"
        "        inner()\n"
        "    mid()\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_c135_nonlocal_taint_visible_at_intermediate_ancestor_too():
    # `mid` itself (between `inner` and `outer`) must also see the taint if it
    # reads the same variable after `inner()` runs -- not just the outermost scope.
    src = (
        "import base64\n"
        "def outer():\n"
        "    payload = 'safe'\n"
        "    def mid():\n"
        "        def inner():\n"
        "            nonlocal payload\n"
        "            payload = base64.b64decode(b'eA==')\n"
        "        inner()\n"
        "        exec(payload)\n"
        "    mid()\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_c135_nonlocal_write_does_not_leak_to_unrelated_same_named_function():
    # Safety control: an unrelated function elsewhere with no `nonlocal` relationship
    # to the tainted one must not be swept in just by sharing a bare variable name.
    src = (
        "import base64\n"
        "def outer():\n"
        "    payload = 'safe'\n"
        "    def inner():\n"
        "        nonlocal payload\n"
        "        payload = base64.b64decode(b'eA==')\n"
        "    inner()\n"
        "def unrelated():\n"
        "    payload = 'totally unrelated safe literal'\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


# ---------------------------------------------------------------------------
# B-214 (false NEGATIVE, evasion) + B-215 (false POSITIVE): one shared root cause.
# The shadow model walked a scope's ENTIRE subtree, counting bindings inside nested
# functions as shadowing the enclosing scope. `_own_bound_names` now stops at nested
# scope boundaries, which closes both directions at once -- fixing either alone
# trades one bug for the other (see `_nonlocal_declared_names`).
# ---------------------------------------------------------------------------

def test_b214_shadow_in_sibling_nested_function_does_not_suppress_real_call():
    # A local rebind of `_decode` inside ONE nested function must not strip the
    # module-level wrapper from an unrelated SIBLING nested function that genuinely
    # calls it. Python scopes that rebind to `helper_unrelated` alone.
    src = (
        "import base64\n"
        "def _decode(blob):\n"
        "    return base64.b64decode(blob)\n"
        "def outer():\n"
        "    def helper_unrelated():\n"
        "        _decode = lambda x: x\n"
        "        return _decode('noop')\n"
        "    def helper_real():\n"
        "        payload = _decode(b'eA==')\n"
        "        exec(payload)\n"
        "    helper_unrelated()\n"
        "    helper_real()\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b214_never_called_dead_decoy_does_not_suppress_detection():
    # The real-world weaponised form, and why B-214 was urgent rather than academic:
    # the attacker authors the skill being vetted, so a two-line NEVER-CALLED decoy
    # was a cheap, fully controllable way to silence decode->exec detection on
    # otherwise-caught malware. `_unused_decoy` has no runtime effect whatsoever.
    src = (
        "import base64\n"
        "def _decode(blob):\n"
        "    return base64.b64decode(blob)\n"
        "def run():\n"
        "    def _unused_decoy():\n"
        "        _decode = None\n"
        "    payload = _decode(b'eA==')\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b214_dead_decoy_nested_two_levels_deep_does_not_suppress_detection():
    # Same evasion buried one level further down, so the fix cannot be a
    # depth-1 special case.
    src = (
        "import base64\n"
        "def _decode(blob):\n"
        "    return base64.b64decode(blob)\n"
        "def run():\n"
        "    def _lvl1():\n"
        "        def _lvl2():\n"
        "            _decode = None\n"
        "        return _lvl2\n"
        "    payload = _decode(b'eA==')\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b214_decoy_inside_composing_wrapper_does_not_suppress_it():
    # The same decoy aimed at `_decode_composing_funcnames` instead: a dead nested
    # rebind of the chained helper `_step2` must not stop `_decode` from being
    # recognised as decode-composing in the first place.
    src = (
        "import base64\n"
        "def _step2(b):\n"
        "    return base64.b64decode(b)\n"
        "def _decode(x):\n"
        "    def _decoy():\n"
        "        _step2 = None\n"
        "    return _step2(x)\n"
        "exec(_decode(blob))\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b214_genuine_own_scope_shadow_still_suppresses():
    # FP-safety control for B-214's narrowing: a rebind in the calling scope's OWN
    # body is a real shadow in Python and must still suppress. This is the C-135
    # round-3 guarantee -- narrowing the walk must not give it up.
    src = (
        "import base64\n"
        "def _decode(blob):\n"
        "    return base64.b64decode(blob)\n"
        "def outer():\n"
        "    def helper_real():\n"
        "        _decode = lambda x: x\n"
        "        payload = _decode(b'eA==')\n"
        "        exec(payload)\n"
        "    helper_real()\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b214_shadow_in_enclosing_scope_still_suppresses_nested_call():
    # The other half of the FP-safety control: a rebind in an ENCLOSING scope really
    # does shadow the module-level name for the nested function too, so the
    # ancestor-chain walk must stay.
    src = (
        "import base64\n"
        "def _decode(blob):\n"
        "    return base64.b64decode(blob)\n"
        "def outer():\n"
        "    _decode = lambda x: x\n"
        "    def helper_real():\n"
        "        payload = _decode(b'eA==')\n"
        "        exec(payload)\n"
        "    helper_real()\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b215_grandparent_reusing_name_not_swept_in_by_nonlocal_write():
    # `nonlocal x` in `inner` binds to `outer`'s own `x` -- the NEAREST enclosing
    # scope that binds the name. `grandparent`'s same-named local is a different
    # variable that no write ever touches, so its exec() must stay silent.
    src = (
        "import base64\n"
        "def grandparent():\n"
        "    x = 'grandparents own local, never touched by any nonlocal write'\n"
        "    def outer():\n"
        "        x = 'outers own local (the REAL nonlocal target for inner)'\n"
        "        def inner():\n"
        "            nonlocal x\n"
        "            x = base64.b64decode(b'eA==')\n"
        "        inner()\n"
        "        return x\n"
        "    outer()\n"
        "    exec(x)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b215_unrelated_reuse_two_levels_out_not_swept_in():
    # Same shape one level deeper, to prove the resolution walks to the nearest
    # binder rather than stopping at a fixed depth.
    src = (
        "import base64\n"
        "def grandparent():\n"
        "    x = 'grandparents own unrelated local'\n"
        "    def mid():\n"
        "        x = 'mids own unrelated local'\n"
        "        def outer():\n"
        "            x = 'the real nonlocal target'\n"
        "            def inner():\n"
        "                nonlocal x\n"
        "                x = base64.b64decode(b'eA==')\n"
        "            inner()\n"
        "        outer()\n"
        "    mid()\n"
        "    exec(x)\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b215_grandparent_is_the_real_target_still_flags():
    # Positive control for B-215: when the intermediate scope does NOT bind the name,
    # the grandparent genuinely IS what `nonlocal` rebinds -- must still fire. This is
    # the false-negative the narrowing must not open.
    src = (
        "import base64\n"
        "def grandparent():\n"
        "    x = 'safe default'\n"
        "    def outer():\n"
        "        def inner():\n"
        "            nonlocal x\n"
        "            x = base64.b64decode(b'eA==')\n"
        "        inner()\n"
        "    outer()\n"
        "    exec(x)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b215_intermediate_scope_sharing_the_cell_via_nonlocal_still_flags():
    # An intermediate ancestor that ALSO declares the name `nonlocal` is not the
    # target -- it shares the very same cell, one level further out. It must be
    # seeded alongside the real target, not mistaken for it, so its own read fires.
    src = (
        "import base64\n"
        "def outer():\n"
        "    payload = 'safe'\n"
        "    def mid():\n"
        "        nonlocal payload\n"
        "        def inner():\n"
        "            nonlocal payload\n"
        "            payload = base64.b64decode(b'eA==')\n"
        "        inner()\n"
        "        exec(payload)\n"
        "    mid()\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b215_nonlocal_target_bound_by_a_parameter_still_flags():
    # The target scope's binding need not be an assignment -- a parameter binds the
    # name just as well, and the resolution must recognise every binding form or it
    # would silently fall back to over-approximating.
    src = (
        "import base64\n"
        "def outer(payload):\n"
        "    def inner():\n"
        "        nonlocal payload\n"
        "        payload = base64.b64decode(b'eA==')\n"
        "    inner()\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b215_nonlocal_target_bound_by_a_for_loop_still_flags():
    src = (
        "import base64\n"
        "def outer(items):\n"
        "    for payload in items:\n"
        "        pass\n"
        "    def inner():\n"
        "        nonlocal payload\n"
        "        payload = base64.b64decode(b'eA==')\n"
        "    inner()\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b215_nonlocal_target_bound_by_a_with_statement_still_flags():
    src = (
        "import base64\n"
        "def outer():\n"
        "    with open('seed.bin', 'rb') as payload:\n"
        "        pass\n"
        "    def inner():\n"
        "        nonlocal payload\n"
        "        payload = base64.b64decode(b'eA==')\n"
        "    inner()\n"
        "    exec(payload)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)
