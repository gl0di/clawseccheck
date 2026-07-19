"""C-202: decode->exec generalization past inline base64.

The pre-existing OBFUSCATED_EXEC rule only saw a decode primitive written inline in
the exec/eval argument (or a variable assigned directly from one). Real malicious
skills route the decoded payload through a local `_decode()`-style helper first,
sometimes layering xor/zlib/hex, sometimes chaining a second helper -- all of which
evaded the inline-only check. This suite locks in the wrapper-indirection fix and
proves it doesn't over-trigger on a decode helper that never reaches exec/eval.
"""
from __future__ import annotations

import ast
import sys

import pytest

from clawseccheck.skillast import (
    _build_toplevel_owner_map,
    _nonlocal_target_scopes,
    _own_bound_names,
    analyze_python,
)


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


# --- B-215: every binding form the target scope may use -------------------------
#
# These three used to assert ONLY `OBFUSCATED_EXEC in _crit_rules(src)`, which is
# vacuous: when `_nonlocal_target_scopes` cannot model a binding form it returns []
# and the caller falls back to seeding EVERY ancestor, which produces that same
# positive verdict. So the assertion could not tell "binding form correctly modelled"
# from "binding form not modelled at all" -- with `add_args`, the `ast.For` branch,
# the `ast.withitem` branch, or the entire resolver body disabled, all three still
# passed. Each now pins the resolution two ways the fallback cannot fake:
#   1. structurally, on `_nonlocal_target_scopes` -- it must NAME the target scope
#      (the fallback returns [], the "unmodelled" signal);
#   2. behaviourally, with a same-named GRANDPARENT local that must NOT be swept in
#      (the fallback seeds it and the grandparent's own exec fires -- the exact
#      B-215 false positive).


def _nonlocal_targets(src: str, name: str = "payload") -> list[str]:
    """Names of the scope(s) `_nonlocal_target_scopes` resolves the `nonlocal name`
    write in `src` to. `[]` means the binding form is unmodelled and the caller falls
    back to over-approximating -- which is precisely what these tests must detect."""
    tree = ast.parse(src)
    top = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    owner_map, parent_scope = _build_toplevel_owner_map(top)
    scope = next(
        (
            owner_map.get(n)
            for n in ast.walk(tree)
            if isinstance(n, ast.Nonlocal) and name in n.names
        ),
        None,
    )
    assert scope is not None, "test source has no `nonlocal` declaration to resolve"
    targets = _nonlocal_target_scopes(name, scope, parent_scope, owner_map, {}, {})
    return [getattr(t, "name", "<module>") for t in targets]


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
    assert _nonlocal_targets(src) == ["outer"]
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b215_parameter_target_does_not_sweep_in_a_same_named_grandparent():
    # The negative half: `outer`'s PARAMETER is the real target, so `gp`'s unrelated
    # local of the same name is never written and its exec must stay silent.
    src = (
        "import base64\n"
        "def gp():\n"
        "    payload = 'gp own local, never touched by the nonlocal write'\n"
        "    def outer(payload):\n"
        "        def inner():\n"
        "            nonlocal payload\n"
        "            payload = base64.b64decode(b'eA==')\n"
        "        inner()\n"
        "    outer(b'')\n"
        "    exec(payload)\n"
    )
    assert _nonlocal_targets(src) == ["outer"]
    assert "OBFUSCATED_EXEC" not in _rules(src)


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
    assert _nonlocal_targets(src) == ["outer"]
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b215_for_loop_target_does_not_sweep_in_a_same_named_grandparent():
    src = (
        "import base64\n"
        "def gp(items):\n"
        "    payload = 'gp own local, never touched by the nonlocal write'\n"
        "    def outer():\n"
        "        for payload in items:\n"
        "            pass\n"
        "        def inner():\n"
        "            nonlocal payload\n"
        "            payload = base64.b64decode(b'eA==')\n"
        "        inner()\n"
        "    outer()\n"
        "    exec(payload)\n"
    )
    assert _nonlocal_targets(src) == ["outer"]
    assert "OBFUSCATED_EXEC" not in _rules(src)


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
    assert _nonlocal_targets(src) == ["outer"]
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b215_with_statement_target_does_not_sweep_in_a_same_named_grandparent():
    src = (
        "import base64\n"
        "def gp():\n"
        "    payload = 'gp own local, never touched by the nonlocal write'\n"
        "    def outer():\n"
        "        with open('seed.bin', 'rb') as payload:\n"
        "            pass\n"
        "        def inner():\n"
        "            nonlocal payload\n"
        "            payload = base64.b64decode(b'eA==')\n"
        "        inner()\n"
        "    outer()\n"
        "    exec(payload)\n"
    )
    assert _nonlocal_targets(src) == ["outer"]
    assert "OBFUSCATED_EXEC" not in _rules(src)


# --- B-214: every binding form `_own_bound_names` claims to model -----------------
#
# `_own_bound_names` decides whether a scope locally rebinds a decode-composing name
# and therefore must NOT resolve it to the module-level helper. Each form below is
# verdict-moving: on the pre-B-214 subtree walk every one of them produced a crit
# OBFUSCATED_EXEC false positive (the local rebind was invisible, so `_decode(...)`
# was read as a call to the module-level wrapper). They shipped with no coverage --
# deleting any single branch left the suite green -- so each is pinned here twice:
# once on `_own_bound_names` directly, once on the verdict it moves.

_DECODE_HELPER = "import base64\ndef _decode(b):\n    return base64.b64decode(b)\n"


def _run_binds(src: str) -> set[str]:
    """`_own_bound_names` of the `run()` defined in `src` -- what the scope model
    believes `run` rebinds locally, asserted alongside the verdict it moves."""
    tree = ast.parse(src)
    run = next(n for n in tree.body if getattr(n, "name", None) == "run")
    return _own_bound_names(run)


def _shadow_case(binding_line: str, params: str = "") -> str:
    return _DECODE_HELPER + (
        f"def run({params}):\n"
        f"{binding_line}"
        "    payload = _decode(b'eA==')\n"
        "    exec(payload)\n"
    )


def test_b214_control_unshadowed_wrapper_call_still_flags():
    # The control every case below is measured against: with NO local rebind the
    # wrapper call really does resolve to the module-level `_decode` and must fire.
    # Without this, a shadow test could pass for the wrong reason (nothing firing).
    src = _shadow_case("")
    assert "_decode" not in _run_binds(src)
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b214_import_binds_and_shadows_the_composing_name():
    for line in (
        "    import _decode\n",
        "    import mylib as _decode\n",
        "    from mylib import _decode\n",
        "    from mylib import thing as _decode\n",
    ):
        src = _shadow_case(line)
        assert "_decode" in _run_binds(src), line
        assert "OBFUSCATED_EXEC" not in _rules(src), line


def test_b214_import_star_binds_nothing():
    # `from x import *` binds an unknowable set; it must not be read as binding the
    # literal name "*", and it must not suppress the wrapper match.
    src = _shadow_case("    from mylib import *\n")
    assert "*" not in _run_binds(src)
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b214_except_handler_alias_binds_and_shadows_the_composing_name():
    src = _shadow_case(
        "    try:\n"
        "        pass\n"
        "    except Exception as _decode:\n"
        "        pass\n"
    )
    assert "_decode" in _run_binds(src)
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b214_del_binds_and_shadows_the_composing_name():
    # `del x` makes x local to the scope: a later read raises UnboundLocalError
    # rather than falling through to the module-level binding, so it is a real shadow.
    src = _shadow_case("    del _decode\n")
    assert "_decode" in _run_binds(src)
    assert "OBFUSCATED_EXEC" not in _rules(src)


@pytest.mark.skipif(sys.version_info < (3, 10), reason="match statements are 3.10+ syntax")
def test_b214_match_capture_patterns_bind_and_shadow_the_composing_name():
    for line in (
        "    match cmd:\n        case _decode:\n            pass\n",  # MatchAs
        "    match cmd:\n        case [*_decode]:\n            pass\n",  # MatchStar
        "    match cmd:\n        case {**_decode}:\n            pass\n",  # MatchMapping.rest
    ):
        src = _shadow_case(line, params="cmd")
        assert "_decode" in _run_binds(src), line
        assert "OBFUSCATED_EXEC" not in _rules(src), line


def test_b214_lambda_parameter_does_not_shadow_the_enclosing_scope():
    # A lambda opens its OWN scope: its parameter binds nothing in the enclosing
    # function, so it must not suppress the wrapper match.
    src = _shadow_case("    f = lambda _decode: _decode\n")
    binds = _run_binds(src)
    assert "_decode" not in binds and "f" in binds
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b214_walrus_inside_a_lambda_body_does_not_shadow_the_enclosing_scope():
    # The `ast.Lambda` skip, in the direction that moves a verdict: a walrus in a
    # lambda BODY binds in the lambda's scope, not the enclosing one. The pre-B-214
    # subtree walk counted it as an enclosing binding and MISSED this payload
    # entirely -- a false negative, and a cheap evasion primitive.
    src = _shadow_case("    f = lambda x: (_decode := x)\n")
    assert "_decode" not in _run_binds(src)
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


# --- B-214 follow-up: the two per-scope walks must stop at the SAME boundary -------


def test_b214_nested_closure_return_is_not_the_outer_functions_return_path():
    # Found by adversarial C-135 review of the B-214 fix itself. `_own_bound_names`
    # was narrowed to stop at nested-scope boundaries, but `_scope_own_nodes` -- which
    # enumerates a function's return paths -- filtered nested scopes only among a
    # node's CHILDREN, never among the scope's own top-level body statements. So a
    # nested `def` sitting directly in the body leaked its whole body into the
    # parent's node set: the closure's `return _decode(...)` counted as the OUTER
    # function's return path, while the closure's own rebinding of that name no longer
    # subtracted. `get_template` returns a plain string literal and decodes nothing,
    # yet was classified decode-composing -- a crit false positive that reached the
    # real `--vet` path as B13 FAIL / CRITICAL on a benign skill.
    src = (
        "import base64\n"
        "def decode_field(v):\n"
        "    return base64.b64decode(v)\n"
        "def get_template():\n"
        "    def render():\n"
        '        decode_field = REGISTRY["decoder"]\n'
        '        return decode_field("x")\n'
        "    return \"print('hello')\"\n"
        "exec(get_template())\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b214_nested_def_first_in_body_does_not_leak_its_return_path():
    # The same leak reduced to its mechanism, independent of any shadowing: a nested
    # closure that genuinely decodes must not make its ENCLOSING function look
    # decode-composing when that function returns a literal.
    src = (
        "import base64\n"
        "def outer():\n"
        "    def inner():\n"
        "        return base64.b64decode(b'eA==')\n"
        "    return 'plain literal'\n"
        "exec(outer())\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b214_outer_function_own_return_path_still_flags():
    # FP-safety control for the boundary fix: narrowing the walk must not stop the
    # OUTER function's own return path from being seen. Same shape, decode moved out
    # of the closure and onto `outer`'s own return.
    src = (
        "import base64\n"
        "def outer():\n"
        "    def inner():\n"
        "        return 'unused'\n"
        "    return base64.b64decode(b'eA==')\n"
        "exec(outer())\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


# --- B-214 follow-up: a nested scope's node is not entirely "someone else's scope" --


def test_b214_walrus_in_a_nested_def_default_shadows_the_enclosing_scope():
    # Only a nested scope's BODY is the new scope. Its argument defaults, decorators,
    # annotations and class bases are evaluated in the ENCLOSING one, so a walrus
    # there genuinely rebinds the enclosing name. Skipping the whole node made these
    # rebinds invisible and resolved the later call to the module-level helper -- a
    # crit false positive on code that only ever calls the local identity lambda.
    src = _shadow_case("    def h(a=(_decode := (lambda x: x))):\n        pass\n")
    assert "_decode" in _run_binds(src)
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b214_walrus_in_a_decorator_shadows_the_enclosing_scope():
    src = _shadow_case("    @(_decode := (lambda f: f))\n    def h():\n        pass\n")
    assert "_decode" in _run_binds(src)
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b214_walrus_in_a_lambda_default_shadows_the_enclosing_scope():
    src = _shadow_case("    g = lambda a=(_decode := (lambda x: x)): a\n")
    assert "_decode" in _run_binds(src)
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b214_walrus_in_a_class_base_shadows_the_enclosing_scope():
    src = _shadow_case("    class C((_decode := object)):\n        pass\n")
    assert "_decode" in _run_binds(src)
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b214_nested_def_body_is_still_not_the_enclosing_scope():
    # FP-safety control for the above: descending into a nested def's defaults must
    # NOT turn into descending into its body. A rebind inside the body binds there,
    # not in `run`, so it must not suppress -- this is the B-214 dead-decoy guarantee.
    src = _shadow_case("    def h(a=1):\n        _decode = None\n")
    assert "_decode" not in _run_binds(src)
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


# ---------------------------------------------------------------------------
# B-261 (false NEGATIVE, evasion): the THIRD distinct scope rule, after B-214
# (shadow resolution across SIBLING scopes) and B-215 (which ancestor a nonlocal
# taint is seeded into). Both of those concerned some OTHER scope's view of the
# name. This one is the writing scope's view of its OWN write: the scope that
# binds a name via `nonlocal`/`global` is not creating a fresh local, so it must
# keep seeing that name as tainted for the rest of its own body.
#
# The pre-fix failure was self-cancelling: `_tainted_names` seeded the taint into
# the ancestor bucket (B-215), then `_tainted_names_visible` subtracted that very
# ancestor back out again, because `_own_bound_names` counted the declared rebind
# as the writing scope's own shadowing local. The exec read clean.
# ---------------------------------------------------------------------------

def test_b261_nonlocal_write_and_exec_in_the_same_function_flags():
    # The repro: the `nonlocal` write AND the exec that consumes it live in ONE
    # inner function. B-210's `nonlocal` case only ever covered the write and the
    # read landing in DIFFERENT scopes.
    src = (
        "import base64\n"
        "def outer():\n"
        "    x = None\n"
        "    def inner():\n"
        "        nonlocal x\n"
        "        x = base64.b64decode(b'eA==')\n"
        "        exec(x)\n"
        "    inner()\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b261_global_write_and_exec_in_the_same_function_flags():
    # Same root cause reached through `global` -- an equally cheap evasion, and one
    # that would have stayed open had the fix keyed on `nonlocal` alone.
    src = (
        "import base64\n"
        "def f():\n"
        "    global x\n"
        "    x = base64.b64decode(b'eA==')\n"
        "    exec(x)\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b261_declared_names_are_not_own_bound_names():
    # Structural half: a declared rebind is not a local of the declaring scope, so
    # `_own_bound_names` must not report it even though an Assign targets it.
    tree = ast.parse(
        "def run():\n"
        "    nonlocal_free = 1\n"
        "    global g\n"
        "    g = 2\n"
    )
    run = next(n for n in tree.body if getattr(n, "name", None) == "run")
    binds = _own_bound_names(run)
    assert "nonlocal_free" in binds  # a plain local is still bound here
    assert "g" not in binds  # the `global` target is not


def test_b261_genuine_local_rebind_still_shadows():
    # The discrimination this fix turns on: WITHOUT a declaration, the very same
    # assignment is a fresh local and must still shadow the module-level wrapper.
    # If this ever goes green-by-firing, the fix has over-reached into B-214's job.
    src = _shadow_case("    _decode = None\n")
    assert "_decode" in _run_binds(src)
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b261_declaration_in_a_nested_function_does_not_unshadow_the_outer_scope():
    # Owner-correctness of the subtraction: `helper` declares `_decode` nonlocal,
    # but `run` binds it as a genuine local of its own. The declaration belongs to
    # `helper` alone, so `run` must keep its shadow and stay silent. A subtraction
    # that leaked across the nested-function boundary would reopen a false positive
    # here -- this is the FP-direction control for the fix.
    src = _shadow_case(
        "    _decode = None\n"
        "    def helper():\n"
        "        nonlocal _decode\n"
        "        _decode = None\n"
    )
    assert "_decode" in _run_binds(src)
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b261_benign_same_scope_nonlocal_write_stays_silent():
    # Clean control: the exact scope shape of the repro with no decode->exec chain
    # anywhere. The fix must buy detection only where a real decode reaches a sink.
    src = (
        "def make_counter():\n"
        "    total = 0\n"
        "    def bump(n):\n"
        "        nonlocal total\n"
        "        total = total + n\n"
        "        return total\n"
        "    return bump\n"
    )
    assert _rules(src) == set()


# ---------------------------------------------------------------------------
# B-261, second half: `global` is a REDIRECT, not a walk.
#
# Dropping a declared name from `_own_bound_names` is necessary but, for `global`,
# not sufficient -- and shipping only that produced a real false-positive FAIL.
# `global n` in a nested helper made an ENCLOSING function's same-named decoded
# local read as visible taint, though the two are provably different variables.
# The declarations are asymmetric, and these tests pin both directions:
#
#   nonlocal n -> nearest ENCLOSING FUNCTION that binds n. Python's syntax
#                 guarantees one exists, so that ancestor re-contributes the shadow
#                 and the ordinary outward walk stops itself. Module never reached.
#   global n   -> the MODULE binding, always. Every enclosing function is skipped
#                 whether or not it binds n, and no accumulated shadow may hide the
#                 module bucket.
#
# The discriminating pair is `..._reaches_a_module_level_decode` (crit) against
# `..._does_not_expose_an_enclosing_functions_decode` (silent): identical syntax,
# opposite verdicts, decided solely by WHICH scope holds the decode.
# ---------------------------------------------------------------------------

def test_b261_nested_global_does_not_expose_an_enclosing_functions_decode():
    # THE false positive this half of the fix exists to prevent, in its realistic
    # form: `make_registrar`'s `template` is a decoded bundled asset; `register`'s
    # `template` is the module-level one it declares `global`. Different variables,
    # so the decoded bytes provably cannot reach the exec. Fully benign -- must not
    # be crit. (No external input anywhere, so no other rule confounds the verdict.)
    src = (
        "import base64\n"
        "template = ''\n"
        "def make_registrar():\n"
        "    template = base64.b64decode(b'aGVsbG8=')\n"
        "    open('/tmp/asset.bin', 'wb').write(template)\n"
        "    def register():\n"
        "        global template\n"
        "        template = 'PLUGINS = {}'\n"
        "        exec(template)\n"
        "    return register\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b261_nested_global_reaches_a_module_level_decode():
    # The other half of the discriminating pair, and the reason the FP above cannot
    # be fixed by simply reverting to a shadow: same shape, decode moved to MODULE
    # level, where `global` says the name really does resolve. Must stay crit even
    # though `outer` binds the same bare name -- a plain outward walk would let that
    # unrelated binding shadow the module bucket and lose the detection.
    src = (
        "import base64\n"
        "blob = base64.b64decode(b'eA==')\n"
        "def outer():\n"
        "    blob = 'unrelated'\n"
        "    def inner():\n"
        "        global blob\n"
        "        exec(blob)\n"
        "    inner()\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b261_nested_global_does_not_expose_an_enclosing_augmented_assignment():
    # Same FP through `+=` rather than `=`: AugAssign is a binding form too, so the
    # subtraction reaches it and the redirect has to cover it as well.
    src = (
        "import base64\n"
        "def outer():\n"
        "    buf = base64.b64decode(b'eA==')\n"
        "    def inner():\n"
        "        global buf\n"
        "        buf += 'x'\n"
        "        exec(buf)\n"
        "    inner()\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b261_global_in_a_method_does_not_expose_the_enclosing_functions_decode():
    # Same FP reached through a class body nested in a function -- the method chains
    # to `make` via parent_scope, so the redirect must apply on that path too.
    src = (
        "import base64\n"
        "tmpl = ''\n"
        "def make():\n"
        "    tmpl = base64.b64decode(b'eA==')\n"
        "    class R:\n"
        "        def go(self):\n"
        "            global tmpl\n"
        "            tmpl = 'print(1)'\n"
        "            exec(tmpl)\n"
        "    return tmpl, R\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b261_global_declared_but_never_assigned_does_not_expose_an_enclosing_decode():
    # The declaration alone redirects -- there need be no assignment at all. This
    # shape was a latent false positive even BEFORE the B-261 work (the name never
    # entered any shadow set, so the enclosing bucket was always exposed); modelling
    # `global` as a redirect rather than as an absent binding closes it too.
    src = (
        "import base64\n"
        "blob = ''\n"
        "def outer():\n"
        "    blob = base64.b64decode(b'eA==')\n"
        "    def inner():\n"
        "        global blob\n"
        "        exec(blob)\n"
        "    inner()\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b261_nested_global_write_and_exec_in_the_same_function_flags():
    # The ticket's own repro reached through `global` from a NESTED scope, not just
    # a top-level one: write and exec in one inner function. Guards the FP fixes
    # above from being over-applied into a detection hole.
    src = (
        "import base64\n"
        "def outer():\n"
        "    def inner():\n"
        "        global g\n"
        "        g = base64.b64decode(b'eA==')\n"
        "        exec(g)\n"
        "    inner()\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b261_global_write_in_an_enclosing_scope_is_visible_to_a_nested_read():
    # `outer` writes the decode to MODULE scope via `global`; `inner` declares
    # nothing, so its read falls through `outer` (which binds no local `n`) to that
    # same module binding. Real flow -- and the case that makes dropping a declared
    # name from `_own_bound_names` load-bearing: keep it as a shadow and `outer`
    # hides the module bucket from `inner`, reopening the evasion.
    src = (
        "import base64\n"
        "def outer():\n"
        "    global n\n"
        "    n = base64.b64decode(b'eA==')\n"
        "    def inner():\n"
        "        exec(n)\n"
        "    inner()\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b261_global_skips_every_enclosing_function_not_just_the_nearest():
    # Generalization guard: the redirect is not a one-level patch. TWO enclosing
    # functions each hold their own decoded local; `c`'s `global t` skips both.
    src = (
        "import base64\n"
        "t = ''\n"
        "def a():\n"
        "    t = base64.b64decode(b'eA==')\n"
        "    def b():\n"
        "        t = base64.b64decode(b'eQ==')\n"
        "        def c():\n"
        "            global t\n"
        "            t = 'x'\n"
        "            exec(t)\n"
        "        c()\n"
        "    b()\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b261_global_skipping_still_reaches_module_through_a_deep_chain():
    # The paired true positive for the above: same three-level shape, decode moved
    # to module scope. Both enclosing bindings are skipped in this direction too,
    # so neither may shadow the module bucket away.
    src = (
        "import base64\n"
        "t = base64.b64decode(b'eA==')\n"
        "def a():\n"
        "    t = 1\n"
        "    def b():\n"
        "        t = 2\n"
        "        def c():\n"
        "            global t\n"
        "            exec(t)\n"
        "        c()\n"
        "    b()\n"
    )
    assert "OBFUSCATED_EXEC" in _crit_rules(src)


def test_b261_global_in_a_nested_function_does_not_unshadow_the_outer_scope():
    # Owner attribution for `global`, the axis the `nonlocal` control above does not
    # cover: `helper` declares `_decode` global, but `run` binds it as a genuine
    # local. The declaration belongs to `helper` alone, so `run` keeps its shadow
    # and the wrapper call must stay silent.
    src = (
        _DECODE_HELPER
        + "def run():\n"
        "    _decode = None\n"
        "    def helper():\n"
        "        global _decode\n"
        "        _decode = None\n"
        "    payload = _decode(b'eA==')\n"
        "    exec(payload)\n"
    )
    assert "_decode" in _run_binds(src)
    assert "OBFUSCATED_EXEC" not in _rules(src)


def test_b261_nested_nonlocal_does_not_expose_a_module_level_decode():
    # The mirror direction, pinning that `nonlocal` needs NO redirect: `inner`'s `x`
    # is `outer`'s cell, never the tainted module-level `x`. Nothing special-cases
    # this -- `outer` binds `x` and so re-contributes the shadow before the walk
    # reaches module. If a future change gives `nonlocal` the `global` treatment,
    # this goes red.
    src = (
        "import base64\n"
        "x = base64.b64decode(b'eA==')\n"
        "def outer():\n"
        "    x = 1\n"
        "    def inner():\n"
        "        nonlocal x\n"
        "        x = 'safe'\n"
        "        exec(x)\n"
        "    inner()\n"
    )
    assert "OBFUSCATED_EXEC" not in _rules(src)
