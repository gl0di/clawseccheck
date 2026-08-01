"""B336 -- exec()/eval() sink fed by a locally-defined helper that reads and joins
MULTIPLE chunked/part files at runtime (e.g. `_load.part1.txt`, `.part2.txt`), then
executes the assembled result -- the split-by-file scanner-evasion loader shape.
Reuses skillast.py's CHUNKED_FILE_EXEC AST rule; the standalone check is pure wiring.
WARN-only (never FAIL): checks/_vet.py's check_installed_skills (B13) routes this rule
through its own explicit continue-branch, before its generic crit/cred-exfil
fallthrough, so it can never become FAIL-capable. Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.checks import (
    PASS,
    UNKNOWN,
    WARN,
    check_chunked_file_assembly_exec,
    check_installed_skills,
    vet_skill,
)
from clawseccheck.collector import Context, collect
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str) -> dict:
    return {f.rule: f for f in analyze_python(src, "t.py")}


# --- analyzer-level (skillast.py CHUNKED_FILE_EXEC) ---


def test_chunked_loop_form_fires():
    src = """
import os

_CHUNKS = ["x.part1.txt", "x.part2.txt", "x.part3.txt"]


def _load():
    parts = []
    for c in _CHUNKS:
        with open(os.path.join("/tmp", c)) as fh:
            parts.append(fh.read())
    return "".join(parts)


exec(compile(_load(), "<runtime>", "exec"), {})
"""
    assert "CHUNKED_FILE_EXEC" in _rules(src)


def test_chunked_assigned_then_passed_hop_form_fires():
    src = """
import os

_CHUNKS = ["y.part1.bin", "y.part2.bin"]


def _load():
    parts = []
    for c in _CHUNKS:
        with open(os.path.join("/tmp", c)) as fh:
            parts.append(fh.read())
    return "".join(parts)


src = _load()
exec(src)
"""
    assert "CHUNKED_FILE_EXEC" in _rules(src)


def test_chunked_unrolled_form_fires():
    src = """
def _load():
    with open("payload.part1.dat") as a, open("payload.part2.dat") as b:
        return a.read() + b.read()


eval(compile(_load(), "<r>", "eval"))
"""
    assert "CHUNKED_FILE_EXEC" in _rules(src)


def test_asset_write_no_exec_sink_is_clean():
    src = """
import base64

def write_logo(path):
    data = base64.b64decode(b"aGVsbG8=")
    with open(path, "wb") as fh:
        fh.write(data)
"""
    assert "CHUNKED_FILE_EXEC" not in _rules(src)


def test_config_assembly_into_json_loads_is_clean():
    src = """
import json, os

_FILES = ["base.json", "override.json"]


def _load_cfg():
    parts = []
    for name in _FILES:
        with open(os.path.join("/etc/app", name)) as fh:
            parts.append(fh.read())
    return "".join(parts)


CONFIG = json.loads(_load_cfg())
"""
    assert "CHUNKED_FILE_EXEC" not in _rules(src)


def test_multi_file_package_import_is_clean():
    src = """
from . import helpers
from .utils import thing
import pkg.mod
"""
    assert "CHUNKED_FILE_EXEC" not in _rules(src)


def test_inline_literal_exec_is_clean():
    src = 'exec("def _generated(): return 42")\n'
    assert "CHUNKED_FILE_EXEC" not in _rules(src)


def test_version_numbered_names_dont_corroborate():
    # C-135 (independent review, SkillTrustBench SC-005 pass): the original leg-3
    # regex only required a bare trailing digit before the extension -- no chunk/part
    # marker word -- so it also matched ordinary version-numbered independent assets
    # (a two-locale string table), not just genuine split-payload chunks. Pinned FP.
    src = """
import os

_VERSIONS = ["strings_v1.txt", "strings_v2.txt"]


def _load_string_table():
    parts = []
    for name in _VERSIONS:
        with open(os.path.join("/i18n", name)) as fh:
            parts.append(fh.read())
    return "{" + ", ".join(parts) + "}"


STRINGS = eval(_load_string_table())
"""
    assert "CHUNKED_FILE_EXEC" not in _rules(src)


def test_cross_scope_name_shadow_does_not_taint_unrelated_function():
    # C-135 (independent review, SkillTrustBench SC-005 pass): the original taint
    # fixpoint matched tainted names as bare strings module-wide, with no scope
    # resolution -- so an unrelated function reusing the same bare identifier
    # (TEMPLATE) for its own local, with zero actual data flow from the chunked
    # read, had its own eval() call wrongly flagged. Pinned FP.
    src = """
import os

_PARTS = ["release_notes.part1.txt", "release_notes.part2.txt"]


def _load_release_notes():
    parts = []
    for name in _PARTS:
        with open(os.path.join("/tmp", name)) as fh:
            parts.append(fh.read())
    TEMPLATE = "".join(parts)
    return TEMPLATE


TEMPLATE = _load_release_notes()


def run_builtin_selftest():
    TEMPLATE = "1 + 1 == 2"
    return eval(TEMPLATE)
"""
    assert "CHUNKED_FILE_EXEC" not in _rules(src)


def test_nonchunked_names_dont_corroborate():
    src = """
import os

_FILES = ["en_strings.txt", "fr_strings.txt"]


def _load():
    parts = []
    for name in _FILES:
        with open(os.path.join("/i18n", name)) as fh:
            parts.append(fh.read())
    return "".join(parts)


exec(compile(_load(), "<runtime>", "exec"), {})
"""
    assert "CHUNKED_FILE_EXEC" not in _rules(src)


def test_unrelated_chunked_helper_does_not_donate_evidence_to_other_exec():
    # B-417 (C-135 follow-up): when a file has MORE THAN ONE composing helper, leg 3
    # used to be evaluated against the UNION of every composing helper's paths in the
    # file, not just the one that actually fed the sink under test. So a totally
    # unrelated helper that reads genuinely chunked/sharded DATA files (e.g. a schema
    # index split to stay under a hosting blob-size limit) could donate chunk-shaped
    # path evidence to a DIFFERENT exec() call that is really fed by two ordinary,
    # non-chunked template fragments. Pinned FP -- this is the exact B-417 repro
    # (sqlmodel-codegen shape).
    src = """
import json
import os

INDEX_CHUNKS = ["data/schema_index.part1.jsonl", "data/schema_index.part2.jsonl"]


def load_schema_index():
    rows = []
    for path in INDEX_CHUNKS:
        with open(path, encoding="utf-8") as fh:
            rows.append(fh.read())
    return "".join(rows)


def build_model_source():
    with open("templates/model_header.tmpl", encoding="utf-8") as header:
        with open("templates/model_body.tmpl", encoding="utf-8") as body:
            return header.read() + body.read()


def materialize_models():
    namespace = {}
    exec(build_model_source(), namespace)
    return namespace


def schema_names():
    return [
        json.loads(line)["name"]
        for line in load_schema_index().splitlines()
        if line.strip()
    ]
"""
    assert "CHUNKED_FILE_EXEC" not in _rules(src)


def test_unrelated_chunked_helper_control_single_helper_still_clean():
    # Control for the test above: with load_schema_index() removed, only one
    # composing helper (build_model_source) remains -- confirms the exec() in
    # question is correctly silent on its own, independent of the multi-helper fix.
    src = """
def build_model_source():
    with open("templates/model_header.tmpl", encoding="utf-8") as header:
        with open("templates/model_body.tmpl", encoding="utf-8") as body:
            return header.read() + body.read()


def materialize_models():
    namespace = {}
    exec(build_model_source(), namespace)
    return namespace
"""
    assert "CHUNKED_FILE_EXEC" not in _rules(src)


def test_actually_chunked_helper_still_fires_alongside_unrelated_composing_helper():
    # The true-positive twin of the two tests above: the GENUINELY chunked helper
    # (load_payload) feeds exec(), while a second, unrelated composing helper
    # (load_docs, two ordinary non-chunked files) does NOT. B-417's per-helper
    # attribution fix must not regress this real positive, and the evidence must cite
    # only load_payload()'s chunked paths.
    src = """
import os

_PARTS = ["payload.part1.bin", "payload.part2.bin"]


def load_payload():
    parts = []
    for p in _PARTS:
        with open(os.path.join("/tmp", p)) as fh:
            parts.append(fh.read())
    return "".join(parts)


def load_docs():
    with open("docs/intro.md") as a:
        with open("docs/outro.md") as b:
            return a.read() + b.read()


def run():
    exec(load_payload())


def render_docs():
    return load_docs()
"""
    rules = _rules(src)
    assert "CHUNKED_FILE_EXEC" in rules
    reason = rules["CHUNKED_FILE_EXEC"].reason
    assert "payload.part1.bin" in reason and "payload.part2.bin" in reason
    assert "docs/intro.md" not in reason and "docs/outro.md" not in reason


# --- check-level ---


def test_unknown_when_no_installed_skills():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {}
    f = check_chunked_file_assembly_exec(ctx)
    assert f.status == UNKNOWN


# --- vet-level: B336 surfaces as WARN on the bad fixture, PASS on every clean one ---


def test_vet_bad_chunked_file_exec_is_warn():
    skill_dir = FIXTURES / "bad_b336_chunked_file_exec" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert any(x.id == "B336" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])])


def test_vet_clean_asset_write_b336_passes():
    skill_dir = FIXTURES / "clean_b336_asset_write" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B336" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


def test_vet_clean_config_assembly_b336_passes():
    skill_dir = FIXTURES / "clean_b336_config_assembly" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B336" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


def test_vet_clean_package_import_b336_passes():
    skill_dir = FIXTURES / "clean_b336_package_import" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B336" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


def test_vet_clean_inline_literal_exec_b336_passes():
    skill_dir = FIXTURES / "clean_b336_inline_literal_exec" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B336" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


def test_vet_clean_nonchunked_names_b336_passes():
    skill_dir = FIXTURES / "clean_b336_nonchunked_names" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B336" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


def test_vet_clean_version_numbered_names_b336_passes():
    skill_dir = FIXTURES / "clean_b336_version_numbered_names" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B336" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


def test_vet_clean_name_shadow_b336_passes():
    skill_dir = FIXTURES / "clean_b336_name_shadow" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B336" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


def test_vet_clean_cross_helper_misattribution_b336_passes():
    # B-417: the unrelated, genuinely chunked helper (load_schema_index) must not
    # donate leg-3 evidence to the unrelated, non-chunked exec() actually fed by
    # build_model_source().
    skill_dir = FIXTURES / "clean_b336_cross_helper_misattribution" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B336" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


def test_vet_bad_multi_helper_true_feed_is_warn():
    # True-positive twin: the genuinely chunked helper still fires even with a second,
    # unrelated (non-feeding) composing helper in the same file.
    skill_dir = FIXTURES / "bad_b336_multi_helper_true_feed" / "skills" / "loader"
    f = vet_skill(skill_dir)
    assert any(x.id == "B336" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])])


# --- B13 (check_installed_skills) end-to-end: WARN, not FAIL, not PASS ---


def test_b13_bad_chunked_file_exec_is_warn_not_fail():
    ctx = collect(FIXTURES / "bad_b336_chunked_file_exec")
    f = check_installed_skills(ctx)
    assert f.status == WARN
    assert f.severity == "HIGH"


def test_b13_bad_multi_helper_true_feed_is_warn_not_fail():
    ctx = collect(FIXTURES / "bad_b336_multi_helper_true_feed")
    f = check_installed_skills(ctx)
    assert f.status == WARN
    assert f.severity == "HIGH"


def test_b13_clean_cross_helper_misattribution_stays_pass():
    # B-417 end-to-end: an unrelated, genuinely chunked helper in the same file must
    # not turn B13's verdict into a WARN via this rule.
    ctx = collect(FIXTURES / "clean_b336_cross_helper_misattribution")
    f = check_installed_skills(ctx)
    assert f.status == PASS


def test_b13_clean_nonchunked_names_stays_pass():
    # Leg 3 must hold end-to-end too: the same read+join+exec SHAPE with non-chunked
    # file names must not turn B13's verdict into a WARN via this rule.
    ctx = collect(FIXTURES / "clean_b336_nonchunked_names")
    f = check_installed_skills(ctx)
    assert f.status == PASS


def test_b13_clean_version_numbered_names_stays_pass():
    # C-135 pinned FP: version-numbered independent assets (strings_v1.txt,
    # strings_v2.txt) must not turn B13's verdict into a WARN via this rule.
    ctx = collect(FIXTURES / "clean_b336_version_numbered_names")
    f = check_installed_skills(ctx)
    assert f.status == PASS


def test_b13_clean_name_shadow_stays_pass():
    # C-135 pinned FP: an unrelated function's own same-named local (ordinary name
    # shadowing, zero real data flow) must not turn B13's verdict into a WARN.
    ctx = collect(FIXTURES / "clean_b336_name_shadow")
    f = check_installed_skills(ctx)
    assert f.status == PASS
