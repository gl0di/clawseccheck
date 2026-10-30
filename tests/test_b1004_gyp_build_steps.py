"""B-1004: node-gyp build steps (`actions` / `rules` / `postbuilds`) in a `binding.gyp`.

npm runs `node-gyp rebuild` for a package that ships a `binding.gyp` and declares no
install script, and node-gyp then executes every build-step `action` argv in it - code at
install time with no lifecycle script at all. MAL-2026-18377 (`spectral-core`) shipped
exactly that: `gypfile: true`, a `type: none` target with no sources, and one inline
`node -e` action. `--vet` read it as INSTALL with any host not on the paste-host list.

Two consumers, two verdicts:
  * B42 (skill install policy, --vet and audit) WARNs on a build step that runs an inline
    interpreter or matches the same `_HOOK_EXEC_RE` a postinstall hook gets, and on a
    binding.gyp it cannot read. Never FAIL: a script-file build step is how honest native
    addons build (node-sqlite3 runs `node ./extract.js` from a `type: none` target).
  * B349 (dependency tree, audit) reads a build step's script FILE through the same
    resolver and obfuscation detectors as a `<!(...)` expansion; an unreadable build
    config degrades it to UNKNOWN.

Every sample here is inert text with `.invalid` hosts; nothing is executed. Offline.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck import audit, deptree
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_dependency_tree_hooks, vet_skill
from clawseccheck.dossier import build_profile

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
BAD = FIXTURES / "bad_b42_gyp_inline_action"
CLEAN = FIXTURES / "clean_b42_gyp_native_action"
NONLITERAL = FIXTURES / "warn_b42_gyp_nonliteral"
DEPTREE = FIXTURES / "deptree_gyp_actions_pkg"


def _b42_vet(path: Path):
    f = vet_skill(path)
    return next((x for x in [f, *getattr(f, "ring_findings", [])] if x.id == "B42"), None)


def _verdict(path: Path) -> str:
    return build_profile(vet_skill(path), str(path), "skill").verdict


# ---------------------------------------------------------------------------
# --vet, end to end on the fixtures
# ---------------------------------------------------------------------------

def test_inline_build_step_warns_and_is_no_longer_install():
    b42 = _b42_vet(BAD)
    assert b42 is not None and b42.status == WARN
    assert any("binding.gyp action 'configure'" in e for e in b42.evidence)
    assert _verdict(BAD) == "CAUTION"


def test_honest_native_build_with_actions_stays_clean():
    """The node-sqlite3 shape: `type: none`, no sources, a script-file action - plus the
    ordinary `<!(node -p ...)` N-API include expansion, which B42 does not judge."""
    assert _b42_vet(CLEAN) is None  # --vet keeps only FAIL/WARN ring findings
    assert _verdict(CLEAN) == "INSTALL"


def test_unreadable_build_config_warns_rather_than_reading_as_install():
    """gyp `eval`s the file, so `'-' + 'e'` runs unchanged under node-gyp while a literal
    parser cannot read it. A ring UNKNOWN is dropped by --vet, so this must be a WARN."""
    b42 = _b42_vet(NONLITERAL)
    assert b42 is not None and b42.status == WARN
    assert any("not a plain literal" in e for e in b42.evidence)
    assert _verdict(NONLITERAL) == "CAUTION"


def test_archive_target_is_read_too(tmp_path):
    """An npm tarball nests the package under `package/`; the shape still has to WARN."""
    import tarfile

    tgz = tmp_path / "pkg.tgz"
    with tarfile.open(tgz, "w:gz") as tar:
        for f in BAD.iterdir():
            tar.add(f, arcname=f"package/{f.name}")
    b42 = _b42_vet(tgz)
    assert b42 is not None and b42.status == WARN


# ---------------------------------------------------------------------------
# B42 in the audit (installed skills under an OpenClaw home)
# ---------------------------------------------------------------------------

def _home_with(tmp_path: Path, fixture: Path) -> Path:
    d = tmp_path / "skills" / fixture.name
    d.mkdir(parents=True)
    for f in fixture.rglob("*"):
        if f.is_file():
            dest = d / f.relative_to(fixture)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(f.read_bytes())
    (tmp_path / "skills").chmod(0o700)
    d.chmod(0o700)
    return tmp_path


@pytest.mark.parametrize("fixture,status", [(BAD, WARN), (CLEAN, PASS), (NONLITERAL, WARN)])
def test_audit_b42_matches_vet(tmp_path, fixture, status):
    _, findings, _ = audit(str(_home_with(tmp_path, fixture)))
    assert next(f for f in findings if f.id == "B42").status == status


# ---------------------------------------------------------------------------
# deptree.extract_gyp_build_steps - literal parse, grounded keys
# ---------------------------------------------------------------------------

def _argvs(text: str):
    steps, _ = deptree.extract_gyp_build_steps(text)
    return sorted((s.key, s.argv) for s in steps)


def test_reads_actions_rules_and_postbuilds_anywhere_including_conditions():
    text = """{
      'target_defaults': {'postbuilds': [{'postbuild_name': 'p', 'action': ['sh', '-c', 'x']}]},
      'targets': [{
        'target_name': 't',
        'conditions': [['OS=="linux"', {'actions+': [{'action_name': 'a', 'inputs': [],
                                                      'outputs': [], 'action': ['node', 'a.js']}]}]],
        'rules': [{'rule_name': 'r', 'extension': 'idl', 'action': ['python', 'gen.py']}],
        'copies': [{'destination': 'out', 'files': ['f']}],
      }],
    }"""
    assert _argvs(text) == [
        ("actions", ("node", "a.js")),
        ("postbuilds", ("sh", "-c", "x")),
        ("rules", ("python", "gen.py")),
    ]


def test_json_style_build_config_is_read():
    """The real sample was written as JSON, which is also a Python literal."""
    steps, _ = deptree.extract_gyp_build_steps((BAD / "binding.gyp").read_text())
    assert [s.argv[:2] for s in steps] == [("node", "-e")]


@pytest.mark.parametrize("text", [
    "{'targets': [{'actions': [{'action': ['node', '-' + 'e', 'x']}]}]}",  # gyp accepts, literal does not
    "['not', 'a', 'dict']",
    "{'targets': [",  # malformed
    "{'a': true}",  # JSON keyword: gyp itself rejects it too, we still claim nothing
])
def test_a_config_that_is_not_a_plain_literal_dict_is_disclosed(text):
    capped: list = []
    steps, _ = deptree.extract_gyp_build_steps(text, capped=capped)
    assert steps == ()
    assert capped


def test_no_build_steps_is_not_a_cap():
    capped: list = []
    assert deptree.extract_gyp_build_steps("{'targets': [{'sources': ['a.cc']}]}", capped=capped) == ((), {})
    assert capped == []


def test_build_step_cap_is_disclosed():
    actions = ", ".join(
        f"{{'action_name': 'a{i}', 'action': ['node', 'f{i}.js']}}"
        for i in range(deptree.MAX_GYP_ACTIONS + 5)
    )
    capped: list = []
    steps, _ = deptree.extract_gyp_build_steps(f"{{'targets': [{{'actions': [{actions}]}}]}}", capped=capped)
    assert len(steps) == deptree.MAX_GYP_ACTIONS
    assert capped


def test_deep_nesting_does_not_raise():
    capped: list = []
    deptree.extract_gyp_build_steps("[" * 5000 + "]" * 5000, capped=capped)
    assert capped


# ---------------------------------------------------------------------------
# deptree.runs_inline_code - the discriminator
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("argv", [
    ["node", "-e", "x"],
    ["node", "--eval", "x"],
    ["node", "--eval=x"],
    ["node", "-p", "x"],
    ["node", "-pe", "x"],
    ["node", "--no-warnings", "-e", "x"],
    ["node", "-r", "./pre.js", "-e", "x"],
    ["/usr/bin/node", "-e", "x"],
    ["node.exe", "-e", "x"],
    ["nodejs", "-e", "x"],
    ["env", "node", "-e", "x"],
    ["/usr/bin/env", "FOO=1", "node", "-e", "x"],
    ["python3", "-c", "x"],
    ["python", "-Bc", "x"],
    ["python3.12", "-c", "x"],
    ["sh", "-c", "x"],
    ["bash", "-lc", "x"],
    ["bash", "-o", "pipefail", "-c", "x"],
    ["perl", "-ne", "x"],
    ["ruby", "-e", "x"],
    ["cmd", "/c", "x"],
    ["powershell", "-NoProfile", "-Command", "x"],
    ["pwsh", "-EncodedCommand", "eA=="],
])
def test_inline_interpreter_shapes(argv):
    assert deptree.runs_inline_code(argv)


@pytest.mark.parametrize("argv", [
    ["node", "./extract.js", "a.tar.gz", "out"],  # node-sqlite3
    ["node", "copy.js", "out", ""],  # better-sqlite3
    ["node", "build.js", "-e", "prod"],  # a flag AFTER the script is the script's own
    ["python", "<(DEPTH)/gen.py", "-o", "out"],  # Chromium testdata in node-gyp
    ["python", "-m", "grpc_tools.protoc", "-I."],
    ["bash", "script.sh", "-c", "x"],
    ["node", "-r", "./pre.js", "main.js"],
    ["protoc", "-e", "x"],  # not an interpreter
    ["<(unresolved)", "build.js"],
    [],
])
def test_script_file_and_non_interpreter_shapes(argv):
    assert not deptree.runs_inline_code(argv)


def test_a_gyp_variable_interpreter_is_resolved():
    assert deptree.runs_inline_code(["<(n)", "-e", "x"], {"n": "node"})
    assert deptree.runs_inline_code(["<(a)", "-e", "x"], {"a": "<(b)", "b": "node"})
    assert not deptree.runs_inline_code(["<(n)", "build.js"], {"n": "node"})


def test_an_unresolved_variable_with_an_inline_switch_counts():
    assert deptree.runs_inline_code(["<(who_knows)", "-e", "x"], {})


def test_variables_feed_the_resolver_from_the_file():
    text = "{'variables': {'n%': 'node'}, 'targets': [{'actions': [{'action': ['<(n)', '-e', 'x']}]}]}"
    steps, variables = deptree.extract_gyp_build_steps(text)
    assert variables == {"n": "node"}
    assert deptree.runs_inline_code(steps[0].argv, variables)


# ---------------------------------------------------------------------------
# B349 - the dependency tree reads build steps too
# ---------------------------------------------------------------------------

class _Ctx:
    def __init__(self, nm_root):
        self.openclaw_pkg_root = None
        self.dep_tree = deptree.scan_dep_tree(nm_root)


def test_b349_fixture_fails_on_the_obfuscated_build_step_target_only():
    f = check_dependency_tree_hooks(_Ctx(DEPTREE / "node_modules"))
    assert f.status == FAIL
    assert len(f.evidence) == 1
    assert f.evidence[0].startswith("gyp-action-pkg (gyp-action-pkg) binding.gyp actions: node setup.js")


def _tree(tmp_path: Path, name: str, gyp: str, files=None) -> Path:
    d = tmp_path / "node_modules" / name
    d.mkdir(parents=True)
    (d / "package.json").write_text(json.dumps({"name": name, "version": "1.0.0", "gypfile": True}))
    (d / "binding.gyp").write_text(gyp)
    for rel, body in (files or {}).items():
        (d / rel).write_text(body)
    return tmp_path / "node_modules"


def test_b349_honest_build_step_passes(tmp_path):
    nm = _tree(tmp_path, "native", (CLEAN / "binding.gyp").read_text(),
               {"extract.js": (CLEAN / "extract.js").read_text()})
    scan = deptree.scan_dep_tree(nm)
    assert any(d.kind == "actions" and [t.name for t in d.targets] == ["extract.js"]
               for d in scan.build_directives), "the script file must actually be read"
    assert check_dependency_tree_hooks(_Ctx(nm)).status == PASS


def test_b349_inline_build_step_has_no_target_and_no_verdict(tmp_path):
    """Same contract as an inline `<!(node -e ...)` expansion: nothing on disk to read."""
    nm = _tree(tmp_path, "inline", (BAD / "binding.gyp").read_text())
    scan = deptree.scan_dep_tree(nm)
    assert [(d.kind, d.targets) for d in scan.build_directives] == [("actions", ())]
    assert check_dependency_tree_hooks(_Ctx(nm)).status == PASS


def test_b349_unreadable_build_config_is_unknown(tmp_path):
    nm = _tree(tmp_path, "nonliteral", (NONLITERAL / "binding.gyp").read_text())
    f = check_dependency_tree_hooks(_Ctx(nm))
    assert f.status == UNKNOWN
    assert any("not a plain literal" in e for e in f.evidence)
