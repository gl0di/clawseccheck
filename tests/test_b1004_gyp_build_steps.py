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

import sys
import json
from pathlib import Path

import pytest

from clawseccheck import audit, deptree, gypbuild
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
# gypbuild.parse_gyp_build_config - literal parse, grounded keys
# ---------------------------------------------------------------------------

def _argvs(text: str):
    cfg = deptree.parse_gyp_build_config(text)
    return sorted((s.key, s.argv) for s in cfg.steps)


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


def test_conditions_inside_an_action_entry_supply_the_argv():
    """C-135 item 7: gyp processes conditions in every dict, so a branch inside the entry
    can set (`action`, `action=`) or extend (`action+`) the argv."""
    text = """{'targets': [{'actions': [{
        'action_name': 'a', 'inputs': [], 'outputs': [],
        'conditions': [['OS=="linux"', {'action': ['node', '-e', 'x']}, {'action=': ['true']}]],
    }, {
        'action_name': 'b', 'inputs': [], 'outputs': [], 'action': ['node'],
        'conditions': [['1==1', {'action+': ['-e', 'y']}]],
    }]}]}"""
    argvs = [a for _, a in _argvs(text)]
    assert ("node", "-e", "x") in argvs and ("true",) in argvs
    assert ("node", "-e", "y") in argvs


def test_nested_conditions_inside_an_action_entry_are_unexamined():
    text = """{'targets': [{'actions': [{'action_name': 'a', 'inputs': [], 'outputs': [],
        'conditions': [['1', {'conditions': [['1', {'action': ['node', '-e', 'x']}]]}]]}]}]}"""
    cfg = deptree.parse_gyp_build_config(text)
    assert [s.unexamined != "" for s in cfg.steps] == [True]


def test_json_style_build_config_is_read():
    """The real sample was written as JSON, which is also a Python literal."""
    cfg = deptree.parse_gyp_build_config((BAD / "binding.gyp").read_text())
    assert [s.argv[:2] for s in cfg.steps] == [("node", "-e")]


@pytest.mark.parametrize("text", [
    "{'targets': [{'actions': [{'action': ['node', '-' + 'e', 'x']}]}]}",  # gyp accepts, literal does not
    "['not', 'a', 'dict']",
    "{'targets': [",  # malformed
    "{'a': true}",  # JSON keyword: gyp itself rejects it too, we still claim nothing
    "﻿{'targets': []}",  # BOM: gyp's own eval rejects it as well
])
def test_a_config_that_is_not_a_plain_literal_dict_is_disclosed(text):
    capped: list = []
    cfg = deptree.parse_gyp_build_config(text, capped=capped)
    assert cfg.steps == ()
    assert capped


def test_no_build_steps_is_not_a_cap():
    capped: list = []
    cfg = deptree.parse_gyp_build_config("{'targets': [{'sources': ['a.cc']}]}", capped=capped)
    assert cfg.steps == () and capped == []


def test_build_step_cap_is_disclosed():
    actions = ", ".join(
        f"{{'action_name': 'a{i}', 'action': ['node', 'f{i}.js']}}"
        for i in range(gypbuild.MAX_GYP_ACTIONS + 5)
    )
    capped: list = []
    cfg = deptree.parse_gyp_build_config(f"{{'targets': [{{'actions': [{actions}]}}]}}", capped=capped)
    assert len(cfg.steps) == gypbuild.MAX_GYP_ACTIONS
    assert capped


def test_deep_nesting_does_not_raise():
    capped: list = []
    deptree.parse_gyp_build_config("[" * 5000 + "]" * 5000, capped=capped)
    assert capped


def test_references_are_collected_but_expansions_and_same_file_targets_are_not():
    cfg = deptree.parse_gyp_build_config(
        "{'includes': ['common.gypi'], 'targets': [{'dependencies': ['deps/x.gyp:x', 'local_t',"
        " \"<!(node -p \\\"require('node-addon-api').gyp\\\")\"]}]}"
    )
    assert cfg.references[:2] == (("includes", "common.gypi"), ("dependencies", "deps/x.gyp:x"))
    assert all(v != "local_t" for _, v in cfg.references)


# ---------------------------------------------------------------------------
# gypbuild.classify_build_step - the discriminator
# ---------------------------------------------------------------------------

def _kind(argv, variables=None):
    r = deptree.classify_build_step(argv, variables or {})
    return r and r[0]


@pytest.mark.parametrize("argv", [
    ["node", "-e", "x"], ["node", "--eval", "x"], ["node", "--eval=x"], ["node", "-p", "x"],
    ["node", "-pe", "x"], ["node", "--no-warnings", "-e", "x"], ["node", "-r", "./pre.js", "-e", "x"],
    ["/usr/bin/node", "-e", "x"], ["node.exe", "-e", "x"], ["NODE", "-e", "x"], ["nodejs", "-e", "x"],
    # C-135 item 4: an unlisted value-taking option no longer hides the switch
    ["node", "--disable-warning", "DEP0040", "-p", "x"], ["node", "--unhandled-rejections", "strict", "-p", "x"],
    ["node", "--env-file", "/dev/null", "-p", "x"], ["node", "--inspect-port", "9", "-p", "x"],
    ["python3", "--check-hash-based-pycs", "default", "-c", "x"],
    ["node", "--import", "data:text/javascript,1", "x.js"], ["node", "--import=data:text/javascript,1"],
    # item 5: wrappers
    ["env", "node", "-e", "x"], ["/usr/bin/env", "FOO=1", "node", "-e", "x"], ["env", "-u", "X", "node", "-pe", "x"],
    ["env", "-C", "/tmp", "node", "-p", "x"], ["env", "--chdir", "/tmp", "node", "-p", "x"],
    ["env", "-S", "node -e x"], ["env", "NODE_OPTIONS=--import=data:text/javascript,1", "node", "x.js"],
    ["nice", "node", "--eval", "x"], ["nice", "-n", "5", "node", "-e", "x"], ["timeout", "5", "python3", "-Ic", "x"],
    ["timeout", "-s", "KILL", "5", "node", "-e", "x"], ["nohup", "node", "-e", "x"], ["command", "node", "-e", "x"],
    ["xargs", "-0", "node", "-e", "x"], ["timeout", "--unknown-opt", "v", "node", "-e", "x"],
    # item 6: interpreters and glued switches
    ["python3", "-c", "x"], ["python", "-Bc", "x"], [f"python3.{sys.version_info.minor}", "-c", "x"], ["python3.13t", "-c", "x"],
    ["pypy3", "-c", "x"], ["python3", "-cimport os"], ["perl", "-ne", "x"], ["perl", "-eprint 1"],
    ["ruby", "-e", "x"], ["ruby", "-eputs 1"], ["php", "-r", "x"], ["lua", "-e", "x"], ["osascript", "-e", "x"],
    ["deno", "eval", "x"], ["bun", "-e", "x"],
])
def test_inline_interpreter_shapes(argv):
    assert _kind(argv) == "inline", argv


@pytest.mark.parametrize("argv", [
    ["sh", "-c", "x"], ["bash", "-lc", "cd x && make"], ["bash", "-o", "pipefail", "-c", "x"],
    ["ash", "-c", "x"], ["fish", "-c", "x"], ["tcsh", "-c", "x"], ["csh", "-c", "x"], ["mksh", "-c", "x"],
    ["busybox", "sh", "-c", "x"], ["cmd", "/c", "dir"], ["cmd.exe", "/q", "/s", "/d", "/c", "dir"],
    ["CMD", "/C", "dir"], ["powershell", "-NoProfile", "-Command", "Get-Date"],
    ["pwsh", "-EncodedCommand", "eA=="], ["eval", "true"],
])
def test_inline_shell_shapes(argv):
    assert _kind(argv) == "shell", argv


@pytest.mark.parametrize("argv", [
    ["node", "./extract.js", "a.tar.gz", "out"],  # node-sqlite3
    ["node", "copy.js", "out", ""],  # better-sqlite3
    ["node", "build.js", "-e", "prod"],  # a flag AFTER the script is the script's own
    ["node", "x.js", "--", "-e"], ["node", "--", "-e", "x"],
    ["python", "<(DEPTH)/gen.py", "-o", "out"],  # Chromium testdata in node-gyp
    ["python", "-m", "grpc_tools.protoc", "-I."], ["python", "gen-code.py", "-c", "cfg.json"],
    ["bash", "script.sh", "-c", "x"], ["node", "-r", "./pre.js", "main.js"], ["node", "-c", "x.js"],
    ["protoc", "-e", "x"], ["<(unresolved)", "build.js"], ["<(python)", "gen.py"], [],
    # C-135 item 1: paths and resolved variables
    ["<(PRODUCT_DIR)/mytool", "-p", "x"], ["$(srcdir)/tool", "-e", "x"], ["$(CC)", "-c", "x.c"],
    ["<(cc)", "-c", "x.c"], ["./tools/gen", "-e", "x"], ["xcrun", "clang", "-c", "x.c"],
    # item 2: script files with words the old joined-string pattern matched
    ["bash", "scripts/gen.sh"], ["bash", "-e", "gen.sh"], ["bash", "-eu", "gen.sh"], ["sh", "-x", "gen.sh"],
    ["powershell", "-NoProfile", "-File", "build.ps1"], ["powershell", "-ExecutionPolicy", "Bypass", "-File", "build.ps1"],
    ["pwsh", "-File", "build.ps1"], ["python", "tools/base64_embed.py", "in", "out"],
    ["python", "embed.py", "--encoding=base64", "x"], ["python", "download.py", "https://example.invalid/x.tar.gz"],
    # item 3: an inline switch that runs one plain script file
    ["cmd", "/c", "build.bat"], ["sh", "-c", "./build.sh"], ["powershell", "-Command", "./build.ps1"],
    ["env", "FOO=1", "python", "gen.py"], ["python", "-W", "ignore", "gen.py"], ["perl", "-I", "lib", "gen.pl"],
])
def test_script_file_and_non_interpreter_shapes(argv):
    assert deptree.classify_build_step(argv, {}) is None, argv


def test_a_download_at_build_time_is_named():
    assert deptree.classify_build_step(["curl", "-o", "x", "https://example.invalid/x"], {}) == ("fetch", "curl")


def test_a_resolved_non_interpreter_variable_stays_quiet():
    assert deptree.classify_build_step(["<(cc)", "-c", "x.c"], {"cc": "gcc"}) is None
    assert deptree.classify_build_step(["<(cc)", "-c", "x"], {"cc": "gcc"}) is None


def test_a_gyp_variable_interpreter_is_resolved():
    assert _kind(["<(n)", "-e", "x"], {"n": "node"}) == "inline"
    assert _kind(["<(a)", "-e", "x"], {"a": "<(b)", "b": "node"}) == "inline"
    assert deptree.classify_build_step(["<(n)", "build.js"], {"n": "node"}) is None


def test_every_value_of_a_redefined_variable_is_tried():
    """gyp scopes variables per dict; a second same-named definition must not hide one."""
    assert _kind(["<(n)", "-e", "x"], {"n": ("gcc", "node")}) == "inline"


def test_list_splice_and_switch_from_a_variable():
    """C-135 item 7: `<@(cmd)` and `node <(f)` are expanded before the argv is judged."""
    assert _kind(["<@(cmd)"], {"cmd": ["node", "-e", "x"]}) == "inline"
    assert _kind(["node", "<(f)", "x"], {"f": "-e"}) == "inline"
    assert _kind(["<@(cmd)"], {}) == "unresolved"
    assert _kind(["node", "<(f)", "x"], {}) == "unresolved"


def test_an_unresolved_program_given_inline_code_is_unresolved():
    assert _kind(["<(who_knows)", "-e", "require('x')"], {}) == "unresolved"


def test_variables_feed_the_resolver_from_the_file():
    text = "{'variables': {'n%': 'node'}, 'targets': [{'actions': [{'action': ['<(n)', '-e', 'x']}]}]}"
    cfg = deptree.parse_gyp_build_config(text)
    assert cfg.variables == {"n": ("node",)}
    assert deptree.runs_inline_code(cfg.steps[0].argv, cfg.variables)


# ---------------------------------------------------------------------------
# B42 end to end on constructed skills (C-135 items 8-13)
# ---------------------------------------------------------------------------

_INLINE_STEP = ("{'targets': [{'target_name': 't', 'type': 'none', 'actions': [{'action_name': 'a',"
                " 'inputs': [], 'outputs': ['x'], 'action': ['node', '-e', 'console.log(1)']}]}]}")
_FILE_STEP = ("{'targets': [{'target_name': 't', 'type': 'none', 'actions': [{'action_name': 'a',"
              " 'inputs': [], 'outputs': ['x'], 'action': ['node', './gen.js']}]}]}")


def _skill(tmp_path: Path, files: dict, manifest=None) -> Path:
    d = tmp_path / "s"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("---\nname: s\ndescription: Native helper.\n---\n# s\n")
    (d / "package.json").write_text(json.dumps(manifest or {"name": "s", "version": "1.0.0", "gypfile": True}))
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return d


def _b42_detail(path: Path) -> str:
    b42 = _b42_vet(path)
    return "" if b42 is None else b42.status + " " + b42.detail


def test_included_file_is_followed(tmp_path):
    bad = _skill(tmp_path / "b", {"binding.gyp": "{'includes': ['common.gypi'], 'targets': []}",
                                  "common.gypi": "{'target_defaults': {'actions': [{'action_name': 'a', 'inputs': [],"
                                                 " 'outputs': ['x'], 'action': ['node', '-e', 'console.log(1)']}]}}"})
    assert "common.gypi action 'a' runs inline node code" in _b42_detail(bad)
    clean = _skill(tmp_path / "c", {"binding.gyp": "{'includes': ['common.gypi'], 'targets': []}",
                                    "common.gypi": "{'variables': {'x': '1'}}"})
    assert _b42_vet(clean) is None


def test_dependency_gyp_is_followed_and_a_missing_one_is_disclosed(tmp_path):
    bad = _skill(tmp_path / "b", {"binding.gyp": "{'targets': [{'target_name': 't', 'dependencies': ['deps/x.gyp:x']}]}",
                                  "deps/x.gyp": _INLINE_STEP})
    assert "deps/x.gyp action 'a' runs inline node code" in _b42_detail(bad)
    clean = _skill(tmp_path / "c", {"binding.gyp": "{'targets': [{'target_name': 't', 'dependencies': ['deps/x.gyp:x']}]}",
                                    "deps/x.gyp": _FILE_STEP, "deps/gen.js": "// gen\n"})
    assert _b42_vet(clean) is None
    missing = _skill(tmp_path / "m", {"binding.gyp": "{'targets': [{'target_name': 't', 'dependencies': ['../x.gyp:x']}]}"})
    assert "was not read" in _b42_detail(missing)


def test_zip_and_tgz_and_zip_in_dir_agree(tmp_path):
    """C-135 item 9: a .zip member's blob header kept the archive prefix, so it was missed."""
    import tarfile
    import zipfile

    src = _skill(tmp_path / "src", {"binding.gyp": _INLINE_STEP})
    zp = tmp_path / "s.zip"
    with zipfile.ZipFile(zp, "w") as z:
        for f in src.iterdir():
            z.write(f, f.name)
    tg = tmp_path / "s.tgz"
    with tarfile.open(tg, "w:gz") as t:
        for f in src.iterdir():
            t.add(f, arcname=f"package/{f.name}")
    holder = tmp_path / "holder"
    holder.mkdir()
    (holder / "SKILL.md").write_text("# holder\n")
    (holder / "s.zip").write_bytes(zp.read_bytes())
    for target in (zp, tg, holder):
        assert "runs inline node code" in _b42_detail(target), target.name


def test_root_binding_gyp_is_read_from_disk_past_the_blob_caps(tmp_path):
    """C-135 item 10: a padded binding.gyp, or one crowded out of the blob by 500+ files,
    used to read PASS on a file nobody read."""
    crowded = _skill(tmp_path / "c", {"binding.gyp": _INLINE_STEP,
                                      **{f"a{i}.js": f"// {i}\n" for i in range(600)}})
    assert "runs inline node code" in _b42_detail(crowded)
    big = _skill(tmp_path / "b", {"binding.gyp": "#" + "pad" * 400_000 + "\n" + _INLINE_STEP})
    assert "too large to examine" in _b42_detail(big)
    header = _skill(tmp_path / "h", {"binding.gyp": "# file: notes.txt\n" + _INLINE_STEP})
    assert "runs inline node code" in _b42_detail(header)


def test_a_nested_binding_gyp_is_not_claimed_to_run(tmp_path):
    """npm builds the ROOT binding.gyp only (@npmcli/node-gyp stats `${path}/binding.gyp`)."""
    assert _b42_vet(_skill(tmp_path, {"src/binding.gyp": _INLINE_STEP})) is None


@pytest.mark.parametrize("manifest,phrase", [
    ({"name": "s", "gypfile": True}, "npm runs node-gyp for it on install"),
    ({"name": "s", "gypfile": False}, "gypfile is false, so npm does not build it automatically"),
    ({"name": "s", "scripts": {"install": "node-gyp rebuild"}}, "declares its own install/preinstall script"),
    ({"name": "s", "scripts": {"preinstall": "true"}}, "declares its own install/preinstall script"),
])
def test_trigger_wording_is_true_for_the_manifest(tmp_path, manifest, phrase):
    """C-135 item 12: the claim that npm builds it must match npm's own gate."""
    f = vet_skill(_skill(tmp_path, {"binding.gyp": _INLINE_STEP}, manifest))
    b42 = next(x for x in [f, *getattr(f, "ring_findings", [])] if x.id == "B42")
    assert phrase in b42.detail
    assert "npm install --ignore-scripts" in b42.fix


def test_axes_do_not_say_there_is_no_code(tmp_path):
    """C-135 item 13: B42 says the binding.gyp runs code; Persistence/Connections must not
    answer 'no executable code to analyze' about the same skill."""
    d = _skill(tmp_path, {"binding.gyp": _INLINE_STEP})
    prof = build_profile(vet_skill(d), str(d), "skill")
    reasons = {a.axis: a.reason for a in prof.axes}
    for axis in ("persistence", "connections"):
        assert "no executable code" not in reasons[axis]
        assert "no reader" in reasons[axis]


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


# ---------------------------------------------------------------------------
# C-135 round 2 - every case through the real path (vet_skill -> B42 / dossier)
# ---------------------------------------------------------------------------

def _act(argv, extra: str = "", top: str = "") -> str:
    """A binding.gyp with one action; *extra* is spliced into the action entry, *top* into
    the top-level dict."""
    return ("{" + top + "'targets': [{'target_name': 't', 'type': 'none', 'actions': [{"
            "'action_name': 'a', 'inputs': [], 'outputs': ['x'], 'action': " + repr(list(argv))
            + extra + "}]}]}")


_ROUND2 = [
    # item 1: variables resolve at the call site (t4 / n20 / n21)
    ("t4 list splice", {"binding.gyp": _act(["<@(cmd)"], top="'variables': {'cmd': ['node', '-e', 'x']}, ")}, "runs inline node code"),
    ("n20 switch from a variable", {"binding.gyp": _act(["node", "<(f)", "x"], top="'variables': {'f': '-e'}, ")}, "runs inline node code"),
    ("n21 both from variables", {"binding.gyp": _act(["<(n)", "<(f)", "x"], top="'variables': {'n': 'node', 'f': '-e'}, ")}, "runs inline node code"),
    # item 2: wrapper depth
    ("n1 env x7", {"binding.gyp": _act(["env"] * 7 + ["node", "-pe", "1"])}, "runs inline node code"),
    # item 3: option tokens with a script extension do not end the scan
    ("n2 --title=x.js", {"binding.gyp": _act(["node", "--title=x.js", "-e", "1"])}, "runs inline node code"),
    ("--title x.js", {"binding.gyp": _act(["node", "--title", "x.js", "-e", "1"])}, "runs inline node code"),
    ("n17 python -Xa.py", {"binding.gyp": _act(["python3", "-Xa.py", "-c", "1"])}, "runs inline python3 code"),
    ("perl -i.js", {"binding.gyp": _act(["perl", "-i.js", "-e", "1"])}, "runs inline perl code"),
    ("bash --rcfile a.sh", {"binding.gyp": _act(["bash", "--rcfile", "a.sh", "-c", "echo"])}, "inline shell command"),
    # item 4: list filters
    ("n3 action!", {"binding.gyp": _act(["node", "safe.js", "-e", "1"], extra=", 'action!': ['safe.js']"),
                    "safe.js": "//\n"}, "list filter"),
    ("action/", {"binding.gyp": _act(["node", "safe.js", "-e", "1"], extra=", 'action/': [['exclude', 'safe']]"),
                 "safe.js": "//\n"}, "list filter"),
    # item 5: variable syntax and gyp's automatic variables
    ("n4 ^(n)", {"binding.gyp": _act(["^(n)", "-e", "1"], top="'variables': {'n': 'node'}, ")}, "runs inline node code"),
    ("dashed name", {"binding.gyp": _act(["<(my-interp)", "-e", "1"], top="'variables': {'my-interp': 'node'}, ")}, "runs inline node code"),
    ("n22 _key", {"binding.gyp": _act(["<(_p)", "<(_f)", "<(_c)"], extra=", 'p': 'node', 'f': '-e', 'c': '1'")}, "runs inline node code"),
    ("n23 _inputs idiom", {"binding.gyp": "{'targets': [{'target_name': 't', 'type': 'none', 'actions': [{'action_name': 'a', "
                           "'inputs': ['tools/gen.py', 'data.txt'], 'outputs': ['x'], 'action': ['python', '<@(_inputs)', '<@(_outputs)']}]}]}",
                           "tools/gen.py": "print(1)\n"}, None),
    ("undefined is named truly", {"binding.gyp": _act(["node", "<(nowhere)", "1"])}, "which no build file read here defines"),
    # item 6: the combination cap is not a PASS
    ("n6 cap", {"binding.gyp": "{'targets': [{'target_name': 't', 'type': 'none', 'variables': {'a': 'gcc'}, 'conditions': ["
                + ", ".join(f"['OS==\"n{i}\"', {{'variables': {{'b': '--x{i}', 'a': 'cc{i}'}}}}]" for i in range(40))
                + "], 'actions': [{'action_name': 'a', 'inputs': [], 'outputs': ['x'], 'action': ['<(a)', '<(b)', '1']}]}]}"},
     "more gyp variable combinations"),
    # item 7: node-gyp's implicit root includes
    ("n5 common.gypi", {"binding.gyp": "{'targets': [{'target_name': 't', 'sources': ['a.cc']}]}", "a.cc": "int x;\n",
                        "common.gypi": "{'target_defaults': {'actions': [{'action_name': 'a', 'inputs': [], 'outputs': ['x'], 'action': ['node', '-e', '1']}]}}"},
     "common.gypi action 'a' runs inline node code"),
    ("n5b config.gypi", {"binding.gyp": "{'targets': [{'target_name': 't', 'sources': ['a.cc']}]}", "a.cc": "int x;\n",
                         "config.gypi": "{'target_defaults': {'actions': [{'action_name': 'a', 'inputs': [], 'outputs': ['x'], 'action': ['node', '-e', '1']}]}}"},
     "config.gypi action 'a' runs inline node code"),
    # item 8: make / shell substitution in any argument
    ("n24 $(shell", {"binding.gyp": _act(["touch", '$(shell node -e "1")'])}, "command substitution"),
    ("n25 $$(", {"binding.gyp": _act(["touch", '$$(node -e "1")'])}, "command substitution"),
    ("backtick", {"binding.gyp": _act(["touch", "`node -e 1`"])}, "command substitution"),
    # item 9: interpreter at any position, more interpreters and fetchers
    ("n8 chroot", {"binding.gyp": _act(["chroot", "/", "node", "-e", "1"])}, "runs inline node code"),
    ("find -exec", {"binding.gyp": _act(["find", ".", "-exec", "node", "-e", "1", ";"])}, "runs inline node code"),
    ("n9 awk", {"binding.gyp": _act(["awk", 'BEGIN{system("true")}'])}, "runs inline awk code"),
    ("n7 powershell -enc", {"binding.gyp": _act(["powershell", "-NoP", "-enc", "AAAA"])}, "inline shell command"),
    ("cmd /cnode", {"binding.gyp": _act(["cmd", "/cnode -e 1"])}, "inline shell command"),
    ("git clone", {"binding.gyp": _act(["git", "clone", "https://example.invalid/r"])}, "fetches with git clone"),
    ("Rscript", {"binding.gyp": _act(["Rscript", "-e", "1"])}, "runs inline rscript code"),
    # item 10: an included file named by a command expansion
    ("includes <!", {"binding.gyp": "{'includes': ['<!(node -p \"x\")'], 'targets': []}"}, "named by a command expansion"),
    # honest shapes stay quiet on the real path
    ("n18 honest mix", {"binding.gyp": "{'targets': [{'target_name': 't', 'type': 'none', 'actions': ["
                        "{'action_name': 'p', 'inputs': [], 'outputs': ['x'], 'action': ['python3', 'tools/protoc_wrapper.py', '--include', 'x', '-c', 'cfg', '-e', 'x']},"
                        "{'action_name': 'f', 'inputs': [], 'outputs': ['x'], 'action': ['<(PRODUCT_DIR)/flatc', '-c', '-o', 'out', 'schema.fbs']},"
                        "{'action_name': 'c', 'inputs': [], 'outputs': ['x'], 'action': ['cmake', '-S', '.', '-B', 'build']},"
                        "{'action_name': 'n', 'inputs': [], 'outputs': ['x'], 'action': ['node', 'tools/gen.js', '<@(_inputs)']}]}]}",
                        "tools/protoc_wrapper.py": "print(1)\n", "tools/gen.js": "//\n"}, None),
    ("n19 honest per-OS", {"binding.gyp": _act([], extra="").replace("'action': [], ", "")
                           .replace("'outputs': ['x']", "'outputs': ['x'], 'conditions': [['OS==\"win\"', {'action': ['cmd', '/c', 'build.bat']}], "
                                    "['OS!=\"win\"', {'action': ['bash', 'build.sh']}]]"),
                           "build.sh": "make\n"}, None),
]


@pytest.mark.parametrize("label,files,expect", _ROUND2, ids=[c[0] for c in _ROUND2])
def test_round2_through_vet(tmp_path, label, files, expect):
    d = _skill(tmp_path, files)
    detail = _b42_detail(d)
    if expect is None:
        assert detail == "", detail
    else:
        assert detail.startswith("WARN") and expect in detail, detail
        prof = build_profile(vet_skill(d), str(d), "skill")
        reasons = {a.axis: a.reason for a in prof.axes}
        assert "no executable code" not in reasons["persistence"], label


def test_unpacked_archive_target_that_could_not_be_unpacked_warns(tmp_path):
    """C-135 round 2 item 10: a directory with an oversized binding.gyp WARNs, so an archive
    the collector refused to unpack must not read clean."""
    import tarfile

    src = _skill(tmp_path / "src", {"binding.gyp": "#" + "pad" * 400_000 + "\n" + _INLINE_STEP})
    tg = tmp_path / "big.tgz"
    with tarfile.open(tg, "w:gz") as t:
        for f in src.iterdir():
            t.add(f, arcname=f"package/{f.name}")
    assert "was not unpacked in full" in _b42_detail(tg)
    md = tmp_path / "SKILL.md"
    md.write_text("---\nname: m\ndescription: x\n---\n# m\n")
    assert _b42_vet(md) is None  # a bare non-archive file is not an archive


def test_install_policy_variables_are_tuples_at_the_call_site(tmp_path):
    """C-135 round 2 item 1, at the function that broke: check_install_policy itself."""
    from clawseccheck.checks import check_install_policy
    from clawseccheck.collector import Context

    d = _skill(tmp_path, {"binding.gyp": _act(["<(n)", "<(f)", "x"], top="'variables': {'n': 'node', 'f': '-e'}, ")})
    ctx = Context(home=d)
    ctx.installed_skills = {"s": ""}
    f = check_install_policy(ctx)
    assert f.status == WARN and "runs inline node code" in f.detail
    assert getattr(f, "gyp_build_code", False)
