"""C-664 slice C3b: third-party JSON read without recursion and without a depth limit.

A deeply nested file used to raise ``RecursionError`` out of a check or a CLI mode, and a
fixed depth limit would have been an evasion (pad the document, the fields stop being read).
These sites now read the document with ``configloader.loads_shallow``: a field within the
shallow depth is read exactly as ``json.loads`` reads it however the file is padded, and a
subtree below it is the opaque ``ELIDED`` marker.

Converted: the ``--vet`` type detection of a ``.json`` target, the skill-frontmatter metadata
readers (B89, B103), the skill's own-host manifest, the MCP surface readers, the dependency
tree's ``package.json``, the skill provenance lock and origin records, and the OpenClaw dist
version. NOT converted (they still read with ``json.loads`` and need the shallow reader plus a
consumer that tolerates ``ELIDED``): B138, B182, B357 and the ``--vet`` detection read of the
user's ``openclaw.json``.

The one rule that holds at every converted site: an elided subtree may only stop a
"confirmed good" answer (a PASS, a trust grant, a confirmed match) from being given. It never
hides a finding the shallow fields carry (a FAIL, a WARN, a mismatch). Each hostile twin
carries the evidence plus a pad key (a 201-level and a 100,000-level array) and a pad INSIDE
the evidence-bearing record, so every field type is exercised against the marker. Offline:
the files are written under ``tmp_path``.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from clawseccheck import deptree, mcpsurface, openclawdist
from clawseccheck.checks import (
    _fm_metadata_obj,
    _fm_metadata_obj_multiline,
    _skill_own_host,
    check_dependency_tree_hooks,
    check_dormant_capability,
    check_install_directive_supply_chain,
    detect_vet_type_with_reason,
)
from clawseccheck.skillprovenance import read_provenance

PADS = (201, 100_000)


def deep(n: int) -> str:
    return "[" * n + "]" * n


def deep_obj(n: int) -> str:
    return '{"a":' * n + "0" + "}" * n


# ----------------------------------------------------------------------------- mcpsurface

def _dump(pad: str = "", inner: str = "") -> str:
    tool = (
        '{"name": "send", "description": "Sends a message.", %s'
        '"inputSchema": {"properties": {"to": {"description": "recipient", "default": %s}}},'
        '"annotations": {"readOnlyHint": true %s}}'
    ) % (
        '"title": %s,' % (inner or '"t"'),
        inner or '"x"',
        (', "zz": ' + inner) if inner else "",
    )
    return '{"server": "srv", "tools": [%s]%s}' % (tool, (', "zz": ' + pad) if pad else "")


def _tool_view(surface):
    return [(t.name, t.description, [(p.name, p.description) for p in t.params])
            for t in surface.tools]


def test_manifest_unpadded_is_unchanged(tmp_path):
    f = tmp_path / "d.json"
    f.write_text(_dump())
    surface = mcpsurface.from_manifest(f)
    assert surface is not None and surface.truncated is False
    assert _tool_view(surface) == [("send", "Sends a message.", [("to", "recipient")])]


@pytest.mark.parametrize("n", PADS)
@pytest.mark.parametrize("where", ("key", "fields"))
def test_manifest_padded_is_read_in_full_and_marked_truncated(tmp_path, n, where):
    f = tmp_path / "d.json"
    f.write_text(_dump(pad=deep(n)) if where == "key" else _dump(inner=deep(n)))
    surface = mcpsurface.from_manifest(f)
    assert surface is not None
    assert _tool_view(surface) == [("send", "Sends a message.", [("to", "recipient")])]
    assert surface.truncated is True  # an unread part: no confident PASS downstream


@pytest.mark.parametrize("doc", ("[" * 100_000 + "]" * 100_000, '{"tools":' * 100_000 + "[]" + "}" * 100_000),
                         ids=("arrays", "objects"))
def test_manifest_whole_document_deep_is_no_surface_and_no_crash(tmp_path, doc):
    f = tmp_path / "d.json"
    f.write_text(doc)
    assert mcpsurface.from_manifest(f) is None


def _probe(pad: str = "") -> str:
    return ('{"servers": {"srv": {"tools": 1}}, "tools": ["mcp__srv__send"]%s}'
            % ((', "zz": ' + pad) if pad else ""))


def test_probe_unpadded_is_unchanged(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(_probe())
    [surface] = mcpsurface.from_probe_json(f)
    assert [t.name for t in surface.tools] == ["mcp__srv__send"] and surface.truncated is False


@pytest.mark.parametrize("n", PADS)
def test_probe_padded_keeps_the_names_and_marks_truncated(tmp_path, n):
    f = tmp_path / "p.json"
    f.write_text(_probe(deep(n)))
    [surface] = mcpsurface.from_probe_json(f)
    assert [t.name for t in surface.tools] == ["mcp__srv__send"] and surface.truncated is True


def test_probe_whole_document_deep_is_no_surface_and_no_crash(tmp_path):
    f = tmp_path / "p.json"
    f.write_text("[" * 100_000 + "]" * 100_000)
    assert mcpsurface.from_probe_json(f) == []


# ----------------------------------------------------------------------------- deptree

class _Ctx:
    def __init__(self, root):
        self.openclaw_pkg_root = Path(root)
        self.dep_tree = deptree.scan_dep_tree(deptree.find_dep_tree(Path(root)))


def _package(root: Path, manifest_text: str, name: str = "evil") -> None:
    d = root / "node_modules" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "package.json").write_text(manifest_text)


def _manifest(scripts: str, pad: str = "") -> str:
    return ('{"name": "evil", "version": "1.0.0", "scripts": %s%s}'
            % (scripts, (', "zz": ' + pad) if pad else ""))


HOOK = '{"preinstall": "node steal.js"}'


def test_deptree_unpadded_hook_and_clean_are_unchanged(tmp_path):
    _package(tmp_path, _manifest(HOOK))
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert [(h.package, h.phase) for h in scan.hooks] == [("evil", "preinstall")]
    assert scan.gyp_capped == ()
    clean = tmp_path / "clean"
    clean.mkdir()
    _package(clean, '{"name": "evil", "version": "1.0.0"}')
    assert check_dependency_tree_hooks(_Ctx(clean)).status == "PASS"


@pytest.mark.parametrize("n", PADS)
@pytest.mark.parametrize("where", ("key", "scripts", "field"))
def test_deptree_padded_hook_is_still_found_and_disclosed(tmp_path, n, where):
    if where == "key":
        text = _manifest(HOOK, pad=deep(n))
    elif where == "scripts":
        text = _manifest('{"preinstall": "node steal.js", "zz": %s}' % deep(n))
    else:  # a pad in a field type the reader checks with isinstance
        text = _manifest('{"preinstall": "node steal.js", "install": %s}' % deep(n))
    _package(tmp_path, text)
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert [(h.package, h.phase) for h in scan.hooks] == [("evil", "preinstall")]
    assert len(scan.gyp_capped) == 1 and "nested deeper" in scan.gyp_capped[0]
    assert check_dependency_tree_hooks(_Ctx(tmp_path)).status in {"FAIL", "WARN", "UNKNOWN"}


@pytest.mark.parametrize("n", PADS)
def test_deptree_padded_signalled_hook_still_fails(tmp_path, n):
    """A real signal in the install target stays a FAIL: the disclosure only degrades a PASS."""
    root = tmp_path / "openclaw"
    root.mkdir()
    (root / "package.json").write_text('{"name": "openclaw"}')
    _package(root, _manifest('{"preinstall": "node s.js"}', pad=deep(n)))
    (root / "node_modules" / "evil" / "s.js").write_text(
        "const b = require('fs').readFileSync('p.b64', 'utf8');\n"
        "eval(Buffer.from(b, 'base64').toString('utf8'));\n")
    finding = check_dependency_tree_hooks(_Ctx(root))
    assert finding.status == "FAIL" and "JS_EVAL_DECODED" in "\n".join(finding.evidence or [])


@pytest.mark.parametrize("n", PADS)
def test_deptree_clean_package_padded_is_not_a_pass_and_not_an_error(tmp_path, n):
    _package(tmp_path, '{"name": "evil", "version": "1.0.0", "zz": %s}' % deep(n))
    finding = check_dependency_tree_hooks(_Ctx(tmp_path))
    assert finding.status == "UNKNOWN", finding.detail


@pytest.mark.parametrize("doc", ("[" * 100_000 + "]" * 100_000, deep_obj(100_000)), ids=("arrays", "objects"))
def test_deptree_whole_document_deep_is_unreadable_not_a_crash(tmp_path, doc):
    _package(tmp_path, doc)
    scan = deptree.scan_dep_tree(deptree.find_dep_tree(tmp_path))
    assert scan.unreadable == 1 and scan.hooks == ()


# ----------------------------------------------------------------------------- skillprovenance

_A = "e87e9a8be39c612fd572ffc56bce1623cd00aded13f71b67bf31e7c599816f7e"
_S = "17dc0cbda39c12dda19f39ec6ee0e0260edc235203957e99eda7df52071c0e26"


def _lock(pad: str = "", rec_pad: str = "") -> str:
    rec = {"version": "3.61.0", "installedAt": 1, "registry": "https://clawhub.ai",
           "artifact": {"kind": "tarball", "sha256": _A},
           "skillFile": {"path": "SKILL.md", "sha256": _S}}
    text = json.dumps({"version": 1, "skills": {"clawseccheck": rec}})
    if rec_pad:  # a pad INSIDE the record, in a field the reader checks with isinstance
        text = text.replace('"registry"', '"zz": %s, "registry"' % rec_pad)
    if pad:
        text = text[:-1] + ', "zz": %s}' % pad
    return text


def _origin(root: Path, text: str) -> None:
    d = root / "skills" / "clawseccheck" / ".clawhub"
    d.mkdir(parents=True, exist_ok=True)
    (d / "origin.json").write_text(text)


def _origin_text(pad: str = "") -> str:
    return ('{"version": 1, "installedVersion": "3.61.0", "artifact": {"sha256": "%s"}, '
            '"skillFile": {"sha256": "%s"}%s}' % (_A, _S, (', "zz": ' + pad) if pad else ""))


def _workspace(tmp_path: Path, lock_text: str) -> Path:
    root = tmp_path / "workspace"
    (root / ".clawhub").mkdir(parents=True)
    (root / ".clawhub" / "lock.json").write_text(lock_text)
    return root


def test_provenance_unpadded_is_unchanged_and_corroborated(tmp_path):
    _origin(_workspace(tmp_path, _lock()), _origin_text())
    scan = read_provenance(tmp_path)
    entry = scan.skills["clawseccheck"]
    assert (entry.version, entry.artifact_sha256, entry.corroborated) == ("3.61.0", _A, True)
    assert not any("nested deeper" in n for n in scan.notes)


@pytest.mark.parametrize("n", PADS)
@pytest.mark.parametrize("where", ("key", "record"))
def test_provenance_padded_lock_is_read_in_full_and_disclosed(tmp_path, n, where):
    text = _lock(pad=deep(n)) if where == "key" else _lock(rec_pad=deep(n))
    _workspace(tmp_path, text)
    scan = read_provenance(tmp_path)
    entry = scan.skills["clawseccheck"]
    assert (entry.version, entry.artifact_sha256, entry.skill_file_sha256) == ("3.61.0", _A, _S)
    assert any("nested deeper" in n_ for n_ in scan.notes)


@pytest.mark.parametrize("n", PADS)
def test_provenance_padded_origin_is_no_second_witness(tmp_path, n):
    _origin(_workspace(tmp_path, _lock()), _origin_text(pad=deep(n)))
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is None


@pytest.mark.parametrize("n", PADS)
def test_provenance_padded_origin_that_mismatches_is_still_a_mismatch(tmp_path, n):
    """Elision withholds a confirmation; it must never hide a disagreement (the monitor
    alerts only on `corroborated is False`)."""
    text = _origin_text(pad=deep(n)).replace(_A, "0" * 64)
    _origin(_workspace(tmp_path, _lock()), text)
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is False


def test_provenance_unpadded_origin_that_mismatches_is_false(tmp_path):
    _origin(_workspace(tmp_path, _lock()), _origin_text().replace(_A, "0" * 64))
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is False


def _nested(n: int, leaf: str = "3.61.0"):
    value = leaf
    for _ in range(n):
        value = [value]
    return value


def _records(tmp_path: Path, lock_version, origin_version, artifact=_A) -> None:
    rec = json.loads(_lock())["skills"]["clawseccheck"]
    rec["version"] = lock_version
    root = _workspace(tmp_path, json.dumps({"version": 1, "skills": {"clawseccheck": rec}}))
    origin = json.loads(_origin_text())
    origin["installedVersion"] = origin_version
    origin["artifact"]["sha256"] = artifact
    _origin(root, json.dumps(origin))


@pytest.mark.parametrize("n", (100, 150))
def test_provenance_identical_deep_versions_are_neither_confirmed_nor_refuted(tmp_path, n):
    """The lock record sits deeper than the origin, so the two cut the same list at
    different depths; that must not read as a mismatch."""
    _records(tmp_path, _nested(n), _nested(n))
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is None


def test_provenance_visible_digest_mismatch_beside_an_elided_version_is_false(tmp_path):
    _records(tmp_path, _nested(100), _nested(100), artifact="0" * 64)
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is False


def test_provenance_scalar_version_against_a_deep_version_is_false(tmp_path):
    _records(tmp_path, "3.61.0", _nested(100))
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is False


@pytest.mark.parametrize("n", PADS)
def test_provenance_whole_document_deep_origin_is_no_witness_and_no_crash(tmp_path, n):
    _origin(_workspace(tmp_path, _lock()), "[" * 100_000 + "]" * 100_000)
    assert read_provenance(tmp_path).skills["clawseccheck"].corroborated is None


def test_provenance_whole_document_deep_is_no_record_and_no_crash(tmp_path):
    _workspace(tmp_path, "[" * 100_000 + "]" * 100_000)
    assert read_provenance(tmp_path).skills == {}


# ----------------------------------------------------------------------------- openclawdist

@pytest.mark.parametrize("n", PADS)
def test_dist_version_is_read_however_the_manifest_is_padded(tmp_path, n):
    (tmp_path / "package.json").write_text('{"name": "openclaw", "zz": %s, "version": "2026.9.9"}' % deep(n))
    assert openclawdist._read_version(tmp_path) == "2026.9.9"


def test_dist_version_whole_document_deep_is_empty_not_a_crash(tmp_path):
    (tmp_path / "package.json").write_text("[" * 100_000 + "]" * 100_000)
    assert openclawdist._read_version(tmp_path) == ""


# ----------------------------------------------------------------------------- vet type detection

MCP_SPEC = '{"mcpServers": {"s": {"command": "x"}}%s}'


def _detect(tmp_path: Path, text: str, name: str = "t.json"):
    f = tmp_path / name
    f.write_text(text)
    return detect_vet_type_with_reason(f, home=tmp_path / "nohome")


def test_detect_unpadded_is_unchanged(tmp_path):
    assert _detect(tmp_path, MCP_SPEC % "") == ("mcp", None)
    assert _detect(tmp_path, '{"compilerOptions": {}}', "u.json") == ("unknown", None)


@pytest.mark.parametrize("n", PADS)
def test_detect_padded_spec_is_still_an_mcp_spec(tmp_path, n):
    assert _detect(tmp_path, MCP_SPEC % (', "zz": ' + deep(n))) == ("mcp", None)
    assert _detect(tmp_path, '{"command": "x", "args": %s}' % deep(n), "c.json") == ("mcp", None)
    assert _detect(tmp_path, '{"compilerOptions": {}, "zz": %s}' % deep(n), "u.json") == ("unknown", None)


def test_detect_whole_document_deep_is_no_crash(tmp_path):
    assert _detect(tmp_path, "[" * 100_000 + "]" * 100_000) == ("unknown", None)


# ----------------------------------------------------------------------------- skill frontmatter

def _skill(meta: str) -> str:
    return "---\nname: x\ndescription: y\nmetadata: %s\n---\n\nbody\n" % meta


def _install_meta(url: str, pad: str = "", label: str = '"l"') -> str:
    return ('{"openclaw": {"install": [{"kind": "download", "label": %s, "url": "%s"}]%s}}'
            % (label, url, (', "zz": ' + pad) if pad else ""))


def _b103(meta: str):
    return check_install_directive_supply_chain(SimpleNamespace(installed_skills={"s": _skill(meta)}))


def test_b103_unpadded_fail_and_pass_are_unchanged():
    assert _b103(_install_meta("http://evil.example/a.sh")).status == "FAIL"
    assert _b103(_install_meta("https://good.example/a.sh")).status == "PASS"


@pytest.mark.parametrize("n", PADS)
@pytest.mark.parametrize("where", ("key", "label"))
def test_b103_padded_plaintext_install_still_fails(n, where):
    meta = (_install_meta("http://evil.example/a.sh", pad=deep(n)) if where == "key"
            else _install_meta("http://evil.example/a.sh", label=deep(n)))
    assert _b103(meta).status == "FAIL"


@pytest.mark.parametrize("n", PADS)
def test_b103_padded_clean_install_is_not_a_pass_and_not_an_error(n):
    finding = _b103(_install_meta("https://good.example/a.sh", pad=deep(n)))
    assert finding.status == "UNKNOWN" and "nested too deeply" in finding.detail


def _dormant(meta: str):
    return check_dormant_capability(SimpleNamespace(
        installed_skills={"s": _skill(meta)}, installed_skill_py={"s": "x = 1"}))


UNREACHABLE = '{"openclaw": {"user-invocable": false, "disable-model-invocation": true}%s}'
REACHABLE = '{"openclaw": {"user-invocable": true}%s}'


def test_b89_unpadded_is_unchanged():
    assert _dormant(UNREACHABLE % "").status == "WARN"
    assert _dormant(REACHABLE % "").status == "PASS"


@pytest.mark.parametrize("n", PADS)
def test_b89_padded_unreachable_skill_still_warns(n):
    assert _dormant(UNREACHABLE % (', "zz": ' + deep(n))).status == "WARN"


@pytest.mark.parametrize("n", PADS)
def test_b89_padded_reachable_skill_is_not_a_pass_and_not_an_error(n):
    assert _dormant(REACHABLE % (', "zz": ' + deep(n))).status == "UNKNOWN"


@pytest.mark.parametrize("n", PADS)
def test_frontmatter_helpers_read_shallow_fields_and_never_crash(n):
    fm_line = 'metadata: {"openclaw": {"install": [1]}, "zz": %s}\n' % deep(n)
    assert _fm_metadata_obj(fm_line)["openclaw"] == {"install": [1]}
    assert _fm_metadata_obj_multiline(fm_line)["openclaw"] == {"install": [1]}
    assert _fm_metadata_obj('metadata: {"zz": ' + deep(100_000) + "}\n")["zz"] is not None
    assert _fm_metadata_obj_multiline('metadata: {"a":' * 1 + deep_obj(100_000) + "}\n") is not None


# ----------------------------------------------------------------------------- _skill_own_host

def _blob(manifest: str) -> str:
    return "---\nname: x\n---\n\n# file: skill.json\n" + manifest + "\n"


OWN = '{"name": "x", "homepage": "https://good.example/x"%s}'


def test_own_host_unpadded_is_unchanged():
    assert _skill_own_host(_blob(OWN % "")) == "good.example"


@pytest.mark.parametrize("n", PADS)
def test_own_host_of_a_padded_manifest_grants_no_trust(n):
    assert _skill_own_host(_blob(OWN % (', "zz": ' + deep(n)))) is None


def test_own_host_whole_document_deep_is_no_trust_and_no_crash():
    assert _skill_own_host(_blob(deep_obj(100_000))) is None
