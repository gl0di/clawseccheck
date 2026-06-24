"""1.3.0 — coverage for the two field-found permission-scan gaps + agent discovery.

B20: bootstrap/memory files outside the three hardcoded workspace dirs (home root, or an
agent-declared path) were invisible. C5: group/world-writable ANCESTOR install dirs above
the binary (the npm package root) were missed; a sticky dir (/tmp) must NOT false-positive.

Discovery: the agent supplies WHERE to look (attestation `paths`), the engine still stat()s
the path itself, so the finding keeps real-stat strength.
"""
import os
from pathlib import Path

import pytest

from clawseccheck import attest
from clawseccheck.checks import check_bootstrap_write_protection, check_path_safety
from clawseccheck.collector import Context


def _is_posix():
    import clawseccheck.checks as c
    return c._is_posix()


pytestmark = pytest.mark.skipif(not _is_posix(), reason="POSIX mode bits only")


def _ctx(home, attestation=None):
    c = Context(home=Path(home))
    c.config = {}
    c.include_host = True  # C5 host-PATH scan is gated on include_host (B-021)
    if attestation is not None:
        c.attestation = attestation
    return c


def _b20(ctx):
    return check_bootstrap_write_protection(ctx)


# ---------------------------------------------------------------------------
# B20 — home-root scan (the previously-invisible location)
# ---------------------------------------------------------------------------

def _home_with_root_memory(tmp_path, mode):
    os.chmod(tmp_path, 0o755)
    (tmp_path / "openclaw.json").write_text("{}")
    ws = tmp_path / "workspace-home"
    ws.mkdir()
    os.chmod(ws, 0o755)
    (ws / "SOUL.md").write_text("id")
    os.chmod(ws / "SOUL.md", 0o644)
    mem = tmp_path / "MEMORY.md"          # ROOT, outside any workspace dir
    mem.write_text("m")
    os.chmod(mem, mode)
    return tmp_path


def test_b20_flags_group_writable_memory_in_home_root(tmp_path):
    f = _b20(_ctx(_home_with_root_memory(tmp_path, 0o664)))
    assert f.status == "WARN"
    assert any("MEMORY.md" in e for e in f.evidence)


def test_b20_home_root_tight_memory_passes(tmp_path):
    f = _b20(_ctx(_home_with_root_memory(tmp_path, 0o600)))
    assert f.status == "PASS"


# ---------------------------------------------------------------------------
# B20 — agent-declared (attested) bootstrap path anywhere on disk
# ---------------------------------------------------------------------------

def test_b20_attested_memory_outside_home_warns(tmp_path):
    ext = tmp_path / "elsewhere"
    ext.mkdir()
    mem = ext / "MEMORY.md"
    mem.write_text("m")
    os.chmod(mem, 0o664)
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}")
    att = {"schema": attest.SCHEMA_ID, "paths": {"bootstrap": [str(mem)]}}
    f = _b20(_ctx(home, att))
    assert f.status == "WARN"
    assert any("attested" in e for e in f.evidence)


def test_b20_attested_critical_world_writable_fails(tmp_path):
    ext = tmp_path / "elsewhere"
    ext.mkdir()
    soul = ext / "SOUL.md"               # critical identity file -> world-write = FAIL
    soul.write_text("id")
    os.chmod(soul, 0o666)
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}")
    att = {"schema": attest.SCHEMA_ID, "paths": {"bootstrap": [str(soul)]}}
    f = _b20(_ctx(home, att))
    assert f.status == "FAIL"


# ---------------------------------------------------------------------------
# C5 — ancestor install-dir walk + sticky-safety + attested install
# ---------------------------------------------------------------------------

def _fake_install(tmp_path, *, pkg_mode=0o755):
    """root/lib/node_modules/openclaw/bin/openclaw, with the package root at pkg_mode."""
    pkg = tmp_path / "lib" / "node_modules" / "openclaw"
    bindir = pkg / "bin"
    bindir.mkdir(parents=True)
    binfile = bindir / "openclaw"
    binfile.write_text("#!/bin/sh\n")
    for d in (tmp_path, tmp_path / "lib", tmp_path / "lib" / "node_modules", bindir):
        os.chmod(d, 0o755)
    os.chmod(binfile, 0o755)
    os.chmod(pkg, pkg_mode)
    return binfile


def test_c5_flags_group_writable_ancestor(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks
    binfile = _fake_install(tmp_path, pkg_mode=0o775)   # bin tight, package root 775
    monkeypatch.setattr(checks, "_is_posix", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: str(binfile))
    monkeypatch.setenv("PATH", str(binfile.parent))
    f = check_path_safety(_ctx(tmp_path))
    assert f.status == "WARN"
    assert any("ancestor" in e and "openclaw" in e for e in f.evidence)


def test_c5_clean_tree_passes(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks
    binfile = _fake_install(tmp_path, pkg_mode=0o755)   # all tight
    monkeypatch.setattr(checks, "_is_posix", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: str(binfile))
    monkeypatch.setenv("PATH", str(binfile.parent))
    assert check_path_safety(_ctx(tmp_path)).status == "PASS"


def test_c5_sticky_ancestor_not_flagged(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks
    # An ancestor that is world-writable BUT sticky (like /tmp) must NOT be flagged.
    sticky = tmp_path / "sticky"
    pkg = sticky / "openclaw"
    pkg.mkdir(parents=True)
    binfile = pkg / "openclaw"
    binfile.write_text("#!/bin/sh\n")
    os.chmod(tmp_path, 0o755)
    os.chmod(pkg, 0o755)
    os.chmod(binfile, 0o755)
    os.chmod(sticky, 0o1777)             # sticky + world-write
    monkeypatch.setattr(checks, "_is_posix", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: str(binfile))
    monkeypatch.setenv("PATH", str(binfile.parent))
    f = check_path_safety(_ctx(tmp_path))
    assert f.status == "PASS", f.evidence


def test_c5_attested_install_dir_warns(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks
    inst = tmp_path / "openclaw"
    inst.mkdir()
    os.chmod(inst, 0o775)
    monkeypatch.setattr(checks, "_is_posix", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: None)   # not on PATH
    att = {"schema": attest.SCHEMA_ID, "paths": {"openclaw_install": str(inst)}}
    f = check_path_safety(_ctx(tmp_path, att))
    assert f.status == "WARN"
    assert any("attested" in e for e in f.evidence)


def test_c5_attested_install_clean_passes(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks
    inst = tmp_path / "openclaw"
    inst.mkdir()
    os.chmod(tmp_path, 0o755)
    os.chmod(inst, 0o755)
    monkeypatch.setattr(checks, "_is_posix", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    att = {"schema": attest.SCHEMA_ID, "paths": {"openclaw_install": str(inst)}}
    assert check_path_safety(_ctx(tmp_path, att)).status == "PASS"


def test_c5_no_path_no_attest_unknown(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks
    monkeypatch.setattr(checks, "_is_posix", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert check_path_safety(_ctx(tmp_path)).status == "UNKNOWN"


# ---------------------------------------------------------------------------
# attest.attested_paths — discovery extraction, tolerant of junk
# ---------------------------------------------------------------------------

def test_attested_paths_extracts():
    att = {"paths": {"bootstrap": ["/a/MEMORY.md", "/b/SOUL.md"], "openclaw_install": "/opt/oc"}}
    out = attest.attested_paths(att)
    assert out["bootstrap"] == ["/a/MEMORY.md", "/b/SOUL.md"]
    assert out["openclaw_install"] == "/opt/oc"


def test_attested_paths_tolerates_junk():
    assert attest.attested_paths(None) == {"bootstrap": [], "openclaw_install": None}
    assert attest.attested_paths({}) == {"bootstrap": [], "openclaw_install": None}
    assert attest.attested_paths({"paths": "nope"}) == {"bootstrap": [], "openclaw_install": None}
    # mixed junk in the list is filtered; empty install string -> None
    out = attest.attested_paths({"paths": {"bootstrap": ["/ok", 5, "", None], "openclaw_install": ""}})
    assert out["bootstrap"] == ["/ok"]
    assert out["openclaw_install"] is None


def test_template_includes_paths():
    t = attest.template()
    assert "paths" in t
    assert t["paths"] == {"bootstrap": [], "openclaw_install": ""}
    assert "paths" in t["_questions"]
