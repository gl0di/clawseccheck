"""ClawHub security-audit finding (2026-07-27, v3.58.0, Intent-Code Divergence,
93% confidence): `_credential_surface_map`'s docstring promises "no absolute paths
leave this function", but its `_rel()` helper fell back to `str(path)` -- the
absolute path -- whenever `relative_to()` failed. No call site triggered the
fallback (every candidate was built as `home_path / suffix`), so the leak was
latent rather than live, but nothing enforced the invariant structurally: a
future credential-surface source could pass an out-of-home path and leak
silently. Extracted the closure to the module-level `_credential_surface_rel`
so the fallback branch is directly testable, not just structurally unreachable.
Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.collector import Context
from clawseccheck.report import _credential_surface_map, _credential_surface_rel


def test_rel_of_a_path_under_home_is_relative():
    home = Path("/home/user/.openclaw")
    p = home / ".ssh" / "id_rsa"
    assert _credential_surface_rel(p, home) == ".ssh/id_rsa"


def test_rel_of_a_path_outside_home_falls_back_to_bare_name_not_absolute_path():
    home = Path("/home/user/.openclaw")
    outside = Path("/home/user/.aws/credentials")
    result = _credential_surface_rel(outside, home)
    assert result == "credentials"
    assert str(home) not in result
    assert "/home/user" not in result


def test_rel_with_no_home_path_falls_back_to_bare_name_not_absolute_path():
    outside = Path("/home/user/.ssh/id_rsa")
    result = _credential_surface_rel(outside, None)
    assert result == "id_rsa"
    assert "/home/user" not in result


def _populated_home(tmp_path: Path) -> Path:
    home = tmp_path / "openclaw-home"
    home.mkdir()
    (home / ".env").write_text("SECRET=1\n", encoding="utf-8")
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "id_rsa").write_text("not a real key\n", encoding="utf-8")
    cookie_dir = home / ".mozilla" / "firefox"
    cookie_dir.mkdir(parents=True)
    (cookie_dir / "cookies.sqlite").write_text("", encoding="utf-8")
    return home


def test_credential_surface_evidence_never_contains_the_absolute_home_path(tmp_path):
    home = _populated_home(tmp_path)
    ctx = Context(home=home)
    entries = _credential_surface_map(ctx)

    reachable_classes = {e["class"] for e in entries if e["reachable"]}
    assert {".env", "ssh", "cookies"} <= reachable_classes, (
        "fixture didn't populate the candidates this test means to exercise"
    )

    evidence = [text for entry in entries for text in entry["evidence"]]
    for text in evidence:
        assert str(tmp_path) not in text, f"absolute tmp_path leaked into evidence: {text!r}"
        assert str(home) not in text, f"absolute home path leaked into evidence: {text!r}"
    assert any(".ssh" in t or "id_rsa" in t for t in evidence)
