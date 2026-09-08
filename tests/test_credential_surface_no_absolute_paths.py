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


# --- the env class describes the SUBJECT, never the auditing shell ---------------------


def test_the_env_class_ignores_the_auditing_process_environment(monkeypatch, tmp_path):
    """`_credential_surface_map` read `os.environ` — the shell running the audit.

    Two harms, and the first is the worse one. A clean home with no credentials anywhere
    reported `env reachable=yes`, because the AUDITOR's shell had secret-shaped variables
    in it — a tool that states a falsehood about its subject is worse than one that
    crashes. And the names reached `--json`'s `secret_reachability` and the text report's
    credential-surface block, so pasting a report into an issue published the secret-shaped
    variable names of the reader's own shell (§8).

    `collector.persistent_env_evidence` already refuses `os.environ` for exactly this
    reason and documents it at length; this pins that the report layer agrees.
    """
    from clawseccheck.collector import collect
    from clawseccheck.report import _credential_surface_map

    monkeypatch.setenv("SYNTHETIC_AUDITOR_API_TOKEN", "not-the-subject-s-secret")

    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")

    entries = _credential_surface_map(collect(home))
    env = [e for e in entries if e.get("class") == "env"]
    assert env, "the env class disappeared from the map"

    blob = " ".join(env[0].get("evidence") or [])
    assert "SYNTHETIC_AUDITOR_API_TOKEN" not in blob, (
        "the auditing shell's variable name reached the report — a user pasting this into "
        "an issue would publish it"
    )
    assert env[0]["reachable"] is False, (
        "a home with no env-bearing artifact was reported as having reachable env "
        "credentials, on the strength of the auditor's own environment"
    )


def test_the_env_class_reports_a_key_that_really_is_the_subjects(tmp_path):
    """The other direction: the check must still SEE a real persistent env credential.

    Without this, the fix above would be satisfied by an env class that reports nothing
    ever — which is the same defect with the sign flipped.
    """
    from clawseccheck.report import _credential_surface_map

    class _Ctx:
        home = None
        config: dict = {}
        dotenv_values = {"SUBJECT_SERVICE_API_KEY": "x"}
        dotenv_sources = {"SUBJECT_SERVICE_API_KEY": ".env"}
        unit_env_values: dict = {}
        unit_env_sources: dict = {}
        dotenv_found = True
        unit_env_found = False

    env = [e for e in _credential_surface_map(_Ctx()) if e.get("class") == "env"]
    assert env and env[0]["reachable"] is True, (
        "a secret-shaped key in the subject's own dotenv was not reported"
    )
    assert "SUBJECT_SERVICE_API_KEY" in " ".join(env[0]["evidence"])
