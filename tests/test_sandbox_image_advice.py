"""B4 names the container image a sandboxed session depends on (advice only).

Observed 2026-11-05: `agents.defaults.sandbox.mode` = "non-main" with the image
`openclaw-sandbox:bookworm-slim` absent makes every non-main session fail with OpenClaw's
`SandboxProvisioningError: Sandbox image not found`. clawseccheck cannot see the container
engine, so the verdict must NOT change; the dependency is disclosed in `fix`, never in
`detail` (`baseline.fingerprint()` hashes `detail`).
"""
from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_sandbox
from clawseccheck.collector import Context

DEFAULT_IMAGE = "openclaw-sandbox:bookworm-slim"


def _ctx(sandbox: dict, agents_extra: dict | None = None) -> Context:
    c = Context(home=Path("/nonexistent"))
    agents = {"defaults": {"sandbox": sandbox}}
    if agents_extra:
        agents.update(agents_extra)
    c.config = {"agents": agents}
    c.include_host = True
    return c


def test_non_main_default_image_is_named_in_fix_only():
    f = check_sandbox(_ctx({"mode": "non-main"}))
    assert f.status == WARN  # verdict unchanged
    assert DEFAULT_IMAGE in f.fix
    assert "SandboxProvisioningError" in f.fix
    assert "scripts/sandbox-setup.sh" in f.fix
    assert "image" not in f.detail.lower()
    assert DEFAULT_IMAGE not in f.detail


def test_all_mode_pass_text_is_unchanged():
    f = check_sandbox(_ctx({"mode": "all"}))
    assert f.status == PASS
    assert f.detail == "Execution is sandboxed."
    assert f.fix == "Keep sandbox mode enabled."


def test_configured_image_override_is_named_instead_of_default():
    f = check_sandbox(_ctx({"mode": "non-main", "docker": {"image": "registry.example/sbx:1"}}))
    assert f.status == WARN
    assert "registry.example/sbx:1" in f.fix
    assert DEFAULT_IMAGE not in f.fix
    assert "scripts/sandbox-setup.sh" not in f.fix
    assert "Build or pull" in f.fix


def test_non_string_image_does_not_invent_a_name():
    f = check_sandbox(_ctx({"mode": "non-main", "docker": {"image": ["x"]}}))
    assert f.status == WARN
    assert DEFAULT_IMAGE not in f.fix
    assert "agents.defaults.sandbox.docker.image" in f.fix


def test_non_docker_backend_gets_no_image_sentence():
    f = check_sandbox(_ctx({"mode": "non-main", "backend": "ssh"}))
    assert f.status == WARN
    assert "SandboxProvisioningError" not in f.fix
    assert "container image" not in f.fix


def test_docker_backend_explicit_still_gets_sentence():
    f = check_sandbox(_ctx({"mode": "non-main", "backend": " docker "}))
    assert DEFAULT_IMAGE in f.fix


def test_per_agent_non_main_warn_also_carries_sentence():
    extra = {"list": [{"id": "w", "sandbox": {"mode": "non-main"}}]}
    f = check_sandbox(_ctx({"mode": "all"}, extra))
    assert f.status == WARN  # the per-agent branch, verdict unchanged
    assert "agent 'w'" in " ".join(f.evidence)
    assert DEFAULT_IMAGE in f.fix


def test_control_chars_in_image_are_stripped():
    f = check_sandbox(_ctx({"mode": "non-main", "docker": {"image": "img\x1b[31m:1"}}))
    assert "\x1b" not in f.fix


def test_off_mode_unchanged_no_image_sentence():
    f = check_sandbox(_ctx({"mode": "off"}))
    assert "SandboxProvisioningError" not in f.fix
