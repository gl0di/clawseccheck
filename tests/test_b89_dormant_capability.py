"""B89 (F-092 (b), narrowed): dormant-capability skill.

A skill unreachable by BOTH the user (user-invocable:false) AND the model
(disable-model-invocation:true) that STILL ships executable code is a dormant-capability
shape — inert code nobody can trigger, staged for later activation -> WARN. The "ships
code" narrowing is what keeps it zero-FP: a legitimate doc-only unreachable skill (and any
skill that is still reachable, like our own) never fires.

Both invocation-flag shapes are read: top-level YAML (Claude-Code) and nested
metadata.openclaw (OpenClaw). All offline; blobs built in-memory, vet case in tmp_path.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_dormant_capability, vet_skill
from clawseccheck.collector import Context


def _blob(frontmatter: str, body: str = "hello\n") -> str:
    return f"# file: SKILL.md\n---\n{frontmatter}\n---\n{body}"


def _ctx(frontmatter: str, *, code: bool = False, name: str = "demo") -> Context:
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {name: _blob(frontmatter)}
    if code:
        ctx.installed_skill_py = {name: [("run.py", "import os\nos.getcwd()\n")]}
    return ctx


def _b89(finding):
    for f in [finding, *getattr(finding, "ring_findings", [])]:
        if f.id == "B89":
            return f
    return None


# ---- WARN: unreachable + ships code ----


def test_toplevel_unreachable_with_code_is_warn():
    fm = "name: demo\nuser-invocable: false\ndisable-model-invocation: true"
    assert check_dormant_capability(_ctx(fm, code=True)).status == WARN


def test_nested_user_invocable_unreachable_with_code_is_warn():
    """OpenClaw shape: user-invocable nested in metadata.openclaw."""
    fm = (
        'name: demo\n'
        'metadata: {"openclaw":{"emoji":"x","user-invocable":false}}\n'
        "disable-model-invocation: true"
    )
    assert check_dormant_capability(_ctx(fm, code=True)).status == WARN


def test_yes_no_boolean_form_is_read():
    fm = "name: demo\nuser-invocable: no\ndisable-model-invocation: yes"
    assert check_dormant_capability(_ctx(fm, code=True)).status == WARN


# ---- PASS: the narrowing and reachable shapes ----


def test_unreachable_without_code_is_pass():
    """Doc-only unreachable skill is not a dormant-capability shape (the narrowing)."""
    fm = "name: demo\nuser-invocable: false\ndisable-model-invocation: true"
    assert check_dormant_capability(_ctx(fm, code=False)).status == PASS


def test_model_disabled_but_user_invocable_is_pass():
    """The clawstealth shape: model-disabled but still user-invocable -> reachable -> PASS."""
    fm = "name: stealth\ndisable-model-invocation: true"
    assert check_dormant_capability(_ctx(fm, code=True)).status == PASS


def test_default_reachable_skill_is_pass():
    fm = "name: demo\ndescription: a normal skill"
    assert check_dormant_capability(_ctx(fm, code=True)).status == PASS


def test_user_disabled_but_model_enabled_is_pass():
    """Only user-invocable:false (model can still invoke) -> reachable -> PASS."""
    fm = "name: demo\nuser-invocable: false"
    assert check_dormant_capability(_ctx(fm, code=True)).status == PASS


# ---- UNKNOWN paths ----


def test_no_installed_skills_is_unknown():
    assert check_dormant_capability(Context(home=Path("/x"))).status == UNKNOWN


def test_no_frontmatter_is_unknown():
    ctx = Context(home=Path("/x"))
    ctx.installed_skills = {"x": "# file: SKILL.md\nbody without fences\n"}
    assert check_dormant_capability(ctx).status == UNKNOWN


# ---- vet integration ----


def test_vet_skill_surfaces_b89(tmp_path):
    d = tmp_path / "skills" / "dormant"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: dormant\nuser-invocable: false\ndisable-model-invocation: true\n---\nbody\n",
        encoding="utf-8",
    )
    (d / "payload.py").write_text("import socket\nsocket.gethostname()\n", encoding="utf-8")
    b89 = _b89(vet_skill(d))
    assert b89 is not None and b89.status == WARN


# ---- zero-FP on the shipped SKILL.md (user-invocable:true, ships code) ----


def test_own_skill_md_is_not_dormant():
    skill_md = Path(__file__).resolve().parent.parent / "SKILL.md"
    blob = "# file: SKILL.md\n" + skill_md.read_text(encoding="utf-8")
    ctx = Context(home=Path("/x"))
    ctx.installed_skills = {"clawseccheck": blob}
    ctx.installed_skill_py = {"clawseccheck": [("checks.py", "x = 1\n")]}  # we do ship code
    assert check_dormant_capability(ctx).status == PASS
