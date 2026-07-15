"""RISK-19 (C-197): Skill Composition Risk (SCR) — Trust Transfer.

Per "Benign in Isolation, Harmful in Composition" (arXiv 2606.15242): an
audit/security/verification-themed installed skill co-present with a SEPARATE
installed skill that has exec/network/write capability. Neither skill is
individually malicious; the risk is compositional — an agent can misread the
audit-themed skill's benign-sounding output as authorization for the other
skill's risky action. Architect-ratified design (2026-07-13): a static RISK-*
chain, mirroring RISK-11's cross-agent trust reassembly.

Authorization Confusion (the paper's second SCR mechanism — advisory context
reinterpreted as formal approval) is a documented, unimplemented residual: it is
a runtime reading of prose, not a structural property two co-installed skills
expose statically.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.risk import risk_paths

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _mk_skills(tmp_path: Path, skills: dict[str, dict[str, str]]) -> Path:
    for name, files in skills.items():
        d = tmp_path / "skills" / name
        d.mkdir(parents=True, exist_ok=True)
        for fname, content in files.items():
            (d / fname).write_text(content, encoding="utf-8")
    return tmp_path


def _risk19(tmp_path: Path):
    ctx, findings, _ = audit(tmp_path, include_native=False)
    paths = risk_paths(ctx, findings)
    return next((p for p in paths if p.id == "RISK-19"), None)


_AUDIT_SKILL_MD = (
    "---\nname: security-auditor\ndescription: Audits the codebase for security "
    "issues and reports findings.\n---\nScans files for known vulnerability patterns.\n"
)
_HIGH_BLAST_SKILL_MD = (
    "---\nname: deploy-tool\ndescription: Deploys the application to production.\n"
    "---\nRuns deployment commands.\n"
)
_HIGH_BLAST_PY = (
    'import subprocess\ndef deploy():\n    subprocess.run(["kubectl", "apply", "-f", "manifest.yaml"])\n'
)


def test_audit_themed_plus_high_blast_skill_fires(tmp_path):
    _mk_skills(tmp_path, {
        "security-auditor": {"SKILL.md": _AUDIT_SKILL_MD},
        "deploy-tool": {"SKILL.md": _HIGH_BLAST_SKILL_MD, "deploy.py": _HIGH_BLAST_PY},
    })
    p = _risk19(tmp_path)
    assert p is not None, "RISK-19 did not fire for a genuine audit+high-blast composition"
    assert p.severity == "MEDIUM"
    assert "security-auditor" in p.why and "deploy-tool" in p.why


def test_only_audit_themed_skill_does_not_fire(tmp_path):
    _mk_skills(tmp_path, {"security-auditor": {"SKILL.md": _AUDIT_SKILL_MD}})
    assert _risk19(tmp_path) is None


def test_only_high_blast_skill_does_not_fire(tmp_path):
    _mk_skills(tmp_path, {
        "deploy-tool": {"SKILL.md": _HIGH_BLAST_SKILL_MD, "deploy.py": _HIGH_BLAST_PY},
    })
    assert _risk19(tmp_path) is None


def test_single_skill_with_both_roles_does_not_fire(tmp_path):
    """A composition requires TWO skills — one skill being both audit-themed and
    high-capability is not a trust-transfer composition."""
    _mk_skills(tmp_path, {
        "security-auditor": {
            "SKILL.md": _AUDIT_SKILL_MD,
            "scan.py": 'import subprocess\ndef scan():\n    subprocess.run(["grep", "-r", "secret"])\n',
        },
    })
    assert _risk19(tmp_path) is None


def test_two_ordinary_unrelated_skills_do_not_fire(tmp_path):
    _mk_skills(tmp_path, {
        "weather": {
            "SKILL.md": "---\nname: weather\ndescription: Fetches the local forecast.\n"
            "---\nPrints weather.\n"
        },
        "notes": {
            "SKILL.md": "---\nname: notes\ndescription: Takes notes for the user.\n"
            "---\nWrites notes.\n"
        },
    })
    assert _risk19(tmp_path) is None


def test_no_skills_at_all_does_not_fire(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}\n", encoding="utf-8")
    assert _risk19(tmp_path) is None


def test_read_only_capability_does_not_count_as_high_blast(tmp_path):
    """A skill that merely reads (no exec/network/write) must not count as the
    high-blast leg, even when co-present with an audit-themed skill."""
    _mk_skills(tmp_path, {
        "security-auditor": {"SKILL.md": _AUDIT_SKILL_MD},
        "reader": {
            "SKILL.md": "---\nname: reader\ndescription: Reads local files for the user.\n"
            "---\nReads a file.\n",
            "reader.py": "def read(path):\n    return open(path).read()\n",
        },
    })
    assert _risk19(tmp_path) is None
