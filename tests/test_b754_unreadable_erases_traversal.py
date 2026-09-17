"""B-754 — an unreadable file must not erase a CONFIRMED archive path traversal from
every output surface.

``check_installed_skills`` is a first-match-wins cascade (see
``tests/test_b746_cascade_rank_order.py``). B-746 put the coverage arms
(``parse_error_paths`` / ``skill_limit_hits`` / the unreadable-file sub-branch)
deliberately ABOVE the ``path_traversal`` arm, so a home carrying both an unreadable
file and a confirmed zip-slip archive keeps ``engine_degraded=True`` and reports
UNKNOWN rather than a confident FAIL — that ordering is correct and B-746's own DoD
requires it to stay.

What was wrong is narrower: because the coverage arm RETURNS as soon as it wins, the
traversal — which the scan already found, via ``ctx.path_traversal_violations`` — was
never looked at, let alone mentioned. One unrelated unreadable file anywhere in the
skill silently erased a confirmed archive escape from the rendered ``--vet-skill``
dossier, the rendered ``--home`` audit report, and the JSON — while the verdict quietly
stayed UNKNOWN/CAUTION as if the scan had found nothing at all.

The fix: ``check_installed_skills`` now computes ``path_traversal_violations`` BEFORE
the coverage-arm cascade (rather than at the traversal arm's own later point in it), so
the unreadable-file branch can append a "confirmed archive escape ALSO found" clause to
its own ``detail`` — the field every rendered surface (dossier Danger row, audit
per-skill summary line, and JSON ``detail``/``reason``) unconditionally shows. Status,
severity and the winning bucket name are UNCHANGED, so the verdict still degrades to
UNKNOWN/CAUTION exactly as before; only the silence is fixed.

Unreadable files are injected via ``monkeypatch`` on ``Path.read_bytes``/``Path.open``
(the same technique ``tests/test_b458_unreadable_file.py`` uses) rather than
``chmod 000``: root ignores the mode bits, so a chmod-based test would silently pass
for the wrong reason wherever the suite runs as root. Offline, read-only, stdlib only.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import UNKNOWN
from clawseccheck.checks import vet_skill
from clawseccheck.dossier import build_profile
from clawseccheck.report import render_report, render_vet_dossier

_TRAVERSAL_MEMBER = "../../../tmp/b754_escape.txt"
_MANIFEST = "---\nname: b754-repro\ndescription: A friendly helper skill.\n---\n# Helper\n"


def _skill_dir(root: Path, *, extra_file: bool = True) -> Path:
    """SKILL.md + a real zip-slip bundle.zip + (optionally) an ordinary opaque.py.

    The archive is a genuine zip-slip; ``opaque.py`` has nothing to do with it — the
    same shape the task's own repro uses, so an unrelated file is what erases the
    finding, not something plausibly connected to it.
    """
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(_MANIFEST, encoding="utf-8")
    with zipfile.ZipFile(root / "bundle.zip", "w") as zf:
        zf.writestr(_TRAVERSAL_MEMBER, "pwned")
    if extra_file:
        (root / "opaque.py").write_text("print('hello')\n", encoding="utf-8")
    return root


def _make_unreadable(monkeypatch, name: str) -> None:
    """Make exactly the file named *name* raise PermissionError on read; every other
    path reads normally. Same technique as test_b458_unreadable_file.py."""
    real_read_bytes = Path.read_bytes
    real_open = Path.open
    exc = PermissionError(13, "Permission denied")

    def read_bytes(self):
        if self.name == name:
            raise exc
        return real_read_bytes(self)

    def open_(self, *a, **kw):
        if self.name == name:
            raise exc
        return real_open(self, *a, **kw)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(Path, "open", open_)


# ---------------------------------------------------------------------------------
# --vet-skill surface: the dossier text render and the JSON render.
# ---------------------------------------------------------------------------------

def test_vet_skill_control_readable_names_the_traversal_and_fails(tmp_path):
    """Control: with every file readable, the traversal FAILs the danger axis exactly
    as it does today — the fix must not touch this path at all."""
    skill = _skill_dir(tmp_path / "skill")
    f = vet_skill(skill)
    assert f.status == "SKILL_ARCHIVE_PATH_TRAVERSAL", f"{f.status}: {f.detail}"
    assert "b754_escape.txt" in f.detail

    p = build_profile(f, str(skill), "skill")
    danger = next(a for a in p.axes if a.axis == "danger")
    assert danger.status == "FAIL"
    text = render_vet_dossier(p)
    assert "b754_escape.txt" in text, text


def test_vet_skill_unreadable_file_still_names_the_traversal(tmp_path, monkeypatch):
    """The defect, fixed: an unrelated unreadable file must not erase the traversal
    from the dossier text, and the coverage disclosure must survive alongside it."""
    skill = _skill_dir(tmp_path / "skill")
    _make_unreadable(monkeypatch, "opaque.py")

    f = vet_skill(skill)
    # Guard against a vacuous pass: the injection must actually have blinded the scan,
    # and the coverage arm must still be the one that WON (B-746's ordering).
    assert f.status == UNKNOWN, f"{f.status}: {f.detail}"
    assert "opaque.py" in f.detail
    assert "could not be READ" in f.detail
    assert getattr(f, "engine_degraded", False) is True, (
        "the coverage arm must keep engine_degraded, or the audit score loses its cap "
        "(B-458) — B-746's ordering requirement must survive this fix too"
    )

    # The fix: the confirmed escape is now named too, alongside the coverage gap.
    assert "b754_escape.txt" in f.detail, (
        "the confirmed archive traversal must be named in the SAME finding as the "
        f"coverage disclosure, not silently dropped: {f.detail!r}"
    )

    p = build_profile(f, str(skill), "skill")
    danger = next(a for a in p.axes if a.axis == "danger")
    # B-746's DoD bullet, asserted rather than assumed: the coverage arm still wins
    # the VERDICT — an incomplete read must not produce a confident FAIL.
    assert danger.status == UNKNOWN, danger.status

    text = render_vet_dossier(p)
    assert "opaque.py" in text, "coverage disclosure missing from the rendered dossier text"
    assert "b754_escape.txt" in text, (
        "traversal missing from the rendered dossier text — the JSON alone is not enough"
    )


def test_vet_skill_unreadable_file_with_no_traversal_is_unchanged(tmp_path, monkeypatch):
    """C-135 direction check: a skill with NO archive at all must not suddenly start
    mentioning a traversal just because a file happens to be unreadable."""
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(_MANIFEST, encoding="utf-8")
    (skill / "opaque.py").write_text("print('hello')\n", encoding="utf-8")
    _make_unreadable(monkeypatch, "opaque.py")

    f = vet_skill(skill)
    assert f.status == UNKNOWN
    assert "opaque.py" in f.detail
    assert "traversal" not in f.detail.lower()
    assert "escape" not in f.detail.lower()


# ---------------------------------------------------------------------------------
# --home surface: the full audit report render.
# ---------------------------------------------------------------------------------

def _home(tmp_path: Path, *, extra_file: bool = True) -> Path:
    home = tmp_path / "home"
    _skill_dir(home / "workspace" / "skills" / "b754-repro", extra_file=extra_file)
    cfg = home / "openclaw.json"
    cfg.write_text('{"model": "test"}\n', encoding="utf-8")
    cfg.chmod(0o600)
    return home


def test_home_audit_control_readable_names_the_traversal(tmp_path):
    home = _home(tmp_path)
    ctx, findings, score = audit(home)
    text = render_report(findings, score, ctx=ctx)
    assert "b754_escape.txt" in text, text


def test_home_audit_unreadable_file_still_names_the_traversal(tmp_path, monkeypatch):
    """The same defect, on the OTHER surface: an unrelated unreadable file inside an
    installed skill must not erase a confirmed traversal from the rendered audit
    report either."""
    home = _home(tmp_path)
    _make_unreadable(monkeypatch, "opaque.py")

    ctx, findings, score = audit(home)
    b13 = next(f for f in findings if f.id == "B13")
    assert b13.status == UNKNOWN, f"{b13.status}: {b13.detail}"
    assert "opaque.py" in b13.detail
    assert "b754_escape.txt" in b13.detail

    text = render_report(findings, score, ctx=ctx)
    assert "opaque.py" in text, "coverage disclosure missing from the rendered audit report"
    assert "b754_escape.txt" in text, (
        "traversal missing from the rendered audit report — the JSON alone is not enough"
    )
