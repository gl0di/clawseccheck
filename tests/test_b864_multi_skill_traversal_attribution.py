"""B-864 (independent review, 2026-09-22) — on a MULTI-skill audit, a confirmed archive
path traversal must be attributed to the skill that actually shipped it, not to
whichever skill happened to win the ``check_installed_skills`` (B13) coverage arm.

The targeted review of B-864's own fix (3d10a5b) found one real defect: ``detail`` is
built from ``ctx.path_traversal_violations`` — the WHOLE HOME's flat list, with entries
that are skill-relative and carry no skill name at all (``"<file>::<member>"``,
``collector.py``'s ``decompress_and_classify``). On a home where one skill wins a
coverage arm (an unparseable file, oversized low-entropy padding, a file/size cap, or an
unreadable file) and a DIFFERENT skill ships the confirmed archive escape, the combined
disclosure named the escape right next to the winning skill's own problem with nothing
to say it belongs to someone else — and the accompanying ``fix`` text ("this skill also
contains a confirmed archive path traversal") said outright that it did.

Concretely, with ``alpha`` shipping an unparseable ``broken.py`` and ``bravo`` shipping
``bundle.zip`` with a genuine ``../../../tmp/x.txt`` escape, the finding before this fix
read:

    could not analyze alpha: broken.py ... — separately, a confirmed archive path
    traversal was ALSO found in what could be parsed: bundle.zip::../../../tmp/x.txt

with a fix clause of "this skill also contains a confirmed archive path traversal" —
both plainly about alpha, even though the escape is bravo's. The same misattribution
reproduces on the ``skill_limit_hits`` -> ``padding_anomalies`` WARN arm, its generic
"hit limits" UNKNOWN sibling, and the original B-754 unreadable-file branch, since B-864
copied the identical wording (and the same un-prefixed join) to all three sites.

Fixed by prefixing every disclosed entry with its owning skill — via
``ctx.skill_traversal_violations`` (collector.py's ``_note_skill_traversal``, keyed by
the skill directory's path), resolved to a display name and joined as ``"<name>:
<entry>"``, the same shape ``parse_error_paths`` already uses a few lines up in the same
function — and by rewording the ``fix`` clause to stop asserting the winning skill is
the one that shipped the escape. "Found in what could be PARSED" was also wrong on the
``parse_error_paths`` arm specifically: the traversal comes from reading an archive's
member list during collection, unrelated to whether some other file parses as Python;
reworded to "what could be read" to match the other three sites.

Status, severity and the winning bucket name are unchanged at all four sites — this is
a text-only fix, verified per arm below alongside the attribution assertion. The
single-skill ``vet_skill`` path was already correct (there is only one skill to
attribute to) and stays correct — asserted directly at the bottom of this file.

Rendered-surface check uses ``render_json``, not ``render_report`` (the plain-text
audit report): the review that found this defect also verified the text report is
NOT affected, because its per-skill inventory rows come from an independent, per-skill
re-vet (``report._skill_inventory``) that already attributes correctly on its own —
only the AGGREGATE ``B13`` finding's ``detail``/``fix`` (and therefore every surface
that renders those fields verbatim: JSON, the vet dossier, SARIF, ``--explain``, the
judge packet) carried the misattribution. Asserting against the text report here would
pass even with the bug present, for the wrong reason — the JSON check is the one that
actually exercises this fix.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from clawseccheck import scoring
from clawseccheck.catalog import UNKNOWN, WARN
from clawseccheck.checks import check_installed_skills, vet_skill
from clawseccheck.collector import (
    _MAX_BYTES_PER_SKILL,
    _MAX_FILE_BYTES,
    _MAX_FILES_PER_SKILL,
    collect,
)
from clawseccheck.report import render_json

_TRAVERSAL_MEMBER = "../../../tmp/rv_escape.txt"

# Same sizing recipe as tests/test_b864_coverage_arms_name_traversal.py /
# tests/test_truncation_coverage.py.
_PER_FILE = min(_MAX_FILE_BYTES - 1, int(_MAX_BYTES_PER_SKILL * 0.75))
_PAD_FILE_COUNT = _MAX_FILES_PER_SKILL + 20

_UNPARSEABLE_PY = """\
This file is prose, not Python.

It documents how the helper works: it reads notes and prints them.
Nothing here parses as Python source at all -- there is no valid statement.
"""


def _manifest(name: str) -> str:
    return f"---\nname: {name}\ndescription: A friendly helper skill.\n---\n# Helper\n"


def _bare_skill(root: Path, name: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(_manifest(name), encoding="utf-8")
    return root


def _traversal_skill(root: Path, name: str) -> Path:
    """The skill that ships ONLY a genuine zip-slip archive — nothing else, so any
    coverage-arm trigger in the finding must come from the OTHER skill."""
    _bare_skill(root, name)
    with zipfile.ZipFile(root / "bundle.zip", "w") as zf:
        zf.writestr(_TRAVERSAL_MEMBER, "pwned")
    return root


def _parse_error_arm_skill(root: Path, name: str) -> Path:
    _bare_skill(root, name)
    (root / "scripts").mkdir()
    (root / "scripts" / "broken.py").write_text(_UNPARSEABLE_PY, encoding="utf-8")
    return root


def _padding_arm_skill(root: Path, name: str) -> Path:
    _bare_skill(root, name)
    (root / "aaa_first.md").write_text("A" * _PER_FILE, encoding="utf-8")
    (root / "zzz_second.md").write_text("A" * _PER_FILE, encoding="utf-8")
    return root


def _generic_limit_arm_skill(root: Path, name: str) -> Path:
    _bare_skill(root, name)
    for i in range(_PAD_FILE_COUNT):
        (root / f"zzzpad_{i:04d}.txt").write_text("ok\n", encoding="utf-8")
    return root


def _unreadable_arm_skill(root: Path, name: str) -> Path:
    _bare_skill(root, name)
    (root / "opaque.py").write_text("print('hello')\n", encoding="utf-8")
    return root


def _two_skill_home(tmp_path: Path, arm_skill_builder) -> Path:
    """A home with two skills: "alpha", built by *arm_skill_builder* to win one of the
    coverage arms on its own, and "bravo", which ships ONLY the confirmed archive
    escape. Alphabetical order matches the reviewer's own repro (alpha is collected
    before bravo)."""
    home = tmp_path / "home"
    skills = home / "workspace" / "skills"
    arm_skill_builder(skills / "alpha", "alpha")
    _traversal_skill(skills / "bravo", "bravo")
    cfg = home / "openclaw.json"
    cfg.write_text('{"model": "test"}\n', encoding="utf-8")
    cfg.chmod(0o600)
    return home


def _make_unreadable_exact(monkeypatch, target: Path) -> None:
    """Make exactly *target* raise PermissionError on read; every other path — in
    particular a same-named file living in a DIFFERENT skill's directory — reads
    normally.

    Deliberately matched on the resolved path rather than the bare filename the way
    tests/test_b754_unreadable_erases_traversal.py's ``_make_unreadable`` does: a
    filename-only match is unsafe on a TWO-skill fixture, since it would blind every
    skill's same-named file at once rather than just the one under test. Uses
    ``chmod``, not ``monkeypatch``, only as a fallback is not needed here — root
    ignores mode bits, so the monkeypatch technique is used throughout this suite.
    """
    real_read_bytes = Path.read_bytes
    real_open = Path.open
    resolved = target.resolve()
    exc = PermissionError(13, "Permission denied")

    def read_bytes(self):
        if self.resolve() == resolved:
            raise exc
        return real_read_bytes(self)

    def open_(self, *a, **kw):
        if self.resolve() == resolved:
            raise exc
        return real_open(self, *a, **kw)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr(Path, "open", open_)


def _run(home: Path):
    ctx = collect(home)
    b13 = check_installed_skills(ctx)
    return ctx, b13


def _rendered_json(b13, ctx) -> str:
    """The JSON surface — where the review confirmed the misattribution actually
    reaches a reader; see the module docstring for why this, not ``render_report``.

    *ctx* is accepted for symmetry with the other arms' fixtures but deliberately NOT
    threaded into either call below — the SAME pre-existing, unrelated hang this
    module's sibling test file already routes around
    (tests/test_b864_coverage_arms_name_traversal.py's docstring, task_240721be):
    `render_json(..., ctx=ctx)` reaches `scoring.project` -> `scoring.compute(findings,
    ctx, ...)` -> `trajaudit.grade_cap_signal(ctx)` -> `skill_indicators()`'s unbounded
    `rx.finditer(text)` over `ctx.installed_skills` on the padding/generic/unreadable
    arms' large low-entropy fixture text, which hangs (confirmed here the same way that
    docstring confirms it: 30s+ with no completion, reproduced independent of pytest).
    `Finding.detail`/`.fix` — what this test actually checks — do not depend on ctx at
    all (`_finding_to_dict` reads them straight off the Finding), so `ctx=None` below
    exercises the exact same claim without paying for, or triggering, that unrelated
    bug.
    """
    del ctx  # intentionally unused — see docstring
    score = scoring.compute([b13])  # ctx omitted — see test_b864_coverage_arms_name_traversal.py
    text = render_json([b13], score, ctx=None)
    json.loads(text)  # must stay valid JSON
    return text


# =====================================================================================
# 1. parse_error_paths
# =====================================================================================

def test_parse_error_arm_attributes_the_traversal_to_the_owning_skill(tmp_path):
    home = _two_skill_home(tmp_path, _parse_error_arm_skill)
    ctx, b13 = _run(home)

    # Guard against a vacuous pass: this must land on the parse_error_paths arm, won by
    # alpha, exactly as before.
    assert b13.status == UNKNOWN, f"{b13.status}: {b13.detail}"
    assert "could not analyze alpha:" in b13.detail, b13.detail
    assert "broken.py" in b13.detail
    assert b13.engine_degraded is True

    # The fix: the traversal is attributed to bravo, which shipped it.
    assert "bravo: bundle.zip::" in b13.detail, (
        f"the traversal must be prefixed with its owning skill (bravo): {b13.detail!r}"
    )
    assert "rv_escape.txt" in b13.detail

    # The defect: the traversal must NOT read as alpha's.
    assert "alpha: bundle.zip" not in b13.detail, (
        f"the traversal must not be misattributed to alpha, which never shipped it: "
        f"{b13.detail!r}"
    )
    assert "this skill also contains" not in b13.fix, (
        f"the fix text must not assert that alpha (the arm's own winner) is the one "
        f"carrying the traversal: {b13.fix!r}"
    )

    # The wrong "what could be parsed" phrasing must be gone too.
    assert "what could be parsed" not in b13.detail, b13.detail

    text = _rendered_json(b13, ctx)
    assert "bravo: bundle.zip::" in text, (
        "misattributed-free disclosure missing from the rendered audit report — the "
        "JSON alone is not enough"
    )


# =====================================================================================
# 2. skill_limit_hits — padding_anomalies (WARN)
# =====================================================================================

def test_padding_anomalies_arm_attributes_the_traversal_to_the_owning_skill(tmp_path):
    home = _two_skill_home(tmp_path, _padding_arm_skill)
    ctx, b13 = _run(home)

    assert b13.status == WARN, f"{b13.status}: {b13.detail}"
    assert "padding" in b13.detail.lower() or "low-entropy" in b13.detail.lower()

    assert "bravo: bundle.zip::" in b13.detail, (
        f"the traversal must be prefixed with its owning skill (bravo): {b13.detail!r}"
    )
    assert "rv_escape.txt" in b13.detail
    assert "alpha: bundle.zip" not in b13.detail, (
        f"the traversal must not be misattributed to alpha: {b13.detail!r}"
    )
    assert "this skill also contains" not in b13.fix, b13.fix

    text = _rendered_json(b13, ctx)
    assert "bravo: bundle.zip::" in text


# =====================================================================================
# 3. skill_limit_hits — the generic "hit limits" UNKNOWN
# =====================================================================================

def test_generic_skill_limit_hits_arm_attributes_the_traversal_to_the_owning_skill(tmp_path):
    home = _two_skill_home(tmp_path, _generic_limit_arm_skill)
    ctx, b13 = _run(home)

    assert b13.status == UNKNOWN, f"{b13.status}: {b13.detail}"
    assert "hit limits" in b13.detail or "truncated" in b13.detail
    assert "padding" not in b13.detail.lower()
    assert "could not be READ" not in b13.detail
    assert b13.engine_degraded is False

    assert "bravo: bundle.zip::" in b13.detail, (
        f"the traversal must be prefixed with its owning skill (bravo): {b13.detail!r}"
    )
    assert "rv_escape.txt" in b13.detail
    assert "alpha: bundle.zip" not in b13.detail, (
        f"the traversal must not be misattributed to alpha: {b13.detail!r}"
    )
    assert "this skill also contains" not in b13.fix, b13.fix

    text = _rendered_json(b13, ctx)
    assert "bravo: bundle.zip::" in text


# =====================================================================================
# 4. the original B-754 unreadable-file branch
# =====================================================================================

def test_unreadable_file_arm_attributes_the_traversal_to_the_owning_skill(tmp_path, monkeypatch):
    home = _two_skill_home(tmp_path, _unreadable_arm_skill)
    _make_unreadable_exact(monkeypatch, home / "workspace" / "skills" / "alpha" / "opaque.py")
    ctx, b13 = _run(home)

    assert b13.status == UNKNOWN, f"{b13.status}: {b13.detail}"
    assert "could not be READ" in b13.detail
    assert "opaque.py" in b13.detail
    assert b13.engine_degraded is True

    assert "bravo: bundle.zip::" in b13.detail, (
        f"the traversal must be prefixed with its owning skill (bravo): {b13.detail!r}"
    )
    assert "rv_escape.txt" in b13.detail
    assert "alpha: bundle.zip" not in b13.detail, (
        f"the traversal must not be misattributed to alpha: {b13.detail!r}"
    )
    assert "this skill also contains" not in b13.fix, b13.fix

    text = _rendered_json(b13, ctx)
    assert "bravo: bundle.zip::" in text


# =====================================================================================
# 5. single-skill control — the already-correct vet_skill surface stays correct
# =====================================================================================

def test_single_skill_vet_skill_path_is_unaffected(tmp_path):
    """There is only one skill to attribute to on the ``--vet-skill`` surface, so the
    fix must be a harmless no-op there: the escape is still named, still inside the
    same finding as the coverage disclosure, and the winning bucket/status are
    unchanged."""
    skill = tmp_path / "skill"
    _parse_error_arm_skill(skill, "solo")
    with zipfile.ZipFile(skill / "bundle.zip", "w") as zf:
        zf.writestr(_TRAVERSAL_MEMBER, "pwned")

    f = vet_skill(skill)
    assert f.status == UNKNOWN, f"{f.status}: {f.detail}"
    assert "could not analyze" in f.detail
    assert "broken.py" in f.detail
    assert "rv_escape.txt" in f.detail, (
        f"the confirmed escape must still be named on the single-skill surface: {f.detail!r}"
    )
    assert f.engine_degraded is True
