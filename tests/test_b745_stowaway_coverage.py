"""B-745 — a bundled native executable must stay disclosed even when an earlier B13
bucket wins the cascade before `check_installed_skills` ever reaches the `warnings`
arm that names it as a stowaway (F-054).

Reproduced (2026-09-05, filed against `JS_NATIVE_DLOPEN`'s remediation text): a skill
with only `addon.node` (a real ELF) reports it by name in the WARN detail; adding a
`run.js` that dlopens it makes the JS warn bucket win the cascade instead, and the
native-executable fact vanished entirely — not just from `detail`, from the whole
finding. Both are WARN, so the verdict itself never lied; what was lost is a fact the
reader needs most in exactly this scenario (the JS-level scan cannot see inside the
binary the dlopen call loads).

Fix (option C, the B-552 precedent): the same fact is registered eagerly under a
"_"-prefixed `_signal_buckets` key (`_stowaway_note`), which `_b13_verdict` (C-358)
always folds into `fx.evidence` regardless of which bucket wins — never a corroborating
signal, never able to win the ladder itself. The `warnings` bucket further down still
carries the fact for when it IS the winner, so that branch's rendered `detail` text is
byte-identical to before.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from clawseccheck.catalog import WARN
from clawseccheck.checks import check_installed_skills, vet_skill
from clawseccheck.collector import collect

# A minimal but real ELF header — the same magic bytes test_stowaway.py uses to trip
# F-054's stowaway detection.
_ELF = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 64
_DLOPEN = 'process.dlopen(module, "./addon.node");\n'


def _skill_dir(base: Path, name: str, js: str | None) -> Path:
    d = base / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A skill.\n---\nsee run.js\n", encoding="utf-8"
    )
    (d / "addon.node").write_bytes(_ELF)
    if js is not None:
        (d / "run.js").write_text(js, encoding="utf-8")
    return d


def test_native_binary_is_disclosed_when_a_js_warn_wins_the_cascade(tmp_path):
    """The reported case: a JS warn (dlopen) wins the B13 cascade before the
    `warnings` arm — where the stowaway fact used to be named exclusively — is ever
    reached. The fact must still reach the finding, as evidence."""
    home = tmp_path / "home"
    _skill_dir(home / "workspace" / "skills", "both", _DLOPEN)

    f = check_installed_skills(collect(home))
    assert f.status == WARN, f.status
    assert "dlopen" in f.detail, f.detail  # precondition: the JS bucket is the winner
    assert any("native executable" in e for e in f.evidence), f.evidence
    assert any("addon.node" in e for e in f.evidence), f.evidence


def test_single_cause_stowaway_keeps_its_current_detail_text(tmp_path):
    """Non-regression: with no JS at all, the `warnings` bucket still wins the
    cascade and its rendered detail text is unchanged from before this fix."""
    home = tmp_path / "home"
    _skill_dir(home / "workspace" / "skills", "addononly", None)

    f = check_installed_skills(collect(home))
    assert f.status == WARN, f.status
    assert f.detail.startswith("Warnings in installed skill(s): "), f.detail
    assert "stowaway" in f.detail, f.detail
    assert "addon.node" in f.detail, f.detail


def test_coverage_note_never_becomes_a_corroborating_signal():
    """C-358 contract: the "_"-prefixed channel rides into evidence only — it must
    never appear in `corroborating_buckets` (that field means "another bucket also
    fired", not "a fact was rescued")."""
    with tempfile.TemporaryDirectory() as td:
        home = Path(td) / "home"
        _skill_dir(home / "workspace" / "skills", "both", _DLOPEN)
        f = check_installed_skills(collect(home))

    assert "_stowaway_note" not in (getattr(f, "corroborating_buckets", None) or [])


def test_vet_skill_path_also_discloses_it():
    """`vet_skill` -> `_vet_resolved_skill` calls `check_installed_skills` on its own
    single-skill ctx, so the fix must reach --vet-skill too, not just the full audit."""
    with tempfile.TemporaryDirectory() as td:
        d = _skill_dir(Path(td), "both", _DLOPEN)
        f = vet_skill(str(d))

    assert any("native executable" in e for e in f.evidence), f.evidence
    assert any("addon.node" in e for e in f.evidence), f.evidence


def test_no_stowaway_means_no_note_at_all(tmp_path):
    """A skill with a plain JS warn and no native binary must not gain a phantom
    stowaway note — the eager list is empty when `ctx.stowaway_files` is empty."""
    home = tmp_path / "home"
    d = home / "workspace" / "skills" / "jsonly"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: jsonly\ndescription: A skill.\n---\nsee run.js\n", encoding="utf-8"
    )
    (d / "run.js").write_text(_DLOPEN, encoding="utf-8")

    f = check_installed_skills(collect(home))
    assert f.status == WARN, f.status
    assert not any("stowaway" in e for e in f.evidence), f.evidence
