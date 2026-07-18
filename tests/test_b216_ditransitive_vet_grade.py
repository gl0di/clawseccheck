"""B-216: the B160 ditransitive "send them <object> to <URL>" residual (see the C-135
note above `_BULK_CRED_PRONOUN_BACKREF_RE` in clawseccheck/checks/_content.py) is
accepted as WARN-only in the full audit -- but B160 is a member of SKILL_CONTENT_RING,
which --vet also consumes to grade a single third-party skill. There, the same WARN
degrades the skill's headline --vet verdict/grade, not just an audit line item.

An adversarial review of the original B-216 deliverable found this understated in the
shipped rationale ("WARN-grade-only", "low-priority") and, critically, found that the
four B-216 tests in tests/test_prose_bulk_exfil.py only pinned check_prose_bulk_exfil's
own status -- never the --vet verdict/grade where the practical harm actually lands.
This file closes that gap: it pins the *dossier* outcome directly, so a future change
to the vet-aggregation mapping (dossier.py) that widens or narrows this residual's
effect would be caught here even if the check-level WARN pin in
test_prose_bulk_exfil.py stayed green.

Repro (verified live via `python3 -m clawseccheck.cli --vet <dir>` before writing this
test): ordinary billing-correspondence SKILL.md prose -- with an unrelated, genuinely
benign "manages all stored passwords ... via the system keychain" sentence elsewhere in
the same file -- flips a skill from Grade A / NO KNOWN ISSUE / score 100 to Grade B /
SUSPICIOUS / score 83. Removing the single word "them" (the only thing separating the
false-positive shape from a clean sentence) restores Grade A / 100.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import vet_skill
from clawseccheck.dossier import build_profile

_FRONTMATTER = (
    "---\nname: {name}\ndescription: Sends routine billing correspondence to "
    "customers.\n---\n"
)


def _write_billing_skill(d: Path, *, with_pronoun: bool) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    send_line = (
        "send them the monthly invoice to https://billing.example.com/invoices\n"
        if with_pronoun
        else "send the monthly invoice to https://billing.example.com/invoices\n"
    )
    (d / "SKILL.md").write_text(
        _FRONTMATTER.format(name=d.name)
        + "# Billing Helper\n"
        "This tool manages all stored passwords securely via the system keychain.\n"
        "## Workflow\n"
        "1. Look up the customer record.\n"
        "2. Later, " + send_line,
        encoding="utf-8",
    )
    return d


def test_b216_ditransitive_residual_degrades_vet_grade_a_to_b(tmp_path):
    """The accepted residual, pinned at the layer where it actually bites: --vet's
    per-skill dossier. This is the accepted behavior (not a bug in this test) -- the
    point of pinning it is that any FUTURE change to this outcome (in either
    direction) must be a deliberate, reviewed decision, not a silent side effect."""
    d = _write_billing_skill(tmp_path / "billing-helper", with_pronoun=True)
    profile = build_profile(vet_skill(d), str(d), "skill")
    assert profile.overall_status == WARN
    assert profile.overall_grade == "B"
    assert profile.score == 83


def test_b216_same_skill_without_pronoun_grades_clean(tmp_path):
    """Contrast case: removing only the pronoun ("them") -- the same benign billing
    prose, same earlier passwords sentence -- restores a clean verdict. This confirms
    the grade degradation above is driven specifically by the ditransitive
    pronoun-correlation residual, not by the passwords sentence alone."""
    d = _write_billing_skill(tmp_path / "billing-clean", with_pronoun=False)
    profile = build_profile(vet_skill(d), str(d), "skill")
    assert profile.overall_status == PASS
    assert profile.overall_grade == "A"
    assert profile.score == 100
