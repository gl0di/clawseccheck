"""B-315 — an unscored check must never emit a FAIL scoring.compute() can't see.

Dave's ruling: "scored=False means 'cannot be assessed' — such a check becomes
incapable of emitting FAIL (WARN is its ceiling). Any check that CAN FAIL must
participate in scoring/capping." Before this, 6 of 78 scored=False CheckMeta entries
had a live FAIL branch, so a HIGH FAIL could sit in the findings list while the
headline grade claimed A/100 (B-315's own repro).

An independent architect audit (AST scan of every `_finding(...)`/`Finding(...)` call
site in `clawseccheck/checks/`, cross-checked against 466 real fixture homes) found
exactly six: B43, B55, B70, B185, B186, B193. Resolution, decided per-check on the
merits (not a blanket rule):

  - B43 (downgrade): confidence=ATTESTED — the verdict is the audited agent's OWN
    self-report; a grade cap the subject can talk itself into is unsound.
  - B70 (downgrade): the B68-B73 block comment claims the group is WARN-only with zero
    false-positive FAILs; B70's FAIL branch was the sole violator of that documented
    intent (and this exact loopback predicate is the one CLAUDE.md records as
    version-dependent across Python 3.9/3.12) — downgrading restores the claim.
  - B55/B185/B186/B193 (per-finding scored=True override, CheckMeta stays scored=False):
    each has a genuinely deterministic, narrowly-scoped, well-vetted FAIL branch (B185
    carries 5 rounds of C-135 in tests/test_b185_compiled_tool_poisoning.py) sitting
    alongside a WARN/PASS branch its own catalog.py comment explicitly wants excluded
    from scoring for an unrelated reason (opportunistic log presence for B185;
    protecting a benign relocated/legacy setup from being docked for B186/B193; the
    general write/least-privilege dimension staying with B3/B22/B31 for B55's own
    WARN/PASS/UNKNOWN branches). A blanket CheckMeta promotion would have started
    scoring those protected branches too; a blanket downgrade would have thrown away a
    well-vetted FAIL signal. The `_finding(..., scored=True)` override
    (checks/_shared.py) lets only the FAIL finding itself participate.

    B55 moved from "downgrade" to this group on 2026-07-31 (CLAWSECCHECK-B-376/B-369):
    ClawRange's false-negative hunter found the original WARN a real miss on two
    grounded mutations — proven broad reach (a wildcard elevated sender, or a
    genuinely open channel per `_open_channels`) is not "merely unscoped", and an
    exec-only approval gate does not scope write-capable tools, so neither mutation
    should have stayed silent at WARN. Followed the exact B186 precedent rather than
    inventing a new one: CheckMeta stays scored=False (B3/B22/B31 still own the
    general dimension), only this one narrow FAIL branch gets scored=True.

This file pins the Finding-level invariant every future check must hold — including
new ones nobody has audited yet — over the full 466-home fixture corpus (+ each
fixture's nested `openclaw_home/` variant where present, matching how the corpus is
actually laid out), plus targeted tests for the six specific resolutions.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import BY_ID, FAIL, WARN
from clawseccheck.checks import (
    CHECKS,
    check_bundled_root_override,
    check_compiled_tool_poisoning,
    check_fs_write_exposure,
    check_trustedproxy_loopback,
    check_unit_embedded_gateway_secret,
)
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _corpus_targets():
    homes = sorted(d for d in FIXTURES.iterdir() if d.is_dir() and not d.name.startswith("."))
    targets = []
    for h in homes:
        targets.append(h)
        nested = h / "openclaw_home"
        if nested.is_dir():
            targets.append(nested)
    return targets


CORPUS = _corpus_targets()


def test_corpus_is_non_empty():
    assert len(CORPUS) >= 400, "expected the full fixtures/ corpus (466+ homes)"


@pytest.mark.parametrize("home", CORPUS, ids=lambda p: str(p.relative_to(FIXTURES)))
def test_no_unscored_check_fails_on_the_real_corpus(home):
    """The mechanical guard B-315's own DoD asks for: drive every check over the
    fixture corpus and assert no scored=False CheckMeta's check function emits FAIL
    with Finding.scored still False — i.e. no FAIL is invisible to scoring.compute().

    This test calls each check function directly, bypassing run_all()'s per-check
    crash isolation (checks/__init__.py::_check_error_finding) and _run_content_ring's
    equivalent for --vet — both of which intentionally catch any raised exception and
    degrade to UNKNOWN in production. A check that raises here (e.g.
    skillast.ScriptProseCoverageIncomplete, deliberately raised rather than returning
    a silent [] when a bundled script's source can't be parsed at all — see that
    exception's own docstring) is not itself a B-315 violation; skip it rather than
    letting an intentional, already-handled raise fail this narrower assertion."""
    ctx = collect(home)
    for chk in CHECKS:
        try:
            f = chk(ctx)
        except Exception:  # noqa: BLE001 — mirrors run_all's own crash isolation
            continue
        if f.status == FAIL:
            assert f.scored is True, (
                f"{f.id} emitted FAIL with scored=False on {home} — this FAIL is "
                "invisible to scoring.compute() (B-315)."
            )


def test_catalog_scored_false_ids_match_the_audited_set():
    """Documents which CheckMeta entries are still scored=False so a future check
    author sees this file when they touch the set. Not exhaustive re-derivation of the
    architect audit — the corpus test above is what actually enforces the invariant."""
    unscored = {c.id for c in BY_ID.values() if not c.scored}
    assert {"B43", "B55", "B70", "B185", "B186", "B193", "B324", "B322", "B323", "B325"} <= unscored
    assert len(unscored) == 87


# ── Targeted: the two downgrades (FAIL -> WARN, CheckMeta unchanged) ──────────────────

def test_b43_never_fails():
    from clawseccheck.collector import Context
    from clawseccheck.checks import check_capability_blast_radius

    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {}
    # Shape that used to reach B43's FAIL branch (untrusted_to_action="ungated"
    # alongside high-blast-radius verbs) — see tests/test_attest.py's
    # test_b43_warns_high_blast_and_ungated for the full corpus of former-FAIL cases.
    ctx.attestation = {
        "tools": ["search", "send_email", "create_filter"],
        "untrusted_to_action": "ungated",
    }
    f = check_capability_blast_radius(ctx)
    assert f.status != FAIL
    assert f.status == WARN
    assert f.scored is False
    assert BY_ID["B43"].scored is False


def test_b70_never_fails():
    f = check_trustedproxy_loopback(
        collect(FIXTURES / "bad_b233_trustedproxy_nonloopback_no_headers")
    )
    assert f.status != FAIL
    assert f.status == WARN
    assert f.scored is False
    assert BY_ID["B70"].scored is False


# ── Targeted: the four per-finding promotions (FAIL -> scored=True override) ──────────

def test_b55_fail_branch_is_scored_but_checkmeta_is_not():
    assert BY_ID["B55"].scored is False  # WARN/PASS/UNKNOWN stay unscored (B3/B22/B31 own it)

    f = check_fs_write_exposure(collect(FIXTURES / "bad_b55_fs_write_broad"))
    assert f.status == FAIL
    assert f.scored is True  # per-finding override — this specific Finding participates


def test_b186_fail_branch_is_scored_but_checkmeta_is_not(tmp_path):
    import os

    assert BY_ID["B186"].scored is False  # WARN/PASS stay unscored (dev-relocation case)

    target = tmp_path / "relocated"
    target.mkdir()
    os.chmod(target, 0o777)
    home = tmp_path / ".openclaw"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "openclaw.service").write_text(
        f"[Service]\nEnvironment=OPENCLAW_BUNDLED_SKILLS_DIR={target}\n",
        encoding="utf-8",
    )
    f = check_bundled_root_override(collect(home))
    assert f.status == FAIL
    assert f.scored is True  # per-finding override — this specific Finding participates


def test_b193_fail_branch_is_scored_but_checkmeta_is_not(tmp_path):
    import os

    assert BY_ID["B193"].scored is False  # owner-only inline token stays unscored (hygiene)

    home = tmp_path / ".openclaw"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    token_var = "OPENCLAW_GATEWAY_" + "TOKEN"
    value = "q" * 12 + "3" + "cr" + "3t" + "7" * 12
    unit = unit_dir / "openclaw-gateway.service"
    unit.write_text(f"[Service]\nEnvironment={token_var}={value}\n", encoding="utf-8")
    os.chmod(unit, 0o644)
    f = check_unit_embedded_gateway_secret(collect(home))
    assert f.status == FAIL
    assert f.scored is True  # per-finding override — this specific Finding participates


def test_b185_fail_branch_scored_flag_when_reachable():
    """B185 needs a real trajectory sidecar with a context.compiled event to reach FAIL
    (see tests/test_b185_compiled_tool_poisoning.py for the full corpus) — this only
    pins the CheckMeta side of the contract, mirroring the B186/B193 tests above."""
    assert BY_ID["B185"].scored is False  # WARN/PASS/UNKNOWN stay unscored (log-presence)
    # The FAIL-branch scored=True override is exercised end-to-end by
    # tests/test_b185_compiled_tool_poisoning.py's many FAIL-asserting cases; this test
    # only needs to confirm none of them regress the CheckMeta side.
    ctx = collect(FIXTURES / "home_safe")
    f = check_compiled_tool_poisoning(ctx)
    if f.status == FAIL:
        assert f.scored is True
