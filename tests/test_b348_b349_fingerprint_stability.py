"""B-348 / B-349 — a finding's IDENTITY may depend on the audited config, and on nothing
else.

``baseline.fingerprint()`` hashes ``Finding.detail`` (``clawseccheck/baseline.py:37-42``),
and a real user's ``.clawseccheckignore`` keys a per-finding suppression on that exact
``<id>:<8-hex>`` string (``baseline.apply()``). So any span of a ``detail`` that varies
*without the audited configuration varying* silently un-suppresses a finding the user
deliberately triaged away: no error, no warning, the finding simply reappears as if newly
discovered. ``tests/test_finding_fingerprint_manifest.py`` catches that when a WORDING
change causes it. It cannot catch it when nothing was reworded at all — which is exactly
how these two arrived:

* **B-348, the wall clock.** B176 embedded ``lastSeenAgeDays=<N.N>d``, recomputed from
  ``time.time()`` on every run, in its ``detail``. Rounded to 0.1 day, a user's
  ``B176:<hash>`` suppression self-orphaned roughly every 2.4 hours on a completely
  unchanged config.
* **B-349, the scan root.** B158/B183/B184/B186/B192 embedded the absolute path of the
  audited home in their ``detail``, so relocating a workspace (or scanning the same skill
  from a different parent directory) orphaned every suppression for those five ids — and
  put the reporter's home-directory layout into any report they shared.

Both are fixed by moving the varying span out of ``detail`` while keeping it visible to
the reader: the age now rides in ``evidence=`` (which is NOT hashed and IS rendered under
a WARN, ``report.py``), and paths are rendered relative to the audited home, whose
absolute form the report header prints once ("Audited config: ...").

These tests pin the property directly — same config, different clock / different parent
directory, identical fingerprint — so a future change that re-introduces either channel
fails here with a name, rather than only showing up as an unexplained manifest diff.
"""
from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

import pytest

from clawseccheck import audit, baseline

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# The five ids B-349 found embedding the audited home in their detail. Each entry names a
# fixture that actually drives that check down a path-quoting branch, so the assertion is
# not vacuous (test_selected_fixtures_actually_emit_each_path_id proves it).
_PATH_ID_FIXTURES = {
    "B158": "bad_f119_missing_extradir",
    "B183": "bad_b100_clickfix_setup",
    "B184": "bad_b184_registry_env_dotenv",
    "B186": "bad_b186_bundled_dotenv/openclaw_home",
    "B192": "bad_b184_registry_env_dotenv",
}

_B176_FIXTURE = "bad_b176_paired_operator_admin"
_AGE_RE = re.compile(r"lastSeenAgeDays=\d+(?:\.\d+)?d")

# 45 days: far enough that every `lastSeenAgeDays` in the corpus moves by hundreds of
# tenths, so a surviving clock span cannot round to the same string by luck.
_CLOCK_JUMP_SECONDS = 45 * 86_400


def _findings_by_id(home: Path) -> dict:
    _, findings, _ = audit(home)
    return {f.id: f for f in findings}


def _fingerprints(home: Path) -> dict:
    return {f.id: baseline.fingerprint(f) for f in _findings_by_id(home).values()}


@pytest.fixture()
def frozen_clock(monkeypatch):
    """Freeze ``time.time`` at a caller-chosen offset. Patching ``time.time`` is
    exhaustive for the check engine: it is the only wall-clock read in the package
    outside ``scanbudget``'s ``time.monotonic()`` deadlines, and no module under
    ``clawseccheck/checks/`` calls ``datetime.now()`` / ``date.today()``."""
    def _freeze(offset_seconds: float) -> None:
        at = time.time() + offset_seconds
        monkeypatch.setattr(time, "time", lambda: at)
    return _freeze


# ---------------------------------------------------------------------------------------
# B-348 — the wall clock
# ---------------------------------------------------------------------------------------

def test_b176_fingerprint_survives_a_45_day_clock_jump(frozen_clock):
    """Same paired-devices config, two clocks 45 days apart, one fingerprint.

    Mutation check: restore ``lastSeenAgeDays=`` into B176's detail (checks/_lifecycle.py)
    and this fails with two different digests.
    """
    home = FIXTURES / _B176_FIXTURE

    frozen_clock(0)
    early = _findings_by_id(home)["B176"]
    early_fp, early_detail = baseline.fingerprint(early), early.detail

    frozen_clock(_CLOCK_JUMP_SECONDS)
    later = _findings_by_id(home)["B176"]

    assert later.status == early.status
    assert later.detail == early_detail, (
        "B176's detail text moved with the wall clock alone, so its fingerprint — and "
        "therefore any user's .clawseccheckignore suppression of this exact finding — "
        "does not survive the passage of time on an unchanged config"
    )
    assert baseline.fingerprint(later) == early_fp


def test_b176_keeps_the_device_age_out_of_detail_and_in_evidence():
    """The age is still reported; it just stops participating in the finding's identity.

    ``report.py`` renders up to 12 ``evidence`` lines under a WARN, so a reader still sees
    how stale each paired device is — which is the whole point of surfacing it.
    """
    f = _findings_by_id(FIXTURES / _B176_FIXTURE)["B176"]
    assert f.status == "WARN", f"fixture no longer drives B176 to WARN (got {f.status})"

    assert not _AGE_RE.search(f.detail), (
        "B176's detail embeds a wall-clock-derived age again — that span belongs in "
        f"evidence=, which is not hashed: {f.detail[:200]}"
    )
    assert any(_AGE_RE.search(e) for e in f.evidence), (
        "B176 no longer reports the device age anywhere the reader can see it; the fix "
        "was to move it into evidence=, not to delete it"
    )
    # The device identity itself must still be in the detail -- moving the age out is not
    # licence to make the finding text vague about WHICH device holds the authority.
    assert "deviceId=" in f.detail and "scopes=" in f.detail


def test_no_finding_detail_on_the_b176_fixture_is_clock_dependent(frozen_clock):
    """Whole-config sufficiency, not just B176: every fingerprint on this fixture is
    identical across the clock jump."""
    home = FIXTURES / _B176_FIXTURE

    frozen_clock(0)
    early = _fingerprints(home)
    frozen_clock(_CLOCK_JUMP_SECONDS)
    later = _fingerprints(home)

    drifted = sorted(k for k in set(early) | set(later) if early.get(k) != later.get(k))
    assert not drifted, f"clock-dependent Finding.detail on {_B176_FIXTURE}: {drifted}"


# ---------------------------------------------------------------------------------------
# B-349 — the scan root
# ---------------------------------------------------------------------------------------

def _relocate(src: Path, dest_root: Path) -> Path:
    """Copy fixture home *src* under *dest_root*, keeping its own directory NAME identical.

    Only the parent chain differs between the two copies, which is precisely the change a
    real user makes when they move a workspace or scan the same skill from somewhere else.
    """
    dest = dest_root / src.name
    dest_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dest)
    return dest


@pytest.mark.parametrize("fixture_rel", sorted(set(_PATH_ID_FIXTURES.values())))
def test_fingerprints_survive_relocation_to_a_different_parent(tmp_path, fixture_rel):
    """The same config under two different parent directories fingerprints identically.

    Asserted over EVERY id the audit emits, not just the five known ones — a new check
    that starts quoting the scan root gets caught here by name.

    Mutation check: revert any ``_detail_path()`` call in checks/_lifecycle.py /
    _config.py / _host.py to interpolate the raw path and this fails, naming that id.
    """
    src = FIXTURES / fixture_rel
    assert src.is_dir(), f"missing fixture {fixture_rel}"

    one = _relocate(src, tmp_path / "a")
    two = _relocate(src, tmp_path / "b" / "deeper" / "nest")

    left, right = _fingerprints(one), _fingerprints(two)
    drifted = sorted(k for k in set(left) | set(right) if left.get(k) != right.get(k))
    assert not drifted, (
        f"{fixture_rel}: Finding.detail depends on where the audited home lives, so these "
        f"ids' fingerprints do not survive the user relocating it: {drifted}"
    )


def test_selected_fixtures_actually_emit_each_path_id():
    """Non-vacuity: the relocation test above would pass trivially if these fixtures did
    not actually drive the five checks down a path-quoting branch."""
    missing = []
    for check_id, fixture_rel in sorted(_PATH_ID_FIXTURES.items()):
        found = _findings_by_id(FIXTURES / fixture_rel)
        if check_id not in found:
            missing.append((check_id, fixture_rel))
    assert not missing, f"fixture no longer emits the id it was chosen for: {missing}"


@pytest.mark.parametrize("check_id,fixture_rel", sorted(_PATH_ID_FIXTURES.items()))
def test_path_id_detail_does_not_quote_the_audited_home(tmp_path, check_id, fixture_rel):
    """Directly: the audited home's absolute path may not appear in these details at all.

    Scanning a relocated copy makes this exact, with no reliance on where the repo itself
    happens to sit: the temp root is a string that CANNOT legitimately appear in any
    config-derived span, because the fixture's own contents never mention it.
    """
    home = _relocate(FIXTURES / fixture_rel, tmp_path / "relocated")
    f = _findings_by_id(home)[check_id]
    assert str(tmp_path) not in f.detail, (
        f"{check_id} quotes the audited home's absolute path in its detail, which is "
        f"hashed into the finding's identity: {f.detail[:250]}"
    )
