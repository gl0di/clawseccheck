import sys
from pathlib import Path

import pytest

# make the skill package importable when running pytest from anywhere
sys.path.insert(0, str(Path(__file__).resolve().parent))

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


# Fixtures whose POINT is a loose mode: the finding they demonstrate IS the permission,
# so inheriting the checkout umask would silently disarm them (under `umask 077` the
# "bad" fixture stops being bad and the audit returns PASS). Pinned open for the same
# reason openclaw.json is pinned shut — determinism regardless of the checkout umask.
_LOOSE_FIXTURE_FILES = {
    # B182: the ClawHub CLI token store the bad fixture exposes to other local users.
    "bad_b182_clawhub_token_store/.config/clawhub/config.json": 0o644,
}

# The mirror image: fixtures whose point is a TIGHT mode. git records only the executable
# bit, so without this the checkout umask decides the verdict — and B188 is a HIGH scored
# FAIL, so a CI runner with umask 022 would turn a clean fixture into a false FAIL while
# this machine (whose $HOME is 0750 and seals the whole tree) stayed green. Pinned for the
# same determinism reason as the loose set above.
_TIGHT_FIXTURE_PATHS = {
    # B188: a genuine state database, so the fixture corpus actually EXERCISES the check
    # instead of exiting at its "no state database found" branch (every other fixture home
    # has no state DB at all, so B188 returns UNKNOWN on all of them).
    "clean_b188_state_db/state": 0o700,
    "clean_b188_state_db/state/openclaw.sqlite": 0o600,
    # CLAWSECCHECK-B-309 C-135 follow-up: this fixture's whole point is B164's
    # exfil_evidence WARN firing off a `logs/app.log` sink, isolated from B19 (data
    # at-rest) noise — an umask-dependent group/world-readable logs/ dir would add an
    # unrelated scored B19 WARN and make the score comparison against
    # clean_i025_b164_baseline non-deterministic across checkout umasks.
    "clean_i025_b164_residual_no_cap/logs": 0o700,
    "clean_i025_b164_residual_no_cap/logs/app.log": 0o600,
    # CLAWSECCHECK-B-309 C-135 FOLLOW-UP #2: same reason as the residual fixture above —
    # this fixture's whole point is B164's exfil_evidence WARN firing (but NOT cap-
    # eligible) off a `logs/app.log` sink, isolated from B19 noise so the score
    # comparison against clean_i025_b164_baseline stays deterministic across umasks.
    "clean_i025_b164_own_api_log_no_cap/logs": 0o700,
    "clean_i025_b164_own_api_log_no_cap/logs/app.log": 0o600,
    # CLAWSECCHECK-B-309 C-135 FOLLOW-UP #3: same reason as the two fixtures above —
    # this fixture's whole point is B164's exfil_evidence WARN firing (but NOT cap-
    # eligible, since the line names a known host with no independent transport verb)
    # off a `logs/app.log` sink, isolated from B19 noise so the score comparison
    # against clean_i025_b164_baseline stays deterministic across umasks.
    "clean_i025_b164_host_mention_no_verb_no_cap/logs": 0o700,
    "clean_i025_b164_host_mention_no_verb_no_cap/logs/app.log": 0o600,
}


@pytest.fixture(scope="session", autouse=True)
def _deterministic_fixture_perms():
    """Pin fixture config perms so at-rest perm checks are deterministic
    regardless of the umask at checkout time."""
    for cfg in _FIXTURES.rglob("openclaw.json"):
        cfg.chmod(0o600)
    for rel, mode in _LOOSE_FIXTURE_FILES.items():
        target = _FIXTURES / rel
        if target.is_file():
            target.chmod(mode)
    for rel, mode in _TIGHT_FIXTURE_PATHS.items():
        target = _FIXTURES / rel
        if target.exists():  # dirs as well as files
            target.chmod(mode)
    yield


@pytest.fixture(autouse=True)
def _stub_host_detect(monkeypatch):
    """Keep host-monitor detection deterministic and offline across the suite.

    Every audit()/CLI run sees an 'unsupported' host, so the B50–B54 host-posture
    checks report UNKNOWN and never touch the score on the CI/dev machine (whose
    real host monitors are nondeterministic). Tests that exercise host detection
    call clawseccheck.hostwatch.detect() directly (with a fake root), or re-patch
    clawseccheck._host_detect themselves, and are unaffected by this stub.
    """
    import clawseccheck
    monkeypatch.setattr(
        clawseccheck, "_host_detect",
        lambda root="/", **_: {"system": "test", "supported": False, "classes": {}},
    )
