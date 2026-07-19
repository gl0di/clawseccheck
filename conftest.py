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
