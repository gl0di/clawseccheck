import sys
from pathlib import Path

import pytest

# make the skill package importable when running pytest from anywhere
sys.path.insert(0, str(Path(__file__).resolve().parent))

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _deterministic_fixture_perms():
    """Pin fixture config perms to 600 so at-rest perm checks are deterministic
    regardless of the umask at checkout time."""
    for cfg in _FIXTURES.rglob("openclaw.json"):
        cfg.chmod(0o600)
    yield
