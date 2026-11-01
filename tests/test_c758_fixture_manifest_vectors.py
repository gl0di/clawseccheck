"""C-758: the dependency manifests under two fixtures were edited after Dependabot
alerts (flask in bad_c256_corroboration, lodash/react in clean_f117_registry).
Those edits are legitimate only while the fixture still models what its test needs.
Pin the *shape* that matters, so a future bump that changes it is a red build.

- bad_c256_corroboration: the "unpinned dependency" corroboration signal must come
  from a bare (versionless) requirement line; the version of the other lines is
  filler and is deliberately NOT pinned.
- clean_f117_registry: B157's "clean" verdict rests on every dependency being a
  plain registry exact pin, so every version must stay a bare x.y.z string.
"""
import json
import re
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def test_c256_fixture_keeps_a_bare_unpinned_requirement():
    req = FIXTURES / "bad_c256_corroboration/skills/helper-tool/requirements.txt"
    lines = [ln.strip() for ln in req.read_text().splitlines() if ln.strip()]
    assert any(re.fullmatch(r"[A-Za-z0-9_.-]+", ln) for ln in lines), (
        "bad_c256_corroboration lost its bare unpinned requirement; the "
        "warns_unpinned corroboration signal would no longer fire"
    )


def test_f117_clean_fixture_keeps_exact_registry_pins():
    pj = FIXTURES / "clean_f117_registry/skills/deppy/package.json"
    deps = json.loads(pj.read_text())["dependencies"]
    assert deps, "clean_f117_registry has no dependencies"
    for name, ver in deps.items():
        assert re.fullmatch(r"\d+\.\d+\.\d+", ver), (
            f"{name}={ver!r} is not an exact registry pin; the clean fixture "
            "no longer models an exact pin"
        )
