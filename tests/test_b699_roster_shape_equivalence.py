"""B-699 — the two agent-roster shapes must reach the same verdicts.

The whole premise of the 4.0.0 release is that the published build reads
``agents.list`` only, so a config written by OpenClaw 2026.8.1 — which writes
``agents.entries`` — produced an EMPTY roster and several per-agent checks then asserted
a clean verdict about it. ``collector.agent_roster`` is the single reader that closes
that, and it was validated differentially against the vendor.

What was NOT covered is the property a user actually depends on: **the same setup,
written in either shape, must be judged the same way.** Every existing test asks whether
one check reads one shape. This asks whether the CATALOG agrees with itself across both,
which is the only form of the question that catches a check nobody thought to update.

## Why this covers 8 fixtures and not all 21

A ``list`` entry carries its id in an ``id`` field, and that field is optional — the
array position is the identity when it is absent. An ``entries`` record is keyed BY id,
and ``listAgentEntriesWithSource`` makes the KEY win over any ``id`` inside the entry. So
a list entry with no ``id`` has **no faithful translation**: inventing a key would give
the agent an identity it does not have in the source shape, and the two configs would no
longer describe the same setup. That is a real asymmetry between the shapes, not a gap in
this test, so the untranslatable fixtures are named below rather than quietly skipped.

Worth recording because a release-plan checklist named three fixtures for exactly this
comparison and one of them, ``bad_b4_peragent_sandbox``, is in the untranslatable set —
its single agent is ``{"name": "Gary"}`` with no id. The other two are covered here.

## Why the comparison is on (check, status) and not on text

``AgentEntry.path`` is ``agents.list[0]`` in one shape and ``agents.entries.<key>`` in
the other, and findings quote it. That difference is correct — it points the reader at
their own file — so comparing rendered detail would fail on a difference that is the
feature. Status per check is what a user acts on.

Offline; writes only inside ``tmp_path``. Both sides of every comparison run from
``tmp_path``, so any location-sensitive check is perturbed identically on both and
cancels out — which is sound for an equivalence test but WOULD be vacuous if it silenced
everything, so ``test_the_comparison_is_not_vacuous`` pins that the fixtures' own
findings still fire there.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.collector import agent_roster

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

#: Fixtures whose every ``agents.list`` entry carries a string id, so the record form can
#: be built without inventing identity. Derived once and pinned, so a fixture that gains
#: or loses an id shows up as a change here rather than silently leaving the comparison.
TRANSLATABLE = (
    "bad_b351_codemode_agent_only",
    "bad_b351_codemode_global_on_agent_narrowed",
    "bad_b352_agent_only_prepend",
    "clean_agent_profile_narrower",
    "clean_b409_real_allowlist_intersection_unaffected",
    "clean_b409_weak_agent_profile_no_widening",
    "warn_b409_profile_alsoallow_widening",
    "warn_b55_agent_profile_widens",
)

#: Named, not skipped. Every one of these has a list entry with no ``id``, so it has no
#: faithful record-shape twin — see the module docstring.
UNTRANSLATABLE_NO_ID = (
    "bad_b283_fs_per_agent_optout",
    "bad_b326_elevated_default_full",
    "bad_b327_embedded_agent_project_settings_policy",
    "bad_b4_peragent_sandbox",
    "clean_b326_elevated_default_absent",
    "clean_b326_elevated_default_on",
    "clean_b327_embedded_agent_project_settings_policy",
    "clean_b4_peragent_sandbox",
    "clean_b4_peragent_sandbox_shared_scope",
    "unknown_b326_elevated_default_env_var",
    "warn_b326_elevated_default_full_dormant",
    "warn_b326_elevated_default_full_exec_hardened",
    "warn_b326_elevated_default_full_no_allowfrom",
)


def _fixture_config(name: str) -> tuple[Path, dict]:
    """The fixture's config path and parsed body, whichever layout it uses."""
    for candidate in (FIXTURES / name / "openclaw.json", FIXTURES / f"{name}.json"):
        if candidate.is_file():
            return candidate, json.loads(candidate.read_text(encoding="utf-8"))
    raise AssertionError(f"fixture {name!r} not found under {FIXTURES}")


def _to_entries(cfg: dict) -> dict:
    """Rewrite ``agents.list`` as ``agents.entries``, keyed by each entry's own id.

    The ``id`` field is dropped from the value because the record form's schema rejects it
    and the vendor re-injects the key as the id regardless — keeping it would test a shape
    OpenClaw will not load.
    """
    out = json.loads(json.dumps(cfg))
    entries = {}
    for entry in out["agents"]["list"]:
        body = {k: v for k, v in entry.items() if k != "id"}
        entries[entry["id"]] = body
    out["agents"].pop("list")
    out["agents"]["entries"] = entries
    return out


def _home_with(tmp_path: Path, name: str, cfg: dict, label: str) -> Path:
    """A throwaway home carrying *cfg*, with the fixture's other files alongside it."""
    home = tmp_path / label
    source = FIXTURES / name
    if source.is_dir():
        shutil.copytree(source, home)
    else:
        home.mkdir(parents=True, exist_ok=True)
    config = home / "openclaw.json"
    config.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    config.chmod(0o600)  # conftest pins fixture configs this way; at-rest checks read it
    return home


def _verdicts(home: Path) -> dict:
    _ctx, findings, _score = audit(home)
    return {f.id: f.status for f in findings}


# ── the property ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", TRANSLATABLE)
def test_both_roster_shapes_reach_the_same_verdicts(name, tmp_path):
    """The same setup, written either way, is judged the same way."""
    _path, cfg = _fixture_config(name)
    as_list = _home_with(tmp_path, name, cfg, "list")
    as_entries = _home_with(tmp_path, name, _to_entries(cfg), "entries")

    left, right = _verdicts(as_list), _verdicts(as_entries)
    differing = {c: (left.get(c), right.get(c))
                 for c in set(left) | set(right) if left.get(c) != right.get(c)}
    assert not differing, (
        f"{name}: these checks judge the two roster shapes differently — "
        f"{differing}. A user who upgraded OpenClaw would get a different verdict for a "
        "setup they did not change.")


@pytest.mark.parametrize("name", TRANSLATABLE)
def test_the_roster_itself_is_read_in_both_shapes(name):
    """Precondition, asserted rather than assumed: if either shape produced an EMPTY
    roster, the verdicts above would agree for the most trivial possible reason."""
    _path, cfg = _fixture_config(name)
    from_list = agent_roster(cfg)
    from_entries = agent_roster(_to_entries(cfg))
    assert from_list, f"{name}: the list shape yields no agents at all"
    assert len(from_entries) == len(from_list)
    assert {a.id for a in from_entries} == {a.id for a in from_list}


def test_the_comparison_is_not_vacuous(tmp_path):
    """A negative needs a positive control.

    Every home here is built under ``tmp_path``, and location-sensitive checks behave
    differently outside the workspace. That perturbs both sides identically, so the
    equivalence stays sound — but if it silenced the fixtures' own findings, the test
    above would be comparing two empty verdict sets and passing for nothing.

    So: the three fixtures named for a WARN or FAIL must still produce one there.
    """
    from clawseccheck.catalog import FAIL, WARN

    unfired = []
    for name in ("bad_b351_codemode_agent_only", "warn_b409_profile_alsoallow_widening",
                 "warn_b55_agent_profile_widens"):
        _path, cfg = _fixture_config(name)
        verdicts = _verdicts(_home_with(tmp_path, name, cfg, f"probe-{name}"))
        if not any(v in (FAIL, WARN) for v in verdicts.values()):
            unfired.append(name)
    assert not unfired, (
        f"{unfired} produced no FAIL or WARN under tmp_path, so the equivalence check "
        "above is comparing silence with silence")


def test_the_untranslatable_fixtures_really_have_no_id(tmp_path):
    """The exclusion list is a claim about the corpus, so it is checked against it.

    Without this, a fixture could gain an id and quietly stay outside the comparison —
    a silently shrinking test, which is the shape this release spent the day removing.
    """
    wrong = []
    for name in UNTRANSLATABLE_NO_ID:
        _path, cfg = _fixture_config(name)
        ids = [e.get("id") for e in cfg["agents"]["list"] if isinstance(e, dict)]
        if all(isinstance(i, str) and i for i in ids):
            wrong.append(name)
    assert not wrong, (
        f"{wrong} now carry ids on every agent, so they CAN be translated — move them "
        "into TRANSLATABLE rather than leaving them excluded")


def test_the_two_partitions_together_are_every_list_form_fixture():
    """No fixture falls between the two lists unnoticed."""
    listed = set(TRANSLATABLE) | set(UNTRANSLATABLE_NO_ID)
    found = set()
    for path in sorted(FIXTURES.glob("*.json")) + sorted(FIXTURES.glob("*/openclaw.json")):
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        agents = cfg.get("agents")
        if not isinstance(agents, dict) or not isinstance(agents.get("list"), list):
            continue
        if not agents["list"]:
            continue
        found.add(path.parent.name if path.name == "openclaw.json" else path.stem)
    assert found == listed, (
        f"list-form fixtures not accounted for: {sorted(found - listed)}; "
        f"listed but no longer list-form: {sorted(listed - found)}")
