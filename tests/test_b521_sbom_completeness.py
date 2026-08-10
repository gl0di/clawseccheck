"""B-521 — the AI-BOM must not claim completeness while withholding a component.

`build_sbom` set ``"complete": config_found``, i.e. "complete" was an alias for "we found
a config". But the collector deliberately drops clawseccheck's own skill from the
inventory (``collector.py`` ``_OWN_SKILL_NAMES`` -> ``ctx.self_excluded_skills``). The
exclusion is sound — a tool auditing itself is noise — but it makes the component list
short by one, and the BOM asserted completeness anyway.

``report.py`` has disclosed the exclusion since B-507. The BOM never did, so a consumer
reading only this file (the whole point of a machine-readable export: diffing, archiving,
feeding other local tooling) could not distinguish a genuinely complete inventory from a
pruned one.

That is the same defect B-463 fixed one field over — two different facts serialising
identically — so the fix has the same shape: say the true thing, and ship the names so a
consumer can tell WHICH component is absent, not merely that one is.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.collector import Context
from clawseccheck.sbom import build_sbom, render_sbom

_HOME_FAKE = Path("/nonexistent/home")


def _ctx(*, config_found: bool, excluded: list) -> Context:
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {"some-skill": "---\nname: some-skill\n---\n"}
    ctx.config = {}
    ctx.config_found = config_found
    ctx.self_excluded_skills = list(excluded)
    return ctx


def test_withheld_skill_makes_the_bom_not_complete():
    """The defect itself."""
    bom = build_sbom(_ctx(config_found=True, excluded=["clawseccheck"]))
    assert bom["config_found"] is True
    assert bom["complete"] is False


def test_the_withheld_names_are_shipped_not_just_the_flag():
    """A consumer has to be able to tell WHICH component is missing."""
    bom = build_sbom(_ctx(config_found=True, excluded=["clawseccheck"]))
    assert bom["self_excluded_skills"] == ["clawseccheck"]


def test_nothing_withheld_is_still_complete():
    """The fix must not make every BOM incomplete — that would be the same lie inverted."""
    bom = build_sbom(_ctx(config_found=True, excluded=[]))
    assert bom["complete"] is True
    assert bom["self_excluded_skills"] == []


def test_no_config_is_still_not_complete():
    """B-463's arm stays intact: a home we never found is not an empty inventory."""
    bom = build_sbom(_ctx(config_found=False, excluded=[]))
    assert bom["complete"] is False


def test_a_pruned_bom_does_not_serialise_like_a_whole_one():
    """The B-463 property, restated for this field: the two states must be tellable
    apart from the bytes alone, because that is all a diff pipeline ever sees."""
    whole = render_sbom(_ctx(config_found=True, excluded=[]))
    pruned = render_sbom(_ctx(config_found=True, excluded=["clawseccheck"]))
    assert whole != pruned


def test_excluded_names_are_sorted_for_deterministic_output():
    """Everything else in this export is stably ordered; a set-ordered list would make
    the BOM diff against itself."""
    bom = build_sbom(_ctx(config_found=True, excluded=["zebra", "alpha", "middle"]))
    assert bom["self_excluded_skills"] == ["alpha", "middle", "zebra"]


def test_a_context_without_the_attribute_does_not_crash():
    """`build_sbom` takes a duck-typed ctx; older//partial ones must not blow up."""
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    ctx.config = {}
    ctx.config_found = True
    del ctx.self_excluded_skills
    bom = build_sbom(ctx)
    assert bom["self_excluded_skills"] == []
    assert bom["complete"] is True


def test_the_field_survives_json_round_trip():
    payload = json.loads(render_sbom(_ctx(config_found=True, excluded=["clawseccheck"])))
    assert payload["complete"] is False
    assert payload["self_excluded_skills"] == ["clawseccheck"]
