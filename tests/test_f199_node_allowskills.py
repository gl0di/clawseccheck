"""F-199 — gateway.nodes.allowSkills, unread in either spelling (0 hits pre- and
post-rename, re-verified 2026-09-16).

Vendor description (schema-*.mjs, grounded against the installed 2026.9.5 dist):
"Accept skills published by paired nodes while they are connected (default: true)."
A paired node can publish executable skills into this setup while it is connected, and
the gate defaults OPEN — exactly the shape B71/B-698 already closed for the sibling
`gateway.nodes.commands`/`{allow,deny}Commands` setting, but for `allowSkills` this is a
rename in the OPPOSITE direction: pre-2026.8.1 nested it under
`gateway.nodes.skills.enabled`; 2026.8.1+ reads the flat `gateway.nodes.allowSkills`.

Every shape-parity assertion below is PARAMETRISED over the two spellings on purpose —
the exact failure shape B-698 had, where a per-shape test could go green while one
spelling silently stopped being read.
"""
from pathlib import Path

import pytest

from clawseccheck.checks import (
    _node_allow_skills,
    check_node_allowskills_default_on,
)
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(config, found=True):
    c = Context(home=Path("/nonexistent"))
    c.config = config
    c.config_found = found
    return c


def _cfg(shape, value):
    """The setting in the OLD spelling and the NEW one, as (label, config) pairs."""
    if shape == "legacy":
        return {"gateway": {"nodes": {"skills": {"enabled": value}}}}
    return {"gateway": {"nodes": {"allowSkills": value}}}


_SHAPES = ["legacy", "2026.8.1"]


# ---------------------------------------------------------------- the accessor

def test_accessor_reads_the_legacy_spelling():
    value, path = _node_allow_skills({"gateway": {"nodes": {"skills": {"enabled": False}}}})
    assert value is False
    assert path == "gateway.nodes.skills.enabled"


def test_accessor_reads_the_new_spelling():
    value, path = _node_allow_skills({"gateway": {"nodes": {"allowSkills": False}}})
    assert value is False
    assert path == "gateway.nodes.allowSkills"


def test_accessor_labels_the_shape_actually_found():
    """A 2026.8.1 user pointed at `gateway.nodes.skills.enabled` is pointed at a key
    their own file does not contain — the label is not cosmetic."""
    _, legacy_path = _node_allow_skills({"gateway": {"nodes": {"skills": {"enabled": False}}}})
    _, new_path = _node_allow_skills({"gateway": {"nodes": {"allowSkills": False}}})
    assert legacy_path != new_path


def test_new_key_wins_when_both_are_present():
    """Mirrors the vendor's own migration (legacy-*.mjs)::

        if (nodes.allowSkills === void 0) nodes.allowSkills = skills.enabled;

    The legacy value is used ONLY when the new key is absent.
    """
    cfg = {"gateway": {"nodes": {
        "skills": {"enabled": False},
        "allowSkills": True,
    }}}
    value, path = _node_allow_skills(cfg)
    assert value is True
    assert path == "gateway.nodes.allowSkills"


def test_an_explicit_null_new_key_still_wins():
    """`=== void 0` is false for `null`, so a present-but-null new key beats the legacy
    one for OpenClaw too."""
    cfg = {"gateway": {"nodes": {
        "skills": {"enabled": False},
        "allowSkills": None,
    }}}
    value, _path = _node_allow_skills(cfg)
    assert value is None


def test_accessor_is_quiet_on_a_config_with_neither():
    for cfg in ({}, {"gateway": {}}, {"gateway": {"nodes": {}}},
                {"gateway": {"nodes": {"skills": {}}}}, {"gateway": "not-a-dict"}):
        value, path = _node_allow_skills(cfg)
        assert value is None, cfg
        assert path == "gateway.nodes.allowSkills"


# -------------------------------------------------------------------- B386 (the check)

@pytest.mark.parametrize("shape", _SHAPES)
def test_warns_on_explicit_true_in_either_shape(shape):
    r = check_node_allowskills_default_on(_ctx(_cfg(shape, True)))
    assert r.status == "WARN", shape
    assert r.evidence, shape


@pytest.mark.parametrize("shape", _SHAPES)
def test_passes_on_explicit_false_in_either_shape(shape):
    r = check_node_allowskills_default_on(_ctx(_cfg(shape, False)))
    assert r.status == "PASS", shape


def test_warns_when_absent_default_true():
    for cfg in ({}, {"gateway": {}}, {"gateway": {"nodes": {}}}):
        r = check_node_allowskills_default_on(_ctx(cfg))
        assert r.status == "WARN", cfg


def test_absent_and_explicit_true_read_identically():
    """Same effective-state doctrine B196 applies to browser.evaluateEnabled: the
    vendor default is true, so leaving the key out must not read as safer than writing
    `true` by hand -- both are WARN, and neither is UNKNOWN."""
    absent = check_node_allowskills_default_on(_ctx({"gateway": {"nodes": {}}}))
    explicit = check_node_allowskills_default_on(
        _ctx({"gateway": {"nodes": {"allowSkills": True}}}))
    assert absent.status == explicit.status == "WARN"


@pytest.mark.parametrize("shape", _SHAPES)
def test_user_facing_text_names_the_shape_actually_present(shape):
    r = check_node_allowskills_default_on(_ctx(_cfg(shape, True)))
    expected = ("gateway.nodes.skills.enabled" if shape == "legacy"
                else "gateway.nodes.allowSkills")
    wrong = ("gateway.nodes.allowSkills" if shape == "legacy"
             else "gateway.nodes.skills.enabled")
    blob = " ".join([r.detail or "", r.fix or "", *(r.evidence or [])])
    assert expected in blob
    assert wrong not in blob


def test_unknown_when_no_config_found():
    r = check_node_allowskills_default_on(_ctx({}, found=False))
    assert r.status == "UNKNOWN"


def test_unknown_when_config_unparseable():
    c = _ctx({})
    c.config_parse_error = True
    r = check_node_allowskills_default_on(c)
    assert r.status == "UNKNOWN"


def test_still_registered_and_scored_consistently():
    from clawseccheck.catalog import BY_ID
    meta = BY_ID["B386"]
    assert meta.scored is False


# ------------------------------------------------------------------- fixtures

@pytest.mark.parametrize("name,status", [
    ("bad_b386_allowskills_default_on", "WARN"),
    ("clean_b386_allowskills_disabled_legacy", "PASS"),
])
def test_fixture_produces_the_expected_status(name, status):
    from clawseccheck.collector import collect
    r = check_node_allowskills_default_on(collect(FIXTURES / name))
    assert r.status == status, (name, r.detail)
