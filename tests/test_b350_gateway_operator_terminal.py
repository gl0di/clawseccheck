"""B350 — the gateway operator terminal, a PTY-backed shell served to Control UI/mobile.

Grounded against the installed dist (openclaw@2026.7.1-2):
`gateway.terminal` is `{enabled?: boolean, shell?: string,
detachedSessionTimeoutSeconds?: number}` — `plugin-sdk/config-schema.d.ts:4499-4503`.
An object only, with no boolean shorthand, so unlike `tools.codeMode` there is no second
shape to read. `schema-DRyO1XBt.js:130` gives the default as false and states enabling it
"exposes a browser/mobile shell with the gateway process environment".

The design point these tests exist to pin: the VERDICT does not branch on the bind.
`_gateway_remote_exposure_reason` returns None for BOTH "proven loopback" and "cannot be
resolved" (the `auto` profile), so branching on it would turn an unresolvable bind into a
silent PASS — the fail-open shape this project keeps finding. The bind only shapes the
REACH sentence in the detail.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import BY_ID, HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import CHECKS, check_gateway_operator_terminal
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _f(name: str):
    return check_gateway_operator_terminal(collect(FIXTURES / name))


# ------------------------------------------------------------------ the default is quiet
@pytest.mark.parametrize("name", [
    "clean_b350_terminal_absent",
    "clean_b350_terminal_disabled",
])
def test_clean_fixtures_pass(name):
    f = _f(name)
    assert f.status == PASS, f"{name}: expected PASS, got {f.status}: {f.detail}"
    assert "not enabled" in f.detail


# ------------------------------------------------------------------ it fires when on
@pytest.mark.parametrize("name", [
    "bad_b350_terminal_on_lan",
    "bad_b350_terminal_on_loopback",
    "bad_b350_terminal_on_unresolvable_bind",
])
def test_enabled_terminal_warns_whatever_the_bind(name):
    """The whole point: enabling it is reportable on its own.

    All three binds — proven-remote, proven-loopback, unresolvable — reach the same
    WARN. If a future change makes one of these go silent, it has made the verdict
    depend on the bind, which is the fail-open shape the docstring warns about.
    """
    f = _f(name)
    assert f.status == WARN, f"{name}: expected WARN, got {f.status}: {f.detail}"
    assert "gateway.terminal.enabled is true" in f.detail


def test_it_never_fails():
    """WARN-only by design — a FAIL tier needs its own C-135 pass first."""
    for name in ("bad_b350_terminal_on_lan", "bad_b350_terminal_on_loopback",
                 "bad_b350_terminal_on_unresolvable_bind"):
        assert _f(name).status != "FAIL", name


# ------------------------------------------------------------------ the reach sentence
def test_reach_distinguishes_the_three_binds():
    """Proven-loopback must not be described the way an unresolvable bind is.

    `_gateway_remote_exposure_reason` collapses both to None, so the check reads
    parse_bind_host/LOOPBACK FIRST. This test is what fails if that ordering is lost:
    the loopback fixture would start claiming its reach "cannot be resolved".
    """
    lan = _f("bad_b350_terminal_on_lan").detail
    loop = _f("bad_b350_terminal_on_loopback").detail
    auto = _f("bad_b350_terminal_on_unresolvable_bind").detail

    assert "reachable beyond loopback" in lan
    assert "only from this host" in loop
    assert "cannot be resolved from config alone" in auto

    # and they are genuinely three different sentences, not one string that happens to
    # contain all three substrings
    assert len({lan, loop, auto}) == 3


def test_a_pinned_shell_is_named_and_an_unset_one_is_described():
    """`.shell` unset launches the host login $SHELL (dist description :131)."""
    pinned = _f("bad_b350_terminal_on_loopback").detail
    unset = _f("bad_b350_terminal_on_lan").detail
    assert "/usr/bin/bash" in pinned
    assert "host login shell" in unset


# ------------------------------------------------------------------ UNKNOWN, not a fake PASS
def test_an_unreadable_config_is_unknown_not_pass(tmp_path):
    """§2.4: when the check cannot determine state it must say so.

    An empty directory has no openclaw.json, so the config was never read — reporting
    "the terminal is not enabled" there would be a verdict over ground nobody looked at.
    """
    f = check_gateway_operator_terminal(collect(tmp_path))
    assert f.status == UNKNOWN, f"expected UNKNOWN, got {f.status}: {f.detail}"


# ------------------------------------------------------------------ wiring, not just the fn
def test_the_check_is_actually_registered():
    """A check that exists but is never called is the failure this repo keeps finding.

    Asserting on the function alone would stay green with the registration deleted, so
    this asserts the CHECKS list itself — the thing run_all iterates.
    """
    assert check_gateway_operator_terminal in CHECKS


def test_catalog_entry_matches_what_the_check_emits():
    meta = BY_ID["B350"]
    assert meta.severity == HIGH
    assert meta.surface == "gateway"
    emitted = _f("bad_b350_terminal_on_lan")
    assert emitted.id == "B350"
    assert emitted.title == meta.title
    assert emitted.severity == meta.severity


# ------------------------------------------------------------------ what must NOT fire
def _ctx(gateway, tmp_path):
    """A Context whose config locus counts as READ — otherwise every branch below would
    land on the no-gateway-config UNKNOWN instead of the one under test."""
    return Context(home=tmp_path, config={"gateway": gateway}, config_found=True)


def test_a_present_terminal_block_without_enabled_is_quiet(tmp_path):
    """The dist default is false, so a block that only sets the timeout is not a finding."""
    ctx = _ctx({"terminal": {"detachedSessionTimeoutSeconds": 300}}, tmp_path)
    assert check_gateway_operator_terminal(ctx).status == PASS


def test_a_gateway_with_no_terminal_key_is_a_real_pass(tmp_path):
    """Distinguishes a genuine PASS from the UNKNOWN above: the gateway block WAS read
    and simply carries no terminal config, which is the shipped default."""
    ctx = _ctx({"bind": "127.0.0.1:8080"}, tmp_path)
    assert check_gateway_operator_terminal(ctx).status == PASS


def test_only_a_real_boolean_true_counts(tmp_path):
    """`enabled` is ZodBoolean; a truthy non-bool is a config OpenClaw would reject, so
    reading it as "on" would be asserting something about a config that never loads."""
    for truthy in ("true", 1, "yes"):
        ctx = _ctx({"terminal": {"enabled": truthy}}, tmp_path)
        assert check_gateway_operator_terminal(ctx).status == PASS, truthy


# ---------------------------------------------------- the fail-open branch, pinned open
def test_a_malformed_gateway_value_is_unknown_not_pass(tmp_path):
    """`"gateway": null` makes every dig() below degrade to its default without raising,
    which is indistinguishable from "terminal simply not configured". Reporting PASS
    there is a verdict over ground the check never actually read."""
    for malformed in (None, [], 7, "on"):
        ctx = Context(home=tmp_path, config={"gateway": malformed}, config_found=True)
        f = check_gateway_operator_terminal(ctx)
        assert f.status == UNKNOWN, f"{malformed!r}: got {f.status}: {f.detail}"


def test_a_read_config_with_no_gateway_block_is_a_PASS_not_an_unknown(tmp_path):
    """Found by an independent adversarial pass, and it was a real defect.

    The first version of this check collapsed "gateway absent" into the malformed-gateway
    UNKNOWN, whose detail said "No gateway config was read" — about a config that HAD been
    read. It was also inconsistent with its own semantics: `{"gateway": {}}` returned PASS
    while `{"tools": {...}}` with no gateway returned UNKNOWN, though both encode the same
    fact. 72 of the fixture homes are this shape, so it was not hypothetical.

    An absent gateway block cannot enable the terminal: the vendor gates the feature on
    `gateway?.terminal?.enabled === true`, which nothing absent can satisfy.
    """
    ctx = Context(home=tmp_path, config={"tools": {"profile": "minimal"}}, config_found=True)
    f = check_gateway_operator_terminal(ctx)
    assert f.status == PASS, f"got {f.status}: {f.detail}"
    assert "was read" not in f.detail, "must not claim the config went unread"


def test_an_empty_gateway_object_and_an_absent_one_agree(tmp_path):
    """The inconsistency the adversarial pass named: both encode "default false"."""
    absent = Context(home=tmp_path, config={"tools": {}}, config_found=True)
    empty = Context(home=tmp_path, config={"gateway": {}}, config_found=True)
    assert (check_gateway_operator_terminal(absent).status
            == check_gateway_operator_terminal(empty).status == PASS)


def test_a_malformed_gateway_names_the_type_it_found(tmp_path):
    """UNKNOWN here must say what it actually saw, so the fix text is actionable."""
    f = check_gateway_operator_terminal(
        Context(home=tmp_path, config={"gateway": []}, config_found=True))
    assert f.status == UNKNOWN
    assert "not an object" in f.detail and "list" in f.detail


def test_a_completely_read_empty_config_is_not_applicable_not_a_bare_unknown(tmp_path):
    """The two empty states must not collapse into one.

    config_found=True with an empty config means the locus was read and there is no
    gateway surface to misconfigure -> not_applicable. A host with no openclaw.json at
    all (config_found=False) is a real UNKNOWN and must NOT be marked not_applicable,
    because nothing was read.
    """
    read_and_empty = Context(home=tmp_path, config={}, config_found=True)
    never_read = Context(home=tmp_path, config={}, config_found=False)

    a = check_gateway_operator_terminal(read_and_empty)
    b = check_gateway_operator_terminal(never_read)
    assert a.status == UNKNOWN and b.status == UNKNOWN
    assert a.not_applicable is True, "a completely-read empty config should be N/A"
    assert b.not_applicable is False, "a config that was never read is a real UNKNOWN"


def test_an_included_gateway_fragment_is_seen_the_same_as_an_inline_one(tmp_path):
    """`$include` layering, named as an untested FN surface by the adversarial pass.

    `configloader` resolves `$include` while the collector builds ctx.config, so a
    gateway block that arrives from a fragment is indistinguishable from an inline one
    by the time any check runs. Pinned with a positive control — the same content inline
    — because "the included one warned" alone would not prove the two agree.
    """
    import json

    included = tmp_path / "inc"
    included.mkdir()
    (included / "gw.json").write_text(json.dumps(
        {"bind": "0.0.0.0:8080", "terminal": {"enabled": True, "shell": "/bin/bash"}}),
        encoding="utf-8")
    (included / "openclaw.json").write_text(json.dumps(
        {"tools": {"profile": "minimal"}, "gateway": {"$include": "./gw.json"}}),
        encoding="utf-8")

    inline = tmp_path / "inline"
    inline.mkdir()
    (inline / "openclaw.json").write_text(json.dumps(
        {"tools": {"profile": "minimal"},
         "gateway": {"bind": "0.0.0.0:8080",
                     "terminal": {"enabled": True, "shell": "/bin/bash"}}}),
        encoding="utf-8")

    via_include = check_gateway_operator_terminal(collect(included))
    via_inline = check_gateway_operator_terminal(collect(inline))
    assert via_include.status == WARN
    assert via_include.status == via_inline.status
    assert via_include.detail == via_inline.detail
