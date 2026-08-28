"""B-499 — an absent ``dmPolicy`` is not a restriction; OpenClaw resolves it to "pairing".

A1 previously reported a config that never wrote ``dmPolicy`` identically to one that
restricted ingress: both PASS, same text. They are not the same posture. Grounded against
the installed dist (openclaw@2026.7.1-2): 8 schema sites bind
``dmPolicy: DmPolicySchema.optional().default("pairing")``, 7 more bind a bare
``.optional()`` resolved by one of 48 runtime ``?? "pairing"`` fallbacks.

Dave's 2026-08-21 decision was deliberately NOT to make this a trifecta leg. Promoting a
resolved default to a leg would move the leg count on ordinary configs, which is the
Golden Rule #5 risk that kept this deferred for months. So it is a WARN-grade signal that
A1 *discloses* while ``active`` stays untouched — and the two kill criteria below are the
tests that keep it that way:

  K6a  no A1 verdict may flip to FAIL anywhere    (test_no_fixture_home_gains_an_a1_fail)
  K6b  the leg count may not move anywhere        (test_no_fixture_home_changes_its_leg_count)

Both are asserted over EVERY fixture home, not a sample — measured 537 homes, 6 PASS->WARN
moves, 0 FAIL flips, 0 leg-count moves.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, UNKNOWN, WARN
from clawseccheck.checks import check_trifecta
from clawseccheck.checks._shared import _resolved_default_input_channels
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CONFIG_NAMES = {"openclaw.json", "clawdbot.json", "openclaw.json5", "openclaw.jsonc"}


def _fixture_homes() -> list[Path]:
    """Every directory holding an OpenClaw config. A home is never nested in another."""
    homes: list[Path] = []
    for d, sub, files in __import__("os").walk(FIXTURES):
        if CONFIG_NAMES & set(files):
            homes.append(Path(d))
            sub[:] = []
    return sorted(homes)


# --------------------------------------------------------------------------- the helper


def test_absent_dmpolicy_is_reported():
    cfg = {"channels": {"telegram": {"enabled": True}}}
    assert _resolved_default_input_channels(cfg) == ["telegram"]


@pytest.mark.parametrize("written", ["open", "allowlist", "pairing", "disabled"])
def test_a_written_dmpolicy_is_never_a_resolved_default(written):
    """The signal is about the field being ABSENT. A config that wrote "pairing" by hand
    made a choice; this check has nothing to say about it.

    These four are the whole of ``DmPolicySchema`` in the installed dist — grounded, not
    guessed. An earlier draft of this test also parametrised ``"owner"``, which is NOT a
    schema member anywhere in the dist; pinning it here would have pinned a false claim,
    and the remediation text that recommended it was steering users into the
    unmodeled-literal gap described below."""
    cfg = {"channels": {"telegram": {"enabled": True, "dmPolicy": written}}}
    assert _resolved_default_input_channels(cfg) == []


def test_the_remediation_never_recommends_a_value_the_schema_rejects():
    """Golden Rule #4, applied to our own advice. The first version of this WARN told the
    user to write ``dmPolicy: "owner"``. ``DmPolicySchema`` is
    ``open | pairing | allowlist | disabled`` (Feishu/Lark: the first three), so "owner"
    is unmodeled: on Feishu it normalises to "pairing" and leaves ingress live while this
    tool reports PASS, and on every other channel zod refuses the config outright. Either
    way the advice was wrong, and one of those ways is a lying PASS we caused.

    Found by an independent C-135 pass, which is the only reason it is not shipped.

    Uses a fixture with a real tool surface, not a hand-built minimal config: a thin
    config returns the older thin-surface WARN first, so `fix` would be that branch's
    attestation text and this test would assert nothing about our own."""
    f = check_trifecta(collect(home=str(FIXTURES / "clean_risk21_owner_origin_exec")))
    assert "Resolved default" in f.detail, "did not reach the branch under test"
    assert "disabled" in f.fix
    for invented in ('"owner"', "`owner`"):
        assert invented not in f.fix, f"remediation recommends a non-schema value: {f.fix}"


def test_an_unmodeled_dmpolicy_is_not_reported_as_a_resolved_default():
    """Scope boundary, pinned so it is not mistaken for coverage. An unmodeled literal is
    neither absent nor a known untrusted policy, so it falls through this helper AND
    ``_untrusted_input_channels`` — the silent-PASS gap documented at ``_shared.py`` in
    ``_norm_group_policy``'s docstring. B-499 does NOT close it; closing it is Feishu/Lark
    scoped (only their normaliser maps a stray literal to "pairing"; elsewhere zod rejects
    the config so it never runs) and needs its own measurement and C-135."""
    cfg = {"channels": {"feishu": {"enabled": True, "dmPolicy": "owner"}}}
    assert _resolved_default_input_channels(cfg) == []


def test_a_disabled_channel_ingests_nothing():
    cfg = {"channels": {"telegram": {"enabled": False}}}
    assert _resolved_default_input_channels(cfg) == []


def test_the_defaults_node_is_not_a_channel():
    """`channels.defaults` holds defaults. Three sibling helpers skip it by name and one
    (``_untrusted_input_channels``) does not; this one skips it, matching the majority and
    the in-source comment. Reporting it would put the word "defaults" in user-facing text
    as if it were a messaging channel."""
    cfg = {"channels": {"defaults": {"enabled": True}}}
    assert _resolved_default_input_channels(cfg) == []


def test_an_account_inherits_the_channels_written_policy():
    """Account -> channel precedence. An account that omits dmPolicy under a channel that
    sets it is NOT a resolved default — the effective value was chosen, one level up."""
    cfg = {
        "channels": {
            "telegram": {"enabled": True, "dmPolicy": "disabled", "accounts": {"a": {}}},
        }
    }
    assert _resolved_default_input_channels(cfg) == []


def test_an_account_absent_under_a_channel_absent_is_reported_once():
    cfg = {
        "channels": {
            "telegram": {"enabled": True, "accounts": {"a": {}, "b": {}}},
        }
    }
    assert _resolved_default_input_channels(cfg) == ["telegram"]


def test_a_channel_already_counted_as_untrusted_is_not_reported_twice():
    """An "open" groupPolicy already makes this a full A1 leg. Adding a softer signal for
    the same channel would say the same thing twice and pad the WARN text."""
    cfg = {"channels": {"telegram": {"enabled": True, "groupPolicy": "open"}}}
    assert _resolved_default_input_channels(cfg) == []


def test_schema_drifted_accounts_do_not_raise():
    """B-378 idiom: a non-dict `accounts` degrades to "no accounts", never crashes."""
    for drift in ("not-a-dict", ["a"], 7, None):
        cfg = {"channels": {"telegram": {"enabled": True, "accounts": drift}}}
        assert _resolved_default_input_channels(cfg) == ["telegram"]


def test_a_non_dict_channel_does_not_raise():
    cfg = {"channels": {"telegram": "not-a-dict"}}
    assert _resolved_default_input_channels(cfg) == []


# --------------------------------------------------------------------------- A1 end to end


def _ctx(tmp_path: Path, cfg, *, raw: bool = False):
    """A home laid out the way `collect` actually resolves it: the config sits at
    ``<home>/openclaw.json``, not under a ``.openclaw/`` subdirectory. Getting this wrong
    yields an empty ``ctx.config`` and a WARN from the unrelated thin-surface branch — a
    test that passes while asserting nothing, which is how the first draft of this file
    "passed"."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    p = home / "openclaw.json"
    p.write_text(cfg if raw else json.dumps(cfg), encoding="utf-8")
    p.chmod(0o600)
    ctx = collect(home=str(home))
    if not raw:
        # Vacuity guard: every assertion below is meaningless if the config was not read.
        assert ctx.config, "collect() did not read the fixture config"
    return ctx


def test_a1_warns_and_names_the_channel(tmp_path):
    f = check_trifecta(_ctx(tmp_path, {"channels": {"telegram": {"enabled": True}}}))
    assert f.status == WARN, f.status
    assert "telegram" in f.detail
    assert "pairing" in f.detail
    # The disclosure has to say it is NOT a leg, or a reader will assume the leg count moved.
    assert "Not counted as a leg" in f.detail


def test_a1_says_nothing_when_every_channel_wrote_its_policy(tmp_path):
    """A config this small cannot reach PASS at all — the pre-existing thin-surface guard
    (B-033) fires first, because a config with no tool surface cannot resolve two of the
    three legs. So the assertion is about the DISCLOSURE, not the status: with the policy
    written, this change must contribute nothing, and the WARN that remains must be the
    older one. Asserting PASS here would have been asserting something this fixture never
    produces, on either side of the change."""
    cfg = {"channels": {"telegram": {"enabled": True, "dmPolicy": "owner"}}}
    f = check_trifecta(_ctx(tmp_path, cfg))
    assert "Resolved default" not in f.detail
    assert "Cannot determine from config" in f.detail, "expected the thin-surface WARN"
    assert "--attest" in f.fix, "the remaining WARN must keep its own remediation"


def test_the_leg_count_never_moves(tmp_path):
    """K6b at unit scale: the same config with and without a written dmPolicy must produce
    the same `active` list. Only the status and the disclosure differ."""
    absent = check_trifecta(_ctx(tmp_path, {"channels": {"telegram": {"enabled": True}}}))
    tmp2 = tmp_path / "two"
    tmp2.mkdir()
    written = check_trifecta(
        _ctx(tmp2, {"channels": {"telegram": {"enabled": True, "dmPolicy": "owner"}}})
    )
    assert sorted(absent.evidence or []) == sorted(written.evidence or [])


def test_a_real_fail_is_not_downgraded_to_the_new_warn():
    """The WARN branch sits AFTER the >=3-leg FAIL return. A 3/3 trifecta whose channels
    also omit dmPolicy must still FAIL — a disclosure must never soften a verdict."""
    f = check_trifecta(collect(home=str(FIXTURES / "home_vuln")))
    assert f.status == FAIL, f.status


def test_an_unreadable_config_stays_unknown(tmp_path):
    """B-306's guard runs first. A config the audit could not read must not acquire a
    confidently-worded WARN from this change."""
    ctx = _ctx(tmp_path, '{"channels": {"telegram": {"enabled": tr', raw=True)  # truncated
    assert ctx.config_parse_error, "the truncated config was not detected as unparseable"
    f = check_trifecta(ctx)
    assert f.status == UNKNOWN, f.status
    assert "Resolved default" not in f.detail


def test_the_warn_branch_is_what_moves_the_verdict():
    """THE guard for the half of this change that moves verdicts.

    Added after an independent C-135 pass found the file vacuous in exactly one place:
    deleting the entire WARN branch from `check_trifecta` left all 20 original tests
    green while flipping six fixture homes back WARN->PASS. The test that looked like
    this guard (`test_a1_warns_and_names_the_channel`) is not one — its config is thin
    enough that the older B-033 thin-surface WARN returns first, so its `status == WARN`
    is satisfied by pre-change code.

    This fixture is chosen because it isolates the branch: two legs (so no FAIL), a real
    tool surface (so the thin-surface WARN does NOT fire), and a channel with no
    dmPolicy. Without the branch it PASSes; with it, it WARNs. If someone deletes the
    branch, this is the test that goes red."""
    ctx = collect(home=str(FIXTURES / "clean_risk21_owner_origin_exec"))
    f = check_trifecta(ctx)
    assert f.status == WARN, f.status
    assert "Resolved default" in f.detail
    # Prove the WARN is THIS branch's and not one of the two that outrank it.
    assert len(f.evidence or []) == 2, f.evidence  # not the >=3-leg FAIL
    assert "Cannot determine from config" not in f.detail  # not the thin-surface WARN


def test_the_distance_note_stops_advising_against_a_state_already_in_force(tmp_path):
    """B-499 follow-up from the same C-135 pass: the two sentences contradicted each
    other inside one paragraph — "the missing leg is 'untrusted input'. Avoid enabling a
    non-owner channel ..." printed immediately before "telegram ... runs on pairing".
    The imperative is dropped when ingress is resolved-by-default; the consequence stays,
    because the consequence is still true.

    The shape has to be built rather than borrowed: it needs the two OTHER legs active so
    the missing one is 'untrusted input'. The risk21 fixtures do not qualify — their
    active pair already includes untrusted input, so the missing leg there is sensitive
    data and this branch correctly never fires."""
    home = tmp_path / "home"
    home.mkdir()
    # B-666: the store's CONTENT raises the leg, not the directory's existence — an empty
    # `credentials/` used to be enough here and is (correctly) inert now. Assembled from
    # fragments so no contiguous secret-shaped literal exists in source (§2.3).
    store = home / "credentials"
    store.mkdir()
    (store / "oauth.json").write_text(
        json.dumps({"access_token": "ya29." + "A" * 40}), encoding="utf-8"
    )
    cfg = {
        "channels": {"telegram": {"enabled": True}},  # no dmPolicy -> resolved default
        "tools": {"elevated": {"allowFrom": ["*"]}},  # outbound-actions leg
    }
    p = home / "openclaw.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    p.chmod(0o600)
    f = check_trifecta(collect(home=str(home)))

    assert sorted(f.evidence or []) == ["outbound actions", "sensitive data"], f.evidence
    assert "the missing leg is 'untrusted input'" in f.detail
    assert "undeclared rather than closed" in f.detail
    assert "Avoid enabling" not in f.detail, "stale advice survived next to the disclosure"
    # The consequence must not be softened away along with the imperative.
    assert "one injected prompt is enough" in f.detail


# --------------------------------------------------------------------------- kill criteria


def test_no_fixture_home_gains_an_a1_fail():
    """K6a, over EVERY fixture home. A WARN-grade signal that convicts is not this task."""
    homes = _fixture_homes()
    assert len(homes) > 400, f"fixture discovery is broken, found {len(homes)}"
    # home_vuln and its kin are legitimately FAIL on 3/3 legs; what must not happen is a
    # FAIL whose only cause is a resolved default, i.e. a FAIL on a home with <3 legs.
    for home in homes:
        f = check_trifecta(collect(home=str(home)))
        if f.status == FAIL:
            assert len(f.evidence or []) >= 3, (
                f"{home.name}: A1 FAILs on {len(f.evidence or [])} legs — a resolved "
                "default must never be able to produce a FAIL"
            )


def test_no_fixture_home_changes_its_leg_count():
    """K6b, over EVERY fixture home: `active` is a function of `_trifecta_legs` alone, and
    `_resolved_default_input_channels` is not one of its inputs. Asserted rather than
    argued, because 'it cannot affect that' is exactly the claim this project has seen
    turn out false."""
    from clawseccheck.checks._shared import _trifecta_legs

    for home in _fixture_homes():
        ctx = collect(home=str(home))
        legs = _trifecta_legs(ctx)
        expected = sorted(k for k, v in legs.items() if v)
        f = check_trifecta(ctx)
        assert sorted(f.evidence or []) == expected, home.name
