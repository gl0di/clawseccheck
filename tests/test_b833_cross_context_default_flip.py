"""B363 (re-grounded B-833) — the default of tools.message.crossContext.allowAcrossProviders
flipped from DENY to ALLOW in OpenClaw 2026.9.5, in code, with the config path and the
schema's own default/enum unchanged.

    2026.9.4  outbound-policy-*.mjs:122   allowAcrossProviders === true    (unset = deny)
    2026.9.5  outbound-policy-*.mjs:122   allowAcrossProviders !== false   (unset = allow)

Before this fix B363 PASSed an unset key with "(or is unset, the shipped default)" on every
build. The tests below pin the three-valued build answer (``deny`` / ``allow`` /
``unknown``), the resulting verdict matrix, and the two things that must NOT move: the
explicit-``true`` WARN text (``baseline.fingerprint()`` hashes ``detail``, so changing it
orphans users' ``.clawseccheckignore`` entries) and the per-agent-wins precedence.

Offline and read-only: no dist is read, the build is injected through
``Context.installed_dist_version`` or ``meta.lastTouchedVersion``.
"""
from __future__ import annotations

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _ACTIONS_ALLOW_UNDETERMINED,
    _CROSS_CONTEXT_DEFAULT_ALLOW_MIN,
    _CROSS_CONTEXT_DENY_MEASURED_MIN,
    _MESSAGE_CROSS_CONTEXT_GUARDED_ACTIONS,
    _cross_context_default,
    _message_actions_allow_for_scope,
    _message_actions_guarded_reachable,
    check_cross_context_send,
)
from clawseccheck.collector import Context

_KEY = "tools.message.crossContext.allowAcrossProviders"
_UNSET = object()  # distinguishes "field absent" from "field set to None" below


def _cc(value):
    return {"crossContext": {"allowAcrossProviders": value}}


def _global(value):
    return {"tools": {"message": _cc(value)}}


def _agent(value=None):
    """An agent entry with its own value, or with none when *value* is None."""
    return {} if value is None else {"tools": {"message": _cc(value)}}


def _entries(**agents):
    return {"agents": {"entries": dict(agents)}}


def _msg(cc=_UNSET, allow=_UNSET):
    """A ``tools.message`` node (global or per-agent) with an optional crossContext
    value and/or actions.allow list, either of which may be left OUT entirely (the
    `_UNSET` sentinel default) rather than set to ``None`` -- callers of C-579's
    stand-down logic need to distinguish "no actions node at all" from "actions.allow
    explicitly empty"."""
    message: dict = {}
    if cc is not _UNSET:
        message["crossContext"] = {"allowAcrossProviders": cc}
    if allow is not _UNSET:
        message["actions"] = {"allow": allow}
    return message


def _global_msg(cc=_UNSET, allow=_UNSET):
    return {"tools": {"message": _msg(cc, allow)}}


def _agent_msg(cc=_UNSET, allow=_UNSET):
    message = _msg(cc, allow)
    return {"tools": {"message": message}} if message else {}


def _ctx(cfg, tmp_path, version=None):
    return Context(home=tmp_path, config=cfg, config_found=True,
                   installed_dist_version=version)


def _stamped(version, cfg=None):
    out = dict(cfg or {})
    out["meta"] = {"lastTouchedVersion": version}
    return out


# ----------------------------------------------------------------------------------------
# the build answer
class TestCrossContextDefault:
    @pytest.mark.parametrize("installed, expected", [
        ("2026.9.4", "deny"),
        ("2026.9.4-1", "deny"),       # a correction suffix sorts BELOW the next release
        ("2026.9.3", "deny"),
        ("2026.8.1", "deny"),
        ("2026.7.1-2", "deny"),
        ("2026.6.34", "deny"),        # the extended-stable line, resolver read
        ("2026.6.9", "deny"),         # the oldest release whose resolver was read
        ("2026.6.8", "unknown"),      # older than the measured series: never extrapolated
        ("2026.5.1", "unknown"),
        ("2025.12.3", "unknown"),
        ("0.0.0", "unknown"),         # not a calendar release: no confident safe verdict
        ("2026.9", "unknown"),        # ... nor is a two-part string
        ("2026.9.5", "allow"),
        ("2026.9.5-1", "allow"),      # ... and a suffix on the threshold itself sorts at/above it
        ("2026.9.6", "allow"),
        ("2026.10.1", "allow"),       # calendar-numeric, not lexicographic
        ("2027.1.1", "allow"),
        ("2026.9.5-beta.1", "unknown"),   # a pre-release is unorderable, never assumed
        ("not a version", "unknown"),
        ("", "unknown"),
    ])
    def test_installed_version_decides_outright(self, tmp_path, installed, expected):
        assert _cross_context_default(_ctx({}, tmp_path, installed)) == expected

    def test_an_installed_version_beats_a_contradicting_stamp(self, tmp_path):
        """The installed build's resolver is the one that runs; the stamp only says which
        build last SAVED the config."""
        ctx = _ctx(_stamped("2026.9.5"), tmp_path, "2026.9.4")
        assert _cross_context_default(ctx) == "deny"
        ctx = _ctx(_stamped("2026.9.4"), tmp_path, "2026.9.5")
        assert _cross_context_default(ctx) == "allow"

    def test_a_stamp_at_or_after_the_flip_proves_allow(self, tmp_path):
        assert _cross_context_default(_ctx(_stamped("2026.9.5"), tmp_path)) == "allow"
        assert _cross_context_default(_ctx(_stamped("2026.9.7"), tmp_path)) == "allow"

    @pytest.mark.parametrize("stamp", ["2026.9.4", "2026.9.3", "2026.7.1-2", "", None])
    def test_a_stale_stamp_never_proves_deny(self, tmp_path, stamp):
        """The user may have upgraded five minutes ago without re-saving: a stamp BELOW
        the threshold proves nothing about what is installed now."""
        cfg = {} if stamp is None else _stamped(stamp)
        assert _cross_context_default(_ctx(cfg, tmp_path)) == "unknown"

    def test_no_version_at_all_is_unknown(self, tmp_path):
        assert _cross_context_default(_ctx({}, tmp_path)) == "unknown"

    def test_the_thresholds_are_the_measured_releases(self):
        assert _CROSS_CONTEXT_DEFAULT_ALLOW_MIN == (2026, 9, 5)
        assert _CROSS_CONTEXT_DENY_MEASURED_MIN == (2026, 6, 9)

    def test_an_unplaceable_installed_version_never_yields_a_pass(self, tmp_path):
        """The C-135 finding: 'deny' is the answer that PASSes, so a version string we
        cannot place on the measured timeline must not reach it."""
        for version in ("0.0.0", "2026.9", "2026.6.8", "1.0.0"):
            f = check_cross_context_send(_ctx({"tools": {}}, tmp_path, version))
            assert f.status == UNKNOWN, version


# ----------------------------------------------------------------------------------------
# the verdict matrix
class TestUnsetKey:
    def test_unset_on_a_denying_build_is_pass(self, tmp_path):
        f = check_cross_context_send(_ctx({"tools": {}}, tmp_path, "2026.9.4"))
        assert f.status == PASS
        assert "before 2026.9.5" in f.detail and "denies" in f.detail

    def test_unset_on_the_flipped_build_warns(self, tmp_path):
        """THE regression this task exists for: this used to PASS with "the shipped
        default" while the 9.5 runtime allowed cross-provider sends."""
        f = check_cross_context_send(_ctx({"tools": {}}, tmp_path, "2026.9.5"))
        assert f.status == WARN
        assert "unset" in f.detail and "2026.9.5" in f.detail
        assert f.evidence and f.evidence[0].startswith(_KEY)
        # the fix names the key, the value to set and WHY (the default moved)
        assert "false" in f.fix and "ALLOW" in f.fix

    def test_unset_with_a_correction_release_of_the_flipped_build_warns(self, tmp_path):
        assert check_cross_context_send(
            _ctx({"tools": {}}, tmp_path, "2026.9.5-1")).status == WARN

    def test_unset_on_the_prior_line_correction_release_still_passes(self, tmp_path):
        assert check_cross_context_send(
            _ctx({"tools": {}}, tmp_path, "2026.9.4-1")).status == PASS

    def test_unset_and_the_build_unknown_is_unknown_not_a_hedged_pass(self, tmp_path):
        f = check_cross_context_send(_ctx({"tools": {}}, tmp_path))
        assert f.status == UNKNOWN
        assert "could not be determined" in f.detail
        # the fix must not name a default it cannot establish as fact
        assert "explicitly" in f.fix

    def test_a_prerelease_of_the_flipped_build_is_unknown(self, tmp_path):
        f = check_cross_context_send(_ctx({"tools": {}}, tmp_path, "2026.9.5-beta.1"))
        assert f.status == UNKNOWN

    def test_a_stamp_from_the_flipped_build_warns_without_an_install(self, tmp_path):
        f = check_cross_context_send(_ctx(_stamped("2026.9.5"), tmp_path))
        assert f.status == WARN

    def test_a_stale_stamp_and_no_install_is_unknown(self, tmp_path):
        f = check_cross_context_send(_ctx(_stamped("2026.9.4"), tmp_path))
        assert f.status == UNKNOWN

    def test_an_empty_crossContext_object_is_unset(self, tmp_path):
        cfg = {"tools": {"message": {"crossContext": {}}}}
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5")).status == WARN
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4")).status == PASS

    @pytest.mark.parametrize("bad", ["false", "true", None, 0, 1, [], {}, ""])
    def test_a_non_boolean_value_is_treated_as_unset_at_the_global_scope(self, tmp_path, bad):
        """C-135: the schema declares the key boolean().optional() and OpenClaw refuses to
        load a config that violates it (InvalidConfigError), so a non-boolean never reaches
        the resolver. The check reads it as UNSET, the same way at BOTH scopes."""
        cfg = _global(bad)
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5")).status == WARN
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4")).status == PASS
        assert check_cross_context_send(_ctx(cfg, tmp_path)).status == UNKNOWN

    @pytest.mark.parametrize("bad", ["false", "true", None, 0, 1, [], {}, ""])
    def test_a_non_boolean_value_is_treated_as_unset_at_the_agent_scope(self, tmp_path, bad):
        """The two scopes must AGREE (the C-135 defect): an agent's non-boolean inherits the
        global value exactly as an agent with no value does."""
        cfg = {**_global(False), **_entries(w=_agent(bad))}
        for version in (None, "2026.9.4", "2026.9.5"):
            assert check_cross_context_send(_ctx(cfg, tmp_path, version)).status == PASS
        cfg = _entries(w=_agent(bad))
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5")).status == WARN


class TestExplicitValues:
    @pytest.mark.parametrize("version", [None, "2026.9.4", "2026.9.5", "2026.9.5-beta.1"])
    def test_explicit_false_is_pass_on_every_build(self, tmp_path, version):
        f = check_cross_context_send(_ctx(_global(False), tmp_path, version))
        assert f.status == PASS
        assert "explicitly false" in f.detail

    @pytest.mark.parametrize("version", [None, "2026.9.4", "2026.9.5"])
    def test_explicit_true_warns_on_every_build(self, tmp_path, version):
        f = check_cross_context_send(_ctx(_global(True), tmp_path, version))
        assert f.status == WARN

    def test_explicit_true_text_is_byte_identical_to_the_pre_fix_wording(self, tmp_path):
        """`baseline.fingerprint()` is sha1(detail): moving this string orphans every
        `.clawseccheckignore` entry a user already wrote for the B363 WARN. The fix text
        for a default-allow finding is separate; THIS detail must never move."""
        f = check_cross_context_send(_ctx(_global(True), tmp_path, "2026.9.4"))
        assert f.detail == (
            "1 scope(s) resolve tools.message.crossContext.allowAcrossProviders to "
            "true: tools.message.crossContext.allowAcrossProviders — the message tool "
            "can send into a conversation on a different channel provider than the one "
            "it is currently bound to.")
        assert f.fix == (
            "Keep allowAcrossProviders false unless an agent genuinely needs to relay "
            "across providers; if it does, prefer the per-agent override over the global "
            "default so unrelated agents stay confined.")


class TestPerAgent:
    """Per-agent keys WIN over the global value, key by key, and an agent that leaves the
    key unset INHERITS — which on 2026.9.5+ means it inherits ALLOW."""

    def test_global_unset_one_agent_false_another_unset_warns_on_9_5(self, tmp_path):
        """The vendor executed differential: `other` is DENIED on 9.4 and ALLOWED on 9.5."""
        cfg = _entries(pub=_agent(False), other=_agent())
        f = check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5"))
        assert f.status == WARN
        assert "unset" in f.detail
        # ... and passes on the build that denied by default
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4")).status == PASS

    def test_global_false_and_an_agent_that_leaves_it_unset_is_pass_on_9_5(self, tmp_path):
        cfg = {**_global(False), **_entries(a=_agent())}
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5")).status == PASS

    def test_global_false_and_an_agent_that_widens_it_warns_naming_only_that_agent(self, tmp_path):
        cfg = {**_global(False), **_entries(safe=_agent(), widened=_agent(True))}
        for version in ("2026.9.4", "2026.9.5", None):
            f = check_cross_context_send(_ctx(cfg, tmp_path, version))
            assert f.status == WARN
            assert "widened" in f.detail and "safe" not in f.detail

    def test_global_unset_and_every_agent_explicitly_false_still_warns_on_9_5(self, tmp_path):
        """Deliberate: an unset GLOBAL still applies to any scope with no value of its own
        (an agent added later, an implicit default agent), and `set the global key to false`
        is a one-line remediation. Documented rather than hidden."""
        cfg = _entries(a=_agent(False), b=_agent(False))
        f = check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5"))
        assert f.status == WARN
        assert f.evidence and f.evidence[0].startswith(_KEY)

    def test_an_agent_true_and_an_unset_global_lists_both_scopes_on_9_5(self, tmp_path):
        cfg = _entries(w=_agent(True))
        f = check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5"))
        assert f.status == WARN and len(f.evidence) == 2

    def test_legacy_agents_list_roster_shape_is_read_too(self, tmp_path):
        """2026.8.1 moved agents.list[] to agents.entries{}; both must be honoured."""
        cfg = {"agents": {"list": [{"id": "a"}, {"id": "b", **_agent(False)}]}}
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5")).status == WARN
        cfg = {**_global(False),
               "agents": {"list": [{"id": "a"}, {"id": "w", **_agent(True)}]}}
        f = check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5"))
        assert f.status == WARN and "w" in f.detail


class TestUnchangedGuards:
    def test_an_unread_config_is_unknown_on_every_build(self, tmp_path):
        for version in (None, "2026.9.4", "2026.9.5"):
            ctx = Context(home=tmp_path, config={}, config_found=False,
                          installed_dist_version=version)
            assert check_cross_context_send(ctx).status == UNKNOWN

    def test_a_malformed_global_node_is_unknown_on_every_build(self, tmp_path):
        cfg = {"tools": {"message": {"crossContext": "nope"}}}
        for version in (None, "2026.9.4", "2026.9.5"):
            assert check_cross_context_send(_ctx(cfg, tmp_path, version)).status == UNKNOWN

    def test_a_malformed_agent_node_is_unknown_when_nothing_else_warns(self, tmp_path):
        cfg = {**_global(False),
               "agents": {"entries": {"a": {"tools": {"message": {"crossContext": "nope"}}}}}}
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5")).status == UNKNOWN

    def test_an_offender_outranks_a_malformed_sibling(self, tmp_path):
        """Same precedence the check always had: a proven WARN is not downgraded by an
        unreadable neighbour."""
        cfg = {"agents": {"entries": {
            "bad": {"tools": {"message": {"crossContext": "nope"}}},
            "w": _agent(True)}}}
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4")).status == WARN


# ----------------------------------------------------------------------------------------
# C-579: tools.message.actions.allow modelled -- B363 stands down (WARN -> PASS) only when
# the effective allow-list PROVABLY excludes every guarded cross-context action.
class TestActionsAllowUnit:
    """The two pure helpers in isolation, before trusting the integration behaviour."""

    def test_absent_actions_node_is_no_restriction(self):
        assert _message_actions_allow_for_scope(None, None) is None

    def test_empty_actions_object_is_no_restriction(self):
        assert _message_actions_allow_for_scope({}, None) is None

    def test_a_normalized_empty_list_is_no_restriction_not_exclude_everything(self):
        """The vendor gotcha this module exists to mirror: resolveAllowedMessageActions
        treats a normalized-empty list exactly like unset."""
        assert _message_actions_allow_for_scope({"allow": []}, []) is None
        assert _message_actions_allow_for_scope({"allow": [" ", ""]}, [" ", ""]) is None

    def test_a_real_restriction_normalizes_trims_and_dedupes(self):
        """Trims whitespace and dedupes, but never lowercases -- action names are
        case-sensitive strings in the vendor's own normalizeUniqueStringEntries."""
        result = _message_actions_allow_for_scope(
            {"allow": ["send", " send ", "Send", "poll"]},
            ["send", " send ", "Send", "poll"])
        assert result == frozenset({"send", "Send", "poll"})

    def test_actions_not_an_object_is_undetermined(self):
        assert _message_actions_allow_for_scope("nope", None) is _ACTIONS_ALLOW_UNDETERMINED

    def test_allow_not_a_list_is_undetermined(self):
        assert _message_actions_allow_for_scope({"allow": "send"}, "send") is \
            _ACTIONS_ALLOW_UNDETERMINED

    def test_allow_with_a_non_string_entry_is_undetermined(self):
        """Never silently drop the bad entry and reason from the rest -- a mixed list
        does not validate against OpenClaw's own array(string()) schema either."""
        assert _message_actions_allow_for_scope(
            {"allow": ["reaction", 5]}, ["reaction", 5]) is _ACTIONS_ALLOW_UNDETERMINED

    def test_guarded_reachable_true_for_none_and_undetermined(self):
        assert _message_actions_guarded_reachable(None) is True
        assert _message_actions_guarded_reachable(_ACTIONS_ALLOW_UNDETERMINED) is True

    def test_guarded_reachable_false_only_when_disjoint(self):
        assert _message_actions_guarded_reachable(frozenset({"typing", "reaction"})) is False
        assert _message_actions_guarded_reachable(frozenset({"typing", "send"})) is True

    def test_the_guarded_set_matches_the_grounded_vendor_list(self):
        """outbound-policy-CSxk6Tec.mjs:9-25, openclaw@2026.9.5 -- CONTEXT_GUARDED_ACTIONS."""
        assert _MESSAGE_CROSS_CONTEXT_GUARDED_ACTIONS == frozenset({
            "send", "poll", "poll-vote", "reply", "sendWithEffect", "sendAttachment",
            "upload-file", "edit", "delete", "pin", "unpin", "thread-create",
            "thread-reply", "topic-create", "topic-edit", "sticker",
        })


class TestActionsAllowStandDown:
    def test_empty_allow_list_does_not_stand_down_explicit_true(self, tmp_path):
        """The empty-array gotcha, through the full check: [] must not be misread as
        'excludes everything'."""
        cfg = _global_msg(cc=True, allow=[])
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4")).status == WARN

    def test_a_guarded_action_in_the_allow_list_does_not_stand_down(self, tmp_path):
        cfg = _global_msg(cc=True, allow=["send"])
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4")).status == WARN

    def test_explicit_true_stands_down_when_the_allow_list_excludes_every_guarded_action(
            self, tmp_path):
        cfg = _global_msg(cc=True, allow=["typing"])
        f = check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4"))
        assert f.status == PASS
        assert "explicitly true" in f.detail
        assert "['typing']" in f.detail
        assert f.evidence == ["typing"]
        assert "false first" in f.fix

    def test_a_malformed_actions_object_never_stands_down(self, tmp_path):
        cfg = {"tools": {"message": {"crossContext": {"allowAcrossProviders": True},
                                      "actions": "nope"}}}
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4")).status == WARN

    def test_a_malformed_allow_value_never_stands_down(self, tmp_path):
        cfg = _global_msg(cc=True, allow="send")
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4")).status == WARN

    def test_an_allow_list_with_a_non_string_entry_never_stands_down(self, tmp_path):
        cfg = _global_msg(cc=True, allow=["reaction", 5])
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4")).status == WARN

    def test_default_allow_unset_stands_down_when_nothing_inherits_a_guarded_action(
            self, tmp_path):
        cfg = _global_msg(allow=["typing"])  # crossContext left unset entirely
        f = check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5"))
        assert f.status == PASS
        assert "excludes every guarded cross-context action" in f.detail
        assert f.evidence == ["typing"]
        # the prior-line build is unaffected either way (still denies by default)
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4")).status == PASS

    def test_default_allow_unset_still_warns_when_an_inheriting_agent_reopens_it(
            self, tmp_path):
        """The global scope excludes every guarded action, but an agent that inherits
        the unset crossContext default has its OWN actions.allow reopen one -- the
        default-allow bucket must not stand down just because the GLOBAL leg is clean."""
        cfg = {**_global_msg(allow=["typing"]),
               **_entries(w={"tools": {"message": {"actions": {"allow": ["send"]}}}})}
        f = check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5"))
        assert f.status == WARN
        assert "unset — defaults to true" in f.detail

    def test_an_agent_with_its_own_excluding_allow_list_stands_down_alone(self, tmp_path):
        """One agent's own actions.allow excludes every guarded action; a sibling with
        no allow-list of its own stays reachable and is the only one named."""
        cfg = _entries(
            quiet={"tools": {"message": {"crossContext": {"allowAcrossProviders": True},
                                          "actions": {"allow": ["typing"]}}}},
            loud=_agent(True),
        )
        f = check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.4"))
        assert f.status == WARN
        assert "loud" in f.detail and "quiet" not in f.detail

    def test_an_agent_with_no_actions_node_inherits_the_global_exclusion(self, tmp_path):
        """An agent that sets its own crossContext=true but no actions.allow of its own
        falls back to the GLOBAL actions.allow -- same per-key-wins shallow merge the
        crossContext leg already gets."""
        cfg = {**_global_msg(allow=["typing"]),
               **_entries(w=_agent(True))}
        f = check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5"))
        assert f.status == PASS


class TestActionsAllowMetamorphic:
    """C-579's own requirement: adding tools.message.actions.allow must never RAISE
    severity -- it may only stand a WARN down to PASS (when it provably excludes every
    guarded action) or leave the verdict exactly where it was (anything undeterminable,
    or a list that still includes a guarded action)."""

    _BASELINE_WARN_CONFIGS = [
        _global_msg(cc=True),
        _global_msg(),  # unset, default-allow build
        {**_entries(w=_agent(True))},
    ]

    @pytest.mark.parametrize("cfg", _BASELINE_WARN_CONFIGS)
    def test_baseline_configs_really_are_warn_on_9_5(self, tmp_path, cfg):
        assert check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5")).status == WARN

    @pytest.mark.parametrize("cfg", _BASELINE_WARN_CONFIGS)
    def test_adding_an_excluding_allow_list_only_ever_moves_warn_to_pass(self, tmp_path, cfg):
        # A plain dict-merge of cfg and _global_msg(...) would clobber an existing
        # tools.message.crossContext with an empty one (both set "tools.message"),
        # so merge recursively at the tools.message level instead.
        merged = _deep_merge(cfg, _global_msg(allow=["typing"]))
        status = check_cross_context_send(_ctx(merged, tmp_path, "2026.9.5")).status
        assert status in (WARN, PASS)

    @pytest.mark.parametrize("cfg", _BASELINE_WARN_CONFIGS)
    def test_adding_a_non_excluding_allow_list_never_changes_the_verdict(self, tmp_path, cfg):
        merged = _deep_merge(cfg, _global_msg(allow=["send"]))
        before = check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5")).status
        after = check_cross_context_send(_ctx(merged, tmp_path, "2026.9.5")).status
        assert before == after == WARN

    @pytest.mark.parametrize("cfg", _BASELINE_WARN_CONFIGS)
    def test_adding_an_undeterminable_allow_list_never_changes_the_verdict(self, tmp_path, cfg):
        merged = _deep_merge(cfg, _global_msg(allow="send"))  # malformed: not a list
        before = check_cross_context_send(_ctx(cfg, tmp_path, "2026.9.5")).status
        after = check_cross_context_send(_ctx(merged, tmp_path, "2026.9.5")).status
        assert before == after == WARN


def _deep_merge(a: dict, b: dict) -> dict:
    """Small recursive dict merge for the metamorphic tests above -- *b*'s leaves win,
    but a shared branch (``tools.message``) is merged rather than one side clobbering
    the other's sibling keys."""
    out = dict(a)
    for key, value in b.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out
