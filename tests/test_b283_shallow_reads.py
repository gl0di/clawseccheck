"""B-283 — three shallow-read corrections that each produced a lying PASS.

(a) SHALLOW-1  ``_UNTRUSTED_INPUT_POLICIES`` matched the dead literal ``"paired"`` instead
    of the real (and DEFAULT) ``"pairing"``, and never normalized the ``groupPolicy``
    alias ``"allowall"`` (which the dist schema transforms to ``"open"``).
(b) SHALLOW-2  B68 read one sibling of a pair — ``tools.exec.applyPatch.workspaceOnly`` —
    and never ``tools.fs.workspaceOnly``, which governs the whole fs tool family.
(c) SHALLOW-4  B26 and its ``risk.py`` twin resolved ``contextVisibility`` at channel and
    default scope only, missing the per-account override the dist resolves FIRST.

Every assertion below runs the real check/helper functions end-to-end. Offline; nothing is
written outside ``tmp_path``.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck import risk
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _external_input_channels,
    _open_channels,
    _untrusted_input_channels,
    check_exec_applypatch_workspace,
    check_trifecta,
    check_untrusted_context,
)
from clawseccheck.checks._shared import (
    _UNTRUSTED_INPUT_POLICIES,
    _channels_with_context_visibility_all,
    _norm_group_policy,
)
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context.__new__(Context)
    c.config = cfg
    c.config_path = "/nonexistent/openclaw.json"
    c.config_error = None
    c.config_parse_error = False
    c.bootstrap_files = {}
    c.skills = []
    c.attestation = None
    return c


# ═══════════════════════════════════════════════════════════════════════════════
# (a) SHALLOW-1 — pairing / allowall
# ═══════════════════════════════════════════════════════════════════════════════

class TestUntrustedInputPolicySet:
    def test_dead_paired_literal_is_gone(self):
        # "paired" is not an OpenClaw policy value at all — DmPolicySchema is
        # _enum(["open","pairing","allowlist"]). Keeping it in the set meant the only
        # member that could ever match was the one that never occurs.
        assert "paired" not in _UNTRUSTED_INPUT_POLICIES

    def test_real_policy_values_are_covered(self):
        assert _UNTRUSTED_INPUT_POLICIES == frozenset({"open", "allowlist", "pairing"})

    @pytest.mark.parametrize("policy", ["open", "allowlist", "pairing"])
    def test_untrusted_dm_policies_are_ingress(self, policy):
        cfg = {"channels": {"telegram": {"dmPolicy": policy}}}
        assert _external_input_channels(cfg) == ["telegram"]
        assert _untrusted_input_channels(cfg) == ["telegram"]
        assert risk._has_untrusted_ingress([], cfg) is True

    @pytest.mark.parametrize("policy", ["disabled", "owner", "paired", None])
    def test_non_untrusted_dm_policies_are_not_ingress(self, policy):
        # Includes the now-dead "paired": an unrecognised literal must NOT be ingress.
        # `None` is the absent-dmPolicy case, deliberately still out of scope (see below).
        node = {} if policy is None else {"dmPolicy": policy}
        cfg = {"channels": {"telegram": node}}
        assert _external_input_channels(cfg) == []
        assert _untrusted_input_channels(cfg) == []
        assert risk._has_untrusted_ingress([], cfg) is False

    def test_pairing_resolves_identically_to_allowlist(self):
        # GROUNDING CORRECTION (C-135 review): a paired sender resolves through
        # dm-policy-shared-BaGKWQzz.js:92 to allow("dm_policy_allowlisted") -- the exact
        # same decision/reasonCode a dmPolicy=="allowlist" match produces. OpenClaw itself
        # classifies pairing identically to allowlist, so anything allowlist counts as
        # ingress, pairing must too.
        allowlist = {"channels": {"a": {"dmPolicy": "allowlist"}}}
        pairing = {"channels": {"a": {"dmPolicy": "pairing"}}}
        assert _external_input_channels(pairing) == _external_input_channels(allowlist)


class TestGroupPolicyAllowallAlias:
    """GROUNDING CORRECTION (C-135 review, B-283): ``allowall`` is Feishu-only.

    Checked against the installed dist: Feishu's own ``GroupPolicySchema`` is the ONLY
    channel schema that accepts the ``"allowall"`` literal (``union([_enum(["open",
    "allowlist","disabled"]), literal("allowall").transform(() => "open")])``,
    channel-PR3XHV0V.js:89-93). LINE defines a separate, bare
    ``_enum(["open","allowlist","disabled"])`` with no ``"allowall"`` member
    (reply-payload-transform-Ce9ZfUxA.js:19-23), and the "core" ``GroupPolicySchema`` shared
    by Telegram/Discord/Slack/Signal/Matrix/Nextcloud-Talk/Zalo/Zalouser is likewise a bare
    ``_enum(["open","disabled","allowlist"])`` (zod-schema.core-DviqqtPj.js:424-428). Both
    REJECT ``"allowall"`` outright, so a config with e.g. ``groupPolicy: "allowall"`` on one
    of those channels fails OpenClaw's own schema validation and cannot be a config a
    running instance actually loaded. A prior version of this normalizer treated every
    channel the same way, which meant this package could FAIL a config that cannot exist —
    a fabricated schema fact, not just a wrong comment. These tests pin the Feishu-only
    scoping so it cannot silently regress back to channel-agnostic.
    """

    def test_norm_group_policy_maps_allowall_to_open_on_feishu(self):
        assert _norm_group_policy("feishu", "allowall") == "open"

    @pytest.mark.parametrize("channel", ["telegram", "discord", "line", "slack", "tg"])
    def test_norm_group_policy_leaves_allowall_untouched_off_feishu(self, channel):
        # The GR#4 fix under test: "allowall" is schema-invalid on every non-Feishu
        # channel, so it must pass through unchanged (same as any other unmodeled string).
        assert _norm_group_policy(channel, "allowall") == "allowall"

    @pytest.mark.parametrize("value", ["open", "allowlist", "disabled", None, "", 7])
    def test_norm_group_policy_passes_everything_else_through(self, value):
        assert _norm_group_policy("feishu", value) == value
        assert _norm_group_policy("telegram", value) == value

    def test_allowall_group_is_ingress_and_open_on_feishu(self):
        cfg = {"channels": {"feishu": {"groupPolicy": "allowall"}}}
        assert _external_input_channels(cfg) == ["feishu"]
        assert _untrusted_input_channels(cfg) == ["feishu"]
        assert _open_channels(cfg) == ["feishu"]
        assert risk._has_untrusted_ingress([], cfg) is True
        assert risk._open_channel_labels(cfg) == ["feishu (open group)"]

    def test_allowall_group_off_feishu_is_not_ingress_or_open(self):
        # The regression this correction exists to prevent: without Feishu-scoping this
        # produced a CRITICAL scored B2 FAIL on a value zod would refuse to load.
        cfg = {"channels": {"telegram": {"groupPolicy": "allowall"}}}
        assert _external_input_channels(cfg) == []
        assert _untrusted_input_channels(cfg) == []
        assert _open_channels(cfg) == []
        assert risk._has_untrusted_ingress([], cfg) is False
        assert risk._open_channel_labels(cfg) == []

    def test_allowall_is_indistinguishable_from_open_on_feishu(self):
        # The dist transform is literal("allowall") -> "open" on Feishu, so every helper
        # must produce byte-identical output for the two spellings on that channel.
        allowall = {"channels": {"feishu": {"groupPolicy": "allowall"}}}
        openp = {"channels": {"feishu": {"groupPolicy": "open"}}}
        for fn in (_external_input_channels, _untrusted_input_channels, _open_channels):
            assert fn(allowall) == fn(openp), fn.__name__
        assert risk._open_channel_labels(allowall) == risk._open_channel_labels(openp)

    def test_allowall_is_group_scope_only(self):
        # allowall is NOT in DmPolicySchema on any channel, and normalizeFeishuDmPolicy maps
        # an unrecognised dmPolicy to "pairing", never to "open" — so a dmPolicy of
        # "allowall" must not be promoted to an OPEN channel (B2's question), even on
        # Feishu.
        cfg = {"channels": {"feishu": {"dmPolicy": "allowall"}}}
        assert _open_channels(cfg) == []

    def test_allowall_respects_enabled_false(self):
        cfg = {"channels": {"feishu": {"enabled": False, "groupPolicy": "allowall"}}}
        assert _external_input_channels(cfg) == []
        assert _untrusted_input_channels(cfg) == []

    def test_allowall_detected_on_account_node(self):
        cfg = {"channels": {"feishu": {"accounts": {"a1": {"groupPolicy": "allowall"}}}}}
        assert _external_input_channels(cfg) == ["feishu"]
        assert _open_channels(cfg) == ["feishu"]


class TestTrifectaPayoff:
    """The security win, proven end-to-end through the real A1 check.

    Before B-283, a bot on the DEFAULT dmPolicy ("pairing") holding sensitive + outbound
    tools scored a clean 2/3 PASS: the untrusted-input leg never activated, because the
    only untrusted literal in the set ("paired") never occurs. An attacker self-enrols
    through the pairing handshake and the full lethal trifecta is live while A1 says PASS.
    """

    _TOOLS = {"allow": ["read_file", "db_query", "http_post", "send_message"]}

    def test_pairing_completes_the_trifecta(self):
        cfg = {"channels": {"telegram": {"dmPolicy": "pairing"}}, "tools": self._TOOLS}
        f = check_trifecta(_ctx(cfg))
        assert f.status == FAIL
        assert "3/3" in f.detail and "untrusted input" in f.detail

    def test_allowall_group_completes_the_trifecta(self):
        # "allowall" only resolves as ingress on Feishu (see TestGroupPolicyAllowallAlias).
        cfg = {"channels": {"feishu": {"groupPolicy": "allowall"}}, "tools": self._TOOLS}
        f = check_trifecta(_ctx(cfg))
        assert f.status == FAIL
        assert "3/3" in f.detail

    def test_disabled_channel_stays_two_of_three(self):
        # The negative control: without ingress the same tool set is only 2/3 -> PASS.
        cfg = {"channels": {"telegram": {"dmPolicy": "disabled"}}, "tools": self._TOOLS}
        f = check_trifecta(_ctx(cfg))
        assert f.status == PASS
        assert "2/3" in f.detail


class TestAbsentDmPolicyStillOutOfScope:
    """Honest-labelling guard: B-283 NARROWS the ingress gap, it does not close it.

    The product default for dmPolicy is "pairing", but an ABSENT dmPolicy is still read as
    "no untrusted ingress". Treating absent as pairing would flip nearly every
    enabled-channel config and could cascade into A1 (CRITICAL, scored) grade changes; it
    needs its own C-135 pass. This test pins the CURRENT behavior so the residual is
    visible and a future change to it is deliberate, not accidental.
    """

    def test_absent_dm_policy_is_not_yet_treated_as_pairing(self):
        cfg = {"channels": {"telegram": {"enabled": True}}}
        assert _external_input_channels(cfg) == []
        assert risk._has_untrusted_ingress([], cfg) is False


class TestPolicyFixtures:
    def test_clean_disabled_channel_is_not_ingress(self):
        cfg = json.loads(
            (FIXTURES / "clean_b283_dm_pairing_disabled" / "openclaw.json").read_text()
        )
        assert _external_input_channels(cfg) == []
        assert risk._has_untrusted_ingress([], cfg) is False

    def test_bad_pairing_fixture_is_ingress(self):
        cfg = json.loads(
            (FIXTURES / "bad_b283_dm_pairing" / "openclaw.json").read_text()
        )
        assert _external_input_channels(cfg) == ["telegram"]
        assert risk._has_untrusted_ingress([], cfg) is True

    def test_bad_allowall_fixture_is_ingress_and_open(self):
        # Grounded on "feishu" (item 2, C-135 review): Feishu is the only channel schema
        # in the dist that accepts groupPolicy:"allowall" — see
        # TestGroupPolicyAllowallAlias for the full grounding. The fixture previously used
        # "telegram", which pinned a schema fact the dist refutes into a shipped fixture.
        cfg = json.loads(
            (FIXTURES / "bad_b283_group_allowall" / "openclaw.json").read_text()
        )
        assert _external_input_channels(cfg) == ["feishu"]
        assert _open_channels(cfg) == ["feishu"]


# ═══════════════════════════════════════════════════════════════════════════════
# (b) SHALLOW-2 — tools.fs.workspaceOnly
# ═══════════════════════════════════════════════════════════════════════════════

class TestFsWorkspaceOnly:
    def test_product_default_absent_field_does_not_blanket_warn(self):
        # THE mass-false-positive guard. tools.fs.workspaceOnly defaults to FALSE, so a
        # naive `!== true -> WARN` would fire on nearly every real config. With the
        # sandbox containing all agents, the composite predicate is not satisfied.
        f = check_exec_applypatch_workspace(
            _ctx(
                {
                    "tools": {"profile": "coding"},
                    "agents": {"defaults": {"sandbox": {"mode": "all"}}},
                }
            )
        )
        assert f.status == PASS

    def test_no_fs_tools_granted_passes(self):
        # profile "minimal" grants no fs tool -> nothing to confine.
        f = check_exec_applypatch_workspace(_ctx({"tools": {"profile": "minimal"}}))
        assert f.status == PASS

    def test_explicit_allowlist_without_fs_tools_passes(self):
        f = check_exec_applypatch_workspace(_ctx({"tools": {"allow": ["exec", "web"]}}))
        assert f.status == PASS

    def test_workspace_only_true_passes(self):
        f = check_exec_applypatch_workspace(
            _ctx({"tools": {"allow": ["read", "write"], "fs": {"workspaceOnly": True}}})
        )
        assert f.status == PASS

    def test_fs_granted_unconfined_unsandboxed_warns(self):
        f = check_exec_applypatch_workspace(
            _ctx(
                {
                    "tools": {"allow": ["read", "write", "edit"]},
                    "agents": {"defaults": {"sandbox": {"mode": "non-main"}}},
                }
            )
        )
        assert f.status == WARN
        assert "tools.fs.workspaceOnly" in " ".join(f.evidence)

    def test_explicit_false_warns(self):
        f = check_exec_applypatch_workspace(
            _ctx({"tools": {"allow": ["read"], "fs": {"workspaceOnly": False}}})
        )
        assert f.status == WARN
        assert any("tools.fs.workspaceOnly=false" in e for e in f.evidence)

    def test_explicit_false_warns_even_when_sandboxed(self):
        # OpenClaw itself enumerates `tools.fs.workspaceOnly === false` as a dangerous
        # config flag regardless of sandboxing — an active opt-out is always reported.
        f = check_exec_applypatch_workspace(
            _ctx(
                {
                    "tools": {"allow": ["read"], "fs": {"workspaceOnly": False}},
                    "agents": {"defaults": {"sandbox": {"mode": "all"}}},
                }
            )
        )
        assert f.status == WARN

    def test_per_agent_optout_under_hardened_global_warns(self):
        # BOTH scopes must be read: per-agent overrides global
        # (context.tools?.fs?.workspaceOnly ?? cfg.tools?.fs?.workspaceOnly).
        f = check_exec_applypatch_workspace(
            _ctx(
                {
                    "tools": {"allow": ["read"], "fs": {"workspaceOnly": True}},
                    "agents": {
                        "list": [
                            {"name": "helper", "tools": {"fs": {"workspaceOnly": False}}}
                        ]
                    },
                }
            )
        )
        assert f.status == WARN
        assert any("agents.list[helper]" in e for e in f.evidence)

    def test_per_agent_true_under_absent_global_is_not_a_blanket_pass(self):
        # One agent confining itself does not confine agents WITHOUT an override — they
        # keep the product default (false).
        f = check_exec_applypatch_workspace(
            _ctx(
                {
                    "tools": {"allow": ["read", "write"]},
                    "agents": {
                        "list": [
                            {"name": "safe", "tools": {"fs": {"workspaceOnly": True}}}
                        ]
                    },
                }
            )
        )
        assert f.status == WARN

    def test_group_fs_deny_passes(self):
        f = check_exec_applypatch_workspace(
            _ctx({"tools": {"allow": ["read", "write"], "deny": ["group:fs"]}})
        )
        assert f.status == PASS

    def test_unenumerable_grants_are_unknown(self):
        # No allowlist and no profile -> grants come from runtime defaults static config
        # cannot resolve. UNKNOWN, never a fabricated PASS (GR#4).
        f = check_exec_applypatch_workspace(_ctx({"gateway": {"bind": "127.0.0.1:8080"}}))
        assert f.status == UNKNOWN

    def test_applypatch_sibling_still_warns(self):
        # The pre-B-283 behavior must not regress.
        f = check_exec_applypatch_workspace(
            _ctx({"tools": {"exec": {"applyPatch": {"workspaceOnly": False}}}})
        )
        assert f.status == WARN
        assert any("applyPatch" in e for e in f.evidence)

    def test_never_fails(self):
        # B68 is scored=False and advisory — it must never emit FAIL on any shape.
        for cfg in (
            {},
            {"tools": {"allow": ["read"], "fs": {"workspaceOnly": False}}},
            {"tools": {"profile": "coding"}},
        ):
            assert check_exec_applypatch_workspace(_ctx(cfg)).status != FAIL

    @pytest.mark.parametrize(
        "fixture,expected",
        [
            ("clean_b283_fs_workspace_confined", PASS),
            ("clean_b283_fs_product_default_sandboxed", PASS),
            ("bad_b283_fs_unconfined_absent", WARN),
            ("bad_b283_fs_explicit_false", WARN),
            ("bad_b283_fs_per_agent_optout", WARN),
        ],
    )
    def test_fs_fixtures(self, fixture, expected):
        assert check_exec_applypatch_workspace(collect(FIXTURES / fixture)).status == expected


# ═══════════════════════════════════════════════════════════════════════════════
# (c) SHALLOW-4 — contextVisibility per-account override
# ═══════════════════════════════════════════════════════════════════════════════

_CTXVIS_CASES = [
    # (label, cfg, expected_channels)
    (
        "account 'all' overrides an allowlist channel",
        {
            "channels": {
                "slack": {
                    "contextVisibility": "allowlist",
                    "accounts": {"ops": {"contextVisibility": "all"}},
                }
            }
        },
        ["slack"],
    ),
    (
        "account 'all' overrides an allowlist default",
        {
            "channels": {
                "defaults": {"contextVisibility": "allowlist"},
                "slack": {"accounts": {"ops": {"contextVisibility": "all"}}},
            }
        },
        ["slack"],
    ),
    (
        "genuinely safe: channel and account both allowlist",
        {
            "channels": {
                "slack": {
                    "contextVisibility": "allowlist",
                    "accounts": {"ops": {"contextVisibility": "allowlist"}},
                }
            }
        },
        [],
    ),
    (
        "control: channel-level 'all' (must not regress)",
        {"channels": {"slack": {"contextVisibility": "all"}}},
        ["slack"],
    ),
    (
        "one account opts into allowlist on an 'all' channel — others still resolve all",
        {
            "channels": {
                "slack": {
                    "contextVisibility": "all",
                    "accounts": {"ops": {"contextVisibility": "allowlist"}},
                }
            }
        },
        ["slack"],
    ),
    (
        "account inherits an allowlist channel when it sets nothing",
        {
            "channels": {
                "slack": {
                    "contextVisibility": "allowlist",
                    "accounts": {"ops": {"name": "ops"}},
                }
            }
        },
        [],
    ),
    (
        "no explicit visibility anywhere -> OpenClaw default 'all'",
        {"channels": {"slack": {}}},
        ["slack"],
    ),
    (
        "'defaults' is not itself a channel",
        {"channels": {"defaults": {"contextVisibility": "all"}, "slack": {"contextVisibility": "allowlist"}}},
        [],
    ),
]


class TestContextVisibilityAccountDescent:
    @pytest.mark.parametrize(
        "label,cfg,expected", _CTXVIS_CASES, ids=[c[0] for c in _CTXVIS_CASES]
    )
    def test_shared_resolver(self, label, cfg, expected):
        assert _channels_with_context_visibility_all(cfg) == expected

    @pytest.mark.parametrize(
        "label,cfg,expected", _CTXVIS_CASES, ids=[c[0] for c in _CTXVIS_CASES]
    )
    def test_risk_mirror_agrees_with_shared_resolver(self, label, cfg, expected):
        # TRAP the task called out: fixing only ONE site leaves RISK-15/RISK-18 blind.
        # risk.py keeps a deliberate mirror (it imports only via the checks aggregator),
        # so this pins the two implementations equal on every case.
        assert risk._channels_with_visibility_all(cfg) == expected

    @pytest.mark.parametrize(
        "label,cfg,expected", _CTXVIS_CASES, ids=[c[0] for c in _CTXVIS_CASES]
    )
    def test_b26_status_follows(self, label, cfg, expected):
        f = check_untrusted_context(_ctx(cfg))
        assert f.status == (WARN if expected else PASS)
        if expected:
            assert f.evidence == expected

    def test_b26_unknown_with_no_channels(self):
        assert check_untrusted_context(_ctx({"channels": {}})).status == UNKNOWN

    def test_b26_never_fails_on_account_override(self):
        # B26 is a hardening advisory — the widened read must not make it FAIL-capable.
        cfg = {
            "channels": {
                "slack": {
                    "contextVisibility": "allowlist",
                    "accounts": {"ops": {"contextVisibility": "all"}},
                }
            }
        }
        assert check_untrusted_context(_ctx(cfg)).status == WARN

    def test_malformed_accounts_are_ignored(self):
        for accounts in ([], "nope", {"ops": "nope"}, {"ops": None}):
            cfg = {"channels": {"slack": {"contextVisibility": "allowlist", "accounts": accounts}}}
            assert _channels_with_context_visibility_all(cfg) == []
            assert risk._channels_with_visibility_all(cfg) == []

    @pytest.mark.parametrize(
        "fixture,expected",
        [
            ("clean_b283_ctxvis_account_allowlist", PASS),
            ("bad_b283_ctxvis_account_all", WARN),
            ("bad_b283_ctxvis_defaults_account_all", WARN),
        ],
    )
    def test_ctxvis_fixtures(self, fixture, expected):
        assert check_untrusted_context(collect(FIXTURES / fixture)).status == expected


class TestRiskChainsSeeAccountOverride:
    """RISK-15 keys off B26's status; RISK-18 calls the helper directly. Both were blind."""

    _ATTACK_CHANNELS = {
        "slack": {
            "contextVisibility": "allowlist",
            "accounts": {"ops": {"contextVisibility": "all"}},
        }
    }

    def test_risk18_legs_now_positive(self):
        cfg = {
            "channels": self._ATTACK_CHANNELS,
            "cron": {"jobs": [{"name": "n", "schedule": "* * * * *"}]},
            "agents": {"defaults": {"heartbeat": {"every": "5m"}}},
        }
        assert risk._channels_with_visibility_all(cfg) == ["slack"]
        path = risk._rule_persistent_foothold(_ctx(cfg), [], cfg)
        assert path is not None and path.id == "RISK-18"

    def test_risk18_silent_when_visibility_is_restricted(self):
        cfg = {
            "channels": {
                "slack": {
                    "contextVisibility": "allowlist",
                    "accounts": {"ops": {"contextVisibility": "allowlist"}},
                }
            },
            "cron": {"jobs": [{"name": "n", "schedule": "* * * * *"}]},
            "agents": {"defaults": {"heartbeat": {"every": "5m"}}},
        }
        assert risk._rule_persistent_foothold(_ctx(cfg), [], cfg) is None
