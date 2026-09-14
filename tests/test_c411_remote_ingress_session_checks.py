"""B361/B362/B363/B364 (CLAWSECCHECK-C-411) — remote-ingress / multi-user session
hardening, re-grounded against openclaw@2026.9.3.

Two items were re-scoped by measurement before implementation, and two more were
dropped entirely:

- **tools.sessions.visibility was dropped from this task's scope** — it is already
  covered by the pre-existing B39 (``checks/_agents.py``). While re-grounding it,
  ``session-visibility-DihshKLi.mjs``'s own ``resolveSessionToolsVisibility`` showed
  its runtime default is `"all"` (the PERMISSIVE end — "defaulting invalid or missing
  values to all"), not `"tree"` as the C-411 stub (and, transitively, B39's own
  design) assumed. That is a real gap in the EXISTING B39 check, filed as a separate
  bug rather than folded into this task.
- **requireMention / chatmode / allowBots were dropped from this task's scope.**
  Grounding them found genuinely heterogeneous per-provider nesting — top-level for
  some providers (mattermost, slack, googlechat, msteams), ``.groups.*`` for others
  (telegram, whatsapp, irc, imessage, signal — and telegram nests a THIRD level,
  ``.groups.*.topics.*``), ``.guilds.*``/``.guilds.*.channels.*`` for discord, plus a
  generic ``.accounts.*`` override layer on top of all of them. A half-modeled
  version of this (e.g. only the top-level path) would silently miss most providers —
  worse than not shipping it. Needs its own dedicated grounding+design pass.
- **tools.agentToAgent** and **session.scope** were confirmed unchanged from the
  8.2 grounding and implemented as filed.
- **tools.message.allowCrossContextSend** (the path the stub cited) does not exist;
  the real path is ``tools.message.crossContext.allowAcrossProviders``, with a
  per-agent override (``agents.entries.<id>.tools.message.crossContext.
  allowAcrossProviders``) that WINS over the global value key-by-key — reading only
  the global key would miss an agent that widens past a safe default on its own.
- **session.resetTriggers** ships as a disclosure-only WARN (never a "does this
  phrase look guessable" judgment call — Golden Rule #4), same reasoning B341
  already uses for a comparable grant.

No FAIL branch exists in this family — none of the four needed the formal C-135
gate (CLAUDE.md §4, scoped to new FAIL-*capable* checks).
"""
from __future__ import annotations

from clawseccheck.catalog import BY_ID, MEDIUM, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    CHECKS,
    check_agent_to_agent_pivot,
    check_cross_context_send,
    check_session_reset_triggers,
    check_session_scope_global,
)
from clawseccheck.collector import Context

_OPEN_CHANNEL = {"channels": {"telegram": {"dmPolicy": "open"}}}
_TWO_AGENTS = {"agents": {"entries": {"a": {}, "b": {}}}}


def _ctx(cfg, tmp_path, *, found=True):
    return Context(home=tmp_path, config=cfg, config_found=found)


def _merged(*dicts):
    out = {}
    for d in dicts:
        out.update(d)
    return out


# =============================================================================== B361
class TestAgentToAgentPivot:
    def test_absent_block_with_one_agent_is_pass(self, tmp_path):
        f = check_agent_to_agent_pivot(_ctx(dict(_OPEN_CHANNEL), tmp_path))
        assert f.status == PASS

    def test_absent_block_two_agents_open_channel_warns(self, tmp_path):
        """The permissive default: an absent tools.agentToAgent is the SAME posture
        as an explicit {enabled: true} with no allow restriction."""
        cfg = _merged(_OPEN_CHANNEL, _TWO_AGENTS)
        f = check_agent_to_agent_pivot(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "privilege pivot" in f.detail

    def test_enabled_false_is_pass(self, tmp_path):
        cfg = _merged(_OPEN_CHANNEL, _TWO_AGENTS, {"tools": {"agentToAgent": {"enabled": False}}})
        f = check_agent_to_agent_pivot(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_restrictive_allow_list_is_pass(self, tmp_path):
        cfg = _merged(
            _OPEN_CHANNEL, _TWO_AGENTS, {"tools": {"agentToAgent": {"allow": ["a", "b"]}}}
        )
        f = check_agent_to_agent_pivot(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_allow_list_containing_wildcard_still_warns(self, tmp_path):
        cfg = _merged(
            _OPEN_CHANNEL, _TWO_AGENTS, {"tools": {"agentToAgent": {"allow": ["a", "*"]}}}
        )
        f = check_agent_to_agent_pivot(_ctx(cfg, tmp_path))
        assert f.status == WARN

    def test_empty_allow_list_still_warns(self, tmp_path):
        cfg = _merged(_OPEN_CHANNEL, _TWO_AGENTS, {"tools": {"agentToAgent": {"allow": []}}})
        f = check_agent_to_agent_pivot(_ctx(cfg, tmp_path))
        assert f.status == WARN

    def test_two_agents_no_reachable_channel_is_pass(self, tmp_path):
        f = check_agent_to_agent_pivot(_ctx(dict(_TWO_AGENTS), tmp_path))
        assert f.status == PASS

    def test_single_agent_is_pass_even_when_unrestricted(self, tmp_path):
        cfg = _merged(_OPEN_CHANNEL, {"tools": {"agentToAgent": {"enabled": True}}})
        f = check_agent_to_agent_pivot(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_malformed_node_is_unknown(self, tmp_path):
        f = check_agent_to_agent_pivot(_ctx({"tools": {"agentToAgent": "nope"}}, tmp_path))
        assert f.status == UNKNOWN

    def test_unread_config_is_unknown(self, tmp_path):
        f = check_agent_to_agent_pivot(_ctx({}, tmp_path, found=False))
        assert f.status == UNKNOWN

    def test_registered_and_catalog_consistent(self, tmp_path):
        assert check_agent_to_agent_pivot in CHECKS
        meta = BY_ID["B361"]
        assert meta.severity == MEDIUM and meta.surface == "agents"
        emitted = check_agent_to_agent_pivot(_ctx({"channels": {}}, tmp_path))
        assert emitted.id == "B361" and emitted.title == meta.title


# =============================================================================== B362
class TestSessionScopeGlobal:
    def test_absent_is_pass(self, tmp_path):
        f = check_session_scope_global(_ctx(dict(_OPEN_CHANNEL), tmp_path))
        assert f.status == PASS

    def test_per_sender_is_pass(self, tmp_path):
        cfg = _merged(_OPEN_CHANNEL, {"session": {"scope": "per-sender"}})
        f = check_session_scope_global(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_global_with_open_channel_warns(self, tmp_path):
        cfg = _merged(_OPEN_CHANNEL, {"session": {"scope": "global"}})
        f = check_session_scope_global(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "bleed" in f.detail or "persists into every other sender" in f.detail

    def test_global_with_no_reachable_channel_is_pass(self, tmp_path):
        f = check_session_scope_global(_ctx({"session": {"scope": "global"}}, tmp_path))
        assert f.status == PASS

    def test_unrecognized_value_is_unknown(self, tmp_path):
        f = check_session_scope_global(_ctx({"session": {"scope": "nope"}}, tmp_path))
        assert f.status == UNKNOWN

    def test_unread_config_is_unknown(self, tmp_path):
        f = check_session_scope_global(_ctx({}, tmp_path, found=False))
        assert f.status == UNKNOWN

    def test_registered_and_catalog_consistent(self, tmp_path):
        assert check_session_scope_global in CHECKS
        meta = BY_ID["B362"]
        assert meta.severity == MEDIUM and meta.surface == "sessions"
        emitted = check_session_scope_global(_ctx({"channels": {}}, tmp_path))
        assert emitted.id == "B362" and emitted.title == meta.title


# =============================================================================== B363
class TestCrossContextSend:
    def test_absent_is_pass(self, tmp_path):
        f = check_cross_context_send(_ctx({"tools": {}}, tmp_path))
        assert f.status == PASS

    def test_global_false_is_pass(self, tmp_path):
        cfg = {"tools": {"message": {"crossContext": {"allowAcrossProviders": False}}}}
        f = check_cross_context_send(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_global_true_warns(self, tmp_path):
        cfg = {"tools": {"message": {"crossContext": {"allowAcrossProviders": True}}}}
        f = check_cross_context_send(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "tools.message.crossContext.allowAcrossProviders" in f.detail

    def test_per_agent_true_with_global_false_still_warns(self, tmp_path):
        """The precedence lesson: per-agent WINS over global, so reading only the
        global key would miss this agent entirely."""
        cfg = {
            "tools": {"message": {"crossContext": {"allowAcrossProviders": False}}},
            "agents": {
                "entries": {
                    "safe": {},
                    "widened": {
                        "tools": {"message": {"crossContext": {"allowAcrossProviders": True}}}
                    },
                }
            },
        }
        f = check_cross_context_send(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "widened" in f.detail
        assert "safe" not in f.detail

    def test_malformed_global_node_is_unknown(self, tmp_path):
        f = check_cross_context_send(
            _ctx({"tools": {"message": {"crossContext": "nope"}}}, tmp_path)
        )
        assert f.status == UNKNOWN

    def test_malformed_per_agent_node_is_unknown(self, tmp_path):
        cfg = {
            "agents": {"entries": {"a": {"tools": {"message": {"crossContext": "nope"}}}}},
        }
        f = check_cross_context_send(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN

    def test_unread_config_is_unknown(self, tmp_path):
        f = check_cross_context_send(_ctx({}, tmp_path, found=False))
        assert f.status == UNKNOWN

    def test_registered_and_catalog_consistent(self, tmp_path):
        assert check_cross_context_send in CHECKS
        meta = BY_ID["B363"]
        assert meta.severity == MEDIUM and meta.surface == "tools"
        emitted = check_cross_context_send(_ctx({"tools": {}}, tmp_path))
        assert emitted.id == "B363" and emitted.title == meta.title


# =============================================================================== B364
class TestSessionResetTriggers:
    def test_absent_is_pass(self, tmp_path):
        f = check_session_reset_triggers(_ctx({"session": {}}, tmp_path))
        assert f.status == PASS

    def test_empty_list_is_pass(self, tmp_path):
        f = check_session_reset_triggers(_ctx({"session": {"resetTriggers": []}}, tmp_path))
        assert f.status == PASS

    def test_non_empty_list_warns_and_discloses_phrases(self, tmp_path):
        cfg = {"session": {"resetTriggers": ["reset", "start over"]}}
        f = check_session_reset_triggers(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "reset" in f.detail or "reset" in (f.evidence or [])

    def test_not_a_list_is_unknown(self, tmp_path):
        f = check_session_reset_triggers(_ctx({"session": {"resetTriggers": "reset"}}, tmp_path))
        assert f.status == UNKNOWN

    def test_non_string_entries_are_unknown(self, tmp_path):
        f = check_session_reset_triggers(_ctx({"session": {"resetTriggers": [1, 2]}}, tmp_path))
        assert f.status == UNKNOWN

    def test_unread_config_is_unknown(self, tmp_path):
        f = check_session_reset_triggers(_ctx({}, tmp_path, found=False))
        assert f.status == UNKNOWN

    def test_never_scored(self, tmp_path):
        """Disclosure-only, matching B341's precedent for a comparable grant."""
        cfg = {"session": {"resetTriggers": ["x"]}}
        f = check_session_reset_triggers(_ctx(cfg, tmp_path))
        assert f.scored is False

    def test_registered_and_catalog_consistent(self, tmp_path):
        assert check_session_reset_triggers in CHECKS
        meta = BY_ID["B364"]
        assert meta.severity == MEDIUM and meta.surface == "sessions" and meta.scored is False
        emitted = check_session_reset_triggers(_ctx({"session": {}}, tmp_path))
        assert emitted.id == "B364" and emitted.title == meta.title
