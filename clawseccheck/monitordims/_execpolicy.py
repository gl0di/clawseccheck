"""The `exec_policy` dimension — the approval gate on unattended shell execution.

B-664. `tools.exec` decides whether the agent may run a shell command, whether the command
must be on an allow list, and whether a human is asked when it is not. Before this, none of
that was a watched dimension: `_CONFIG_DIMENSIONS` held `mcp`, `mcp_detail`, `channels`,
`gateway_bind` and `plugins`, and `tools.exec` reached the monitor only if some check's
STATUS happened to move — which on `fixtures/home_safe` it does not. Flipping
`tools.exec.mode` from `"ask"` to `"auto"` produced `rc=0` and "No new threats among what
was compared."

## The resolution is OpenClaw's, ported — and the port was checked by EXECUTION

`resolveExecPolicyForMode` (`dist/exec-approvals-BIKWP8_V.js`) maps a mode to the triple
the exec tool actually enforces:

    mode        security     ask       autoReview
    deny        deny         off       false
    allowlist   allowlist    off       false
    ask         allowlist    on-miss   false
    auto        allowlist    on-miss   TRUE
    full        full         off       false

With no `mode`, `resolveExecModeFromPolicy` derives one from `security`/`ask`.
`tests/test_b664_exec_policy_dimension.py` runs the REAL functions out of the installed
dist over a 96-combination matrix and requires this port to agree on every one, because
reading them was not enough twice over:

  * read alone, the `DEFAULT_SECURITY = "full"` / `DEFAULT_ASK = "off"` constants sitting
    beside the resolver suggest an absent `tools.exec` resolves to `full`;
  * executed alone, `resolveExecModePolicy({})` returns `"ask"` — the constants are NOT
    applied inside it;
  * the CALL SITE settles it (`dist/bash-tools-DHyGpWCr.js`):
    `configuredSecurity = explicitSecurity ?? (host === "sandbox" ? "deny" : "full")`,
    `ask: defaults?.ask ?? "off"` — so an absent `tools.exec` really does resolve to
    `full`/`off`, i.e. the most permissive state.

Either half alone gives the wrong default, and a wrong default would have inverted the
alert.

## "Reading less can only make it quieter" was FALSE, and is why this file is shaped as it is

The first version of this module said exactly that about the layers it skipped. An
independent C-135 pass disproved it with four reproducible false alarms, and the reason is
worth stating because it generalises: **an unread layer does not only remove signal, it
changes what the DEFAULT is** — and the default here is `full`, the top of the rank. Every
skipped layer that lowers the real policy turns a benign edit into a `-> full` HIGH.

  * **`agents.defaults.sandbox.mode`** decides `effectiveHost`, and
    `defaultSecurity = effectiveHost === "sandbox" ? "deny" : "full"`
    (`exec-defaults-BLH0Yltk.js`). Under `sandbox.mode: "all"`, deleting a now-redundant
    `tools.exec.security: "allowlist"` TIGHTENS the policy to `deny` — and the old code
    called it `allowlist -> full`, an inverted verdict at HIGH.
  * **`agents.list[].tools.exec`** replaces the global for that agent
    (`applyExecPolicyLayer`, and `resolveAgentConfig` passes `tools: entry.tools` with no
    merge from `agents.defaults.tools`). Changing an inert global therefore changed nothing,
    and the old code reported `deny -> full`.

So both are now MODELLED rather than skipped, per scope. What remains genuinely out of
static reach is named at `_undetermined_reason`, and each such case returns `undetermined`
— never a policy, and never the permissive default.

## What is still out of scope, and now says so rather than guessing

  * `~/.openclaw/exec-approvals.json` — mutable RUNTIME state OpenClaw writes (B326 excludes
    it for the same reason). It can only make the real policy TIGHTER (`minSecurity` /
    `maxAsk`), so it is a false-negative direction only.
  * the session layer (`applySessionLegacyExecPolicyLayer`) — per-session, not on disk.
  * `sandbox.mode: "non-main"`, where `shouldSandboxSession` is genuinely session-dependent
    and the default security cannot be decided statically.

## Why not reuse `_b326_exec_policy_blocking_reason`

It looks like the right primitive and is not: `_B326_BLOCKING_MODES` includes `"auto"`,
because B326 asks "does anything block the elevated-`full` override" — a different question
from "is a human asked". Reusing it would have made the B-664 case invisible for a second
time, from the other direction.
"""

from __future__ import annotations

from ._shared import NOTE_RECORD_DAMAGED, NOTE_UNDETERMINED  # noqa: F401

#: `resolveExecPolicyForMode`, ported. Verified against the real function by execution.
_MODE_POLICY = {
    "deny": ("deny", "off", False),
    "allowlist": ("allowlist", "off", False),
    "ask": ("allowlist", "on-miss", False),
    "auto": ("allowlist", "on-miss", True),
    "full": ("full", "off", False),
}

#: How much the agent may run, least to most. Derived from the table above, not invented:
#: `deny` runs nothing, `allowlist` runs only listed commands, `full` runs anything.
_SECURITY_RANK = {"deny": 0, "allowlist": 1, "full": 2}


def _resolve_mode_from_policy(security, ask) -> str:
    """`resolveExecModeFromPolicy`, ported verbatim including the clause order."""
    if security == "deny":
        return "deny"
    if security == "allowlist" and ask == "off":
        return "allowlist"
    if security == "full" and ask != "always":
        return "full"
    return "ask"


#: `shouldSandboxSession` (`runtime-status-BRnZ3ffr.js`) is unconditional for these two and
#: genuinely session-dependent for `"non-main"`. Absent means `"off"` (`config-Dy4vED5-.js`).
_SANDBOX_ALWAYS = "all"
_SANDBOX_NEVER = "off"


def _undetermined_reason(exec_cfg, sandbox_mode) -> "str | None":
    """Why this scope's policy cannot be decided from static config, or None.

    Every branch here exists because the alternative is guessing, and the guess would land
    on `full` — the top of the rank — which is how an unread layer becomes a false alarm.
    """
    from ..checks import _b323_contains_env_var_reference  # noqa: PLC0415

    for field in ("mode", "security", "ask", "host"):
        value = exec_cfg.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            # A number, list, dict or bool. `resolveExecPolicyForMode` THROWS on a
            # non-string mode and the zod schema is a strict enum, so OpenClaw would refuse
            # to start — but the old code let non-strings fall past its `isinstance` guards
            # to the permissive default and alerted `deny -> full`. The TYPE of the garbage
            # decided whether the arm stood down or fired HIGH.
            return f"tools.exec.{field} is not a string"
        if _b323_contains_env_var_reference(value):
            # Could expand to anything. Same hazard B-397 fixed for B326, same helper.
            return "an unresolved ${...} reference"

    mode = exec_cfg.get("mode")
    if isinstance(mode, str) and mode and mode not in _MODE_POLICY:
        return f"tools.exec.mode={mode!r} is not a mode OpenClaw accepts"

    # The sandbox only decides the DEFAULT security, so it is irrelevant once a mode is set:
    # `applyExecPolicyLayer` replaces the whole triple from the mode table. Checking it
    # unconditionally is what made every sandbox user with an explicit mode permanently
    # silent — a false negative introduced by an over-eager honesty guard.
    if isinstance(mode, str) and mode:
        return None
    host = exec_cfg.get("host")
    if isinstance(host, str) and host and host != "auto":
        # An EXPLICIT target never enters the `sandboxAvailable` ternary in
        # `resolveExecTarget`, so it is fully determined — the opposite of what the first
        # version of this guard assumed. Note: compared RAW, because the dist does not trim.
        return None
    if sandbox_mode is None or sandbox_mode == _SANDBOX_NEVER:
        return None
    if sandbox_mode == _SANDBOX_ALWAYS:
        return None
    return (f"agents sandbox mode {sandbox_mode!r} decides per session whether exec runs "
            "in a sandbox, and that decides the default")


def _resolve_scope(exec_cfg, sandbox_mode) -> dict:
    """One scope's effective policy — the global one, or one agent's.

    `effectiveHost` comes from `resolveExecTarget`: an explicit target wins, and an absent
    or `"auto"` target falls to `sandboxAvailable ? "sandbox" : "gateway"`. Then
    `defaultSecurity = effectiveHost === "sandbox" ? "deny" : "full"`.
    """
    why = _undetermined_reason(exec_cfg, sandbox_mode)
    if why:
        return {"undetermined": why}

    mode = exec_cfg.get("mode")
    if isinstance(mode, str) and mode:
        # `if (layer.mode)` in `applyExecPolicyLayer` is a TRUTHINESS test, so an empty
        # string is treated as absent by the dist — hence the `and mode` rather than a
        # bare presence check.
        security, ask, auto_review = _MODE_POLICY[mode]
        return {"mode": mode, "security": security, "ask": ask,
                "auto_review": bool(auto_review)}

    host = exec_cfg.get("host")
    if isinstance(host, str) and host and host != "auto":
        effective_host = host
    else:
        effective_host = "sandbox" if sandbox_mode == _SANDBOX_ALWAYS else "gateway"
    default_security = "deny" if effective_host == "sandbox" else "full"

    security = exec_cfg.get("security")
    ask = exec_cfg.get("ask")
    security = security if isinstance(security, str) and security else default_security
    ask = ask if isinstance(ask, str) and ask else "off"
    return {"mode": _resolve_mode_from_policy(security, ask),
            "security": security, "ask": ask, "auto_review": False}


def _exec_policy_sig(ctx) -> dict:
    """The effective exec policy PER SCOPE — the global one, and each agent that overrides it.

    Records the RESOLVED triple rather than the raw fields, because the raw fields do not
    compare meaningfully: `{"mode": "ask"}` and `{"security": "allowlist", "ask": "on-miss"}`
    are the same policy written two ways, and diffing the raw form would alert on a rewrite
    that changed nothing.

    Per scope rather than globally, because `agents.list[].tools.exec` REPLACES the global
    for that agent. Comparing the global alone reported an edit to an already-overridden
    global as `deny -> full` while nothing about what any agent could run had changed.
    """
    from ..collector import agent_roster, dig  # noqa: PLC0415

    cfg = ctx.config
    if not isinstance(cfg, dict):
        return {}

    global_exec = dig(cfg, "tools.exec")
    global_exec = global_exec if isinstance(global_exec, dict) else {}
    global_sandbox = dig(cfg, "agents.defaults.sandbox.mode")
    scopes = {}

    # B-699: the roster comes from `agent_roster`, so a 2026.8.1 `agents.entries` record is
    # read as well as the legacy `agents.list`. The scope KEY is unchanged in both shapes —
    # it is built from the agent id, which `agent_roster` injects from the record key — so a
    # user migrating their config does not get a spurious "scope moved" alert out of it.
    _listed = agent_roster(cfg)
    # The global scope is only recorded when something actually RUNS under it. With a
    # non-empty roster whose every entry carries its own `tools.exec`, the global is
    # inert — and recording it anyway meant an edit to it produced a `deny -> full` HIGH
    # about a policy no agent uses. When the roster is empty, or has any entry without
    # an override, the global is what that agent runs, so it stays.
    _all_overridden = bool(_listed) and all(
        isinstance(a.entry.get("tools"), dict)
        and isinstance(a.entry["tools"].get("exec"), dict)
        for a in _listed)
    if not _all_overridden:
        scopes["global"] = _resolve_scope(global_exec, global_sandbox)

    for _agent in _listed:
        entry, index = _agent.entry, _agent.index
        agent_exec = (entry.get("tools") or {}).get("exec") \
            if isinstance(entry.get("tools"), dict) else None
        if not isinstance(agent_exec, dict):
            # No override: this agent runs the global policy, already recorded above.
            continue
        agent_id = entry.get("id")
        name = str(agent_id) if isinstance(agent_id, (str, int)) else f"#{index}"
        agent_sandbox = global_sandbox
        own_sandbox = entry.get("sandbox")
        if isinstance(own_sandbox, dict) and own_sandbox.get("mode") is not None:
            agent_sandbox = own_sandbox.get("mode")
        # `applyExecPolicyLayer(global, agent)`: a layer's `mode` replaces the whole
        # triple, otherwise its security/ask override field by field.
        merged = dict(global_exec)
        merged.update({k: v for k, v in agent_exec.items() if v is not None})
        if agent_exec.get("mode"):
            merged.pop("security", None)
            merged.pop("ask", None)
        scopes[f"agent:{name}"] = _resolve_scope(merged, agent_sandbox)

    return {"scopes": scopes}


def _human_reviews_a_miss(rec: dict) -> bool:
    """True when a command outside the allow list reaches a PERSON before it runs."""
    return rec.get("ask") != "off" and not rec.get("auto_review")


def _every_request_is_prompted(rec: dict) -> bool:
    """`ask: "always"` prompts a human on EVERY exec request, not only on an allow-list miss.

    Which means the set of commands the agent can run unattended is empty, whatever
    `security` says — and `resolveExecModeFromPolicy` has a clause (`security === "full" &&
    ask !== "always"`) that exists for exactly this. Dropping an allow list while keeping
    universal prompting is an operator trading one control for a stricter one; the first
    version of this arm called it "any command, with no allow list at all" at HIGH.
    """
    return rec.get("ask") == "always" and not rec.get("auto_review")


def _misses_can_still_run(rec: dict) -> bool:
    """True when a command outside the allow list can run at all.

    Under `allowlist`/`deny` a miss is refused, so there is no approval to lose — which is
    why tightening from `ask` to `allowlist` must NOT alert even though it removes the
    prompt. That direction was a false alarm in the first draft of this arm.
    """
    return rec.get("security") == "full" or bool(rec.get("auto_review"))


def _describe(rec: dict) -> str:
    """How to name a policy on screen.

    The mode label alone is not enough: `{"security":"allowlist","ask":"always"}` and
    `{"security":"full","ask":"always"}` are both mode `ask`, so an alert about the second
    rendered as "(tools.exec: ask -> ask)" — a sentence that refutes itself while claiming a
    widening.
    """
    mode = rec.get("mode")
    if rec.get("security") != _MODE_POLICY.get(mode, (None,))[0] or mode is None:
        return f"{mode}/{rec.get('security')}/{rec.get('ask')}"
    return str(mode)


def _diff_scope(scope: str, prev_rec: dict, curr_rec: dict, alerts, note) -> None:
    """One scope's policy, compared. `scope` is "global" or "agent:<id>"."""
    where = "" if scope == "global" else f" for agent '{scope.split(':', 1)[1]}'"

    if prev_rec.get("undetermined") or curr_rec.get("undetermined"):
        why = curr_rec.get("undetermined") or prev_rec.get("undetermined")
        note(NOTE_UNDETERMINED,
             f"Your agent's shell-approval policy{where} could not be determined this run "
             f"({why}), so this run cannot tell you whether it was relaxed.")
        return

    p_sec = _SECURITY_RANK.get(prev_rec.get("security"))
    c_sec = _SECURITY_RANK.get(curr_rec.get("security"))
    if p_sec is None or c_sec is None:
        note(NOTE_RECORD_DAMAGED,
             f"The shell-approval policy{where} was not compared — one of the two records "
             "names a confinement level this build does not recognise.")
        return

    # `_every_request_is_prompted`: with `ask: "always"` nothing runs unattended whatever
    # the confinement says, so a widening there is not a widening of what the agent can do
    # on its own. Checked on the CURRENT side, because that is the state the sentence would
    # describe.
    widened = c_sec > p_sec and not _every_request_is_prompted(curr_rec)
    if widened:
        alerts.append((
            "HIGH" if curr_rec.get("security") == "full" else "MEDIUM",
            f"Your agent may now run a wider set of shell commands{where} than at the last "
            f"check (tools.exec: {_describe(prev_rec)} -> {_describe(curr_rec)})."
            + (" 'full' means any command, with no allow list at all."
               if curr_rec.get("security") == "full" else "")))

    # `and not widened`: on `ask` -> `full` BOTH facts are true, and this repo treats
    # reporting one edit twice as a defect in its own right (the bootstrap/memory overlap,
    # the new-file overlap, the args_pkg/args0 collapse). The widening sentence already
    # says 'full' means any command with no allow list, which subsumes this one — so this
    # alert is for the case the first cannot see: the confinement did NOT move and the
    # human left the loop anyway, which is exactly `ask` -> `auto`.
    if (not widened and _human_reviews_a_miss(prev_rec)
            and not _human_reviews_a_miss(curr_rec)
            and _misses_can_still_run(curr_rec)):
        alerts.append((
            "HIGH",
            f"A shell command your agent could not run without asking you can now be "
            f"approved without you{where} (tools.exec: {_describe(prev_rec)} -> "
            f"{_describe(curr_rec)}). Confirm you made this change."))


def _diff_exec_policy(pair, alerts, compare_config, note) -> None:
    """The approval gate on unattended shell execution, compared scope by scope.

    Takes its pair from `pair_or_note`, not `_both_dims`: a damaged or missing record here
    must be DISCLOSED rather than silently skipped, the same way the gateway address is.

    Only scopes present on BOTH sides are compared. A scope that appeared is a new agent,
    which is a different fact from an existing agent's policy being relaxed — and a scope
    that vanished took its agent with it.
    """
    if not compare_config or pair is None:
        return
    prev_rec, curr_rec = pair
    prev_scopes = prev_rec.get("scopes")
    curr_scopes = curr_rec.get("scopes")
    if not isinstance(prev_scopes, dict) or not isinstance(curr_scopes, dict):
        # A baseline written before this dimension recorded scopes, or a damaged record.
        # `pair_or_note` cannot see this — its guard is on the dimension, not its shape.
        return
    for scope in sorted(set(prev_scopes) & set(curr_scopes)):
        p, c = prev_scopes[scope], curr_scopes[scope]
        if isinstance(p, dict) and isinstance(c, dict):
            _diff_scope(scope, p, c, alerts, note)
