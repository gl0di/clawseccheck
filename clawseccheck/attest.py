"""Attestation layer — a structured agent self-report that enriches the static audit.

The static audit reads only what the config files contain. Many security-relevant
facts are *not* in any config field: the agent's real tool/verb inventory, whether
untrusted input can reach a side-effect without approval, host monitors a file scan
cannot see. The attestation layer lets the user's *agent* self-report those facts in
a small JSON, which the engine consumes via ``--attest``.

Trust model (the whole point — read this before extending):

* A self-report is **weaker** evidence than a config fact. The agent being audited
  may be compromised or prompt-injected, so it could be wrong or could lie. Every
  attestation-derived finding therefore carries confidence ``ATTESTED`` (below
  HIGH/MEDIUM) and is advisory (not scored).
* An attestation may only **resolve an UNKNOWN** or sharpen a heuristic. It never
  overrides a hard config fact.
* A **disagreement** between the self-report and the static config is itself a
  finding (see B44): config that grants a dangerous verb the agent omitted is a
  drift / blind-spot / injection signal.

Everything here is local and read-only: load a JSON file, classify strings. No
network, no subprocess, no execution. Pure stdlib.
"""
from __future__ import annotations

import json

SCHEMA_ID = "clawseccheck-attest/1"

# ---------------------------------------------------------------- verb taxonomy
# Blast-radius classes for a held tool/verb, most-dangerous first. classify_verb()
# returns the first class whose hints substring-match the lowered verb name. The
# match is heuristic (hence ATTESTED confidence), mirroring the _hint() approach
# used elsewhere for tool-name taxonomies.
#
# MAILBOX_CONFIG is the highest blast radius: a mailbox-config mutation (auto-forward
# rule, filter, delegation, signature, auto-responder) installs a *persistent silent
# channel* that keeps exfiltrating after the agent stops acting.
_VERB_CLASSES = (
    # EXEC is the broadest blast radius of all: arbitrary code/command execution
    # SUBSUMES egress (curl), destruction (rm) and config mutation. It is the single
    # most dangerous primitive an agent can hold, so it ranks first. Hints are kept
    # high-precision on purpose — bare "system"/"eval"/"spawn" are omitted because they
    # match benign reads (get_system_info, evaluate_expression) and would FP under §5.
    ("EXEC", (
        "bash", "shell", "exec", "subprocess", "powershell", "run_command",
        "run_code", "code_interpreter", "terminal", "os_command", "shell_command",
    )),
    ("MAILBOX_CONFIG", (
        "auto_forward", "autoforward", "auto-forward", "forward_rule", "forwarding",
        "create_filter", "add_filter", "set_filter", "update_filter",
        "delegate", "delegation", "add_member", "grant_access", "share_mailbox",
        "set_signature", "signature", "vacation", "auto_reply", "autoresponder",
        "out_of_office", "set_rule", "create_rule", "forward_to",
    )),
    # DESTRUCTIVE is reserved for IRREVERSIBLE loss. A bare 'delete'/'remove' is left
    # UNKNOWN on purpose: in most real APIs it is a reversible soft-delete (trash, archive,
    # unsend, delete a draft/label), so flagging every 'delete_*' as high-blast would
    # manufacture false FAILs and break the zero-false-positive law. Only names that
    # *spell out* irreversibility land here.
    ("DESTRUCTIVE", (
        "delete_forever", "delete_permanently", "permanently_delete", "empty_trash",
        "purge", "destroy", "expunge", "hard_delete", "drop_table", "drop_database",
        "wipe", "shred", "truncate",
    )),
    ("EGRESS", (
        "send", "forward", "reply", "post", "publish", "webhook", "http_post",
        "upload", "email_send", "share", "tweet", "broadcast", "dispatch",
        "notify_external", "export",
        # real-world MCP verb forms not caught by the bare stems above
        "schedule_message",          # Slack: scheduled send is still egress
        "page_post", "page_photo", "page_video", "page_profile",  # FB page publish
        "send_message_from_page", "messenger_send",
    )),
)

# Reversible / low-blast verbs — explicitly "safe" so a toolset holding only these
# PASSes B43 ("forward-exfil and delete-evidence are physically impossible").
_REVERSIBLE_HINTS = (
    "search", "list", "get", "read", "fetch", "view", "lookup", "find",
    "draft", "create_draft", "label", "unlabel", "tag", "star", "mark",
    "archive", "move", "snooze",
)

# Action classes used by the approval_gates self-report.
GATE_CLASSES = ("exec", "send", "write")
_BYPASS_ALIAS_MAP = {
    "alarm": "sleeper",
    "clock": "cron",
    "cron": "cron",
    "cron_job": "cron",
    "cronjob": "cron",
    "heartbeat": "heartbeat",
    "periodic": "scheduled",
    "scheduled": "scheduled",
    "scheduler": "scheduled",
    "schedule": "scheduled",
    "sleeper": "sleeper",
}

# How a CALLER handles a delegated callee's output, strongest→weakest. A typed/
# structured return ("schema") is a wall that blocks the instruction/data channel; a
# sanitized-text return ("filtered") is a best-effort sieve; "raw" passes the callee's
# output through verbatim. Used by the delegation-reassembly analysis (B47/RISK-11).
RETURN_TIERS = ("schema", "filtered", "raw", "unknown")


def normalize_verb(name) -> str:
    """Isolate the verb from MCP / provider namespacing so classification matches the
    ACTION, not the server name.

    Real tool names arrive wrapped: ``mcp__claude_ai_Slack__slack_send_message`` or
    dotted ``gmail.send``. Substring-matching the whole string lets a *provider* name
    pollute the verdict — e.g. ``mcp__SendGrid__list_templates`` would read as EGRESS
    on the "send" in "SendGrid" though the verb is a reversible ``list_templates``.
    Stripping to the last namespace segment fixes that:
    ``mcp__SendGrid__list_templates`` -> ``list_templates``; ``gmail.send`` -> ``send``.
    """
    s = str(name).replace("__", ".")
    # Take the last NON-EMPTY segment, so a trailing separator can't strip the verb to
    # nothing and hide it: 'forward__' -> 'forward' (not ''), 'gmail.send' -> 'send'.
    parts = [p for p in s.split(".") if p.strip()]
    return (parts[-1] if parts else s).strip().lower()


def classify_verb(name: str) -> str:
    """Map one tool/verb name to a blast-radius class.

    Returns one of MAILBOX_CONFIG, DESTRUCTIVE, EGRESS, REVERSIBLE, or UNKNOWN.
    Classification runs on the normalized verb (namespace stripped) so a provider
    name can never decide the class.
    """
    n = normalize_verb(name)
    for cls, hints in _VERB_CLASSES:
        if any(h in n for h in hints):
            return cls
    if any(h in n for h in _REVERSIBLE_HINTS):
        return "REVERSIBLE"
    return "UNKNOWN"


HIGH_BLAST_CLASSES = ("EXEC", "MAILBOX_CONFIG", "DESTRUCTIVE", "EGRESS")


def classify_tools(tools) -> dict:
    """Group an iterable of verb names by blast-radius class.

    Returns ``{class: [names...]}`` preserving input order, skipping non-strings.
    """
    held: dict[str, list] = {}
    if not isinstance(tools, list):
        return held
    for t in tools:
        if not isinstance(t, (str, bytes)):
            continue
        held.setdefault(classify_verb(t), []).append(str(t))
    return held


# ---------------------------------------------------------------- load / template
def parse_attestation(data) -> dict:
    """Validate an attestation given as a JSON string or an already-parsed object.

    Returns the dict, or ``{}`` on any problem (bad JSON, non-object root, unknown
    schema version). Never raises — a malformed attestation means "no attestation",
    so checks fall back to UNKNOWN. Shared by the file loader and the stdin path so
    both validate identically.
    """
    if isinstance(data, (str, bytes)):
        try:
            data = json.loads(data)
        except ValueError:
            return {}
    if not isinstance(data, dict):
        return {}
    schema = data.get("schema")
    if schema is not None and schema != SCHEMA_ID:
        # Unknown schema version — refuse to guess its shape.
        return {}
    return data


def load_attestation(path) -> dict:
    """Read + minimally validate an attestation JSON file. Read-only.

    Returns the parsed dict, or ``{}`` on any problem (missing file, bad JSON,
    non-object root, wrong schema). Never raises.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return parse_attestation(fh.read())
    except OSError:
        return {}


def template() -> dict:
    """The skeleton the agent fills in (emitted by ``--ask``).

    ``_questions`` is human-facing guidance for whoever fills the file; the engine
    ignores it. Keep it short and concrete — the agent reads this to self-report.
    """
    return {
        "schema": SCHEMA_ID,
        "_questions": {
            "tools": (
                "List your REAL tool/verb names exactly as you can invoke them "
                "(e.g. 'create_draft', 'send_email', 'create_filter', "
                "'delete_forever'). This is the single most important field: it "
                "lets the audit classify what blast radius is actually in your "
                "hands. Config alone cannot see this."
            ),
            "approval_gates": (
                "For each action class, do you require human approval BEFORE acting? "
                "Use 'required' (a human confirms first), 'auto' (you act without "
                "asking), or 'unknown'."
            ),
            "approval_bypass_actors": (
                "From runtime evidence (logs / execution traces), which actors can fire "
                "tool calls without human confirmation? Include any that can start a tool call "
                "without intervention, e.g. heartbeat, cron, scheduled, or sleeper-trigger."
            ),
            "untrusted_to_action": (
                "When you act on content from an UNTRUSTED source (incoming email, "
                "fetched web page, a tool result), can a side-effect (send / exec / "
                "write / delete) happen WITHOUT human approval? "
                "'gated' (no), 'ungated' (yes), or 'unknown'."
            ),
            "host_monitors": (
                "Defensive monitors you KNOW run on this host but a file scan cannot "
                "see (e.g. a corporate EDR agent, a network IDS on the gateway)."
            ),
            "paths": (
                "Filesystem locations the static scan can't guess. 'bootstrap': absolute "
                "paths to your identity/memory files (SOUL.md, AGENTS.md, TOOLS.md, "
                "MEMORY.md, ...) wherever they actually live. 'openclaw_install': the "
                "directory OpenClaw is installed in. The engine still stat()s these "
                "ITSELF — you only point it at WHERE to look, so the permission check "
                "stays an authoritative file stat, not a trusted self-report."
            ),
            "agents": (
                "If you run MORE THAN ONE agent (a main agent plus sub-agents, or "
                "several agents doing different jobs), list each one and the REAL "
                "tool/verb names IT holds: [{'name': 'researcher', 'tools': "
                "['web_fetch', 'read_file']}, ...]. The engine classifies each "
                "agent's lethal-trifecta legs itself and checks whether any single "
                "agent holds all three (untrusted input + sensitive data + outbound/"
                "exec) — privilege separation means no single agent does. Config "
                "cannot express per-agent tool grants, so only you can supply this. "
                "Omit (leave []) if you run a single agent."
            ),
            "delegation": (
                "If your agents call/spawn each other, list the edges: [{'from': "
                "'researcher', 'to': 'main', 'returns': 'schema'}, ...]. 'from' is the "
                "caller, 'to' the callee, and 'returns' is how the CALLER handles the "
                "callee's output — 'schema' (a typed/structured value = a wall that "
                "blocks injected instructions), 'filtered' (sanitized text = a sieve), "
                "'raw' (the callee's output flows in verbatim), or 'unknown'. The engine "
                "checks whether an untrusted-input agent can reassemble the full trifecta "
                "across these edges. Omit (leave []) if there is no delegation."
            ),
        },
        "tools": [],
        "approval_gates": {k: "unknown" for k in GATE_CLASSES},
        "approval_bypass_actors": [],
        "untrusted_to_action": "unknown",
        "host_monitors": [],
        "paths": {"bootstrap": [], "openclaw_install": ""},
        "agents": [],
        "delegation": [],
        "notes": "",
    }


def attested_paths(att: dict) -> dict:
    """Agent-declared filesystem locations for discovery-assisted permission checks.

    DISCOVERY, not attestation-of-fact: the agent supplies *where* to look; the engine
    still runs the stat() itself, so a finding built from these keeps real-stat strength
    (HIGH confidence), unlike the weak ATTESTED self-report fields above. Tolerant of
    junk — returns ``{"bootstrap": [str, ...], "openclaw_install": str | None}``.
    """
    out: dict = {"bootstrap": [], "openclaw_install": None}
    if not isinstance(att, dict):
        return out
    paths = att.get("paths")
    if not isinstance(paths, dict):
        return out
    boot = paths.get("bootstrap")
    if isinstance(boot, list):
        out["bootstrap"] = [str(p) for p in boot
                            if isinstance(p, (str, bytes)) and str(p).strip()]
    inst = paths.get("openclaw_install")
    if isinstance(inst, (str, bytes)) and str(inst).strip():
        out["openclaw_install"] = str(inst)
    return out


def attested_agents(att: dict) -> list[dict]:
    """Agent-declared roster for per-agent privilege-separation analysis (B45).

    The agent self-reports each agent it runs and the tool/verb names that agent
    holds; the engine classifies the lethal-trifecta legs ITSELF (it never trusts a
    self-graded "this agent is safe"). Like the other attestation fields this is a
    DECLARATION the static config cannot express — OpenClaw config has no per-agent
    tool allowlist, only per-agent *deny* lists — so findings built from it carry
    ATTESTED confidence, not HIGH. Tolerant of junk — returns a list of
    ``{"name": str, "tools": [str, ...]}``; non-dict entries are dropped, a missing
    name falls back to a positional label, non-string tools are skipped.
    """
    out: list[dict] = []
    if not isinstance(att, dict):
        return out
    agents = att.get("agents")
    if not isinstance(agents, list):
        return out
    for i, a in enumerate(agents):
        if not isinstance(a, dict):
            continue
        name = a.get("name")
        if isinstance(name, (str, bytes)) and str(name).strip():
            name = str(name).strip()
        else:
            name = f"agent[{i}]"
        tools = a.get("tools")
        tool_list = (
            [str(t) for t in tools if isinstance(t, (str, bytes)) and str(t).strip()]
            if isinstance(tools, list) else []
        )
        out.append({"name": name, "tools": tool_list})
    return out


def attested_delegation(att: dict) -> list[dict]:
    """Agent-declared delegation edges for cross-agent reassembly analysis (B47/RISK-11).

    Each edge is ``{"from": <caller>, "to": <callee>, "returns": <tier>}``: the caller
    can invoke the callee, and ``returns`` is how the caller handles the callee's output
    — one of RETURN_TIERS. The OpenClaw config does not express a delegation graph, so
    this is a DECLARATION (findings carry ATTESTED confidence), not a config fact.
    Tolerant of junk — non-dict edges are dropped, a blank/missing ``from`` or ``to``
    drops the edge, and an unrecognized ``returns`` normalizes to ``"unknown"``.
    """
    out: list[dict] = []
    if not isinstance(att, dict):
        return out
    edges = att.get("delegation")
    if not isinstance(edges, list):
        return out
    for e in edges:
        if not isinstance(e, dict):
            continue
        frm, to = e.get("from"), e.get("to")
        if not (isinstance(frm, (str, bytes)) and str(frm).strip()):
            continue
        if not (isinstance(to, (str, bytes)) and str(to).strip()):
            continue
        ret = e.get("returns")
        ret = str(ret).strip().lower() if isinstance(ret, (str, bytes)) else ""
        if ret not in RETURN_TIERS:
            ret = "unknown"
        out.append({"from": str(frm).strip(), "to": str(to).strip(), "returns": ret})
    return out


def is_ungated(att: dict) -> bool:
    """True when the self-report says a side-effect can fire without approval.

    We require explicit attestation that untrusted input can drive side-effects:
    ``untrusted_to_action == "ungated"``.

    This keeps the FAIL outcome in B43 to real, evidenced behavior rather than
    merely a config shorthand like ``approval_gates: {"...": "auto"}``.
    """
    if not isinstance(att, dict):
        return False
    return isinstance(att.get("untrusted_to_action"), str) and att.get("untrusted_to_action").strip().lower() == "ungated"


def approval_gates_auto(att: dict) -> list[str]:
    """Return action classes where the attester claims approval is not required."""
    if not isinstance(att, dict):
        return []
    gates = att.get("approval_gates")
    if not isinstance(gates, dict):
        return []
    out: list[str] = []
    for cls in GATE_CLASSES:
        if str(gates.get(cls, "")).strip().lower() == "auto":
            out.append(cls)
    return out


def approval_bypass_actors(att: dict) -> list[str]:
    """Return runtime actors that can auto-fire actions without gating.

    Accepted shapes:
      - {"approval_bypass_actors": ["cron", "sleeper"]}
      - {"approval_bypass_actors": {"cron": true, "sleeper": false}}
      - {"approval_bypass_actors": "heartbeat,scheduled"}
      - {"bypass_actors": "heartbeat,sleeper"} (legacy alias)
    """
    if not isinstance(att, dict):
        return []

    actors: list[str] = []
    raw = att.get("approval_bypass_actors")
    if raw is None:
        raw = att.get("bypass_actors")
    if raw is None:
        return actors

    if isinstance(raw, dict):
        items = [k for k, v in raw.items() if v]
    elif isinstance(raw, (list, tuple, set)):
        items = list(raw)
    elif isinstance(raw, str):
        if "," in raw:
            items = raw.split(",")
        elif raw.strip():
            items = [raw]
        else:
            return []
    else:
        return []

    out: list[str] = []
    for item in items:
        if not isinstance(item, (str, bytes)):
            continue
        key = str(item).strip().lower().replace("-", "_")
        if not key:
            continue
        mapped = _BYPASS_ALIAS_MAP.get(key)
        if mapped:
            out.append(mapped)
    return list(dict.fromkeys(out))

