"""Attestation layer - a structured agent self-report that enriches the static audit.

The static audit reads only what the config files contain. Many security-relevant
facts are *not* in any config field: the agent's real tool/verb inventory, whether
untrusted input can reach a side-effect without approval, host monitors a file scan
cannot see. The attestation layer lets the user's *agent* self-report those facts in
a small JSON, which the engine consumes via ``--attest``.

Trust model (the whole point - read this before extending):

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

import unicodedata
from pathlib import Path

from .configloader import MAX_JSON_NESTING, loads_bounded

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
    # high-precision on purpose - bare "system"/"eval"/"spawn" are omitted because they
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
    # COMMERCE (C-339, ESET H1 2026 "Credit Claw" shape): a verb that spends the
    # user's money - direct access, and the loss is irreversible the way a leaked
    # file is not. Kept high-precision on purpose, same discipline as EXEC above: a
    # bare "pay"/"buy"/"order" would FP on unrelated reads (get_order_status,
    # list_orders, sort_order, reorder) - only compound verb forms that spell out an
    # actual money-moving action land here.
    ("COMMERCE", (
        "create_order", "place_order", "submit_order", "complete_purchase",
        "checkout", "charge_card", "process_payment", "capture_payment",
        "make_payment", "pay_invoice", "purchase_item",
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

# Reversible / low-blast verbs - explicitly "safe" so a toolset holding only these
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

# How a CALLER handles a delegated callee's output, strongest->weakest. A typed/
# structured return ("schema") is a wall that blocks the instruction/data channel; a
# sanitized-text return ("filtered") is a best-effort sieve; "raw" passes the callee's
# output through verbatim. Used by the delegation-reassembly analysis (B47/RISK-11).
RETURN_TIERS = ("schema", "filtered", "raw", "unknown")


def normalize_verb(name) -> str:
    """Isolate the verb from MCP / provider namespacing so classification matches the
    ACTION, not the server name.

    Real tool names arrive wrapped: ``mcp__claude_ai_Slack__slack_send_message`` or
    dotted ``gmail.send``. Substring-matching the whole string lets a *provider* name
    pollute the verdict - e.g. ``mcp__SendGrid__list_templates`` would read as EGRESS
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

    Returns one of EXEC, MAILBOX_CONFIG, DESTRUCTIVE, COMMERCE, EGRESS, REVERSIBLE,
    or UNKNOWN. Classification runs on the normalized verb (namespace stripped) so a
    provider name can never decide the class.
    """
    n = normalize_verb(name)
    for cls, hints in _VERB_CLASSES:
        if any(h in n for h in hints):
            return cls
    if any(h in n for h in _REVERSIBLE_HINTS):
        return "REVERSIBLE"
    return "UNKNOWN"


HIGH_BLAST_CLASSES = ("EXEC", "MAILBOX_CONFIG", "DESTRUCTIVE", "COMMERCE", "EGRESS")


# What "blank" means for a name in an attestation (C-714): nothing is left once whitespace and
# the control / format / separator categories are removed. A name made only of U+200B, U+FEFF,
# a NUL or a control byte is as empty as "", but is not "falsy" and survives .strip().
_BLANK_CATEGORIES = frozenset({"Cc", "Cf", "Zs", "Zl", "Zp"})


def is_blank_text(text) -> bool:
    """True when *text* has no visible character (see ``_BLANK_CATEGORIES``)."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    return all(ch.isspace() or unicodedata.category(ch) in _BLANK_CATEGORIES
               for ch in str(text))


def _is_name(value) -> bool:
    """A usable attestation name: a string (or bytes) with a visible character."""
    return isinstance(value, (str, bytes)) and not is_blank_text(value)


def classify_tools(tools) -> dict:
    """Group an iterable of verb names by blast-radius class.

    Returns ``{class: [names...]}`` preserving input order, skipping non-strings and
    blank names (a blank name is not a verb the agent holds; counted as an UNKNOWN verb it
    would let a list of blanks read as a classified toolset, C-714).
    """
    held: dict[str, list] = {}
    if not isinstance(tools, list):
        return held
    for t in tools:
        if not _is_name(t):
            continue
        held.setdefault(classify_verb(t), []).append(str(t))
    return held


# ---------------------------------------------------------------- load / template
def parse_attestation(data) -> dict:
    """Validate an attestation given as JSON text (str or bytes) or an already-parsed object.

    Returns the dict, or ``{}`` on any problem (undecodable bytes, bad JSON, JSON nested
    deeper than ``MAX_JSON_NESTING`` levels, non-object root, unknown schema version).
    Never raises - a malformed attestation means "no attestation", so checks fall back to
    UNKNOWN. Shared by the file loader and the stdin path so both validate
    identically. Bytes are decoded by ``json.loads`` itself (UTF-8, UTF-8 with BOM,
    UTF-16, UTF-32), which is why the loaders hand it the raw bytes.

    How deep a document may nest is OUR limit (``configloader.MAX_JSON_NESTING``, checked
    before the parser runs), not whatever the running interpreter's parser happens to
    follow: that figure differs between CPython versions and, on 3.14, with the process
    stack size, so the answer would otherwise differ between machines (C-648).
    """
    if isinstance(data, (str, bytes)):
        try:
            data = loads_bounded(data, max_nesting=MAX_JSON_NESTING)
        except (ValueError, RecursionError):
            # ValueError covers bad JSON, undecodable bytes (UnicodeDecodeError) and the
            # nesting limit (JSONNestingError). RecursionError (a RuntimeError, not a
            # ValueError) stays as a second net for the parser's own guard (C-626) - same
            # "no attestation".
            return {}
    if not isinstance(data, dict):
        return {}
    schema = data.get("schema")
    if schema is not None and schema != SCHEMA_ID:
        # Unknown schema version - refuse to guess its shape.
        return {}
    return data


def load_attestation(path) -> dict:
    """Read + minimally validate an attestation JSON file. Read-only.

    Returns the parsed dict, or ``{}`` on any problem (missing file, undecodable or
    binary content, bad JSON, non-object root, wrong schema). Never raises.

    C-626: the file is read as BYTES and ``parse_attestation`` decodes it
    (``json.loads(bytes)`` sniffs UTF-8 / UTF-8-with-BOM / UTF-16 / UTF-32), so a
    non-UTF-8 file is a malformed attestation ("no attestation"), not a crash.
    """
    try:
        return parse_attestation(Path(path).read_bytes())
    except (OSError, ValueError):
        return {}


def template() -> dict:
    """The skeleton the agent fills in (emitted by ``--ask``).

    ``_questions`` is human-facing guidance for whoever fills the file; the engine
    ignores it. Keep it short and concrete - the agent reads this to self-report.
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
            "proven_tools": (
                "Tool verbs you have LOG or TRACE evidence you ACTUALLY invoked (not "
                "just hold) \u2014 leave empty if you have no execution log to cite."
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
                "ITSELF \u2014 you only point it at WHERE to look, so the permission check "
                "stays an authoritative file stat, not a trusted self-report."
            ),
            "agents": (
                "If you run MORE THAN ONE agent (a main agent plus sub-agents, or "
                "several agents doing different jobs), list each one and the REAL "
                "tool/verb names IT holds: [{'name': 'researcher', 'tools': "
                "['web_fetch', 'read_file']}, ...]. The engine classifies each "
                "agent's lethal-trifecta legs itself and checks whether any single "
                "agent holds all three (untrusted input + sensitive data + outbound/"
                "exec) \u2014 privilege separation means no single agent does. Config "
                "cannot express per-agent tool grants, so only you can supply this. "
                "Omit (leave []) if you run a single agent."
            ),
            "delegation": (
                "If your agents call/spawn each other, list the edges: [{'from': "
                "'researcher', 'to': 'main', 'returns': 'schema'}, ...]. 'from' is the "
                "caller, 'to' the callee, and 'returns' is how the CALLER handles the "
                "callee's output \u2014 'schema' (a typed/structured value = a wall that "
                "blocks injected instructions), 'filtered' (sanitized text = a sieve), "
                "'raw' (the callee's output flows in verbatim), or 'unknown'. The engine "
                "checks whether an untrusted-input agent can reassemble the full trifecta "
                "across these edges. Omit (leave []) if there is no delegation."
            ),
        },
        "tools": [],
        "proven_tools": [],
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
    junk - returns ``{"bootstrap": [str, ...], "openclaw_install": str | None}``.
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


def attested_proven(att: dict) -> set:
    """Verb names the agent has LOG/TRACE evidence it ACTUALLY invoked (B84).

    Distinct from ``tools`` (what the agent self-reports it HOLDS): this is a
    stronger claim - runtime evidence of actual invocation, not just capability.
    Still ATTESTED confidence (a self-report, not the engine's own observation), but
    within the self-report layer it is the tightest signal available: declared
    (config grant) > effective (self-reported inventory) > proven (self-reported
    execution evidence). Tolerant of junk - returns a set of normalized verb names
    (namespace-stripped, lowercased) so it compares directly against the other two
    sets; non-string entries are skipped.
    """
    if not isinstance(att, dict):
        return set()
    proven = att.get("proven_tools")
    if not isinstance(proven, list):
        return set()
    return {normalize_verb(t) for t in proven if _is_name(t)}


def attested_agents(att: dict) -> list[dict]:
    """Agent-declared roster for per-agent privilege-separation analysis (B45).

    The agent self-reports each agent it runs and the tool/verb names that agent
    holds; the engine classifies the lethal-trifecta legs ITSELF (it never trusts a
    self-graded "this agent is safe"). Like the other attestation fields this is a
    DECLARATION the static config cannot express - OpenClaw config has no per-agent
    tool allowlist, only per-agent *deny* lists - so findings built from it carry
    ATTESTED confidence, not HIGH. Returns a list of ``{"name": str, "tools": [str, ...]}``.

    C-714: the roster is used only when EVERY entry validates (``_agent_entry_problem``);
    one unusable entry and this returns ``[]``, the same as no roster. Entries used to be
    repaired (a blank name became a positional label, a non-list ``tools`` became ``[]``),
    and the repaired entry was an agent that holds nothing - so "no agent holds all three
    legs" (B45) and "no agent shows MCP bleed" (B75/B76) PASSed on a roster that declared
    nothing. Dropping only the bad entries is no better: the entry that fails to validate
    can be the one that declared the risk, and the checks would then PASS on the rest.
    """
    out: list[dict] = []
    if not isinstance(att, dict):
        return out
    agents = att.get("agents")
    if not isinstance(agents, list):
        return out
    if any(_agent_entry_problem(a) is not None for a in agents):
        return out
    for a in agents:
        out.append({"name": str(a["name"]).strip(), "tools": [str(t) for t in a["tools"]]})
    return out


def _agent_entry_problem(a) -> str | None:
    """Why one ``agents`` entry is unusable, as a fixed phrase (never its content), or None.

    Usable = an object with a non-blank ``name`` and a ``tools`` list whose members are all
    non-blank strings (``"tools": []`` is valid: an agent that declares no tools). A
    ``tools`` list with a non-string or blank member is rejected whole, not trimmed: the
    entry's inventory is then not what the agent declared, and the trimmed remainder would
    read as a complete (and possibly empty) toolset.
    """
    if not isinstance(a, dict):
        return "not an object"
    if not _is_name(a.get("name")):
        return "without a usable name"
    tools = a.get("tools")
    if not (isinstance(tools, list) and all(_is_name(t) for t in tools)):
        return "without a tools list of non-blank strings"
    return None


# Attestation lists whose members are names. A list with ANY member that is not a non-blank
# string is removed whole (it then reads exactly as if the key were absent): the member
# that fails to validate can be the one that mattered, so the rest is not a complete list.
_NAME_LISTS = ("tools", "proven_tools", "host_monitors")


def vet_attestation(att) -> tuple:
    """Remove unusable parts of an attestation; return ``(attestation, notes)``.

    C-714. Each part is vetted on its own, a bad part never touches another, and a part
    is all or nothing - it is used as written or it is removed and reads exactly as if
    its key had not been written:

    * ``agents``: removed when it is not a list, or when any entry fails
      ``_agent_entry_problem``.
    * ``tools`` / ``proven_tools`` / ``host_monitors``: removed when any member is not a
      non-blank string.

    Nothing is trimmed or repaired. A part with one bad member is not a smaller, valid
    part: the member that failed can be the one that declared the risk (an agent entry
    holding all three trifecta legs plus one stray value), and a check that then PASSes on
    the remainder reports a clean result nobody declared.

    ``notes`` holds one fixed-phrase string per removed part (a count, a key name and a
    reason - never an entry's content, because the attestation is user-supplied but may be
    attacker-influenced and the caller prints these). An attestation with nothing to
    remove comes back as the SAME object with no notes.
    """
    if not isinstance(att, dict) or not att:
        return att, []
    out = dict(att)
    notes: list[str] = []
    agents = att.get("agents")
    if isinstance(agents, list):
        reasons: dict[str, int] = {}
        for a in agents:
            why = _agent_entry_problem(a)
            if why is not None:
                reasons[why] = reasons.get(why, 0) + 1
        if reasons:
            bad = sum(reasons.values())
            detail = "; ".join(f"{n} {r}" for r, n in sorted(reasons.items()))
            out.pop("agents")
            notes.append(f"the agent roster ({bad} of {len(agents)} "
                         f"{'entry is' if bad == 1 else 'entries are'} unusable: {detail})")
    elif agents is not None:
        out.pop("agents")
        notes.append(f"the agent roster ('agents' is a {type(agents).__name__}, "
                     "not a list)")
    for key in _NAME_LISTS:
        raw = att.get(key)
        if not isinstance(raw, list) or not raw:
            continue
        bad = sum(1 for m in raw if not _is_name(m))
        if not bad:
            continue
        out.pop(key)
        notes.append(f"the '{key}' list ({bad} of {len(raw)} "
                     f"{'member is' if bad == 1 else 'members are'} not a non-blank string)")
    return (out, notes) if notes else (att, notes)


def attested_delegation(att: dict) -> list[dict]:
    """Agent-declared delegation edges for cross-agent reassembly analysis (B47/RISK-11).

    Each edge is ``{"from": <caller>, "to": <callee>, "returns": <tier>}``: the caller
    can invoke the callee, and ``returns`` is how the caller handles the callee's output
    - one of RETURN_TIERS. The OpenClaw config does not express a delegation graph, so
    this is a DECLARATION (findings carry ATTESTED confidence), not a config fact.
    Tolerant of junk - non-dict edges are dropped, a blank/missing ``from`` or ``to``
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

