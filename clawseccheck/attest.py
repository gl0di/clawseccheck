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
        },
        "tools": [],
        "approval_gates": {k: "unknown" for k in GATE_CLASSES},
        "untrusted_to_action": "unknown",
        "host_monitors": [],
        "notes": "",
    }


def is_ungated(att: dict) -> bool:
    """True when the self-report says a side-effect can fire without approval.

    Either ``untrusted_to_action == 'ungated'`` or any approval gate is 'auto'.
    """
    if not isinstance(att, dict):
        return False
    if att.get("untrusted_to_action") == "ungated":
        return True
    gates = att.get("approval_gates")
    if isinstance(gates, dict):
        return any(gates.get(k) == "auto" for k in GATE_CLASSES)
    return False
