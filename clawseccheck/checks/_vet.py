"""Topic module: vet checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import base64
import binascii
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlparse
from ..catalog import (
    CRITICAL,
    FAIL,
    HIGH,
    LOW,
    MEDIUM,
    PASS,
    UNKNOWN,
    WARN,
    Finding,
)
from ..collector import (
    _MAX_BYTES_PER_SKILL,
    Context,
    _read_skill_text,
    dig,
    read_skill_python,
    read_skill_shell,
    read_skill_js,
)
from ..skillast import (
    analyze_javascript,
    analyze_python,
    analyze_python_package,
    analyze_shell,
)
from ..skillast import simulate_effects as _simulate_effects
from ..textnorm import (
    normalize_for_scan,
)

from ._shared import (
    _custom,
    _is_own_source,
    _is_public_ip,
    _mcp_servers,
    _skill_frontmatter_block,
)
from ._content import (
    _B62_EXPECTED,
    _B62_HIGH_SURPRISE,
    _B64URL_BLOB_RE,
    _B64_BLOB_RE,
    _CRED_RE,
    _DECODED_BAD_RE,
    _decoded_is_payload,
    _EXFIL_RE,
    _IOC_ONION_RE,
    _KNOWN_NAMES,
    _b62_classify_category,
    _b62_extract_declaration,
    _b63_decoded_actionable,
    _dep_names_in_skill,
    _fence_ranges,
    _frontmatter_name,
    _in_fence,
    _is_code_example,
    _skill_declared_tools,
    _squat_hits,
    _try_b64_decode,
    _under_defensive_heading,
    _under_install_heading,
    _unpinned_deps_in_skill,
    _whole_text_is_defensive,
    check_agent_snooping,
    check_capability_intent_mismatch,
    check_clickfix_setup_section,
    check_conditional_sleeper_trigger,
    check_config_trust_widening,
    check_cross_file_boundary_payload,
    check_cross_file_payload,
    check_cross_skill_combined_effect,
    check_dependency_confusion,
    check_dormant_capability,
    check_dynamic_dispatch_obfuscation,
    check_event_hook_interceptor,
    check_forged_provenance,
    check_frontmatter_hygiene,
    check_image_attr_injection,
    check_import_from_writable,
    check_install_directive_supply_chain,
    check_instruction_hierarchy_override,
    check_lifecycle_hooks_extended,
    check_manifest_absent,
    check_markdown_image_exfil,
    check_per_source_trust_contracts,
    check_persona_jailbreak,
    check_prompt_self_replication,
    check_pth_persistence,
    check_silent_instruction,
    check_symlink_escape,
    check_trigger_homoglyph,
    check_unicode_obfuscation,
    check_unsafe_deserialization,
)
from ._lifecycle import (
    check_install_policy,
)


# ---------- B13: installed-skill / plugin content vetting (ClawHavoc vector) ----------
# CRITICAL: unambiguous malware signals (paste-staged payloads, credential/wallet theft,
# and the ClawHavoc password-dialog social-engineering trick).
_SKILL_CRIT = [
    (
        "paste / exfiltration host",
        re.compile(
            r"\b(glot\.io|pastebin\.com|hastebin|transfer\.sh|0x0\.st|webhook\.site|requestbin|"
            r"discord\.com/api/webhooks|api\.telegram\.org/bot|rentry\.co|rentry\.org|"
            r"beeceptor\.com|interactsh\.com|oast\.(?:pro|fun|me|live|site|online)|"
            r"canarytokens\.(?:com|net|org)|file\.io|localtunnel\.me|trycloudflare\.com|"
            r"[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app)|ngrok\.io|ngrok-free\.app|"
            r"[a-z0-9-]+\.pipedream\.net|pipedream\.net)\b",
            re.I,
        ),
    ),
    (
        "known stealer malware name",
        re.compile(r"\b(AMOS|Atomic\s*Stealer|RedLine\s*Stealer|Lumma\s*Stealer)\b", re.I),
    ),
    (
        "password-prompt social engineering",
        re.compile(
            r"(enter|type)\s+your\s+(mac|login|system|sudo)\s*password|osascript[^\n]{0,80}password|display\s+dialog[^\n]{0,80}password",
            re.I,
        ),
    ),
    # C-039: rm -rf / (or //) as a bare literal is unambiguously destructive — CRITICAL on its own.
    # Use (?=\s|$|--) so the match fires when / is followed by whitespace, end-of-string, or
    # an option flag (e.g. --no-preserve-root); avoids false \b boundary issues after /.
    (
        "dangerous wipe: rm -rf / (destructive wipe of entire filesystem)",
        re.compile(
            r"\brm\s+-[rR][fF]\s+/+(?=\s|$|--|\Z)|\brm\s+-[fF][rR]\s+/+(?=\s|$|--|\Z)", re.I
        ),
    ),
]


# F-023: local-sink credential exposure — same-line credential source + local data-bearing sink.
# WARN-only/advisory; never FAIL. Static slice only (runtime debug text is E-014 scope).
_SINK_LOG_RE = re.compile(
    r"\blogging\.(?:debug|info|warning|warn|error|critical|exception|log)\s*\("
    r"|\b\w{0,40}log(?:ger)?\.(?:debug|info|warning|warn|error|critical|exception)\s*\("
    r"|\bprint\s*\("
    r"|\bconsole\.(?:log|debug|info|warn|error)\s*\("
    r"|\bsys\.std(?:out|err)\.write\s*\("
    r"|\braise\s+\w{1,40}(?:Error|Exception)\s*\(",
    re.I,
)


_SINK_TEMPFILE_RE = re.compile(
    r"\btempfile\.(?:NamedTemporaryFile|mkstemp|mkdtemp|TemporaryFile|gettempdir)\b"
    r"|\bopen\s*\(\s*[^)\n]{0,60}(?:/tmp/|/var/tmp/|/private/tmp/)"
    r"|\bPath\s*\(\s*['\"][^'\"\n]{0,60}(?:/tmp/|/var/tmp/)"
    r"|>>?\s*/(?:tmp|var/tmp)/",
    re.I,
)


_SINK_REPORT_RE = re.compile(
    r"\bopen\s*\(\s*[^)\n]{0,60}(?:report|summary|output|results?)[\w./-]{0,20}\.(?:md|txt|json|html|csv|log)['\"]"
    r"|\.write(?:_text)?\s*\([^)\n]{0,60}(?:summary|report)\b",
    re.I,
)


_LOCAL_SINK_CHANNELS = [
    ("credential/secret reaches a local log/debug sink (logging/print/console)", _SINK_LOG_RE),
    ("credential/secret reaches a temp-file sink (tempfile or /tmp path)", _SINK_TEMPFILE_RE),
    ("credential/secret reaches a report/output file sink", _SINK_REPORT_RE),
]


# HIGH: suspicious but sometimes legitimate — flag for human review, don't hard-fail.
_SKILL_HIGH = [
    (
        "download-and-run a package over http",
        re.compile(r"npx\s+-y\s+https?://|pip\s+install\s+https?://|bash\s+<\(\s*curl", re.I),
    ),
    (
        "base64-decode piped to exec / obfuscation",
        re.compile(
            r"base64\s+-d[^\n]{0,40}\|\s*(ba)?sh|eval\([^\n]{0,40}(atob|b64decode|base64)", re.I
        ),
    ),
    (
        "powershell download-and-exec",
        re.compile(r"(iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*iex|Invoke-Expression", re.I),
    ),
    # C-039: a remote fetch fed straight to exec — downloads and immediately runs arbitrary remote code.
    (
        "remote code fetch-and-exec — requests.get/urlopen piped to exec or eval",
        re.compile(
            r"exec\s*\(\s*(?:requests?\.get|urllib\b[^\n]{0,60}urlopen)\s*\([^\n]{0,120}\)\s*"
            r"(?:\.text|\.read\s*\(\s*\)|\.content\b)",
            re.I,
        ),
    ),
    # C-039: pip install git+https:// — installs arbitrary code from an unvetted git ref.
    (
        "pip install from git URL (unvetted remote package)",
        re.compile(r"pip\s+(?:install|install\s+-[^\s]{0,20})\s+git\+https?://", re.I),
    ),
    # C-044: excessive-agency — skill prose/manifest grants itself wildcard tool access or
    # auto-approves commands without user confirmation.  This is the SKILL-CONTENT side of
    # the threat; it is distinct from B48 (config `dangerously*` flags) and B3 (config-level
    # `tools.elevated.allowFrom="*"`).  Conservative patterns matched against agent-
    # manipulation phrasing only; ordinary "automatically format output" prose stays clean.
    #
    # Pattern 1 — auto-approve / auto-confirm / auto-execute / auto-deploy directive prose.
    # Must be followed by "all" (or "any" / "every") so "automatically format" doesn't match.
    (
        "excessive agency: auto-approve/execute directive (skill content)",
        re.compile(
            r"\bauto[_\-]?(?:approve|confirm|execute|deploy)\s+(?:all|any|every)\b|"
            # "execute arbitrary commands" / "run any code" variants
            r"\b(?:execute|run)\s+(?:arbitrary|any)\s+(?:commands?|code|scripts?)\b|"
            # Skill manifest declaring wildcard tool grant: tools: ["*"] / tools: [*] / tools: "*"
            # B-100: leading indent is [ \t]* (horizontal only) so ^\s* can't gobble a
            # multi-line whitespace run across \n under re.M and backtrack per line (quadratic).
            r"^[ \t]*tools\s*:\s*\[?\s*[\"']?\*[\"']?\s*\]?\s*$|"
            # permissions: all / permissions: "all"
            r"^[ \t]*permissions\s*:\s*[\"']?all[\"']?\s*$",
            re.I | re.MULTILINE,
        ),
    ),
]


# Agent-context filenames whose presence in a write-mode context is a persistence signal.
# Grounded against real agent config layouts (OpenClaw, Claude Code, CodexCLI).
_AGENT_CONTEXT_FILES_RE = re.compile(
    r"""(?:
        SOUL\.md | MEMORY\.md | CLAUDE\.md | AGENTS\.md |
        \.claude/settings\.json |
        openclaw\.json |
        ~/?\.(bashrc|zshrc|profile|bash_profile|zprofile|bash_login) |
        /etc/environment
    )""",
    re.I | re.VERBOSE,
)


# Self-modification: writing to `__file__` at runtime.
# Patterns: Path(__file__).write_text(, open(__file__, 'w'), open(__file__, "a"),
#           __file__.write_text, f=open(__file__,  (with any spacing)
_SELF_MOD_RE = re.compile(
    r"""(?:
        Path\s*\(\s*__file__\s*\)\s*\.write_text\s*\( |
        open\s*\(\s*__file__\s*,\s*['"][wa]['"] |
        __file__\s*[,)]\s*['"][wa]['"]
    )""",
    re.I | re.VERBOSE,
)


# Write-mode open / write_text in proximity to an agent-context filename.
# Two-step: first find the agent-context filename; then check within ±_PERSIST_WINDOW
# chars for a write verb.  The write verb is NOT "open" alone (read-opens are fine);
# it must be open(..., 'w'/'a'), .write_text(, .write(, >> (shell redirect), or
# pathlib write_bytes/write_text.
_PERSIST_WRITE_VERB_RE = re.compile(
    r"""(?:
        open\s*\([^)]{0,120}[,\s]['"][wa]['"] |   # open(..., 'w') or open(..., 'a')
        \.write_text\s*\(                        |  # pathlib .write_text(
        \.write_bytes\s*\(                       |  # pathlib .write_bytes(
        \.write\s*\(                             |  # fileobj.write(
        >>\s*\S                                  |  # shell append >>
        >\s*\S                                      # shell overwrite >
    )""",
    re.I | re.VERBOSE,
)


# Cron/startup persistence: scheduling a command that runs at login or reboot.
# Grounded: crontab -e / crontab <file, @reboot inside a cron entry, systemctl enable,
# launchctl load, writes to /etc/cron.* paths or ~/Library/LaunchAgents.
# Conservative: "crontab -l" (read-only listing) is excluded; bare "cron" in prose
# (e.g., "runs daily via cron") does NOT fire — must be an action verb context.
_CRON_PERSIST_RE = re.compile(
    r"""(?:
        crontab\s+-[eur]\b                          |  # crontab -e/-u/-r (not -l)
        crontab\s+[^-\s]                            |  # crontab <file>
        @reboot\b                                   |  # cron @reboot directive
        systemctl\s+enable\b                        |  # systemd persistent enable
        launchctl\s+load\b                          |  # macOS launchd load
        /etc/cron\.(?:d|daily|weekly|monthly|hourly)|  # drop into cron dirs
        Library/LaunchAgents                           # macOS per-user launch agent
    )""",
    re.I | re.VERBOSE,
)


# Backgrounding / daemonize — lower confidence (WARN, not FAIL).
# nohup CMD &, disown, setsid CMD — detaches a process from the session.
# Conservative: "nohup" in a doc comment or "disown" in prose must be quiet;
# we require the shell keyword followed by a command token or whitespace+&.
_DAEMONIZE_RE = re.compile(
    r"""(?:
        \bnohup\s+\S                         |  # nohup <cmd>
        \bdisown\b                           |  # disown (bash job control)
        \bsetsid\s+\S                           # setsid <cmd>
    )""",
    re.I | re.VERBOSE,
)


_PERSIST_WINDOW = 200  # chars around agent-context filename to look for a write verb


# B-085: an inline HTML tag's '>' (e.g. <br>, </div>) sits in the window and looks like a
# shell redirect '>' — strip tags first so a defensive note that merely names AGENTS.md as
# a file to protect ("review edits ... AGENTS.md <br>") isn't read as a write to it.
_HTML_TAG_RE = re.compile(r"<[^>\n]{0,60}>")


# C-040: persistence/rogue-agent patterns
# Each tuple: (label, regex)  — consumed in check_installed_skills HIGH loop.
_SKILL_PERSISTENCE_HIGH = [
    ("self-modification: skill writes to its own source file (__file__)", _SELF_MOD_RE),
    ("cron/startup persistence: installs a scheduled or boot-time job", _CRON_PERSIST_RE),
]


# WARN-severity persistence patterns (backgrounding — lower confidence).
# Tuple: (label, regex)
_SKILL_PERSISTENCE_WARN = [
    (
        "backgrounding/daemonize: skill detaches a persistent subprocess (nohup/disown/setsid)",
        _DAEMONIZE_RE,
    ),
]


def _agent_config_write_hits(
    name: str, blob: str, fence_ranges: list[tuple[int, int]]
) -> list[str]:
    """Return evidence strings for agent-config-file write patterns in *blob*.

    Two-step detection: (1) find each agent-context filename match outside a
    code-example fence; (2) confirm a write-mode verb exists within
    ±_PERSIST_WINDOW chars of the filename match.  This keeps a skill that merely
    READS (or documents) an agent-context file from tripping the detector.
    """
    hits: list[str] = []
    seen_skills: set[str] = set()
    for m in _AGENT_CONTEXT_FILES_RE.finditer(blob):
        if _is_code_example(blob, m.start(), fence_ranges):
            continue
        fname = m.group(0)
        win_start = max(0, m.start() - _PERSIST_WINDOW)
        win_end = min(len(blob), m.end() + _PERSIST_WINDOW)
        window = _HTML_TAG_RE.sub(" ", blob[win_start:win_end])  # B-085: drop inline tag '>'
        if _PERSIST_WRITE_VERB_RE.search(window):
            key = name
            if key not in seen_skills:
                seen_skills.add(key)
                hits.append(
                    f"{name}: agent-config persistence: writes to agent-context file '{fname}'"
                )
    return hits


# F-021: runtime-external-fetch instruction detector (OWASP AST05 "Untrusted External
# Instructions").  A skill that directs the agent to fetch its own instructions / system
# prompt / context from an external URL at runtime hides the malicious payload at a
# remote address — the "brand-landing-page" evasion that static line-scan misses.
#
# Detection requires ALL THREE signals in a 300-char window around a URL:
#   1. a fetch/load VERB  (fetch, download, load, read, retrieve, pull, GET)
#   2. an external http(s):// URL
#   3. an instruction/context TARGET noun  (instructions, context, system prompt, config,
#      rules, prompt, directives)
#
# Conservative design: a skill that merely *references* a URL for documentation
# ("see https://… for details") never fires — it contains no fetch verb + target noun
# combination.  _is_code_example is applied so documented anti-patterns stay clean.
_RUNTIME_FETCH_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]{6,}", re.I)


_RUNTIME_FETCH_VERB_RE = re.compile(r"\b(?:fetch|download|load|read|retrieve|pull|GET)\b", re.I)


_RUNTIME_FETCH_NOUN_RE = re.compile(
    r"\b(?:instructions?|context|system\s+prompt|config(?:uration)?|rules?|"
    r"prompt|directives?)\b",
    re.I,
)


_RUNTIME_FETCH_WINDOW = 300  # chars around the URL to scan for verb + noun


def _runtime_fetch_matches(blob: str, fence_ranges: list[tuple[int, int]]) -> list[str]:
    """Return a list of URL strings where the surrounding window contains BOTH a
    fetch/load verb AND an instruction/context noun — fence-aware (C-041).

    A URL that appears only in a code-example context (fenced block or negation
    window) is silently skipped.  A URL that is present but whose window contains
    only a verb, only a noun, or neither is also skipped (doc-reference safe).
    """
    hits: list[str] = []
    seen: set[str] = set()
    for m in _RUNTIME_FETCH_URL_RE.finditer(blob):
        if _is_code_example(blob, m.start(), fence_ranges):
            continue
        url = m.group(0)
        # Expand a symmetric window around the URL match.
        win_start = max(0, m.start() - _RUNTIME_FETCH_WINDOW)
        win_end = min(len(blob), m.end() + _RUNTIME_FETCH_WINDOW)
        window = blob[win_start:win_end]
        if _RUNTIME_FETCH_VERB_RE.search(window) and _RUNTIME_FETCH_NOUN_RE.search(window):
            key = url[:80]
            if key not in seen:
                seen.add(key)
                hits.append(url[:80])
    return hits


# C-039: destructive autonomous actions — HIGH when a destructive command co-occurs with an
# autonomy marker ("silently", "without asking", "--yes", "--force", "non-interactive", etc.).
# The bare `rm -rf /` literal is already CRITICAL via _SKILL_CRIT; the patterns here cover
# the broader class where a human-override directive amplifies a dangerous git/shell command.
# Bounded quantifiers ({0,120}) keep matching linear against attacker-controlled skill text.
_DESTRUCTIVE_CMD_RE = re.compile(
    # rm -rf targeting home or absolute paths is dangerous; rm -rf on relative paths
    # (./dist, ../build, .) is routine tooling and excluded to avoid false positives.
    r"\brm\s+-[rR][fF]\s+(?:~(?:/[^\s]{0,80})?|\$HOME\b|\$\{HOME\}[^\n\s]{0,80})|"
    r"\bgit\s+(?:reset\s+--hard|push\s+(?:--force|-f)\b)|"
    r"\bhistory\s+-[cC]\b|"
    r"\bshred\b[^\n]{0,80}|"
    r"\bmkfs\b[^\n]{0,80}|"
    r"\bdd\s+if=[^\n]{0,80}of=/dev/",
    re.I,
)


_AUTONOMY_RE = re.compile(
    r"without\s+asking|silently|non.?interactive|no\s+confirmation|automatically|"
    r"(?<!\S)--yes\b|(?<!\S)-y\b(?!\w)|without\s+(?:prompting|confirmation|approval)|"
    r"no\s+prompt",
    re.I,
)


# Prompt-injection / approval-bypass directives embedded in a THIRD-PARTY skill's prose
# (the SkillSpector P1-P8 class). Distinct from B6, which scans the user's OWN bootstrap.
# A skill that tells the agent to ignore its instructions, hide actions from the user, or
# exfiltrate secrets warrants review (HIGH). Deliberately narrow: these match agent-
# MANIPULATION phrasing, NOT ordinary setup prose (a skill reading its own `.env` or
# curling a reputable installer must stay clean — see the zero-false-positive law).
# Genuine malware co-located with these still scores CRITICAL via _SKILL_CRIT / cred-exfil.
# (label, standalone, regex). standalone=True fires HIGH on its own (the canonical
# prompt-injection phrase is essentially never in legit skill prose). standalone=False
# rules are dual-use ("do not notify the user on every sync" is a normal UX directive),
# so they fire ONLY alongside a credential/exfil signal — keeping zero false-positive FAILs.
_SKILL_INJECTION = [
    (
        "ignore-instructions directive",
        True,
        re.compile(
            r"ignore\s+(all\s+)?(your\s+|the\s+)?previous\s+instructions|"
            r"disregard\s+(your\s+)?(system\s+)?(prompt|instructions)|"
            r"forget\s+(all\s+)?(your\s+)?(previous\s+)?instructions",
            re.I,
        ),
    ),
    (
        "exfiltration directive",
        False,
        re.compile(
            r"\bexfiltrate\b|"
            r"(send|upload|leak|email)\s+[^\n]{0,40}(secret|token|api[_-]?key|credential|"
            r"password|private\s+key)s?\s+to\b",
            re.I,
        ),
    ),
    (
        "hide-from-user directive",
        False,
        re.compile(
            r"do\s+not\s+(tell|inform|notify|alert)\s+the\s+user|"
            r"without\s+(telling|notifying|informing)\s+the\s+user|"
            r"bypass\s+the\s+(confirmation|approval)\s+(prompt|step|dialog)|"
            r"don'?t\s+ask\s+(the\s+user\s+)?for\s+(permission|confirmation|approval)",
            re.I,
        ),
    ),
]


# F-052: safety-subversion (AR1-3) & system-prompt/tool-definition leak (P6-8) directives in
# skill prose. Unlike the dual-use _SKILL_INJECTION entries these are malicious on their own
# (no cred/exfil co-signal), but they are also the exact phrases a *security* skill quotes as
# examples — so each hit is dampened by _in_example_context (fence + negation + a wider
# security-documentation vocabulary window) to hold zero false positives.
_SKILL_SAFETY_SUBVERSION = [
    (
        "anti-refusal directive",
        re.compile(
            r"\b(?:you\s+(?:must|will|should)\s+)?never\s+refuse\b|"
            r"\bdo\s+not\s+refuse\s+(?:any|the|to|my)\b|"
            r"\brefuse\s+nothing\b|"
            r"\bcomply\s+with\s+(?:any|all|every|each)\s+(?:request|instruction|command)",
            re.I,
        ),
    ),
    (
        "safety-policy override directive",
        re.compile(
            r"\b(?:ignore|disregard|bypass|override|disable|turn\s+off|forget)\s+"
            r"(?:your\s+|the\s+|all\s+)?(?:safety|security|content|moderation|ethical)\s+"
            r"(?:guidelines?|guardrails?|guard\s?rails?|policy|policies|rules?|filters?|"
            r"restrictions?|constraints?)",
            re.I,
        ),
    ),
    (
        "no-warnings directive",
        re.compile(
            r"\bdo\s+not\s+(?:add|include|show|give|display|write|append)\s+(?:any\s+)?"
            r"(?:warnings?|disclaimers?|caveats?|safety\s+notices?)\b|"
            r"\bwithout\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?)\b|"
            r"\bomit\s+(?:all\s+)?(?:warnings?|disclaimers?|caveats?)\b",
            re.I,
        ),
    ),
    (
        "system-prompt leak directive",
        re.compile(
            r"\b(?:print|output|reveal|repeat|echo|display|reproduce|dump|show)\s+"
            r"(?:me\s+)?(?:your\s+|the\s+)?(?:full\s+|entire\s+|complete\s+|exact\s+)?"
            r"system\s+(?:prompt|instructions|message)\b|"
            r"\byour\s+(?:system\s+)?(?:prompt|instructions)\s+"
            r"(?:verbatim|word.for.word|exactly|in\s+full)\b|"
            r"\bwhat\s+are\s+your\s+(?:system\s+)?(?:instructions|prompt)\b",
            re.I,
        ),
    ),
    (
        "tool-definition leak directive",
        re.compile(
            r"\b(?:reveal|dump|print|output|list|show)\s+(?:me\s+)?(?:all\s+)?"
            r"(?:your\s+|the\s+)?(?:tool|function)\s+"
            r"(?:definitions?|schemas?|signatures?|specs?)\b|"
            r"\b(?:reveal|dump|list|enumerate)\s+(?:all\s+)?(?:the\s+)?tools?\s+"
            r"(?:you\s+have\s+access\s+to|available\s+to\s+you|you\s+can\s+use)\b",
            re.I,
        ),
    ),
]


# Wider "this is a documented example, not a live instruction" vocabulary than
# _negation_context: a security skill that quotes these attack phrases surrounds them with
# words like e.g. / malicious / attacker / scanner / detect / flag / like. Any of these within
# _SAFETY_EXAMPLE_WINDOW chars of the hit dampens it.
_SAFETY_EXAMPLE_WINDOW = 160


_SAFETY_EXAMPLE_RE = re.compile(
    r"\b(?:e\.?g\.?|i\.?e\.?|for\s+example|for\s+instance|such\s+as|examples?|"
    r"malicious|malware|attacker|adversar|phish|red[\s-]?team|injection|jailbreak|"
    r"detect|detector|flag(?:s|ged|ging)?|scan(?:s|ner|ning)?|audit|review|"
    r"never\s+(?:say|write|include|use)|avoid|instead\s+of|rather\s+than|"
    r"looks?\s+like|might\s+(?:say|instruct|ask|contain)|would\s+(?:say|instruct)|"
    r"such\s+directives?|these\s+(?:phrases?|patterns?|directives?)|watch\s+(?:out\s+)?for)\b",
    re.I,
)


def _in_example_context(blob: str, pos: int, fence_ranges: list[tuple[int, int]]) -> bool:
    """True when the match at *pos* is a documented example, not a live directive — either
    inside a fence / negation window (_is_code_example) or surrounded by security-doc
    vocabulary (_SAFETY_EXAMPLE_RE) within _SAFETY_EXAMPLE_WINDOW chars."""
    if _is_code_example(blob, pos, fence_ranges):
        return True
    seg = blob[max(0, pos - _SAFETY_EXAMPLE_WINDOW) : pos + _SAFETY_EXAMPLE_WINDOW]
    return bool(_SAFETY_EXAMPLE_RE.search(seg))


_FM_HOMEPAGE_RE = re.compile(
    r"^\s*(?:homepage|repository|repo|url)\s*:\s*[\"']?(https?://[^\s\"'#]+)",
    re.I | re.MULTILINE,
)


_URL_HOST_RE = re.compile(r"https?://([^/:\s\"'<>)\]]+)", re.I)


def _skill_own_host(blob: str):
    """Host of the skill's declared homepage/repository frontmatter URL (lowercased), or
    None when the frontmatter declares no such field. Conservative: only real homepage/
    repo/url keys count — not an icon CDN or a demo link."""
    fm = _skill_frontmatter_block(blob)
    if fm is None:
        return None
    m = _FM_HOMEPAGE_RE.search(fm)
    if m is None:
        return None
    hm = _URL_HOST_RE.match(m.group(1))
    return hm.group(1).lower() if hm else None


def _url_matches_own_host(url: str, own_host) -> bool:
    """True when *url*'s host equals the skill's own declared host (exact or subdomain)."""
    if not own_host:
        return False
    hm = _URL_HOST_RE.match(url)
    if hm is None:
        return False
    h = hm.group(1).lower()
    return h == own_host or h.endswith("." + own_host)


# F-051 (SkillSpector TR1): overly-broad activation triggers — the skill claims to fire on
# nearly any user action. WARN-first (many legit skills have broad-ish triggers).
_SKILL_BROAD_TRIGGER_RE = re.compile(
    r"\b(?:whenever|any\s?time|each\s+time)\s+the\s+user\s+"
    r"(?:says|does|asks|types|sends|writes|mentions)\s+(?:anything|something)\b|"
    r"\bon\s+every\s+(?:message|file|url|link|request|prompt|input|interaction|keystroke)\b|"
    r"\b(?:for|on)\s+(?:any|all|every)\s+(?:user\s+)?(?:request|input|message|prompt|query|interaction)\b|"
    r"\balways\s+(?:activate|trigger|invoke|run\s+this|use\s+this\s+skill)\b",
    re.I,
)


# F-060 (H6): prose telling the agent to RUN a bundled relative script — local instruction
# chain (the payload lives one hop away in a file the prose never quotes). Narrow to run/exec
# verbs + a bundled dir prefix + a script extension so reading a doc (references/x.md) is NOT
# flagged; WARN-first (delegation is common).
_SKILL_LOCAL_CHAIN_RE = re.compile(
    r"\b(?:run|execute|exec|source|bash|sh|invoke|launch)\s+(?:the\s+)?(?:file\s+|script\s+)?"
    r"[`'\"]?(?:\./|scripts?/|bin/|lib/|tools?/)[\w./-]*\.(?:sh|bash|zsh|py|pl|rb)\b",
    re.I,
)


_IOC_IPURL_RE = re.compile(r"\bhttps?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d{2,5})?\b")


# `curl URL | sh` is how uv/rustup/brew/deno legitimately install — only suspicious when the
# host is NOT a well-known installer domain.
_REPUTABLE_INSTALL_HOSTS = (
    "astral.sh",
    "sh.rustup.rs",
    "rustup.rs",
    "get.docker.com",
    "brew.sh",
    "deno.land",
    "bun.sh",
    "get.pnpm.io",
    "install.python-poetry.org",
    "sdk.cloud.google.com",
    "nodejs.org",
    "get.k3s.io",
    "starship.rs",
    "get.helm.sh",
    "fnm.vercel.app",
)


# Bounded quantifiers ({0,256}) instead of unbounded [^\n|]* — two adjacent
# unbounded same-class runs split by a tail that fails on no-pipe lines caused
# catastrophic O(n^2) backtracking, so one long line of attacker-controlled
# skill text could hang the scanner (B-006 ReDoS). Bounding the runs keeps the
# match linear while still covering any real `curl URL | sh` one-liner (the URL
# sits within 256 chars of curl and the pipe within 256 of the host).
_PIPE_SHELL_RE = re.compile(
    r"(?:curl|wget)\b[^\n|]{0,256}?https?://([^\s/'\"|]+)[^\n|]{0,256}\|\s*(?:sudo\s+)?(?:ba|z)?sh",
    re.I,
)


# PowerShell -EncodedCommand / -enc carries UTF-16LE-encoded payloads hidden from plain
# text search. We extract the blob, attempt UTF-16LE decode, and re-scan.
_PS_ENC_RE = re.compile(r"-(?:EncodedCommand|enc(?:odedcommand)?)\s+([A-Za-z0-9+/=_-]{20,})", re.I)


_WS_RE = re.compile(r"\s+")


# A run of >=2 quoted string literals optionally joined by '+', e.g.
#   "Y3Vy" + "bCBo" + "dHRw"   — the JS/TS/Python string-concat split evasion.
_QUOTED_CONCAT_RE = re.compile(r"""(?:"[^"\n]*"|'[^'\n]*')(?:\s*\+?\s*(?:"[^"\n]*"|'[^'\n]*'))+""")


# Joiners stripped from a quoted-concat run to glue its base64 fragments back together.
_CONCAT_STRIP_RE = re.compile(r"""[\s"'+\\,]+""")


def _blank_fences(blob: str, ranges: list[tuple[int, int]]) -> str:
    """Return a copy of *blob* with each fenced code block replaced by spaces.

    Newlines inside fence spans are preserved so line numbers stay accurate for
    any downstream use; only non-newline characters are blanked.  This lets the
    cross-skill cred+exfil detector ignore patterns that only appear inside
    documentation code examples.
    """
    if not ranges:
        return blob
    chars = list(blob)
    for start, end in ranges:
        for i in range(start, min(end, len(chars))):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def _has_cred_exfil_outside_fence(blob: str, fence_ranges: list[tuple[int, int]]) -> bool:
    """Same-line cred+exfil rule, fence-aware (C-041).

    A line is only considered if its start position is outside every known fence
    range.  A line that is entirely inside a fenced code block is skipped so that
    documentation examples do not trigger a CRITICAL finding.
    """
    pos = 0
    for ln in blob.splitlines():
        ln_start = pos
        if not _in_fence(ln_start, fence_ranges):
            if _CRED_RE.search(ln) and _EXFIL_RE.search(ln):
                return True
        pos += len(ln) + 1  # +1 for the stripped newline
    return False


def _local_sink_exfil_hits(name: str, blob: str, fence_ranges: list[tuple[int, int]]) -> list[str]:
    """F-023: same-line credential-source AND local-sink (log/tempfile/report), fence-aware.

    One finding per channel per skill. Mirrors _has_cred_exfil_outside_fence zero-FP
    discipline. Static slice only; runtime debug/error text and undeclared-tool-args
    are out of scope (E-014).
    """
    hits: list[str] = []
    seen: set[str] = set()
    pos = 0
    for ln in blob.splitlines():
        ln_start = pos
        pos += len(ln) + 1  # +1 for the stripped newline
        if _in_fence(ln_start, fence_ranges):
            continue
        if not _CRED_RE.search(ln):
            continue
        for label, rx in _LOCAL_SINK_CHANNELS:
            if rx.search(ln) and label not in seen:
                seen.add(label)
                hits.append(f"{name}: {label}")
                break
    return hits


def _decoded_payloads(blob: str) -> list[str]:
    """Return short previews of base64 blobs that decode to shell/download payloads.

    Tries both standard and URL-safe base64 alphabets.
    """
    hits = []
    seen: set[str] = set()
    # B-093: a security/educational skill whose whole text is defensive documentation
    # (## Known Risks + negation) may embed an encoded attack sample — do not let the B63
    # silent-instruction arm FAIL it (matches B58's base_defensive dampening; C-135).
    container_defensive = _whole_text_is_defensive(normalize_for_scan(blob))

    def _check(decoded: str) -> None:
        # NFKC-fold so a fullwidth / homoglyph variant inside the payload
        # (e.g. `ｃurl`) normalizes to ASCII before the keyword match.
        norm = unicodedata.normalize("NFKC", decoded)
        key = norm[:80]
        if key in seen:
            return
        seen.add(key)
        if len(norm) >= 6 and _decoded_is_payload(norm):
            hits.append(norm.strip().replace("\n", " ")[:80])
            return
        # B-093: _DECODED_BAD_RE only catches shell/download payloads. A base64 blob can
        # also decode to a silent-instruction directive (read-then-exfil + "don't include
        # this in your summary") that no shell keyword covers. Route decoded text through
        # B63's decode-aware actionable check so the encoded soft-exfil surfaces instead of
        # passing as an inert blob — unless the container is defensive documentation.
        if len(norm) >= 6 and not container_defensive and _b63_decoded_actionable(norm):
            hits.append(norm.strip().replace("\n", " ")[:80])

    def _scan(source: str) -> None:
        # Standard base64 blobs.
        for token in _B64_BLOB_RE.findall(source):
            decoded = _try_b64_decode(token, urlsafe=False)
            if decoded is not None:
                _check(decoded)
        # URL-safe base64 blobs (characters - and _ instead of + and /).
        # We skip tokens that are a pure subset of the standard alphabet (already covered).
        for token in _B64URL_BLOB_RE.findall(source):
            if not re.search(r"[-_]", token):
                continue  # no URL-safe chars; standard pass already handled this
            decoded = _try_b64_decode(token, urlsafe=True)
            if decoded is not None:
                _check(decoded)

    # Pass 1: the blob as-is (contiguous blobs).
    _scan(blob)
    # Pass 2: whitespace stripped — rejoins a base64 blob wrapped/split across
    # lines (each fragment below the 40-char threshold), the verified B-010 evasion.
    _scan(_WS_RE.sub("", blob))
    # Pass 3: quoted-string concatenation runs ("frag"+"frag"+...) glued back
    # together, so a blob split across concatenated string literals is rejoined.
    for run in _QUOTED_CONCAT_RE.findall(blob):
        _scan(_CONCAT_STRIP_RE.sub("", run))

    return hits


def _powershell_encoded_payloads(blob: str) -> list[str]:
    """Detect PowerShell -EncodedCommand blobs, decode them as UTF-16LE, and re-scan.

    Returns short previews for any decoded payload that contains shell/download patterns.
    UTF-16LE is the encoding Windows PowerShell uses for -EncodedCommand blobs.
    """
    hits = []
    for token in _PS_ENC_RE.findall(blob):
        # Fix padding and try both standard and URL-safe base64.
        for urlsafe in (False, True):
            try:
                if urlsafe:
                    pad = (-len(token)) % 4
                    raw = base64.urlsafe_b64decode(token + "=" * pad)
                else:
                    raw = base64.b64decode(token + "=" * ((-len(token)) % 4))
                decoded = raw.decode("utf-16-le", "ignore")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if decoded and _DECODED_BAD_RE.search(decoded):
                hits.append(f"[PS -EncodedCommand] {decoded.strip().replace(chr(10), ' ')[:80]}")
            # Also re-scan with _EXFIL_RE for exfil-sink hosts not in _DECODED_BAD_RE.
            elif decoded and _EXFIL_RE.search(decoded):
                hits.append(f"[PS -EncodedCommand] {decoded.strip().replace(chr(10), ' ')[:80]}")
    return hits


def check_installed_skills(ctx: Context) -> Finding:
    # Lazy import to avoid circular dependency: logsafe imports SECRET_PATTERNS
    # from this module, so a top-level "from .logsafe import redact" would cycle.
    from ..logsafe import redact as _redact  # noqa: PLC0415

    skills = ctx.installed_skills
    if not skills:
        return _custom(
            "B13",
            HIGH,
            UNKNOWN,
            "No installed third-party skills found to inspect.",
            "Run on the host where installed skills live (~/.openclaw/skills, workspace/skills).",
        )
    crit, high, _persist_warn, warns_local_exfil, parse_error_paths, warns_env_exfil = (
        [],
        [],
        [],
        [],
        [],
        [],
    )
    warns_timebomb: list[str] = []
    warns_install_curl: list[str] = []  # F-097: down-ranked install-doc curl|bash / fetch
    warns_js: list[str] = []  # F-064: soft JS/TS signals (child_process template, dynamic require)
    warns_content: list[
        str
    ] = []  # F-051/F-060/F-062 soft content signals (broad trigger, local chain, IOCs)
    for name, blob in skills.items():
        # C-041: precompute fence ranges once per blob so every check below can
        # skip matches that are purely inside a documented code example.
        _fr = _fence_ranges(blob)
        _own_host = _skill_own_host(blob)  # F-097: skill's own declared homepage host

        # CRIT patterns: iterate all matches; drop those that are code examples.
        for label, rx in _SKILL_CRIT:
            for m in rx.finditer(blob):
                if not _is_code_example(blob, m.start(), _fr):
                    crit.append(f"{name}: {label}")
                    break  # one finding per label per skill is enough

        # Same-line cred+exfil: skip lines that fall entirely inside a fence.
        if _has_cred_exfil_outside_fence(blob, _fr):
            crit.append(f"{name}: secret/credential exfiltration (same-line)")

        for payload in _decoded_payloads(blob):
            # Redact before the preview enters the finding — the decoded bytes are
            # attacker-controlled and may contain secret-shaped strings (H2).
            # Base64/PS-EncodedCommand payloads are NOT prose examples; no FP filter.
            crit.append(f"{name}: hidden base64 payload -> '{_redact(payload)}'")
        for payload in _powershell_encoded_payloads(blob):
            crit.append(f"{name}: {_redact(payload)}")

        # HIGH patterns: same fence-aware approach.
        for label, rx in _SKILL_HIGH:
            for m in rx.finditer(blob):
                if not _is_code_example(blob, m.start(), _fr):
                    # F-097: an http download-and-run under an install/setup heading is a
                    # documented installer (capability, not malice) -> WARN. The obfuscation/
                    # powershell/git entries are NOT gated and stay FAIL.
                    if label == "download-and-run a package over http" and (
                        _under_install_heading(blob, m.start())
                        or _under_defensive_heading(blob, m.start())
                    ):
                        warns_install_curl.append(f"{name}: {label}")
                    else:
                        high.append(f"{name}: {label}")
                    break

        # F-021: runtime-external-fetch instruction (OWASP AST05).
        # Fires when a skill's text contains fetch/load verb + external http(s) URL +
        # instruction/context noun in a 300-char window — all outside code examples.
        for rf_url in _runtime_fetch_matches(blob, _fr):
            # F-097: a fetch to the skill's own declared host, or documented under an
            # install/setup heading, is capability not malice -> WARN. A foreign/IP host
            # fetch (e.g. agentos' hardcoded IP) is not down-ranked and stays FAIL.
            _pos = blob.find(rf_url)
            _downrank = _url_matches_own_host(rf_url, _own_host) or (
                _pos != -1 and _under_install_heading(blob, _pos)
            )
            msg = f"{name}: runtime-external-fetch instruction (OWASP AST05): {rf_url}"
            (warns_install_curl if _downrank else high).append(msg)

        # F-023: same-line credential-source + local data-bearing sink (log/tempfile/report).
        # WARN-only; collected outside the HIGH bucket so it never escalates to FAIL.
        warns_local_exfil.extend(_local_sink_exfil_hits(name, blob, _fr))

        # Pipe-to-shell: use finditer so we have match positions for FP filter.
        for pm in _PIPE_SHELL_RE.finditer(blob):
            host = pm.group(1)
            h = host.lower()
            if any(h == r or h.endswith("." + r) for r in _REPUTABLE_INSTALL_HOSTS):
                continue
            if not _is_code_example(blob, pm.start(), _fr):
                msg = f"{name}: pipe-to-shell from non-reputable host {host}"
                # F-097: pipe-to-shell to the skill's own host or under an install/setup
                # heading is a documented installer -> WARN; else it stays FAIL.
                _own = _own_host is not None and (h == _own_host or h.endswith("." + _own_host))
                if _own or _under_install_heading(blob, pm.start()):
                    warns_install_curl.append(msg)
                else:
                    high.append(msg)

        # Cross-skill cred+exfil: run against the blob with fenced spans blanked so
        # a credential path that only appears inside a documentation example does not
        # combine with an exfil host reference to produce a cross-skill finding.
        _blob_nofence = _blank_fences(blob, _fr)
        _has_same_line = _has_cred_exfil_outside_fence(blob, _fr)
        _has_cross = bool(_CRED_RE.search(_blob_nofence) and _EXFIL_RE.search(_blob_nofence))
        if not _has_same_line and _has_cross:
            high.append(
                f"{name}: credential path and exfil sink both present in skill (split-stage risk)"
            )

        # C-039: destructive + autonomy pattern — HIGH when a destructive shell command
        # (git reset --hard, git push --force, rm -rf ~, shred, mkfs, dd to /dev/) appears
        # alongside an autonomy marker in the skill text. Bare rm -rf / is already CRITICAL
        # via _SKILL_CRIT; this catches the broader class that only becomes dangerous when
        # the agent is instructed to act without asking.  Fence-aware: skip matches that
        # are inside documented code-example blocks.
        if _DESTRUCTIVE_CMD_RE.search(blob) and _AUTONOMY_RE.search(blob):
            # Confirm neither signal is exclusively inside a fenced documentation block.
            _has_destructive_live = any(
                not _is_code_example(blob, m.start(), _fr)
                for m in _DESTRUCTIVE_CMD_RE.finditer(blob)
            )
            _has_autonomy_live = any(
                not _is_code_example(blob, m.start(), _fr) for m in _AUTONOMY_RE.finditer(blob)
            )
            if _has_destructive_live and _has_autonomy_live:
                high.append(
                    f"{name}: destructive command with autonomy marker (no-confirmation destructive action)"
                )

        # Dual-use directives only fire alongside a real cred/exfil signal (zero-FP);
        # the canonical "ignore previous instructions" phrase fires on its own. Co-located
        # real malware (paste-host) still scores CRITICAL via _SKILL_CRIT independently.
        # B-119: the standalone (canonical-phrase) arm previously had NO defensive/example
        # guard, unlike its F-052 sibling below — so a skill that merely QUOTES the phrase as
        # documentation ("for example: <!-- ignore previous instructions -->") got FAILed
        # HIGH. Mirror F-052 EXACTLY: dampen a canonical-phrase hit only when it sits in an
        # example/quote context (_in_example_context). We deliberately do NOT also dampen on
        # _whole_text_is_defensive — a "## Known Risks" heading + one "Never…" line is
        # trivially forgeable and silenced a real hijack directive (C-135 bypasses B5/B1) —
        # nor gate on a sink predicate: bare "curl"/"POST"/URL tokens are ordinary security-
        # doc vocabulary and produced a false-positive FAIL class (C-135 direction A). A
        # co-located live payload (obfuscated / paste-host / hidden-comment exfil) still
        # scores via B58 / _SKILL_CRIT independently. The standalone regexes match against
        # _blob_norm, so the guard uses fence ranges over THAT SAME string (position
        # consistency), not the raw-blob _fr computed above.
        cred_exfil_signal = _has_same_line or _has_cross
        _blob_norm = normalize_for_scan(blob)
        _fr_norm = _fence_ranges(_blob_norm)
        for label, standalone, rx in _SKILL_INJECTION:
            if not standalone:
                if rx.search(_blob_norm) and cred_exfil_signal:
                    high.append(f"{name}: injection directive — {label}")
                continue
            for m in rx.finditer(_blob_norm):
                if _in_example_context(_blob_norm, m.start(), _fr_norm):
                    continue
                high.append(f"{name}: injection directive — {label}")
                break

        # F-052: anti-refusal + system-prompt/tool-definition leak directives. Malicious on
        # their own (no co-signal), but dampened by _in_example_context so a security skill
        # that quotes them as examples stays clean. Fence-position-aware -> search raw blob.
        for label, rx in _SKILL_SAFETY_SUBVERSION:
            for m in rx.finditer(blob):
                if not _in_example_context(blob, m.start(), _fr):
                    high.append(f"{name}: injection directive — {label}")
                    break

        # F-051 / F-060 / F-062: soft content signals -> WARN (never FAIL on their own).
        for m in _SKILL_BROAD_TRIGGER_RE.finditer(blob):
            if not _in_example_context(blob, m.start(), _fr):
                warns_content.append(
                    f"{name}: overly-broad activation trigger — the skill "
                    "claims to fire on nearly any user action (TR1)"
                )
                break
        for m in _SKILL_LOCAL_CHAIN_RE.finditer(blob):
            if not _is_code_example(blob, m.start(), _fr):
                warns_content.append(
                    f"{name}: prose instructs running a bundled script "
                    f"({m.group(0)[:60]}) — review the referenced file (H6)"
                )
                break
        for m in _IOC_ONION_RE.finditer(blob):
            if not _is_code_example(blob, m.start(), _fr):
                warns_content.append(f"{name}: references a Tor .onion address ({m.group(0)})")
                break
        for m in _IOC_IPURL_RE.finditer(blob):
            if _is_public_ip(m.group(1)) and not _is_code_example(blob, m.start(), _fr):
                warns_content.append(
                    f"{name}: hardcoded public-IP URL ({m.group(0)}) — "
                    "unusual for a legitimate skill"
                )
                break
        # F-059: skill-manifest least-privilege — allowed-tools grant vs declared purpose.
        _overgrant = _skill_tool_overgrant(blob, name)
        if _overgrant:
            warns_content.append(_overgrant)

        # C-040: persistence / rogue-agent patterns — HIGH (self-mod, cron/startup)
        # and WARN (backgrounding/daemonize). Fence-aware via _is_code_example.
        for p_label, p_rx in _SKILL_PERSISTENCE_HIGH:
            for pm in p_rx.finditer(blob):
                if not _is_code_example(blob, pm.start(), _fr):
                    high.append(f"{name}: {p_label}")
                    break  # one finding per label per skill

        # C-040: agent-config injection (two-step: filename + write-verb in window).
        for hit in _agent_config_write_hits(name, blob, _fr):
            high.append(hit)

        # C-040: backgrounding/daemonize — lower confidence → WARN bucket.
        # We collect into a separate list so they don't escalate to HIGH FAIL.
        # Stored per-skill in a shared list; returned as WARN after the HIGH check.
        for p_label, p_rx in _SKILL_PERSISTENCE_WARN:
            for pm in p_rx.finditer(blob):
                if not _is_code_example(blob, pm.start(), _fr):
                    # Append to high for now with a WARN tag — separated at return time.
                    # Actually: collect separately to keep severity correct.
                    # We use a dedicated collector defined just below.
                    _persist_warn.append(f"{name}: {p_label}")
                    break

        # AST analysis of the skill's Python files — catches obfuscation regex misses.
        # crit rules (obfuscated exec, getattr/import indirection) FAIL on their own;
        # info rules (plain shell sinks, deserialization) escalate only alongside a
        # credential/exfil signal, so a skill that merely uses subprocess is never failed.
        # F-057: AST_UNANALYZABLE findings (parse failures) are collected separately so
        # they surface as UNKNOWN rather than silently vanishing; they do not alter
        # crit/high/verdict but rank above the WARN buckets below.
        # F-018: also run the abstract effect simulator on each Python file and accumulate
        # the per-entry-point results into ctx.effect_profiles[name].  This is strictly
        # additive — the simulator result is NEVER used to alter crit/high/verdict.
        _skill_ep_results: list[dict] = []
        for relpath, src in ctx.installed_skill_py.get(name, []):
            for af in analyze_python(src, relpath):
                if af.rule == "AST_UNANALYZABLE":
                    parse_error_paths.append(f"{name}: {relpath}")
                    continue
                # F-049: env/agent-config secret -> network sink. WARN-grade (never an
                # automatic FAIL); collected separately from the crit/info verdict path.
                if af.rule == "ENV_EXFIL_FLOW":
                    warns_env_exfil.append(f"{name}: {af.reason} ({relpath}:{af.lineno})")
                    continue
                # F-058: code-level time-bomb / sandbox-evasion gate. WARN-grade.
                if af.rule == "CONDITIONAL_SINK":
                    warns_timebomb.append(f"{name}: {af.reason} ({relpath}:{af.lineno})")
                    continue
                loc = f"{relpath}:{af.lineno}"
                if af.severity == "crit":
                    crit.append(f"{name}: {af.reason} ({loc})")
                elif cred_exfil_signal:
                    high.append(f"{name}: {af.reason} ({loc})")
            # simulate_effects never raises; guard here too in case of future
            # refactors or mocking in tests.
            try:
                _ep = _simulate_effects(src, relpath)
            except Exception:  # noqa: BLE001
                _ep = []
            for entry in _ep:
                # Annotate each entry-point record with its source file for traceability.
                annotated = dict(entry)
                annotated["file"] = relpath
                _skill_ep_results.append(annotated)
        if _skill_ep_results:
            ctx.effect_profiles[name] = _skill_ep_results
        # F-056: cross-file / import-graph taint. A decode-derived value defined in one of
        # this skill's files, imported and run in another, is invisible to the per-file
        # pass above (each half is clean alone). CROSS_FILE_EXEC is crit -> FAIL; the reason
        # already carries the importing file:line and the source module.
        for af in analyze_python_package(ctx.installed_skill_py.get(name, [])):
            crit.append(f"{name}: {af.reason}")
        # F-050: bundled shell (.sh/.bash/.zsh) semantic pass — cred-file read -> outbound
        # exfil, or download piped into a non-shell interpreter. Both are crit -> FAIL.
        for relpath, src in ctx.installed_skill_shell.get(name, []):
            for af in analyze_shell(src, relpath):
                crit.append(f"{name}: {af.reason} ({relpath}:{af.lineno})")
        # F-064: bundled JS/TS (.js/.ts/.mjs/.cjs) lexical pass. eval-of-decoded and
        # remote fetch-then-exec are crit -> FAIL; child_process-with-template and
        # dynamic require() are warn -> the JS WARN bucket below.
        for relpath, src in ctx.installed_skill_js.get(name, []):
            for af in analyze_javascript(src, relpath):
                msg = f"{name}: {af.reason} ({relpath}:{af.lineno})"
                if af.severity == "crit":
                    crit.append(msg)
                else:
                    warns_js.append(msg)
    # C-044: unpinned dependency scan — collect across all skills; WARN severity.
    # Runs after the main CRIT/HIGH loop to avoid polluting the main evidence lists.
    warns_unpinned: list[str] = []
    for name, blob in skills.items():
        warns_unpinned.extend(_unpinned_deps_in_skill(name, blob))
    n = len(skills)
    if crit:
        extra = f" (+{len(crit) - 6} more)" if len(crit) > 6 else ""
        return _custom(
            "B13",
            CRITICAL,
            FAIL,
            "Dangerous code in an installed skill — this is the ClawHavoc class: "
            + "; ".join(crit[:6])
            + extra,
            "Uninstall the flagged skill(s) NOW and rotate any secrets they could reach "
            "(channel tokens, 1Password, cloud keys). Only reinstall skills whose source "
            "you have read.",
            crit,
        )
    if high:
        return _custom(
            "B13",
            HIGH,
            FAIL,
            "Suspicious patterns in installed skill(s): " + "; ".join(high[:6]),
            "Review the flagged skills' source before trusting them; prefer pinned, "
            "signed, VirusTotal-clean releases.",
            high,
        )

    # F-057: parse-error UNKNOWN — ranked above WARN buckets so an unparseable file is
    # never silently masked by a low-confidence WARN or a spurious PASS.  Crit and high
    # FAIL returns above still win, so a skill with real dangerous patterns is never
    # downgraded to UNKNOWN — it FAILs as expected.
    if parse_error_paths:
        extra = f" (+{len(parse_error_paths) - 6} more)" if len(parse_error_paths) > 6 else ""
        return _custom(
            "B13",
            HIGH,
            UNKNOWN,
            "could not analyze "
            + "; ".join(parse_error_paths[:6])
            + extra
            + " — parse error(s); file(s) not scanned by the AST/taint layer",
            "Inspect the flagged file(s) manually: a parse failure may indicate "
            "Python 2 syntax, a template, or a deliberately malformed file used "
            "to blind the AST scanner.",
            parse_error_paths,
        )

    # B-074: scanning hit a size/file/nesting cap (text/py truncation or archive limits) —
    # content beyond the cap was NOT scanned, so the result is UNKNOWN, never a clean PASS.
    # Ranked above the WARN buckets (like the parse-error UNKNOWN): a payload padded past the
    # cap must not read as covered. Crit/high FAIL above still take precedence.
    if getattr(ctx, "limit_hits", None):
        # F-087: padding_anomalies is a SEPARATE, narrower channel — only the text-slice
        # path in collector.py writes it, and only when the discarded tail is low-entropy
        # filler (the shape of deliberate cap-evasion padding). An archive-limit or
        # py-cap hit alone never populates it, so those stay the honest UNKNOWN below;
        # this WARN never happens on a genuine high-entropy oversized asset either.
        if getattr(ctx, "padding_anomalies", None):
            return _custom(
                "B13",
                HIGH,
                WARN,
                "Skill scanning was truncated by oversized LOW-ENTROPY padding — classic "
                "cap-evasion (a real payload can be pushed past the "
                f"{_MAX_BYTES_PER_SKILL // 1000}KB budget behind benign filler); content "
                "beyond the cap was NOT scanned: " + "; ".join(ctx.padding_anomalies[:6]),
                "The unscanned tail is uniform filler, the shape used to hide a payload "
                "past the analysis limit. Split the oversized file(s) and re-vet, or "
                "inspect manually.",
                ctx.padding_anomalies,
            )
        return _custom(
            "B13",
            HIGH,
            UNKNOWN,
            "Skill scanning was truncated / hit limits — coverage is incomplete: "
            + "; ".join(ctx.limit_hits[:6]),
            "Content beyond the size/file cap was not scanned; a payload padded past the "
            "cap can hide there. Review the skill manually or split oversized files.",
        )

    # F-097: install-doc curl|bash / remote-fetch — capability, not malice. WARN, not FAIL.
    # Ranked below crit/high FAIL and the parse/truncation UNKNOWNs above (so a real danger
    # or an incomplete scan still wins), among the WARN buckets.
    if warns_install_curl:
        extra = f" (+{len(warns_install_curl) - 6} more)" if len(warns_install_curl) > 6 else ""
        return _custom(
            "B13",
            HIGH,
            WARN,
            "Installer/setup fetch in installed skill(s): "
            + "; ".join(warns_install_curl[:6])
            + extra,
            "The skill documents a curl|bash / remote-fetch installer under an Install/Setup/"
            "Usage heading, or fetches from its own declared host — a capability, not proof of "
            "malice. Review the installer URL before running: confirm the host is the vendor's, "
            "over HTTPS, and not an IP or paste site.",
            warns_install_curl,
        )

    # F-049: env-var / agent-config secret reaching a network sink — WARN-first (env
    # secrets legitimately go to trusted APIs, so this is never an automatic FAIL). Ranked
    # first among the WARN buckets: a secret leaving the box outranks a persistence/unpinned
    # nudge. Crit/high FAIL and the parse-error UNKNOWN above still take precedence.
    if warns_env_exfil:
        extra = f" (+{len(warns_env_exfil) - 6} more)" if len(warns_env_exfil) > 6 else ""
        return _custom(
            "B13",
            HIGH,
            WARN,
            "Possible secret exfiltration in installed skill(s): "
            + "; ".join(warns_env_exfil[:6])
            + extra,
            "A skill reads an environment-variable or agent-config secret and sends it to a "
            "network endpoint. Confirm the destination is a trusted first-party API, not an "
            "attacker-controlled host — env secrets (API keys, tokens) sent off-box are the "
            "classic exfiltration vector.",
            warns_env_exfil,
        )

    # F-058: a dangerous sink gated on a wall-clock date or an environment variable — a
    # code-level time-bomb / sandbox-evasion pattern. WARN-first (conditional execution has
    # legit uses); ranked among the WARN buckets, below crit/high FAIL and parse-UNKNOWN.
    if warns_timebomb:
        extra = f" (+{len(warns_timebomb) - 6} more)" if len(warns_timebomb) > 6 else ""
        return _custom(
            "B13",
            HIGH,
            WARN,
            "Time-bomb / environment-gated code in installed skill(s): "
            + "; ".join(warns_timebomb[:6])
            + extra,
            "A skill runs a dangerous action (exec/subprocess/network) only when a date "
            "or environment condition is met — the classic way a payload stays dormant in "
            "review/CI and detonates later. Read the guarded branch and confirm it is benign.",
            warns_timebomb,
        )

    # F-064: soft JS/TS signals — child_process exec with an interpolated command, or a
    # dynamic require() of a non-literal. WARN-first (both have legit uses); ranked among
    # the WARN buckets, below crit/high FAIL and the exfil/time-bomb WARNs.
    if warns_js:
        extra = f" (+{len(warns_js) - 6} more)" if len(warns_js) > 6 else ""
        return _custom(
            "B13",
            HIGH,
            WARN,
            "Dynamic JS/TS execution surface in installed skill(s): "
            + "; ".join(warns_js[:6])
            + extra,
            "A bundled .js/.ts file runs child_process with an interpolated command or "
            "require()s a non-literal module path — a command-injection / arbitrary-module "
            "surface. Read the flagged call and confirm the inputs are trusted.",
            warns_js,
        )

    # F-051 / F-060 / F-062: soft content signals — broad activation trigger, delegation to a
    # bundled script, or a Tor/.onion / public-IP IOC. WARN-first; individually weak, worth a
    # human glance. Ranked below the exfil/time-bomb WARNs.
    if warns_content:
        extra = f" (+{len(warns_content) - 6} more)" if len(warns_content) > 6 else ""
        return _custom(
            "B13",
            HIGH,
            WARN,
            "Content signals worth a review in installed skill(s): "
            + "; ".join(warns_content[:6])
            + extra,
            "These are soft signals (broad activation trigger, delegation to a bundled "
            "script, or a Tor/.onion or hardcoded-IP reference). Review the skill's prose "
            "and any referenced files before trusting it.",
            warns_content,
        )

    # C-040: backgrounding/daemonize — lower confidence WARN (nohup/disown/setsid).
    # Only reached when no CRIT/HIGH patterns fired; a skill that also has a CRIT/HIGH
    # signal is already captured above and this path is not reached.
    if _persist_warn:
        return _custom(
            "B13",
            HIGH,
            WARN,
            "Possible persistence/daemonize pattern in installed skill(s): "
            + "; ".join(_persist_warn[:6]),
            "Review whether the skill legitimately needs a background process; "
            "a skill that detaches subprocesses (nohup/disown/setsid) can "
            "establish hidden persistence on the host.",
            _persist_warn,
        )

    # F-023: local-sink secret exposure — WARN-only (never FAIL).
    # Only reached when no CRIT/HIGH patterns and no _persist_warn fired.
    if warns_local_exfil:
        extra = f" (+{len(warns_local_exfil) - 6} more)" if len(warns_local_exfil) > 6 else ""
        return _custom(
            "B13",
            HIGH,
            WARN,
            "Possible local-sink secret exposure in installed skill(s): "
            + "; ".join(warns_local_exfil[:6])
            + extra,
            "A skill writes a credential/secret onto the same line as a local log, temp "
            "file, or report sink. Route sensitive values through redaction; never log or "
            "persist raw secrets. Remove the sink or scrub the value before it is written.",
            warns_local_exfil,
        )

    # Path traversal check
    if getattr(ctx, "path_traversal_violations", None):
        return _custom(
            "B13",
            HIGH,
            "SKILL_ARCHIVE_PATH_TRAVERSAL",
            "Archive path traversal detected: " + "; ".join(ctx.path_traversal_violations[:6]),
            "Ensure archives inside skills do not attempt path traversal.",
        )

    # Mismatch/polyglot/binary warnings
    warnings = []
    if getattr(ctx, "mismatches", None):
        warnings.extend(ctx.mismatches)
    if getattr(ctx, "polyglots", None):
        warnings.extend(ctx.polyglots)
    if getattr(ctx, "stowaway_files", None):  # F-054: native executables don't belong in a skill
        warnings.append(
            "native executable(s) bundled in the skill (stowaway): "
            + ", ".join(ctx.stowaway_files[:4])
        )
    if getattr(ctx, "symlink_skips", None):  # F-061: symlink / path-escape (was silently dropped)
        warnings.append("symlink / path-escape not followed: " + "; ".join(ctx.symlink_skips[:4]))
    if getattr(ctx, "filename_obfuscations", None):  # F-061: homoglyph/RTL/zero-width filename
        warnings.append("obfuscated filename(s): " + ", ".join(ctx.filename_obfuscations[:4]))
    if getattr(ctx, "binary_files", None):
        warnings.append(f"Binary files found: {len(ctx.binary_files)}")

    if warnings:
        return _custom(
            "B13",
            HIGH,
            WARN,
            "Warnings in installed skill(s): " + "; ".join(warnings[:6]),
            "Review the flagged files for extension mismatch, polyglot structures, or unexpected binaries.",
        )

    # C-044: unpinned deps — WARN (supply-chain SC1-3); lower severity than the HIGH/CRIT paths above.
    if warns_unpinned:
        extra = f" (+{len(warns_unpinned) - 6} more)" if len(warns_unpinned) > 6 else ""
        return _custom(
            "B13",
            HIGH,
            WARN,
            "Unpinned dependencies in installed skill(s): " + "; ".join(warns_unpinned[:6]) + extra,
            "Pin all dependencies to exact versions (== X.Y.Z / exact semver) in skill "
            "manifests to prevent supply-chain hijacking via a malicious package update.",
            warns_unpinned,
        )

    # F-022: typosquatting detection — WARN (heuristic, OWASP AST02/AST04).
    # Check skill dir keys, SKILL.md frontmatter name:, and dep package names.
    # Non-redundant with C-038 (Unicode homoglyphs in MCP server names — distinct mechanism).
    warns_squat: list[str] = []
    for skill_name, blob in skills.items():
        # Collect names: dir key + frontmatter name (if distinct) + dep package names
        squat_candidates: list[str] = [skill_name]
        fm_name = _frontmatter_name(blob)
        if fm_name and fm_name.lower() != skill_name.lower():
            squat_candidates.append(fm_name)
        squat_candidates.extend(_dep_names_in_skill(blob))

        for cand, known, d in _squat_hits(squat_candidates):
            warns_squat.append(
                f"{skill_name}: '{cand}' name resembles '{known}' "
                f"(possible typosquat, edit distance {d})"
            )

    if warns_squat:
        extra = f" (+{len(warns_squat) - 6} more)" if len(warns_squat) > 6 else ""
        return _custom(
            "B13",
            HIGH,
            WARN,
            "Possible typosquat name(s) in installed skill(s): "
            + "; ".join(warns_squat[:6])
            + extra,
            "Verify the skill and its dependency names are not impersonating "
            "well-known packages (supply-chain AST02/AST04). Uninstall if "
            "provenance cannot be confirmed.",
            warns_squat,
        )

    return _custom(
        "B13",
        HIGH,
        PASS,
        f"Scanned {n} installed skill(s); no shell-exec / exfiltration / obfuscation "
        "patterns found.",
        "Keep installing only skills whose source you've reviewed — trust no one.",
    )


# F-048: the pre-install vet path runs the shared SKILL_CONTENT_RING (defined near the
# CHECKS list) in addition to check_installed_skills, so --vet reaches the same
# skill-intelligence checks the full audit applies to already-installed skills.
_VET_MERGE_RANK = {FAIL: 3, WARN: 2, UNKNOWN: 1, PASS: 0}


def _run_content_ring(ctx: Context) -> list[Finding]:
    """Run SKILL_CONTENT_RING against `ctx` and return only the actionable (FAIL/WARN)
    findings, de-duplicated by (id, detail).

    PASS/UNKNOWN ring results are dropped on purpose: for a pre-install verdict they add
    no signal, and an UNKNOWN would wrongly outrank a clean PASS (flipping a safe skill to
    "could not assess"). Every ring check is defensive — it returns PASS/UNKNOWN when its
    inputs are absent — so a skill-only ctx (no bootstrap/config) never yields a spurious
    FAIL. A ring check must never break --vet, so a failing check is skipped.
    """
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for check in SKILL_CONTENT_RING:
        try:
            fx = check(ctx)
        except Exception:  # noqa: BLE001 — a ring check must never break --vet
            continue
        if fx.status not in (FAIL, WARN):
            continue
        key = (fx.id, fx.detail)
        if key in seen:
            continue
        seen.add(key)
        out.append(fx)
    return out


def vet_skill(path: str | Path) -> Finding:
    """Vet a skill BEFORE installing it: run the B13 scan on a local skill dir or SKILL.md."""
    p = Path(path).expanduser()
    ctx = Context(home=p)
    if p.is_dir():
        if _is_own_source(p):
            finding = _custom(
                "B13",
                LOW,
                PASS,
                "This is ClawSecCheck's own source. A security auditor necessarily "
                "ships attack signatures and red-team payloads as data, so a naive "
                "malware scan flags its own signature database — that is expected here, "
                "not malware.",
                "Point --vet at third-party skills you're about to install, not at the "
                "scanner itself.",
            )
            finding.ctx = ctx
            return finding
        text, name = _read_skill_text(p, ctx), p.name
        py_sources = read_skill_python(p, ctx)
        shell_sources = read_skill_shell(p, ctx)
        js_sources = read_skill_js(p, ctx)
    elif p.is_file():
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            finding = _custom("B13", HIGH, UNKNOWN, f"could not read {p}: {exc}", "—")
            finding.ctx = ctx
            return finding
        name = p.parent.name or p.stem
        py_sources = [(p.name, text)] if p.suffix == ".py" else []
        shell_sources = [(p.name, text)] if p.suffix in (".sh", ".bash", ".zsh") else []
        js_sources = [(p.name, text)] if p.suffix in (".js", ".ts", ".mjs", ".cjs") else []
    else:
        finding = _custom(
            "B13",
            HIGH,
            UNKNOWN,
            f"no skill found at {p}",
            "Point --vet at a skill dir or SKILL.md.",
        )
        finding.ctx = ctx
        return finding
    ctx.installed_skills = {name or "skill": text}
    ctx.installed_skill_py = {name or "skill": py_sources}
    ctx.installed_skill_shell = {name or "skill": shell_sources}
    ctx.installed_skill_js = {name or "skill": js_sources}
    finding = check_installed_skills(ctx)
    # F-048: also run the shared content-security ring. check_installed_skills has already
    # populated ctx.effect_profiles (so B62 can compare declared vs actual capability), and
    # ctx.installed_skills / ctx.installed_skill_py are set above. Fold in only the
    # actionable (FAIL/WARN) ring results: surface the worst as the primary verdict and
    # carry the rest on .ring_findings for the JSON / human / SARIF renderers.
    ring = _run_content_ring(ctx)
    if ring:
        pool = [finding, *ring]
        primary = max(pool, key=lambda fx: _VET_MERGE_RANK.get(fx.status, 0))
        primary.ring_findings = [
            fx for fx in pool if fx is not primary and fx.status in (FAIL, WARN)
        ]
        primary.ctx = ctx
        return primary
    finding.ctx = ctx
    return finding


_PLUGIN_MANIFEST = "openclaw.plugin.json"


def _locate_plugin_root(p: Path) -> Path | None:
    """Resolve the plugin package root (the dir carrying openclaw.plugin.json).

    Accepts the root itself, the manifest file, or a host wrapper project dir
    (~/.openclaw/npm/projects/<pkg>-<hash>__openclaw-generation__…/) whose real plugin
    lives under node_modules/<pkg> or node_modules/@scope/<pkg> (recon §11.1).
    """
    if p.is_file() and p.name == _PLUGIN_MANIFEST:
        return p.parent
    if not p.is_dir():
        return None
    if (p / _PLUGIN_MANIFEST).is_file():
        return p
    nm = p / "node_modules"
    if nm.is_dir():
        hits = sorted(nm.glob("*/" + _PLUGIN_MANIFEST)) + sorted(
            nm.glob("@*/*/" + _PLUGIN_MANIFEST)
        )
        if len(hits) == 1:
            return hits[0].parent
    return None


def detect_vet_type(target: str | Path, home: str | Path = "~/.openclaw") -> str:
    """Classify a --vet target as 'plugin' / 'mcp' / 'skill' / 'unknown' by content.

    Detection order (design D1, most specific first): a plugin manifest wins; then a
    JSON file with an explicit MCP server-spec shape, or a server name found in the
    config at *home*; then anything skill-shaped (today's --vet semantics). 'unknown'
    means nothing matched — callers route it to the skill engine, which answers with
    an honest UNKNOWN, never a guessed PASS.
    """
    import json as _json

    p = Path(str(target)).expanduser()
    if p.exists():
        if _locate_plugin_root(p) is not None:
            return "plugin"
        if p.is_file() and p.suffix == ".json":
            try:
                data = _json.loads(p.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                data = None
            # Strict spec shapes only (mcpServers / mcp.servers / a bare server spec) —
            # _load_mcp_spec_file's loose {name: dict} fallback would misroute e.g. a
            # tsconfig.json here.
            if isinstance(data, dict) and (
                (isinstance(data.get("mcpServers"), dict) and data["mcpServers"])
                or (isinstance(dig(data, "mcp.servers"), dict) and dig(data, "mcp.servers"))
                or "command" in data
                or ("url" in data and "transport" in data)
            ):
                return "mcp"
            return "unknown"
        if p.is_dir() or p.is_file():
            return "skill"
        return "unknown"
    # Not a path on disk: maybe a configured MCP server name.
    cfg_file = Path(str(home)).expanduser() / "openclaw.json"
    try:
        cfg = _json.loads(cfg_file.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        cfg = {}
    if isinstance(cfg, dict) and str(target) in _mcp_servers(cfg):
        return "mcp"
    return "unknown"


# ---------- vet_source: pre-download reputation gate (E-020 F-073 = E-019 F-064) ----
# "Check before download": judge a source's IDENTITY (slug / URL / package spec) with
# zero network and zero fetch, from bundled local catalogs only. Verdict bands:
#   FAIL    known-bad        — do not fetch, exact IOC match;
#   WARN    suspicious       — fetch only into an isolated quarantine, extra scrutiny;
#   UNKNOWN no known-bad     — proceed via quarantine and --vet the fetched copy.
# NEVER a PASS: an identity check cannot prove unseen code safe (§ honesty).
#
# The known-bad catalog is seeded ONLY from real, primary-source-verified public advisories
# (§2.4 — no fabricated IOCs), each entry citing its advisory. It is a POINT-IN-TIME SNAPSHOT
# (2026-07-03), not a live feed (the feed idea is I-004's territory). Every entry below was
# verified against the PRIMARY advisory text before commit (§4 wall, C-145): indicators the
# primary source did not confirm were left out — e.g. the "hightower6eu" publisher account
# (unconfirmed on the Koi page, and vet_source has no publisher field to match it against).
# Generic slugs ("update", "pdfcheck") and shared hosts (rentry.co, glot.io, *.vercel.app)
# are excluded as false-positive-prone. Tests inject synthetic catalogs via the
# known_bad/known_good parameters. Ecosystem keys: "npm", "pypi", "clawhub", "git", "url",
# "any". Slug pools match a source's name; the "url"/"any" pools also match a URL's host.
_SOURCE_KNOWN_BAD: dict = {
    "npm": frozenset(),
    "pypi": frozenset(),
    "clawhub": frozenset(
        {
            # Palo Alto Unit 42, "OpenClaw's Skill Marketplace and the Emerging AI Supply
            # Chain Threat" (2026-06-23) — verified verbatim against
            # unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/.
            "omnicogg",  # AMOS dropper hidden behind ~22 MB README padding (scanner evasion)
            "money-radar",  # runtime affiliate-link injection abusing agent advisory authority
            "letssendit",  # agentic meme-token front-running scheme
            "ai-tradingview-assistant-for-macos",  # macOS infostealer delivery
            "tradingview-ai-indicator-assistant",  # macOS infostealer delivery
        }
    ),
    "git": frozenset(),
    "url": frozenset(
        {
            # Malicious infrastructure hosts (matched against a vetted URL's host, incl.
            # subdomains). Koi Security "ClawHavoc" (2026-02-01, koi.ai) + Unit 42 (2026-06-23).
            "91.92.242.30",  # shared ClawHavoc C2 — confirmed by BOTH Koi and Unit 42
            "laosji.net",  # Unit 42 — payload / hosting infrastructure
            "letssendit.fun",  # Unit 42 — letssendit campaign infrastructure
        }
    ),
    "any": frozenset(),
}


# Known-good identity pools for typosquat comparison, per ecosystem, used ON TOP of
# the global _KNOWN_NAMES brand list. "plugin-ids" is grounded on the real bundled
# OpenClaw fleet (recon §11.1: dist/extensions/<id> + installed npm plugins) —
# impersonating one of these ids ("telegramm", "cnavas") is exactly the squat this
# gate exists to catch pre-download.
_SOURCE_KNOWN_GOOD: dict = {
    "clawhub": frozenset({"clawseccheck"}),
    "npm": frozenset(),
    "pypi": frozenset(),
    "plugin-ids": frozenset(
        {
            "telegram",
            "brave",
            "canvas",
            "browser",
            "openai",
            "codex",
            "imessage",
            "google",
            "github-copilot",
            "ollama",
            "anthropic",
            "deepgram",
            "elevenlabs",
            "huggingface",
            "duckduckgo",
            "lmstudio",
            "litellm",
            "copilot-proxy",
            "document-extract",
            "file-transfer",
            "azure-speech",
            "cohere",
        }
    ),
}


# Paste / raw-snippet hosts: no provenance, no review, no history — a classic drop
# point for one-off malicious payloads (matched against the URL hostname).
_SOURCE_PASTE_HOSTS = (
    "gist.githubusercontent.com",
    "gist.github.com",
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "dpaste.org",
    "dpaste.com",
    "transfer.sh",
    "termbin.com",
    "0x0.st",
)


_SOURCE_GIT_RE = re.compile(r"^git:(?P<host>[^/\s]+)/(?P<path>[^@\s]+?)(?:@(?P<ref>\S+))?$", re.I)


_SOURCE_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def _parse_source_target(target: str) -> dict:
    """Parse a --vet-source target into identity facts (never raises).

    Recognized shapes mirror the real `openclaw plugins install` sources (recon
    §11.4): `clawhub:<slug>`, `npm:<pkg>[@ver]`, `git:host/owner/repo[@ref]`, plus
    `pypi:<pkg>[==ver]`, http(s) URLs, and a bare registry name (which OpenClaw
    resolves to npm by default — checked against every catalog here).
    """
    t = str(target).strip()
    low = t.lower()
    out = {
        "ecosystem": "registry",
        "name": t,
        "version": None,
        "host": None,
        "ref": None,
        "kind": None,
        "scheme": None,
    }
    if low.startswith(("http://", "https://")):
        parsed = urlparse(t)
        out.update(
            ecosystem="url",
            scheme=parsed.scheme,
            host=(parsed.hostname or "").lower(),
            name=(parsed.path.rstrip("/").rsplit("/", 1)[-1] or (parsed.hostname or t)),
        )
    else:
        m = _SOURCE_GIT_RE.match(t)
        if m:
            out.update(
                ecosystem="git",
                host=m.group("host").lower(),
                name=m.group("path").rsplit("/", 1)[-1],
                ref=m.group("ref"),
            )
        elif low.startswith("npm:"):
            spec = t[4:]
            if spec.startswith("@"):
                scope_name, _, ver = spec[1:].partition("@")
                out.update(ecosystem="npm", name="@" + scope_name, version=ver or None)
            else:
                name, _, ver = spec.partition("@")
                out.update(ecosystem="npm", name=name, version=ver or None)
        elif low.startswith("pypi:"):
            name, _, ver = t[5:].partition("==")
            out.update(ecosystem="pypi", name=name, version=ver or None)
        elif low.startswith("clawhub:"):
            out.update(ecosystem="clawhub", name=t[8:])
    # Kind guess (informational only — which per-type engine the fetched copy faces).
    nlow = str(out["name"]).lower()
    if out["ecosystem"] == "clawhub":
        out["kind"] = "plugin" if nlow.endswith("-plugin") else "skill"
    elif "mcp" in nlow:
        out["kind"] = "mcp"
    elif nlow.startswith("@openclaw/") or nlow.endswith("-plugin"):
        out["kind"] = "plugin"
    return out


def vet_source(
    target: str, *, known_bad: dict | None = None, known_good: dict | None = None
) -> Finding:
    """Pre-download reputation gate: vet a source's identity WITHOUT fetching it.

    Zero network — catalogs are bundled/local. Returns a synthetic "SOURCE-VET"
    Finding whose status is FAIL (known-bad, do not fetch), WARN (suspicious,
    quarantine only) or UNKNOWN (no known-bad record — proceed via the quarantine
    pipeline and --vet the fetched copy). Never PASS: identity cannot prove unseen
    code safe.
    """
    bad = known_bad if known_bad is not None else _SOURCE_KNOWN_BAD
    good = known_good if known_good is not None else _SOURCE_KNOWN_GOOD

    def _f(severity, status, detail, fix, ev=None) -> Finding:
        return Finding(
            "SOURCE-VET",
            "Pre-download source reputation gate",
            severity,
            status,
            detail,
            fix,
            "Source Reputation",
            False,
            ev or [],
        )

    t = str(target).strip()
    if not t:
        return _f(
            HIGH,
            UNKNOWN,
            "empty --vet-source target",
            "Pass a slug (clawhub:name), package spec (npm:pkg / pypi:pkg), "
            "git:host/owner/repo@ref, or URL.",
        )
    info = _parse_source_target(t)
    eco, name = info["ecosystem"], str(info["name"])
    plain = name.lstrip("@").rsplit("/", 1)[-1].lower()

    reasons_bad: list = []
    reasons_susp: list = []
    notes: list = [
        "identity: ecosystem="
        + eco
        + (f" · kind≈{info['kind']}" if info.get("kind") else "")
        + (f" · version={info['version']}" if info.get("version") else " · version=unpinned")
    ]

    # 1. Known-bad IOC — exact ecosystem+name match (a bare registry name is checked
    #    against every ecosystem, mirroring OpenClaw's bare-spec resolution order).
    eco_keys = [eco, "any"] if eco != "registry" else list(bad.keys())
    for k in eco_keys:
        pool = bad.get(k) or frozenset()
        if name.lower() in pool or plain in pool:
            reasons_bad.append(
                f"'{name}' is a known-compromised source (exact IOC match, catalog: {k})"
            )
            break

    # 1b. Known-bad HOST — a URL (or git) whose host is, or is a subdomain of, a known-bad
    #     domain/IP in the url/any pool. The name check above matches slugs/packages; this
    #     matches infrastructure IOCs (a source served straight off known-bad C2 infra).
    host_l = (info.get("host") or "").lower()
    if host_l and not reasons_bad:
        for k in (eco, "any"):
            pool = bad.get(k) or frozenset()
            if any(host_l == h or host_l.endswith("." + h) for h in pool):
                reasons_bad.append(
                    f"host '{host_l}' is known-compromised infrastructure "
                    f"(exact IOC match, catalog: {k})"
                )
                break

    # 2. Typosquat vs the brand list + ecosystem known-good pools + real plugin ids.
    pool = set(_KNOWN_NAMES) | set(good.get("plugin-ids") or ())
    pool |= set(good.get(eco) or ())
    if eco == "registry":
        for v in good.values():
            pool |= set(v)
    if plain not in pool:  # an exact known-good name is the real thing, not a squat
        for cand, kn, d in _squat_hits([plain], known=frozenset(pool))[:3]:
            reasons_susp.append(
                f"'{cand}' resembles well-known '{kn}' (edit distance {d}) — possible typosquat"
            )

    # 3. Source heuristics.
    host = info.get("host") or ""
    if eco == "url":
        if info.get("scheme") == "http":
            reasons_susp.append("plaintext http:// source — no transport integrity")
        if any(host == h or host.endswith("." + h) for h in _SOURCE_PASTE_HOSTS):
            reasons_susp.append(
                f"raw paste/gist host '{host}' — no provenance, no review, no history"
            )
        if _SOURCE_IP_RE.fullmatch(host):
            reasons_susp.append(f"bare-IP host '{host}' — no domain provenance")
        if host.endswith(".onion"):
            reasons_susp.append(f"anonymous .onion host '{host}'")
    if eco == "git" and not info.get("ref"):
        reasons_susp.append(
            "git source without a pinned @ref (tag/sha) — content "
            "can change between this check and the fetch"
        )

    evidence = reasons_bad + reasons_susp + notes
    if reasons_bad:
        return _f(
            CRITICAL,
            FAIL,
            f"KNOWN-BAD source '{t}': " + reasons_bad[0],
            "Do NOT fetch or install this. If it is already installed, remove it "
            "and rotate any secrets the agent could reach.",
            evidence,
        )
    if reasons_susp:
        return _f(
            MEDIUM,
            WARN,
            f"suspicious source identity '{t}': " + reasons_susp[0],
            "Fetch only into an isolated quarantine dir (never under ~/.openclaw) "
            "and run --vet on the fetched copy before any install.",
            evidence,
        )
    return _f(
        LOW,
        UNKNOWN,
        f"no known-bad record for '{t}' — identity checks cannot prove unseen code safe",
        "Proceed via quarantine: fetch into an isolated dir and run --vet on the "
        "fetched copy before installing.",
        evidence,
    )


# Tool name -> capability family (aligned with _B62_EXPECTED's family vocabulary).
_TOOL_FAMILY: dict[str, str] = {
    "bash": "exec",
    "shell": "exec",
    "sh": "exec",
    "exec": "exec",
    "execute": "exec",
    "terminal": "exec",
    "command": "exec",
    "subprocess": "exec",
    "run_command": "exec",
    "write": "write",
    "edit": "write",
    "createfile": "write",
    "filewrite": "write",
    "str_replace_editor": "write",
    "applypatch": "write",
    "apply_patch": "write",
    "webfetch": "network",
    "fetch": "network",
    "browser": "network",
    "http": "network",
    "network": "network",
    "curl": "network",
    "websearch": "network",
    "web_search": "network",
    "read": "read",
    "grep": "read",
    "glob": "read",
    "view": "read",
    "ls": "read",
}


def _skill_tool_overgrant(blob: str, skill_name: str) -> str | None:
    """WARN message if a NARROW-purpose skill's manifest grants high-power tools
    (exec/network/write/cred) beyond what its declared category needs; else None. Only
    recognised narrow categories fire — PERMISSIVE/vague or unrecognised declarations, and
    pure wildcard grants (already flagged HIGH elsewhere), never do."""
    tools = _skill_declared_tools(blob)
    if not tools:
        return None
    name, desc = _b62_extract_declaration(blob, skill_name)
    cat = _b62_classify_category(name, desc)
    if cat is None or cat == "PERMISSIVE":
        return None
    expected = _B62_EXPECTED.get(cat, frozenset())
    granted = {_TOOL_FAMILY[t] for t in tools if t in _TOOL_FAMILY}
    # Only high-power families count as over-grant (exec/network/cred, per _B62_HIGH_SURPRISE).
    # `write` is too common/benign (a fetcher saving its download) to flag.
    surprising = {f for f in granted if f not in expected and f in _B62_HIGH_SURPRISE}
    if not surprising:
        return None
    return (
        f"{skill_name or name}: a '{cat}' skill grants {sorted(surprising)} capability "
        f"({', '.join(sorted(tools))}) beyond its declared purpose (least-privilege)"
    )


SKILL_CONTENT_RING = (
    check_unicode_obfuscation,  # B58 — unicode / hidden-text de-obfuscation
    check_markdown_image_exfil,  # B59 — MD-image data-exfil
    check_image_attr_injection,  # C074 — HTML img-attr injection
    check_prompt_self_replication,  # B60 — self-replication directive
    check_agent_snooping,  # B61 — cross-agent config snooping
    check_capability_intent_mismatch,  # B62 — capability–intent mismatch
    check_silent_instruction,  # B63 — "don't tell the user"
    check_instruction_hierarchy_override,  # B64 — instruction-hierarchy override
    check_conditional_sleeper_trigger,  # B65 — conditional sleeper-trigger
    check_persona_jailbreak,  # B66 — persona / DAN jailbreak
    check_per_source_trust_contracts,  # B67 — per-source trust contracts
    check_forged_provenance,  # B74 — forged role / false-provenance
    check_install_policy,  # B42 — install-time policy (hooks + dir perms)
    check_import_from_writable,  # B86 — defensibility: import-path hijack surface (D1)
    check_symlink_escape,  # B87 — symlink escape to a sensitive host path (TAM-07)
    check_frontmatter_hygiene,  # B88 — frontmatter authoring hygiene (tag values / squat)
    check_dormant_capability,  # B89 — unreachable-yet-code-bearing skill (dormant capability)
    check_cross_file_payload,  # B90 — cross-file split base64 payload reassembly (I-019)
    check_cross_file_boundary_payload,  # B102 — base64 split exactly at a file boundary (F-086)
    check_dynamic_dispatch_obfuscation,  # B91 — dynamic-dispatch sink obfuscation (F-102)
    check_unsafe_deserialization,  # B92 — unsafe deserialization sink (F-098)
    check_trigger_homoglyph,  # B93 — confusable characters in trigger description (F-103)
    check_lifecycle_hooks_extended,  # B94 — extended lifecycle hooks beyond postinstall (F-099)
    check_dependency_confusion,  # B95 — unpinned dep name resembling a well-known package (F-101)
    check_cross_skill_combined_effect,  # B105 — cross-skill Signal-A/Signal-B combined effect (B-096)
    check_event_hook_interceptor,  # B97 — per-turn event-hook interceptor in a skill (F-104)
    check_manifest_absent,  # B98 — undeclared privilege: risky effects, no tools manifest
    check_pth_persistence,  # B99 — .pth/sitecustomize auto-execution persistence (F-088)
    check_clickfix_setup_section,  # B100 — ClickFix paste-into-terminal + remote-fetch (F-090)
    check_config_trust_widening,  # B96 — config-driven trust widening, heuristic-only (F-100)
    check_install_directive_supply_chain,  # B103 — install[] supply-chain provenance (B-099)
)
