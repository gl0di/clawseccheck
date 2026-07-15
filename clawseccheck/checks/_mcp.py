"""Topic module: mcp checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from .. import attest as _attest
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
    Context,
    classify_bytes,
    dig,
)
from ..configloader import loads_json5
from ..textnorm import (
    normalize_for_scan,
    obfuscation_signals,
)

from ._shared import (
    SECRET_KEY_RE,
    _KNOWN_EXFIL_HOST_RE,
    _finding,
    _mcp_has_remote,
    _mcp_servers,
    _mcp_url_is_local,
    _plugins,
)
from ._content import (
    _IOC_ONION_RE,
    _obf_clip,
)
from ._vet import (
    _PLUGIN_MANIFEST,
    _VET_MERGE_RANK,
    _decoded_payloads,
    _locate_plugin_root,
    vet_skill,
)


# Packaging/metadata JSON that is never an embedded MCP server spec.
_PLUGIN_MCP_SKIP = frozenset(
    {
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        _PLUGIN_MANIFEST,
        "tsconfig.json",
        "jsconfig.json",
    }
)


# Directories never swept inside a plugin: third-party deps + VCS/cache noise. The
# node_modules exclusion is disclosed as a coverage note, not silently applied.
_PLUGIN_SKIP_DIRS = frozenset({"node_modules", ".git", "__pycache__"})


_PLUGIN_FILE_CAP = 400  # B-074: a cap hit is disclosed and downgrades to UNKNOWN


_PLUGIN_SNIFF_BYTES = 512

# B-165: plugin runtime JS/TS entry files get the same conservative lexical pass the
# skill vet already runs (analyze_javascript). Bounded per-file read so a minified bundle
# can't blow memory; a JS signal raises the plugin verdict to WARN (never FAIL — a
# minified-bundle false-positive must not force a FAIL), fixing the old false-clean PASS.
_PLUGIN_JS_EXT = (".js", ".mjs", ".cjs", ".ts")
_PLUGIN_JS_MAX_BYTES = 2_000_000


_VET_RANK_STATUS = {3: FAIL, 2: WARN, 1: UNKNOWN, 0: PASS}


def _plugin_finding(severity, status, detail, fix, ev=None) -> Finding:
    return Finding(
        "PLUGIN-VET",
        "Plugin pre-install vet",
        severity,
        status,
        detail,
        fix,
        "Plugin Trust",
        False,
        ev or [],
    )


def vet_plugin(path: str | Path) -> Finding:
    """Vet an OpenClaw plugin BEFORE installing it (container-dispatcher).

    Plugin-specific checks (manifest sanity, npm lifecycle scripts, dependency
    pinning, native-executable stowaways) run here; bundled skills are dispatched to
    vet_skill() — they land on the skill auto-load surface via the
    ~/.openclaw/plugin-skills symlink farm — and embedded MCP server specs to
    vet_mcp(). Plugin runtime JS/TS gets the same conservative *lexical* pass the skill
    vet runs (analyze_javascript: obfuscated-RCE / remote-fetch-then-eval and a couple of
    warn-level signals) — a JS signal raises the verdict to WARN so it is never a silent
    PASS (B-165). That pass is lexical, not a full runtime analysis (the residual D2 limit);
    the coverage note still says so, and it never forces a FAIL on its own.
    """
    import json as _json

    from ..skillast import analyze_javascript  # noqa: PLC0415

    p = Path(str(path)).expanduser()
    if not p.exists():
        return _plugin_finding(
            HIGH,
            UNKNOWN,
            f"no plugin found at {p}",
            f"Point --vet-plugin at a plugin root (a dir carrying {_PLUGIN_MANIFEST}).",
        )
    root = _locate_plugin_root(p)
    if root is None:
        return _plugin_finding(
            HIGH,
            UNKNOWN,
            f"not an OpenClaw plugin: no {_PLUGIN_MANIFEST} found under {p}",
            "A plugin root carries openclaw.plugin.json; for a skill directory use --vet.",
        )
    try:
        manifest = loads_json5(
            (root / _PLUGIN_MANIFEST).read_text(encoding="utf-8", errors="replace")
        )
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        # RecursionError (deeply-nested manifest) and MemoryError (huge manifest) are not
        # ValueError — without them a hostile manifest would abort the whole vet instead of
        # degrading to UNKNOWN, the graceful path every other bad manifest takes (C-135).
        return _plugin_finding(
            HIGH,
            UNKNOWN,
            f"could not parse {_PLUGIN_MANIFEST}: {type(exc).__name__}",
            "Inspect the manifest manually — the host would refuse this plugin too.",
        )
    if not isinstance(manifest, dict):
        return _plugin_finding(
            HIGH,
            UNKNOWN,
            f"{_PLUGIN_MANIFEST} is not a JSON object",
            "Inspect the manifest manually — the host would refuse this plugin too.",
        )

    warns: list[str] = []
    notes: list[str] = []  # coverage / informational evidence — never verdict-moving
    subs: list[Finding] = []  # dispatched engine findings (vet_skill / vet_mcp)
    js_signals: list[str] = []  # B-165: lexical JS/TS findings — raise the verdict to WARN

    # -- manifest sanity (required fields per recon §11.2; host blocks activation on error)
    pid = manifest.get("id")
    if not isinstance(pid, str) or not pid or not isinstance(manifest.get("configSchema"), dict):
        warns.append(
            "invalid manifest: required id/configSchema missing or wrong type — "
            "the host treats this as a plugin error and blocks activation"
        )
    pid = pid if isinstance(pid, str) and pid else root.name

    # -- npm packaging (recon §11.3/§11.4)
    pkg: dict = {}
    pkg_path = root / "package.json"
    if pkg_path.is_file():
        try:
            loaded = _json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            loaded = None
        if isinstance(loaded, dict):
            pkg = loaded
        else:
            warns.append("unreadable/unparseable package.json — npm packaging not assessed")
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    lifecycle = [k for k in ("preinstall", "install", "postinstall") if k in scripts]
    if lifecycle:
        warns.append(
            "npm lifecycle script(s) declared: "
            + ", ".join(lifecycle)
            + " — `openclaw plugins install` runs npm with --ignore-scripts, so "
            "these only ever execute for manual `npm install` victims"
        )
    deps = pkg.get("dependencies") if isinstance(pkg.get("dependencies"), dict) else {}
    # A missing lockfile is NOT a warn: bundled host extensions legitimately ship exact
    # pins with no per-plugin lockfile (verified on the 66-plugin real fleet — 21 would
    # have false-WARNed). Only *floating* version ranges are an actionable signal.
    if (
        deps
        and not (root / "npm-shrinkwrap.json").is_file()
        and not (root / "package-lock.json").is_file()
    ):
        notes.append(
            f"coverage: {len(deps)} runtime dependency(ies) without a lockfile "
            "in the package — transitive pins not verifiable here"
        )
    floating = sorted(
        f"{n}@{v}"
        for n, v in deps.items()
        if isinstance(v, str)
        and (v.strip().startswith(("^", "~", ">", "<", "*")) or v.strip() in ("latest", ""))
    )
    if floating:
        extra = f" (+{len(floating) - 4} more)" if len(floating) > 4 else ""
        warns.append("floating dependency version(s): " + ", ".join(floating[:4]) + extra)

    # -- coverage disclosure (D2): JS/TS runtime entry points are outside this vet's depth
    oc = pkg.get("openclaw") if isinstance(pkg.get("openclaw"), dict) else {}
    entries: list[str] = []
    for key in ("extensions", "runtimeExtensions"):
        val = oc.get(key)
        if isinstance(val, list):
            entries.extend(str(x) for x in val)
    if entries:
        notes.append(
            "coverage: plugin runtime JS/TS ("
            + ", ".join(entries[:3])
            + ") is lexically scanned for obfuscated-RCE / remote-eval signals only — not a "
            "full runtime analysis; still review the entry files before trusting"
        )
    notes.append("coverage: node_modules/ (third-party npm deps) excluded from the content scan")
    npm_spec = dig(pkg, "openclaw.install.npmSpec")
    if isinstance(npm_spec, str) and npm_spec and "@" not in npm_spec.lstrip("@"):
        notes.append(
            f"install spec is a bare package name ({npm_spec}) — resolves to latest at install time"
        )

    # -- bundled skills -> vet_skill (the plugin-skills auto-load surface, recon §11.1)
    skill_dirs: list[Path] = []
    try:
        root_res = root.resolve()
    except OSError:
        root_res = root
    skills_field = manifest.get("skills")
    if isinstance(skills_field, list):
        for entry in skills_field:
            d = root / str(entry)
            try:
                escaped = not d.resolve().is_relative_to(root_res)
            except OSError:
                escaped = True
            if escaped:
                warns.append(f"manifest skills entry escapes the plugin root: {str(entry)!r}")
                continue
            if not d.is_dir():
                notes.append(f"manifest skills entry not present in the package: {str(entry)!r}")
                continue
            if (d / "SKILL.md").is_file():
                skill_dirs.append(d)
            else:
                kids = [c for c in sorted(d.iterdir()) if c.is_dir() and not c.is_symlink()]
                skill_dirs.extend(kids if kids else [d])
    for sd in skill_dirs:
        try:
            sf = vet_skill(sd)
        except Exception:  # noqa: BLE001 — a dispatched engine must never break the vet
            warns.append(f"bundled skill {sd.name!r} could not be vetted")
            continue
        sf.detail = f"[bundled skill {sd.name!r}] {sf.detail}"
        subs.append(sf)

    # -- capped tree sweep (skips node_modules; symlinks never followed) for embedded
    #    MCP specs and native-executable stowaways outside the dispatched skill dirs
    truncated = False
    swept: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _PLUGIN_SKIP_DIRS)
        for fn in sorted(filenames):
            fp = Path(dirpath) / fn
            if fp.is_symlink():
                continue
            swept.append(fp)
            if len(swept) >= _PLUGIN_FILE_CAP:
                truncated = True
                break
        if truncated:
            break
    if truncated:
        notes.append(
            f"scan hit the {_PLUGIN_FILE_CAP}-file cap — files beyond the cap were NOT scanned"
        )

    def _under_skills(fp: Path) -> bool:
        return any(sd in fp.parents for sd in skill_dirs)

    for fp in swept:
        if _under_skills(fp):
            continue  # bundled-skill content already dispatched to vet_skill above
        if fp.suffix == ".json" and fp.name not in _PLUGIN_MCP_SKIP:
            try:
                data = _json.loads(fp.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                data = None
            servers = None
            if isinstance(data, dict):
                servers = (
                    data.get("mcpServers")
                    if isinstance(data.get("mcpServers"), dict)
                    else dig(data, "mcp.servers")
                )
            if isinstance(servers, dict) and servers:
                try:
                    mcp_findings = vet_mcp(fp)
                except Exception:  # noqa: BLE001 — a dispatched engine must never break the vet
                    mcp_findings = []
                for mf in mcp_findings:
                    mf.detail = f"[embedded MCP spec {fp.name}] {mf.detail}"
                    subs.append(mf)
        try:
            size = fp.stat().st_size
            with open(fp, "rb") as fh:
                head = fh.read(_PLUGIN_SNIFF_BYTES)
        except OSError:
            continue
        _cls, fmt = classify_bytes(head, size)
        if fmt in ("ELF", "PE", "class", "pyc", "wasm") or (fmt or "").startswith("Mach-O"):
            warns.append(
                "native executable bundled in the plugin (stowaway): "
                f"{fp.relative_to(root)} ({fmt})"
            )
        elif fp.suffix.lower() in _PLUGIN_JS_EXT:
            # B-165: same conservative lexical JS/TS pass as the skill vet. Bounded read so
            # a minified bundle can't blow memory; a signal raises the verdict to WARN (below),
            # never FAIL, so a false-positive can't force a FAIL.
            if size <= _PLUGIN_JS_MAX_BYTES:
                try:
                    src = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    src = None
                if src is not None:
                    rel = fp.relative_to(root)
                    for af in analyze_javascript(src, str(rel)):
                        js_signals.append(f"runtime JS/TS: {af.reason} ({rel}:{af.lineno})")
            else:
                notes.append(
                    f"coverage: runtime JS/TS '{fp.relative_to(root)}' exceeds the "
                    f"{_PLUGIN_JS_MAX_BYTES // 1_000_000}MB scan cap — not lexically scanned"
                )

    # -- verdict: same merge rank as the skill vet; UNKNOWN floor on a capped sweep
    sub_rank = max((_VET_MERGE_RANK.get(f.status, 0) for f in subs), default=0)
    # B-165: js_signals raise the floor to WARN (2), never FAIL — a lexical false-positive
    # on a minified bundle must not force a FAIL.
    rank = max(sub_rank, 2 if (warns or js_signals) else 0, 1 if truncated else 0)
    status = _VET_RANK_STATUS[rank]

    n_mcp = sum(1 for f in subs if f.id == "MCP-VET")
    summary = f"plugin '{pid}' ({len(skill_dirs)} bundled skill(s), {n_mcp} embedded MCP spec(s))"
    actionable = [f for f in subs if f.status in (FAIL, WARN, UNKNOWN)]
    evidence = warns + js_signals + [f"{f.status}: {f.detail}" for f in actionable] + notes

    if status == FAIL:
        worst = max(subs, key=lambda f: _VET_MERGE_RANK.get(f.status, 0))
        sev = CRITICAL if worst.severity == CRITICAL else HIGH
        finding = _plugin_finding(
            sev,
            FAIL,
            f"dangerous bundled content in {summary}: {worst.detail}",
            "Do NOT install this plugin. " + (worst.fix or "Review the flagged content."),
            evidence,
        )
    elif status == WARN:
        if warns:
            head_sig, label = warns[0], "supply-chain / packaging signals"
        elif js_signals:
            head_sig, label = js_signals[0], "runtime JS/TS signals"
        else:
            head_sig, label = actionable[0].detail, "bundled-content signals"
        finding = _plugin_finding(
            MEDIUM,
            WARN,
            f"{label} in {summary}: {head_sig}",
            "Review the flagged signals before installing; prefer pinned, shrinkwrapped, "
            "source-readable plugins.",
            evidence,
        )
    elif status == UNKNOWN:
        finding = _plugin_finding(
            HIGH,
            UNKNOWN,
            f"{summary}: content could not be fully assessed",
            "Review the undisclosed portion manually or re-run against the unpacked plugin.",
            evidence,
        )
    else:
        finding = _plugin_finding(
            LOW,
            PASS,
            f"{summary}: no manifest, packaging, or bundled-content signals",
            "Skim the JS/TS entry files anyway — this vet's JS pass is lexical, not a full runtime analysis.",
            evidence,
        )
    finding.ring_findings = actionable
    if warns:
        # Container-native signals (manifest sanity, npm lifecycle scripts, floating
        # dependency versions, skills-entry path escape, native-executable stowaways)
        # are folded straight into this PLUGIN-VET finding's own status/detail — they
        # never ride on a dispatched sub-finding, so ring_findings alone would silently
        # drop them from the risk dossier (B-149). Tag them for the Build axis the same
        # way vet_mcp() tags MCP-VET via axis_reasons; each item is always WARN-severity
        # (rank 2) regardless of whether a dispatched sub-finding pushed the overall
        # status further to FAIL.
        finding.axis_reasons = {"build": [[WARN, w] for w in warns]}
    return finding


# ---------- vet_mcp: supply-chain / trust vetting for MCP servers ----------
# Install-vector commands that are pipe-to-run dangerous (execute arbitrary code).
_VET_MCP_DANGEROUS_CMDS = frozenset({"curl", "wget", "bash", "sh", "iex", "powershell"})


# Package-runner commands where an unpinned spec is a pull-latest-each-run risk.
_VET_MCP_RUNNER_CMDS = frozenset({"npx", "npm", "uvx", "pnpm", "bunx"})


# Detect @latest or a package name with no @<version> pin.
# "@latest" explicit, OR a bare package name without any "@" version suffix.
_VET_MCP_UNPINNED_PKG_RE = re.compile(
    r"@latest"
    r"|^(?!-)[^@\s]+$",  # bare package name: no "@" at all (not a flag like -y)
    re.I,
)


# Broad oauth scopes that signal wide permissions.
_VET_MCP_BROAD_SCOPE_RE = re.compile(r"\*|all|admin|write|full", re.I)


# Capability-detection patterns applied to the full joined command+args string.
# Each pattern is (family_name, compiled_re).
_LP_CAP_FAMILIES: list[tuple[str, re.Pattern[str]]] = [
    (
        "shell",
        re.compile(
            r"\b(?:subprocess|popen|os\.system|execvp?e?|"
            r"bash|sh|cmd\.exe|powershell|iex)\b",
            re.I,
        ),
    ),
    (
        "network",
        re.compile(
            r"\b(?:requests?\.(?:get|post|put|delete|head|patch)|"
            r"urllib\.request|socket\.connect|fetch|"
            r"curl|wget|httpx|aiohttp)\b",
            re.I,
        ),
    ),
    (
        "file_write",
        re.compile(
            r'\bopen\s*\([^)]*["\']w["\']|'
            r"\b(?:write_text|write_bytes|fsync|shutil\.copy|shutil\.move)\b",
            re.I,
        ),
    ),
    (
        "env_read",
        re.compile(
            r"\bos\.environ\b|\bos\.getenv\b|\bgetenv\b",
            re.I,
        ),
    ),
    (
        "mcp",
        re.compile(
            r"@modelcontextprotocol/|mcp-server|mcp_server",
            re.I,
        ),
    ),
]


# A scope string that looks read-only (contains "read"/"view"/"list"/"get" but
# NOT "write"/"exec"/"admin"/"shell"/"network"/"full"/"all"/"*").
_LP_SCOPE_READONLY_RE = re.compile(r"\b(?:read|view|list|get|fetch|query|search)\b", re.I)


_LP_SCOPE_WRITE_RE = re.compile(
    r"\b(?:write|exec|admin|shell|network|full|all|post|put|delete|patch)\b"
    r"|\*",
    re.I,
)


def _lp_detect_caps(cmd_line: str) -> list[str]:
    """Return list of capability family names detected in *cmd_line*."""
    return [fam for fam, pat in _LP_CAP_FAMILIES if pat.search(cmd_line)]


def _vet_mcp_least_privilege(name: str, spec: dict) -> tuple[list[str], list[str]]:
    """F-007: MCP least-privilege cross-check (LP1 only).

    Returns (dangerous_reasons, suspicious_reasons).

    LP1: oauth.scope IS present AND appears read-only, but the command exercises
         elevated capabilities (shell/network/file_write) that the scope does not
         cover — under-declared scope.

    Grounding note (§4):
      - Absent oauth.scope is NORMAL for MCP servers (scope is optional, only
        needed for OAuth flows) — NO finding is emitted when scope is absent.
        The whole helper short-circuits to empty when oauth.scope is absent.
      - LP3 ("capable but no scope") is DROPPED: absent scope is the common case,
        not a least-privilege violation.  Emitting LP3 would flag every non-OAuth
        MCP server and cause massive false-positives.
      - LP2 (wildcard scope) is already covered by _VET_MCP_BROAD_SCOPE_RE in the
        existing oauth.scope block of _vet_mcp_server — not duplicated here.
      - LP4 (over-declared) is deferred — no grounded scope-vocab mapping exists.
    """
    dangerous: list[str] = []
    suspicious: list[str] = []

    if not isinstance(spec, dict):
        return dangerous, suspicious

    # Guard: only run LP cross-check when oauth.scope is explicitly declared.
    # Absent scope is normal for non-OAuth MCP servers — emit nothing.
    oauth = spec.get("oauth") or {}
    if not isinstance(oauth, dict):
        return dangerous, suspicious
    scope = str(oauth.get("scope") or "").strip()
    if not scope:
        return dangerous, suspicious

    # LP2 (broad/wildcard scope) is already handled by _VET_MCP_BROAD_SCOPE_RE
    # in _vet_mcp_server — do not double-report here.

    # LP1: scope IS present and looks read-only — check whether the command
    # exercises elevated capabilities that exceed a read-only grant.
    if not (_LP_SCOPE_READONLY_RE.search(scope) and not _LP_SCOPE_WRITE_RE.search(scope)):
        # Scope already has write/exec/network tokens, or is not recognisably
        # read-only — LP1 does not apply.
        return dangerous, suspicious

    # Build full command string for capability scanning.
    cmd = str(spec.get("command", ""))
    args = spec.get("args") or []
    if not isinstance(args, list):
        args = []
    full_cmd = " ".join([cmd] + [str(a) for a in args])

    caps = _lp_detect_caps(full_cmd)
    # Only flag elevated capabilities (shell/network/file_write).
    # env_read and mcp are low-risk relative to a read-only scope.
    elevated_caps = [c for c in caps if c in ("shell", "network", "file_write")]
    if elevated_caps:
        elevated_str = "/".join(elevated_caps)
        suspicious.append(
            f"{name}: oauth.scope='{scope}' appears read-only but command "
            f"exercises {elevated_str} capabilities — under-declared scope (LP1)"
        )

    return dangerous, suspicious


# TP1: hidden instructions in tool descriptions — keyword boosts signal danger.
_C038_HIDDEN_INSTR_RE = re.compile(
    r"(?:SYSTEM\s*:|IGNORE\s+PREVIOUS|OVERRIDE\s+(?:ALL\s+)?INSTRUCTIONS?|"
    r"<\|im_start\|>\s*system)",
    re.I,
)


# TP1: HTML comment / markdown comment hiding.
_C038_COMMENT_RE = re.compile(r"<!--.*?-->|\[//\]:\s*#\s*\(", re.DOTALL | re.I)


# TP1: data-URI embedding.
_C038_DATA_URI_RE = re.compile(r"data:[^;,]{0,40};base64,", re.I)


# TP3: imperative injection in param defaults or descriptions.
_C038_PARAM_INJECT_RE = re.compile(
    r"ignore\s+previous|<\|im_start\|>|"
    r"(?:curl|wget|nc|netcat|bash)\s+https?://|"
    r"https?://[^\s\"']{0,80}(?:\?|&)[^\s\"']{0,40}=",
    re.I,
)


def _vet_mcp_tool_poisoning(name: str, spec: dict) -> tuple[list[str], list[str]]:
    """C-038: MCP tool-poisoning TP1–TP3.

    Returns (dangerous_reasons, suspicious_reasons).

    TP2 is unconditional (server name is always available).
    TP1/TP3 run only when spec contains a 'tools' key (tool metadata present
    inline in the spec file — currently ungrounded for production configs;
    kept for future configs that may embed tool descriptions).
    """
    dangerous: list[str] = []
    suspicious: list[str] = []

    # ---- TP2: homoglyph / mixed-script / bidi-override in server NAME ----
    # The server name is a real field we can inspect offline.
    signals = obfuscation_signals(name)
    if signals:
        norm_name = normalize_for_scan(name)
        if norm_name != name:
            suspicious.append(
                f"{name}: server name contains obfuscation / homoglyph characters "
                f"({'; '.join(signals)}) — may impersonate a trusted server"
            )

    # ---- TP1 / TP3: tool metadata — only if embedded inline in the spec ----
    # (Grounding: not a standard field in openclaw.json; guard prevents FP.)
    tools = spec.get("tools")
    if not isinstance(tools, list):
        return dangerous, suspicious

    for tool in tools:
        if not isinstance(tool, dict):
            continue
        tool_name = str(tool.get("name", "<unnamed>"))
        description = str(tool.get("description", ""))
        norm_desc = normalize_for_scan(description)

        # TP1a: HTML/markdown comment hiding in description.
        if _C038_COMMENT_RE.search(description):
            dangerous.append(
                f"{name}/{tool_name}: tool description contains hidden comment "
                "(HTML/markdown comment block — potential hidden instruction)"
            )

        # TP1b: data-URI in description.
        if _C038_DATA_URI_RE.search(description):
            dangerous.append(
                f"{name}/{tool_name}: tool description contains data-URI "
                "(potential base64-encoded hidden payload)"
            )

        # TP1c: base64 blobs that decode to shell/download payloads.
        b64_hits = _decoded_payloads(description)
        for hit in b64_hits[:2]:
            dangerous.append(
                f"{name}/{tool_name}: tool description base64 blob decodes to "
                f"shell/download payload: {hit[:60]}"
            )

        # TP1d: keyword-boost injection phrases in normalized description.
        if _C038_HIDDEN_INSTR_RE.search(norm_desc):
            dangerous.append(
                f"{name}/{tool_name}: tool description contains injection keyword "
                f"(SYSTEM:/IGNORE PREVIOUS/OVERRIDE — prompt injection risk)"
            )

        # TP3: injection in parameter descriptions / defaults.
        input_schema = tool.get("inputSchema") or {}
        if isinstance(input_schema, dict):
            props = input_schema.get("properties") or {}
            if isinstance(props, dict):
                for param_name, param_def in props.items():
                    if not isinstance(param_def, dict):
                        continue
                    param_desc = str(param_def.get("description", ""))
                    param_default = str(param_def.get("default", ""))
                    for text, label in ((param_desc, "description"), (param_default, "default")):
                        if _C038_PARAM_INJECT_RE.search(normalize_for_scan(text)):
                            dangerous.append(
                                f"{name}/{tool_name}: parameter '{param_name}' "
                                f"{label} contains injection directive or exfil URL"
                            )
                            break

    return dangerous, suspicious


def _vet_mcp_server(name: str, spec: dict) -> tuple[list[str], list[str]]:
    """Return (dangerous_reasons, suspicious_reasons) for one MCP server spec.

    Grounded on real MCP fields: command, args, env, transport, url, oauth.scope.
    Reuses _mcp_server_risks for existing B24 signals and adds supply-chain signals.
    """
    dangerous: list[str] = []
    suspicious: list[str] = []

    if not isinstance(spec, dict):
        return dangerous, suspicious

    # ---- Re-use existing B24 risk signals ----
    b24_fails, b24_warns = _mcp_server_risks(name, spec)
    # Demote b24 FAIL env-wildcard / tokenPassthrough to dangerous; warns to suspicious.
    dangerous.extend(b24_fails)
    suspicious.extend(b24_warns)

    cmd = str(spec.get("command", "")).strip().lower()
    # Strip path components to get just the binary name.
    cmd_base = cmd.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    args = spec.get("args") or []
    if not isinstance(args, list):
        args = []
    args_strs = [str(a) for a in args]

    # ---- Install vector: pipe-to-run ----
    if cmd_base in _VET_MCP_DANGEROUS_CMDS:
        dangerous.append(
            f"{name}: command '{cmd_base}' is a pipe-to-run install vector "
            "(executes arbitrary code directly)"
        )

    # ---- Install vector: package runner with unpinned spec ----
    if cmd_base in _VET_MCP_RUNNER_CMDS:
        # Look at non-flag args for a package spec that has no pinned version.
        pkg_args = [a for a in args_strs if not a.startswith("-")]
        for arg in pkg_args:
            if _VET_MCP_UNPINNED_PKG_RE.search(arg):
                suspicious.append(
                    f"{name}: '{cmd_base} {arg}' is unpinned — pulls latest each run "
                    "(supply-chain risk)"
                )
                break  # one signal per server is enough

    # ---- Transport / URL: remote trust surface ----
    url = str(spec.get("url") or spec.get("endpoint") or "")
    transport = str(spec.get("transport") or "")
    is_remote_transport = transport.lower() in ("streamable-http", "sse")

    if url.startswith("http://") and not _mcp_url_is_local(url):
        dangerous.append(
            f"{name}: url uses plaintext HTTP ({url[:60]}) — credentials/data sent in clear"
        )
    elif url and not url.startswith("http"):
        # Non-HTTP URL present — note it as suspicious (unknown scheme).
        suspicious.append(f"{name}: url uses non-HTTPS scheme ({url[:60]})")

    # Remote transport or non-loopback URL -> note enlarged trust surface.
    # (Already handled in b24_warns for remote https without allowedHosts; avoid duplicate.)
    if is_remote_transport and not url:
        suspicious.append(
            f"{name}: transport='{transport}' is a remote/streaming transport "
            "(larger trust surface than stdio)"
        )

    # ---- Secret exposure via env ----
    env = spec.get("env") or {}
    if isinstance(env, dict):
        secret_keys = [k for k in env if SECRET_KEY_RE.search(str(k)) and str(k) != "*"]
        wildcard_keys = [k for k in env if str(k) == "*" or str(env[k]) == "*"]
        if wildcard_keys:
            # Already caught by b24_fails but add a clearer vet message if not already there.
            if not any("passthrough" in r.lower() or "wildcard" in r.lower() for r in dangerous):
                dangerous.append(
                    f"{name}: env contains wildcard passthrough — ALL env vars "
                    "(including host secrets) forwarded to MCP server"
                )
        elif len(secret_keys) >= 3:
            # Many secret-like keys: broad passthrough.
            suspicious.append(
                f"{name}: env forwards {len(secret_keys)} secret-like vars "
                f"({', '.join(secret_keys[:3])}…) — server receives your secrets"
            )
    elif env == "*":
        if not any("passthrough" in r.lower() or "wildcard" in r.lower() for r in dangerous):
            dangerous.append(f"{name}: env='*' — ALL env vars forwarded to MCP server")

    # ---- oauth.scope wildcard / broad ----
    oauth = spec.get("oauth") or {}
    if isinstance(oauth, dict):
        scope = str(oauth.get("scope") or "")
        if scope and _VET_MCP_BROAD_SCOPE_RE.search(scope):
            suspicious.append(
                f"{name}: oauth.scope='{scope}' is broad/wildcard — server has wide permissions"
            )

    # ---- C-038 TP1–TP3: MCP tool-poisoning ----
    tp_dangerous, tp_suspicious = _vet_mcp_tool_poisoning(name, spec)
    dangerous.extend(tp_dangerous)
    suspicious.extend(tp_suspicious)

    # ---- F-007: least-privilege cross-check (LP1 / LP3) ----
    lp_dangerous, lp_suspicious = _vet_mcp_least_privilege(name, spec)
    dangerous.extend(lp_dangerous)
    suspicious.extend(lp_suspicious)

    return dangerous, suspicious


# Route one MCP vet reason to a risk-dossier axis by its wording. Conservative: an
# unclassifiable reason falls back by severity at the caller (dangerous→danger,
# suspicious→build), so a signal is never dropped or silently downgraded.
_MCP_AXIS_CONNECTIONS = (
    "plaintext http", "non-https", "url uses", "transport=", "remote/streaming",
    "passthrough", "wildcard", "secret-like", "forwards", "receives your secrets",
    "sent in clear", "larger trust surface",
)


_MCP_AXIS_BEHAVIOR = (
    "injection directive", "exfil", "tool-poisoning", "poison", "tool description",
    "tool name", "tool '",
)


_MCP_AXIS_BUILD = (
    "unpinned", "@latest", "supply-chain", "oauth.scope", "least-privilege",
    "broad/wildcard", "wide permissions", "read-only",
)


def _mcp_reason_axis(reason: str) -> str | None:
    """Best-effort axis for one MCP vet reason; None → let the caller default by severity."""
    r = reason.lower()
    if "pipe-to-run" in r or "pipe-to-shell" in r:
        return "danger"
    if any(k in r for k in _MCP_AXIS_CONNECTIONS):
        return "connections"
    if any(k in r for k in _MCP_AXIS_BEHAVIOR):
        return "behavior"
    if any(k in r for k in _MCP_AXIS_BUILD):
        return "build"
    return None


def _load_mcp_spec_file(path: Path) -> dict[str, dict] | None:
    """Load a JSON file and normalise to {name: spec}.

    Accepts:
      - A single server spec dict  -> {"<filename stem>": spec}
      - A {name: spec} map         -> as-is (if all values are dicts)
      - A full config with mcp.servers  -> extracted servers dict

    Returns None if the file cannot be parsed as any of those shapes.
    """
    import json as _json

    try:
        data = _json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    # Full config: mcp.servers.<name>
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        servers = mcp.get("servers")
        if isinstance(servers, dict) and servers:
            return servers

    # mcpServers top-level (common alternative key)
    mcp_servers = data.get("mcpServers")
    if isinstance(mcp_servers, dict) and mcp_servers:
        return mcp_servers

    # Single server spec: top-level contains "command", "url", or "transport"
    # (these are MCP server spec fields, not wrapper keys).
    if "command" in data or ("url" in data and "transport" in data):
        stem = path.stem
        return {stem: data}

    # {name: spec} map: all values must be dicts
    if data and all(isinstance(v, dict) for v in data.values()):
        return data

    return None


def vet_mcp(target: str | Path | None = None, home: str | Path = "~/.openclaw") -> list[Finding]:
    """Vet MCP servers for supply-chain / trust risk BEFORE trusting them.

    Args:
        target: one of —
            None         -> vet ALL servers from the config at *home*.
            str/Path     -> if it points to an existing file: load as a JSON
                           spec (single server, {name:spec} map, or full config).
                           Otherwise treat as a server NAME and vet that one
                           server from the config at *home*.
        home: path to the OpenClaw home dir (default: ~/.openclaw).

    Returns a list of Finding objects — one per server — using a synthetic
    "MCP-VET" id (not a scored audit check). Each Finding's status is:
        PASS       — no supply-chain / trust signals detected.
        WARN       — suspicious signals (e.g. unpinned package, remote transport).
        FAIL       — dangerous signals (e.g. pipe-to-run, plaintext HTTP, wildcard env).
        UNKNOWN    — spec could not be parsed.
    """
    # Resolve servers to vet.
    servers: dict[str, dict] = {}

    if target is not None:
        p = Path(str(target)).expanduser()
        if p.is_file():
            loaded = _load_mcp_spec_file(p)
            if loaded is None:
                return [
                    Finding(
                        id="MCP-VET",
                        title="MCP supply-chain / trust vet",
                        severity=HIGH,
                        status=UNKNOWN,
                        detail=f"Could not parse '{p}' as a valid MCP server spec or config.",
                        fix="Provide a JSON file containing a server spec, a {name:spec} map, "
                        "or a full config with mcp.servers.",
                        framework="MCP Trust",
                        scored=False,
                    )
                ]
            servers = loaded
        else:
            # Treat target as a server name — load from config.
            name = str(target)
            home_path = Path(str(home)).expanduser()
            cfg_file = home_path / "openclaw.json"
            import json as _json

            try:
                cfg = _json.loads(cfg_file.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                cfg = {}
            all_servers = _mcp_servers(cfg)
            if name in all_servers:
                servers = {name: all_servers[name]}
            else:
                return [
                    Finding(
                        id="MCP-VET",
                        title="MCP supply-chain / trust vet",
                        severity=HIGH,
                        status=UNKNOWN,
                        detail=f"Server '{name}' not found in config at {cfg_file}.",
                        fix="Check the server name or point --vet-mcp at a JSON file.",
                        framework="MCP Trust",
                        scored=False,
                    )
                ]
    else:
        # Vet all servers from config at home.
        home_path = Path(str(home)).expanduser()
        cfg_file = home_path / "openclaw.json"
        import json as _json

        try:
            cfg = _json.loads(cfg_file.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            cfg = {}
        servers = _mcp_servers(cfg)

    if not servers:
        return [
            Finding(
                id="MCP-VET",
                title="MCP supply-chain / trust vet",
                severity=HIGH,
                status=UNKNOWN,
                detail="No MCP servers configured.",
                fix="Configure MCP servers under mcp.servers.<name> in openclaw.json.",
                framework="MCP Trust",
                scored=False,
            )
        ]

    findings: list[Finding] = []
    for sname, spec in servers.items():
        dangerous, suspicious = _vet_mcp_server(sname, spec)

        if dangerous:
            status = FAIL
            all_reasons = dangerous + suspicious
            fix = (
                "Do NOT trust this server until you have reviewed its source. "
                "Remove pipe-to-run commands (curl/wget/bash/sh), switch to HTTPS, "
                "eliminate wildcard env passthrough, and pin package specs to exact versions."
            )
        elif suspicious:
            status = WARN
            all_reasons = suspicious
            fix = (
                "Review before trusting: pin package specs to exact versions "
                "(avoid @latest / bare package names), prefer stdio transport over "
                "remote/SSE, and minimise secret env var exposure."
            )
        else:
            status = PASS
            all_reasons = []
            fix = "No supply-chain signals detected — keep specs pinned and env vars minimal."

        # Reasons are collected with a "<sname>: " prefix; strip it so the server name
        # appears once (as the finding title), not repeated on every line.
        _pfx = f"{sname}: "
        clean = [r[len(_pfx) :] if r.startswith(_pfx) else r for r in all_reasons[:6]]
        more = f" (+{len(all_reasons) - 6} more)" if len(all_reasons) > 6 else ""
        detail = ("; ".join(clean) + more) if clean else "no supply-chain / trust risks detected"
        # Split the reasons across risk-dossier axes with their own severity, so the
        # dossier can show (e.g.) an unpinned spec under Build and a wildcard-env under
        # Connections rather than lumping everything under Danger. {axis: [[status, text]]}.
        axis_reasons: dict[str, list] = {}
        for reason_status, reasons in ((FAIL, dangerous), (WARN, suspicious)):
            for r in reasons:
                disp = r[len(_pfx) :] if r.startswith(_pfx) else r
                axis = _mcp_reason_axis(r) or ("danger" if reason_status == FAIL else "build")
                axis_reasons.setdefault(axis, []).append([reason_status, disp])
        findings.append(
            Finding(
                id="MCP-VET",
                title=sname,
                severity=HIGH,
                status=status,
                detail=detail,
                fix=fix,
                framework="MCP Trust",
                scored=False,
                evidence=clean,
                axis_reasons=axis_reasons,
            )
        )

    return findings


def _mcp_has_tool_restrictions(spec: dict) -> bool:
    tools = spec.get("tools")
    return isinstance(tools, list) and len(tools) > 0


def check_mcp(ctx: Context) -> Finding:
    servers = _mcp_servers(ctx.config)
    if not servers:
        return _finding("B15", UNKNOWN, "No MCP servers configured.", "—")
    names = ", ".join(list(servers)[:5])
    n = len(servers)
    if all(_mcp_has_tool_restrictions(spec) for spec in servers.values()):
        return _finding(
            "B15",
            PASS,
            f"{n} MCP server(s) configured ({names}). "
            "All servers have explicit tool allowlists configured.",
            "Keep per-server tool allowlists tight and review them after updates.",
        )
    # Frame by transport so a local stdio server isn't described as a "remote" risk (C-057).
    if any(_mcp_has_remote(spec) for spec in servers.values()):
        return _finding(
            "B15",
            WARN,
            f"{n} MCP server(s) configured ({names}). "
            "Remote MCP servers can carry prompt injection, SSRF and data exposure.",
            "Verify each MCP server's source and trust boundary, restrict its tool "
            "reachability, and avoid untrusted remote MCP endpoints.",
        )
    return _finding(
        "B15",
        WARN,
        f"{n} MCP server(s) configured ({names}). "
        "Local (stdio) MCP servers run as subprocesses with the agent's "
        "privileges; a malicious or compromised server can read local data and "
        "act through the agent's tools.",
        "Verify each MCP server's source and trust boundary, pin its "
        "package/command to a known version, and restrict its tool reachability.",
    )


# B-159: flags that legitimately take a URL as a registry/index config value,
# not a package spec — a URL immediately after one of these is not unpinned-
# package evidence. `pip install --registry https://... some-pkg==1.2.3` (or
# `npx --registry=... pkg@1.2.3`) commonly points at a private mirror while
# still pinning the package itself.
_MCP_SAFE_URL_FLAGS = (
    "--registry", "--index-url", "-i", "--extra-index-url",
    "--find-links", "-f", "--proxy", "--trusted-host",
)
_MCP_SAFE_URL_LOOKBEHIND = "".join(
    rf"(?<!{re.escape(flag)} )(?<!{re.escape(flag)}=)" for flag in _MCP_SAFE_URL_FLAGS
)

# ---------- B24: MCP server hardening ----------
# Unpinned / dangerous install specs for stdio commands.
_MCP_UNPINNED_RE = re.compile(
    r"(?:npx|pip(?:x)?|uvx)\b[^\n]*?"  # npx / pip / pipx / uvx prefix
    r"(?:"
    r"@latest"  # explicit @latest tag
    rf"|{_MCP_SAFE_URL_LOOKBEHIND}https?://"  # URL argument (not a known safe registry/index flag value)
    r"|(?<![a-zA-Z0-9._-])(?!@[0-9])@(?![0-9])[a-zA-Z]"  # @scope but not pinned @1.2.3
    r")",
    re.I,
)


_MCP_CURL_RE = re.compile(r"\bcurl\b[^\n]*?https?://", re.I)


# B-150: downloader piped straight into a shell interpreter — e.g.
# `curl http://x | bash`, `wget -qO- http://x | sh`, `curl ... | sudo bash`.
# This is the unambiguous "pipe-to-run" shape (distinct from a bare curl/wget
# fetch with no pipe, which stays a WARN via _MCP_CURL_RE above).
_MCP_PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget|invoke-webrequest|iwr)\b[^|\n]*\|\s*(?:sudo\s+)?"
    r"(?:bash|sh|zsh|dash|ksh|powershell|pwsh)\b",
    re.I,
)

# B-150: PowerShell IEX/Invoke-Expression executing content pulled from the
# network in the same expression (the Windows equivalent of pipe-to-run).
_MCP_IEX_DOWNLOAD_RE = re.compile(
    r"(?:iex|invoke-expression)\s*\(?[^\n]*?"
    r"(?:net\.webclient|downloadstring|invoke-webrequest|iwr\b)",
    re.I,
)


# Broad secret env vars.
_MCP_SECRET_ENV_RE = re.compile(
    r"^(OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_[A-Z_]+|AZURE_[A-Z_]+|GCP_[A-Z_]+|"
    r"GOOGLE_[A-Z_]*(?:API_)?KEY|GITHUB_TOKEN|GITLAB_TOKEN|SECRET[_A-Z]*|"
    r"API_KEY[_A-Z]*|TOKEN[_A-Z]*)$",
    re.I,
)


# Metadata / internal IPs in allowedHosts.
_MCP_META_IP_RE = re.compile(
    r"^(?:"
    r"169\.254\.\d+\.\d+"  # link-local / AWS metadata
    r"|10\.\d+\.\d+\.\d+"  # RFC-1918 /8
    r"|192\.168\.\d+\.\d+"  # RFC-1918 /16
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"  # RFC-1918 /12
    r"|localhost|127\.\d+\.\d+\.\d+"  # loopback
    r"|::1"  # IPv6 loopback
    r")$",
    re.I,
)


def _mcp_server_risks(name: str, spec: dict) -> tuple[list[str], list[str]]:
    """Return (fail_reasons, warn_reasons) for one MCP server spec dict.

    Conservative: FAIL only on unambiguous positive evidence of a known-risky
    pattern; WARN for likely-insecure defaults that may be intentional.
    """
    fails: list[str] = []
    warns: list[str] = []

    if not isinstance(spec, dict):
        return fails, warns

    # ---- stdio command using npx/pip/curl with URL or @latest/unpinned spec ----
    cmd = spec.get("command", "")
    args = spec.get("args") or []
    if isinstance(args, list):
        full_cmd = " ".join([str(cmd)] + [str(a) for a in args])
    else:
        full_cmd = str(cmd)

    # B-073: detection runs on the raw command, but the string echoed into evidence
    # is host-only-sanitized so a credential embedded in a URL arg
    # (e.g. npx --registry https://TOKEN@reg/pkg) never reaches the report (§8).
    from ..logsafe import redact_urls_in_text  # noqa: PLC0415
    safe_cmd = redact_urls_in_text(full_cmd)[:80]
    if _MCP_UNPINNED_RE.search(full_cmd):
        warns.append(f"{name}: stdio command uses unpinned/URL spec ({safe_cmd})")
    if _MCP_CURL_RE.search(full_cmd):
        warns.append(f"{name}: stdio command uses curl with URL ({safe_cmd})")

    # B-150: unambiguous pipe-to-run install vector — a downloader (curl/wget/
    # Invoke-WebRequest) piped straight into a shell interpreter, or a
    # PowerShell IEX/Invoke-Expression executing downloaded content. This is
    # deliberately narrower than raw command-base membership in
    # _VET_MCP_DANGEROUS_CMDS (which --vet-mcp uses for its own, intentionally
    # stricter, "is the binary itself risky" signal): B24 stays conservative
    # (per its docstring, FAIL only on unambiguous positive evidence), so a
    # bare `curl <url>` with no pipe into a shell stays a WARN above, not a
    # FAIL — only the actual pipe-to-shell/IEX shape escalates.
    if _MCP_PIPE_TO_SHELL_RE.search(full_cmd) or _MCP_IEX_DOWNLOAD_RE.search(full_cmd):
        fails.append(
            f"{name}: command pipes a remote download directly into a shell "
            f"interpreter (pipe-to-run install vector) ({safe_cmd})"
        )

    # ---- env passthrough ----
    env = spec.get("env") or {}
    if isinstance(env, dict):
        for key, val in env.items():
            if key == "*" or val == "*":
                fails.append(f"{name}: env passthrough '*' (all env vars exposed)")
                break
            if _MCP_SECRET_ENV_RE.match(str(key)):
                warns.append(f"{name}: env passes broad secret var {key}")
    elif env == "*":
        fails.append(f"{name}: env passthrough '*' (all env vars exposed)")

    # ---- tokenPassthrough / token-passthrough ----
    if spec.get("tokenPassthrough") is True or spec.get("token-passthrough") is True:
        fails.append(f"{name}: tokenPassthrough=true (host token forwarded to MCP server)")

    # ---- allowedHosts ----
    allowed_hosts = spec.get("allowedHosts") or []
    if isinstance(allowed_hosts, list):
        for host in allowed_hosts:
            h = str(host)
            if h == "*":
                fails.append(f"{name}: allowedHosts contains '*' (unrestricted SSRF surface)")
                break
            if _MCP_META_IP_RE.match(h):
                fails.append(f"{name}: allowedHosts contains internal/metadata IP {h}")
                break
    elif isinstance(allowed_hosts, str) and allowed_hosts == "*":
        fails.append(f"{name}: allowedHosts='*' (unrestricted SSRF surface)")

    # ---- remote https URL with no allowlist ----
    url = spec.get("url") or spec.get("endpoint") or ""
    if isinstance(url, str) and url.startswith("https://"):
        # Only flag when there is no allowedHosts restriction configured at all
        if not allowed_hosts:
            # B-162: reduce to scheme://host — a url/endpoint can carry a token in
            # userinfo/path/query (https://user:TOKEN@host/...?api_key=...); the raw
            # value must never round-trip into evidence (§8, mirrors C047 below).
            from ..logsafe import sanitize_url_host_only  # noqa: PLC0415
            warns.append(
                f"{name}: remote MCP endpoint {sanitize_url_host_only(url)} "
                "with no allowedHosts restriction"
            )

    return fails, warns


def check_mcp_hardening(ctx: Context) -> Finding:
    """B24 — MCP server hardening.

    Inspects each configured MCP server spec for positive evidence of risky
    patterns. FAIL only on unambiguous danger signals; WARN for likely-insecure
    defaults; PASS when servers exist but none trigger; UNKNOWN when no MCP.
    """
    servers = _mcp_servers(ctx.config)
    if not servers:
        return _finding("B24", UNKNOWN, "No MCP servers configured.", "—")

    all_fails: list[str] = []
    all_warns: list[str] = []
    for name, spec in servers.items():
        f, w = _mcp_server_risks(name, spec)
        all_fails.extend(f)
        all_warns.extend(w)

    n = len(servers)
    names_preview = ", ".join(list(servers)[:5])

    # Detail is a summary only; the per-server specifics go in evidence so the renderer
    # does not print the same line twice (in the "why" and again as a bullet) — C-057.
    if all_fails:
        ev = all_fails[:6]
        if len(all_fails) > 6:
            ev = ev + [f"(+{len(all_fails) - 6} more issue(s) not shown)"]
        return _finding(
            "B24",
            FAIL,
            f"{n} MCP server(s) ({names_preview}) have dangerous hardening issues — see evidence.",
            "Remove wildcard env passthrough, disable tokenPassthrough, restrict "
            "allowedHosts to specific safe hosts, and pin MCP package specs to "
            "exact versions.",
            evidence=ev,
        )

    if all_warns:
        ev = all_warns[:6]
        if len(all_warns) > 6:
            ev = ev + [f"(+{len(all_warns) - 6} more issue(s) not shown)"]
        return _finding(
            "B24",
            WARN,
            f"{n} MCP server(s) ({names_preview}) have likely-insecure settings — see evidence.",
            "Pin MCP package specs to exact versions (avoid @latest/URLs), restrict "
            "allowedHosts to known-safe hosts, and avoid forwarding broad secret env vars.",
            evidence=ev,
        )

    return _finding(
        "B24",
        PASS,
        f"{n} MCP server(s) configured ({names_preview}); no hardening issues detected.",
        "Keep MCP server specs pinned, env vars minimal, and allowedHosts restricted.",
    )


def check_mcp_external_endpoint(ctx: Context) -> Finding:
    """C047 — advisory UNKNOWN for non-local MCP server URLs.

    A remote MCP endpoint can act as an exfiltration sink, but config alone cannot
    prove whether it is legitimate or attacker-controlled. This is UNKNOWN-only on
    non-local URLs and PASS when MCP is absent or limited to local/stdio endpoints.
    """
    servers = _mcp_servers(ctx.config)
    external = []
    # B-073: keep only scheme://host of the endpoint in evidence — userinfo, path,
    # and query can each carry a token (https://user:token@host/mcp/<token>?key=...) (§8).
    from ..logsafe import sanitize_url_host_only  # noqa: PLC0415
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        url = spec.get("url") or spec.get("endpoint")
        if not isinstance(url, str) or not url.strip():
            continue
        if _mcp_url_is_local(url):
            continue
        external.append(f"{name}: non-local MCP URL {_obf_clip(sanitize_url_host_only(url.strip()))}")

    if external:
        return _finding(
            "C047",
            UNKNOWN,
            "Non-local MCP server endpoint(s) require manual review: " + "; ".join(external[:4]),
            "Review each non-local MCP server URL, confirm the owner and trust boundary, "
            "and prefer localhost/stdio or a Unix socket when a remote endpoint is not required.",
            external,
        )
    return _finding(
        "C047",
        PASS,
        "No non-local MCP server URLs detected.",
        "Keep MCP endpoints local where possible and review any future remote URLs before enabling them.",
    )


def check_mcp_server_exfil_host_in_args(ctx: Context) -> Finding:
    """B166 (C-211) — a known paste/exfiltration host (webhook.site, ngrok, pastebin,
    *.onion, ...) referenced in an MCP server's own `command`/`args` — the server's
    identity-level startup config itself names an untrusted drop point, before the
    server is ever run. Distinct from C047 (a non-local `url`/`endpoint` MCP transport,
    which is dual-use and only UNKNOWN) — this is a stronger, unambiguous host list
    matched against the server's own launch arguments, so it's WARN.

    Grounded against the real OASB registry corpus (v2.0, 2988 benign / 166 malicious
    `mcp_tool` samples): 0 benign false positives, narrow recall (catches 1/166) — a
    precision-first, low-yield signal. Advisory (never scored, never escalates to FAIL):
    a config-level string match in a server's own args cannot prove malicious intent on
    its own, only that it names a known drop point.
    """
    servers = _mcp_servers(ctx.config)
    if not servers:
        return _finding(
            "B166",
            UNKNOWN,
            "No MCP servers configured.",
            "Configure MCP servers to evaluate their command/args for known exfiltration hosts.",
        )
    hits: list[str] = []
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        cmd = str(spec.get("command") or "")
        raw_args = spec.get("args")
        args = raw_args if isinstance(raw_args, list) else []
        joined = " ".join([cmd, *(str(a) for a in args)])
        m = _KNOWN_EXFIL_HOST_RE.search(joined)
        onion = _IOC_ONION_RE.search(joined) if not m else None
        hit = m or onion
        if hit:
            hits.append(f"{name}: command/args reference known exfiltration host '{hit.group(0)}'")

    if hits:
        return _finding(
            "B166",
            WARN,
            "MCP server command/args reference a known paste/exfiltration host: "
            + "; ".join(hits[:4]),
            "Review the flagged MCP server's own startup command/args before enabling it — "
            "a known paste/exfil host named in its OWN launch arguments (not just runtime "
            "traffic) is a strong signal the server is designed to exfiltrate data.",
            hits,
        )
    return _finding(
        "B166",
        PASS,
        "No MCP server command/args reference a known paste/exfiltration host.",
        "Keep MCP server startup command/args free of paste/exfiltration-host references.",
    )


def check_plugin_permission_mode(ctx: Context) -> Finding:
    """B57 (NC-8) — plugin permissionMode=approve-all.

    Grounded (docs.openclaw.ai/gateway/security): plugins "run in-process with the
    Gateway — treat them as trusted code", and `plugins.entries.<name>.config.permissionMode
    = approve-all` is an audit-tracked dangerous flag that auto-approves every plugin
    permission prompt, removing the last gate before trusted-code actions.

    UNKNOWN — no plugins installed (plugins.entries absent).
    FAIL    — any installed plugin sets config.permissionMode == "approve-all".
    PASS    — no plugin uses approve-all.
    """
    cfg = ctx.config
    plugins = _plugins(cfg)
    if not plugins:
        return _finding(
            "B57",
            UNKNOWN,
            "No plugins are installed (plugins.entries absent), so plugin permission "
            "modes are not applicable.",
            "When you install plugins, set each plugins.entries.<name>.config.permissionMode "
            "to 'ask' (never 'approve-all').",
        )
    offenders = []
    for name, entry in plugins.items():
        if not isinstance(entry, dict):
            continue
        if dig(entry, "config.permissionMode") == "approve-all":
            offenders.append(
                f"plugins.entries.{name}.config.permissionMode=approve-all — auto-approves "
                "every plugin permission prompt (plugins run in-process as trusted code)"
            )
    if offenders:
        return _finding(
            "B57",
            FAIL,
            "One or more installed plugins set config.permissionMode=approve-all, "
            "auto-approving every plugin permission prompt (plugins run in-process as "
            "trusted code, so this removes the last gate).",
            "Set permissionMode to 'ask' for the listed plugin(s) so each privileged "
            "action is confirmed.",
            evidence=offenders,
        )
    return _finding(
        "B57",
        PASS,
        "No installed plugin sets config.permissionMode=approve-all.",
        "Keep plugin permissionMode at 'ask'.",
    )


def check_mcp_tool_inheritance(ctx: Context) -> Finding:
    """B75 — MCP tool-inheritance bypass check (attestation-based).

    Grounded on GitHub issue #63399: globally-registered mcp.servers tools were
    auto-injected into ALL agents, bypassing per-agent tools.allow/deny filters.
    A narrow-role agent still receives every MCP tool namespace.

    UNKNOWN — no attestation provided (config alone cannot prove per-agent MCP reach).
    WARN    — one or more attested agents hold MCP-namespaced tools that leak past
              the per-agent filter (evidence: agent name + tool count).
    PASS    — attestation present but no agent shows unexpected MCP tool bleed.

    Advisory (scored=False): never FAILs — WARN only, consistent with §5.
    """
    agents = _attest.attested_agents(ctx.attestation)
    if not agents:
        # No attestation -> cannot determine per-agent MCP reachability.
        return _finding(
            "B75",
            UNKNOWN,
            "No attestation provided — cannot determine whether MCP tools bypass "
            "per-agent tool filters at runtime (GitHub issue #63399).",
            "Run with --attest and include each agent's real tool list. "
            "MCP tools may be accessible to all agents regardless of per-agent "
            "tools.allow/deny configuration.",
        )

    mcp_servers = _mcp_servers(ctx.config)
    has_mcp = bool(mcp_servers)

    bleed_ev: list[str] = []
    for agent in agents:
        name = agent["name"]
        tools = agent["tools"]
        # MCP tools are namespaced: mcp__server__verb or server__verb (double underscore)
        mcp_tools = [t for t in tools if "__" in t]
        if mcp_tools:
            count = len(mcp_tools)
            sample = ", ".join(mcp_tools[:3])
            extra = f" (+{count - 3} more)" if count > 3 else ""
            bleed_ev.append(f"agent '{name}' holds {count} MCP-namespaced tool(s): {sample}{extra}")

    if bleed_ev and has_mcp:
        ev_summary = "; ".join(bleed_ev[:3])
        extra = f" (+{len(bleed_ev) - 3} more)" if len(bleed_ev) > 3 else ""
        return _finding(
            "B75",
            WARN,
            "MCP tools appear accessible to named agents despite per-agent tool "
            "filters — consistent with OpenClaw issue #63399 (MCP bypass): " + ev_summary + extra,
            "Verify each agent's effective tool list with 'openclaw tools list --agent <name>'. "
            "Until issue #63399 is resolved, treat every named agent as having access to all "
            "registered MCP tools and apply compensating controls (least-privilege roles, "
            "sandbox.tools restrictions).",
            bleed_ev,
        )

    return _finding(
        "B75",
        PASS,
        "Attested agents do not show unexpected MCP-namespaced tools, or no MCP "
        "servers are configured.",
        "Keep per-agent tool inventories minimal. Re-run after adding MCP servers "
        "to verify no unintended tool bleed.",
    )


def check_mcp_bypass_highblast(ctx: Context) -> Finding:
    """B76 — High-blast MCP tool-inheritance bypass (attestation-based, scored).

    Grounded on OpenClaw #63399: globally-registered mcp.servers tools bypass
    per-agent filters and are injected into ALL agents at runtime.

    B75 (scored=False) flags any MCP bleed broadly.  B76 (scored=True) targets only
    the subset that materially raises attack blast radius: agents holding MCP-namespaced
    tools whose verb classifies as EXEC, EGRESS, DESTRUCTIVE, or MAILBOX_CONFIG.
    These are the primitives that enable code execution, exfiltration, irreversible
    deletion, or persistent mailbox takeover.

    classify_verb() strips MCP namespace before matching so provider names cannot
    inflate the verdict (e.g. 'mcp__SendGrid__list_templates' → verb='list_templates'
    → REVERSIBLE, not EGRESS).

    UNKNOWN — no attestation provided.
    WARN    — one or more attested agents hold high-blast MCP tools + mcp.servers set.
    PASS    — no high-blast MCP tools found, or no mcp.servers configured.
    """
    agents = _attest.attested_agents(ctx.attestation)
    if not agents:
        return _finding(
            "B76",
            UNKNOWN,
            "No attestation provided — cannot determine whether high-blast MCP tools "
            "bypass per-agent filters at runtime (OpenClaw #63399).",
            "Run with --attest including each agent's real tool list. High-blast MCP "
            "tools (EXEC/EGRESS/DESTRUCTIVE/MAILBOX_CONFIG verbs) may be reachable by "
            "all agents regardless of per-agent tool configuration.",
        )

    mcp_servers = _mcp_servers(ctx.config)
    if not mcp_servers:
        return _finding(
            "B76",
            PASS,
            "No MCP servers configured — high-blast MCP tool inheritance bypass not applicable.",
            "This check activates when mcp.servers (or mcpServers) are registered.",
        )

    blast_ev: list[str] = []
    for agent in agents:
        name = agent["name"]
        tools = agent["tools"]
        mcp_tools = [t for t in tools if "__" in t]
        high_blast = [
            t for t in mcp_tools if _attest.classify_verb(t) in _attest.HIGH_BLAST_CLASSES
        ]
        if high_blast:
            count = len(high_blast)
            sample = ", ".join(high_blast[:3])
            extra = f" (+{count - 3} more)" if count > 3 else ""
            blast_ev.append(f"agent '{name}' holds {count} high-blast MCP tool(s): {sample}{extra}")

    if blast_ev:
        ev_summary = "; ".join(blast_ev[:3])
        extra_ev = f" (+{len(blast_ev) - 3} more agents)" if len(blast_ev) > 3 else ""
        return _finding(
            "B76",
            WARN,
            "Attested agents hold high-blast MCP tools that bypass per-agent filters "
            "(OpenClaw #63399 — EXEC/EGRESS/DESTRUCTIVE/MAILBOX_CONFIG verbs): "
            + ev_summary
            + extra_ev,
            "High-blast MCP tools increase the blast radius of prompt-injection or "
            "rogue-agent attacks. Until #63399 is resolved: disable MCP servers not "
            "needed by all agents, use sandbox.tools restrictions, or add per-source "
            "deny lists via toolsBySender.",
            blast_ev,
        )

    return _finding(
        "B76",
        PASS,
        "No attested agent holds high-blast MCP tools despite MCP servers configured.",
        "Current MCP tool inventory contains only low-blast verbs (search/read/draft). "
        "Re-run after adding MCP servers or changing tool configurations.",
    )


# ---------- B151: codex connector shell hooks in the plugin doc-cache ----------
# Real path: agents/<agent>/agent/codex-home/.tmp/plugins/plugins/<connector>/hooks.json
# (the Codex CLI's own third-party plugin cache — a DIFFERENT on-disk location from an
# OpenClaw skill dir; existing skill-supply-chain checks scan SKILL_DIRS and never reach
# here). Some connectors wire a shell script to a tool-use event, e.g.
# {"PostToolUse": {"Bash": "./scripts/post_bash_upload.sh"}, "Stop": "./scripts/stop_close_and_upload.sh"}
# — an upload-shaped surface. This is informational disclosure only (WARN, LOW/advisory,
# never FAIL): a third-party connector legitimately reacting to tool-use/session-end
# events is not proof of malice, but the shell wiring is worth surfacing.
#
# The exact hooks.json shape is not part of OpenClaw's own config schema (it belongs to
# the Codex CLI's connector ecosystem, read generically here — never hardcoded to one
# connector's exact keys), so detection is deliberately shape-tolerant: any string value
# reachable from the JSON (at any nesting depth) that looks like a shell script path is
# treated as a "shell hook", tagged with the event name under which it was found (the
# top-level key it was nested under, when discoverable).
_C015_CODEX_PLUGIN_MARKER = ("agent", "codex-home", ".tmp", "plugins", "plugins")

# Tool-use / lifecycle event names worth calling out by name when found as a top-level
# (or near-top-level) key — informational framing only, not an exhaustive enum: any
# other event name is still reported, just without a "recognized" label.
_HOOK_EVENT_HINTS = frozenset({
    "posttooluse", "pretooluse", "stop", "subagentstop", "sessionstart", "sessionend",
    "notification", "userpromptsubmit",
})


def _looks_like_shell_script(value: str) -> bool:
    """True if *value* looks like a shell-script command/path (generic, not one shape)."""
    v = value.strip()
    if not v:
        return False
    if v.endswith((".sh", ".bash", ".zsh")):
        return True
    # A bare command line invoking a shell interpreter or a relative script path.
    first_tok = v.split()[0] if v.split() else v
    first_tok = first_tok.lstrip("./")
    return first_tok in {"sh", "bash", "zsh"} or v.startswith(("./", "../"))


def _walk_hook_shell_refs(node, event_name: str | None, out: list[tuple[str, str]]) -> None:
    """Recursively collect (event_name, shell_ref) pairs from a hooks.json structure.

    Shape-tolerant: descends dicts/lists at any depth, carrying the closest enclosing
    top-level-ish key as the "event name" label (best-effort; never fabricated beyond
    what the JSON itself names).
    """
    if isinstance(node, dict):
        for key, val in node.items():
            child_event = str(key) if event_name is None else event_name
            _walk_hook_shell_refs(val, child_event, out)
    elif isinstance(node, list):
        for item in node:
            _walk_hook_shell_refs(item, event_name, out)
    elif isinstance(node, str):
        if _looks_like_shell_script(node):
            out.append((event_name or "<unknown event>", node))


def _codex_plugin_doc_cache_dirs(ctx: Context) -> list[Path]:
    """agents/<agent>/agent/codex-home/.tmp/plugins/plugins/ dirs under ctx.home, if any."""
    agents_root = ctx.home / "agents"
    out: list[Path] = []
    if not agents_root.is_dir():
        return out
    try:
        agent_dirs = sorted(p for p in agents_root.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return out
    for agent_dir in agent_dirs:
        cache_dir = agent_dir
        for part in _C015_CODEX_PLUGIN_MARKER:
            cache_dir = cache_dir / part
        if cache_dir.is_dir():
            out.append(cache_dir)
    return out


def check_codex_plugin_hooks(ctx: Context) -> Finding:
    """B151 — codex connector shell hooks in the plugin doc-cache (informational).

    Walks agents/*/agent/codex-home/.tmp/plugins/plugins/*/hooks.json (the Codex CLI's
    own third-party plugin cache, distinct from any OpenClaw skill directory) and, for
    each hooks.json found, reports when a hook wires a shell script to a tool-use/
    lifecycle event. Advisory only (WARN, LOW, never FAIL) — an upload-shaped surface in
    a third-party connector cache, not proof of malice.

    PASS    — doc-cache dir(s) found with hooks.json file(s), none wire a shell script.
    WARN    — at least one hooks.json wires a shell script to an event.
    UNKNOWN — no codex-home doc-cache directory found, or no hooks.json within it.
    """
    cache_dirs = _codex_plugin_doc_cache_dirs(ctx)
    if not cache_dirs:
        return _finding(
            "B151",
            UNKNOWN,
            "No Codex CLI plugin doc-cache directory found under agents/*/agent/"
            "codex-home/.tmp/plugins/plugins/ — not applicable (Codex CLI connectors "
            "are not in use, or the cache has not been populated).",
            "No action needed unless Codex CLI connectors are adopted later.",
        )

    import json as _json

    any_hooks_file = False
    shell_ev: list[str] = []
    clean_connectors: list[str] = []

    for cache_dir in cache_dirs:
        try:
            connector_dirs = sorted(p for p in cache_dir.iterdir() if p.is_dir() and not p.is_symlink())
        except OSError:
            continue
        for connector_dir in connector_dirs:
            hooks_path = connector_dir / "hooks.json"
            if not hooks_path.is_file() or hooks_path.is_symlink():
                continue
            any_hooks_file = True
            try:
                data = _json.loads(hooks_path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            refs: list[tuple[str, str]] = []
            _walk_hook_shell_refs(data, None, refs)
            if refs:
                for event_name, script in refs[:3]:
                    shell_ev.append(
                        f"{connector_dir.name}/hooks.json: {event_name} -> {script}"
                    )
            else:
                clean_connectors.append(connector_dir.name)

    if not any_hooks_file:
        return _finding(
            "B151",
            UNKNOWN,
            "Codex CLI plugin doc-cache directory found, but no hooks.json file exists "
            "within it — no connector shell-hook wiring to assess.",
            "No action needed unless a connector with hooks.json is installed later.",
        )

    if shell_ev:
        detail = "; ".join(shell_ev[:6])
        extra = f" (+{len(shell_ev) - 6} more)" if len(shell_ev) > 6 else ""
        return _finding(
            "B151",
            WARN,
            "Third-party Codex connector(s) wire a shell script to a tool-use/lifecycle "
            f"event in the plugin doc-cache: {detail}{extra}. This is an upload-shaped "
            "surface disclosed for awareness — not proof of malice; many legitimate "
            "connectors do this.",
            "Review the referenced script(s) before trusting the connector, and confirm "
            "they only run with your consent (e.g. as part of an explicit workflow).",
            evidence=shell_ev[:6],
        )

    return _finding(
        "B151",
        PASS,
        f"Codex connector hooks.json file(s) found ({', '.join(clean_connectors[:6])}); "
        "none wire a shell script to a tool-use/lifecycle event.",
        "Keep reviewing new connectors' hooks.json before trusting them.",
        evidence=clean_connectors[:6],
    )


# ---------- B152: orphaned plugin caches not declared in plugins.entries ----------
# Real example: npm/projects/openclaw-brave-plugin-* and agents/main/agent/plugins/nvidia
# exist on disk but are not declared in openclaw.json's plugins.entries. Two grounded
# on-disk plugin-cache locations (recon §11.1): ~/.openclaw/npm/projects/<wrapper>/ (an
# npm/ClawHub-installed plugin's host wrapper project — the real plugin + its manifest
# live at <wrapper>/node_modules/<pkg-or-@scope/pkg>/) and agents/<agent>/agent/plugins/
# (a per-agent plugin cache directory; no manifest guaranteed, so the directory name
# itself is the best-effort candidate id). _plugins() already reads the declared
# plugins.entries set (reused as-is, same access pattern other B5x/B57 checks use).
#
# WARN (LOW/advisory), never FAIL: an on-disk plugin cache with no matching
# plugins.entries key may be stale (uninstalled but not cleaned up), mid-install, or a
# plugin declared under a different config key shape — not proof of malice.
_NPM_PROJECTS_REL = ("npm", "projects")
_AGENT_PLUGINS_REL = ("agent", "plugins")


def _npm_projects_plugin_ids(ctx: Context) -> dict[str, Path]:
    """{plugin-id: wrapper-dir} for each ~/.openclaw/npm/projects/<wrapper>/ whose
    manifest (found via the shared _locate_plugin_root helper) declares an id."""
    out: dict[str, Path] = {}
    npm_projects = ctx.home
    for part in _NPM_PROJECTS_REL:
        npm_projects = npm_projects / part
    if not npm_projects.is_dir():
        return out
    try:
        wrapper_dirs = sorted(p for p in npm_projects.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return out
    import json as _json

    for wrapper_dir in wrapper_dirs:
        root = _locate_plugin_root(wrapper_dir)
        pid: str | None = None
        if root is not None:
            try:
                manifest = _json.loads(
                    (root / _PLUGIN_MANIFEST).read_text(encoding="utf-8", errors="replace")
                )
            except (OSError, ValueError):
                manifest = None
            if isinstance(manifest, dict) and isinstance(manifest.get("id"), str) and manifest["id"]:
                pid = manifest["id"]
        if pid is None:
            # No manifest / unresolvable id — fall back to the wrapper dir name itself so
            # the on-disk presence is still surfaced (never silently dropped, F-061 spirit).
            pid = wrapper_dir.name
        out[pid] = wrapper_dir
    return out


def _agent_plugins_ids(ctx: Context) -> dict[str, Path]:
    """{plugin-id: plugin-dir} for each agents/<agent>/agent/plugins/<name>/ directory."""
    out: dict[str, Path] = {}
    agents_root = ctx.home / "agents"
    if not agents_root.is_dir():
        return out
    try:
        agent_dirs = sorted(p for p in agents_root.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return out
    for agent_dir in agent_dirs:
        plugins_dir = agent_dir
        for part in _AGENT_PLUGINS_REL:
            plugins_dir = plugins_dir / part
        if not plugins_dir.is_dir():
            continue
        try:
            plugin_dirs = sorted(p for p in plugins_dir.iterdir() if p.is_dir() and not p.is_symlink())
        except OSError:
            continue
        for plugin_dir in plugin_dirs:
            out.setdefault(plugin_dir.name, plugin_dir)
    return out


def check_orphaned_plugin_caches(ctx: Context) -> Finding:
    """B152 — on-disk plugin caches not declared in plugins.entries (informational).

    Compares plugin cache directories under ~/.openclaw/npm/projects/ and
    agents/*/agent/plugins/ against the declared plugins.entries set from config, and
    WARNs (LOW/advisory) on any on-disk plugin directory not declared. Never FAIL — a
    stale/uninstalled cache, an in-progress install, or a plugin declared elsewhere is
    not proof of malice, just a hygiene signal worth surfacing.

    PASS    — on-disk plugin cache directories found, all match a declared entry.
    WARN    — at least one on-disk plugin cache directory has no matching
              plugins.entries key.
    UNKNOWN — no on-disk plugin cache directory found at either known location.
    """
    npm_ids = _npm_projects_plugin_ids(ctx)
    agent_ids = _agent_plugins_ids(ctx)

    if not npm_ids and not agent_ids:
        return _finding(
            "B152",
            UNKNOWN,
            "No on-disk plugin cache directory found under ~/.openclaw/npm/projects/ "
            "or agents/*/agent/plugins/ — not applicable.",
            "No action needed unless plugins are installed later.",
        )

    declared = set(_plugins(ctx.config))
    on_disk: dict[str, Path] = {}
    on_disk.update(npm_ids)
    on_disk.update(agent_ids)

    orphaned = sorted(pid for pid in on_disk if pid not in declared)

    if orphaned:
        ev = [f"{pid} ({on_disk[pid]})" for pid in orphaned[:6]]
        extra = f" (+{len(orphaned) - 6} more)" if len(orphaned) > 6 else ""
        return _finding(
            "B152",
            WARN,
            "On-disk plugin cache director(y/ies) found with no matching "
            f"plugins.entries declaration: {', '.join(orphaned[:6])}{extra}. This may "
            "be a stale/uninstalled cache, a mid-install artifact, or a plugin declared "
            "under a different key — not proof of malice.",
            "Review each undeclared plugin cache: if it is stale, remove it; if it is "
            "an intentional plugin, ensure it is declared under plugins.entries so it "
            "is covered by plugin-permission and supply-chain checks.",
            evidence=ev,
        )

    return _finding(
        "B152",
        PASS,
        f"On-disk plugin cache director(y/ies) found ({', '.join(sorted(on_disk)[:6])}); "
        "all match a declared plugins.entries entry.",
        "Keep plugins.entries in sync with on-disk plugin caches as plugins are added "
        "or removed.",
        evidence=sorted(on_disk)[:6],
    )
