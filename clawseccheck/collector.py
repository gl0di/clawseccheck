"""Read-only collection of OpenClaw config + bootstrap files.

Reads ONLY: ~/.openclaw/openclaw.json and workspace bootstrap markdown files.
No network. No writes. Pure stdlib.
"""
from __future__ import annotations

import math
import hashlib
import io
import json
import sqlite3
import zipfile
import tarfile
import gzip
import bz2
import lzma
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from .configloader import (
    ConfigLoadError as _ConfigLoadError,
    load_openclaw_config as _load_openclaw_config,
)
from .safeio import walk_dir_safely, is_safe_tar_member
from .skilldiscovery import (
    config_extra_skill_dirs as _config_extra_skill_dirs,
    config_plugin_load_paths as _config_plugin_load_paths,
    iter_discovered_skill_dirs as _iter_discovered_skill_dirs,
)
from .textnorm import obfuscation_signals

# Bootstrap / prompt files injected into the system prompt as "trusted context".
# The native `openclaw security audit` does not inspect these files; checks
# B6/B7/B9 cover that gap.
BOOTSTRAP_FILES = [
    "SOUL.md", "AGENTS.md", "TOOLS.md", "MEMORY.md", "IDENTITY.md",
    "USER.md", "HEARTBEAT.md", "BOOTSTRAP.md", "memory.md",
]

WORKSPACE_DIRS = ["workspace-home", "workspace-work", "workspace"]

# Where OpenClaw discovers installed skills (we read their CONTENT, never run them).
SKILL_DIRS = ["skills", "workspace/skills", "workspace-home/skills",
              "workspace-work/skills", ".agents/skills"]
# B-265: the ONLY own-skill directory name we still recognise. "clawshield" was a dead
# legacy namespace (renamed away in v0.16.0) that protected nothing and handed an attacker
# a free cloak. Note this set is never a self-exclusion decision on its own — it only
# selects which *shape* of `_is_own_source` layout check applies; the engine markers below
# are what actually grant the exclusion.
_OWN_SKILL_NAMES = {"clawseccheck"}

# Distinctive symbols that only ClawSecCheck's own signature engine (the checks/ package)
# contains. Used to recognise our own source so neither --vet nor the installed-skill audit
# flags the scanner's embedded attack signatures + red-team payloads as malware.
_OWN_ENGINE_MARKERS = ("def check_installed_skills", "def vet_skill", "_SKILL_CRIT")
_MAX_SKILLS = 300
# B-268: how many cap-evicted skill NAMES are retained as the truncation frontier. Names
# are cheap (a directory basename), but the frontier must not itself become an unbounded
# allocation on a deliberate 100k-skill flood. Past this point ctx.skills_frontier_partial
# goes True and consumers must stop using the name list as a completeness oracle. Set well
# above _MAX_SKILLS so any plausible real fleet keeps an EXACT frontier.
_MAX_SKILL_FRONTIER_NAMES = 5_000
# B-144 follow-up: raised 60_000 -> 200_000 -> 1_000_000, all three caps kept in lock-
# step. _MAX_FILE_BYTES must move WITH _MAX_BYTES_PER_SKILL, not independently — a
# single file over _MAX_FILE_BYTES is dropped whole by collect_skill_files before the
# per-skill budget logic ever sees it, so raising only the per-skill cap has no effect
# on a skill with one large file. Regex/entropy scanning 1MB is still low-single-digit
# milliseconds per check (DEFAULT_CHECK_BUDGET_S is 15s); the cross-file reassembly
# checks (B90/B154) are independently bounded by their own fragment/window caps
# regardless of blob size. Confirmed on a real config: a legitimate ~152KB skill
# (clawstealth) was hitting the old 60KB cap and reading as UNKNOWN purely from asymmetry
# with _MAX_PY_BYTES_PER_SKILL (already 200KB) before that first bump.
_MAX_BYTES_PER_SKILL = 1_000_000
_MAX_FILE_BYTES = 1_000_000
_MAX_FILES_PER_SKILL = 500
_MAX_PY_BYTES_PER_SKILL = 1_000_000  # cap on Python source kept per skill for AST analysis
_ARCHIVE_FILE_LIMIT = _MAX_FILES_PER_SKILL
_ARCHIVE_MAX_FILE_BYTES = _MAX_FILE_BYTES
_ARCHIVE_MAX_TOTAL_BYTES = 20_000_000
_ARCHIVE_MAX_EXPANSION_RATIO = 100

# B-153: openclaw.json is user/agent-authored structured config (MCP server lists,
# capability grants, agent definitions, …) rather than a skill payload, so it gets its
# OWN — slightly larger — cap instead of reusing _MAX_FILE_BYTES verbatim: a real config
# with many servers/agents can legitimately run a few hundred KB larger than a single
# skill file, and the read happens exactly ONCE per audit (unlike per-skill-file reads),
# so a larger single cap doesn't reopen the memory-scaling hole B-153 closes. Still
# bounded — a 500MB config caps at 5MB read, not unbounded RSS growth.
_MAX_CONFIG_BYTES = 5_000_000

# B-231 sub-item 1: the cron job store (~/.openclaw/cron/jobs.json, or the SQLite-backed
# cron_jobs table when the legacy JSON file is absent) is read-only, symlink-safe, and
# capped the same way as the config/bootstrap reads above — a huge/padded store must not
# load whole into memory or feed an unbounded number of jobs into the content-ring scan.
_MAX_CRON_BYTES = _MAX_CONFIG_BYTES
_MAX_CRON_JOBS = 200

# B-236 (B172): the standing exec-approvals store (~/.openclaw/exec-approvals.json) is
# read-only and size/entry-capped the same way as the cron store above.
_MAX_EXEC_APPROVALS_BYTES = _MAX_CONFIG_BYTES
_MAX_EXEC_APPROVALS_AGENTS = 200

# B-240 (B177): the persisted installed_plugin_index.install_records_json column (OpenClaw's
# own ClawHub trust verdict per plugin) is read-only and size/entry-capped the same way as
# the cron/exec-approvals stores above — a huge/padded blob must not load whole into memory
# or feed an unbounded number of records into the finding text.
_MAX_PLUGIN_TRUST_BYTES = _MAX_CONFIG_BYTES
_MAX_PLUGIN_TRUST_RECORDS = 500

# B-111: an archive member name is attacker-controlled and NOT OS-length-limited (unlike a
# real filesystem path) — a crafted zip/tar entry can carry a multi-KB name. It flows
# uncapped into ctx.limit_hits / ctx.path_traversal_violations / ctx.file_manifest keys,
# which are joined straight into report evidence text (see B13 in the checks engine). Cap it at the
# point of entry so every downstream consumer inherits the bound.
_UNTRUSTED_NAME_CAP = 120


def _cap_name(name: str) -> str:
    """Bound an attacker-controlled archive member name before it reaches evidence text."""
    if len(name) <= _UNTRUSTED_NAME_CAP:
        return name
    return name[:_UNTRUSTED_NAME_CAP] + "...(truncated)"

# F-087: padding-anomaly evasion signal. When a file is sliced by the text-scan cap,
# the discarded tail is sampled (bounded — never re-reads gigabytes) and measured for
# Shannon entropy. Low-entropy filler (a repeated byte, long whitespace/newline runs, a
# giant comment block) is the shape of deliberate cap-evasion padding (standard §2.5,
# "omnicogg"); a real high-entropy binary asset stays the honest UNKNOWN it is today.
_ENTROPY_SAMPLE_BYTES = 65_536      # sample at most 64 KiB of the cut tail
_ENTROPY_MIN_SAMPLE = 2_048         # below this, entropy is too noisy to judge
# bits/byte. Empirically calibrated (not guessed): a repeated short benign English
# line measures ~3.84, varied prose ~4.3, base64-of-random ~6.0 — but a single
# repeated byte measures 0.0 and a whitespace run ~1.0. 3.0 cleanly separates
# genuinely degenerate/uniform filler (the "omnicogg" padding shape) from any text
# with ordinary character variety, even repetitive documentation. Err toward
# honest-UNKNOWN on the boundary rather than widen and risk a false WARN.
_PADDING_ENTROPY_THRESHOLD = 3.0

def _shannon_entropy_bits(s: str) -> float:
    """Shannon entropy (bits per byte) over the UTF-8 byte histogram of *s*.

    Stdlib-only, single pass, bounded by the caller's sample slice — never call this
    on more than a small bounded sample of a large tail.
    """
    data = s.encode("utf-8", "replace")
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


@dataclass
class Context:
    home: Path
    config: dict = field(default_factory=dict)
    bootstrap: dict = field(default_factory=dict)   # filename -> text
    errors: list[str] = field(default_factory=list)
    config_mode: int | None = None                  # octal perms of openclaw.json, or None
    config_found: bool = False                       # openclaw.json present (vs non-OpenClaw setup)
    config_parse_error: bool = False                 # openclaw.json present but unparseable (B-166)
    native: object = None                           # NativeResult from openclaw security audit
    host: object = None                             # hostwatch.detect() result; set by audit(include_host=True)
    include_host: bool = False                      # host-filesystem scanning enabled (audit(include_host=True) / not --no-host)
    # B-231 sub-item 1: normalized cron jobs (from ~/.openclaw/cron/jobs.json, or the
    # SQLite-backed cron_jobs table when the JSON file is absent). Each entry is a plain
    # dict: id, name, enabled, delete_after_run, trigger_script, payload_kind,
    # payload_message — the same shape regardless of which backing store it came from.
    cron_jobs: list = field(default_factory=list)
    cron_found: bool = False        # a cron store (JSON or SQLite) was found and read
    cron_parse_error: bool = False  # a cron store was found but could not be parsed/read
    # B-236 (B172): standing exec-approvals.json grants, one dict per agent present in
    # the store's `agents` map: {agent_id, security, ask, allow_always_count}. Populated
    # regardless of whether allow_always_count is 0 -- the consuming check filters.
    exec_approvals_grants: list = field(default_factory=list)
    exec_approvals_found: bool = False        # exec-approvals.json present and read
    exec_approvals_parse_error: bool = False  # present but could not be parsed/read
    # B-240 (B177): OpenClaw's OWN persisted per-plugin ClawHub trust verdict, read from
    # the installed_plugin_index.install_records_json column in the shared state SQLite DB
    # (~/.openclaw/state/openclaw.sqlite). Each entry: {plugin_id, disposition, scan_status,
    # moderation_state, reasons (list[str]), pending, stale} — disposition is one of
    # "clean" | "review-recommended" | "review-required" | "blocked" | None (no verdict
    # persisted for that install yet).
    plugin_trust_records: list = field(default_factory=list)
    plugin_trust_found: bool = False        # installed_plugin_index row present and read
    plugin_trust_parse_error: bool = False  # present but could not be read/parsed (locked/corrupt)
    installed_skills: dict = field(default_factory=dict)  # skill name -> concatenated text
    installed_skill_py: dict = field(default_factory=dict)  # skill name -> [(relpath, source)] for AST
    installed_skill_shell: dict = field(default_factory=dict)  # skill name -> [(relpath, source)] for .sh/.bash
    installed_skill_js: dict = field(default_factory=dict)  # skill name -> [(relpath, source)] for .js/.ts
    # skill name -> that skill's own resolved directory (the dir containing its SKILL.md).
    # F-131: lets a per-skill Context be scoped to JUST that skill (mirrors vet_skill's
    # Context(home=<skill dir>)) instead of the whole OpenClaw home, so home-wide-walking
    # ring checks (B42 install-policy, B87 symlink-escape) don't cross-attribute another
    # skill's evidence onto this one.
    installed_skill_dirs: dict = field(default_factory=dict)
    attestation: dict = field(default_factory=dict)  # agent self-report (--attest); see attest.py
    _collected_skill_files: dict[str, list[dict]] = field(default_factory=dict)

    # F-018: per-skill aggregated effect profiles from the abstract effect simulator.
    # Populated by check_installed_skills; keyed by skill name.
    # Each value is a list of entry-point result dicts (see skillast.simulate_effects).
    effect_profiles: dict = field(default_factory=dict)

    # Integrity & analysis metadata blocks
    limit_hits: list[str] = field(default_factory=list)
    mismatches: list[str] = field(default_factory=list)
    polyglots: list[str] = field(default_factory=list)
    binary_files: list[str] = field(default_factory=list)
    stowaway_files: list[str] = field(default_factory=list)  # F-054: native executables bundled in a skill
    total_files_inspected: int = 0
    excluded_binary_files_count: int = 0
    archives_unpacked: int = 0
    path_traversal_violations: list[str] = field(default_factory=list)
    file_manifest: dict[str, str] = field(default_factory=dict)  # file relpath -> status
    symlink_skips: list[str] = field(default_factory=list)        # F-061: skipped symlinks / path-escapes
    filename_obfuscations: list[str] = field(default_factory=list)  # F-061: homoglyph/RTL/zero-width filenames
    # F-087: skill names whose text-scan was truncated by a LOW-ENTROPY cut tail — the
    # shape of deliberate cap-evasion padding, distinct from limit_hits (which fires on
    # ANY cap — archive/py/text — including a genuine high-entropy oversized asset).
    padding_anomalies: list[str] = field(default_factory=list)

    # B-268: the _MAX_SKILLS truncation frontier. `installed_skills` is a capped VIEW of
    # the filesystem, and a consumer that diffs it against a previous view (monitor.py) or
    # prints its length as an inventory total (report.py) was reading that view as ground
    # truth. These three fields make the partiality explicit and machine-readable:
    #   skills_capped_names — directory names DISCOVERED but not read because the cap was
    #     already full. Bounded by _MAX_SKILL_FRONTIER_NAMES so a 100k-skill flood cannot
    #     turn the frontier itself into an unbounded allocation.
    #   skills_capped_count — the true number skipped, exact even when the name list above
    #     was itself truncated.
    #   skills_frontier_partial — True when skills_capped_names is incomplete, i.e. a
    #     consumer may NOT use "absent from the name list" to conclude "absent from disk".
    skills_capped_names: list[str] = field(default_factory=list)
    skills_capped_count: int = 0
    skills_frontier_partial: bool = False

    @property
    def bootstrap_blob(self) -> str:
        return "\n".join(self.bootstrap.values())


def _read_with_limit(file_obj: io.BufferedIOBase, byte_limit: int) -> tuple[bytes, bool]:
    """Read up to ``byte_limit`` bytes from ``file_obj`` without over-allocation."""
    if byte_limit < 0:
        raise ValueError("byte_limit must be >= 0")

    out = bytearray()
    while True:
        chunk = file_obj.read(byte_limit + 1 - len(out))
        if not chunk:
            return bytes(out), False
        out.extend(chunk)
        if len(out) > byte_limit:
            return bytes(out[:byte_limit]), True


def _pyc_fmt(data: bytes) -> str | None:
    r"""Name a would-be-binary file 'pyc' when it carries the CPython bytecode magic
    (``<version-low-byte>\r\r\n`` — bytes 1..3 are ``\x0d\x0d\x0a`` for every 3.x release,
    since the 16-bit magic's high byte is 0x0d). F-116: consulted ONLY on the binary return
    paths, so a benign text file that merely starts with ``#\r\r\n`` (which stays high-
    printable-ratio TEXT) is never misnamed pyc."""
    return "pyc" if len(data) >= 4 and data[1:4] == b"\x0d\x0d\x0a" else None


def classify_bytes(data: bytes, file_size: int) -> tuple[str, str | None]:
    """Classify data as "TEXT" or "BINARY" and return (classification, format_name)."""
    fmt = None
    if data.startswith(b"\x7fELF"):
        fmt = "ELF"
    elif data.startswith(b"MZ"):
        fmt = "PE"
    elif data.startswith(b"\xce\xfa\xed\xfe"):
        fmt = "Mach-O (32 LSB)"
    elif data.startswith(b"\xcf\xfa\xed\xfe"):
        fmt = "Mach-O (64 LSB)"
    elif data.startswith(b"\xfe\xed\xfa\xce"):
        fmt = "Mach-O (32 MSB)"
    elif data.startswith(b"\xfe\xed\xfa\xcf"):
        fmt = "Mach-O (64 MSB)"
    elif data.startswith(b"\xc0\xde\xc0\xde"):
        fmt = "Mach-O (FAT LSB)"
    elif data.startswith(b"\xca\xfe\xba\xbe"):
        if file_size < 50000 and len(data) >= 10:
            major_version = int.from_bytes(data[6:8], "big")
            constant_pool_count = int.from_bytes(data[8:10], "big")
            if 45 <= major_version <= 100 and constant_pool_count > 0:
                fmt = "class"
        if not fmt:
            fmt = "Mach-O (FAT MSB)"
    elif data.startswith(b"\x00asm"):
        fmt = "wasm"  # F-116: WebAssembly module — unambiguous magic, a loose .wasm is a stowaway
    elif data.startswith(b"PK\x03\x04"):
        fmt = "ZIP"
    elif data.startswith(b"PK\x05\x06"):
        fmt = "ZIP"
    elif data.startswith(b"PK\x07\x08"):
        fmt = "ZIP"
    elif data.startswith(b"\x1f\x8b"):
        fmt = "gzip"
    elif data.startswith(b"BZh"):
        fmt = "bz2"
    elif data.startswith(b"\xfd7zXZ\x00"):
        fmt = "xz"
    elif len(data) >= 262 and data[257:262] == b"ustar":
        fmt = "tar"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        fmt = "PNG"
    elif data.startswith(b"\xff\xd8\xff"):
        fmt = "JPEG"
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        fmt = "GIF"
    elif data.startswith(b"%PDF-"):
        fmt = "PDF"

    if fmt is not None:
        return "BINARY", fmt

    # Attempt to decode first 4096 bytes as UTF-8, UTF-16LE, UTF-16BE
    chunk = data[:4096]
    decoded = None
    for encoding in ("utf-8", "utf-16le", "utf-16be"):
        try:
            decoded = chunk.decode(encoding)
            break
        except UnicodeDecodeError:
            continue

    if decoded is None:
        return "BINARY", _pyc_fmt(data)

    if not decoded:
        return "TEXT", None

    # Calculate printable ratio
    printable_count = 0
    for char in decoded:
        if char in ("\t", "\n", "\r"):
            printable_count += 1
        else:
            cat = unicodedata.category(char)
            # Cc, Cf, Cs, Co, Cn are Unicode categories for control/format/surrogates/etc.
            if cat not in ("Cc", "Cf", "Cs", "Co", "Cn"):
                printable_count += 1

    ratio = printable_count / len(decoded)
    if ratio >= 0.85:
        return "TEXT", None
    else:
        return "BINARY", _pyc_fmt(data)


def check_mismatch(filename: str, classification: str, format_name: str | None, data: bytes) -> str | None:
    ext = Path(filename).suffix.lower()
    text_extensions = {".py", ".json", ".txt", ".md", ".sh", ".bash", ".zsh", ".js", ".ts", ".mjs", ".cjs", ".ps1"}
    
    if ext in text_extensions:
        if data.startswith(b"MZ") or data.startswith(b"\x7fELF") or data.startswith(b"PK\x03\x04"):
            return "MISMATCH_EXTENSION"
            
    binary_ext_to_format = {
        ".png": "PNG",
        ".jpg": "JPEG",
        ".jpeg": "JPEG",
        ".pdf": "PDF",
        ".zip": "ZIP",
        ".gz": "gzip",
        ".bz2": "bz2",
        ".xz": "xz",
        ".tar": "tar",
        ".class": "class",
    }
    if ext in binary_ext_to_format:
        expected_format = binary_ext_to_format[ext]
        if format_name is not None and format_name != expected_format:
            return "MISMATCH_EXTENSION"
            
    return None


def check_polyglot(filename: str, format_name: str | None, data: bytes) -> str | None:
    if format_name != "ZIP":
        idx = data.find(b"PK\x03\x04")
        if idx > 0:
            return "POLYGLOT_DETECTED"

    if format_name in ("PNG", "JPEG", "GIF"):
        header = data[:1024].lower()
        html_tags = (b"<html>", b"<script", b"<body>", b"<iframe>", b"</a>", b"</div>")
        for tag in html_tags:
            if tag in header:
                return "POLYGLOT_DETECTED"

    ext = Path(filename).suffix.lower()
    archive_extensions = {".zip", ".tar", ".gz", ".bz2", ".xz"}
    if ext not in archive_extensions and len(data) > 0:
        tail = data[-1024:]
        if b"PK\x01\x02" in tail or b"PK\x05\x06" in tail:
            return "POLYGLOT_DETECTED"

    return None


def decompress_and_classify(
    ctx: Context | None,
    skill_dir: Path,
    file_bytes: bytes,
    file_relpath: str,
    depth: int,
    archive_stats: dict
) -> list[tuple[str, bytes, str, str | None]]:
    """Recursively decompress and classify files from an archive."""
    try:
        classification, format_name = classify_bytes(file_bytes, len(file_bytes))
    except Exception as e:
        if ctx is not None:
            ctx.limit_hits.append(f"Classification failed for {file_relpath}: {e}")
            ctx.file_manifest[file_relpath] = "binary-strings"
        return [(file_relpath, file_bytes, "BINARY", None)]

    if format_name not in ("ZIP", "tar", "gzip", "bz2", "xz"):
        return [(file_relpath, file_bytes, classification, format_name)]
        
    if depth > 3:
        if ctx is not None:
            ctx.limit_hits.append(f"Depth limit hit (>3) at {file_relpath}")
            ctx.file_manifest[file_relpath] = "capped(depth)"
        return [(file_relpath, file_bytes, classification, format_name)]
        
    if ctx is not None:
        ctx.archives_unpacked += 1
        
    compressed_size = len(file_bytes)
    results = []
    
    # ZIP
    if format_name == "ZIP":
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                namelist = zf.namelist()
                if len(namelist) + archive_stats["total_files_count"] > _ARCHIVE_FILE_LIMIT:
                    if ctx is not None:
                        ctx.limit_hits.append(f"Max files limit hit (>500) in {file_relpath}")
                        ctx.file_manifest[file_relpath] = "capped(files)"
                    return [(file_relpath, file_bytes, classification, format_name)]

                for member_name in namelist:
                    # B-111: member_name is attacker-controlled and NOT length-limited like a
                    # real filesystem path — use a capped display name for evidence/manifest
                    # text; the real (uncapped) member_name still drives zf.getinfo/zf.open.
                    member_disp = _cap_name(member_name)
                    if not is_safe_tar_member(skill_dir, member_name):
                        if ctx is not None:
                            ctx.path_traversal_violations.append(f"{file_relpath}::{member_disp}")
                            ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "unsafe-path"
                        return [(file_relpath, file_bytes, classification, format_name)]

                    if member_name.endswith("/"):
                        continue

                    try:
                        member_info = zf.getinfo(member_name)
                        if member_info.is_dir():
                            continue

                        if member_info.file_size > _ARCHIVE_MAX_FILE_BYTES:
                            if ctx is not None:
                                ctx.limit_hits.append(
                                    f"Max file decompressed size hit (>200,000) for {member_disp} in {file_relpath}"
                                )
                                ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "capped(size)"
                            continue

                        with zf.open(member_name, "r") as zfp:
                            member_bytes, truncated = _read_with_limit(zfp, _ARCHIVE_MAX_FILE_BYTES)
                    except Exception:
                        continue

                    if truncated:
                        if ctx is not None:
                            ctx.limit_hits.append(f"Max file decompressed size hit (>200,000) for {member_disp} in {file_relpath}")
                            ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "capped(size)"
                        continue

                    archive_stats["total_files_count"] += 1
                    archive_stats["cumulative_decompressed_size"] += len(member_bytes)

                    if archive_stats["cumulative_decompressed_size"] > _ARCHIVE_MAX_TOTAL_BYTES:
                        if ctx is not None:
                            ctx.limit_hits.append(f"Max cumulative size hit (>20MB) in {file_relpath}")
                            ctx.file_manifest[file_relpath] = "capped(size)"
                        return [(file_relpath, file_bytes, classification, format_name)]

                    if compressed_size > 10240:
                        ratio = archive_stats["cumulative_decompressed_size"] / compressed_size
                        if ratio > _ARCHIVE_MAX_EXPANSION_RATIO:
                            if ctx is not None:
                                ctx.limit_hits.append(f"Max expansion ratio hit (>100x) in {file_relpath}")
                                ctx.file_manifest[file_relpath] = "capped(ratio)"
                            return [(file_relpath, file_bytes, classification, format_name)]

                    sub_rel = f"{file_relpath}::{member_disp}"
                    sub_results = decompress_and_classify(ctx, skill_dir, member_bytes, sub_rel, depth + 1, archive_stats)
                    results.extend(sub_results)

                if ctx is not None:
                    ctx.file_manifest[file_relpath] = "decoded"
        except Exception as e:
            if ctx is not None:
                ctx.limit_hits.append(f"ZIP decompression failed in {file_relpath}: {e}")
                ctx.file_manifest[file_relpath] = "binary-strings"
            return [(file_relpath, file_bytes, classification, format_name)]

    # TAR
    elif format_name == "tar":
        try:
            with tarfile.open(fileobj=io.BytesIO(file_bytes)) as tf:
                members = tf.getmembers()
                if len(members) + archive_stats["total_files_count"] > _ARCHIVE_FILE_LIMIT:
                    if ctx is not None:
                        ctx.limit_hits.append(f"Max files limit hit (>500) in {file_relpath}")
                        ctx.file_manifest[file_relpath] = "capped(files)"
                    return [(file_relpath, file_bytes, classification, format_name)]
                    
                for member in members:
                    # B-111: member.name is attacker-controlled and NOT length-limited like a
                    # real filesystem path — use a capped display name for evidence/manifest
                    # text; the real (uncapped) member.name still drives tf.extractfile.
                    member_disp = _cap_name(member.name)
                    if not is_safe_tar_member(skill_dir, member.name):
                        if ctx is not None:
                            ctx.path_traversal_violations.append(f"{file_relpath}::{member_disp}")
                            ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "unsafe-path"
                            return [(file_relpath, file_bytes, classification, format_name)]

                    if not member.isreg():
                        if ctx is not None and (member.issym() or member.islnk()):
                            # F-061-style disclosure: a symlink/hardlink member inside an
                            # archive is dropped just like a symlink hit by walk_dir_safely
                            # on a real directory — record it the same way so --vet on an
                            # archive surfaces "N symlink member(s) not followed" too.
                            tgt = member.linkname or "?"
                            reason = f"symlink -> {tgt}"
                            ctx.symlink_skips.append(f"{file_relpath}::{member_disp}: {reason}")
                            ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "skipped:" + reason.split(" ", 1)[0]
                        continue

                    try:
                        if member.size > _ARCHIVE_MAX_FILE_BYTES:
                            if ctx is not None:
                                ctx.limit_hits.append(f"Max file decompressed size hit (>200,000) for {member_disp} in {file_relpath}")
                                ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "capped(size)"
                            continue

                        f_obj = tf.extractfile(member)
                        if f_obj is None:
                            continue
                        member_bytes = f_obj.read(member.size)
                    except Exception:
                        continue

                    if len(member_bytes) > _ARCHIVE_MAX_FILE_BYTES:
                        if ctx is not None:
                            ctx.limit_hits.append(f"Max file decompressed size hit (>200,000) for {member_disp} in {file_relpath}")
                            ctx.file_manifest[f"{file_relpath}::{member_disp}"] = "capped(size)"
                        continue
                        
                    archive_stats["total_files_count"] += 1
                    archive_stats["cumulative_decompressed_size"] += len(member_bytes)
                    
                    if archive_stats["cumulative_decompressed_size"] > _ARCHIVE_MAX_TOTAL_BYTES:
                        if ctx is not None:
                            ctx.limit_hits.append(f"Max cumulative size hit (>20MB) in {file_relpath}")
                            ctx.file_manifest[file_relpath] = "capped(size)"
                        return [(file_relpath, file_bytes, classification, format_name)]
                        
                    if compressed_size > 10240:
                        ratio = archive_stats["cumulative_decompressed_size"] / compressed_size
                        if ratio > _ARCHIVE_MAX_EXPANSION_RATIO:
                            if ctx is not None:
                                ctx.limit_hits.append(f"Max expansion ratio hit (>100x) in {file_relpath}")
                                ctx.file_manifest[file_relpath] = "capped(ratio)"
                            return [(file_relpath, file_bytes, classification, format_name)]
                            
                    sub_rel = f"{file_relpath}::{member_disp}"
                    sub_results = decompress_and_classify(ctx, skill_dir, member_bytes, sub_rel, depth + 1, archive_stats)
                    results.extend(sub_results)
                if ctx is not None:
                    ctx.file_manifest[file_relpath] = "decoded"
        except Exception as e:
            if ctx is not None:
                ctx.limit_hits.append(f"tar decompression failed in {file_relpath}: {e}")
                ctx.file_manifest[file_relpath] = "binary-strings"
            return [(file_relpath, file_bytes, classification, format_name)]

    # GZIP
    elif format_name == "gzip":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(file_bytes), mode="rb") as gz:
                member_bytes, truncated = _read_with_limit(gz, _ARCHIVE_MAX_FILE_BYTES)

            if truncated or len(member_bytes) > _ARCHIVE_MAX_FILE_BYTES:
                if ctx is not None:
                    ctx.limit_hits.append(f"Max file decompressed size hit (>200,000) in {file_relpath}")
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]
                
            archive_stats["total_files_count"] += 1
            archive_stats["cumulative_decompressed_size"] += len(member_bytes)
            
            if archive_stats["cumulative_decompressed_size"] > _ARCHIVE_MAX_TOTAL_BYTES:
                if ctx is not None:
                    ctx.limit_hits.append(f"Max cumulative size hit (>20MB) in {file_relpath}")
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]

            if compressed_size > 10240:
                ratio = archive_stats["cumulative_decompressed_size"] / compressed_size
                if ratio > _ARCHIVE_MAX_EXPANSION_RATIO:
                    if ctx is not None:
                        ctx.limit_hits.append(f"Max expansion ratio hit (>100x) in {file_relpath}")
                        ctx.file_manifest[file_relpath] = "capped(ratio)"
                    return [(file_relpath, file_bytes, classification, format_name)]

            sub_rel = file_relpath[:-3] if file_relpath.lower().endswith(".gz") else f"{file_relpath}::extracted"
            sub_results = decompress_and_classify(ctx, skill_dir, member_bytes, sub_rel, depth + 1, archive_stats)
            results.extend(sub_results)
            if ctx is not None:
                ctx.file_manifest[file_relpath] = "decoded"
        except Exception as e:
            if ctx is not None:
                ctx.limit_hits.append(f"gzip decompression failed in {file_relpath}: {e}")
                ctx.file_manifest[file_relpath] = "binary-strings"
            return [(file_relpath, file_bytes, classification, format_name)]

    # BZIP2
    elif format_name == "bz2":
        try:
            with bz2.BZ2File(io.BytesIO(file_bytes), mode="rb") as bzf:
                member_bytes, truncated = _read_with_limit(bzf, _ARCHIVE_MAX_FILE_BYTES)

            if truncated or len(member_bytes) > _ARCHIVE_MAX_FILE_BYTES:
                if ctx is not None:
                    ctx.limit_hits.append(f"Max file decompressed size hit (>200,000) in {file_relpath}")
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]
                
            archive_stats["total_files_count"] += 1
            archive_stats["cumulative_decompressed_size"] += len(member_bytes)
            
            if archive_stats["cumulative_decompressed_size"] > _ARCHIVE_MAX_TOTAL_BYTES:
                if ctx is not None:
                    ctx.limit_hits.append(f"Max cumulative size hit (>20MB) in {file_relpath}")
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]

            if compressed_size > 10240:
                ratio = archive_stats["cumulative_decompressed_size"] / compressed_size
                if ratio > _ARCHIVE_MAX_EXPANSION_RATIO:
                    if ctx is not None:
                        ctx.limit_hits.append(f"Max expansion ratio hit (>100x) in {file_relpath}")
                        ctx.file_manifest[file_relpath] = "capped(ratio)"
                    return [(file_relpath, file_bytes, classification, format_name)]

            sub_rel = file_relpath[:-4] if file_relpath.lower().endswith(".bz2") else f"{file_relpath}::extracted"
            sub_results = decompress_and_classify(ctx, skill_dir, member_bytes, sub_rel, depth + 1, archive_stats)
            results.extend(sub_results)
            if ctx is not None:
                ctx.file_manifest[file_relpath] = "decoded"
        except Exception as e:
            if ctx is not None:
                ctx.limit_hits.append(f"bz2 decompression failed in {file_relpath}: {e}")
                ctx.file_manifest[file_relpath] = "binary-strings"
            return [(file_relpath, file_bytes, classification, format_name)]

    # XZ
    elif format_name == "xz":
        try:
            with lzma.open(io.BytesIO(file_bytes), mode="rb") as xf:
                member_bytes, truncated = _read_with_limit(xf, _ARCHIVE_MAX_FILE_BYTES)

            if truncated or len(member_bytes) > _ARCHIVE_MAX_FILE_BYTES:
                if ctx is not None:
                    ctx.limit_hits.append(f"Max file decompressed size hit (>200,000) in {file_relpath}")
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]
                
            archive_stats["total_files_count"] += 1
            archive_stats["cumulative_decompressed_size"] += len(member_bytes)
            
            if archive_stats["cumulative_decompressed_size"] > _ARCHIVE_MAX_TOTAL_BYTES:
                if ctx is not None:
                    ctx.limit_hits.append(f"Max cumulative size hit (>20MB) in {file_relpath}")
                    ctx.file_manifest[file_relpath] = "capped(size)"
                return [(file_relpath, file_bytes, classification, format_name)]

            if compressed_size > 10240:
                ratio = archive_stats["cumulative_decompressed_size"] / compressed_size
                if ratio > _ARCHIVE_MAX_EXPANSION_RATIO:
                    if ctx is not None:
                        ctx.limit_hits.append(f"Max expansion ratio hit (>100x) in {file_relpath}")
                        ctx.file_manifest[file_relpath] = "capped(ratio)"
                    return [(file_relpath, file_bytes, classification, format_name)]

            sub_rel = file_relpath[:-3] if file_relpath.lower().endswith(".xz") else f"{file_relpath}::extracted"
            sub_results = decompress_and_classify(ctx, skill_dir, member_bytes, sub_rel, depth + 1, archive_stats)
            results.extend(sub_results)
            if ctx is not None:
                ctx.file_manifest[file_relpath] = "decoded"
        except Exception as e:
            if ctx is not None:
                ctx.limit_hits.append(f"xz decompression failed in {file_relpath}: {e}")
                ctx.file_manifest[file_relpath] = "binary-strings"
            return [(file_relpath, file_bytes, classification, format_name)]

    return results


def collect_skill_files(skill_dir: Path, ctx: Context | None = None) -> list[dict]:
    """Collect (and archive-decompress/classify) the files that make up one skill.

    B-152: *skill_dir* may also be a single **file** — e.g. a bare skill archive
    (.zip/.tar.gz/.tgz/.tar.bz2/.tar.xz) passed directly to --vet/--vet-skill instead
    of an installed skill directory. In that case the file itself is the sole entry
    walked below, so it goes through the exact same archive-decompression / size-cap /
    mismatch-polyglot bookkeeping as an archive found while walking a directory
    (previously only reachable when the archive was *inside* a scanned skill dir).
    """
    if ctx is not None:
        cache_key = str(skill_dir)
        cached = ctx._collected_skill_files.get(cache_key)
        if cached is not None:
            return cached

    if skill_dir.is_file():
        # Anchor relative paths / traversal checks on the parent dir, same as
        # is_safe_tar_member expects a directory, never the archive file itself.
        base_dir = skill_dir.parent
        files = [skill_dir]
    else:
        base_dir = skill_dir
        _skips: list = []
        files = walk_dir_safely(
            base_dir, exclude_pycache=True, exclude_vcs=True, max_files=_MAX_FILES_PER_SKILL, skips=_skips
        )
        if ctx is not None and _skips:
            # F-061: a skill shipping `data -> ~/.ssh/id_rsa` or `-> ../../openclaw.json` used to
            # be skipped silently. Record the skip + its target so it surfaces as a WARN.
            for spath, reason in _skips:
                try:
                    rel = str(Path(spath).relative_to(base_dir))
                except (ValueError, OSError):
                    rel = spath
                ctx.symlink_skips.append(f"{rel}: {reason}")
                ctx.file_manifest.setdefault(rel, "skipped:" + reason.split(" ", 1)[0])
    collected = []

    for f in files:
        if not f.is_file():
            continue

        if ctx is not None:
            ctx.total_files_inspected += 1

        try:
            st_size = f.stat().st_size
        except OSError:
            continue

        relpath = str(f.relative_to(base_dir))
        
        # Read the first 4096 bytes to classify
        try:
            with open(f, "rb") as fp:
                header = fp.read(4096)
        except OSError:
            continue
            
        classification, format_name = classify_bytes(header, st_size)
        
        is_archive = format_name in ("ZIP", "tar", "gzip", "bz2", "xz")
        
        if is_archive:
            if st_size > 10 * 1024 * 1024:
                if ctx is not None:
                    ctx.limit_hits.append(f"Compressed size of archive {f.name} exceeds 10MB")
                    ctx.file_manifest[relpath] = "capped(size)"
                continue
        else:
            if st_size > _MAX_FILE_BYTES:
                if ctx is not None:
                    ctx.limit_hits.append(f"File {f.name} size exceeds {_MAX_FILE_BYTES} bytes")
                    ctx.file_manifest[relpath] = "capped(size)"
                continue

        # Read the whole file bytes
        try:
            file_bytes = f.read_bytes()
        except OSError:
            continue
            
        archive_stats = {
            "total_files_count": 0,
            "cumulative_decompressed_size": 0,
            "compressed_size": len(file_bytes),
        }
        
        # Recursively decompress and classify
        extracted = decompress_and_classify(
            ctx, base_dir, file_bytes, relpath, depth=1, archive_stats=archive_stats
        )
        
        for sub_relpath, sub_bytes, sub_class, sub_fmt in extracted:
            mismatch_err = check_mismatch(sub_relpath, sub_class, sub_fmt, sub_bytes)
            if mismatch_err and ctx is not None:
                ctx.mismatches.append(f"{sub_relpath}: {mismatch_err}")
                
            polyglot_err = check_polyglot(sub_relpath, sub_fmt, sub_bytes)
            if polyglot_err and ctx is not None:
                ctx.polyglots.append(f"{sub_relpath}: {polyglot_err}")
                
            if sub_class == "BINARY":
                if ctx is not None:
                    ctx.excluded_binary_files_count += 1
                    ctx.binary_files.append(sub_relpath)
                    # F-054: a native executable (ELF/PE/Mach-O/JVM class) bundled inside a
                    # skill is a stowaway — skills are text/config; a compiled binary the
                    # prose doesn't need has no business here. Recorded for a WARN.
                    if sub_fmt in ("ELF", "PE", "class", "pyc", "wasm") or (sub_fmt or "").startswith("Mach-O"):
                        ctx.stowaway_files.append(f"{sub_relpath} ({sub_fmt})")
            
            # Map statuses here!
            if ctx is not None:
                if sub_relpath not in ctx.file_manifest:
                    if sub_relpath.lower().endswith(".py"):
                        ctx.file_manifest[sub_relpath] = "scanned-ast"
                    elif sub_class == "TEXT":
                        ctx.file_manifest[sub_relpath] = "scanned-text"
                    else:
                        if sub_fmt not in ("ZIP", "tar", "gzip", "bz2", "xz"):
                            ctx.file_manifest[sub_relpath] = "binary-strings"
            
            collected.append({
                "relpath": sub_relpath,
                "content": sub_bytes,
                "classification": sub_class,
                "format": sub_fmt,
            })

    # F-061: flag filenames carrying homoglyph / RTL-override / zero-width obfuscation
    # (e.g. a Cyrillic-lookalike `helper.py`). Same detector used for MCP server names.
    if ctx is not None:
        for item in collected:
            if obfuscation_signals(item["relpath"]):
                ctx.filename_obfuscations.append(item["relpath"])

    if ctx is not None:
        ctx._collected_skill_files[str(skill_dir)] = collected

    return collected


# B-086: extensions/names scanned before the size/file cap can be hit. SKILL.md is
# always the highest-signal file; executable/script extensions are the next most
# likely place a real payload lives. Everything else keeps its original (alphabetical)
# relative order — the sort is stable, so ties are unaffected.
_HIGH_PRIORITY_SCAN_EXTS = (".sh", ".bash", ".py", ".mjs", ".js", ".ps1")


def _skill_scan_priority(item: dict) -> tuple[int, str]:
    relpath = item.get("relpath", "")
    name = Path(relpath).name
    if name == "SKILL.md":
        tier = 0
    elif name.lower().endswith(_HIGH_PRIORITY_SCAN_EXTS):
        tier = 1
    else:
        tier = 2
    return (tier, relpath)


def _read_skill_text(skill_dir: Path, ctx: Context | None = None) -> str:
    """Concatenate the text/code files of one installed skill (capped, read-only).

    B-086: files are scanned in RISK-PRIORITY order, not the raw alphabetical walk
    order — SKILL.md first, then executable/script extensions, then everything
    else (stable within each tier). A padded low-risk decoy file (e.g. `AAA_ref.md`)
    can no longer push a genuinely higher-signal file out of the scan budget just
    by sorting first alphabetically. Does not mutate collect_skill_files's own
    (cached) ordering — only this local copy.
    """
    collected = sorted(collect_skill_files(skill_dir, ctx), key=_skill_scan_priority)
    parts = []
    total = 0
    file_count = 0
    truncated = False

    for item in collected:
        if total >= _MAX_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            truncated = True  # B-074: more content existed than we scanned
            break
        if item["classification"] != "TEXT":
            continue

        text = item["content"].decode(encoding="utf-8", errors="replace")
        budget = _MAX_BYTES_PER_SKILL - total
        if len(text) > budget:
            truncated = True  # this file was sliced — its tail is unscanned
            # F-087: sample the CUT tail (bounded — never re-reads the whole file) and
            # measure its entropy. Low-entropy filler is the shape of deliberate
            # cap-evasion padding; a real high-entropy asset leaves no anomaly signal.
            tail_sample = text[budget : budget + _ENTROPY_SAMPLE_BYTES]
            if (
                ctx is not None
                and len(tail_sample) >= _ENTROPY_MIN_SAMPLE
                and _shannon_entropy_bits(tail_sample) < _PADDING_ENTROPY_THRESHOLD
            ):
                ctx.padding_anomalies.append(skill_dir.name)
        chunk = text[:budget]
        parts.append(f"# file: {Path(item['relpath']).name}\n{chunk}")
        total += len(chunk)
        file_count += 1

    # B-074: silent truncation reads as "fully covered" and lets a payload padded past the
    # cap escape. Record the cap hit so check_installed_skills surfaces UNKNOWN, not PASS.
    if truncated and ctx is not None:
        ctx.limit_hits.append(
            f"text scan of skill '{skill_dir.name}' hit the "
            f"{_MAX_BYTES_PER_SKILL // 1000}KB/{_MAX_FILES_PER_SKILL}-file cap — "
            "content beyond the cap was NOT scanned")

    return "\n".join(parts)


# B-267: budgets for skill_tree_signature() — the CHANGE-DETECTION walk, deliberately
# separate from and far wider than the malware-SCAN budgets above. The scan caps exist to
# bound regex/AST/entropy work on attacker-supplied content; fingerprinting costs one
# streamed sha256 per file, so it can cover ground the scanner never will. Measured on the
# real ~/.openclaw: the largest installed skill is 2,190 files / 7.5MB and fingerprints in
# ~0.65s — comfortably inside both budgets, and paid only on a --monitor run (snapshot() is
# the sole caller), never on a plain audit.
_SIG_MAX_FILES = 20_000
_SIG_MAX_TOTAL_BYTES = 200_000_000
_SIG_CHUNK = 1 << 20


def skill_tree_signature(skill_dir: Path) -> dict:
    """Fingerprint EVERY file under one skill directory, independent of the scan budget.

    Returns ``{"digest": str, "files": int, "bytes": int, "complete": bool}``.

    B-267: ``_read_skill_text`` builds the blob the audit SCANS — TEXT-classified files
    only, truncated at ``_MAX_BYTES_PER_SKILL``, with any single file over
    ``_MAX_FILE_BYTES`` dropped whole before the budget logic ever sees it. Hashing that
    blob (which is what monitor's ``_skill_sig`` used to do, alone) answers "did the part
    we scanned change?", and monitor was reporting the answer as "did the skill change?".
    Those differ precisely where it matters: swapping ``bin/helper`` (non-TEXT), appending
    a directive to a file past the per-skill budget, or editing inside an oversized
    ``REFERENCE.md`` all leave the scanned blob byte-identical. Verified first-hand — all
    three produced ZERO monitor alerts before this function existed.

    Change detection does not need the scan budget, so this walk does not inherit it. Each
    file contributes ``relpath\\0size\\0sha256(content)`` to a canonical, sorted fold, so
    the digest moves on any content edit, size change, addition, removal or rename —
    including in regions no scanner will ever read.

    ``complete`` is False when the walk itself hit ``_SIG_MAX_FILES`` /
    ``_SIG_MAX_TOTAL_BYTES``, i.e. part of the tree was never fingerprinted. An UNCHANGED
    digest is proof of no change only when ``complete`` is True; callers must treat the
    incomplete case as unknown rather than as evidence of stability (same discipline B-074
    applies to a truncated scan).

    NARROWS, does not close — two blind spots remain, both inherited deliberately:

    * ``__pycache__`` and VCS metadata (``.git``/``.hg``/``.svn``) are excluded, matching
      ``collect_skill_files``'s existing B-125 boundary. They are already outside the
      audited surface, and including them would fire a "skill CHANGED" alert on every
      ``git status`` or interpreter run — a false positive on ordinary use. A payload
      parked *only* inside ``.git/`` is therefore still invisible here, exactly as it is
      to every other part of the audit.
    * Symlinks are skipped (``walk_dir_safely``), so re-pointing a symlink inside a skill
      does not move the digest. Symlink entries are separately surfaced as tamper signals
      by F-061's ``symlink_skips``.

    Read-only and never raises: an unreadable file folds in a stable ``unreadable`` marker
    (stable, so a persistently chmod-000 file does not flap an alert every run) rather
    than being dropped silently, which would make it indistinguishable from a deletion.
    """
    capped: list = []
    files = walk_dir_safely(
        skill_dir,
        exclude_pycache=True,
        exclude_vcs=True,
        max_files=_SIG_MAX_FILES,
        capped=capped,
    )
    entries: list[tuple[str, str]] = []
    total = 0
    complete = not capped
    for f in sorted(files):
        try:
            rel = str(f.relative_to(skill_dir))
        except (ValueError, OSError):
            rel = f.name
        try:
            if not f.is_file():
                continue
            size = f.stat().st_size
        except OSError:
            entries.append((rel, "unreadable"))
            continue
        if total + size > _SIG_MAX_TOTAL_BYTES:
            # Budget exhausted: record the file's existence and size (both still real
            # evidence) but not its content digest, and declare the walk incomplete.
            entries.append((rel, f"{size}:uncovered"))
            complete = False
            continue
        digest = hashlib.sha256()
        try:
            with open(f, "rb") as fh:
                while True:
                    chunk = fh.read(_SIG_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
        except OSError:
            entries.append((rel, "unreadable"))
            continue
        total += size
        entries.append((rel, f"{size}:{digest.hexdigest()}"))

    fold = hashlib.sha256()
    for rel, mark in sorted(entries):
        fold.update(rel.encode("utf-8", "replace"))
        fold.update(b"\x00")
        fold.update(mark.encode("ascii", "replace"))
        fold.update(b"\n")
    return {
        "digest": fold.hexdigest()[:32],
        "files": len(entries),
        "bytes": total,
        "complete": complete,
    }


def _ipynb_code_source(text: str, skill_name: str, ctx: "Context | None") -> str | None:
    """F-116: concatenate the source of a Jupyter notebook's `code` cells so the AST/taint
    engine (which otherwise sees only .py/.sh/.js) can analyze them. Returns joined Python
    source, or None when the notebook JSON can't be parsed — in which case a limit_hit is
    recorded so the AST layer degrades to UNKNOWN (AST_UNANALYZABLE), never a false PASS."""
    try:
        nb = json.loads(text)
        cells = nb["cells"]
        if not isinstance(cells, list):
            raise ValueError("cells is not a list")
    except (ValueError, KeyError, TypeError):
        if ctx is not None:
            ctx.limit_hits.append(
                f"notebook in skill '{skill_name}' could not be parsed — its code cells "
                "were NOT analyzed (AST_UNANALYZABLE)"
            )
        return None
    parts: list[str] = []
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        src = cell.get("source")
        if isinstance(src, list):
            parts.append("".join(s for s in src if isinstance(s, str)))
        elif isinstance(src, str):
            parts.append(src)
    return "\n".join(parts)


def read_skill_python(skill_dir: Path, ctx: Context | None = None) -> list[tuple[str, str]]:
    """Collect the Python source files of one skill for read-only AST analysis.

    Returns a list of (relative-path, source) pairs. F-116: Jupyter `.ipynb` notebooks are
    included — their code cells are routed to the SAME engine as `.py`.
    """
    collected = collect_skill_files(skill_dir, ctx)
    out: list[tuple[str, str]] = []
    total = 0
    file_count = 0
    truncated = False

    for item in collected:
        if total >= _MAX_PY_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            truncated = True
            break
        if item["classification"] != "TEXT":
            continue
        rel = item["relpath"].lower()
        if not rel.endswith((".py", ".ipynb")):
            continue

        text = item["content"].decode(encoding="utf-8", errors="replace")
        if rel.endswith(".ipynb"):
            # F-116: route the notebook's code cells through the same AST/taint engine as .py.
            src = _ipynb_code_source(text, skill_dir.name, ctx)
            if src is None:
                continue  # malformed notebook -> limit_hit recorded; degrade to UNKNOWN
            text = src
        out.append((item["relpath"], text))
        total += len(text)
        file_count += 1

    # B-074: record when Python collection was capped so the AST/taint layer's blind spot
    # (unscanned .py beyond the cap) surfaces as UNKNOWN rather than a clean PASS.
    if truncated and ctx is not None:
        ctx.limit_hits.append(
            f"Python scan of skill '{skill_dir.name}' hit the "
            f"{_MAX_PY_BYTES_PER_SKILL // 1000}KB/{_MAX_FILES_PER_SKILL}-file cap — "
            ".py content beyond the cap was NOT analyzed")

    return out


def read_skill_shell(skill_dir: Path, ctx: Context | None = None) -> list[tuple[str, str]]:
    """Collect the shell source files (.sh/.bash/.zsh) of one skill for a read-only
    regex/token pass (F-050). Returns a list of (relative-path, source) pairs. Same byte /
    file caps as the Python collector so a padded bundle can't blow up the scan."""
    collected = collect_skill_files(skill_dir, ctx)
    out: list[tuple[str, str]] = []
    total = 0
    file_count = 0
    truncated = False
    for item in collected:
        if total >= _MAX_PY_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            truncated = True
            break
        if item["classification"] != "TEXT":
            continue
        if not item["relpath"].lower().endswith((".sh", ".bash", ".zsh")):
            continue
        text = item["content"].decode(encoding="utf-8", errors="replace")
        out.append((item["relpath"], text))
        total += len(text)
        file_count += 1

    # B-074: record when shell collection was capped so a padded shell payload beyond the
    # cap surfaces as UNKNOWN rather than a clean PASS (mirrors read_skill_python).
    if truncated and ctx is not None:
        ctx.limit_hits.append(
            f"shell scan of skill '{skill_dir.name}' hit the "
            f"{_MAX_PY_BYTES_PER_SKILL // 1000}KB/{_MAX_FILES_PER_SKILL}-file cap — "
            "shell content beyond the cap was NOT scanned")

    return out


def read_skill_js(skill_dir: Path, ctx: Context | None = None) -> list[tuple[str, str]]:
    """Collect the JS/TS source files (.js/.ts/.mjs/.cjs) of one skill for a read-only
    lexical pass (F-064). Returns a list of (relative-path, source) pairs. Same byte /
    file caps as the Python and shell collectors so a padded bundle can't blow up the scan."""
    collected = collect_skill_files(skill_dir, ctx)
    out: list[tuple[str, str]] = []
    total = 0
    file_count = 0
    truncated = False
    for item in collected:
        if total >= _MAX_PY_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            truncated = True
            break
        if item["classification"] != "TEXT":
            continue
        if not item["relpath"].lower().endswith((".js", ".ts", ".mjs", ".cjs")):
            continue
        text = item["content"].decode(encoding="utf-8", errors="replace")
        out.append((item["relpath"], text))
        total += len(text)
        file_count += 1

    # B-074: record when JS collection was capped so a padded JS payload beyond the cap
    # surfaces as UNKNOWN rather than a clean PASS (mirrors read_skill_python/read_skill_shell).
    if truncated and ctx is not None:
        ctx.limit_hits.append(
            f"js scan of skill '{skill_dir.name}' hit the "
            f"{_MAX_PY_BYTES_PER_SKILL // 1000}KB/{_MAX_FILES_PER_SKILL}-file cap — "
            "js content beyond the cap was NOT scanned")

    return out


def _config_workspace_dirs(
    home: Path, cfg: dict, limit_hits: list[str] | None = None
) -> list[Path]:
    """Absolute workspace dir(s) declared in openclaw.json (B-161).

    OpenClaw's ``agents.defaults.workspace`` — and any per-agent
    ``agents.list[].workspace`` override — can point the agent's workspace outside the
    hardcoded WORKSPACE_DIRS names. Bootstrap files and a ``skills/`` dir living there
    would otherwise be invisible, so a malicious SOUL.md / skill in a custom workspace
    scored clean. Returns de-duplicated absolute, RESOLVED dirs (relative paths resolved
    against *home*). Never raises; blank / non-string values are skipped. When the value
    points at the default location it resolves to a path SKILL_DIRS already covers, so
    nothing is scanned twice (see the resolved-path de-dup in the callers).

    B-169: real OpenClaw does not confine ``workspace`` under the user's home
    (``resolveUserPath`` has no home-check), so a workspace that resolves OUTSIDE *home*
    is legitimate and MUST still be scanned — rejecting it would be a false-positive
    FAIL/skip (Golden Rule #5). Instead, when *limit_hits* is given and a workspace
    resolves outside *home*, one de-duplicated disclosure line is appended so the report
    stays transparent about the scan's actual scope.
    """
    if not isinstance(cfg, dict):
        return []
    raw: list[str] = []
    dv = dig(cfg, "agents.defaults.workspace")
    if isinstance(dv, str) and dv.strip():
        raw.append(dv)
    agents_list = dig(cfg, "agents.list")
    if isinstance(agents_list, list):
        for a in agents_list:
            if isinstance(a, dict):
                w = a.get("workspace")
                if isinstance(w, str) and w.strip():
                    raw.append(w)
    try:
        resolved_home = home.resolve()
    except (OSError, ValueError, RuntimeError):
        resolved_home = home
    out: list[Path] = []
    seen: set[Path] = set()
    for r in raw:
        p = Path(r).expanduser()
        if not p.is_absolute():
            p = home / p
        try:
            resolved = p.resolve()
        except (OSError, ValueError, RuntimeError):
            # An unusable workspace path — embedded null byte (ValueError), symlink loop /
            # over-deep (RuntimeError), or an OS error — must be skipped, never crash the
            # audit. Dropping it here also stops a later is_dir() from raising on it (C-135).
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if limit_hits is not None:
            try:
                in_home = resolved.is_relative_to(resolved_home)
            except (OSError, ValueError):
                in_home = False
            if not in_home:
                msg = (
                    f"custom workspace '{resolved.name}' resolves outside the audited "
                    f"--home ({resolved}) — bootstrap/skills read from there are outside "
                    "the scoped audit"
                )
                if msg not in limit_hits:
                    limit_hits.append(msg)
        out.append(resolved)
    return out


def _is_own_source(p: Path) -> bool:
    """True if `p` is ClawSecCheck's own source tree (repo root, install dir, or the
    package dir itself). A security auditor necessarily ships attack signatures and
    red-team payloads as *data*, so a naive malware scan of its own source self-flags.

    Recognition is by structure (package layout) AND distinctive engine symbols — not
    by name alone — so a look-alike skill that merely calls itself "clawseccheck" is
    still scanned normally and cannot use the name to dodge detection.

    B-265: this is the single self-identity oracle for BOTH surfaces. It used to be
    reachable only from `vet_skill` (it lived in `checks/_shared.py`, a Layer-2 module
    the Layer-1 collector must not import), while skill *discovery* self-excluded on the
    bare directory basename. That let `mv evil-skill clawshield` erase a skill from
    `ctx.installed_skills` — and therefore from the whole audit and from --monitor —
    with no frontmatter edit, while --vet pointed at the same bytes still said
    "F (DANGEROUS)". Moving it down here (the same precedent as `_OWN_SKILL_NAMES`,
    already collector-resident) keeps the import direction legal and makes the two
    surfaces agree. `checks/_shared.py` re-imports it, so `vet_skill`'s behaviour and
    the `clawseccheck.checks` aggregator re-export (§3.1-a) are unchanged.

    HONEST SCOPE — this CLOSES the rename-only cloak but does not make self-exclusion
    unforgeable: an attacker who copies our actual engine sources (all of
    `_OWN_ENGINE_MARKERS` present, in a `checks/` package laid out like ours) alongside
    a payload would still be excluded. That residual is strictly narrower than the old
    one — it costs the attacker shipping our whole engine rather than one `mv` — and it
    is bounded further by `check_installed_skills` being only one of the surfaces that
    sees a skill. Making exclusion tamper-proof needs a signed/attested identity, not a
    content heuristic; tracked separately, not solvable inside a static string test.

    C-135 residual, accepted deliberately: an own install that ships the DOCS but not the
    engine (a hand-made partial copy — `SKILL.md` + `README.md` + `docs/` under a
    `clawseccheck/` dir with no `clawseccheck/checks/`) is no longer excluded, so the
    audit scans our own prose, which necessarily quotes attack payloads, and self-flags.
    Not a shipped shape: both documented installs put the engine on disk (ClawHub installs
    the whole tree — pyproject `packages` includes `clawseccheck.checks` — and the pipx
    route creates no skill dir at all), and a docs-only copy has no working console script.
    Verified against the real `~/.openclaw` install, which recognises correctly. Left
    unmitigated on purpose: every candidate fix keys on copyable doc content, which is
    exactly the forgeable-identity mistake this change exists to remove. Failing closed
    (scan what we cannot verify) is the safe direction; the old behaviour here was a
    lying PASS that let a payload hide behind a copy of our README. Pinned by
    `tests/test_b265_ownname_content_exclusion.py::test_docs_only_own_install_is_scanned`.
    """
    # The engine is the checks/ package (current) or a legacy single-file checks.py.
    # Read every engine source so the markers are found regardless of which topic module
    # the I-022 split scattered them into.
    if (p / "clawseccheck" / "checks").is_dir():  # repo root / install dir (package)
        sources = sorted((p / "clawseccheck" / "checks").glob("*.py"))
    elif (p / "clawseccheck" / "checks.py").is_file():  # repo root / install dir (legacy)
        sources = [p / "clawseccheck" / "checks.py"]
    elif p.name.lower() in _OWN_SKILL_NAMES and (p / "checks").is_dir():  # package dir
        sources = sorted((p / "checks").glob("*.py"))
    elif p.name.lower() in _OWN_SKILL_NAMES and (p / "checks.py").is_file():  # package dir (legacy)
        sources = [p / "checks.py"]
    else:
        return False
    try:
        head = "\n".join(s.read_text(encoding="utf-8", errors="replace") for s in sources)
    except OSError:
        return False
    return all(m in head for m in _OWN_ENGINE_MARKERS)


def _read_installed_skills(home: Path, ctx: Context) -> None:
    seen: set[str] = set()
    # (base_dir, allow_symlink_entries). The hardcoded roots refuse symlinked skill dirs —
    # a planted symlink is a tamper signal — but plugin-skills entries are *deliberately*
    # symlinks into a plugin's bundled skills/ dir, so those get dereferenced (B-161).
    roots: list[tuple[Path, bool]] = [(home / rel, False) for rel in SKILL_DIRS]
    # OpenClaw also loads personal cross-agent skills from ~/.agents/skills. Only add
    # this global root when auditing an actual profile directory under the user's home;
    # fixture/custom --home scans must remain hermetic and never absorb unrelated skills.
    try:
        user_home = Path.home().resolve()
        audited_home = home.resolve()
    except (OSError, ValueError, RuntimeError):
        user_home = None
        audited_home = None
    if (
        user_home is not None
        and audited_home is not None
        and audited_home.parent == user_home
        and audited_home.name.startswith(".openclaw")
    ):
        roots.append((user_home / ".agents" / "skills", False))
    for cw in _config_workspace_dirs(home, ctx.config, limit_hits=ctx.limit_hits):
        roots.append((cw / "skills", False))
    roots.extend((path, False) for path in _config_extra_skill_dirs(home, ctx.config))
    # F-119: plugins.load.paths (a real dist key) — a path-loaded plugin bundles skills under
    # <plugin>/skills/ that enter the auto-load surface; discover them so they're scanned like
    # any other installed skill instead of being silently invisible.
    roots.extend((pp / "skills", False) for pp in _config_plugin_load_paths(home, ctx.config))
    plugin_skills = home / "plugin-skills"
    if plugin_skills.is_dir():
        roots.append((plugin_skills, True))
    seen_roots: set[Path] = set()
    for base, allow_symlink in roots:
        if not base.is_dir():
            continue
        try:
            base_key = base.resolve()
        except (OSError, ValueError, RuntimeError):
            base_key = base
        if base_key in seen_roots:
            continue
        seen_roots.add(base_key)
        for sd, target in _iter_discovered_skill_dirs(
            base, allow_symlink_entries=allow_symlink, limit_hits=ctx.limit_hits
        ):
            if len(ctx.installed_skills) >= _MAX_SKILLS:
                # B-268: this used to `return` — the collection stopped dead, leaving
                # ctx.installed_skills a silently truncated view with no trace that more
                # existed. Two consumers then read that view as filesystem ground truth:
                # monitor's skill diff reported every uncollected name as "was removed"
                # (measured: 310 skills + one early-sorting addition => a phantom
                # "Skill 's299' was removed"), and the inventory line printed its length
                # as the installed total. Worse, discovery order is filename order, which
                # is ATTACKER-CONTROLLED: flooding aaa*-named skills pushes a real one out
                # of the scanned set entirely, and nothing recorded a limit hit, so B13
                # still reported a clean verdict over a scan that never saw it.
                #
                # Keep walking so the frontier is EXACT — the skipped dirs are only
                # enumerated (a bounded directory listing, already capped by
                # skilldiscovery's _MAX_DIRS), never read, so the cap still does its job
                # of bounding content work.
                ctx.skills_capped_count += 1
                if len(ctx.skills_capped_names) < _MAX_SKILL_FRONTIER_NAMES:
                    ctx.skills_capped_names.append(sd.name)
                else:
                    ctx.skills_frontier_partial = True
                continue
            # B-265: self-exclusion is CONTENT-verified, never basename-verified. Test the
            # resolved `target` (the real bytes), not `sd` — a symlinked plugin-skills entry
            # must be judged by what it points at. A malicious skill renamed to an own-skill
            # name now enters the inventory and is audited like any other.
            if _is_own_source(target):
                continue
            key = sd.name
            if key in seen:
                try:
                    rel = sd.relative_to(base).as_posix()
                except ValueError:
                    rel = sd.name
                key = f"{base.name}/{rel}"
                suffix = 2
                original = key
                while key in seen:
                    key = f"{original}#{suffix}"
                    suffix += 1
            seen.add(key)
            try:
                ctx.installed_skills[key] = _read_skill_text(target, ctx)
                ctx.installed_skill_py[key] = read_skill_python(target, ctx)
                ctx.installed_skill_shell[key] = read_skill_shell(target, ctx)
                ctx.installed_skill_js[key] = read_skill_js(target, ctx)
                ctx.installed_skill_dirs[key] = target
            except OSError as exc:
                ctx.errors.append(f"could not read skill {key}: {exc}")

    # B-268: record the cap hit, mirroring what skilldiscovery.py already does for its
    # sibling _MAX_DIRS cap. This is what makes check_installed_skills (B13) degrade to
    # UNKNOWN instead of reporting a clean PASS over a scan that never reached the skills
    # beyond the cap — the existing B-074 discipline, which this cap alone was bypassing.
    if ctx.skills_capped_count:
        ctx.limit_hits.append(
            f"installed-skill collection hit the {_MAX_SKILLS}-skill cap — "
            f"{ctx.skills_capped_count} further skill director"
            f"{'y was' if ctx.skills_capped_count == 1 else 'ies were'} NOT read"
        )


# Skill-load tiers in PRECEDENCE order, HIGHEST-WINS first. Grounded against the dist loader
# (openclaw dist workspace-*.js — every discovered skill is merged into one global Map keyed by
# declared `name:`, so the LAST-merged root silently overwrites — "shadows" — any same-named
# skill from an earlier root, with NO warning). Precedence highest→lowest: workspace >
# project-agent > personal-agent > managed (~/.openclaw/skills) > bundled(dist) > extraDirs /
# plugins.load.paths. The audit sees the home-rooted tiers below; the bundled-dist tier lives
# outside the home and is not scanned.
SKILL_TIER_ORDER = ("workspace", "project-agent", "personal-agent", "managed", "extra/plugin")


def skill_load_roots(
    home: Path, cfg: dict | None = None, *, user_home: Path | None = None
) -> list[tuple[Path, str]]:
    """Return ``(root_dir, tier)`` for every skill-load root the audit can see, in PRECEDENCE
    order — highest-precedence (the tier that WINS a name collision) FIRST. Resolved-path
    de-duped so one physical dir is never listed twice (the highest-precedence alias wins).
    Read-only; never raises. Used by B104 to flag cross-tier NAME shadowing (a planted
    higher-precedence copy silently overriding a trusted skill). ``user_home`` adds the
    personal ``~/.agents/skills`` tier — pass it only when auditing a real ``~/.openclaw``
    profile, so fixture/custom --home scans stay hermetic (mirrors ``_read_installed_skills``)."""
    cfg = cfg if isinstance(cfg, dict) else {}
    ordered: list[tuple[Path, str]] = []
    # workspace tier (highest): default workspace names under home + any custom workspace.
    for rel in ("workspace/skills", "workspace-home/skills", "workspace-work/skills"):
        ordered.append((home / rel, "workspace"))
    for cw in _config_workspace_dirs(home, cfg):
        ordered.append((cw / "skills", "workspace"))
    # agent tiers.
    ordered.append((home / ".agents" / "skills", "project-agent"))
    if user_home is not None:
        ordered.append((user_home / ".agents" / "skills", "personal-agent"))
    # managed tier (~/.openclaw/skills).
    ordered.append((home / "skills", "managed"))
    # extra/plugin tier (lowest): skills.load.extraDirs + plugins.load.paths + plugin-skills.
    for d in _config_extra_skill_dirs(home, cfg):
        ordered.append((d, "extra/plugin"))
    for pp in _config_plugin_load_paths(home, cfg):
        ordered.append((pp / "skills", "extra/plugin"))
    ordered.append((home / "plugin-skills", "extra/plugin"))
    # Resolved-path de-dup — keep the first (highest-precedence) occurrence of each dir.
    out: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for path, tier in ordered:
        try:
            key = path.resolve()
        except (OSError, ValueError, RuntimeError):
            key = path
        if key in seen:
            continue
        seen.add(key)
        out.append((path, tier))
    return out


def _collect_cron(home: Path, ctx: Context) -> None:
    """B-231 sub-item 1: read-only, symlink-safe, size/entry-capped collection of the
    OpenClaw cron job store into ``ctx.cron_jobs``.

    Two backing stores exist (grounded against the openclaw dist): the legacy JSON file
    ``~/.openclaw/cron/jobs.json`` (``{"version": 1, "jobs": [CronJobSchema, ...]}``,
    each job's ``payload``/``trigger`` sub-objects carrying ``message``/``script``), and
    the SQLite-backed ``cron_jobs`` table in ``~/.openclaw/state/openclaw.sqlite``
    (``job_id``, ``name``, ``enabled``, ``delete_after_run``, ``trigger_script``,
    ``payload_kind``, ``payload_message`` columns). The JSON file is preferred when
    present; the SQLite table is a read-only fallback. Neither present leaves
    ``ctx.cron_found`` False, so a consuming check reports UNKNOWN, never a fake PASS.

    Both branches resolve candidate files through ``safeio.walk_dir_safely`` — symlinks
    and path-escapes are skipped, matching every other collector read.
    """
    cron_dir = home / "cron"
    json_candidates = walk_dir_safely(cron_dir, max_files=50) if cron_dir.is_dir() else []
    jobs_json = next((p for p in json_candidates if p.name == "jobs.json"), None)
    if jobs_json is not None:
        try:
            with open(jobs_json, "rb") as fp:
                raw, truncated = _read_with_limit(fp, _MAX_CRON_BYTES)
            if truncated:
                ctx.limit_hits.append(
                    f"cron store '{jobs_json}' exceeded the "
                    f"{_MAX_CRON_BYTES // 1_000_000}MB cap — content beyond the cap "
                    "was NOT scanned"
                )
            store = json.loads(raw.decode("utf-8", errors="replace"))
            jobs = store.get("jobs") if isinstance(store, dict) else None
            if not isinstance(jobs, list):
                jobs = []
            ctx.cron_found = True
            for job in jobs[:_MAX_CRON_JOBS]:
                if not isinstance(job, dict):
                    continue
                payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
                trigger = job.get("trigger") if isinstance(job.get("trigger"), dict) else {}
                ctx.cron_jobs.append({
                    "id": job.get("id"),
                    "name": job.get("name"),
                    "enabled": job.get("enabled"),
                    "delete_after_run": job.get("deleteAfterRun"),
                    "trigger_script": trigger.get("script"),
                    "payload_kind": payload.get("kind"),
                    "payload_message": payload.get("message"),
                })
            if len(jobs) > _MAX_CRON_JOBS:
                ctx.limit_hits.append(
                    f"cron store '{jobs_json}' has {len(jobs)} jobs — only the first "
                    f"{_MAX_CRON_JOBS} were scanned"
                )
        except (OSError, ValueError) as exc:
            ctx.errors.append(f"could not parse {jobs_json}: {exc}")
            ctx.cron_found = True
            ctx.cron_parse_error = True
        return

    # No legacy JSON store -- fall back to the SQLite-backed cron_jobs table.
    state_dir = home / "state"
    sqlite_candidates = walk_dir_safely(state_dir, max_files=100) if state_dir.is_dir() else []
    db_path = next((p for p in sqlite_candidates if p.name == "openclaw.sqlite"), None)
    if db_path is None:
        return  # neither store present -> cron_found stays False (UNKNOWN, not a fake PASS)

    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            cur = conn.execute(
                "SELECT job_id, name, enabled, delete_after_run, trigger_script, "
                "payload_kind, payload_message FROM cron_jobs LIMIT ?",
                (_MAX_CRON_JOBS,),
            )
            rows = cur.fetchall()
        finally:
            conn.close()
        ctx.cron_found = True
        for job_id, name, enabled, delete_after_run, trigger_script, payload_kind, payload_message in rows:
            ctx.cron_jobs.append({
                "id": job_id,
                "name": name,
                "enabled": bool(enabled) if enabled is not None else None,
                "delete_after_run": bool(delete_after_run) if delete_after_run is not None else None,
                "trigger_script": trigger_script,
                "payload_kind": payload_kind,
                "payload_message": payload_message,
            })
    except sqlite3.Error as exc:
        # A state DB that exists but has no cron_jobs table yet (a fresh install where
        # cron was never touched) is not a corrupt store -- treat like "not found" so the
        # check reports the same honest UNKNOWN as no store at all, not a parse error.
        if "no such table" not in str(exc).lower():
            ctx.errors.append(f"could not read cron_jobs from {db_path}: {exc}")
            ctx.cron_found = True
            ctx.cron_parse_error = True


def _collect_exec_approvals(home: Path, ctx: Context) -> None:
    """B-236 (B172): read-only collection of the standing OpenClaw exec-approvals
    store (~/.openclaw/exec-approvals.json) into ``ctx.exec_approvals_grants``.

    Grounded against the installed dist (exec-approvals-BIKWP8_V.js): the file is a
    single top-level JSON object (written by OpenClaw itself via JSON.stringify --
    never JSON5, so this reads it with plain ``json.loads``, not the config loader)
    shaped ``{version, socket, defaults: {security, ask, askFallback, autoAllowSkills},
    agents: {<agentId>: {security, ask, askFallback, allowlist: [{pattern, argPattern?,
    source, id, ...}]}}}``. An ``agents.<id>.allowlist[]`` entry with
    ``source == "allow-always"`` is a durable per-command exec approval persisted by a
    historical "always allow" click -- a standing grant living entirely outside
    openclaw.json that no check previously read (grep for "exec-approvals" across
    clawseccheck/ was zero hits before this).

    IMPORTANT (adversarially corrected during B-236's own review): OpenClaw computes
    the EFFECTIVE exec policy as minSecurity(tools.exec.security, execApprovals.security)
    + maxAsk(tools.exec.ask, execApprovals.ask) (bash-tools*.js:581-582;
    exec-approvals-BIKWP8_V.js:1126-1140 -- runtime comment "Stricter values from
    tools.exec and ...exec-approvals both apply"). A standing grant can only TIGHTEN
    the openclaw.json gate, never loosen it -- so this collector exists to make a
    persisted grant VISIBLE/inventoried (check_exec_approvals_grants, B172), not to
    imply it bypasses tools.exec (it provably does not).

    The file lives directly under ``home`` (a single fixed filename, not a
    subdirectory to walk), so this checks ``is_symlink()`` itself rather than reusing
    ``walk_dir_safely`` -- a symlinked store is treated as absent (never followed),
    matching that helper's own symlink policy without walking the whole home tree just
    to find one top-level file.

    ``ctx.exec_approvals_found`` stays False when the file is absent -- a consuming
    check reports UNKNOWN, never a fake PASS (Golden Rule #4, the B-228 pattern).
    """
    target = home / "exec-approvals.json"
    if target.is_symlink() or not target.is_file():
        return
    try:
        with open(target, "rb") as fp:
            raw, truncated = _read_with_limit(fp, _MAX_EXEC_APPROVALS_BYTES)
        if truncated:
            ctx.limit_hits.append(
                f"exec-approvals store '{target}' exceeded the "
                f"{_MAX_EXEC_APPROVALS_BYTES // 1_000_000}MB cap — content beyond the "
                "cap was NOT scanned"
            )
        store = json.loads(raw.decode("utf-8", errors="replace"))
        if not isinstance(store, dict):
            raise ValueError("exec-approvals.json root is not a JSON object")
        agents = store.get("agents")
        if not isinstance(agents, dict):
            agents = {}
        ctx.exec_approvals_found = True
        for agent_id, agent in list(agents.items())[:_MAX_EXEC_APPROVALS_AGENTS]:
            if not isinstance(agent, dict):
                continue
            allowlist = agent.get("allowlist")
            allow_always_count = 0
            if isinstance(allowlist, list):
                allow_always_count = sum(
                    1 for e in allowlist
                    if isinstance(e, dict) and e.get("source") == "allow-always"
                )
            security = agent.get("security")
            ask = agent.get("ask")
            ctx.exec_approvals_grants.append({
                "agent_id": agent_id if isinstance(agent_id, str) else str(agent_id),
                "security": security if isinstance(security, str) else None,
                "ask": ask if isinstance(ask, str) else None,
                "allow_always_count": allow_always_count,
            })
    except (OSError, ValueError) as exc:
        ctx.errors.append(f"could not parse {target}: {exc}")
        ctx.exec_approvals_found = True
        ctx.exec_approvals_parse_error = True


def _collect_plugin_trust(home: Path, ctx: Context) -> None:
    """B-240 (B177): read-only collection of OpenClaw's OWN persisted per-plugin ClawHub
    trust verdict into ``ctx.plugin_trust_records``.

    Grounded against the installed dist: OpenClaw persists a single-row
    ``installed_plugin_index`` table (primary key ``index_key = 'installed-plugin-index'``)
    in the shared state SQLite database, resolved to
    ``~/.openclaw/state/openclaw.sqlite`` (openclaw-state-db-DzSsA9Ji.js:
    resolveOpenClawStateSqlitePath -> <stateDir>/state/openclaw.sqlite; confirmed against
    the real file: SQLite 3.x, table present). Its ``install_records_json`` column is a
    JSON object keyed by pluginId (installed-plugin-index-store-CWgFGnm0.js:
    readPersistedInstalledPluginIndexFromSqlite); each install record MAY carry
    ``clawhubTrustDisposition`` ("clean" | "review-recommended" | "review-required" |
    "blocked" — types.openclaw-CXjMEWAQ.d.ts:1308), ``clawhubTrustScanStatus``,
    ``clawhubTrustModerationState``, ``clawhubTrustReasons`` (string[]),
    ``clawhubTrustPending``, ``clawhubTrustStale`` (installed-plugin-index-records-
    C_n191FN.js: CLAWHUB_TRUST_INSTALL_RECORD_FIELDS) — OpenClaw's own ClawHub malware-
    scan/moderation verdict for that install, computed at install/refresh time
    (clawhub-install-trust-DdnykQnp.js) and never previously read by ClawSecCheck (grep
    for "clawhubTrust"/"openclaw.sqlite" across clawseccheck/ was zero hits before this).

    The same state database also has ``auth_profile_stores``/``auth_profile_state`` tables
    (columns: store_key, store_json/state_json, updated_at) that plausibly hold live MCP
    OAuth credentials — this collector deliberately reads ONLY installed_plugin_index and
    never touches those tables; openclaw.sqlite itself should stay 0600 regardless (B11
    already covers general config/state-file permissions).

    Opened READ-ONLY via the ``file:...?mode=ro`` URI plus ``PRAGMA query_only = 1`` — this
    collector never writes to the shared state database. Reuses the exact
    ``walk_dir_safely(state_dir)`` + filename-match pattern ``_collect_cron`` already uses
    for the same file (symlink-safe, path-escape-safe).

    ``ctx.plugin_trust_found`` stays False when the state DB, the table, or the index row
    is absent — a consuming check reports UNKNOWN, never a fake PASS (Golden Rule #4).
    ``ctx.plugin_trust_parse_error`` is set when the DB/table/row exist but the column
    could not be read or parsed (locked DB, corrupt file, malformed JSON) — also surfaced
    as UNKNOWN downstream, never a crash.
    """
    state_dir = home / "state"
    sqlite_candidates = walk_dir_safely(state_dir, max_files=100) if state_dir.is_dir() else []
    db_path = next((p for p in sqlite_candidates if p.name == "openclaw.sqlite"), None)
    if db_path is None:
        return  # no state DB -> plugin_trust_found stays False (UNKNOWN, not a fake PASS)

    try:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only = 1")
            cur = conn.execute(
                "SELECT install_records_json FROM installed_plugin_index "
                "WHERE index_key = 'installed-plugin-index'"
            )
            row = cur.fetchone()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        # A state DB that exists but predates the plugin index (no such table) is not a
        # corrupt store -- same honest UNKNOWN as "not found", not a parse error (mirrors
        # _collect_cron's identical "no such table" carve-out).
        if "no such table" not in str(exc).lower():
            ctx.errors.append(
                f"could not read installed_plugin_index from {db_path}: {exc}"
            )
            ctx.plugin_trust_found = True
            ctx.plugin_trust_parse_error = True
        return

    if row is None or row[0] is None:
        return  # DB + table present, but no index row persisted yet -> stays UNKNOWN

    raw = row[0]
    if len(raw) > _MAX_PLUGIN_TRUST_BYTES:
        ctx.limit_hits.append(
            f"installed_plugin_index.install_records_json in {db_path} exceeded the "
            f"{_MAX_PLUGIN_TRUST_BYTES // 1_000_000}MB cap — content beyond the cap was "
            "NOT scanned"
        )
        raw = raw[:_MAX_PLUGIN_TRUST_BYTES]

    try:
        installs = json.loads(raw)
    except ValueError as exc:
        ctx.errors.append(f"could not parse install_records_json in {db_path}: {exc}")
        ctx.plugin_trust_found = True
        ctx.plugin_trust_parse_error = True
        return
    if not isinstance(installs, dict):
        ctx.plugin_trust_found = True
        ctx.plugin_trust_parse_error = True
        return

    ctx.plugin_trust_found = True
    for plugin_id, rec in list(installs.items())[:_MAX_PLUGIN_TRUST_RECORDS]:
        if not isinstance(rec, dict):
            continue
        disposition = rec.get("clawhubTrustDisposition")
        reasons = rec.get("clawhubTrustReasons")
        ctx.plugin_trust_records.append({
            "plugin_id": plugin_id if isinstance(plugin_id, str) else str(plugin_id),
            "disposition": disposition if isinstance(disposition, str) else None,
            "scan_status": rec.get("clawhubTrustScanStatus")
            if isinstance(rec.get("clawhubTrustScanStatus"), str) else None,
            "moderation_state": rec.get("clawhubTrustModerationState")
            if isinstance(rec.get("clawhubTrustModerationState"), str) else None,
            "reasons": [r for r in reasons if isinstance(r, str)]
            if isinstance(reasons, list) else [],
            "pending": rec.get("clawhubTrustPending")
            if isinstance(rec.get("clawhubTrustPending"), bool) else None,
            "stale": rec.get("clawhubTrustStale")
            if isinstance(rec.get("clawhubTrustStale"), bool) else None,
        })
    if len(installs) > _MAX_PLUGIN_TRUST_RECORDS:
        ctx.limit_hits.append(
            f"installed_plugin_index in {db_path} has {len(installs)} install record(s) — "
            f"only the first {_MAX_PLUGIN_TRUST_RECORDS} were scanned"
        )


def collect(home: Path | str = "~/.openclaw") -> Context:
    home = Path(home).expanduser()
    ctx = Context(home=home)

    cfg_path = home / "openclaw.json"
    ctx.config_found = cfg_path.is_file()
    parsed_ok = False
    if cfg_path.is_file():
        try:
            parsed = _load_openclaw_config(cfg_path, root_byte_limit=_MAX_CONFIG_BYTES)
        except (OSError, _ConfigLoadError, RecursionError) as exc:
            message = str(exc)
            ctx.errors.append(f"could not parse {cfg_path}: {message}")
            if "cap" in message or "exceeds" in message:
                ctx.limit_hits.append(message)
        else:
            ctx.config = parsed
            try:
                ctx.config_mode = cfg_path.stat().st_mode & 0o777
            except OSError as exc:
                ctx.errors.append(f"could not stat {cfg_path}: {exc}")
            parsed_ok = True
    else:
        ctx.errors.append(f"config not found: {cfg_path}")

    # B-166: "config present but unparseable" (read error, size-cap truncation, decode/
    # JSON/recursion error, or a non-object top level) is a distinct, machine-visible state
    # from "no config file". Surfaced in --json/--sarif and trips --exit-code so a broken
    # config can't silently pass a CI gate as an UNKNOWN-only run. A valid empty "{}" is
    # NOT an error (parsed_ok stays True).
    ctx.config_parse_error = ctx.config_found and not parsed_ok

    # Scan the home root first, then workspace sub-directories.  The root is
    # included so bootstrap files that live outside the three named workspace
    # dirs are not invisible (§6: never hardcode one layout).
    # Resolved paths are tracked so a symlink from a workspace dir back to a
    # root file is not read twice.
    _seen_bootstrap: set[Path] = set()
    _ws_dirs: list[tuple[str, Path]] = [("", home)]
    _ws_dirs += [(ws, home / ws) for ws in WORKSPACE_DIRS]
    # B-161: also scan any config-declared custom workspace(s) for bootstrap files, so a
    # SOUL.md/AGENTS.md living outside the hardcoded names is not invisible. The
    # resolved-path de-dup below keeps a file that also lives under a hardcoded dir from
    # being read (or counted) twice.
    for _cw in _config_workspace_dirs(home, ctx.config, limit_hits=ctx.limit_hits):
        _ws_dirs.append((_cw.name or "workspace", _cw))
    for _ws, wdir in _ws_dirs:
        if not wdir.is_dir():
            continue
        for name in BOOTSTRAP_FILES:
            f = wdir / name
            if not f.is_file():
                continue
            try:
                real = f.resolve()
            except OSError:
                real = f
            if real in _seen_bootstrap:
                continue
            _seen_bootstrap.add(real)
            key = name if _ws == "" else f"{_ws}/{name}"
            try:
                # B-103: cap the read like the skill path — a huge/padded bootstrap
                # file must not load whole into memory (memory DoS) or turn the B58
                # quadratic regex unbounded. _read_with_limit streams up to the cap
                # (never over-allocates); a slice records a limit_hit so checks over
                # ctx.bootstrap surface UNKNOWN instead of scanning a clipped file.
                with open(f, "rb") as fp:
                    raw, truncated = _read_with_limit(fp, _MAX_FILE_BYTES)
                ctx.bootstrap[key] = raw.decode("utf-8", errors="replace")
                if truncated:
                    ctx.limit_hits.append(
                        f"bootstrap file '{key}' exceeded the "
                        f"{_MAX_FILE_BYTES // 1000}KB cap — content beyond the cap "
                        "was NOT scanned")
            except OSError as exc:
                ctx.errors.append(f"could not read {f}: {exc}")

    _collect_cron(home, ctx)
    _collect_exec_approvals(home, ctx)
    _collect_plugin_trust(home, ctx)
    _read_installed_skills(home, ctx)
    return ctx


def dig(d: dict, path: str, default=None):
    """Nested lookup by dotted path; returns default if any segment is missing."""
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur
