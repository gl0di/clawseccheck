"""Read-only collection of OpenClaw config + bootstrap files.

Reads ONLY: ~/.openclaw/openclaw.json and workspace bootstrap markdown files.
No network. No writes. Pure stdlib.
"""
from __future__ import annotations

import math
import io
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
_OWN_SKILL_NAMES = {"clawseccheck", "clawshield"}
_MAX_SKILLS = 300
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
    installed_skills: dict = field(default_factory=dict)  # skill name -> concatenated text
    installed_skill_py: dict = field(default_factory=dict)  # skill name -> [(relpath, source)] for AST
    installed_skill_shell: dict = field(default_factory=dict)  # skill name -> [(relpath, source)] for .sh/.bash
    installed_skill_js: dict = field(default_factory=dict)  # skill name -> [(relpath, source)] for .js/.ts
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
        return "BINARY", None

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
        return "BINARY", None


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
                    if sub_fmt in ("ELF", "PE", "class") or (sub_fmt or "").startswith("Mach-O"):
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


def read_skill_python(skill_dir: Path, ctx: Context | None = None) -> list[tuple[str, str]]:
    """Collect the Python source files of one skill for read-only AST analysis.

    Returns a list of (relative-path, source) pairs.
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
        if not item["relpath"].lower().endswith(".py"):
            continue

        text = item["content"].decode(encoding="utf-8", errors="replace")
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
                return
            if sd.name.lower() in _OWN_SKILL_NAMES:
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
            except OSError as exc:
                ctx.errors.append(f"could not read skill {key}: {exc}")


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
