"""Read-only collection of OpenClaw config + bootstrap files.

Reads ONLY: ~/.openclaw/openclaw.json and workspace bootstrap markdown files.
No network. No writes. Pure stdlib.
"""
from __future__ import annotations

import json
import re
import io
import zipfile
import tarfile
import gzip
import bz2
import lzma
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from .safeio import walk_dir_safely, is_safe_tar_member

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
_MAX_BYTES_PER_SKILL = 60_000
_MAX_FILE_BYTES = 200_000
_MAX_FILES_PER_SKILL = 500
_MAX_PY_BYTES_PER_SKILL = 200_000  # cap on Python source kept per skill for AST analysis
_ARCHIVE_FILE_LIMIT = _MAX_FILES_PER_SKILL
_ARCHIVE_MAX_FILE_BYTES = _MAX_FILE_BYTES
_ARCHIVE_MAX_TOTAL_BYTES = 20_000_000
_ARCHIVE_MAX_EXPANSION_RATIO = 100

_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


def _loads_tolerant(text: str) -> dict:
    """Parse JSON, tolerating JSON5-isms (comments, trailing commas)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        stripped = _COMMENT_RE.sub("", text)
        stripped = _TRAILING_COMMA_RE.sub(r"\1", stripped)
        return json.loads(stripped)


@dataclass
class Context:
    home: Path
    config: dict = field(default_factory=dict)
    bootstrap: dict = field(default_factory=dict)   # filename -> text
    errors: list[str] = field(default_factory=list)
    config_mode: int | None = None                  # octal perms of openclaw.json, or None
    config_found: bool = False                       # openclaw.json present (vs non-OpenClaw setup)
    native: object = None                           # NativeResult from openclaw security audit
    host: object = None                             # hostwatch.detect() result; set by audit(include_host=True)
    include_host: bool = False                      # host-filesystem scanning enabled (audit(include_host=True) / not --no-host)
    installed_skills: dict = field(default_factory=dict)  # skill name -> concatenated text
    installed_skill_py: dict = field(default_factory=dict)  # skill name -> [(relpath, source)] for AST
    attestation: dict = field(default_factory=dict)  # agent self-report (--attest); see attest.py
    _collected_skill_files: dict[str, list[dict]] = field(default_factory=dict)

    # F-018: per-skill aggregated effect profiles from the abstract effect simulator.
    # Populated by check_installed_skills; keyed by skill name.
    # Each value is a list of entry-point result dicts (see skillast.simulate_effects).
    effect_profiles: dict = field(default_factory=dict)

    # Integrity & analysis metadata blocks (CLAWSECCHECK-E-009)
    limit_hits: list[str] = field(default_factory=list)
    mismatches: list[str] = field(default_factory=list)
    polyglots: list[str] = field(default_factory=list)
    binary_files: list[str] = field(default_factory=list)
    total_files_inspected: int = 0
    excluded_binary_files_count: int = 0
    archives_unpacked: int = 0
    path_traversal_violations: list[str] = field(default_factory=list)
    file_manifest: dict[str, str] = field(default_factory=dict)  # file relpath -> status

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
                    if not is_safe_tar_member(skill_dir, member_name):
                        if ctx is not None:
                            ctx.path_traversal_violations.append(f"{file_relpath}::{member_name}")
                            ctx.file_manifest[f"{file_relpath}::{member_name}"] = "unsafe-path"
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
                                    f"Max file decompressed size hit (>200,000) for {member_name} in {file_relpath}"
                                )
                                ctx.file_manifest[f"{file_relpath}::{member_name}"] = "capped(size)"
                            continue

                        with zf.open(member_name, "r") as zfp:
                            member_bytes, truncated = _read_with_limit(zfp, _ARCHIVE_MAX_FILE_BYTES)
                    except Exception:
                        continue

                    if truncated:
                        if ctx is not None:
                            ctx.limit_hits.append(f"Max file decompressed size hit (>200,000) for {member_name} in {file_relpath}")
                            ctx.file_manifest[f"{file_relpath}::{member_name}"] = "capped(size)"
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

                    sub_rel = f"{file_relpath}::{member_name}"
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
                    if not is_safe_tar_member(skill_dir, member.name):
                        if ctx is not None:
                            ctx.path_traversal_violations.append(f"{file_relpath}::{member.name}")
                            ctx.file_manifest[f"{file_relpath}::{member.name}"] = "unsafe-path"
                            return [(file_relpath, file_bytes, classification, format_name)]
                        
                    if not member.isreg():
                        continue
                        
                    try:
                        if member.size > _ARCHIVE_MAX_FILE_BYTES:
                            if ctx is not None:
                                ctx.limit_hits.append(f"Max file decompressed size hit (>200,000) for {member.name} in {file_relpath}")
                                ctx.file_manifest[f"{file_relpath}::{member.name}"] = "capped(size)"
                            continue

                        f_obj = tf.extractfile(member)
                        if f_obj is None:
                            continue
                        member_bytes = f_obj.read(member.size)
                    except Exception:
                        continue
                        
                    if len(member_bytes) > _ARCHIVE_MAX_FILE_BYTES:
                        if ctx is not None:
                            ctx.limit_hits.append(f"Max file decompressed size hit (>200,000) for {member.name} in {file_relpath}")
                            ctx.file_manifest[f"{file_relpath}::{member.name}"] = "capped(size)"
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
                            
                    sub_rel = f"{file_relpath}::{member.name}"
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
    if ctx is not None:
        cache_key = str(skill_dir)
        cached = ctx._collected_skill_files.get(cache_key)
        if cached is not None:
            return cached

    files = walk_dir_safely(skill_dir, exclude_pycache=True, max_files=_MAX_FILES_PER_SKILL)
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
            
        relpath = str(f.relative_to(skill_dir))
        
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
            ctx, skill_dir, file_bytes, relpath, depth=1, archive_stats=archive_stats
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

    if ctx is not None:
        ctx._collected_skill_files[str(skill_dir)] = collected

    return collected


def _read_skill_text(skill_dir: Path, ctx: Context | None = None) -> str:
    """Concatenate the text/code files of one installed skill (capped, read-only)."""
    collected = collect_skill_files(skill_dir, ctx)
    parts = []
    total = 0
    file_count = 0
    
    for item in collected:
        if total >= _MAX_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            break
        if item["classification"] != "TEXT":
            continue
            
        text = item["content"].decode(encoding="utf-8", errors="replace")
        chunk = text[: _MAX_BYTES_PER_SKILL - total]
        parts.append(f"# file: {Path(item['relpath']).name}\n{chunk}")
        total += len(chunk)
        file_count += 1
        
    return "\n".join(parts)


def read_skill_python(skill_dir: Path, ctx: Context | None = None) -> list[tuple[str, str]]:
    """Collect the Python source files of one skill for read-only AST analysis.

    Returns a list of (relative-path, source) pairs.
    """
    collected = collect_skill_files(skill_dir, ctx)
    out: list[tuple[str, str]] = []
    total = 0
    file_count = 0
    
    for item in collected:
        if total >= _MAX_PY_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            break
        if item["classification"] != "TEXT":
            continue
        if not item["relpath"].lower().endswith(".py"):
            continue
            
        text = item["content"].decode(encoding="utf-8", errors="replace")
        out.append((item["relpath"], text))
        total += len(text)
        file_count += 1
        
    return out


def _read_installed_skills(home: Path, ctx: Context) -> None:
    seen = set()
    for rel in SKILL_DIRS:
        base = home / rel
        if not base.is_dir():
            continue
        for sd in sorted(base.iterdir()):
            if len(ctx.installed_skills) >= _MAX_SKILLS:
                return
            if sd.is_symlink() or not sd.is_dir() or sd.name.lower() in _OWN_SKILL_NAMES:
                continue
            if not (sd / "SKILL.md").is_file():
                continue
            key = sd.name
            if key in seen:
                continue
            seen.add(key)
            try:
                ctx.installed_skills[key] = _read_skill_text(sd, ctx)
                ctx.installed_skill_py[key] = read_skill_python(sd, ctx)
            except OSError as exc:
                ctx.errors.append(f"could not read skill {key}: {exc}")


def collect(home: Path | str = "~/.openclaw") -> Context:
    home = Path(home).expanduser()
    ctx = Context(home=home)

    cfg_path = home / "openclaw.json"
    ctx.config_found = cfg_path.is_file()
    if cfg_path.is_file():
        try:
            parsed = _loads_tolerant(cfg_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            ctx.errors.append(f"could not parse {cfg_path}: {exc}")
        except RecursionError:
            ctx.errors.append(f"could not parse {cfg_path}: nesting too deep")
        else:
            if isinstance(parsed, dict):
                ctx.config = parsed
                ctx.config_mode = cfg_path.stat().st_mode & 0o777
            else:
                ctx.errors.append(
                    f"malformed {cfg_path}: expected a JSON object, "
                    f"got {type(parsed).__name__}"
                )
    else:
        ctx.errors.append(f"config not found: {cfg_path}")

    for ws in WORKSPACE_DIRS:
        wdir = home / ws
        if not wdir.is_dir():
            continue
        for name in BOOTSTRAP_FILES:
            f = wdir / name
            if f.is_file():
                try:
                    ctx.bootstrap[f"{ws}/{name}"] = f.read_text(encoding="utf-8")
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
