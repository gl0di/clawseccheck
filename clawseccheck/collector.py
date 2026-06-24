"""Read-only collection of OpenClaw config + bootstrap files.

Reads ONLY: ~/.openclaw/openclaw.json and workspace bootstrap markdown files.
No network. No writes. Pure stdlib.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# Bootstrap / prompt files injected into the system prompt as "trusted context".
# The native `openclaw security audit` does NOT scan these -> our wedge (B6/B7/B9).
BOOTSTRAP_FILES = [
    "SOUL.md", "AGENTS.md", "TOOLS.md", "MEMORY.md", "IDENTITY.md",
    "USER.md", "HEARTBEAT.md", "BOOTSTRAP.md", "memory.md",
]

WORKSPACE_DIRS = ["workspace-home", "workspace-work", "workspace"]

# Where OpenClaw discovers installed skills (we read their CONTENT, never run them).
SKILL_DIRS = ["skills", "workspace/skills", "workspace-home/skills",
              "workspace-work/skills", ".agents/skills"]
_SKILL_TEXT_EXT = {".md", ".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".mjs",
                   ".cjs", ".json", ".txt", ".ps1"}
_OWN_SKILL_NAMES = {"clawseccheck", "clawshield"}
_MAX_SKILLS = 300
_MAX_BYTES_PER_SKILL = 60_000
_MAX_FILE_BYTES = 200_000
_MAX_FILES_PER_SKILL = 500
_MAX_PY_BYTES_PER_SKILL = 200_000  # cap on Python source kept per skill for AST analysis

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

    @property
    def bootstrap_blob(self) -> str:
        return "\n".join(self.bootstrap.values())


def _read_skill_text(skill_dir: Path) -> str:
    """Concatenate the text/code files of one installed skill (capped, read-only).

    Symlinks are skipped and any path that resolves outside the skill directory is
    refused, so a malicious skill cannot use a symlink to make the auditor read
    (and surface) a file elsewhere on disk.
    """
    parts, total, file_count = [], 0, 0
    try:
        root = skill_dir.resolve()
    except OSError:
        return ""
    files = sorted(skill_dir.rglob("*"))
    for f in files:
        if total >= _MAX_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            break
        if f.is_symlink() or not f.is_file() or f.suffix.lower() not in _SKILL_TEXT_EXT:
            continue
        try:
            real = f.resolve()
            if root != real and root not in real.parents:  # escaped the skill dir
                continue
            if f.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        chunk = text[: _MAX_BYTES_PER_SKILL - total]
        parts.append(f"# file: {f.name}\n{chunk}")
        total += len(chunk)
        file_count += 1
    return "\n".join(parts)


def read_skill_python(skill_dir: Path) -> list[tuple[str, str]]:
    """Collect the Python source files of one skill for read-only AST analysis.

    Returns a list of (relative-path, source) pairs, bounded by the same caps and
    symlink/escape guards as _read_skill_text — never executes anything.
    """
    out: list[tuple[str, str]] = []
    total, file_count = 0, 0
    try:
        root = skill_dir.resolve()
    except OSError:
        return out
    for f in sorted(skill_dir.rglob("*.py")):
        if total >= _MAX_PY_BYTES_PER_SKILL or file_count >= _MAX_FILES_PER_SKILL:
            break
        if f.is_symlink() or not f.is_file():
            continue
        try:
            real = f.resolve()
            if root != real and root not in real.parents:  # escaped the skill dir
                continue
            if f.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = str(f.relative_to(skill_dir))
        except ValueError:
            rel = f.name
        out.append((rel, text))
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
                ctx.installed_skills[key] = _read_skill_text(sd)
                ctx.installed_skill_py[key] = read_skill_python(sd)
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
            # Deeply-nested JSON overflows json.loads' C recursion limit. Only the
            # user's own config reaches this path (self-inflicted, not attacker-
            # reachable), so degrade gracefully instead of crashing the audit (B-014).
            ctx.errors.append(f"could not parse {cfg_path}: nesting too deep")
        else:
            if isinstance(parsed, dict):
                ctx.config = parsed
                ctx.config_mode = cfg_path.stat().st_mode & 0o777
            else:
                # Valid JSON but a non-object top level (list/scalar). The config
                # contract is a JSON object; every later cfg.get() would raise
                # AttributeError on a list/str/int. Degrade with a clear note and
                # leave ctx.config as the empty dict so downstream checks read the
                # config as absent rather than crashing the audit (B-016).
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
