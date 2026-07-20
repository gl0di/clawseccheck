"""Bounded discovery of configured and grouped OpenClaw skill directories."""
from __future__ import annotations

from pathlib import Path

_MAX_DEPTH = 6
_MAX_DIRS = 2_000


def config_extra_skill_dirs(home: Path, cfg: dict) -> list[Path]:
    """Resolve ``skills.load.extraDirs`` without guessing outside the audited config."""
    skills = cfg.get("skills") if isinstance(cfg, dict) else None
    load = skills.get("load") if isinstance(skills, dict) else None
    raw = load.get("extraDirs") if isinstance(load, dict) else None
    values = [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []
    out: list[Path] = []
    seen: set[Path] = set()
    for value in values:
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            continue
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = home / path
        try:
            resolved = path.resolve()
        except (OSError, ValueError, RuntimeError):
            continue
        if resolved not in seen:
            seen.add(resolved)
            out.append(path)
    return out


def config_plugin_load_paths(home: Path, cfg: dict) -> list[Path]:
    """Resolve ``plugins.load.paths`` (a real dist key) — extra plugin roots whose bundled
    skills live under ``<plugin>/skills/`` and enter the auto-load surface. Mirrors
    ``config_extra_skill_dirs``: no guessing outside the audited config; ``\\x00`` / OSError /
    dedup guards; relative paths resolve against *home*."""
    plugins = cfg.get("plugins") if isinstance(cfg, dict) else None
    load = plugins.get("load") if isinstance(plugins, dict) else None
    raw = load.get("paths") if isinstance(load, dict) else None
    values = [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []
    out: list[Path] = []
    seen: set[Path] = set()
    for value in values:
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            continue
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = home / path
        try:
            resolved = path.resolve()
        except (OSError, ValueError, RuntimeError):
            continue
        if resolved not in seen:
            seen.add(resolved)
            out.append(path)
    return out


def iter_discovered_skill_dirs(
    base: Path,
    *,
    allow_symlink_entries: bool,
    # Any object with ``.append(str)``. The collector passes a domain-scoped sink so this
    # leaf's cap hit is tagged ``skill`` without this module importing the collector.
    limit_hits,
):
    """Yield ``(display_path, resolved_dir)`` for grouped layouts up to six levels."""
    try:
        base_target = base.resolve()
    except (OSError, ValueError, RuntimeError):
        return
    queue: list[tuple[Path, Path, int]] = [(base, base_target, 0)]
    seen_dirs: set[Path] = set()
    visited = 0

    while queue:
        display, target, depth = queue.pop(0)
        if target in seen_dirs:
            continue
        seen_dirs.add(target)
        visited += 1
        if visited > _MAX_DIRS:
            limit_hits.append(
                f"skill discovery under '{base}' exceeded the {_MAX_DIRS}-directory cap"
            )
            return

        if (target / "SKILL.md").is_file():
            yield display, target
            continue
        if depth >= _MAX_DEPTH:
            continue

        try:
            entries = sorted(target.iterdir(), key=lambda path: path.name)
        except OSError:
            continue
        for entry in entries:
            if entry.name in {".git", "node_modules", "__pycache__"}:
                continue
            try:
                is_link = entry.is_symlink()
                if is_link and not allow_symlink_entries:
                    continue
                entry_target = entry.resolve() if is_link else entry
                if not entry_target.is_dir():
                    continue
            except (OSError, ValueError, RuntimeError):
                continue
            queue.append((display / entry.name, entry_target, depth + 1))
