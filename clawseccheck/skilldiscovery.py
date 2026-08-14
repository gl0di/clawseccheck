"""Bounded discovery of configured and grouped OpenClaw skill directories."""
from __future__ import annotations

from pathlib import Path

_MAX_DEPTH = 6
_MAX_DIRS = 2_000


def _exists_as_entry(path: Path) -> bool:
    """True when *path* is a directory entry at all, whatever it points at.

    `Path.exists()` follows symlinks and `is_file()` additionally demands a regular file, so
    both answer False for a dangling link, a FIFO or a socket — conflating "there is nothing
    here" with "there is something here I cannot read as a file". Only the second is a fact
    about a skill.
    """
    try:
        path.lstat()
    except (OSError, ValueError):
        return False
    return True


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

        manifest = target / "SKILL.md"
        try:
            is_manifest = manifest.is_file()
        except OSError as exc:
            # `Path.is_file()` re-raises anything outside ENOENT/ENOTDIR/EBADF/ELOOP, so
            # EACCES propagates — a `chmod 000` directory anywhere under a skills root
            # crashed the whole audit, not just this branch of it. Verified pre-existing
            # against `git show HEAD:` before this handler was added. Same root cause as the
            # walk-layer crash filed separately; this is the discovery-layer instance, and it
            # is the one that takes the entire run down.
            limit_hits.append(
                f"skill discovery could not read '{display.name}/SKILL.md': {exc.strerror or exc}"
            )
            continue
        if is_manifest:
            yield display, target
            continue
        # B-549 shape 2 — a directory whose SKILL.md is present but unreadable (a dangling
        # symlink, a FIFO) — is deliberately NOT handled here, after three attempts that were
        # each worse than the silence they replaced. Recorded so the next attempt starts from
        # the wreckage rather than repeating it:
        #
        #   1. yield + `continue`: a group directory carrying one dangling SKILL.md hid every
        #      skill beneath it — pre-change found `group/real`, that version found only
        #      `group`, and a live `curl | sh` went dark for the cost of one symlink.
        #   2. yield without `continue`: a dangling SKILL.md in the skills ROOT made the
        #      container an installed skill whose text is the union of every real skill —
        #      `inventory.skills: ['skills', 'alpha', 'beta']`, one payload attributed twice,
        #      and on a home with NO payload the merged text blew the per-skill 1000KB cap
        #      that no real skill came near, costing a HIGH check its verdict.
        #   3. disclose into `limit_hits` without yielding: the population came out right,
        #      but `LIMIT_DOMAIN_SKILL` means "my scan was truncated" to its consumers, so
        #      `check_installed_skills`' coverage-gap branch fired on a clean home with three
        #      fully-scanned skills — B13 PASS became UNKNOWN for one broken symlink.
        #
        # All three were Golden Rule #5 failures found by an independent adversarial pass,
        # and all three shared one mistake: treating "a directory looks like a skill but could
        # not be assessed" as either a member of the population or a truncated scan. It is
        # neither. It needs a channel no verdict currently consumes — a per-subject inventory
        # row — which is a different piece of work with its own task. The pre-existing silence
        # is wrong, but it is not a false statement, and each of these was.
        if depth >= _MAX_DEPTH:
            continue

        try:
            entries = sorted(target.iterdir(), key=lambda path: path.name)
        except OSError as exc:
            # Same silent-drop shape one layer up from the walk: an unreadable directory
            # under a skill root disappeared from discovery with no bookkeeping at all.
            # The domain-scoped sink is already in scope, so the disclosure costs nothing.
            limit_hits.append(
                f"skill discovery could not list '{display.name}/': {exc.strerror or exc}"
            )
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
