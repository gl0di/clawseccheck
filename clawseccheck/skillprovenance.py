"""F-174 (B) — where each installed skill came from, as a time series.

Read-only, stdlib only, no network. A LEAF: it imports nothing from this package. It renders
no verdict — `monitor.py` is the consumer, the same leaf->consumer split `sockets.py`->B340,
`deptree.py`->B349, `configjournal.py`->B77 and `openclawdist.py` already use.

**What is on disk**, verified first-hand on the maintainer's machine rather than assumed:

* `<workspace>/.clawhub/lock.json` — `{"version": 1, "skills": {"<name>": {...}}}`, 27 KB,
  one record per installed skill carrying `version`, `installedAt` (epoch ms),
  `registry`, `artifact.{kind,sha256,integrity}`, `skillFile.{path,sha256}` and a
  `verification` block (`ok`, `decision`, plus card/artifact/provenance/security detail).
* `<skill>/.clawhub/origin.json` — the same facts written beside the skill itself, under
  slightly different names: `slug`, `installedVersion`, `installedAt`, `artifact`,
  `skillFile`. No `verification` block.

B181 already reads these digests for a point-in-time verdict. What was missing is the time
series: `installedVersion` moving, `installedAt` moving, `artifact.sha256` changing. That is
how an update is *detected* — the tier of the pre-update story that works with no
cooperation from the user, because it needs nothing but the next scheduled run.

**Why both files, when they agree.** Measured on the real machine they agree exactly —
`3.61.0`, the same `installedAt`, the same two digests. That is the expected state, and it
is precisely what makes a DISAGREEMENT worth recording: the two are written by the same
installer at the same moment, so one of them moving alone is not something an ordinary
update produces. Same reasoning as F-170's config journal — a second witness earns its keep
by agreeing until it does not. The corroboration is recorded as a flag, never as a verdict:
this module says the two sources differ, and nothing about why.

**Nothing here is a secret**, but nothing here is a path either: the skill NAME goes into
the snapshot and the on-disk location does not, because a drift baseline reaches the event
journal and any report a user pastes into an issue.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

# The workspace directory names OpenClaw uses, in the order `collector.WORKSPACE_DIRS`
# lists them. Duplicated as a literal rather than imported, deliberately: this module is a
# leaf and importing the collector would invert the layering for three strings. The
# `tests/test_f174_skill_provenance.py` guard asserts the two lists stay equal.
WORKSPACE_DIRS = ("workspace-home", "workspace-work", "workspace")

# Bounds. A workspace with more skills than this is not a setup this tool can usefully
# fingerprint in a scheduled run, and the cap is disclosed rather than silently applied.
MAX_SKILLS = 500
MAX_LOCK_BYTES = 4 * 1024 * 1024


@dataclass
class SkillOrigin:
    """One installed skill's provenance. Every field is a str/int/bool so it survives the
    JSON round-trip into and out of the drift baseline unchanged."""

    name: str = ""
    version: str = ""
    installed_at: int = 0
    registry: str = ""
    artifact_sha256: str = ""
    skill_file_sha256: str = ""
    # True/False when both sources exist and could be compared; None when only one did.
    # Three states, not two: "the second witness is absent" and "the second witness
    # disagrees" call for opposite reactions, and a bool would report a skill installed
    # before origin.json existed as though its records conflicted.
    corroborated: "bool | None" = None
    # True when more than one workspace holds an install record under this NAME and they
    # do not agree. Which one the agent actually loads is not something this tool can
    # determine, so the consumer must not compare the chosen record's digests across runs
    # — see the suppression in monitor.diff_with_notes.
    ambiguous: bool = False

    def as_dimension(self) -> dict:
        return {
            "version": self.version,
            "installed_at": self.installed_at,
            "registry": self.registry,
            "artifact_sha256": self.artifact_sha256,
            "skill_file_sha256": self.skill_file_sha256,
            "corroborated": self.corroborated,
            "ambiguous": self.ambiguous,
        }


@dataclass
class ProvenanceScan:
    """`skills` maps name -> SkillOrigin. `present` says whether a lock file was found at
    all, which is a different fact from finding one with no skills in it: the first means
    this install does not use ClawHub, the second means it does and has none installed.
    A consumer that conflated them would report every skill as removed the day a user
    switched to a workspace layout we did not look in."""

    present: bool = False
    skills: dict = None
    capped: bool = False
    notes: tuple = ()

    def __post_init__(self):
        if self.skills is None:
            self.skills = {}

    def as_dimension(self) -> dict:
        return {name: o.as_dimension() for name, o in sorted(self.skills.items())}


def _load_json(p: Path, *, max_bytes: int) -> "dict | None":
    """A bounded JSON object read, or None. Never raises.

    Bounded because this reads a file the audited agent writes: a 4 MB ceiling is roughly
    150x the real 27 KB lock file, generous enough never to fire in normal use and tight
    enough that a hostile or corrupted file cannot make a scheduled run allocate without
    limit.
    """
    try:
        if p.stat().st_size > max_bytes:
            return None
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _digest_pair(rec: dict) -> "tuple[str, str]":
    """`(artifact.sha256, skillFile.sha256)` out of a record in either file's shape."""
    artifact = rec.get("artifact")
    skill_file = rec.get("skillFile")
    a = artifact.get("sha256") if isinstance(artifact, dict) else None
    s = skill_file.get("sha256") if isinstance(skill_file, dict) else None
    return (a if isinstance(a, str) else "", s if isinstance(s, str) else "")


def _int_or_zero(value) -> int:
    """`installedAt` as an int. Excludes bool, which is an int in Python and would let a
    corrupted `true` compare as 1 against a real epoch."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def workspace_roots(home: Path, config: "dict | None" = None) -> "list[Path]":
    """Every workspace directory to look in, deduplicated, existing ones only.

    *config* may add roots (`agents.defaults.workspace`, `agents.list[].workspace`) and can
    only ever ADD them — the same invariant `monitor._SHRINKABLE_DIMENSIONS` documents and
    depends on. That is why this dimension belongs in the shrinkable group: a run that could
    not read the config sees a SUBSET, never a superset, so a disappearance on a blind run
    is untrustworthy while an addition or a content change is still real evidence.
    """
    roots: list[Path] = [home / name for name in WORKSPACE_DIRS]
    extra: list[Path] = []
    if isinstance(config, dict):
        agents = config.get("agents")
        if isinstance(agents, dict):
            defaults = agents.get("defaults")
            if isinstance(defaults, dict) and isinstance(defaults.get("workspace"), str):
                extra.append(Path(defaults["workspace"]).expanduser())
            listed = agents.get("list")
            if isinstance(listed, list):
                for entry in listed:
                    if isinstance(entry, dict) and isinstance(entry.get("workspace"), str):
                        extra.append(Path(entry["workspace"]).expanduser())
    # A RELATIVE workspace string is resolved against *home*, never against the process's
    # working directory — matching `collector._config_workspace_dirs` (B-161), which is the
    # established precedent for exactly this key and says so in its own docstring. The first
    # version used a bare `expanduser()`, so a relative path stayed CWD-relative and running
    # the same check from a different directory read a different workspace: an independent
    # pass turned that into a false "the skill was replaced with different content" with no
    # config edit at all.
    #
    # Sorted, so which config-declared root is searched first does not depend on the order
    # the user happens to have listed their agents in. Adding an agent to `agents.list` is
    # an ordinary edit and must not change what this reports.
    roots.extend(sorted((home / p if not p.is_absolute() else p) for p in extra))
    seen: set = set()
    out: list[Path] = []
    for r in roots:
        try:
            # RESOLVED for de-duplication, again matching the collector: a config workspace
            # that is a symlink to a default one is the same directory, and treating it as a
            # second source would manufacture the very conflict this de-dup exists to avoid.
            key = str(r.resolve())
        except (OSError, ValueError, RuntimeError):
            key = str(r)
        if key in seen:
            continue
        seen.add(key)
        try:
            if r.is_dir():
                out.append(r)
        except OSError:
            continue
    return out


def read_provenance(home: Path | str = "~/.openclaw", config: "dict | None" = None, *,
                    max_skills: int = MAX_SKILLS) -> ProvenanceScan:
    """Every installed skill's install record, corroborated where a second source exists."""
    home = Path(home).expanduser()
    notes: list[str] = []
    skills: dict = {}
    present = False
    capped = False

    for root in workspace_roots(home, config):
        lock = _load_json(root / ".clawhub" / "lock.json", max_bytes=MAX_LOCK_BYTES)
        if lock is None:
            continue
        present = True
        records = lock.get("skills")
        if not isinstance(records, dict):
            notes.append("the install record has no skills section")
            continue
        for name, rec in sorted(records.items()):
            if not isinstance(name, str) or not isinstance(rec, dict):
                continue
            if name in skills:
                # FIRST root wins — but winning is not enough on its own, and the first
                # attempt at this fix stopped there and was broken again by the next pass.
                #
                # The history is worth keeping because it shows the shape of the mistake.
                # Originally this was LAST-wins, so merely adding `agents.list[].workspace`
                # to openclaw.json changed which of two same-named records won and the diff
                # read the swap as "the skill was replaced with different content" — a false
                # HIGH from an ordinary config edit. First-wins with the default workspaces
                # searched first fixed the default-vs-config case. It did NOT fix ordering
                # among config roots (adding an agent to `agents.list` flipped the winner
                # again), and `workspace_roots` now sorts those — but sorting only makes the
                # choice stable, not correct.
                #
                # The honest answer is that when two workspaces hold different records under
                # one name, WHICH ONE THE AGENT LOADS IS NOT SOMETHING WE CAN DETERMINE. So
                # the conflict is recorded rather than resolved, and the consumer stands
                # down from the digest comparison for that skill instead of comparing a
                # record it picked arbitrarily.
                won = skills[name]
                rival_artifact, rival_skill_file = _digest_pair(rec)
                rival_version = rec.get("version")
                if (won.version, won.artifact_sha256, won.skill_file_sha256) != (
                        rival_version if isinstance(rival_version, str) else "",
                        rival_artifact, rival_skill_file):
                    won.ambiguous = True
                continue
            if len(skills) >= max_skills:
                capped = True
                break
            artifact, skill_file = _digest_pair(rec)
            version = rec.get("version")
            registry = rec.get("registry")
            skills[name] = SkillOrigin(
                name=name,
                version=version if isinstance(version, str) else "",
                installed_at=_int_or_zero(rec.get("installedAt")),
                registry=registry if isinstance(registry, str) else "",
                artifact_sha256=artifact,
                skill_file_sha256=skill_file,
                corroborated=_corroborate(root, name, rec),
            )
    if capped:
        notes.append("more installed skills than this run records")
    return ProvenanceScan(present=present, skills=skills, capped=capped,
                          notes=tuple(notes))


def _corroborate(root: Path, name: str, rec: dict) -> "bool | None":
    """Does the skill's own `origin.json` agree with the workspace lock file?

    None when there is no `origin.json` to ask — a skill installed before that file existed,
    or installed by hand. Reported as "no second witness", never as disagreement.

    Compared on the two digests and the version only. `installedAt` is deliberately left
    out: it is the same value in both files today, but it is a timestamp written by two
    separate writes, and building a mismatch signal on clock equality is how a benign
    millisecond becomes an accusation.
    """
    origin = _load_json(root / "skills" / name / ".clawhub" / "origin.json",
                        max_bytes=MAX_LOCK_BYTES)
    if origin is None:
        return None
    o_artifact, o_skill_file = _digest_pair(origin)
    l_artifact, l_skill_file = _digest_pair(rec)
    o_version = origin.get("installedVersion")
    l_version = rec.get("version")
    return (o_artifact == l_artifact
            and o_skill_file == l_skill_file
            and o_version == l_version)
