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

**Why both files, when a second one is there at all.** `origin.json` is a real and
documented artifact — `openclaw skills verify` reads it to check an installed version against
the registry it came from — but the docs describe it as present only "when origin metadata
exists", and it is **optional**. Measured on this machine, 2026-08-22: the workspace lock
holds 19 skills, exactly one of them has a `skills/<name>/` directory at all, and **zero**
`origin.json` files exist anywhere under `~/.openclaw`. So `_corroborate` returns None for
every skill here and there is no second witness to disagree with.

An earlier version of this paragraph claimed the two files had been "measured on the real
machine" agreeing exactly, version and both digests. That is not the state of this machine and
the sentence is not repeated. The field stays, because when the file IS there the reasoning
holds — the two are written by the same installer at the same moment, so one of them moving
alone is not something an ordinary update produces — and because `corroborated` is already
three-state, so "no second witness" and "the witnesses disagree" never collapse into one. Same reasoning as F-170's config journal — a second witness earns its keep
by agreeing until it does not. The corroboration is recorded as a flag, never as a verdict:
this module says the two sources differ, and nothing about why.

**Nothing here is a secret**, but nothing here is a path either: the skill NAME goes into
the snapshot and the on-disk location does not, because a drift baseline reaches the event
journal and any report a user pastes into an issue. That holds for `winner_root` too — it
identifies WHICH root's record won, so a later run can tell "the same record" from "a
different one", and it does so through `_root_identity`, which returns a literal name for the
three `WORKSPACE_DIRS` constants and a digest for everything else — **including anything else
under home**. The earlier rule was "literal for anything under home, digest otherwise", on the
reasoning that a path under home is one of OpenClaw's own fixed names. It is not: a
config-declared `~/.openclaw/client-acme-private`, and every `workspace-<agent id>` B-610
made a scan target, are user-chosen.
"""
from __future__ import annotations

import hashlib
import json
import re
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

# The fields two records under one NAME must agree on before the consumer may treat them as
# one subject. The rule is not a matter of taste: **it must equal the union of the fields
# the consumer's guarded comparisons read**, or a comparison ends up gated on a flag that
# never looked at the field it is about to render a verdict on. That is exactly how
# `corroborated` came to be missing here — two workspaces holding byte-identical lock
# records but disagreeing `origin.json` files produced `ambiguous=False`, and
# `monitor.diff_with_notes` then raised "the two install records no longer agree" about
# whichever record first-wins happened to pick.
#
# `installed_at` is deliberately OUT, for the reason `_corroborate` gives: it is written by
# two separate writes, and a benign millisecond turning into "your workspaces disagree"
# would manufacture silence out of clock noise. `registry` is OUT because no comparison in
# the consumer renders a verdict on it, so including it would only widen the stand-down.
CONFLICT_FIELDS = ("version", "artifact_sha256", "skill_file_sha256", "corroborated")


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
    # do not agree on CONFLICT_FIELDS. Which one the agent actually loads is not something
    # this tool can determine, so the consumer must not compare the chosen record's digests
    # across runs — see the stand-down in monitor.diff_with_notes.
    ambiguous: bool = False
    # How many workspace roots held a record under this name. For WORDING only: the
    # consumer says "3 records found" rather than a bare "more than one".
    n_records: int = 1
    # WHICH root's record won, as a location-free identity (`_root_identity`) — IDENTITY,
    # never content. This is the field that decides whether an ambiguous record may still
    # be compared across runs.
    #
    # `ambiguous` alone cannot decide it: it is a bool, and two runs both reporting True
    # does NOT prove they are about the same winning record — one root can be added while
    # another is removed, and first-wins would elect a different one with the flag never
    # moving.
    #
    # Neither can the witness SET, which is what this field replaces. A digest over every
    # root that held a record answers "did the set move", and the set moves when an
    # ATTACKER ADDS A FILE. Measured end-to-end through the real CLI: a skill downgraded
    # 2.0.0 -> 1.0.0 with a swapped artifact digest in the winning record, plus one decoy
    # `<workspace>/.clawhub/lock.json` that never wins, alerted before the set-keyed
    # stand-down and went silent after it — and stayed silent on every later run, because
    # by then the tampered record IS the baseline. Silence bought for one file.
    #
    # The winner's identity answers what the guard is actually asking: is the record about
    # to be compared the record the baseline recorded? A root that does not win cannot
    # change that answer and so must not be able to stop the comparison; a config edit
    # that genuinely elects a different root does, and that is the benign case the
    # stand-down exists for.
    winner_root: str = ""

    def conflict_tuple(self) -> tuple:
        """What two records under one name must agree on to be one subject."""
        return tuple(getattr(self, field) for field in CONFLICT_FIELDS)

    def as_dimension(self) -> dict:
        return {
            "version": self.version,
            "installed_at": self.installed_at,
            "registry": self.registry,
            "artifact_sha256": self.artifact_sha256,
            "skill_file_sha256": self.skill_file_sha256,
            "corroborated": self.corroborated,
            "ambiguous": self.ambiguous,
            "n_records": self.n_records,
            "winner_root": self.winner_root,
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


def _root_identity(home: Path, root: Path) -> str:
    """A stable, location-free name for one workspace root.

    "Location-free" is meant literally, and the first version was not. It returned the raw
    relative path for ANY root under *home*, on the reasoning that those "are OpenClaw's own
    fixed directory names, already public constants in this module, and they carry nothing
    personal". That is true of the three `WORKSPACE_DIRS` entries and of nothing else — a
    config-declared `~/.openclaw/client-acme-private` put its user-chosen directory name into
    `winner_root`, which reaches the drift baseline, the event journal, and any report a user
    pastes into an issue. So the literal form is now allowed only for the names that really
    are public constants; everything else is digested, inside home or not.

    **Resolved first.** `workspace_roots` de-duplicates on the resolved path — its comment
    explains why: "a config workspace that is a symlink to a default one is the same
    directory" — while this digested the unresolved string, so the same directory reached
    through a symlink produced two identities. `_prov_comparable` keys its stand-down on this
    field, so that disagreement manufactured the disclosed-but-blind state out of an edit that
    changed nothing real. Reproduce it by digesting a directory and a symlink to it: before the
    fix the two strings differed, because only one of them had been through `resolve()`. The
    specific hex is deliberately not quoted — it is a digest of an absolute path and no later
    reader could re-derive it.

    The digest is per-machine by construction (it is taken over an absolute path) and needs to
    be nothing more: it is only ever compared against the same machine's previous run. It hides
    the name, not the directory: against a guessed candidate it is a confirmation oracle, since
    the input space is small. That is enough for the property claimed here — the string carries
    no location — and is not claimed to be more.

    **The migration cost, stated as what it is.** Changing this changes `winner_root`, which
    `_prov_comparable` keys its stand-down on. Non-ambiguous records never reach that
    comparison and the three literals do not move, so the only affected shape is an ambiguous
    record whose winner is a config-declared root. For that shape the first run after the
    change stands down — and a stand-down is **not a deferred alert**: the arm `continue`s past
    all three alert branches, and by the next run the baseline already holds the new record, so
    a content swap landing inside that window is never reported at all. `monitor.py` spells the
    same shape out for the case it was written for. The window is one run, except after a
    BLIND run, which carries the legacy value forward through `_degrade_snapshot`'s merge, so
    it lasts until the first sighted run that sees the root again.

    A one-time migration — accepting a baseline's legacy literal as matching its digest — was
    considered and not done here: the obvious encoding of it puts the raw name back into the
    record this change exists to keep it out of. Left as a decision rather than a silent
    trade-off.
    """
    try:
        resolved = root.resolve()
    except (OSError, ValueError, RuntimeError):
        resolved = root
    try:
        rel = resolved.relative_to(home.resolve()).as_posix()
    except (OSError, ValueError, RuntimeError):
        rel = ""
    if rel in WORKSPACE_DIRS:
        return rel
    return "x" + hashlib.sha256(str(resolved).encode("utf-8", "replace")).hexdigest()[:16]


# OpenClaw's `DEFAULT_AGENT_ID`, and its `normalizeAgentId` / `resolveDefaultAgentId` /
# `resolveAgentWorkspaceDir` rules. Duplicated from `collector.py` rather than imported, for
# the same reason `WORKSPACE_DIRS` is: this module is a LEAF and importing the collector would
# invert the layering. `tests/test_b610_derived_agent_workspaces.py` pins the two derivations equal on
# a battery of configs, not just the constant — a duplicated *rule* rots more quietly than a
# duplicated list.
DEFAULT_AGENT_ID = "main"


# Spelled with BOTH cases instead of `re.IGNORECASE`, deliberately. JS's `/i` without
# the `u` flag does not case-fold non-ASCII, while Python's IGNORECASE does — so
# `re.IGNORECASE` accepted U+0130 `İ`, U+0131 `ı` and U+017F `ſ` as valid ASCII
# letters and returned them unsanitised. Measured against the real dist function over a
# 65,504-codepoint BMP sweep: those three were the ONLY divergences, and an id like
# `İstanbul` is a perfectly ordinary Turkish agent name whose workspace we would then
# have kept looking for in the wrong directory.
_JS_TRIM_CHARS = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
    "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)

_VALID_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_INVALID_AGENT_ID_CHARS_RE = re.compile(r"[^a-z0-9_-]+")


def _normalize_agent_id(value) -> str:
    """OpenClaw's `normalizeAgentId`, transcribed from the copy the workspace resolver binds.

    ```js
    /** Normalize user or config agent ids to the filesystem-safe canonical form. */
    function normalizeAgentId(value) {
        const trimmed = (value ?? "").trim();
        if (!trimmed) return DEFAULT_AGENT_ID;
        const normalized = normalizeLowercaseStringOrEmpty(trimmed);
        if (VALID_ID_RE.test(trimmed)) return normalized;
        return normalized.replace(INVALID_CHARS_RE, "-").replace(LEADING_DASH_RE, "")
                         .replace(TRAILING_DASH_RE, "").slice(0, 64) || DEFAULT_AGENT_ID;
    }
    ```

    with `VALID_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/i` and `INVALID_CHARS_RE = /[^a-z0-9_-]+/g`.

    **There are SIX copies of this function in the dist and they do not agree.** Two
    (`monitor.account-*.js`, `telegram-ingress-spool-*.js`) are a bare
    `trim().toLowerCase() || DEFAULT_AGENT_ID`; the other four sanitise. The first version of
    this port transcribed a bare one — found by grepping for the first definition rather than
    by following what the caller binds — and asserted in its own docstring that the product
    "does not sanitise the value as a path segment". The opposite is true, and the function's
    own comment says so. The copy that matters is the one in the same module as
    `resolveAgentWorkspaceDir` (`config-utils-*.js`), which is the sanitising one.

    Getting this wrong left the hole open for ordinary ids: `Work Laptop` becomes
    `work-laptop`, so OpenClaw uses `workspace-work-laptop` while we derived
    `workspace-work laptop` and read nothing. Measured end to end — `installed_skills == {}`
    against a control of `{'evil': ...}`. It also closed a hazard by accident: a sanitised id
    can no longer contain a path separator, so a derived root cannot escape the state dir
    through the id at all.

    Note `VALID_ID_RE` is tested against the TRIMMED original (case-insensitively) while the
    value returned is the lowercased one — an id that is already valid is never sliced.
    """
    # `String.trim()`, not `str.strip()`: Python strips \x1c-\x1f and \x85 which JS keeps,
    # and keeps \ufeff which JS strips. Only observable when the difference exposes an
    # outer dash to VALID_ID_RE, but "only observable sometimes" is how a transcription
    # bug hides.
    trimmed = (value if isinstance(value, str) else "").strip(_JS_TRIM_CHARS)
    if not trimmed:
        return DEFAULT_AGENT_ID
    normalized = trimmed.lower()
    if _VALID_AGENT_ID_RE.match(trimmed):
        return normalized
    normalized = _INVALID_AGENT_ID_CHARS_RE.sub("-", normalized)
    return normalized.strip("-")[:64] or DEFAULT_AGENT_ID


def _default_agent_id(agents_list) -> str:
    """The entry flagged `default`, else the FIRST entry, else `main`.

    The "else the first entry" half matters: with one entry in `agents.list`, that entry IS
    the default agent and its workspace is the plain `workspace` directory, so nothing is
    derived for it at all.
    """
    chosen = None
    for entry in agents_list:
        if isinstance(entry, dict) and entry.get("default"):
            chosen = entry
            break
    if chosen is None and agents_list:
        # `agents[0]` unconditionally, NOT the first dict. A truthy non-object entry survives
        # JS's own `listAgentEntries` filter (it drops only falsy ones), and `"junk"?.id` is
        # `undefined`, which normalises to the default id. Skipping to the first dict picked a
        # different default agent than the product does, and therefore derived a different set
        # of workspaces.
        chosen = agents_list[0]
    return _normalize_agent_id(chosen.get("id") if isinstance(chosen, dict) else None)


def _derived_agent_workspaces(config: dict) -> "list[str]":
    """Workspaces OpenClaw derives for agents that declare no `workspace` of their own (B-610).

    Rules 3 and 4 of `resolveAgentWorkspaceDir`: ``join(agents.defaults.workspace, id)`` when
    that default is set, else ``workspace-<id>`` under the state dir. Neither was constructed
    before, so a non-default agent's install records were not read at all.
    """
    agents = config.get("agents")
    if not isinstance(agents, dict):
        return []
    listed = agents.get("list")
    if not isinstance(listed, list) or not listed:
        return []
    defaults = agents.get("defaults")
    fallback = ""
    if isinstance(defaults, dict) and isinstance(defaults.get("workspace"), str):
        fallback = defaults["workspace"].strip()
    default_id = _default_agent_id(listed)
    out: list[str] = []
    for entry in listed:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            continue
        own = entry.get("workspace")
        if isinstance(own, str) and own.strip():
            continue
        agent_id = _normalize_agent_id(entry.get("id"))
        if agent_id == default_id:
            continue
        out.append(str(Path(fallback) / agent_id) if fallback else f"workspace-{agent_id}")
    return out


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
        # B-610: the two rules OpenClaw applies to an agent with no explicit workspace.
        extra.extend(Path(w).expanduser() for w in _derived_agent_workspaces(config))
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
    # name -> the ordered root identities that held a record under it, winner first.
    witnesses: dict = {}
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
            if name not in skills and len(skills) >= max_skills:
                capped = True
                break
            artifact, skill_file = _digest_pair(rec)
            version = rec.get("version")
            registry = rec.get("registry")
            entry = SkillOrigin(
                name=name,
                version=version if isinstance(version, str) else "",
                installed_at=_int_or_zero(rec.get("installedAt")),
                registry=registry if isinstance(registry, str) else "",
                artifact_sha256=artifact,
                skill_file_sha256=skill_file,
                # Built for the rival too, not just the winner. Corroboration is one of the
                # CONFLICT_FIELDS, so establishing it costs one bounded read per DUPLICATE
                # record — and skipping it is what let two workspaces with identical locks
                # and disagreeing origin.json files pass as one unambiguous subject.
                corroborated=_corroborate(root, name, rec),
            )
            witnesses.setdefault(name, []).append(_root_identity(home, root))
            won = skills.get(name)
            if won is None:
                skills[name] = entry
            elif won.conflict_tuple() != entry.conflict_tuple():
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
                #
                # What "different" means is CONFLICT_FIELDS, built through the same
                # `SkillOrigin` on both sides so the winner and the rival can never be
                # compared on different fields.
                won.ambiguous = True
    for name, origin in skills.items():
        ids = witnesses.get(name) or []
        origin.n_records = len(ids)
        # The FIRST identity, because the merge above is first-wins: the root that
        # contributed `skills[name]` is the root that appended `ids[0]`. Not `sorted(ids)`
        # and not a digest over all of them — the consumer needs to know WHICH record it is
        # looking at, and only the winner's identity answers that.
        origin.winner_root = ids[0] if ids else ""
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
