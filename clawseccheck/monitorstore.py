"""C-433 slice 1 — the monitor's own local STORE, split out of `monitor.py`.

`monitor.py` had grown to 4,916 lines and its size exemption had been restated three
times; the guard's own message says a restatement is not the answer. The task filed for it
proposed one module per watched dimension, and a measurement showed that plan cannot be
executed as written: `diff_with_notes` is one 1,635-line function whose 202 locals include
**61 read by more than one arm**, so a per-dimension cut is a data-flow rewrite, not a file
move.

This is the cut that IS a file move, and it was chosen for one measurable property:
**nothing here references a single `WATCHED_DIMENSIONS` key.** That matters because
`tests/test_c417_snapshot_enablers.py` derives, from the AST of `monitor.py`, every
snapshot key the module reads and asserts exact equality with the manifest. Code that reads
no dimension key cannot perturb that derivation — which is precisely why this slice is safe
and why the per-dimension one is not.

What lives here: reading and writing `state.json`, appending to and verifying the
hash-chained `events.jsonl`, rotating it, and the baseline reference/witness helpers. What
does NOT live here: anything that builds or compares a dimension. This module renders no
verdict and knows nothing about what a snapshot means — it only stores one.

**Every name is re-exported from `monitor.py`**, which is not a courtesy: 48 test modules
import these by name from there, and the `checks/` package's §3.1-a rule (no `__all__` on a
submodule, private helpers stay importable) applies here for the same reason.

Contract for this move: **byte-identical snapshot output**, verified against
`fixtures/home_safe` and `fixtures/home_vuln` before and after.
"""
from __future__ import annotations

import errno
import hashlib
import json
import re
from pathlib import Path

from .locking import journal_lock
from .safeio import secure_append_text, secure_dir, secure_write_text

DEFAULT_STATE = "~/.clawseccheck/state.json"
DEFAULT_EVENTS = "~/.clawseccheck/events.jsonl"
# B-270 — the three states a monitor baseline can be in, as decided in ONE place
# (``read_baseline``). ABSENT and CORRUPT used to be collapsed into a single None, which
# is what let a destroyed baseline render the same reassuring line as a genuine first run.
BASELINE_ABSENT = "absent"    # no state file at all — a real first run
BASELINE_CORRUPT = "corrupt"  # a file is there but carries no usable snapshot
BASELINE_OK = "ok"            # a non-empty dict snapshot to compare against
# Deliberately makes no claim about whether a replacement was written: this string is
# journaled BEFORE the new state file is saved, and the save can fail (B-271). Whether a
# replacement exists is stated by report.render_monitor, which knows the write's outcome.

# C-162: schema stamp for hash-chained journal lines (history.jsonl / events.jsonl).
# Stamped INSIDE the hashed payload (so verify_chain authenticates it too — a planted
# _schema value breaks the chain like any other tampered field). Bumped only for a
# genuine future format change to the chained entry shape; loaders skip a line whose
# _schema is a newer major than this build understands (see _iter_jsonl consumers)
# rather than risk misparsing it. Absent _schema (legacy pre-C-162 lines) still loads.
SCHEMA_VERSION = 1
# C-164: retention/rotation for the hash-chained journals (history.jsonl /
# events.jsonl). Once a journal exceeds _JOURNAL_MAX_LINES, it is pruned down to
# the last _JOURNAL_KEEP entries in one amortized batch (not every append) — see
# _rotate_journal. The gap between the two keeps rotation infrequent relative to
# append volume.
_JOURNAL_MAX_LINES = 5000
_JOURNAL_KEEP = 4000
def _now_iso() -> str:
    """The one clock the drift baseline and the event journal share.

    The snapshot's ``ts`` and a journal entry's ``ts`` are read against each other to
    answer "what happened since the last run", so they must come from a single producer
    rather than two copies of the same expression that a later edit could drift apart.
    Local time at second resolution — what the journal has always written; this helper
    changes where that string is produced, not what it says.
    """
    from datetime import datetime  # noqa: PLC0415 (local — see record_events)
    return datetime.now().isoformat(timespec="seconds")
def _chain_hash(prev_hash: str, entry: dict) -> str:
    """Return sha256(prev_hash + canonical_json(entry)) as a hex digest.

    *entry* must not contain the 'chain_hash' key itself.
    *prev_hash* is '' for the genesis entry.
    """
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    raw = (prev_hash + canonical).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
def _iter_jsonl(p: Path, *, skipped: "list | None" = None):
    """Stream-parse a JSONL file, yielding one dict per well-formed non-blank line.

    C-164: iterates the open file object line-by-line (never
    ``read_text().splitlines()``), so memory stays flat even on a large journal.
    Blank lines, JSON-decode errors, and non-dict top-level values are silently
    skipped (same graceful contract the previous read_text()-based loops had).

    C-177: opened with ``errors="replace"`` (same pattern as baseline.py's
    ``load_ignore``) so a non-UTF-8 byte anywhere in the file — a plausible
    crash-mid-write artifact — degrades that one line to unparseable-JSON
    (skipped, same as any other malformed line) instead of raising
    ``UnicodeDecodeError`` and permanently wedging every future invocation.

    C-250: when *skipped* (a list) is given, every non-blank line that could NOT be
    turned into a usable entry (a JSON-decode error, or valid JSON that isn't a dict —
    e.g. a tail-truncated final line from a write that died mid-append) is appended to
    it verbatim. Without this, ``verify_chain`` had no way to tell "the chain is clean
    because the file holds nothing else" apart from "the chain is clean over what could
    be parsed, and a trailing line was silently and invisibly dropped" — both rendered
    the identical bare ``OK``. Same opt-in out-param idiom ``_snapshot_memory_files``'s
    ``capped`` already uses: a caller that does not ask for it sees no behaviour change.
    """
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                if skipped is not None:
                    skipped.append(line)
                continue
            if isinstance(entry, dict):
                yield entry
            elif skipped is not None:
                skipped.append(line)
# The machine-readable causes `verify_chain` reports through its `cause` out-param when it
# returns the third outcome. Same vocabulary shape as `_verify_baseline`'s `_why`, and for
# the same reason: the CLI has to pick between sentences that say opposite things, and
# picking them by parsing the human message is how the sentences drift apart.
CHAIN_ABSENT = "absent"          # nothing at this path at all
CHAIN_NOT_A_FILE = "not_a_file"  # something is there, but it is not a regular file
CHAIN_EMPTY = "empty"            # a regular file of zero length
CHAIN_NO_ENTRIES = "no_entries"  # a file with content, none of it a parseable entry
CHAIN_UNREADABLE = "unreadable"  # it is there and could not be opened
CHAIN_BAD_PATH = "bad_path"      # this string cannot name a file at all
def verify_chain(events_path: "str | Path",
                 cause: "list | None" = None) -> "tuple[bool | None, str]":
    """Verify the hash-chain integrity of an events.jsonl file.

    THREE outcomes, never two (B-589):

    - ``(True, "OK…")``  — there is a chain here and it is intact. Also covers a
      journal whose entries all lack a 'chain_hash' (legacy graceful mode): that is a
      real chain with unverifiable rows, and the count is disclosed in the message.
    - ``(False, "broken at entry N")`` — there is a chain here and it does not hold.
    - ``(None, …)`` — there is **no chain here to verify**: the file is absent, empty,
      holds no parseable entry at all, or could not be read.

    The third outcome used to be folded into the first, and that made the crudest
    possible tampering pass the tamper check: ``rm history.jsonl`` turned a BROKEN
    verdict into ``History chain OK (…): OK`` with exit 0, and naming a path that never
    existed printed "OK" about a specific file the user believed held their history. An
    attacker erasing the event that recorded their own install did not have to defeat the
    hash chain at all. Absence is neither intact nor tampered.

    Flipping absence to ``False`` instead would be the opposite error and a worse one —
    ``--verify-baseline`` (F-173) reasoned it out first: a genuine first run, with no
    store written yet, would report tampering and send the user hunting an intruder who
    is not there. Hence a third value rather than the other half of the bool.

    Callers must test ``is True`` / ``is False`` / ``is None`` — a bare ``if ok:`` reads
    the third outcome as BROKEN, which is exactly the collapse this refuses.

    ``cause``: optional list. On the third outcome, one of the ``CHAIN_*`` codes above is
    appended to it. A caller that has to choose between "nothing has been written here
    yet" and "something IS here and it does not verify" needs to know which, and those two
    sentences say opposite things about the same exit code — an independent pass found the
    first one being printed over a default-location store holding 200 overwritten lines.
    Default ``None`` keeps the signature working for callers that only need the verdict.

    C-250: a bare "OK" used to also cover two OTHER gaps that C-167 had already fixed for
    unknown-schema entries but left asymmetric here — a mixed/legacy journal (some or all
    entries carry no 'chain_hash' at all) and a tail-truncated / partial-last-line journal
    (a write that died mid-append, so the final line is not valid JSON) both verified
    identically to a fully clean, fully chain-verified file. Three independent counts are
    now folded into the same disclosure parenthetical, in this order when more than one
    applies: unknown-schema entries (C-167), entries present but not chain-verified
    (legacy, no 'chain_hash' field — reconciles SECURITY_MODEL.md's "whole-file legacy
    carve-out" description with what this always did per-entry: a JOURNAL MIXING legacy
    and chained entries discloses only the legacy COUNT, not "the whole file is legacy"),
    and unparseable lines skipped entirely (see `_iter_jsonl`'s `skipped` out-param) — so
    "OK (1 unknown-schema entry present)" (the pre-existing wording, unchanged when it is
    the only note) can now read "OK (1 unknown-schema entry present; 2 entries not
    chain-verified (legacy, no chain_hash); 1 unparseable line skipped)".

    Returns (False, "broken at entry N") on the first mismatch.
    Never raises — an IO error yields the third outcome (``None``), not a pass: saying
    "OK" about a file that could not be opened is the same lie as saying it about one that
    is not there.

    Authenticates every field of every entry (including '_schema', C-162, and any
    entry whose '_schema' is a newer major than this build understands) — the
    unknown-schema skip policy belongs to the *loaders* (load_events/history.load),
    not to chain verification, which must authenticate the whole file regardless.
    """
    def _no_chain(code: str, message: str) -> "tuple[None, str]":
        if cause is not None:
            cause.append(code)
        return None, message

    try:
        p = Path(events_path).expanduser()
    except (OSError, RuntimeError) as exc:
        # `~unknownuser` raises RuntimeError straight out of expanduser(), which sat
        # outside this try and made the "never raises" contract above false.
        return _no_chain(CHAIN_BAD_PATH, f"no chain here — this path cannot be resolved "
                                         f"({exc})")
    try:
        if not p.is_file():
            # "It does not exist" and "it is not a regular file" are different facts, and
            # asserting the first about a directory, a FIFO or a dangling symlink repeats
            # the very mistake this function was fixed for: naming a cause the evidence
            # does not establish. Order matters — exists() follows the link, so a dangling
            # symlink is False there and True at is_symlink().
            if p.exists():
                return _no_chain(CHAIN_NOT_A_FILE,
                                 "no chain here — the path is not a regular file")
            if p.is_symlink():
                # Deliberately not "its target does not exist": exists() is also False for
                # a symlink LOOP, whose target does exist — it is the link. Claim only
                # what was established, which is that following it does not reach a file.
                return _no_chain(CHAIN_NOT_A_FILE,
                                 "no chain here — the path is a symlink that does not "
                                 "resolve to a readable file")
            return _no_chain(CHAIN_ABSENT, "no chain here — the file does not exist")
        _skipped: "list[str]" = []
        entries = list(_iter_jsonl(p, skipped=_skipped))
    except OSError as exc:
        # A malformed path is not an unreadable store. ENAMETOOLONG / ENOTDIR / ELOOP say
        # the string cannot name a file at all, and routing them to "unreadable" produced
        # a sentence telling the user to check the permissions of, and investigate who
        # locked down, a file that cannot exist.
        if exc.errno in (errno.ENAMETOOLONG, errno.ENOTDIR, errno.ELOOP):
            return _no_chain(CHAIN_BAD_PATH, f"no chain here — this path cannot name a "
                                             f"file ({exc.strerror or exc})")
        # A present-but-unreadable store is the same third state, not a pass: the one
        # thing this function must never say about a file it did not open is "OK".
        return _no_chain(CHAIN_UNREADABLE,
                         f"no chain could be read — {exc.strerror or exc}")

    if not entries:
        # No parseable entry at all. "Empty" and "nothing but garbage" are both "there is
        # no chain here", but they are different facts and the user acts on them
        # differently, so they get different sentences rather than one hedge.
        if _skipped:
            noun = "line" if len(_skipped) == 1 else "lines"
            return _no_chain(CHAIN_NO_ENTRIES,
                             f"no chain here — the file holds no readable entry "
                             f"({len(_skipped)} unparseable {noun})")
        return _no_chain(CHAIN_EMPTY, "no chain here — the file is empty")

    prev_hash = ""
    unknown_schema = 0
    unchained = 0
    for idx, entry in enumerate(entries):
        # Count lines the loaders would skip (C-167): present + authenticated here,
        # but hidden from load_events()/history.load() by the unknown-schema policy.
        if not _schema_ok(entry):
            unknown_schema += 1

        stored = entry.get("chain_hash")
        if stored is None:
            # Legacy entry — skip chain verification for this entry, carry prev_hash.
            # C-250: counted, not just silently tolerated — see the docstring above.
            unchained += 1
            continue

        # Recompute over the entry *without* the chain_hash field
        base = {k: v for k, v in entry.items() if k != "chain_hash"}
        expected = _chain_hash(prev_hash, base)
        if stored != expected:
            return False, f"broken at entry {idx}"
        prev_hash = stored

    notes = []
    if unknown_schema:
        noun = "entry" if unknown_schema == 1 else "entries"
        notes.append(f"{unknown_schema} unknown-schema {noun} present")
    if unchained:
        noun = "entry" if unchained == 1 else "entries"
        notes.append(f"{unchained} {noun} not chain-verified (legacy, no chain_hash)")
    if _skipped:
        noun = "line" if len(_skipped) == 1 else "lines"
        notes.append(f"{len(_skipped)} unparseable {noun} skipped")
    if notes:
        return True, "OK (" + "; ".join(notes) + ")"
    return True, "OK"
def chain_provenance_note(ok: "bool | None", msg: str) -> "str | None":
    """Turn a verify_chain() verdict into a one-line disclosure for a VIEWER
    (--trend / --watch-log) — never a verifier, which already has its own blunter
    wording (see ``_chain_verdict`` in cli.py, unchanged by this function). B-582:
    both viewers rendered a tool-owned store without ever running the check that
    exists for it, so a planted row displayed as fact with rc 0 while
    ``--verify-history``/``--verify-events`` on the identical file said BROKEN.

    Negative-only for a FULLY verified chain — not negative-only for every
    ``ok is True``. An earlier version of this also returned an affirmative
    "Chain verified" line on every ``ok is True``, and that was retracted before
    shipping: a line present on every healthy machine, every run, is exactly the
    "furniture within a week" shape ``report.py``'s coverage-note renderer
    already documents a rule against — a standing line drowns out the situational
    one it sits next to, which here is the one line that actually matters.
    Silence means an UNQUALIFIED ``"OK"`` — the chain verified in full — the same
    way silence already means "nothing was skipped" everywhere else in this
    tool. It does NOT mean any ``ok is True``: ``verify_chain`` itself
    distinguishes a third state — rows that predate F-094 chaining and so were
    never hashed at all, plus unknown-schema/unparseable rows it also counts —
    carried in its own parenthetical (e.g. ``"OK (2 entries not chain-verified
    (legacy, no chain_hash))"``). B-582's own reviewer found that third state was
    being flattened to the same silence as a fully-verified chain; the branch
    below is the fix. ``--verify-history``/``--verify-events`` are a different
    case (an explicit request to check the chain, answered either way) and are
    untouched by this change.

    Two constraints on the broken branch, both deliberate:

    - Never refuse to show the rows. This is the user's own local data; the fix is
      that they cannot be misled, not that they are locked out.
    - Never say "tampering". ``configjournal.py`` already established the
      precedent this mirrors: measured on a healthy real machine, 2 of 42 links in
      an unrelated hash chain were already broken from ordinary causes — a hand
      edit outside the writer, two writes racing from a common base. Log rotation
      produces the same shape here. A broken link is unverified provenance, not an
      accusation, and calling it tampering on an ordinary machine is a false
      positive with an unusually high cost.

    Returns ``None`` on two outcomes: ``ok is True`` with an unqualified
    ``"OK"`` (verified in full — say nothing) and ``ok is None`` (no chain to
    check at all — absent/empty/unreadable; should not happen when a caller
    already loaded rows from the same path moments earlier, and staying silent
    on a race is safer than a claim the evidence does not support, same
    reasoning as ``verify_chain``'s own third outcome). A THIRD outcome — ``ok
    is True`` but ``msg`` carries a parenthetical qualifier — returns a
    situational line naming it, below.
    """
    if not ok:
        if ok is None:
            return None
        match = re.search(r"entry (\d+)", msg)
        where = f"entry {match.group(1)} onward" if match else "an earlier point onward"
        return (
            f"Chain does not verify from {where}: unverified provenance, not evidence of "
            "tampering — an ordinary cause (a hand edit, two racing writes, log rotation) "
            "breaks a link the same way an edit would. Rows recorded from that point on "
            "cannot be confirmed as written by this tool."
        )
    if msg != "OK":
        # ok is True but qualified (legacy rows / unknown-schema entries /
        # unparseable lines skipped) — the third state; say so rather than
        # flattening it to the same silence as an unqualified OK.
        detail = msg[len("OK ("):-1] if msg.startswith("OK (") and msg.endswith(")") else msg
        return (
            f"Chain verifies except: {detail}. Those rows' provenance is unconfirmed, "
            "not evidence of tampering — the qualifier means they predate this tool's "
            "chaining or could not be parsed/authenticated, not that they were altered."
        )
    return None
def _rotate_journal(p: Path, max_lines: int = _JOURNAL_MAX_LINES,
                    keep: int = _JOURNAL_KEEP) -> None:
    """C-164: prune *p* to its last *keep* entries once it exceeds *max_lines*.

    No-op (file left byte-identical) when the line-count is at or below
    *max_lines* — rotation is amortized, not per-append. When it does trigger, the
    survivors' chain is RE-GENESISED: chain_hash is recomputed forward starting
    from prev_hash="" over each entry's own non-hash fields (including '_schema'),
    so ``verify_chain`` reports OK over the whole survivor file afterwards — this
    is what prevents the spurious "chain BROKEN" that simply truncating the file
    would cause (the survivors' original hashes point at now-deleted history).

    This re-genesis is a deliberate, documented local trust boundary: rotation
    itself is not tamper-evident across the rotation boundary (an attacker with
    write access to the file could rotate-and-forge), only within a generation.

    C-250: rotation used to evict up to ``max_lines - keep`` entries (1002 by
    default) with no trace whatsoever — ``render_events`` then printed an
    authoritative-sounding "{keep} recorded change event(s)" starting silently
    mid-history, with nothing on screen to say a prefix of the real history was
    ever cut. A synthetic RETENTION-MARKER entry is now prepended as the new oldest
    survivor, chained like any other (it participates in re-genesis normally), so
    the disclosure travels WITH the file — a copy, a later ``load_events``, or
    ``render_events`` all see it without re-deriving anything. Distinguished by the
    ``retention_pruned`` key (an int, the count evicted THIS rotation); shaped with
    ``ts``/``level``/``message`` like a normal events.jsonl entry so it renders as an
    ordinary line with no report.py special-casing needed, and shaped WITHOUT
    ``date``/``score``/``grade`` so ``history.load()``'s existing
    ``{"date": obj["date"], ...}`` KeyError guard skips it silently and harmlessly
    when this same function backs history.jsonl (see ``history.record``) — a
    marker meant for a human reading the events journal must not corrupt the trend
    line's own row shape.

    A marker only discloses the rotation that PRODUCED it: on a later rotation, an
    older marker can itself age out of the ``keep`` window like any other entry, at
    which point the loss it recorded ages out with it. That is the same bounded,
    local-file honesty this module cannot promise past a rotation boundary anywhere
    else (see the re-genesis note above) — not a new gap.

    Must be called from inside the caller's ``journal_lock`` critical section
    (immediately after an append) — it does not take the lock itself.
    Never raises: any OSError during read/rewrite is swallowed, leaving the
    file as last known good (an unrotated, still-valid, still-growing journal).
    """
    try:
        if not p.is_file():
            return
        entries = list(_iter_jsonl(p))
        if len(entries) <= max_lines:
            return  # no-op — file untouched, byte-identical

        pruned = len(entries) - keep
        survivors = entries[-keep:]
        when = _now_iso()
        noun = "entry" if pruned == 1 else "entries"
        marker = {
            "ts": when,
            "level": "INFO",
            "message": (f"{pruned} older {noun} were pruned by retention at {when} "
                        f"(retention cap: newest {keep} of {max_lines} kept)."),
            "_schema": SCHEMA_VERSION,
            "retention_pruned": pruned,
        }

        prev_hash = ""
        rechained: list[str] = []
        for entry in [marker, *survivors]:
            base = {k: v for k, v in entry.items() if k != "chain_hash"}
            ch = _chain_hash(prev_hash, base)
            rechained.append(json.dumps({**base, "chain_hash": ch}))
            prev_hash = ch

        secure_write_text(p, "\n".join(rechained) + "\n")
    except OSError:
        pass
def read_baseline(path: str | Path = DEFAULT_STATE) -> "tuple[str, dict | None]":
    """B-270: the ONE definition of "is there a usable monitor baseline?".

    Returns ``(status, snapshot)`` where *status* is one of ``BASELINE_ABSENT`` /
    ``BASELINE_CORRUPT`` / ``BASELINE_OK`` and *snapshot* is the parsed dict only when the
    status is OK.

    Before this, ``load_state`` returned raw ``json.loads`` output and collapsed absent,
    corrupt and unreadable into a single ``None``, and three call sites each decided for
    themselves what that meant — ``diff()`` on truthiness, ``cli.py`` on ``is None`` for the
    "first run" wording and on ``is not None`` for the tamper sub-grade. The three
    disagreed, which is what produced these measured behaviours against a state file
    holding ``{}``/``[]``/``0``/``""``/``false``: ``diff()`` saw a falsy baseline and
    returned no alerts, the wording call site saw "not None" and rendered *No new threats
    since last check* over a config that had genuinely changed, and the tamper sub-grade
    saw "present" and awarded full HIGH-weight credit for a baseline that could not detect
    anything (measured on ``fixtures/home_safe``: 24/100 with ``{}`` on disk vs 3/100 with
    no file at all — 21 points of hollow credit).

    Splitting *absent* from *corrupt* is the point. Collapsing them is what let a corrupt
    baseline render the reassuring first-run line "Baseline saved." — indistinguishable
    from a genuine first run, so a silently destroyed baseline looked like a healthy new
    one. ``tests/test_b107_atomic_write.py`` names this exact harm; B-107 fixed only the
    write side.

    A file that exists but cannot be read, parsed, or is not a non-empty JSON object is
    CORRUPT, not ABSENT: a directory at the state path, a 0-byte file, a truncated write, a
    ``chmod 000``, a planted (possibly broken) symlink, and a hand-edited ``null``/``42``/
    ``"abc"``/``[1,2,3]`` all land here rather than being mistaken for a first run.

    ⚠ Scope — this NARROWS L1, it does not close it. Two gaps remain, both by construction:

    * A forged but structurally *valid* snapshot still wins. Nothing here authenticates the
      file's contents against the run that wrote it — this validates shape, not provenance.
    * **Deletion still reads as ABSENT.** An attacker who can write the state file can also
      remove it, and a removed baseline is indistinguishable from a genuine first run using
      the state file alone, so it still renders "Baseline saved." Detecting that needs an
      out-of-band record that a baseline once existed (the journal or the history file
      could carry one); that is a separate design, deliberately not half-built here.

    What it does close is the *corruption* half: a baseline that is present but unusable can
    no longer masquerade as either a healthy first run or a clean comparison.
    """
    p = Path(path).expanduser()
    # `exists()` follows symlinks, so a broken symlink reports False — check the link
    # itself too, or a planted dangling symlink at the state path reads as "first run".
    if not p.exists() and not p.is_symlink():
        return BASELINE_ABSENT, None
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError:
        # Unreadable (perms), a directory, a dangling symlink: present but unusable.
        return BASELINE_CORRUPT, None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return BASELINE_CORRUPT, None
    if not isinstance(payload, dict) or not payload:
        # Non-dict payloads are what crashed diff() with an AttributeError at
        # `prev.get("skills", {})` — and because the crash happened BEFORE save_state, the
        # poison was never replaced, so the failure repeated on every subsequent run.
        # An empty dict is equally unusable: every dimension comparison is a no-op.
        return BASELINE_CORRUPT, None
    return BASELINE_OK, payload
def load_state(path: str | Path = DEFAULT_STATE) -> dict | None:
    """The previously saved snapshot, or None when there is no *usable* one.

    B-270 narrowed this: it now returns None for a present-but-unusable baseline as well as
    an absent one, so no caller can reach ``diff()`` with a payload that is not a non-empty
    dict. Callers that need to tell *absent* from *corrupt* apart — the report wording and
    the tamper sub-grade both do — must use ``read_baseline`` instead.
    """
    return read_baseline(path)[1]
def save_state(path: str | Path, snap: dict) -> None:
    p = Path(path).expanduser()
    # Symlink-safe: create the dir 0700 and refuse to follow a symlinked target,
    # so a planted symlink can never turn this write into an arbitrary-file clobber.
    secure_dir(p.parent)
    secure_write_text(p, json.dumps(snap, indent=2))
# F-173: snapshot fields deliberately EXCLUDED from the baseline reference.
#
# The first version of this feature hashed the state file's raw BYTES, and an independent
# adversarial pass killed it in one command: `state.json` carries `ts` (C-417 put it there,
# so "what happened since the last run" is answerable), so three consecutive runs against a
# completely untouched home produced three different references —
#
#     "Baseline advanced to fca496141fa87813."
#     "Baseline advanced to 070c087f044f5732."
#     "Baseline advanced to cb741da3adc5dfae."
#
# — while a diff of two consecutive baselines showed the `ts` line and nothing else. The
# value that travels OFF the machine (the whole point of the feature) would then have told
# the user to investigate a condition that holds after every scheduled run on a healthy
# machine, and `--verify-baseline` could only ever match inside one cron interval.
#
# So the reference describes the baseline's CONTENT, not its bytes. That is also the better
# primitive on its own merits: a forged baseline with different content moves it, and a
# forged baseline with identical content changed nothing that is watched.
# B-676 joins it, and for the same class of reason rather than by analogy. `not_compared`
# records which comparisons the RUN could not make, which is a property of the run and of
# this build, not of the user's setup — and it is written only on a run that had a usable
# baseline, so it is guaranteed ABSENT on the first run of any new baseline and PRESENT on
# the second. Leaving it in moved the reference between run 1 and run 2 of an untouched
# machine and journaled a witness event for it, breaking the three F-173 invariants that
# exist to stop exactly that (`test_two_runs_over_an_untouched_setup_give_the_SAME_reference`,
# `test_verify_still_matches_after_a_later_run_changed_nothing`,
# `test_a_quiet_run_adds_no_journal_line`). The user-facing signal for a coverage change is
# an ALERT from `monitordims/_coverage.py`, which is the actionable channel; the reference
# does not need to double as a second, vaguer one.
_REFERENCE_VOLATILE_KEYS = frozenset({"ts", "not_compared"})
# How many hex characters of the reference are shown and compared. Short enough to read off
# a phone screen and retype, long enough that finding a second baseline with the same prefix
# is not something an attacker does on the way past — 16 hex chars is 64 bits.
# `--verify-baseline` accepts any prefix at least this long, so a user who pasted the full
# value is not told it is wrong.
BASELINE_DIGEST_CHARS = 16
def snapshot_reference(snap: "dict | None") -> str:
    """F-173: a stable fingerprint of everything a baseline records, minus the clock.

    Canonical JSON (sorted keys, no whitespace) so key order and indentation cannot move
    it, and ``""`` for anything that is not a usable snapshot.

    What it does and does not mean, stated here because the wording everywhere else has to
    match it: this moves when ANYTHING the watch records moves — including a ClawSecCheck
    upgrade that adds checks, which changes `checks` and `watched` without the user having
    touched a thing. It is a fingerprint of the recorded state, not a tamper alarm, and no
    caller may present a mismatch as evidence of anything on its own.
    """
    if not isinstance(snap, dict) or not snap:
        return ""
    trimmed = {k: v for k, v in snap.items() if k not in _REFERENCE_VOLATILE_KEYS}
    try:
        canonical = json.dumps(trimmed, sort_keys=True, separators=(",", ":"),
                               default=str)
    except (TypeError, ValueError):
        return ""
    return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()
def baseline_reference(path: str | Path = DEFAULT_STATE) -> "tuple[str, str]":
    """The stored baseline's reference, as ``(value, reason)``.

    *reason* is ``"ok"``, ``"absent"`` (no such file) or ``"unreadable"`` (it is there and
    we could not parse or read it) — three states rather than one empty string, because an
    independent pass found the CLI printing "no baseline has been saved yet" over a
    `state.json` that was present and unreadable. That sends the user to re-run `--monitor`,
    which is the one action that overwrites the evidence.

    Read back FROM DISK rather than fingerprinted from the dict still in memory: it is the
    file a later `--verify-baseline` will re-read, and a short write that left it truncated
    fails to parse here instead of matching.
    """
    p = Path(path).expanduser()
    try:
        raw = p.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return "", "absent"
    except OSError:
        return "", "unreadable"
    try:
        snap = json.loads(raw)
    except ValueError:
        return "", "unreadable"
    value = snapshot_reference(snap)
    return (value, "ok") if value else ("", "unreadable")
def baseline_witness_event(reference: str) -> "list[tuple[str, str]]":
    """The one journal entry recording that the baseline's reference MOVED, or ``[]``.

    A list, so the caller passes it straight to ``record_events`` and an unavailable
    reference records nothing rather than journaling a sentence with a hole in it.

    The caller must only call this when the value actually changed. Journaling it on every
    run was the first version, and it broke three things at once: two existing tests that
    pin "a first monitor run journals nothing", `--brief`'s event count (a daily cron would
    report "365 event(s) recorded" over a timeline of nothing), and the journal's own
    retention — one unconditional line per run against a 5,000-line cap eventually evicts
    the genuine drift alerts a quiet machine had kept.
    """
    if not reference:
        return []
    return [("INFO", f"Baseline reference is now {reference[:BASELINE_DIGEST_CHARS]}. Keep "
                     f"it somewhere off this machine; check it later with "
                     f"--verify-baseline.")]
def verify_baseline(expected: str, path: str | Path = DEFAULT_STATE
                    ) -> "tuple[bool | None, str, str]":
    """F-173: does the stored baseline still fingerprint to *expected*?

    Returns ``(verdict, actual, reason)``. ``verdict`` is None — not False — whenever there
    is nothing to compare, and *reason* says which nothing it was: ``"absent"``,
    ``"unreadable"``, ``"reference_too_short"``, or ``"ok"`` when a real comparison happened.
    Three verdicts, because "it does not match" and "I could not check" ask the reader for
    opposite reactions, and collapsing them is how a missing file starts reporting as
    tampering.

    Matching is done on a prefix so the value a user copied out of a report or a phone
    notification verifies as-is, and it is case-insensitive because that string will have
    been retyped by hand at least once.
    """
    want = (expected or "").strip().lower()
    actual, reason = baseline_reference(path)
    if not actual:
        return None, "", reason
    if len(want) < BASELINE_DIGEST_CHARS:
        return None, actual, "reference_too_short"
    return actual.startswith(want), actual, "ok"
def _last_chain_hash(p: Path) -> str:
    """Return the 'chain_hash' of the last entry in a JSONL file, or '' if none.

    C-164: streams via ``_iter_jsonl`` (line-by-line) rather than reading the
    whole file into one big list-of-lines, so memory stays flat on a large file;
    only the running "last chain_hash seen so far" is retained.
    """
    if not p.is_file():
        return ""
    last = ""
    try:
        for entry in _iter_jsonl(p):
            val = entry.get("chain_hash")
            if val is not None:
                last = str(val)
    except OSError:
        return ""
    return last
def record_events(alerts, path: str | Path = DEFAULT_EVENTS,
                  when: str | None = None) -> "str | None":
    """Append each drift alert to a local, owner-only event journal (a timeline of
    what changed when). No-op when there are no alerts. Never uploaded — local only.

    B-278: returns None on success (including "nothing to record"), and the OSError text
    when the append FAILED. It still never raises — ``tests/test_symlink_safety.py``
    pins that a planted symlink at the journal path must not take a monitor run down —
    but the failure is no longer invisible. Silently dropping an append is the worst
    failure mode a tamper-evident journal has: the record looks intact and is not.
    Reproduced with a plain ``chmod 0444`` on events.jsonl — no attacker, no symlink: a
    CRITICAL "Gateway bind changed 127.0.0.1 -> 0.0.0.0" alert printed, rc=0, the journal
    stayed 0 bytes, and because the baseline had already advanced the next run reported
    "No new threats since last check" over the now-exposed gateway. The caller is
    responsible for not consuming the event when this returns non-None (see cli.py).

    Each entry carries a 'chain_hash' field: sha256(prev_chain_hash + canonical_json)
    so the journal is tamper-evident. Existing entries without 'chain_hash' are treated
    as the chain genesis (backward compatible). Each entry also carries '_schema'
    (C-162) INSIDE the hashed payload, so it is itself tamper-evident.

    B-108: the read-last-hash→append critical section runs under an advisory
    ``journal_lock`` so two concurrent monitor runs can't both read the same prev
    chain_hash and each append, which would otherwise leave a spurious
    "chain BROKEN" that neither writer actually caused.

    C-164: after appending, the file is opportunistically rotated (pruned +
    re-chained) once it exceeds the retention cap — see ``_rotate_journal``.
    """
    if not alerts:
        return None
    if when is None:
        when = _now_iso()
    p = Path(path).expanduser()
    try:  # symlink-safe append; never RAISE from the event journal — report instead
        secure_dir(p.parent)
        with journal_lock(p):
            prev_hash = _last_chain_hash(p)
            lines_out: list[str] = []
            # C-465: redact at the journal boundary.
            #
            # Both transient channels already do — the text renderer and `--monitor --json`
            # run every message through `report._sanitize`, which calls `logsafe.redact`,
            # and that helper's own comment explains why it is one shared point: "secret
            # redaction cannot be accidentally implemented for JSON while remaining absent
            # from text/SARIF/HTML". The journal is not a renderer, so it sat outside that
            # boundary — and it is the one channel that is append-only and hash-chained,
            # i.e. the one where a leaked value is permanent. The asymmetry pointed the
            # wrong way: the durable channel protected less than the ephemeral one.
            #
            # No live leak today; redaction is done at the SOURCE (`monitordims/_mcp.py`
            # runs command/args through `redact_urls_in_text` before they enter the
            # snapshot, `_channels.py` hashes secret-bearing fields, and the 78
            # `alerts.append` sites interpolate names and counts). This is defence in
            # depth, and it is what makes a future secret-bearing dimension safe by
            # construction rather than by remembering.
            #
            # LAZY, and not by preference: `logsafe` imports from `checks`, so a module
            # level import here would pull the whole engine into the store. `report.py`'s
            # `_sanitize` takes the same lazy import for the same reason, and says so.
            #
            # `redact` is idempotent, so a value already redacted at the source is
            # unchanged. Only NEW entries are affected; existing lines keep their bytes and
            # `verify_chain` recomputes from what is stored, so the chain stays valid
            # across the change.
            from .logsafe import redact  # noqa: PLC0415
            for lvl, msg in alerts:
                base = {"ts": when, "level": lvl, "message": redact(msg),
                        "_schema": SCHEMA_VERSION}
                ch = _chain_hash(prev_hash, base)
                entry = {**base, "chain_hash": ch}
                lines_out.append(json.dumps(entry))
                prev_hash = ch
            secure_append_text(p, "\n".join(lines_out) + "\n")
            _rotate_journal(p)
    except OSError as exc:
        return str(exc)
    return None
def _schema_ok(entry: dict) -> bool:
    """C-162 loader policy: absent/legacy _schema loads; == current loads; a NEWER
    major than this build understands is skipped (no crash, no misparse).

    Skipping is a *loader* concern only: an unknown-future-schema line is
    hidden-but-present, not deleted, and verify_chain() authenticates it, counts it,
    and surfaces the count in its OK message (C-167 — a forged _schema on an honest
    line breaks the chain). So this skip cannot silently erase evidence beyond the
    pre-existing "write access breaks tamper-evidence" boundary."""
    raw = entry.get("_schema")
    if raw is None:
        return True
    try:
        return int(raw) <= SCHEMA_VERSION
    except (TypeError, ValueError):
        # Non-numeric _schema is itself a malformed/tampered line — don't misparse it.
        return False
def load_events(path: str | Path = DEFAULT_EVENTS, limit: int | None = None) -> list[dict]:
    """Read the event journal (chronological). Returns [] if absent/unreadable.

    C-162: a line whose '_schema' is a newer major than this build understands is
    skipped (siblings still load); absent/legacy or current '_schema' loads normally.

    Silently returns [] on any read problem, same as always — a caller that needs to
    know WHY (B-581) wants ``load_events_with_problem`` instead, which this delegates to.
    """
    out, _problem = load_events_with_problem(path, limit=limit)
    return out
def load_events_with_problem(
    path: str | Path = DEFAULT_EVENTS, limit: int | None = None,
) -> "tuple[list[dict], OSError | None]":
    """Same entries as ``load_events()``, plus the ``OSError`` that made the read fail.

    B-581: mirrors ``history.load_with_problem`` — see there for why there is no
    ``Path.is_file()`` pre-check (it can itself raise ``PermissionError`` on Python
    3.12 for a stat-inaccessible path) and why classifying "did this fail" is split
    from "should this be shown" (the latter is cli.py's ``_explicit_paths`` call).
    """
    p = Path(path).expanduser()
    out: list[dict] = []
    try:
        # C-164: stream line-by-line via _iter_jsonl (not read_text().splitlines())
        # so memory stays flat on a large journal.
        for entry in _iter_jsonl(p):
            if not _schema_ok(entry):
                continue
            out.append(entry)
    except OSError as exc:
        return [], exc
    return (out[-limit:] if limit else out), None
