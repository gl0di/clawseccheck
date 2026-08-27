"""The config-file identity dimensions — `config_file_sha256`, `config_resolved_sha256`
and `config_journal_head`.

Not a settings dimension: this is the identity of the FILE, and of OpenClaw's own record of
who wrote it. F-170's journal is what makes attribution possible at all — it can see a change
made and REVERTED between two runs, which no snapshot diff can — so the arms that read it
live here with the digests they corroborate.

A broken chain link is reported as UNKNOWN PROVENANCE, never as tampering: measured on a
healthy real machine, 2 of 42 links were already broken.
"""

from __future__ import annotations
import hashlib
import json

from ._shared import NOTE_UNDETERMINED  # noqa: F401


def _diff_config_digest_unmoved(_c_digest, _c_head, _p_digest, _p_head, alerts) -> None:
    """The config bytes did not move but OpenClaw's journal head did.

    A write that produced no change is still a write. Reported quietly, because the benign
    cause — a rewrite with identical content — is the common one.
    """
    if (_p_digest and _c_digest and _p_digest == _c_digest
            and _p_head and _c_head and _p_head != _c_head):
        # ARM 3 — the signal no snapshot diff can produce, and the reason this task exists.
        # The config reads identical to last time, but OpenClaw journaled at least one write
        # in between: it was changed and put back. Comparing the journal HEAD rather than
        # timestamps makes this exact and self-limiting — the head advances once, so this
        # fires once.
        #
        # INFO: a revert is usually a person trying something and undoing it. What makes it
        # worth a line at all is that the snapshot diff is structurally blind to it, so
        # silence here is not "nothing happened" but "we could never have known".
        alerts.append((
            "INFO",
            "Your settings were changed and changed back between these two checks — the "
            "file matches last time's, but OpenClaw recorded a write in between. A "
            "snapshot comparison alone cannot see this.",
        ))


def _diff_config_journal(
        _c_digest,
        _c_head,
        _config_alerts_from,
        _config_alerts_to,
        _journal_seen,
        _p_digest,
        _trajectory_alerts,
        alerts,
        curr,
) -> None:
    """F-170: attribute a config change to the write that produced it, or say nobody claimed it.

    Attribution requires that the journaled write STARTED from the bytes the previous
    snapshot recorded; without that the stamp names the newest write regardless of how many
    happened in between, which once handed a hand edit OpenClaw's own provenance.
    """
    if _p_digest and _c_digest and _journal_seen:
        _by = curr.get("config_written_by")
        # Attribution requires evidence that THIS write produced the change we are about to
        # blame it for: the journaled write must have STARTED from the bytes the previous
        # snapshot recorded. Without that check the stamp names the newest write regardless
        # of how many happened in between, so a hand edit followed by any OpenClaw write
        # handed the resulting CRITICAL alert OpenClaw's own provenance — a false
        # exoneration, written into a tamper-evident journal. An older snapshot with no
        # `previous_hash` recorded simply does not qualify, and stays unattributed.
        _single_write = (isinstance(_by, dict)
                         and _by.get("previous_hash")
                         and _by.get("previous_hash") == _p_digest)
        if _c_digest != _p_digest and _single_write:
            # ARM 1 — attribution, not a new alert. The drift alerts above already say
            # WHAT changed; a separate "your config changed" line would be the same edit
            # reported twice, which `diff()` already avoids in three other places (the
            # bootstrap/memory overlap, the new-file overlap, the args_pkg/args0 collapse).
            # Appended to every config-derived alert rather than just the first: each one
            # reaches the tamper-evident journal as its own entry and is sorted away from
            # its neighbours in the report, so each has to carry its own provenance.
            _parts = ["written"]
            if _by.get("ts"):
                _parts.append(str(_by["ts"]))
            if _by.get("pid") is not None:
                _parts.append(f"by pid {_by['pid']}")
            _parts.append(f"({_by.get('argv0') or 'unknown program'})")
            _who = "[" + " ".join(_parts) + "]"
            for _i in range(_config_alerts_from, min(_config_alerts_to, len(alerts))):
                if _i in _trajectory_alerts:
                    continue
                _lvl, _msg = alerts[_i]
                alerts[_i] = (_lvl, f"{_msg} {_who}")
        elif _c_digest != _p_digest and _c_head and _c_digest != _c_head:
            # ARM 2 — the config changed and OpenClaw's writer did not produce the bytes
            # that are there now.
            #
            # MEDIUM is a ceiling, not a judgement call. The benign causes are ordinary and
            # numerous — `vim`, `jq ... > tmp && mv`, a dotfile manager swapping a symlink,
            # a backup restore — and they are the same benign-atomic-replace family already
            # documented in _degrade_snapshot. Worded as an observation asking for
            # confirmation, because that is all the evidence supports.
            #
            # Gated on the digest having CHANGED, so it is news exactly once. Firing it
            # whenever the live bytes merely disagree with the journal head would nag on
            # every run forever after one hand edit, and a warning that cannot be cleared
            # is one the reader learns to skip.
            alerts.append((
                "MEDIUM",
                "Your settings file changed, and no completed record of that write was "
                "found in OpenClaw's own config log. That is normal for a hand edit, an "
                "editor that replaces the file, a restored backup, or a write OpenClaw has "
                "not finished logging yet — but it is also what an edit made behind your "
                "back looks like. Confirm you made this change.",
            ))


def _note_unmodelled_config_edit(
        _checks_alerts_from,
        _checks_alerts_to,
        _config_alerts_from,
        _config_alerts_to,
        _trajectory_alerts,
        alerts,
        compare_config,
        curr,
        curr_blind,
        note,
        prev,
        prev_blind,
) -> None:
    """B-659: the settings file changed and nothing this build compares inside it did.

    A NOTE, never an alert — the alert form of this was considered and rejected, because
    OpenClaw writes its own bookkeeping keys on every upgrade and an unnamed "config hash
    changed" is unactionable. The full reasoning is inline below; read it before promoting
    this to an alert.
    """
    # B-659: the settings file changed and nothing this build compares in it did.
    #
    # C-418's contract is that no all-clear is printed over a comparison this run skipped.
    # That scoping is bounded by the same model that produced the blindness: it can only
    # list a skip the code KNOWS about, and a config namespace nobody ever modelled is
    # neither compared nor listed. `_CONFIG_DIMENSIONS` is five fields (`plugins` joined them);
    # `tools.*`, `hooks.*`, `cron`, `agents.*`, `browser.*` and `secrets.providers` reach
    # the monitor only if some check's STATUS happens to move. Measured: appending an entry
    # to `plugins.allow` — a new trust grant, since that list decides which plugins may
    # load — moved zero of 188 check statuses, moved `config_file_sha256`, and produced
    # "No new threats among what was compared" with nothing in the un-compared list.
    #
    # THIS IS NOT THE DESIGN THE EPIC REJECTED, and the distinction is the whole reason it
    # can ship. What was rejected is hashing the parsed config as a catch-all ALERT: OpenClaw
    # itself writes `meta.lastTouchedAt/Version` and `wizard.lastRun*`, so an alert would
    # fire on every upgrade with zero security content, and an unnamed "config hash changed"
    # is unactionable. A NOTE is a different channel with a different contract — it says
    # only "this run did not compare that", it is collapsed to a count unless the reader
    # asks, it never reaches the event journal, and it cannot page a scheduled job. The
    # rejected design's failure mode is alert noise; this one has no alert to make noise
    # with. Do not "promote" it to an alert without re-reading that rejection.
    #
    # Deliberately narrow, because a note on every real change would inflate the
    # "N things could not be compared" count until nobody reads it:
    #   * only when a digest actually MOVED — an unchanged file says nothing, which is what
    #     keeps the false-positive gate (two runs over an unchanged home) silent;
    #   * only when NO config-derived alert fired. If drift was already named, the change is
    #     accounted for and this would be the same edit reported twice;
    #   * never on a blind run, where "the config was not compared" is already said louder.
    # Both digests are consulted, so an edit inside an $include fragment counts too: the
    # root digest cannot see one, and until now nothing read the resolved digest at all.
    if compare_config and not (prev_blind or curr_blind):
        # "Named" means THIS RUN ALREADY TOLD THE USER SOMETHING about the same edit, and
        # that is broader than the config dimensions. Measured: `tools.profile` -> "all"
        # moves no config dimension but turns three checks PASS -> WARN, and the run printed
        # all three regressions by name and then added this note saying it "cannot tell you
        # what it was" — a sentence the same screen refuted three lines above. `tools.*` is
        # not compared as a dimension, but its consequences were named, so the note has
        # nothing left to add.
        #
        # Check transitions are the right second term rather than "any alert at all": a
        # skills or host alert in the same run says nothing about the settings file, and
        # letting it suppress this would hide an unmodelled config edit behind an unrelated
        # event. Trajectory-derived entries stay excluded from the config span for the same
        # reason F-170 excludes them from attribution — their evidence is not the config.
        _named_config_drift = any(
            _i not in _trajectory_alerts
            for _i in range(_config_alerts_from, min(_config_alerts_to, len(alerts)))
        ) or _checks_alerts_to > _checks_alerts_from
        _pf, _cf = prev.get("config_file_sha256"), curr.get("config_file_sha256")
        _pr, _cr = prev.get("config_resolved_sha256"), curr.get("config_resolved_sha256")
        _file_moved = bool(_pf) and bool(_cf) and _pf != _cf
        _resolved_moved = bool(_pr) and bool(_cr) and _pr != _cr
        if (_file_moved or _resolved_moved) and not _named_config_drift:
            note(NOTE_UNDETERMINED,
                 "Your settings file changed since the last check, but nothing this "
                 "version compares inside it did — so the change is in a part of the file "
                 "this version does not watch, and this run cannot tell you what it was. "
                 "Run a full check to see the current verdicts.")


def _config_file_digest(ctx) -> str:
    """sha256 of the config file's bytes as the AUDIT read them, or ``""`` if there is none.

    Reads ``ctx.config_sha256``, which the loader recorded on its own read (see
    ``configloader.load_openclaw_config``'s ``root_digest``). It deliberately does NOT
    re-read the file: a second read is a second file whenever anything writes in between,
    and a snapshot that pairs one file's digest with another file's ``gateway_bind`` is a
    record true of no single moment. That was a real defect in this function's first
    version — a config edited between the audit and the snapshot produced a baseline whose
    digest already matched the *new* bytes, so the very next run saw an unchanged digest
    across the change ``diff()`` was firing CRITICAL on.

    The bytes, deliberately, not the parsed dict: parsing normalizes away comments and
    key order, so a byte-level edit can leave the parsed view identical and vanish. The
    trade runs the other way for ``$include`` — a fragment edit changes the parsed dict
    and leaves these bytes untouched. So this digest covers the ROOT file and nothing
    else: an unchanged value means "the root file is unchanged", never "the config is
    unchanged", and a consumer that reads it as the latter would be wrong silently, which
    is the failure mode this epic exists to remove. Widening it needs the loader to report
    the fragment paths it read — filed separately rather than assumed here.
    """
    return getattr(ctx, "config_sha256", None) or ""


def _config_resolved_digest(ctx) -> str:
    """sha256 of the FULLY RESOLVED config — root plus every ``$include`` fragment.

    B-527: ``_config_file_digest`` above covers the root file's bytes only, so a config
    whose security posture lives in an ``$include`` fragment (bind address, gateway, MCP
    servers, ...) can have a byte-stable root digest across a total posture change — the
    fragment is merged into ``ctx.config`` but never hashed. Measured: editing a fragment's
    ``"bind": "127.0.0.1"`` to ``"0.0.0.0"`` left ``config_file_sha256`` unchanged.

    This closes that gap WITHOUT a second file read: it hashes ``ctx.config``, the dict
    ``configloader.load_openclaw_config`` already produced by resolving and deep-merging
    every fragment on the SAME read that captured the root digest. Re-reading the fragments
    here to hash their raw bytes would reopen the exact race ``_config_file_digest``'s
    docstring documents — a fragment edited between that read and this one would pair one
    moment's digest with another moment's parsed values (``mcp``, ``gateway_bind``, ...) in
    the same snapshot. Hashing the already-resolved dict has no second read to race.

    ``json.dumps(..., sort_keys=True)`` makes the digest depend only on the resolved
    VALUES, never on which fragment contributed a key or the order fragments were merged
    in — the "path ordering must not move the digest" property, translated from paths to
    keys. The trade is the mirror of ``_config_file_digest``'s: a comment-only or
    key-order-only edit to the ROOT file can leave this digest unchanged (parsing already
    normalized that away), which is exactly what the root byte digest still covers.

    Returns ``""`` when there is nothing to hash — but note that ``ctx.config`` defaults
    to ``{}``, which IS a dict, so "nothing to hash" is narrower than "no config was read".
    An earlier version of this line claimed both digests are absent together on a blind run;
    that was false as written, and measured: on a home with no ``openclaw.json`` and no prior
    baseline the caller stored ``sha256("{}")`` here while ``config_file_sha256`` was absent.
    The caller now gates this write on ``ctx.config_found`` and the two really are absent
    together — the invariant holds at the CALL SITE, not in this function.

    WHAT THIS DIGEST IS NOT: the identity of the files that produced the config. Two
    ``$include`` targets with identical contents, or a fragment whose keys duplicate values
    already present, resolve to the same dict and so to the same digest. That is deliberate
    — a drift monitor asks "did the configuration my agent runs under change", and the
    answer there is no. Recording which FILE was authoritative is a different question
    (B-527's work-item 1, a per-fragment ``(path, sha256)`` set) and was not built: it needs
    a ``configloader`` change, it would put fragment paths — which can carry a username or a
    private repo name — into a field this project keeps free of them, and nothing in the
    threat model turns on source identity once the resolved values are covered.
    """
    config = getattr(ctx, "config", None)
    if not isinstance(config, dict):
        return ""
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
