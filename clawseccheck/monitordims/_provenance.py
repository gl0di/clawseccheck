"""The `skill_provenance` dimension — where each installed skill came from, over time.

F-174. `skillprovenance.py` is the reader; this is the comparison. B181 already reads these
digests for a point-in-time verdict — this watches them MOVE, which is how an update is
DETECTED with no cooperation from the user.

`changed_skills` lives here too: it answers "which skills moved since the baseline", off the
same records the arm compares, and the two would drift apart in separate files.
"""

from __future__ import annotations
from ..skillprovenance import KEY_SEP as PROV_KEY_SEP  # noqa: F401
from ..skillprovenance import ROOT_MARK as PROV_ROOT_MARK  # noqa: F401
from ..skillprovenance import _is_record_key as _prov_is_record_key  # noqa: F401
from ..skillprovenance import _is_root_key as _prov_is_root_key  # noqa: F401
from ._shared import (  # noqa: F401
    NOTE_RECORD_DAMAGED,
    NOTE_UNDETERMINED,
    _both_dims,
)


def _prov_searched_roots(dim: dict) -> set:
    """Which workspace roots a stored run looked in, from its per-root marker keys."""
    return {k[len(PROV_ROOT_MARK):] for k in dim if _prov_is_root_key(k)}


def _prov_legacy_names(dim: dict) -> set:
    """The skill-name keys of the provenance dimension, without the B-541 additions.

    `(root, skill)` entries and the `::roots` list share the map with them, so every arm that
    used to treat "a key of this dimension" as "a skill" has to say which it means now. The
    installed/removed arms did not, and reported the same skill once per workspace and a skill
    called `::roots`.
    """
    names = {k for k in dim if not _prov_is_root_key(k)}
    return {k for k in names if not _prov_is_record_key(k, names)}


def _prov_compare_records(prev: dict, curr: dict, p_keys: set, c_keys: set,
                          alerts: list, note, trust_removals: bool,
                          prev_names: set) -> None:
    """Compare every install record with ITSELF across runs (B-541).

    The election this replaces asked "which of these records is the one the agent loads?" —
    a question `skillprovenance.py`'s own comment said could not be answered, and which
    grounding against the installed dist showed is the wrong question anyway: OpenClaw gives
    each configured agent its own workspace, so two records under one skill name are two
    agents that each have it installed, and BOTH are live.

    Three previous repairs all kept the election and argued about *when* the elected record
    may be compared — stand down on `ambiguous`, on the witness set, on the winner's identity.
    Each was broken by the next adversarial pass, and the last one left the filed defect fully
    open: a decoy that always wins is stable, so the guard never closes and the comparison runs
    forever against the wrong record. There is nothing to stand down from here, because no
    record's comparison depends on which one is authoritative.

    A record that APPEARED in a root we searched last run and found nothing in is reported: that
    is the planted-decoy shape, and it is why `roots_searched` lists every root considered
    rather than every root that existed. A record that appeared in a root we had NOT searched
    before is an ordinary config edit adding a workspace. A record that VANISHED is only
    reported when this run actually looked in that root — "we looked and it is gone", never "we
    stopped looking".
    """
    p_roots = _prov_searched_roots(prev)
    c_roots = _prov_searched_roots(curr)
    # How many roots hold each name THIS run, so the wording can stay truthful without naming
    # a location: `_root_identity` deliberately does not publish one (B-611).
    spread: dict = {}
    for key in c_keys:
        spread[key.split(PROV_KEY_SEP, 1)[1]] = spread.get(key.split(PROV_KEY_SEP, 1)[1], 0) + 1

    appeared: list = []
    vanished: list = []
    unsearched: list = []
    revealed: list = []
    for key in sorted(p_keys | c_keys):
        root, _, name = key.partition(PROV_KEY_SEP)
        a, b = prev.get(key), curr.get(key)
        if isinstance(a, dict) and isinstance(b, dict):
            where = "" if spread.get(name, 1) < 2 else (
                f" (that skill is installed in {spread[name]} of your agent workspaces; this "
                f"is the one that moved)")
            av, bv = a.get("version", ""), b.get("version", "")
            ad, bd = a.get("artifact_sha256", ""), b.get("artifact_sha256", "")
            if av and bv and av != bv:
                alerts.append((
                    "INFO",
                    f"The skill '{name}' was updated, from {av} to {bv}{where}. Run "
                    f"--vet-skill on it if you did not expect that."))
            elif av and bv and av == bv and ad and bd and ad != bd:
                alerts.append((
                    "HIGH",
                    f"The skill '{name}' was replaced with different content while its "
                    f"version number stayed at {bv}{where}. A normal update moves both. Run "
                    f"--vet-skill on it."))
            if b.get("corroborated") is False and a.get("corroborated") is not False:
                alerts.append((
                    "MEDIUM",
                    f"The two install records for the skill '{name}' no longer agree with "
                    f"each other. They are written together by the installer, so one "
                    f"changing alone is not something an ordinary update produces."))
        elif isinstance(b, dict) and name in prev_names:
            # ONLY for a name the user already had. The alert says "a second record under a
            # name you already have", and the first version never checked that half — so an
            # ordinary `clawhub install` of a brand-new skill was told, in a MEDIUM, that its
            # arrival "is how an install is made to look unchanged". A false accusation on the
            # most ordinary action there is, found by an independent pass and exactly the
            # class Golden Rule #5 calls a hard blocker.
            (appeared if root in p_roots else revealed).append(name)
        elif isinstance(a, dict) and root not in c_roots:
            # Aggregated, not one line per skill. A workspace leaving the config takes every
            # record in it, and on a real setup that is a screen of identical sentences —
            # which is how a disclosure becomes something the reader scrolls past.
            unsearched.append(name)
        elif isinstance(a, dict) and trust_removals:
            vanished.append(name)

    if appeared:
        alerts.append((
            "MEDIUM",
            f"An install record for {len(appeared)} skill(s) appeared in a workspace that "
            f"held none at the last check: {', '.join(sorted(set(appeared))[:5])}. A second "
            f"record under a name you already have is how an install is made to look "
            f"unchanged. Run --vet-skill on it."))
    if revealed:
        # A second record under a known name, in a root this run searched for the FIRST time.
        # Adding an agent and installing the same skill for it looks exactly like this, and so
        # does a plant that arrives with its own workspace. Undeterminable, so it is stated and
        # not charged: the loud sentence stays on the case where the root was already watched.
        note(NOTE_UNDETERMINED,
             f"A second install record appeared for {len(set(revealed))} skill(s) you already "
             f"have, in a workspace this check looked in for the first time: "
             f"{', '.join(sorted(set(revealed))[:5])}. That is what adding an agent looks "
             f"like, and also what a planted record looks like; this run cannot tell them "
             f"apart.")
    if unsearched:
        _n = len(set(unsearched))
        note(NOTE_UNDETERMINED,
             f"The install records for {_n} skill(s) were not compared: this run did not look "
             f"in the workspace that held them. That is what a workspace leaving your config "
             f"looks like — it is not the same as a record being deleted, which this run "
             f"cannot tell apart from it without looking.")
    if vanished:
        alerts.append((
            "INFO",
            f"The install record for {len(vanished)} skill(s) is gone from a workspace this "
            f"run did look in: {', '.join(sorted(set(vanished))[:5])}."))


def _prov_comparable(a: dict, b: dict) -> bool:
    """May these two install records for one skill be compared as the same subject?

    Yes when neither run found a conflict: one workspace held the record, or several held
    records that agreed, and there is nothing to be undetermined about.

    When either run DID find a conflict, `ambiguous` alone cannot answer it. It is a bool,
    and True on both sides does not prove the two runs are talking about the same winning
    record — one workspace can be added while another is removed, and first-wins would
    elect a different one with the flag never moving. What does prove it is the WINNER'S
    IDENTITY: which root's record was actually taken (`winner_root`). The same root won
    both times ⇒ the record about to be compared is the record the baseline recorded ⇒
    comparing its content across the two runs is sound, ambiguity or not.

    That distinction is the whole point, and getting it wrong is worse than the false alarm
    it fixes. Suppressing on the `ambiguous` flag alone shipped a silence an attacker could
    buy for one extra file. Suppressing on the whole WITNESS SET — a digest over every root
    holding a record, which was the first repair — shipped the same silence at the same
    price, because the set moves when the ATTACKER adds a root: measured through the real
    CLI, a skill downgraded 2.0.0 -> 1.0.0 with a swapped artifact digest in the winning
    record, plus one decoy `<workspace>/.clawhub/lock.json` that never wins, produced an
    INFO and a MEDIUM alert on the set-keyed build's predecessor and nothing at all on the
    set-keyed build. Not deferred either — the following runs compare against a baseline
    that already holds the tampered record, so the alert is never raised at all.

    A root that does not win cannot change which record is compared, so it must not be able
    to stop the comparison. A root that DOES win changes it, and that is the ordinary
    config edit this guard exists for.

    A record with no `winner_root` — an old baseline, written before this field — cannot
    prove stability, so an ambiguous one stands down. Conservative and disclosed, never
    silent: every caller of this that gets False owes the reader a sentence.
    """
    if not a.get("ambiguous") and not b.get("ambiguous"):
        return True
    wa, wb = a.get("winner_root"), b.get("winner_root")
    return isinstance(wa, str) and bool(wa) and wa == wb


def _prov_records_seen(rec: dict) -> "int | None":
    """How many workspace roots this run found records in, when that is worth saying."""
    n = rec.get("n_records")
    return n if isinstance(n, int) and not isinstance(n, bool) and n >= 2 else None


def _prov_not_compared(name: str, a: dict, b: dict) -> str:
    """The sentence a stood-down skill comparison owes the reader (C-418 channel).

    States a fact and never an accusation. "Two of your workspaces hold different records
    for this skill, so its content was not compared" is something this run observed; "the
    records no longer agree, which an ordinary update does not produce" is a verdict, and
    printing it when the cause is undeterminable ambiguity would accuse a user of an attack
    for editing their config. The loud sentence stays where it is earned — on the MEDIUM
    alert, which only fires when the comparison was actually made.
    """
    seen = _prov_records_seen(b) or _prov_records_seen(a)
    count = f" ({seen} records found)" if seen else ""
    if b.get("ambiguous"):
        return (f"More than one of your workspaces holds an install record for the skill "
                f"'{name}'{count}, and they do not match. Which one your agent loads is "
                f"not something this check can determine, so its install record was not "
                f"compared with your last run.")
    # Reached when the CONFLICT is on the baseline's side. "A different workspace's record
    # won this time" is the likely cause but not a fact this run established — a baseline
    # written before `winner_root` existed lands here too — so the sentence claims only
    # what is certain:
    # there was more than one record, and this run cannot show it is looking at the same
    # one. Overclaiming here would be the same fault as the accusation it replaces.
    return (f"More than one of your workspaces held an install record for the skill "
            f"'{name}'{count} when your last check ran, and this run cannot confirm it is "
            f"looking at the same one, so its install record was not compared.")


def changed_skills(prev: "dict | None", curr: "dict | None") -> "list[str]":
    """F-175 tier 3: which skills' install records MOVED between two stored snapshots.

    An update is the moment a vetted setup silently becomes an unvetted one, and this is
    the only tier of the pre-update story that works with no cooperation from the user —
    it needs nothing but the next scheduled run. The caller re-runs the vetting for each
    name and reports the result, rather than merely saying "the version is different".

    A pure function of two snapshots, like `diff`: everything it concludes stays
    reproducible from the state file alone, and the expensive part (actually vetting) stays
    in the shell where it can be contained and budgeted.

    Three deliberate exclusions:

    * **Records that cannot be matched up**, per `_prov_comparable`: a newly ambiguous
      skill, or one whose WINNING ROOT moved between the runs, has no determinable record
      to re-vet. A skill that is merely STILL ambiguous while the same root keeps winning
      is not excluded — first-wins took the same record both times, so a change in it is a
      real change and re-vetting it is exactly right. Nor is one that merely gained a
      losing root: a record that did not win cannot be the record we would re-vet.
    * **A missing dimension on either side**, via `_both_dims`. A first run after this
      release, or a run that found no install records, has nothing to compare and must not
      re-vet the whole estate as though everything had just changed.
    * **Removals.** A skill that is gone cannot be vetted, and its absence is already
      reported by the diff.
    """
    pair = _both_dims(prev if isinstance(prev, dict) else {},
                      curr if isinstance(curr, dict) else {}, "skill_provenance")
    if pair is None:
        return []
    before, after = pair
    out: list[str] = []

    # B-541: when both snapshots carry per-root records, THEY are the subject — a record is
    # compared with itself and no election is involved, so the two exclusions built on
    # `_prov_comparable` have nothing left to exclude. Two things this arm must get right and
    # a naive port would not: the keys are `(root, skill)` and the caller re-vets NAMES, so
    # they are stripped and de-duplicated; and a record appearing in a root that was NOT
    # searched last run is a config edit revealing an existing install, not a new one, so it
    # is not re-vetted merely for having become visible.
    p_names, c_names = _prov_legacy_names(before), _prov_legacy_names(after)
    p_rec = {k for k in before if _prov_is_record_key(k, p_names)}
    c_rec = {k for k in after if _prov_is_record_key(k, c_names)}
    if p_rec and c_rec:
        p_roots = _prov_searched_roots(before)
        seen: set = set()
        for key in sorted(c_rec):
            root, _, name = key.partition(PROV_KEY_SEP)
            rec, old = after.get(key), before.get(key)
            if not isinstance(rec, dict) or name in seen:
                continue
            if not isinstance(old, dict):
                # A SECOND record under a name already present, in a root already watched.
                # A brand-new skill is handled by the arm below, and re-vetting it merely for
                # arriving in a workspace we already searched would re-vet every install.
                if root in p_roots and name in p_names:
                    seen.add(name)
                    out.append(name)
                continue
            if (old.get("version"), old.get("artifact_sha256")) != (
                    rec.get("version"), rec.get("artifact_sha256")):
                seen.add(name)
                out.append(name)
        return out

    for name, rec in sorted(after.items()):
        if (not isinstance(rec, dict) or _prov_is_record_key(name, c_names)
                or _prov_is_root_key(name)):
            continue
        old = before.get(name)
        if not isinstance(old, dict):
            if not rec.get("ambiguous"):
                out.append(name)      # newly installed — exactly a thing to vet
            continue
        if not _prov_comparable(old, rec):
            continue
        if (old.get("version"), old.get("artifact_sha256")) != (
                rec.get("version"), rec.get("artifact_sha256")):
            out.append(name)
    return out


def _diff_skill_provenance(pair, prev, curr, alerts, note, trust_removals) -> None:
    """C-433: the `skill_provenance` dimension's diff arm — BOTH branches.

    Fourth and last per-dimension extraction, and it corrects a claim from the previous
    commit. I recorded that this arm could not leave because `trust_removals` is "a
    genuinely shared accumulator, written once and read by five statements". The read count
    is right; the word accumulator was not. It is

        trust_removals = not curr_blind

    a boolean flag, never mutated after creation. My first scan looked for assignments by
    name and would not have seen a `.append`, so I re-checked for method calls, augmented
    assignment and item stores as well — there are none. A read-only flag is a parameter,
    exactly like `compare_config` two arms up.

    That is the second time on this task I called a per-dimension cut infeasible on a
    measurement that was true of the wrong thing. The blocking claim deserves the same
    adversarial pass as the change it blocks.

    Both the `is None` and `is not None` branches travel together: they are one dimension's
    diff, and splitting them is the by-function shape C-433 rejected. Their conditions were
    read as TEXT before the move rather than inferred — the previous extraction dropped a
    `compare_config` clause that way and reintroduced a B-269 fabrication. These two are
    single-clause.
    """
    if pair is None:
        _p_has, _c_has = "skill_provenance" in prev, "skill_provenance" in curr
        if _p_has and not _c_has:
            note(NOTE_UNDETERMINED,
                 "Where your skills came from was not compared: this run found no install "
                 "records. That happens when the records are missing, unreadable, or kept "
                 "in a workspace this run could not locate.")
        elif _c_has and not _p_has:
            # The FIRST RUN AFTER THIS RELEASE, for every existing user. The first attempt
            # at this block had no branch here, so it fell through to the damaged wording
            # below and told every upgrading user to delete their drift history — a worse
            # regression than the one it was written to fix, introduced while fixing it and
            # caught only because an independent pass reproduced the upgrade path from a
            # real baseline downgraded to the previous schema version. Silent on purpose:
            # the generic `watched` arm above already says the baseline predates it.
            pass
        elif _p_has or _c_has:
            # Present on a side but not a dict — a genuinely damaged record, and the one
            # case the wording below IS true of.
            note(NOTE_RECORD_DAMAGED,
                 "Where your skills came from could not be compared — the saved record for "
                 "them is damaged. Delete the monitor state file to start a fresh baseline.")
    if pair is not None:
        _pp, _cp = pair
        # B-541: the dimension now carries a `(root, skill)` entry per record alongside the
        # legacy name-keyed ones. When BOTH sides have them the per-root pass below is the
        # verdict and this legacy pass is skipped entirely; on the transition run — a baseline
        # written before this release — the legacy pass still runs, so nothing is lost and no
        # user gets a one-run blind spot out of the schema move.
        _p_names, _c_names = _prov_legacy_names(_pp), _prov_legacy_names(_cp)
        _p_rec = {k for k in _pp if _prov_is_record_key(k, _p_names)}
        _c_rec = {k for k in _cp if _prov_is_record_key(k, _c_names)}
        _per_root = bool(_p_rec) and bool(_c_rec)
        for name in sorted(_prov_legacy_names(_cp) & _prov_legacy_names(_pp)):
            if _per_root:
                break
            _a, _b = _pp.get(name), _cp.get(name)
            if not isinstance(_a, dict) or not isinstance(_b, dict):
                continue
            # ONE gate for all three comparisons below, and a sentence whenever it closes.
            #
            # It used to guard the middle one only, so a config edit that added a second
            # workspace produced "The skill 'demo' was updated, from 1.0.0 to 2.0.0" from
            # the arm above it and "the two install records no longer agree with each
            # other" from the arm below — two claims about a skill whose record this run
            # could not even identify, one of them an accusation. A branch that stands down
            # must say so rather than fall silent: an unexplained silence is the B-269
            # failure this project has already paid for twice, and here it is also how an
            # attacker would learn that manufacturing ambiguity costs one file and buys
            # quiet.
            if not _prov_comparable(_a, _b):
                note(NOTE_UNDETERMINED, _prov_not_compared(name, _a, _b))
                continue
            _av, _bv = _a.get("version", ""), _b.get("version", "")
            _ad, _bd = _a.get("artifact_sha256", ""), _b.get("artifact_sha256", "")
            if _av and _bv and _av != _bv:
                alerts.append((
                    "INFO",
                    f"The skill '{name}' was updated, from {_av} to {_bv}. Run "
                    f"--vet-skill on it if you did not expect that."))
            elif _av and _bv and _av == _bv and _ad and _bd and _ad != _bd:
                # Same version, different artifact: the version is the publisher's to
                # choose and the digest is not, so this is the stronger of the two signals
                # even though it is the quieter-looking one.
                #
                # Both versions must be RECORDED and EQUAL — the same correction the
                # OpenClaw arm above needed. Falling through on a missing version and then
                # asserting the number "stayed at" something is a claim built out of a
                # field that was never there.
                alerts.append((
                    "HIGH",
                    f"The skill '{name}' was replaced with different content while its "
                    f"version number stayed at {_bv}. A normal update moves both. Run "
                    f"--vet-skill on it."))
            # Corroboration is reported only on the TRANSITION into disagreement. A skill
            # whose two records already disagreed when the baseline was taken would
            # otherwise re-alert on every run forever, which is how a warning becomes
            # something the reader learns to skip. (The stand-down NOTE above is the
            # opposite case and repeats deliberately: it discloses a comparison this run
            # declined, which stays true for as long as it stays undeterminable.)
            if _b.get("corroborated") is False and _a.get("corroborated") is not False:
                alerts.append((
                    "MEDIUM",
                    f"The two install records for the skill '{name}' no longer agree with "
                    f"each other. They are written together by the installer, so one "
                    f"changing alone is not something an ordinary update produces."))
        # Names only. A `(root, skill)` key entering this arm would report the same skill as
        # "installed" once per workspace, and `::roots` as a skill called `::roots`.
        _new = sorted(_prov_legacy_names(_cp) - _prov_legacy_names(_pp))
        if _new:
            alerts.append((
                "INFO",
                f"{len(_new)} skill(s) were installed since the last check: "
                f"{', '.join(_new[:5])}."))
        _gone = sorted(_prov_legacy_names(_pp) - _prov_legacy_names(_cp))
        if _gone and trust_removals:
            alerts.append((
                "INFO",
                f"{len(_gone)} skill(s) are no longer in your install records: "
                f"{', '.join(_gone[:5])}."))
        if _per_root:
            _prov_compare_records(_pp, _cp, _p_rec, _c_rec, alerts, note, trust_removals,
                                  _p_names)
