"""The `credential_store` dimension - what OpenClaw's own credential store holds.

B-677. `<home>/credentials` is `resolveOAuthDir` ($STATE_DIR/credentials), where OAuth
grants and channel pairing state land. B-666 taught A1 to read it for a plaintext
credential, so the AUDIT treats its contents as a security-relevant fact. The WATCH could
not see it change.

## The gap, measured before this was built

Three transitions, driven through the real CLI on a copy of `fixtures/home_safe`:

    first credential file lands, completing the trifecta   -> CRITICAL (A1 now FAILING)
    a SECOND credential file lands, leg already up         -> 0 alerts
    an existing credential file is REPLACED (token swap)   -> 0 alerts

Only the first is covered, and only coincidentally: A1 moved because that file completed a
2/3 config, which is a property of the config rather than of the credential. The other two
are the security-relevant ones - a planted credential, and a rotated or swapped token - and
nothing in the tree reported them.

## The one overlapping case, accepted rather than suppressed

On the FIRST credential a machine ever stores, A1 may also move, and then the run carries
both lines. That is accepted, and the reasoning is recorded because this repo treats
reporting one edit twice as a defect in its own right (`_execpolicy`'s `and not widened`):

  * it happens at most once per machine - every later credential finds the leg already up;
  * the two sentences are about different subjects. A1 says "your agent is now lethally
    capable"; this says "a credential appeared, here is the file". Neither implies the other;
  * suppressing it would silence the ONLY line that names the file, on the single run where
    a user is most likely to look.

Standing down would also be the shape this project has repeatedly found to be a silencer:
the suppression term available here is "did any check transition fire this run", which is
broader than "did A1 fire", so an unrelated check moving would hide a planted credential.

## What is recorded

Names and digests, never a value and never an absolute path (section 8, the `hostpersist`
rule). `plaintext` marks the files C015's own secret detector recognises, so one definition
of "this file carries a plaintext secret" serves both the check and the watch.

## The SQLite stores (C-675)

OpenClaw now keeps its credentials in databases (`config_machine_state` for
`authProfiles.store` / `auth.sharedStore`, and each agent's `auth_profile_store`), where the
directory above is empty. For those the watch records, per store, only the label, the value's
LENGTH and the store's own `updated_at` column: enough to see one appear, vanish or be
rewritten without reading a value, and no digest of a SQLite store's value is kept. A baseline
written before this has no `stores` key; the first run after the change records without
alerting and says so.
"""

from __future__ import annotations

import hashlib

from ..logsafe import redact
from ._shared import (  # noqa: F401
    NOTE_INSPECTION_CAPPED,
    NOTE_NO_PRIOR_RECORD,
    NOTE_UNDETERMINED,
)

#: A store this long or shorter is the vendor's own initialised-but-empty shape
#: (`{"version":1,"profiles":{}}`, B-749's `_AUTH_PROFILE_STORE_EMPTY_BYTES`).
_EMPTY_STORE_BYTES = 27

#: Longest label (store name) kept in a snapshot or printed in an alert. A label is a KEY NAME
#: the vendor or a user chose, so it is redacted like any other text that may hold a secret, and
#: a label that was shortened or redacted ends in a short hash of the original so that two keys
#: sharing a long prefix (or two redacted ones) stay two entries instead of one.
_LABEL_CAP = 48


def _safe_store_label(label) -> str:
    text = str(label)
    safe = redact(text)
    if safe == text and len(text) <= _LABEL_CAP:
        return text
    return safe[:_LABEL_CAP - 7] + "~" + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:6]


#: How many file names to spell out before falling back to a count.
_CRED_NAME_CAP = 3


def _credentials_sig(state, stores=None) -> dict:
    """The stored form of `checks/_shared._credential_store_state`, plus the SQLite stores.

    `{}` when the caller did not scan, which is how a baseline written by a build without
    this dimension is told from a store that is genuinely empty - the same conditional-key
    contract `openclaw_install` and `host_persist` use.

    *stores* is `collector.read_credential_store_rows`' result (C-675). Its `stores` key is
    written on every run that read them - an EMPTY dict when no database exists, so the first
    store to appear after a baseline with none is an addition rather than an unexplained
    absence. Label, length and the store's own timestamp only.
    """
    sig: dict = {}
    if isinstance(state, dict) and state.get("present"):
        digests = state.get("digests")
        secret = set(state.get("secret_files") or ())
        files = {}
        if isinstance(digests, dict):
            for name, digest in digests.items():
                files[str(name)] = {"digest": str(digest), "plaintext": str(name) in secret}
        sig = {
            "files": files,
            "incomplete": bool(state.get("incomplete")),
            "reason": str(state.get("reason") or ""),
        }
    if isinstance(stores, dict):
        rows = {}
        for label, rec in (stores.get("stores") or {}).items():
            rec = rec if isinstance(rec, dict) else {}
            rows[_safe_store_label(label)] = {
                "length": rec.get("length"), "updated": rec.get("updated")}
        sig["stores"] = rows
        sig["stores_incomplete"] = bool(stores.get("incomplete"))
        sig["stores_reason"] = str(stores.get("reason") or "")
    return sig


def _credential_names(names) -> str:
    shown = sorted(names)[:_CRED_NAME_CAP]
    hidden = len(names) - len(shown)
    clause = ", ".join(f"credentials/{n}" for n in shown)
    return clause + (f" and {hidden} more" if hidden > 0 else "")


def _diff_credentials(pair, alerts, note) -> None:
    """What the credential store gained, lost, or had replaced.

    Takes its pair from `pair_or_note`: a damaged or missing record is disclosed rather
    than silently skipped, the same way the gateway address is.
    """
    if pair is None:
        return
    prev_rec, curr_rec = pair
    _diff_credential_stores(prev_rec, curr_rec, alerts, note)
    prev_files = prev_rec.get("files")
    curr_files = curr_rec.get("files")
    if not isinstance(prev_files, dict) or not isinstance(curr_files, dict):
        return

    # A truncated walk cannot tell "removed" from "never read", so removals stand down
    # wholesale - the `_skills.py` frontier rule, for the same reason: a burst of
    # fabricated removal notices is a worse harm than one missed INFO.
    incomplete = bool(prev_rec.get("incomplete")) or bool(curr_rec.get("incomplete"))
    if incomplete:
        note(NOTE_INSPECTION_CAPPED,
             "Your credential store was not read in full this time"
             + (f" ({curr_rec.get('reason') or prev_rec.get('reason')})"
                if (curr_rec.get("reason") or prev_rec.get("reason")) else "")
             + ", so anything that disappeared from it was not reported.")

    added = sorted(set(curr_files) - set(prev_files))
    removed = sorted(set(prev_files) - set(curr_files))

    added_secret = [n for n in added if curr_files[n].get("plaintext")]
    added_plain = [n for n in added if not curr_files[n].get("plaintext")]

    if added_secret:
        alerts.append((
            "MEDIUM",
            f"{len(added_secret)} new file(s) holding a plaintext credential appeared in "
            f"your credential store: {_credential_names(added_secret)}. Confirm you added them \u2014 a "
            "credential planted here is one your agent will use."))
    if added_plain:
        # No secret in it, so this is pairing/allow-list state rather than a credential.
        # OpenClaw writes those routinely; INFO records it without paging.
        alerts.append((
            "INFO",
            f"{len(added_plain)} new file(s) appeared in your credential store with no "
            f"plaintext credential in them: {_credential_names(added_plain)}."))

    # A CHANGED file is recorded, never paged, and that is a C-135 retraction rather than a
    # preference. The first version raised MEDIUM on "a stored credential was replaced",
    # reasoning that a token changing without the user rotating it is what a takeover looks
    # like. Then the claim underneath it was grounded against the installed dist, which is
    # where it died: OpenClaw refreshes OAuth grants and writes them back -
    # `refreshOAuth` (25 sites), `writeOAuth` (14), `refreshAccessToken` (46), `expiresAt`
    # (976). So `credentials/oauth.json` moves on a schedule on any machine using OAuth,
    # and the alert would have fired on every refresh: an alarm that fires routinely is the
    # exact failure B-676 was opened to fix, one dimension over.
    #
    # A digest cannot tell a refresh from a swap. What COULD is a digest over the
    # identity-bearing subset of the grant - the account and scope, which a refresh
    # preserves and a swap does not - and that needs the grant's real field paths grounded
    # against the dist rather than guessed (section 2.4). Worth its own task; not worth
    # guessing here.
    #
    # So the half that is sound ships: an ADDED credential is the planted-credential case,
    # it was measured as invisible (a second credential file with the leg already up
    # produced zero alerts anywhere), and nothing in OpenClaw creates one on a timer.
    changed = [n for n in sorted(set(prev_files) & set(curr_files))
               if prev_files[n].get("digest") != curr_files[n].get("digest")]
    if changed:
        alerts.append((
            "INFO",
            f"{len(changed)} file(s) in your credential store changed: "
            f"{_credential_names(changed)}. Routine for an OAuth grant, which OpenClaw "
            "refreshes and rewrites on its own; recorded here so the timeline has it."))

    if removed and not incomplete:
        alerts.append((
            "INFO",
            f"{len(removed)} file(s) are no longer in your credential store: "
            f"{_credential_names(removed)}."))


def _diff_credential_stores(prev_rec, curr_rec, alerts, note) -> None:
    """What the SQLite credential stores gained, lost, or had rewritten (C-675).

    A credential LANDING is MEDIUM: a store that appears holding more than the vendor's empty
    shell, or an empty shell (`_EMPTY_STORE_BYTES` or fewer) that now holds more - the
    planted-credential case, and the shape a first sign-in takes on a real install, where the
    shell row already exists. A store that was already populated and CHANGED is INFO, never
    paged, for the reason the directory arm records above: OpenClaw refreshes OAuth grants and
    writes them back, so length and `updated_at` move on a schedule, and without reading the
    value a refresh cannot be told from a second credential added to the same row. A shell
    that merely appears is INFO. Unreadable never reads as unchanged: an incomplete read on
    either side stands the removals down wholesale and says so.
    """
    prev_s, curr_s = prev_rec.get("stores"), curr_rec.get("stores")
    if not isinstance(curr_s, dict):
        return
    if prev_s is None:
        # A baseline from before this was recorded: heal on this run, say so, alert on nothing.
        note(NOTE_NO_PRIOR_RECORD,
             "The credentials your agent keeps in OpenClaw's databases had nothing to compare "
             "against \u2014 your saved record predates this, and will cover it from the next "
             "run onwards.")
        return
    if not isinstance(prev_s, dict):
        return
    incomplete = bool(prev_rec.get("stores_incomplete")) or bool(curr_rec.get("stores_incomplete"))
    if incomplete:
        why = curr_rec.get("stores_reason") or prev_rec.get("stores_reason")
        note(NOTE_INSPECTION_CAPPED,
             "The credentials kept in OpenClaw's databases were not read in full this time"
             + (f" ({why})" if why else "")
             + ", so anything that disappeared from them was not reported.")

    def _length(rec):
        n = rec.get("length") if isinstance(rec, dict) else None
        return n if isinstance(n, int) else None

    added = sorted(set(curr_s) - set(prev_s))
    removed = sorted(set(prev_s) - set(curr_s))
    added_real = [k for k in added if (_length(curr_s[k]) or 0) > _EMPTY_STORE_BYTES]
    added_shell = [k for k in added if k not in added_real]
    if added_real:
        alerts.append((
            "MEDIUM",
            f"{len(added_real)} new credential store(s) appeared in OpenClaw's databases: "
            f"{_store_names(added_real)}. Confirm you signed in \u2014 a credential planted "
            "here is one your agent will use."))
    if added_shell:
        alerts.append((
            "INFO",
            f"{len(added_shell)} new, still-empty credential store(s) appeared in OpenClaw's "
            f"databases: {_store_names(added_shell)}."))
    moved = [k for k in sorted(set(prev_s) & set(curr_s))
             if isinstance(prev_s[k], dict) and isinstance(curr_s[k], dict)
             and (_length(prev_s[k]) != _length(curr_s[k])
                  or prev_s[k].get("updated") != curr_s[k].get("updated"))]
    populated = [k for k in moved
                 if _length(prev_s[k]) is not None
                 and _length(prev_s[k]) <= _EMPTY_STORE_BYTES
                 and (_length(curr_s[k]) or 0) > _EMPTY_STORE_BYTES]
    changed = [k for k in moved if k not in populated]
    if populated:
        alerts.append((
            "MEDIUM",
            f"{len(populated)} credential store(s) that were empty now hold a credential in "
            f"OpenClaw's databases: {_store_names(populated)}. Confirm you signed in \u2014 a "
            "credential planted here is one your agent will use."))
    if changed:
        alerts.append((
            "INFO",
            f"{len(changed)} credential store(s) in OpenClaw's databases changed: "
            f"{_store_names(changed)}. Routine for an OAuth grant, which OpenClaw refreshes and "
            "rewrites on its own; recorded here so the timeline has it."))
    if removed and not incomplete:
        alerts.append((
            "INFO",
            f"{len(removed)} credential store(s) are no longer in OpenClaw's databases: "
            f"{_store_names(removed)}."))


def _store_names(names) -> str:
    shown = sorted(names)[:_CRED_NAME_CAP]
    hidden = len(names) - len(shown)
    return ", ".join(shown) + (f" and {hidden} more" if hidden > 0 else "")
