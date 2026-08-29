"""The `credential_store` dimension — what OpenClaw's own credential store holds.

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
are the security-relevant ones — a planted credential, and a rotated or swapped token — and
nothing in the tree reported them.

## The one overlapping case, accepted rather than suppressed

On the FIRST credential a machine ever stores, A1 may also move, and then the run carries
both lines. That is accepted, and the reasoning is recorded because this repo treats
reporting one edit twice as a defect in its own right (`_execpolicy`'s `and not widened`):

  * it happens at most once per machine — every later credential finds the leg already up;
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
"""

from __future__ import annotations

from ._shared import NOTE_INSPECTION_CAPPED, NOTE_UNDETERMINED  # noqa: F401

#: How many file names to spell out before falling back to a count.
_CRED_NAME_CAP = 3


def _credentials_sig(state) -> dict:
    """The stored form of `checks/_shared._credential_store_state`.

    `{}` when the caller did not scan, which is how a baseline written by a build without
    this dimension is told from a store that is genuinely empty — the same conditional-key
    contract `openclaw_install` and `host_persist` use.
    """
    if not isinstance(state, dict) or not state.get("present"):
        return {}
    digests = state.get("digests")
    secret = set(state.get("secret_files") or ())
    files = {}
    if isinstance(digests, dict):
        for name, digest in digests.items():
            files[str(name)] = {"digest": str(digest), "plaintext": str(name) in secret}
    return {
        "files": files,
        "incomplete": bool(state.get("incomplete")),
        "reason": str(state.get("reason") or ""),
    }


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
    prev_files = prev_rec.get("files")
    curr_files = curr_rec.get("files")
    if not isinstance(prev_files, dict) or not isinstance(curr_files, dict):
        return

    # A truncated walk cannot tell "removed" from "never read", so removals stand down
    # wholesale — the `_skills.py` frontier rule, for the same reason: a burst of
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
            f"your credential store: {_credential_names(added_secret)}. Confirm you added them — a "
            "credential planted here is one your agent will use."))
    if added_plain:
        # No secret in it, so this is pairing/allow-list state rather than a credential.
        # OpenClaw writes those routinely; INFO records it without paging.
        alerts.append((
            "INFO",
            f"{len(added_plain)} new file(s) appeared in your credential store with no "
            f"plaintext credential in them: {_credential_names(added_plain)}."))

    changed = [n for n in sorted(set(prev_files) & set(curr_files))
               if prev_files[n].get("digest") != curr_files[n].get("digest")]
    now_secret = [n for n in changed if curr_files[n].get("plaintext")]
    still_plain = [n for n in changed if not curr_files[n].get("plaintext")]
    if now_secret:
        alerts.append((
            "MEDIUM",
            f"A stored credential was replaced: {_credential_names(now_secret)}. A token that changed "
            "without you rotating it is what a session takeover looks like from here."))
    if still_plain:
        alerts.append((
            "INFO",
            f"{len(still_plain)} file(s) in your credential store changed, with no "
            f"plaintext credential in them: {_credential_names(still_plain)}."))

    if removed and not incomplete:
        alerts.append((
            "INFO",
            f"{len(removed)} file(s) are no longer in your credential store: "
            f"{_credential_names(removed)}."))
