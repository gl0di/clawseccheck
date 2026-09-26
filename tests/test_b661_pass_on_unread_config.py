"""B-661 — no check may PASS on a config nobody read, and the surviving exceptions
are named, not just tolerated.

Given a ``Context`` where nothing was read at all (``config={}``, ``config_found=False``,
``config_parse_error=False`` — the exact shape a plain non-OpenClaw host, or an audit
pointed at the wrong directory, produces), 30 of the 185 registered checks used to
return PASS. 25 were a real fail-open bug: a `dig()`/`.get()` chain silently reads an
unread config's absence the same way it reads an explicitly-safe value, and asserts a
config-derived fact ("Gateway is bound to loopback…", "No exposed plaintext secrets.")
that was never actually checked. Fixed by adding a `config_found` guard (see each
check's own "B-661" comment) or, for `check_offboarding_hygiene`, downgrading only the
config-dependent half of its verdict.

The remaining 5 are genuinely independent of `ctx.config` — their locus is a different
file entirely (``devices/paired.json``, ``.clawhub/lock.json``, …), read and reported
correctly regardless of whether openclaw.json exists. Each has its own "B-661" comment
recording that.

This test is the suite-level guard the fix's own DoD asked for: it pins the exact
surviving PASS set so the count cannot silently grow back — the same way it grew from 23
to 30 between when B-661 was filed and when it was fixed, unnoticed, because nothing
counted it. A new PASS appearing here means either a new check reintroduced the bug (fix
it), or a new genuinely-independent check was added (add it to
``_INDEPENDENT_OF_CONFIG`` below, with a one-line reason, the same way its four
predecessors are documented).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from collections import Counter

import pytest

from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import CHECKS
from clawseccheck.collector import Context

pytestmark = pytest.mark.mechanical

# The 5 checks whose PASS is legitimately independent of ctx.config — each reads a
# DIFFERENT file under ctx.home by presence/content alone, and each carries its own
# "B-661: exempt..." docstring comment at its definition explaining why.
_INDEPENDENT_OF_CONFIG = frozenset({
    "check_clawhub_lock_verification",       # .clawhub/lock.json
    "check_legacy_state_migration_pending",  # credentials/*-allowFrom.json, identity/device-auth.json
    "check_paired_device_operator_authority",  # devices/paired.json
    "check_paired_node_skill_coverage",  # pairing store; PASS only when no skill-capable node is paired (config-gate PASSes need config)
    "check_pending_device_pairing_scope",    # devices/pending.json
    "check_restart_handoff_stale",           # gateway-supervisor-restart-handoff.json
})


def _unread_ctx(tmp_path) -> Context:
    # Mirrors B-661's own repro exactly: a real, empty tmp home, nothing found.
    return Context(home=tmp_path, config={}, config_found=False)


def test_no_new_check_passes_on_an_unread_config(tmp_path):
    ctx = _unread_ctx(tmp_path)
    passing = {fn.__name__ for fn in CHECKS if fn(ctx).status == PASS}
    unexpected = passing - _INDEPENDENT_OF_CONFIG
    assert not unexpected, (
        f"{len(unexpected)} check(s) PASS on a config that was never read: "
        f"{sorted(unexpected)} — either this is a regression of the B-661 fail-open "
        "bug (add a config_found guard, matching the pattern in checks/_config.py's "
        "check_gateway_rate_limit) or a genuinely config-independent check that "
        "belongs in _INDEPENDENT_OF_CONFIG above with a one-line reason."
    )


def test_every_documented_independent_check_still_exists_and_still_passes(tmp_path):
    """The other direction: a name in the allowlist that no longer PASSes (renamed,
    behavior changed, or removed) means the allowlist itself has gone stale."""
    ctx = _unread_ctx(tmp_path)
    by_name = {fn.__name__: fn for fn in CHECKS}
    missing = _INDEPENDENT_OF_CONFIG - by_name.keys()
    assert not missing, f"allowlisted check(s) no longer registered: {sorted(missing)}"
    for name in _INDEPENDENT_OF_CONFIG:
        status = by_name[name](ctx).status
        assert status == PASS, (
            f"{name} is allowlisted as config-independent but returned {status!r} "
            "on an unread config — update the allowlist or investigate the change."
        )


def test_the_vast_majority_now_report_unknown(tmp_path):
    """Anti-vacuity: proves the fix actually landed, not just that nothing NEW broke.
    Pinned as a floor (>=170 of 185), not an exact count, so an unrelated new check
    that correctly defaults to UNKNOWN doesn't need to touch this number."""
    ctx = _unread_ctx(tmp_path)
    counts = Counter(fn(ctx).status for fn in CHECKS)
    assert counts[UNKNOWN] >= 170, (
        f"only {counts[UNKNOWN]} of {len(CHECKS)} checks reported UNKNOWN on an "
        f"unread config (full distribution: {dict(counts)}) — expected the large "
        "majority, per B-661's own fix"
    )
