"""C-417 — Phase 0 of the monitor epic: three store-only snapshot fields.

The drift baseline carried no timestamp, no digest of the config bytes it was taken from,
and no record of which dimensions the build that wrote it could compare. Every later phase
of the epic needs at least one of those as a lower bound for "what happened since the last
run", and none of them is expressible without the field being stored first.

The defining property of this change, and what most of this file pins, is that it emits
**nothing**: no `diff()` arm reads any of the three keys, so a v3 baseline compared against
a v4 snapshot must be byte-for-byte as silent as it was before. A store-only migration that
alerts is the failure mode — the same shape as the v1->v2 and v2->v3 bumps before it, where
a newly-appearing optional key could have been misread as "a new X appeared".

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

from clawseccheck import audit, diff, snapshot
from clawseccheck.monitor import (
    SNAPSHOT_VERSION,
    WATCHED_DIMENSIONS,
    _CONFIG_DIMENSIONS,
    _config_file_digest,
    _now_iso,
    _SHRINKABLE_DIMENSIONS,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
MONITOR_SRC = (
    Path(__file__).resolve().parent.parent / "clawseccheck" / "monitor.py"
).read_text(encoding="utf-8")

_NEW_KEYS = ("ts", "watched", "config_file_sha256")


def _snap(home) -> dict:
    ctx, findings, score = audit(home)
    return snapshot(ctx, findings, score)


def _write_config(home: Path, body: str) -> Path:
    p = home / "openclaw.json"
    p.write_text(body, encoding="utf-8")
    os.chmod(p, 0o600)
    return p


# ---------------------------------------------------------------- shape

def test_the_snapshot_carries_all_three_new_fields():
    snap = _snap(FIXTURES / "home_safe")
    # The literal is deliberate: a schema bump should cost a conscious edit here, not slide
    # through because the assertion reads the constant it is meant to be pinning.
    assert snap["version"] == SNAPSHOT_VERSION == 8
    for key in _NEW_KEYS:
        assert key in snap, f"{key} missing from a clean-run snapshot: {sorted(snap)}"


def test_ts_is_the_same_string_shape_the_journal_writes():
    """One clock, not two: the journal's entries and the baseline are compared against
    each other, so a format difference would silently make every comparison wrong."""
    snap = _snap(FIXTURES / "home_safe")
    parsed = datetime.fromisoformat(snap["ts"])
    assert parsed.second == parsed.replace(microsecond=0).second
    assert "." not in snap["ts"], "second resolution, matching record_events"


def _isoformat_call_sites() -> int:
    """Count real `datetime.now().isoformat(...)` calls — parsed, for the same reason
    `_both_dims_literals` is parsed."""
    n = 0
    for node in ast.walk(ast.parse(MONITOR_SRC)):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "isoformat"):
            continue
        inner = node.func.value
        if (isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "now"):
            n += 1
    return n


def test_only_one_producer_of_that_timestamp_remains_in_the_module():
    """The expression used to be copy-pasted in two places. A third copy is how the two
    clocks drift apart, so the duplication is closed here rather than trusted to review."""
    assert _isoformat_call_sites() == 1, (
        "expected exactly one datetime.now().isoformat() call site, inside _now_iso"
    )
    assert "def _now_iso" in MONITOR_SRC
    assert isinstance(_now_iso(), str) and len(_now_iso()) == 19
    # The shape check above only recognises `datetime.now().isoformat(...)`. A second clock
    # introduced by any OTHER spelling would sail past it, so the alternatives are named —
    # via the AST, not a substring search of the source. A substring search would fail the
    # build on a future comment explaining why `utcnow` was rejected, which is the same
    # documentation-as-evidence mistake `_keys_read_from_a_stored_snapshot` exists to avoid.
    called = set()
    for node in ast.walk(ast.parse(MONITOR_SRC)):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute):
                called.add(fn.attr)
            elif isinstance(fn, ast.Name):
                called.add(fn.id)
    for spelling in ("utcnow", "strftime", "monotonic", "perf_counter"):
        assert spelling not in called, (
            f"a second clock ({spelling}) is called here — route it through _now_iso, or "
            f"this module has two clocks again"
        )


_SNAPSHOT_CEILING_BYTES = 32_768


def test_the_baseline_stays_a_small_local_file():
    """The property this test has claimed to hold since C-417, now actually asserted.

    It used to pin a RATIO — "the three new keys are under 15% of everything else" — while
    its own docstring said the thing that matters is that the baseline stays a small local
    file. Those are different claims, and F-173 is where the difference showed: adding
    three names to `WATCHED_DIMENSIONS` pushed the ratio to 16% and reddened a test about
    file size over a file that had grown by 260 bytes. A bound that fires on something
    other than the harm it names is a bound that gets relaxed, and a bound that gets
    relaxed each release stops meaning anything.

    So: an absolute ceiling, sized against measurement rather than estimate. Real figures
    at the time of writing — the maintainer's own `~/.clawseccheck/state.json` is 6.4 KB,
    `home_safe` 4.8 KB, `home_vuln` 5.2 KB, of which the `watched` manifest is 524 bytes.
    32 KB is roughly 5x the largest of those: enough headroom that ordinary growth never
    touches it, tight enough that a dimension which accidentally stored a whole file's
    contents (the failure that would actually hurt) fails immediately.
    """
    for home in ("home_safe", "home_vuln"):
        ctx, findings, score = audit(FIXTURES / home)
        size = len(json.dumps(snapshot(ctx, findings, score)))
        assert size < _SNAPSHOT_CEILING_BYTES, (
            f"{home}'s baseline is {size} bytes — a drift baseline is rewritten on every "
            f"scheduled run and must stay small"
        )


def test_the_coverage_manifest_does_not_dominate_the_baseline():
    """The one part of the snapshot that grows with every RELEASE rather than with the
    user's setup: `watched` stores a name per comparison this build makes. That is worth
    its cost — it is what lets a run say "your baseline predates this" instead of printing
    a bare all-clear — but it is also the piece most likely to creep, so it is bounded
    separately from the total above rather than hidden inside it."""
    ctx, findings, score = audit(FIXTURES / "home_safe")
    full = snapshot(ctx, findings, score)
    manifest = len(json.dumps(full["watched"]))
    assert manifest < 0.25 * len(json.dumps(full)), (
        f"the coverage manifest is {manifest} of {len(json.dumps(full))} bytes"
    )


# ---------------------------------------------------------------- config digest

def test_the_digest_is_over_the_file_bytes_not_the_parsed_dict():
    """Parsing normalizes comments, key order and $include boundaries away, so a digest
    of the parsed view would call two byte-different configs identical."""
    home = FIXTURES / "home_safe"
    snap = _snap(home)
    expected = hashlib.sha256((home / "openclaw.json").read_bytes()).hexdigest()
    assert snap["config_file_sha256"] == expected
    assert len(snap["config_file_sha256"]) == 64


def test_a_byte_only_edit_moves_the_digest(tmp_path):
    """The whole point of hashing bytes: a change that parses identically still shows."""
    _write_config(tmp_path, '{"gateway": {"bind": "127.0.0.1"}}')
    first = _snap(tmp_path)["config_file_sha256"]
    # Same parsed dict, different bytes (whitespace only).
    _write_config(tmp_path, '{"gateway": {"bind":   "127.0.0.1"}}')
    second = _snap(tmp_path)["config_file_sha256"]
    assert first != second


def test_an_unparseable_config_stores_no_digest(tmp_path):
    """Never persist a digest of a config we could not read — the key is absent, which is
    a readable "no digest for this run", rather than a number that implies we looked."""
    _write_config(tmp_path, '{"gateway": {')  # truncated -> invalid
    ctx, findings, score = audit(tmp_path)
    assert ctx.config_parse_error is True
    assert "config_file_sha256" not in snapshot(ctx, findings, score)


def test_an_include_fragment_edit_does_not_move_the_digest(tmp_path):
    """Pins the documented LIMIT, not a virtue.

    The digest covers the root file, so a config whose posture lives in an `$include`
    fragment has a byte-stable digest across a total posture change — here `gateway.bind`
    going world-open, which `diff()` treats as CRITICAL. Both docstrings say so; without a
    test the stated scope can silently widen or narrow, and a consumer would inherit
    whichever it happened to become. Closing the gap is tracked separately.
    """
    (tmp_path / "frag.json").write_text('{"gateway": {"bind": "127.0.0.1"}}', encoding="utf-8")
    os.chmod(tmp_path / "frag.json", 0o600)
    _write_config(tmp_path, '{"$include": "frag.json"}')

    before = audit(tmp_path)[0]
    assert before.config.get("gateway", {}).get("bind") == "127.0.0.1"

    (tmp_path / "frag.json").write_text('{"gateway": {"bind": "0.0.0.0"}}', encoding="utf-8")
    os.chmod(tmp_path / "frag.json", 0o600)
    after = audit(tmp_path)[0]

    assert after.config.get("gateway", {}).get("bind") == "0.0.0.0", "the posture DID change"
    assert after.config_sha256 == before.config_sha256, (
        "root-file scope: this is the documented blind spot, not a passing property"
    )


def test_a_config_that_vanished_stores_no_digest(tmp_path):
    """The `config_missing_blind` arm: the file was there last run and is gone now (an
    atomic-replace window, a mid-troubleshooting `mv`). The snapshot degrades, and the
    digest must not be carried forward from `prev` — a stale digest beside a fresh `ts`
    would assert we read the config at a time we did not."""
    _write_config(tmp_path, '{"gateway": {"bind": "127.0.0.1"}}')
    prev = _snap(tmp_path)
    assert "config_file_sha256" in prev

    (tmp_path / "openclaw.json").unlink()
    ctx, findings, score = audit(tmp_path)
    curr = snapshot(ctx, findings, score, prev=prev)
    assert curr.get("config_baseline") == "carried", "expected the blind degrade path"
    assert "config_file_sha256" not in curr, (
        "a carried digest would claim the config was read on a run that could not read it"
    )


def test_a_home_that_never_had_a_config_stores_no_digest(tmp_path):
    ctx, findings, score = audit(tmp_path)
    assert ctx.config_found is False
    assert "config_file_sha256" not in snapshot(ctx, findings, score)


def test_the_digest_describes_the_bytes_the_audit_read_not_a_later_re_read(tmp_path):
    """The defect an independent adversarial pass found in this field's first version.

    It re-read the file at snapshot time. A config edited in the window between the audit
    and the snapshot therefore produced a baseline holding the OLD `gateway_bind` next to
    a digest of the NEW bytes — a record true of no single moment. The next run then saw
    an unchanged digest across the exact change `diff()` fires CRITICAL on: the digest
    said "the config did not change" about the change that mattered most.
    """
    p = _write_config(tmp_path, '{"gateway": {"bind": "127.0.0.1"}}')
    safe_bytes = p.read_bytes()

    ctx, findings, score = audit(tmp_path)
    # The window: an attacker (or a careless edit) lands between collection and snapshot.
    _write_config(tmp_path, '{"gateway": {"bind": "0.0.0.0"}}')
    snap = snapshot(ctx, findings, score)

    assert snap["gateway_bind"] == "127.0.0.1", "precondition: the audit saw the safe file"
    assert snap["config_file_sha256"] == hashlib.sha256(safe_bytes).hexdigest(), (
        "the digest must describe the same bytes every other field in this snapshot does"
    )


def test_a_file_that_disappears_after_the_audit_still_records_its_digest(tmp_path):
    """Same root cause, the other symptom: because the first version re-read the file,
    deleting it (or chmod 000, or swapping it for a directory) between the audit and the
    snapshot dropped the key — indistinguishable from a blind run, while every config
    dimension beside it was recorded in full."""
    p = _write_config(tmp_path, '{"gateway": {"bind": "127.0.0.1"}}')
    audited_bytes = p.read_bytes()
    ctx, findings, score = audit(tmp_path)
    assert ctx.config_parse_error is False
    p.unlink()

    snap = snapshot(ctx, findings, score)
    # Against the BYTES, not against ctx.config_sha256: the digest is now a plain read of
    # that attribute, so comparing the two would hold for any value at all — including a
    # fabricated one. An independent pass proved that by setting ctx.config_sha256 = "b"*64
    # and watching this test still pass.
    assert snap["config_file_sha256"] == hashlib.sha256(audited_bytes).hexdigest()


def test_a_context_carrying_no_digest_yields_no_key():
    """The absent-digest path, pinned on the two shapes a Context can actually present:
    the attribute missing entirely (a foreign/legacy object) and the attribute set to None
    (config absent or unparseable)."""

    class _NoAttr:
        config_found = True

    assert _config_file_digest(_NoAttr()) == ""

    class _NullDigest:
        config_found = True
        config_sha256 = None

    assert _config_file_digest(_NullDigest()) == ""


def test_an_oversized_config_records_no_digest(tmp_path):
    """A file past the loader's cap does not parse, so the run is blind and stores neither
    a parsed view nor a digest — one decision, taken in one place, instead of two guards
    that can disagree."""
    from clawseccheck.collector import _MAX_CONFIG_BYTES

    _write_config(tmp_path, "{" + " " * (_MAX_CONFIG_BYTES + 10))
    ctx, findings, score = audit(tmp_path)
    assert ctx.config_parse_error is True
    assert ctx.config_sha256 is None
    assert "config_file_sha256" not in snapshot(ctx, findings, score)


# ---------------------------------------------------------------- watched manifest

_SNAPSHOT_RECEIVERS = {"prev", "curr"}
# Helpers that take a snapshot and a KEY, mapped to the position of that key. Keyed on the
# callee, not on the receiver's name: a name-only scan is exactly as narrow as the manifest
# it guards, since `_dim(snap, "k")` reads a stored key and a `prev`/`curr` scan cannot see
# it. And keyed to the key's POSITION rather than "any string in this call", because the
# looser form swept prose into the manifest — `_emit(prev, curr, "MCP server appeared")`
# made the guard demand that sentence be declared a watched dimension.
_SNAPSHOT_KEY_HELPERS = {"_dim": 1, "_frontier": 1, "_num": 1, "_both_dims": 2,
                         # C-418 wrapped the seven `_both_dims` presence guards in a helper
                         # that also records WHY a comparison was skipped. Its key is the
                         # first argument. This entry is why the guard kept seeing `host`,
                         # whose only read went through the new wrapper — it is the guard
                         # doing its job across a refactor, which is the case it was built
                         # for and the one a name-based scan would have missed.
                         "pair_or_note": 0}


def _keys_read_from_a_stored_snapshot() -> set:
    """Every snapshot key this module reads off a `prev`/`curr` baseline.

    Parsed, not grepped: this file and monitor.py both discuss these patterns in prose,
    and an earlier regex version of this guard happily matched a placeholder inside the
    comment that documented it. A guard that accepts its own documentation as evidence is,
    in miniature, the failure it exists to catch.

    Deliberately module-wide rather than confined to `diff()`: the comparison is spread
    across helpers that take the two snapshots as arguments (`_append_memory_alerts`
    reads `memory` and `memory_capped`; `snapshot()` itself reads `config_ever_seen` off
    `prev`), and a scan of `diff()`'s body alone would call the manifest complete while
    missing them.

    Four literal read shapes — `prev.get("k")`, `helper(snapshot, ..., "k")`, `prev["k"]`,
    `"k" in prev` — plus the one shape no AST scan for literals can ever see: a loop over
    a tuple of key names. `_degrade_snapshot` reads `prev` through exactly that, iterating
    `_CONFIG_DIMENSIONS` and `_SHRINKABLE_DIMENSIONS` with a VARIABLE key, so their members
    are unioned in from the module itself. Every current member also happens to have a
    literal read elsewhere, which is precisely the problem: without this union the guard
    was green by coincidence, and an eighth member added to either tuple would have kept it
    green over an incomplete manifest — the failure this test's own docstring claims cannot
    hide.
    """
    out = set(_CONFIG_DIMENSIONS) | set(_SHRINKABLE_DIMENSIONS)
    for node in ast.walk(ast.parse(MONITOR_SRC)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in _SNAPSHOT_RECEIVERS
                and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            out.add(node.args[0].value)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            pos = _SNAPSHOT_KEY_HELPERS.get(node.func.id)
            if pos is not None and len(node.args) > pos:
                arg = node.args[pos]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    out.add(arg.value)
        if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
                and node.value.id in _SNAPSHOT_RECEIVERS
                and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)):
            out.add(node.slice.value)
        if (isinstance(node, ast.Compare) and isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str) and node.comparators
                and isinstance(node.comparators[0], ast.Name)
                and node.comparators[0].id in _SNAPSHOT_RECEIVERS):
            out.add(node.left.value)
    return out


def test_the_watched_manifest_equals_what_the_module_actually_reads():
    """EXACT equality, not containment — in either direction.

    The first version of this guard checked only that `_both_dims` literals were a subset
    of the manifest. Every one of them already was, so it passed while the manifest was
    missing nine keys — including `raw_score_scope`, whose absence from a baseline
    suppresses the score-drop alert entirely, and `skills_frontier_partial`, whose absence
    silently downgrades a CRITICAL to a HIGH. A subset assertion cannot see an omission,
    which is the only error this manifest can have.

    A superset is equally wrong in the other direction: a declared key nothing reads would
    make a future "your baseline predates this" message fire forever over a comparison
    that was never gated on it.
    """
    read = _keys_read_from_a_stored_snapshot()
    assert read, "the extraction found nothing — it has gone stale, not the code"
    declared = set(WATCHED_DIMENSIONS)
    assert read == declared, (
        f"read but not declared: {sorted(read - declared)}\n"
        f"declared but never read: {sorted(declared - read)}"
    )


def test_the_optional_keys_are_the_ones_that_matter_and_are_present():
    """A named regression pin for the specific omission the first version shipped with.

    These are the keys whose ABSENCE from an older baseline changes a verdict rather than
    merely skipping a dimension — exactly the population the manifest exists to make
    visible, and exactly the population it originally left out."""
    for key in ("raw_score_scope", "skills_frontier_partial", "skills_capped",
                "skills_capped_count", "memory_capped", "config_baseline",
                "config_parse_error", "config_ever_seen", "grade"):
        assert key in WATCHED_DIMENSIONS, f"{key} is gate-bearing and must be declared"


def test_the_unconditional_keys_are_written_on_every_run():
    """What makes the 19/3 split in WATCHED_DIMENSIONS' comment true rather than asserted.

    A consumer distinguishes "your baseline predates this key" from "this key's absence IS
    the answer" purely by which group a key is in. If an entry outside `_CONDITIONAL`
    turned out to be conditionally written, that consumer would announce a stale baseline
    to a user whose baseline is current."""
    for home in ("home_safe", "home_vuln"):
        snap = _snap(FIXTURES / home)
        for key in WATCHED_DIMENSIONS:
            if key in _CONDITIONAL:
                continue
            assert key in snap, f"{key} is treated as unconditional but is absent on {home}"


# Written only under a condition, so their absence from a snapshot is a STATE rather than
# a gap — and therefore the one group for which a future "your baseline predates this"
# message would be a fabrication. Named individually: a blanket "some keys are optional"
# escape would let a genuinely missing key hide behind it.
_CONDITIONAL = {
    "host": "only on a supported host",
    "config_baseline": "only on a blind run (_degrade_snapshot)",
    "config_parse_error": "only on a blind run (_degrade_snapshot)",
    # F-170. Each absent for a DIFFERENT reason, which is why they are named separately:
    # no readable config at all; no config-audit journal on this install; a journal that
    # exists but recorded no write producing the bytes that are there now (a hand edit).
    "config_file_sha256": "absent when the config could not be read",
    "config_resolved_sha256": "absent when the config could not be read",
    "config_journal_head": "absent when OpenClaw keeps no config-audit journal",
    "config_written_by": "absent when no journaled write produced the current bytes",
    # F-173. All three share one condition — the caller ran the behavioural layer and
    # handed the result to `snapshot()` — but they are named individually anyway, because
    # the alternative is one entry that quietly covers whatever else gets added beside them.
    "behavioral_fired": "absent when the caller did not run the behavioural layer",
    "behavioral_undetermined": "absent when the caller did not run the behavioural layer",
    "behavioral_capped": "absent when the caller did not run the behavioural layer",
    # F-174. Both absent for a REAL reason a consumer must not read as a stale baseline:
    # no OpenClaw package could be located on PATH (a cron job's PATH really does produce
    # this — verified with `env -i PATH=/usr/bin:/bin`), and no ClawHub lock file was found
    # in any workspace this run searched.
    "openclaw_install": "absent when no OpenClaw install could be located",
    "skill_provenance": "absent when no ClawHub install record was found",
}


def test_every_unconditional_watched_key_is_actually_produced():
    """The reverse direction: a name in the manifest that no snapshot ever carries would
    make a future 'your baseline predates this' message fire forever over a comparison
    that was never gated on it."""
    snap = _snap(FIXTURES / "home_vuln")
    missing = [d for d in WATCHED_DIMENSIONS if d not in _CONDITIONAL and d not in snap]
    assert not missing, f"declared watched but never produced: {missing}"


def test_the_conditional_keys_really_are_produced_under_their_condition(tmp_path):
    """Otherwise `_CONDITIONAL` becomes a place to park a key that is simply never
    written. The blind-run pair is reachable here; `host` is not, on every machine."""
    _write_config(tmp_path, '{"gateway": {"bind": "127.0.0.1"}}')
    prev = _snap(tmp_path)
    (tmp_path / "openclaw.json").write_text('{"gateway": {', encoding="utf-8")
    os.chmod(tmp_path / "openclaw.json", 0o600)
    ctx, findings, score = audit(tmp_path)
    blind = snapshot(ctx, findings, score, prev=prev)
    assert blind.get("config_parse_error") is True
    assert blind.get("config_baseline") in ("carried", "unknown")


def test_the_behavioral_keys_really_are_produced_under_their_condition(tmp_path):
    """The same anti-parking-lot check for the F-173 trio: absent when the caller passes
    nothing, present the moment it passes a result. Without this, `_CONDITIONAL` would
    happily excuse three keys that no code path ever writes."""
    _write_config(tmp_path, '{"gateway": {"bind": "127.0.0.1"}}')
    ctx, findings, score = audit(tmp_path)
    bare = snapshot(ctx, findings, score)
    assert not any(k.startswith("behavioral_") for k in bare)
    withb = snapshot(ctx, findings, score,
                     behavioral={"fired": ["T1"], "undetermined": ["T3"], "capped": True})
    assert withb["behavioral_fired"] == ["T1"]
    assert withb["behavioral_undetermined"] == ["T3"]
    assert withb["behavioral_capped"] is True


def test_the_manifest_is_sorted_and_survives_a_json_round_trip():
    assert list(WATCHED_DIMENSIONS) == sorted(WATCHED_DIMENSIONS)
    snap = _snap(FIXTURES / "home_safe")
    assert json.loads(json.dumps(snap))["watched"] == list(WATCHED_DIMENSIONS)


# ---------------------------------------------------------------- the migration

def test_snapshot_version_3_migration_no_bogus_alert():
    """The regression that matters, and the twin of the v2 -> v3 test: a baseline written
    before this change, compared against one written after it, must be fully silent."""
    ctx, findings, score = audit(FIXTURES / "home_safe")
    curr = snapshot(ctx, findings, score)
    prev = {k: v for k, v in curr.items() if k not in _NEW_KEYS}
    prev["version"] = 3
    assert diff(prev, curr) == [], "the v3 -> v4 migration must emit nothing"


def test_the_migration_is_silent_in_both_directions():
    """A downgrade happens too — a user pinning an older release after an update. The new
    keys disappearing must not read as a removal either."""
    ctx, findings, score = audit(FIXTURES / "home_safe")
    curr = snapshot(ctx, findings, score)
    older = {k: v for k, v in curr.items() if k not in _NEW_KEYS}
    older["version"] = 3
    assert diff(curr, older) == []


def test_phase_zero_cannot_alert_on_the_new_fields_changing():
    """Store-only by construction: even when all three fields differ between two
    otherwise-identical snapshots, no arm of diff() consumes them."""
    ctx, findings, score = audit(FIXTURES / "home_safe")
    prev = snapshot(ctx, findings, score)
    curr = dict(prev)
    curr["ts"] = "2000-01-01T00:00:00"
    curr["config_file_sha256"] = "0" * 64
    curr["watched"] = ["skills"]
    assert diff(prev, curr) == []
