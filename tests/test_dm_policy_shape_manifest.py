"""C-491 — the dm-policy channel SHAPE manifest, generated straight from the vendor's own
config schema (docs/research/openclaw-dm-policy-walk.mjs, workspace root), and the guard
that keeps _DM_POLICY_NESTED_ONLY_CHANNELS / _DM_POLICY_FLAT_PRIMARY_CHANNELS /
_DM_POLICY_ENABLED_GATE_CHANNELS (checks/_shared.py) from drifting the way B-720 found
them already had: a hand-maintained frozenset with no independent oracle stayed wrong
because nothing re-derived the invariant it encoded.

Load-bearing distinction, worth stating before the asserts below make it look uniform:
schema SHAPE (this manifest) and RUNTIME behaviour are not the same fact.

  * NESTED_ONLY is fully schema-derivable: a channel is nested-only iff its schema
    declares `dm.policy` and no flat `dmPolicy`. Checked below as exact per-name set
    equality -- the manifest is a COMPLETE oracle for this one, so both directions of
    drift (a wrong addition, a wrong removal) redden, and so does mutating the manifest
    instead of the source set.

  * FLAT_PRIMARY and ENABLED_GATE are NOT fully schema-derivable. Whether a flat-primary
    channel's resolver also consults a nested `dm.policy` fallback, and whether a
    dm.enabled=false closure is actually consulted at a real consumer gate, are RUNTIME
    facts grounded in the vendor's minified JS source (see the citations in _shared.py's
    B-720 comment block), not in the JSON-Schema this manifest walks -- in fact no channel
    in the current schema declares both a flat AND a nested dmPolicy key at all, so a
    "schema declares both" test would be vacuously empty. The manifest can only assert a
    NECESSARY condition for membership in each set (the schema key the classification
    depends on must actually exist) -- checked below as a one-directional subset, per
    channel by name. A channel could schema-legally be REMOVED from either set (e.g. if
    slack's dm.enabled turned out to be consumer-gated after all) without this guard
    reddening; closing that direction needs the same source-grounding work B-720 did, not
    a schema walk. This is a documented, honest limit, not an oversight — see
    _DM_POLICY_FLAT_PRIMARY_CHANNELS's own comment in _shared.py for the parallel case
    (the "flat wins, nested is a legacy fallback" branch is intentionally untestable
    input-side today, for the same reason).

Regenerating the manifest is a step in the OpenClaw upgrade protocol's re-baseline
(docs/process/OPENCLAW_UPGRADE_PROTOCOL.md, workspace root) -- never hand-edit
tests/dm_policy_shape_manifest.txt; a hand-added line is the guard writing its own
evidence (CLAUDE.md §2.4's rule for tests/dist_verified_paths.txt, applied here).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.checks._shared import (
    _DM_POLICY_ENABLED_GATE_CHANNELS,
    _DM_POLICY_FLAT_PRIMARY_CHANNELS,
    _DM_POLICY_NESTED_ONLY_CHANNELS,
)

MANIFEST_PATH = Path(__file__).resolve().parent / "dm_policy_shape_manifest.txt"

_COLUMNS = ("flat_dmPolicy", "nested_dm_policy", "dm_enabled")


def _parse_manifest(path: Path) -> dict:
    """{"channel": {"flat_dmPolicy": bool, "nested_dm_policy": bool, "dm_enabled": bool}}."""
    rows: dict = {}
    header = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if header is None:
            header = cols
            assert header == ["channel", *_COLUMNS], header
            continue
        name, *values = cols
        assert len(values) == len(_COLUMNS), f"{name}: malformed manifest row {cols!r}"
        rows[name] = {col: (val == "yes") for col, val in zip(_COLUMNS, values)}
    assert rows, f"{path} produced zero channel rows -- parsing broke or the file is empty"
    return rows


def _nested_only(manifest: dict) -> frozenset:
    """Fully schema-derivable: declares nested dm.policy and no flat dmPolicy."""
    return frozenset(
        name for name, cols in manifest.items()
        if cols["nested_dm_policy"] and not cols["flat_dmPolicy"]
    )


def _mismatched_nested_only(claimed, manifest: dict) -> list:
    """Symmetric-difference report, per channel name, against the fully-derivable set —
    not the vacuous count-equality B-720 warns against."""
    real = _nested_only(manifest)
    extra = sorted(claimed - real)  # claimed nested-only but schema disagrees
    missing = sorted(real - claimed)  # schema says nested-only but not claimed
    return [f"wrongly classified nested-only: {n}" for n in extra] + [
        f"schema says nested-only but not classified as such: {n}" for n in missing
    ]


def _unsupported_members(claimed, manifest: dict, column: str) -> list:
    """One-directional necessary-condition check: every member of *claimed* must at least
    have *column*=yes in the manifest. See the module docstring for why this can only be
    one-directional for FLAT_PRIMARY / ENABLED_GATE."""
    out = []
    for name in sorted(claimed):
        cols = manifest.get(name)
        if cols is None:
            out.append(f"{name}: not a channel the schema declares at all")
        elif not cols[column]:
            out.append(f"{name}: schema does not declare {column} for this channel")
    return out


# --------------------------------------------------------------------------- the manifest


def test_manifest_parses_and_is_converged():
    text = MANIFEST_PATH.read_text(encoding="utf-8")
    assert "converged: yes" in text, (
        "the schema walk that produced this manifest was truncated -- see "
        "docs/research/openclaw-dm-policy-walk.mjs's own convergence note"
    )
    manifest = _parse_manifest(MANIFEST_PATH)
    assert len(manifest) >= 20, f"suspiciously few channel rows ({len(manifest)}) -- did the schema shape move?"


def test_manifest_pins_the_four_known_dm_object_channels():
    """The B-720 grounding comment's own worked example (checks/_shared.py) -- pinned so a
    future re-baseline that silently changes one of these is caught by name, not just by
    the frozenset guards below (which only look at classification, not the raw shape)."""
    manifest = _parse_manifest(MANIFEST_PATH)
    assert manifest["matrix"] == {"flat_dmPolicy": False, "nested_dm_policy": True, "dm_enabled": True}
    assert manifest["discord"] == {"flat_dmPolicy": True, "nested_dm_policy": False, "dm_enabled": True}
    assert manifest["slack"] == {"flat_dmPolicy": True, "nested_dm_policy": False, "dm_enabled": True}
    assert manifest["googlechat"] == {"flat_dmPolicy": True, "nested_dm_policy": False, "dm_enabled": True}


def test_matrix_is_the_only_nested_dm_policy_channel():
    manifest = _parse_manifest(MANIFEST_PATH)
    nested = [n for n, c in manifest.items() if c["nested_dm_policy"]]
    assert nested == ["matrix"], nested


def test_manifest_excludes_known_non_channel_siblings():
    """C-135 finding on this task's own first draft: `channels.defaults` and
    `channels.modelByChannel` are schema siblings of the real per-channel account
    schemas, not channels themselves (see NON_CHANNEL_SIBLINGS in
    openclaw-dm-policy-walk.mjs). Left unfiltered, either one gaining a schema field
    that happened to be named `dm.policy` in some future OpenClaw release would inject a
    spurious nested_dm_policy=yes row for a non-channel key, and
    test_nested_only_channels_agrees_with_the_manifest_exactly would FAIL on a schema
    change unrelated to any real channel — a false-positive FAIL a developer could only
    "fix" by wrongly teaching _DM_POLICY_NESTED_ONLY_CHANNELS about a non-channel key.
    Pinned here so a future edit to the generator cannot silently drop the filter."""
    manifest = _parse_manifest(MANIFEST_PATH)
    assert "defaults" not in manifest
    assert "modelByChannel" not in manifest


# --------------------------------------------------------- the three frozensets, live


def test_nested_only_channels_agrees_with_the_manifest_exactly():
    """Fully schema-derivable, so this is exact set equality, per channel name. This is
    the check that would have caught B-720 directly: googlechat has flat_dmPolicy=yes, so
    it can never satisfy nested-and-no-flat, and a set wrongly containing it reddens here
    naming googlechat."""
    manifest = _parse_manifest(MANIFEST_PATH)
    mismatches = _mismatched_nested_only(_DM_POLICY_NESTED_ONLY_CHANNELS, manifest)
    assert mismatches == [], mismatches


def test_enabled_gate_channels_are_schema_consistent():
    """One-directional (see module docstring): every gate-channel must at least declare
    `dm.enabled` in the schema. Does not assert the converse."""
    manifest = _parse_manifest(MANIFEST_PATH)
    problems = _unsupported_members(_DM_POLICY_ENABLED_GATE_CHANNELS, manifest, "dm_enabled")
    assert problems == [], problems


def test_flat_primary_channels_are_schema_consistent():
    """One-directional (see module docstring): every flat-primary channel must at least
    declare the flat `dmPolicy` key, and none may also be schema-nested-only (the two
    classifications are mutually exclusive by construction in _declared_dm_policy)."""
    manifest = _parse_manifest(MANIFEST_PATH)
    problems = _unsupported_members(_DM_POLICY_FLAT_PRIMARY_CHANNELS, manifest, "flat_dmPolicy")
    assert problems == [], problems
    overlap = _DM_POLICY_FLAT_PRIMARY_CHANNELS & _nested_only(manifest)
    assert overlap == frozenset(), f"classified both flat-primary and schema nested-only: {sorted(overlap)}"


# --------------------------------------------------------- mutation check: source-side
# "Mutating any one of the three sets reddens the guard, naming the specific channel"
# (C-491's own test plan) -- checked directly against the comparison functions above
# rather than by monkeypatching the module constants, so both the addition and removal
# direction are exercised for the one set (NESTED_ONLY) where both are schema-provable.


def test_guard_reddens_when_a_wrong_channel_is_added_to_nested_only():
    """googlechat: flat_dmPolicy=yes in the real manifest, so it can never legally join
    nested-only. This is the exact shape of the original B-720 defect."""
    manifest = _parse_manifest(MANIFEST_PATH)
    mutated = _DM_POLICY_NESTED_ONLY_CHANNELS | {"googlechat"}
    mismatches = _mismatched_nested_only(mutated, manifest)
    assert any("googlechat" in m for m in mismatches), mismatches


def test_guard_reddens_when_matrix_is_removed_from_nested_only():
    manifest = _parse_manifest(MANIFEST_PATH)
    mutated = _DM_POLICY_NESTED_ONLY_CHANNELS - {"matrix"}
    mismatches = _mismatched_nested_only(mutated, manifest)
    assert any("matrix" in m for m in mismatches), mismatches


def test_guard_reddens_when_a_channel_with_no_dm_enabled_joins_the_gate_set():
    manifest = _parse_manifest(MANIFEST_PATH)
    mutated = _DM_POLICY_ENABLED_GATE_CHANNELS | {"telegram"}  # telegram: dm_enabled=no
    problems = _unsupported_members(mutated, manifest, "dm_enabled")
    assert any("telegram" in p for p in problems), problems


def test_guard_reddens_when_flat_primary_gains_a_non_flat_member():
    manifest = _parse_manifest(MANIFEST_PATH)
    mutated = _DM_POLICY_FLAT_PRIMARY_CHANNELS | {"matrix"}  # matrix: flat_dmPolicy=no
    problems = _unsupported_members(mutated, manifest, "flat_dmPolicy")
    assert any("matrix" in p for p in problems), problems


# --------------------------------------------------------- mutation check: manifest-side
# "Mutating the manifest instead ... also reddens -- a guard that only fails in one
# direction is half a guard" (C-491's own test plan). Constructed inline rather than by
# editing the shipped file, so these tests need no filesystem write.


def test_guard_reddens_when_the_manifest_is_mutated_instead_of_the_source_set():
    manifest = _parse_manifest(MANIFEST_PATH)
    tampered = dict(manifest)
    # Flip matrix's nested column off -- the real _DM_POLICY_NESTED_ONLY_CHANNELS still
    # claims matrix, so this must now read as a mismatch even though nothing in
    # checks/_shared.py changed.
    tampered["matrix"] = {**tampered["matrix"], "nested_dm_policy": False}
    mismatches = _mismatched_nested_only(_DM_POLICY_NESTED_ONLY_CHANNELS, tampered)
    assert any("matrix" in m for m in mismatches), mismatches


def test_guard_reddens_when_the_manifest_drops_dm_enabled_for_a_gate_member():
    manifest = _parse_manifest(MANIFEST_PATH)
    tampered = dict(manifest)
    tampered["discord"] = {**tampered["discord"], "dm_enabled": False}
    problems = _unsupported_members(_DM_POLICY_ENABLED_GATE_CHANNELS, tampered, "dm_enabled")
    assert any("discord" in p for p in problems), problems


def test_guard_reddens_when_a_phantom_channel_is_added_to_the_manifest_and_claimed():
    """The other addition-side mutation of the manifest itself: a phantom channel with a
    misleading shape must not silently validate a set that (wrongly) claims it."""
    manifest = _parse_manifest(MANIFEST_PATH)
    tampered = dict(manifest)
    tampered["phantom-channel"] = {"flat_dmPolicy": True, "nested_dm_policy": True, "dm_enabled": False}
    mutated = _DM_POLICY_NESTED_ONLY_CHANNELS | {"phantom-channel"}
    mismatches = _mismatched_nested_only(mutated, tampered)
    # phantom-channel has BOTH flat and nested, so it fails "nested and no flat" too --
    # the guard correctly refuses to treat "declares nested" alone as sufficient.
    assert any("phantom-channel" in m for m in mismatches), mismatches
