"""CLAWSECCHECK-B-493 — A1 attributes each active trifecta leg to its config sources.

Before this, A1's evidence was three fixed leg-name strings
(`['untrusted input', 'sensitive data', 'outbound actions']`) and nothing else — a
reader could tell THAT the trifecta was complete, never WHICH config entry to remove.
`_trifecta_leg_sources` (checks/_shared.py) is the attribution primitive; A1
(check_trifecta, checks/_config.py) renders it via a new `_leg_attribution_note`
appended to `detail`, deliberately NOT folded into `evidence` — `report.py`'s
trifecta-ratio card reads `len(finding.evidence)` as the leg COUNT, and roughly a
dozen existing tests pin its exact `{'untrusted input', 'sensitive data',
'outbound actions'}` membership, so `evidence` had to stay untouched by construction.

Offline, read-only, stdlib only. Nothing here writes outside the repo.
"""
from __future__ import annotations

import os
from pathlib import Path

from clawseccheck.checks import check_trifecta
from clawseccheck.checks._config import _MISSING_LEG_ACTIVATORS
from clawseccheck.checks._shared import _trifecta_leg_sources, _trifecta_legs
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CONFIG_NAMES = {"openclaw.json", "clawdbot.json", "openclaw.json5", "openclaw.jsonc"}

_LEG_NAMES = {"untrusted input", "sensitive data", "outbound actions"}


def _fixture_homes() -> list[Path]:
    """Every directory holding an OpenClaw config. A home is never nested in another."""
    homes: list[Path] = []
    for d, sub, files in os.walk(FIXTURES):
        if CONFIG_NAMES & set(files):
            homes.append(Path(d))
            sub[:] = []
    return sorted(homes)


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# A complete 3/3 trifecta whose untrusted-input leg is deliberately OVER-DETERMINED:
# an open Telegram channel AND a `web` tool each independently raise it — mirrors the
# task's real `trifecta_live` shape (removing either alone leaves the leg active).
_COMPLETE_TRIFECTA_OVERDETERMINED = {
    "channels": {"telegram": {"dmPolicy": "open"}},
    "tools": {"allow": ["web", "fs_write"], "profile": "coding"},
}


def test_complete_trifecta_names_editable_field_paths_per_leg():
    """Every source string names a specific, editable config entry — not the leg
    category name A1's evidence already gives."""
    sources = _trifecta_leg_sources(_ctx(_COMPLETE_TRIFECTA_OVERDETERMINED))
    for leg, entries in sources.items():
        assert entries, f"{leg} is active but named no source"
        for entry in entries:
            assert entry not in _LEG_NAMES, f"{leg} source is just the category name: {entry!r}"
            assert any(
                c in entry for c in ("=", "'", "tools.", "channel", "MCP server", "credentials/")
            ), f"{leg} source doesn't look like a specific field/entry: {entry!r}"


def test_a1_evidence_still_exactly_the_leg_names_not_the_sources():
    """Regression pin for the exact risk this wiring had to avoid: evidence must stay
    `active` (leg names only) — report.py's trifecta-ratio card reads
    len(finding.evidence) as the leg count. The attribution lives in `detail`
    (see _leg_attribution_note), not evidence."""
    f = check_trifecta(_ctx(_COMPLETE_TRIFECTA_OVERDETERMINED))
    assert set(f.evidence) == _LEG_NAMES
    assert len(f.evidence) == 3


def test_a1_detail_names_the_sources_the_primitive_computed():
    """The wiring actually reaches the reader: every source the primitive computed for
    an active leg appears verbatim in A1's rendered detail text."""
    ctx = _ctx(_COMPLETE_TRIFECTA_OVERDETERMINED)
    f = check_trifecta(ctx)
    sources = _trifecta_leg_sources(ctx)
    for leg in f.evidence:
        for entry in sources[leg]:
            assert entry in f.detail, f"{entry!r} computed for {leg!r} but missing from detail"


def test_overdetermined_leg_lists_every_supplier_not_just_the_first():
    """The untrusted-input leg has TWO independent suppliers here. Naming only the
    first is not enough — removing it alone leaves the leg active — so both must
    be named."""
    sources = _trifecta_leg_sources(_ctx(_COMPLETE_TRIFECTA_OVERDETERMINED))["untrusted input"]
    assert any("telegram" in s for s in sources)
    assert any("web" in s for s in sources)
    assert len(sources) >= 2


def test_removing_one_supplier_of_an_overdetermined_leg_leaves_it_active():
    """Proves the over-determination is real, not asserted: drop the channel, keep the
    tool — the leg stays active with only the remaining supplier named."""
    cfg = {"tools": {"allow": ["web", "fs_write"], "profile": "coding"}}
    assert _trifecta_legs(_ctx(cfg))["untrusted input"] is True
    assert _trifecta_leg_sources(_ctx(cfg))["untrusted input"] == ["tools.allow entry 'web'"]


def test_bool_dict_and_sources_dict_agree_on_every_fixture_home():
    """`_trifecta_legs(ctx) == {k: bool(v) for k, v in _trifecta_leg_sources(ctx).items()}`
    everywhere. Two C-135 pins (test_b297_wildcard_group_ingress_leg.py,
    test_b371_a1_b41_ingress_agreement.py) assert `is False` on `_trifecta_legs`'s bool
    return, so any drift here would silently break what they pin."""
    for home in _fixture_homes():
        ctx = collect(home=str(home))
        legs = _trifecta_legs(ctx)
        sources = _trifecta_leg_sources(ctx)
        for k in legs:
            assert legs[k] is bool(sources[k]), f"{home.name}: {k!r} bool/sources mismatch"


def test_no_active_leg_has_an_undetermined_source_anywhere_in_the_corpus():
    """B-493's honesty requirement: where a leg is active but its source cannot be
    determined, say so, rather than naming a plausible-but-wrong key. Measured today
    this is 0/537 real fixture homes — every disjunct in `_trifecta_legs`'s boolean
    expression has a matching attributed term in `_trifecta_leg_sources`. Pinned as an
    assertion, not a comment: a future disjunct added to one side without the other
    would surface here as a leg that reads active with nothing named, before it ships."""
    undetermined = []
    for home in _fixture_homes():
        ctx = collect(home=str(home))
        legs = _trifecta_legs(ctx)
        sources = _trifecta_leg_sources(ctx)
        for leg, entries in sources.items():
            if legs[leg] and not entries:
                undetermined.append((home.name, leg))
    assert undetermined == [], f"active leg(s) with no attributed source: {undetermined}"


def test_missing_leg_activators_sensitive_text_no_longer_says_mode_full_is_the_definition():
    """_MISSING_LEG_ACTIVATORS previously read 'ungated exec, i.e.
    tools.exec.mode=\"full\"' — wrong: `_has_approval_gate` (checks/_shared.py:1624-1661)
    treats tools.exec.mode/security/ask ALL ABSENT as ungated too, not only mode='full'.
    This only checks the wording no longer asserts the false equivalence; it does not
    re-derive `_has_approval_gate`'s own behavior (that is `test_checks.py`'s job)."""
    text = _MISSING_LEG_ACTIVATORS["sensitive data"]
    assert "i.e." not in text, f"still asserts a single defining value: {text!r}"
    assert "absent" in text, f"doesn't disclose the absent-policy-is-ungated case: {text!r}"
