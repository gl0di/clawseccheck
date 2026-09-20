"""B-835 dist guard: ``clawseccheck/checks/_config.py``'s ``_B32_CONTROL_PLANE_TOOLS``
grounded against the installed OpenClaw dist's own ``GATEWAY_CONTROL_PLANE_TOOLS``
(``dangerous-tools-*.mjs``), not against a hand-transcribed literal only.

Located BY CONTENT (``tests/_distgrounding.py``, B-728), never by filename — bundle
filenames are content-hashed and rotate on every OpenClaw release (the file measured
during this fix, ``dangerous-tools-D5_2xo_6.mjs``, is itself a 9.5-only name; 9.4's
copy of the same list lived in a differently-hashed file). If the vendor's list gains a
member this project does not yet know about, ``test_vendor_gateway_control_plane_tools_
matches_known_set`` fails loudly, naming the drift, instead of `checks/_config.py`
silently staying wrong the way it did for "plugins" across the 9.4 -> 9.5 upgrade.

Local-only: skips when the installed dist is absent (CI, a machine without OpenClaw) —
see ``require_dist``'s own docstring for why that is the one honest stand-down and every
other failure to locate the symbol is a finding, not an excuse.

Positive control (``test_extractor_positive_control_catches_a_new_member``): a guard
that cannot fail controls nothing (the same lesson ``tests/test_toolgrant_dist_
grounding.py``'s ``test_diff_tables_*`` pin for its own whole-table comparison). It
needs no installed dist and always runs.
"""
from __future__ import annotations

import re

from _distgrounding import dist_text

from clawseccheck import toolgrant
from clawseccheck.checks import _config as config_module

# The vendor's own GATEWAY_CONTROL_PLANE_TOOLS, resolved (AUTOMATIONS_TOOL_NAME ->
# "automations", automations-tool-name-DBMZPbPL.mjs) — measured against the installed
# openclaw@2026.9.5 on 2026-09-19 (dangerous-tools-D5_2xo_6.mjs:35-39). 9.4's copy of the
# same file (by content, not name) held only {"automations", "gateway"} — "plugins" is
# new in 9.5, which is exactly the drift this guard exists to catch on the NEXT upgrade.
_KNOWN_VENDOR_CONTROL_PLANE_TOOLS = frozenset({"automations", "gateway", "plugins"})


def _extract_gateway_control_plane_tools(text: str) -> frozenset:
    """Parse ``const GATEWAY_CONTROL_PLANE_TOOLS = [...]`` and resolve the
    ``AUTOMATIONS_TOOL_NAME`` symbol the array holds (not a string literal) to its
    grounded value. Raises (not skips) when the literal itself cannot be found, per
    ``_distgrounding``'s "installed but the anchor no longer matches" outcome.
    """
    match = re.search(r"GATEWAY_CONTROL_PLANE_TOOLS\s*=\s*\[(.*?)\]", text, re.S)
    assert match, (
        "GATEWAY_CONTROL_PLANE_TOOLS array literal not found in the matched dist "
        "text — re-locate it with `grep -rl GATEWAY_CONTROL_PLANE_TOOLS dist/*.mjs` "
        "and re-ground checks/_config.py::_B32_CONTROL_PLANE_TOOLS (B-835)."
    )
    body = match.group(1)
    members: set = set()
    for literal, symbol in re.findall(r'"([^"]+)"|(\bAUTOMATIONS_TOOL_NAME\b)', body):
        if symbol:
            members.add("automations")
        elif literal:
            members.add(literal)
    return frozenset(members)


def test_vendor_gateway_control_plane_tools_matches_known_set():
    text = dist_text(
        "dangerous-tools-*.mjs",
        symbol="GATEWAY_CONTROL_PLANE_TOOLS",
        contains="const GATEWAY_CONTROL_PLANE_TOOLS",
    )
    found = _extract_gateway_control_plane_tools(text)
    assert found == _KNOWN_VENDOR_CONTROL_PLANE_TOOLS, (
        f"vendor GATEWAY_CONTROL_PLANE_TOOLS changed: {sorted(found)} != "
        f"{sorted(_KNOWN_VENDOR_CONTROL_PLANE_TOOLS)} — re-ground "
        "clawseccheck/checks/_config.py::_B32_CONTROL_PLANE_TOOLS (B-835) and this "
        "module's _KNOWN_VENDOR_CONTROL_PLANE_TOOLS before shipping."
    )


def test_our_control_plane_set_covers_every_known_vendor_member():
    """The actual regression this task fixes, pinned: every vendor control-plane tool
    (alias-normalised) must be a member of our set. This is what "plugins" failed
    before B-835 (vendor had it, we did not) and what "cron" failed in the opposite
    direction before that (we matched the alias, not the vendor's canonical id)."""
    normalised = {toolgrant._normalize_tool_name(t) for t in _KNOWN_VENDOR_CONTROL_PLANE_TOOLS}
    assert normalised <= config_module._B32_CONTROL_PLANE_TOOLS


def test_extractor_positive_control_catches_a_new_member():
    """Prove the extractor itself can fail: a synthetic literal with a 4th member the
    known set does not have must NOT compare equal."""
    synthetic = (
        'const GATEWAY_CONTROL_PLANE_TOOLS = [\n'
        '\tAUTOMATIONS_TOOL_NAME,\n'
        '\t"gateway",\n'
        '\t"plugins",\n'
        '\t"a_new_control_plane_tool"\n'
        '];'
    )
    found = _extract_gateway_control_plane_tools(synthetic)
    assert found == {"automations", "gateway", "plugins", "a_new_control_plane_tool"}
    assert found != _KNOWN_VENDOR_CONTROL_PLANE_TOOLS


def test_extractor_positive_control_catches_a_missing_member():
    """The other direction: a literal that DROPS a known member must also not compare
    equal — a guard that only notices additions is half a guard."""
    synthetic = (
        'const GATEWAY_CONTROL_PLANE_TOOLS = [\n'
        '\tAUTOMATIONS_TOOL_NAME,\n'
        '\t"gateway"\n'
        '];'
    )
    found = _extract_gateway_control_plane_tools(synthetic)
    assert found == {"automations", "gateway"}
    assert found != _KNOWN_VENDOR_CONTROL_PLANE_TOOLS
