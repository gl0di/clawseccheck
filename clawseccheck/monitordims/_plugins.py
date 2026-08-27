"""The `plugins` dimension — which plugins may load, and what switches that.

B-659. A plugin runs INSIDE the agent, so the allow list is a trust grant and every field
here is read off the installed dist's own zod schema rather than a docs page. The arm
watches the list, the enable flag, the slots, the registry entries — and `bundledDiscovery`,
which a C-135 pass found to be a silent off switch for all of the above.

Signature builder and diff arm together, which is the whole point of this package: a field
added to one half and not the other is the failure the per-dimension split exists to make
visible.
"""

from __future__ import annotations


# C-135: OpenClaw's own plugin-id normalization, so a RENAME cannot read as a GRANT.
#
# An adversarial pass produced six false positives from one omission: `_plugins_sig` stored
# raw strings and the arm did a raw set difference, while OpenClaw compares ids through
# `normalizePluginId` — trim, lowercase, then an alias table
# (`dist/config-state-CtMlHVRM.js`). Every identity-preserving re-spelling therefore looked
# like a set difference, and always on a LOOSENING arm, because a re-spelling adds the new
# form to `allow` and removes the old form from `deny` in the same edit.
#
# The worst of the six was OpenClaw's own `openclaw doctor --fix`, which its warning text
# tells the user to run: the `openai-codex` -> `openai` migration rewrote the id in `allow`
# and `deny` at once and produced two MEDIUM alerts, one of them saying a plugin that is
# still denied had left the block list. Another announced a genuine TIGHTENING (two aliases
# collapsed to one canonical deny entry) as a loosening — the exact inversion the direction
# calibration exists to prevent.
#
# Lifted verbatim from BUILT_IN_PLUGIN_ALIAS_FALLBACKS (`config-state-CtMlHVRM.js`), read
# out of the installed dist rather than from documentation.
_PLUGIN_ID_ALIASES = {
    "google-gemini-cli": "google",
    "minimax-portal": "minimax",
    "minimax-portal-auth": "minimax",
    # A LEGACY MIGRATION rather than an alias, kept in the same map because the effect on a
    # comparison is identical, and labelled because the provenance is not: OpenClaw's
    # `rewriteLegacyOpenAICodexPluginPolicy` (`dist/legacy-config-migrations--PhUdsg4.js`)
    # rewrites this id across allow, deny, entries AND slots when the user runs
    # `openclaw doctor --fix`, which OpenClaw's own warning text tells them to run. Without
    # it that one command produced two MEDIUM alerts, including one asserting a plugin that
    # is still denied had left the block list.
    "openai-codex": "openai",
}


def _plugin_id(raw: object) -> str:
    """A plugin id as OpenClaw compares it: trimmed, lowercased, alias-resolved."""
    ident = str(raw).strip().lower()
    return _PLUGIN_ID_ALIASES.get(ident, ident)


def _plugins_sig(ctx) -> dict:
    """B-659: the plugin TRUST surface — who may load, who may not, and what switches it.

    `plugins.*` reached the monitor only if some check's status happened to move, and
    measured on `fixtures/home_safe` an appended `plugins.allow` entry moved none of 188.
    A plugin runs inside the agent, so the allowlist is a trust grant and a change to it is
    exactly the kind of thing a watch exists to notice.

    Every field is read off the INSTALLED dist's own zod schema for the `plugins` object
    (`zod-schema-O9ml_nmo.js`: `enabled`, `allow`, `deny`, `load`, `slots`, `entries`,
    `bundledDiscovery`), not from a docs page and not invented.

    `bundledDiscovery` is here because a C-135 pass found its absence to be a silent OFF
    SWITCH for everything else in this dimension: `plugins.bundledDiscovery === "compat"`
    sets `bypassAllowlist`, which leaves `allowSet` undefined and makes every bundled plugin
    eligible (`dist/bundled-compat-yOgFRqvZ.js`). One word turns the allowlist off, and
    `doctor --fix` writes it automatically for any restrictive allowlist — so the same run
    that produced the migration false positive also produced this false negative.

    `entries` records each id's `enabled` flag rather than only the id, because a plugin
    already registered and switched off can be switched on without adding a key — invisible
    to a keys-only signature and to the new-key arm both. The rest of an entry's body IS
    provider setup's working state and stays unwatched.

    `plugins.load.paths` — where plugins are loaded FROM — is deliberately out: it is its own
    family and deserves its own adversarial pass rather than a rider on this one. An earlier
    version of this docstring also claimed to be excluding `plugins.mcp`; there is no such
    field in the installed schema, and justifying an omission with an invented field name is
    the shape Golden Rule #4 exists to stop.

    Lists are sorted sets of NORMALIZED ids, so reordering, re-casing, whitespace and the
    built-in aliases cannot register as a change. Absent keys stay absent rather than
    defaulting, so "not configured" and "configured empty" stay distinguishable.
    """
    from ..collector import dig  # noqa: PLC0415
    cfg = getattr(ctx, "config", None)
    out: dict = {}
    enabled = dig(cfg, "plugins.enabled")
    if isinstance(enabled, bool):
        out["enabled"] = enabled
    allow = dig(cfg, "plugins.allow")
    if isinstance(allow, list):
        out["allow"] = sorted({_plugin_id(x) for x in allow})
    deny = dig(cfg, "plugins.deny")
    if isinstance(deny, list):
        out["deny"] = sorted({_plugin_id(x) for x in deny})
    discovery = dig(cfg, "plugins.bundledDiscovery")
    if isinstance(discovery, str):
        out["bundled_discovery"] = discovery.strip().lower()
    slots = dig(cfg, "plugins.slots")
    if isinstance(slots, dict):
        out["slots"] = {str(k): _plugin_id(v) for k, v in slots.items()
                        if isinstance(v, str)}
    entries = dig(cfg, "plugins.entries")
    if isinstance(entries, dict):
        # id -> whether it is switched on. OpenClaw treats an absent `enabled` as on
        # (`config-normalization-shared-w2iz0aeC.js`: `enabled: config?.enabled !== false`),
        # so absent is recorded as True rather than as unknown.
        out["entries"] = {
            _plugin_id(k): (not (isinstance(v, dict) and v.get("enabled") is False))
            for k, v in entries.items()}
    return out


def _diff_plugins(pair, alerts, compare_config) -> None:
    """C-433: the `plugins` dimension's diff arm.

    Third per-dimension extraction, and the largest so far at 66 lines with only THREE
    parameters. `_listed` looked like a blocker in the first survey — it is a closure — but
    it is defined inside this arm rather than at the function's top level, so it travels
    with the arm instead of having to be threaded in. Worth recording because the survey
    that flagged it was counting names, not asking where they were bound.
    """
    # BOTH clauses. The original condition was `if compare_config and _pair is not None:`
    # and the extraction script rebuilt only the None half, which dropped the blind-run
    # guard: on a run recovering from an unknown baseline `compare_config` is False, so
    # this arm ran anyway and fabricated a HIGH "a plugin trust change" about a channel the
    # baseline had simply never recorded. That is the exact class B-269 exists to prevent,
    # and the full suite caught it where a 19-case equivalence harness did not.
    if not compare_config or pair is None:
        return
    _pp, _cp = pair

    def _listed(d: dict, key: str) -> "set | None":
        v = d.get(key)
        return set(v) if isinstance(v, list) else None

    _pa, _ca = _listed(_pp, "allow"), _listed(_cp, "allow")
    if _pa is not None and _ca is not None and (_ca - _pa):
        alerts.append((
            "MEDIUM",
            "Plugin(s) newly allowed to load: " + ", ".join(sorted(_ca - _pa))
            + ". A plugin runs inside your agent — vet it before trusting it."))
    _pd, _cd = _listed(_pp, "deny"), _listed(_cp, "deny")
    if _pd is not None and _cd is not None and (_pd - _cd):
        alerts.append((
            "MEDIUM",
            "Plugin(s) no longer denied: " + ", ".join(sorted(_pd - _cd))
            + ". They were on your block list at the last check and are not now."))
    if _pp.get("enabled") is False and _cp.get("enabled") is True:
        alerts.append((
            "MEDIUM",
            "Plugins were switched on since the last check (plugins.enabled). "
            "Everything on your allow list can load again."))
    # The allowlist's OFF SWITCH, found by the C-135 pass as a silent bypass of every
    # arm above: `bundledDiscovery: "compat"` sets `bypassAllowlist`, leaving `allowSet`
    # undefined so every bundled plugin becomes eligible
    # (`dist/bundled-compat-yOgFRqvZ.js`). One word turns the allowlist off, and the arms
    # watching the allowlist saw nothing because the list itself did not move.
    if (_pp.get("bundled_discovery") != "compat"
            and _cp.get("bundled_discovery") == "compat"):
        alerts.append((
            "MEDIUM",
            "Plugin discovery switched to compat mode, which bypasses your "
            "plugin allow list entirely — every bundled plugin can load again, whatever "
            "the list says."))
    # A slot names the plugin that OWNS memory or the context engine and puts it in the
    # startup scope. Changing who holds one is a trust move that touches neither list.
    _ps, _cs = _pp.get("slots"), _cp.get("slots")
    if isinstance(_ps, dict) and isinstance(_cs, dict):
        _moved = sorted(k for k, v in _cs.items() if _ps.get(k) not in (None, v))
        _claimed = sorted(k for k, v in _cs.items() if k not in _ps)
        if _moved or _claimed:
            alerts.append((
                "MEDIUM",
                "Plugin slot(s) reassigned: "
                + ", ".join(f"{k}={_cs[k]}" for k in _moved + _claimed)
                + ". A slot owner runs at startup, whatever your allow list says."))
    _pe, _ce = _pp.get("entries"), _cp.get("entries")
    if isinstance(_pe, dict) and isinstance(_ce, dict):
        _added = sorted(k for k in _ce if k not in _pe)
        if _added:
            alerts.append((
                "INFO",
                "Plugin registry entry added for: " + ", ".join(_added)
                + ". Configuring a provider writes one of these, so this is expected if "
                "you just did that."))
        # A plugin already registered and switched OFF can be switched on without adding
        # a key — invisible to the arm above and to a keys-only signature. INFO would be
        # wrong here: this is a plugin becoming live, not a provider being configured.
        _switched = sorted(k for k, v in _ce.items() if v and _pe.get(k) is False)
        if _switched:
            alerts.append((
                "MEDIUM",
                "Plugin(s) switched on: " + ", ".join(_switched)
                + ". They were registered but disabled at the last check."))
