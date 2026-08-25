"""AI-BOM export (`--sbom`): a local, deterministic bill-of-materials JSON.

Standalone export format — NOT a human report. Summarizes the installed-skill /
MCP-server / installed-plugin inventory an `audit()` pass already collected, in a
stable machine-readable shape so it can be diffed, archived, or fed to other local
tooling. Local file / stdout only; never uploaded anywhere.

Hashing and field extraction deliberately REUSE monitor.py's existing helpers
(`_h`, `_SKILL_VERSION_RE`) and monitor.py's `_mcp_detail_sig` so the BOM's hashes
line up with monitor.py's own drift-detection snapshots (same hash scheme, same
inputs) — this module does not invent a second hashing convention.

Redaction discipline (ZKDS): the BOM NEVER contains secret/credential VALUES — only
key names, hashes and structural metadata. MCP env vars reuse `_mcp_detail_sig`'s
existing `key:*` marking for secret-shaped key names; values are never read here.
Every filesystem path this module emits (plugin `manifest_path`/`root_dir`/
`entry_point`) is routed through `report._redact_home_paths` first — an install path
carries the operator's OS username, and a BOM is exactly the artifact people paste
into a ticket (CLAUDE.md §8; the same fix already applies to sarif.py's
`_sarif_text` for the same class of leak).
"""
from __future__ import annotations

import json
from pathlib import Path

from .checks import _dep_names_in_skill, _unpinned_deps_in_skill
from .collector import LIMIT_DOMAIN_PLUGIN, limit_hits_for
from .monitor import _SKILL_VERSION_RE, _h, _mcp_detail_sig
from .report import _redact_home_paths

# B-568: bumped 2 -> 3. Two independent additions, both breaking a prior implicit
# promise: (1) a `plugins` array now exists (it was entirely absent — an AI-BOM that
# silently omits a whole component class is worse than no BOM, since completeness is
# its entire claim); (2) `complete` now ALSO requires the installed-plugin index to
# have been read cleanly, where it previously said nothing about plugins at all. A
# consumer pinned to version 2's `complete` == "no skill was withheld" would misread
# version 3's `complete` == "no skill was withheld AND the plugin inventory is known" —
# same shape as B-521's version 1 -> 2 bump one field over.
SBOM_VERSION = 3


def _skill_supplier(name: str, ctx) -> "str | None":
    """Which plugin supplies skill *name*, or ``None``/``"unknown"`` — never a guess.

    Three distinct claims, deliberately spelled three different ways:

    * ``None`` — *not applicable*. ``ctx.installed_skill_bundled`` (collector.py,
      B-507) is a DEFINITIVE set: it is built from WHICH root a skill was discovered
      under, not inferred, so "not bundled" is always a known fact, not an absence of
      one. A directly user-installed skill has no plugin-supplier concept to report.
    * ``"unknown"`` — the skill IS bundled with a plugin (definitively, per the same
      set) but WHICH plugin cannot be determined from the data this module reads: the
      persisted ``installed_plugin_index`` carries no reverse "these are my skills"
      list (its records are pluginId/origin/enabled/manifestPath/rootDir/source/
      contracts only — collector.py's ``_collect_plugin_trust`` docstring), so
      attribution is derived by directory containment instead, and containment can
      fail to resolve to exactly one plugin (index unreadable, zero matches, or an
      ambiguous >1 matches). This is the ONLY honest spelling for "known-unknown" —
      an empty string reads as "the supplier field is blank", not "we don't know".
    * ``"<plugin_id>"`` — exactly one installed-plugin record's ``root_dir`` contains
      the skill's own resolved directory (``ctx.installed_skill_dirs``). Never derived
      from the skill's or plugin's NAME — a name-based match would be exactly the
      "plausible-looking guess" this field must not emit.

    No filesystem access here (``build_sbom`` is pure/deterministic, no I/O): both
    ``ctx.installed_skill_dirs`` values and ``ctx.plugin_index_records[*]["root_dir"]``
    are already-resolved absolute paths by the time the collector writes them, so a
    plain ``Path.relative_to`` containment check (no ``.resolve()`` call) is sufficient
    — confirmed against a real installed-plugin index, not assumed.
    """
    bundled = getattr(ctx, "installed_skill_bundled", None) or set()
    if name not in bundled:
        return None
    skill_dir = (getattr(ctx, "installed_skill_dirs", None) or {}).get(name)
    if not skill_dir:
        return "unknown"
    skill_path = Path(skill_dir)
    matches: set = set()
    for rec in getattr(ctx, "plugin_index_records", None) or []:
        root_dir = rec.get("root_dir")
        plugin_id = rec.get("plugin_id")
        if not root_dir or not plugin_id:
            continue
        try:
            skill_path.relative_to(Path(root_dir))
        except ValueError:
            continue
        matches.add(plugin_id)
    if len(matches) == 1:
        return next(iter(matches))
    return "unknown"  # index unreadable, zero matches, or an ambiguous >1 matches


def _skill_entry(name: str, blob: str, supplier: "str | None") -> dict:
    m = _SKILL_VERSION_RE.search(blob)
    declared_deps = sorted(set(_dep_names_in_skill(blob)))
    unpinned_deps = sorted({
        line.split("'")[1]
        for line in _unpinned_deps_in_skill(name, blob)
        if "'" in line
    })
    return {
        "name": name,
        "version": m.group(1) if m else None,
        "hash": _h(blob),
        "declared_deps": declared_deps,
        "unpinned_deps": unpinned_deps,
        "supplier": supplier,
    }


def _mcp_entry(name: str, detail: dict) -> dict:
    env_keys = detail.get("env_keys") or []
    # "pinned" here means the command's first arg carries a version pin (e.g. an
    # npx `pkg@1.2.3` spec) — a coarse, best-effort supply-chain signal derived
    # from the same args0 field monitor.py already extracts; never fabricated.
    args0 = str(detail.get("args0") or "")
    pinned = "@" in args0.rsplit("/", 1)[-1][1:] if args0 else False
    return {
        "name": name,
        "hash": _h(json.dumps(detail, sort_keys=True, default=str)),
        "transport": detail.get("transport") or "",
        "command": detail.get("command") or "",
        "env_keys": list(env_keys),
        "pinned": pinned,
    }


def _redact_path(value) -> "str | None":
    return _redact_home_paths(str(value)) if value else None


def _plugin_entry(rec: dict) -> dict:
    """One ``installed_plugin_index.plugins_json`` record, reshaped for the BOM.

    ``origin`` is OpenClaw's own provenance tag ("bundled" | "global" | "config" | ...)
    — grounded straight from the persisted index; collector.py's own docstring on this
    field is explicit that it is "provenance, NOT a trust verdict", so this module
    passes it through verbatim rather than interpreting it as one.

    There is no plugin VERSION or PUBLISHER field anywhere in what the collector reads
    (``buildInstalledPluginIndexRecords`` persists pluginId/origin/enabled/
    manifestPath/rootDir/source/contributions.contracts only — collector.py
    ``_collect_plugin_trust`` docstring) — this entry does not fabricate either. A
    consumer wanting a plugin version/publisher needs a new collector.py reader (out of
    this file's ownership); until then this is the honest ceiling of what is knowable.

    ``manifest_path``/``root_dir``/``entry_point`` (the record's own ``source`` field —
    named ``entry_point`` here to avoid colliding with a skill's ``supplier``, a
    different concept) are filesystem paths straight from the state DB and routinely
    carry the operator's OS username; each is redacted via ``_redact_path`` before
    leaving this module. ``hash`` is computed over the RAW (unredacted) record, matching
    ``_mcp_entry``'s existing convention — the hash never leaves the process as text, so
    hashing the unredacted bytes costs nothing and keeps drift-detection precise.
    """
    return {
        "name": rec.get("plugin_id") or "",
        "origin": rec.get("origin"),
        "enabled": rec.get("enabled"),
        "contracts": sorted((rec.get("contracts") or {}).keys()),
        "manifest_path": _redact_path(rec.get("manifest_path")),
        "root_dir": _redact_path(rec.get("root_dir")),
        "entry_point": _redact_path(rec.get("source")),
        "hash": _h(json.dumps(rec, sort_keys=True, default=str)),
    }


def build_sbom(ctx) -> dict:
    """Build the BOM dict from an audited Context. Pure/deterministic (no I/O)."""
    from . import __version__  # noqa: PLC0415 (avoid import-order coupling)

    plugin_records = getattr(ctx, "plugin_index_records", None) or []
    plugins = [
        _plugin_entry(rec)
        for rec in sorted(plugin_records, key=lambda r: r.get("plugin_id") or "")
    ]

    skills = [
        _skill_entry(name, blob, _skill_supplier(name, ctx))
        for name, blob in sorted(ctx.installed_skills.items())
    ]

    mcp_detail = _mcp_detail_sig(ctx)
    mcp_servers = [
        _mcp_entry(name, detail)
        for name, detail in sorted(mcp_detail.items())
    ]

    # B-463: an empty BOM is two very different facts — "this setup has no components" and
    # "we never found the setup". They used to serialise BYTE-IDENTICALLY, so a typo'd
    # --home in a diff/archive pipeline read as "every component was uninstalled". The
    # audit already knows the difference (`config_found`); record it rather than asserting
    # zero components for a path the tool never found. Golden Rule #4.
    home = getattr(ctx, "home", None)
    config_found = bool(getattr(ctx, "config_found", False))

    # B-521: `complete` used to be an alias for `config_found`, which made it claim more
    # than it knew. The collector deliberately drops clawseccheck's own skill from the
    # inventory (collector.py `_OWN_SKILL_NAMES` / `self_excluded_skills`) -- a sound
    # exclusion, since a tool auditing itself is noise, but it means the component list is
    # SHORT BY ONE while the BOM asserted completeness. report.py has disclosed the
    # exclusion since B-507; the BOM never did, so a diff/archive pipeline reading only
    # this file could not tell a genuinely complete inventory from a pruned one.
    #
    # Same shape as B-463 one field over: two different facts must not serialise
    # identically. `complete` now means what it says -- the config was found AND nothing
    # was withheld -- and the withheld names ship alongside it so a consumer can tell
    # WHICH component is missing rather than only that one is.
    self_excluded = sorted(getattr(ctx, "self_excluded_skills", None) or [])

    # B-568: `complete` used to say nothing about the plugin category at all — it was
    # reachable (a pristine home) even though the shape has no plugins array. A plugin
    # component list is "complete" only when the persisted index was actually read
    # (`plugin_index_found`), parsed without error (`not plugin_index_parse_error`), and
    # not truncated by the plugin-domain cap (`not limit_hits_for(ctx, LIMIT_DOMAIN_PLUGIN)`
    # — an untagged/global limit hit is included conservatively, same as every other
    # `limit_hits_for` caller). `plugins_scanned` ships alongside `complete`, same
    # precedent as `self_excluded_skills`: a consumer needs to tell WHY `complete` is
    # false, not only that it is.
    plugin_index_found = bool(getattr(ctx, "plugin_index_found", False))
    plugin_index_parse_error = bool(getattr(ctx, "plugin_index_parse_error", False))
    plugin_index_truncated = bool(limit_hits_for(ctx, LIMIT_DOMAIN_PLUGIN))
    plugins_scanned = (
        plugin_index_found and not plugin_index_parse_error and not plugin_index_truncated
    )

    return {
        "version": SBOM_VERSION,
        "generated_by": f"clawseccheck v{__version__}",
        # B-568: folded like every other path in this document. A BOM is the artifact
        # people paste into tickets, and an un-folded home path carries the operator's
        # login name. `_redact_home_paths` rewrites only a real home prefix to `~`, so
        # the field still says WHICH home was scanned -- which is the whole point of
        # `test_bom_records_which_home_it_scanned`, whose target lives under tmp_path
        # and is therefore untouched by the fold. Verified both ways before changing it.
        "scanned_home": _redact_path(home),
        "config_found": config_found,
        "self_excluded_skills": self_excluded,
        "plugins_scanned": plugins_scanned,
        "complete": config_found and not self_excluded and plugins_scanned,
        "skills": skills,
        "mcp_servers": mcp_servers,
        "plugins": plugins,
    }


def render_sbom(ctx) -> str:
    """Return the BOM as a deterministic, stably-ordered JSON string."""
    payload = build_sbom(ctx)
    return json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)
