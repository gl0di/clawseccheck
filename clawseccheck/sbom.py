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

import hashlib
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


# C-521: CycloneDX / SPDX export — a PRESENTATION-time transform of the exact same
# build_sbom(ctx) inventory above, never a second scan. Both interoperability formats
# want a full-length content hash; monitor.py's _h() (native format's own hash) is
# DELIBERATELY truncated to 16 hex chars for its own compact-signature use, and a
# 16-char value would not itself validate as a real SHA-256 digest under either
# format's schema. _full_hash below reuses the exact same input-construction each
# native entry builder already uses (the same bytes _h() hashes) — just without the
# truncation — so this is still "reuse the digest machinery", not a second convention.


def _full_hash(text: str) -> str:
    """Same convention as monitor.py's ``_h()`` (sha256 of UTF-8 text, errors="replace")
    but UNTRUNCATED, for a hash field a schema will validate the length of."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _full_hashes_by_component(ctx) -> dict:
    """``(kind, name) -> full sha256 hex`` for every skill/mcp/plugin component, hashing
    the identical input text ``build_sbom``'s own ``_skill_entry``/``_mcp_entry``/
    ``_plugin_entry`` already hash (truncated) — reads ``ctx`` again, but ``ctx`` is
    already fully collected in memory by the time any BOM renderer runs, so this is
    cheap dict iteration, not a second scan."""
    out = {}
    for name, blob in ctx.installed_skills.items():
        out[("skills", name)] = _full_hash(blob)
    for name, detail in _mcp_detail_sig(ctx).items():
        out[("mcp_servers", name)] = _full_hash(json.dumps(detail, sort_keys=True, default=str))
    for rec in getattr(ctx, "plugin_index_records", None) or []:
        pid = rec.get("plugin_id") or ""
        out[("plugins", pid)] = _full_hash(json.dumps(rec, sort_keys=True, default=str))
    return out


def render_sbom_cyclonedx(ctx) -> str:
    """The same inventory as ``render_sbom``, as minimal-but-valid CycloneDX 1.5 JSON.

    License is never asserted: nothing this module reads carries license data for a
    locally-installed skill/MCP-server/plugin (Golden Rule #4 — report UNKNOWN, never
    guess), and CycloneDX's ``licenses`` key is optional, so it is omitted rather than
    populated with a fabricated value. ``purl`` (package-URL) is omitted for the same
    reason — these components mostly have no package-registry identity to assert.
    ``version`` is omitted (not "UNKNOWN") when unknown, since CycloneDX only accepts a
    real version string there; an absent key is the format's own honest "not stated".

    No ``metadata.timestamp`` — that field is optional in the CycloneDX spec, and
    omitting it keeps this renderer's output exactly as deterministic (same Context,
    same bytes) as the native format's own documented promise.
    """
    payload = build_sbom(ctx)
    hashes = _full_hashes_by_component(ctx)

    def _component(kind, comp_type, entry):
        c = {
            "type": comp_type,
            "bom-ref": f"{kind[:-1] if kind.endswith('s') else kind}:{entry['name']}",
            "name": entry["name"],
            "hashes": [{"alg": "SHA-256", "content": hashes.get((kind, entry["name"]), "")}],
        }
        version = entry.get("version")
        if version:
            c["version"] = version
        props = []
        if "supplier" in entry and entry["supplier"]:
            props.append({"name": "clawseccheck:supplier", "value": entry["supplier"]})
        if entry.get("declared_deps"):
            props.append({"name": "clawseccheck:declaredDeps",
                          "value": ",".join(entry["declared_deps"])})
        if entry.get("unpinned_deps"):
            props.append({"name": "clawseccheck:unpinnedDeps",
                          "value": ",".join(entry["unpinned_deps"])})
        if kind == "mcp_servers":
            props.append({"name": "clawseccheck:transport", "value": entry.get("transport", "")})
            props.append({"name": "clawseccheck:pinned",
                          "value": str(entry.get("pinned", False)).lower()})
        if kind == "plugins":
            if entry.get("origin"):
                props.append({"name": "clawseccheck:origin", "value": entry["origin"]})
            if entry.get("contracts"):
                props.append({"name": "clawseccheck:contracts",
                              "value": ",".join(entry["contracts"])})
        if props:
            c["properties"] = props
        return c

    components = (
        [_component("skills", "application", s) for s in payload["skills"]]
        + [_component("mcp_servers", "application", m) for m in payload["mcp_servers"]]
        + [_component("plugins", "application", p) for p in payload["plugins"]]
    )
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }
    return json.dumps(bom, ensure_ascii=True, indent=2, sort_keys=True)


def render_sbom_spdx(ctx) -> str:
    """The same inventory as ``render_sbom``, as minimal-but-valid SPDX 2.3 JSON.

    Uses SPDX's own standard ``"NOASSERTION"`` wherever a value is not knowable
    (version, license, download location) — the format's OWN spelling for exactly
    Golden Rule #4's "report UNKNOWN, never guess", so no invented convention is
    needed here the way CycloneDX's key-omission approach required one above.

    ``creationInfo.created`` genuinely is wall-clock "now": SPDX documents are
    conventionally timestamped at generation, and diffing (``--sbom-diff``) compares
    the underlying component list, not this rendered text, so this one field being
    non-deterministic across two runs of an unchanged setup has no effect on the
    diff feature at all.
    """
    from datetime import datetime, timezone

    from . import __version__  # noqa: PLC0415 (avoid import-order coupling)

    payload = build_sbom(ctx)
    hashes = _full_hashes_by_component(ctx)
    home_digest = hashlib.sha256(
        str(payload.get("scanned_home") or "").encode("utf-8", "replace")
    ).hexdigest()[:16]

    def _package(kind, entry):
        spdx_id = f"SPDXRef-{kind[:-1] if kind.endswith('s') else kind}-{entry['name']}"
        # SPDXID must be alnum/dot/hyphen only; a skill/plugin/server name can carry
        # other characters, so sanitize rather than emit a structurally invalid id.
        spdx_id = "".join(ch if ch.isalnum() or ch in ".-" else "-" for ch in spdx_id)
        # C-135: sanitizing can make two DIFFERENT names collide onto the SAME id —
        # "a/b" and "a b" both fold to "a-b", since both "/" and " " map to the same
        # replacement character. SPDX requires SPDXID to be unique per document,
        # and a silent collision would make a strict consumer only see one of the
        # two components (or reject the document outright). Appending a hash-derived
        # suffix UNCONDITIONALLY (not just when a collision is detected) keeps each
        # component's id stable across runs regardless of what else is present —
        # detect-and-suffix-on-repeat would make an id's shape depend on iteration
        # order and on which OTHER components happened to be installed that run.
        spdx_id = f"{spdx_id}-{hashes.get((kind, entry['name']), '')[:8]}"
        comment_bits = []
        if entry.get("supplier"):
            comment_bits.append(f"supplier={entry['supplier']}")
        if entry.get("declared_deps"):
            comment_bits.append(f"declaredDeps={','.join(entry['declared_deps'])}")
        if entry.get("unpinned_deps"):
            comment_bits.append(f"unpinnedDeps={','.join(entry['unpinned_deps'])}")
        if kind == "mcp_servers":
            comment_bits.append(f"transport={entry.get('transport', '')}")
            comment_bits.append(f"pinned={entry.get('pinned', False)}")
        if kind == "plugins" and entry.get("origin"):
            comment_bits.append(f"origin={entry['origin']}")
        pkg = {
            "SPDXID": spdx_id,
            "name": entry["name"],
            "versionInfo": entry.get("version") or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "checksums": [{"algorithm": "SHA256",
                          "checksumValue": hashes.get((kind, entry["name"]), "")}],
        }
        if comment_bits:
            pkg["comment"] = "; ".join(comment_bits)
        return pkg

    packages = (
        [_package("skills", s) for s in payload["skills"]]
        + [_package("mcp_servers", m) for m in payload["mcp_servers"]]
        + [_package("plugins", p) for p in payload["plugins"]]
    )
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "clawseccheck-sbom",
        "documentNamespace": f"https://clawseccheck.local/sbom/{home_digest}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": [f"Tool: clawseccheck-{__version__}"],
        },
        "packages": packages,
    }
    return json.dumps(doc, ensure_ascii=True, indent=2, sort_keys=True)
