"""B332 (F-145/W2.3) — cross-server MCP tool-name collision / homoglyph / near-miss.

mcptrustchecker's MTC-INJ-SHADOW-2 + MTC-UNI-009 analogue: a second MCP server
registers a tool whose name exactly matches, is a homoglyph of, or is a near-miss of a
tool a DIFFERENT, already-configured server exposes — the model routes a tool call by
name alone, so it cannot reliably tell the two servers' same-named tools apart.

FAIL    — exact ASCII collision on a rare/specific name (servers not detected as
          clones of each other), or a homoglyph/fullwidth/zero-width substitution
          (unconditional on genericness/length), between two DIFFERENT servers.
WARN    — an edit-distance-1 near-miss on a long, specific name; OR a non-ASCII exact
          match (the English-only generic-name allowlist can't judge genericness in an
          arbitrary script); OR an exact match between two servers whose FULL
          tool-name sets look like the SAME server deployed twice.
UNKNOWN — fewer than two MCP servers configured, fewer than two servers have any BARE
          tool names available to compare, or the comparison hit its size cap with no
          FAIL/WARN inside the scanned portion.
PASS    — two or more servers' tool names were compared and none collide.

Deliberately names-only: every check helper here reads only ToolDef.name, never
.description/.title, so completeness="names-only" (mcpsurface.from_probe_json, the
only pre-use tool-surface dump OpenClaw's own CLI emits) works identically to a
config-embedded manifest (completeness="full") — see the "explicit probe-json path"
tests below.

This file also pins the fixes from a SECOND, independent C-135 pass (a separate
reviewer on commit a32ae53 of the first cut) — H1-H6 below, mirroring the labels used
in check_mcp_tool_name_shadowing's own in-source C-135 note.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import mcpsurface as ms
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _b332_bare_tool_name,
    _b332_finding_from_surfaces,
    _b332_is_generic,
    check_mcp_tool_name_shadowing,
)
from clawseccheck.checks import _mcp as _mcp_mod
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _mcp(servers: dict) -> Context:
    return _ctx({"mcp": {"servers": servers}})


def _surface(server: str, names, *, source="manifest", completeness="full") -> ms.ToolSurface:
    return ms.ToolSurface(
        server=server,
        tools=[ms.ToolDef(name=n, server=server) for n in names],
        source=source,
        completeness=completeness,
    )


def _tools(*names) -> list:
    return [{"name": n, "description": f"{n} tool"} for n in names]


# --------------------------------------------------------------------------- UNKNOWN
def test_b332_unknown_no_mcp_servers():
    f = check_mcp_tool_name_shadowing(_ctx({}))
    assert f.id == "B332"
    assert f.status == UNKNOWN
    assert "No MCP servers configured" in f.detail


def test_b332_unknown_single_server_only():
    """Only one MCP server present -- cross-server shadowing needs at least two."""
    f = check_mcp_tool_name_shadowing(
        _mcp({"solo-mcp": {"command": "npx", "args": ["srv"], "tools": _tools("search")}})
    )
    assert f.status == UNKNOWN
    assert "one mcp server" in f.detail.lower() or "at least two" in f.detail.lower()


def test_b332_unknown_no_tool_names_available():
    """Two servers configured but neither carries an embedded tools list -- nothing to
    compare, so this must not silently read as a clean PASS."""
    f = check_mcp_tool_name_shadowing(
        _mcp(
            {
                "alpha": {"command": "npx", "args": ["a"]},
                "beta": {"command": "npx", "args": ["b"]},
            }
        )
    )
    assert f.status == UNKNOWN
    assert "no" in f.detail.lower() and "tool" in f.detail.lower()


def test_b332_unknown_helper_single_surface():
    f = _b332_finding_from_surfaces([_surface("alpha", ["search"])])
    assert f.status == UNKNOWN


def test_b332_unknown_probe_surface_with_empty_tool_part_not_counted_as_pass():
    """H5 (independent C-135 review): a probe entry whose tool part is EMPTY after
    namespace-stripping (e.g. a bare "mcp__beta__" name with nothing after the second
    "__") must not silently count toward "compared across 2 servers" -- only 1 server
    (alpha) actually contributes a usable bare name, so this is UNKNOWN, not PASS."""
    data = {
        "servers": {"alpha": {}, "beta": {}},
        "tools": ["mcp__alpha__search", "mcp__beta__"],
    }
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(data, fh)
        path = fh.name
    surfaces = ms.from_probe_json(path)
    f = _b332_finding_from_surfaces(surfaces)
    assert f.status == UNKNOWN
    assert f.status != PASS


# --------------------------------------------------------------------------- PASS (clean)
def test_b332_clean_two_servers_share_generic_search_name():
    """The FP trap this check is designed around: two servers legitimately expose the
    SAME generic instrument name -- that is normal, not an attack. Must NOT FAIL."""
    f = check_mcp_tool_name_shadowing(
        _mcp(
            {
                "docs-mcp": {"command": "npx", "args": ["a"], "tools": _tools("search")},
                "notes-mcp": {"command": "npx", "args": ["b"], "tools": _tools("search")},
            }
        )
    )
    assert f.status == PASS
    assert f.status != FAIL


def test_b332_clean_two_servers_share_multiple_generic_names():
    f = _b332_finding_from_surfaces(
        [
            _surface("alpha", ["search", "read_file", "list"]),
            _surface("beta", ["search", "read_file", "list"]),
        ]
    )
    assert f.status == PASS


def test_b332_clean_fixture_generic_name_overlap():
    f = check_mcp_tool_name_shadowing(collect(FIXTURES / "clean_b332_mcp_generic_name_overlap"))
    assert f.status == PASS


def test_b332_clean_short_non_allowlisted_exact_match_below_length_floor():
    """A short (< _B332_MIN_SPECIFIC_LEN) exact match that ISN'T on the curated
    allowlist still doesn't FAIL -- too short to tell apart from coincidence."""
    f = _b332_finding_from_surfaces([_surface("alpha", ["ls"]), _surface("beta", ["ls"])])
    assert f.status != FAIL


# --------------------------------------------------------------------------- FAIL (homoglyph)
def test_b332_fail_homoglyph_cyrillic_a_in_read_file():
    """"read_file" on a trusted server vs "reаd_file" (Cyrillic а, U+0430) on another --
    a homoglyph is ALWAYS suspicious, regardless of how generic the underlying word
    looks (unlike the exact-match / near-miss legs, this ignores the allowlist)."""
    cyrillic_name = "reаd_file"
    assert cyrillic_name != "read_file"  # sanity: genuinely a different code point
    f = _b332_finding_from_surfaces(
        [_surface("trusted-fs", ["read_file"]), _surface("shadow-fs", [cyrillic_name])]
    )
    assert f.status == FAIL
    assert any("read_file" in e for e in f.evidence)


def test_b332_fail_homoglyph_via_ctx():
    cyrillic_name = "reаd_file"
    f = check_mcp_tool_name_shadowing(
        _mcp(
            {
                "trusted-fs": {"command": "npx", "args": ["a"], "tools": _tools("read_file")},
                "shadow-fs": {"command": "npx", "args": ["b"], "tools": _tools(cyrillic_name)},
            }
        )
    )
    assert f.status == FAIL


def test_b332_fail_homoglyph_even_on_a_generic_name():
    """A homoglyph swapped into an otherwise-GENERIC name must still FAIL -- genericness
    is irrelevant to a homoglyph, since there is no accidental way to type it."""
    cyrillic_name = "seаrch"  # Cyrillic а swapped into "search"
    f = _b332_finding_from_surfaces(
        [_surface("alpha", ["search"]), _surface("beta", [cyrillic_name])]
    )
    assert f.status == FAIL


def test_b332_fail_fullwidth_homoglyph_on_a_generic_name():
    """H3 (independent C-135 review): a fullwidth 's' (U+FF53) swapped into "search"
    must FAIL too, mirroring the pinned Cyrillic-on-generic-name test above -- an
    earlier draft only checked the curated Cyrillic/Greek table and silently PASSED
    this."""
    fullwidth_name = "ｓearch"  # U+FF53 FULLWIDTH LATIN SMALL LETTER S + ascii rest
    assert fullwidth_name != "search"
    f = _b332_finding_from_surfaces(
        [_surface("alpha", ["search"]), _surface("beta", [fullwidth_name])]
    )
    assert f.status == FAIL


def test_b332_fail_zero_width_homoglyph_on_a_generic_name():
    """H3 (independent C-135 review): a zero-width space (U+200B) injected into
    "search" must FAIL too -- two visually-identical names differing only by an
    invisible character is exactly the shadowing shape this check exists to catch,
    and an earlier draft silently PASSED it (same root cause as the fullwidth case)."""
    zero_width_name = "sea​rch"
    assert zero_width_name != "search"
    f = _b332_finding_from_surfaces(
        [_surface("alpha", ["search"]), _surface("beta", [zero_width_name])]
    )
    assert f.status == FAIL


# --------------------------------------------------------------------------- B-488: _B332_ZERO_WIDTH_RE stays at the original six
def test_b332_fail_zero_width_original_six_all_fail_one_sided_insertion():
    """B-488: pin that ALL SIX of `_B332_ZERO_WIDTH_RE`'s members -- not just the
    single U+200B case above -- FAIL when inserted one-sided into an otherwise
    fold-equal pair. This is the shape the class exists to catch, and the
    stays-at-six decision (see the comment above `_B332_ZERO_WIDTH_RE`; do not
    widen it) rests on it staying sound for exactly these six.

    U+200D (ZWJ) is included here even though `_has_suspicious_zero_width` carries
    an emoji-ZWJ exemption (textnorm._is_zwj_between_emoji) -- empirically, a ZWJ
    sandwiched between plain ASCII letters ("sea" / "rch") is NOT a legitimate
    emoji sequence, so the exemption does not apply and it FAILs like the other
    five (verified empirically, not assumed).
    """
    original_six = {
        "U+00AD": "­",  # soft hyphen
        "U+200B": "​",  # zero-width space
        "U+200C": "‌",  # zero-width non-joiner
        "U+200D": "‍",  # zero-width joiner -- not emoji-flanked here, see docstring
        "U+2060": "⁠",  # word joiner
        "U+FEFF": "﻿",  # BOM / zero-width no-break space
    }
    for label, ch in original_six.items():
        shadow_name = "sea" + ch + "rch"
        f = _b332_finding_from_surfaces(
            [_surface("alpha", ["search"]), _surface("beta", [shadow_name])]
        )
        assert f.status == FAIL, f"{label} ({hex(ord(ch))}) expected FAIL, got {f.status}"


def test_b332_no_fail_tier1_zero_width_one_sided_insertion_accepted_gap():
    """B-488: pin the ACCEPTED gap -- none of the 14 Tier-1 code points B-450
    added to `textnorm.obfuscation_signals`'s own wider class (U+180E,
    U+2061-2064, U+206A-206F, U+FFF9-FFFB) FAIL here, even inserted one-sided
    into an otherwise fold-equal pair exactly like the original six above.

    This is a knowingly-missed detection, not an oversight, and since B-490 it
    is no longer a free one: `normalize_for_scan` now strips Tier-1 too, so
    these pairs ARE fold-equal and the only thing holding the verdict at PASS is
    `_B332_ZERO_WIDTH_RE` staying at six. Widening it would catch this shadowing
    -- and would equally flip Japanese ruby annotation and Mongolian pairs from
    PASS to false FAIL (the two tests below), with no rule separating the
    populations. Golden Rule #5 makes the false FAIL decisive. See the comment
    above `_B332_ZERO_WIDTH_RE` for the full trade.
    """
    tier1 = {
        "U+180E": "᠎",
        "U+2061": "⁡",
        "U+2062": "⁢",
        "U+2063": "⁣",
        "U+2064": "⁤",
        "U+206A": "⁪",
        "U+206B": "⁫",
        "U+206C": "⁬",
        "U+206D": "⁭",
        "U+206E": "⁮",
        "U+206F": "⁯",
        "U+FFF9": "￹",
        "U+FFFA": "￺",
        "U+FFFB": "￻",
    }
    assert len(tier1) == 14
    for label, ch in tier1.items():
        shadow_name = "sea" + ch + "rch"
        f = _b332_finding_from_surfaces(
            [_surface("alpha", ["search"]), _surface("beta", [shadow_name])]
        )
        assert f.status != FAIL, f"{label} ({hex(ord(ch))}) unexpectedly FAILed"


def test_b332_pass_japanese_ruby_annotation_not_a_false_fail():
    """B-488, finding 2: the false-FAIL case that rules out widening
    `_B332_ZERO_WIDTH_RE`. U+FFF9/FFFA/FFFB are the actual Unicode
    interlinear-annotation (ruby) mechanism -- ANNOTATION ANCHOR / SEPARATOR /
    TERMINATOR wrapping a base/reading pair, e.g. the base text 検索
    ("kensaku", "search") annotated with its own reading in either fullwidth or
    halfwidth katakana. Both names below carry the SAME three Tier-1 marker
    characters and differ only in halfwidth vs fullwidth katakana, which NFKC
    folds to the identical string -- if `_B332_ZERO_WIDTH_RE` were widened to
    Tier 1, this legitimate pair would flip from PASS to a false FAIL (verified
    empirically while diagnosing this decision). Must stay PASS: widening this
    class would break real Japanese ruby-annotated tool descriptions/names.
    """
    fullwidth_ruby = "￹検索￺ケンサク￻"  # 検索/ケンサク
    halfwidth_ruby = "￹検索￺ｹﾝｻｸ￻"  # 検索/ｹﾝｻｸ
    assert fullwidth_ruby != halfwidth_ruby
    f = _b332_finding_from_surfaces(
        [_surface("alpha", [fullwidth_ruby]), _surface("beta", [halfwidth_ruby])]
    )
    assert f.status == PASS


def test_b332_pass_mongolian_vowel_separator_not_a_false_fail():
    """B-488, finding 2's second case: U+180E MONGOLIAN VOWEL SEPARATOR is real
    Mongolian orthography (it sits between the consonant and the following
    vowel), not an injection channel. Both names below carry the SAME U+180E
    and differ only in an ideographic (U+3000) vs an ASCII space, which NFKC
    folds to the identical string -- if `_B332_ZERO_WIDTH_RE` were widened to
    Tier 1, this legitimate pair would flip from PASS to a false FAIL (verified
    empirically). Must stay PASS: widening this class would break real
    Mongolian-script tool names/descriptions.
    """
    ideographic_space_variant = "ᠡ᠎ᠷ　a"
    ascii_space_variant = "ᠡ᠎ᠷ a"
    assert ideographic_space_variant != ascii_space_variant
    f = _b332_finding_from_surfaces(
        [_surface("alpha", [ideographic_space_variant]), _surface("beta", [ascii_space_variant])]
    )
    assert f.status == PASS


# --------------------------------------------------------------------------- FAIL (exact, rare name)
def test_b332_fail_exact_collision_on_distinctive_name():
    f = check_mcp_tool_name_shadowing(collect(FIXTURES / "bad_b332_mcp_exact_collision"))
    assert f.status == FAIL
    assert "rotate_kubeconfig_secret" in "".join(f.evidence)


def test_b332_fail_exact_collision_helper():
    f = _b332_finding_from_surfaces(
        [
            _surface("trusted-ops-mcp", ["rotate_kubeconfig_secret"]),
            _surface("shadow-mcp", ["rotate_kubeconfig_secret"]),
        ]
    )
    assert f.status == FAIL
    assert any("rotate_kubeconfig_secret" in e for e in f.evidence)


def test_b332_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_b332_mcp_exact_collision", include_native=False)
    ids = {f.id for f in findings}
    assert "B332" in ids, f"B332 not in audit findings: {sorted(ids)}"


# --------------------------------------------------------------------------- WARN (near-miss)
def test_b332_warn_near_miss_edit_distance_one_long_name():
    f = _b332_finding_from_surfaces(
        [
            _surface("alpha", ["rotate_kubeconfig_secret"]),
            _surface("beta", ["rotate_kubeconfig_secrets"]),  # trailing "s" -- edit distance 1
        ]
    )
    assert f.status == WARN
    assert any("rotate_kubeconfig_secret" in e for e in f.evidence)


def test_b332_no_warn_near_miss_on_short_generic_name():
    """An edit-distance-1 typo of a SHORT generic name ("search" -> "saerch") is far
    too common an innocent slip to be evidence on its own -- must not WARN."""
    f = _b332_finding_from_surfaces(
        [_surface("alpha", ["search"]), _surface("beta", ["saerch"])]
    )
    assert f.status != WARN
    assert f.status != FAIL


def test_b332_warn_via_ctx():
    f = check_mcp_tool_name_shadowing(
        _mcp(
            {
                "alpha": {
                    "command": "npx",
                    "args": ["a"],
                    "tools": _tools("rotate_kubeconfig_secret"),
                },
                "beta": {
                    "command": "npx",
                    "args": ["b"],
                    "tools": _tools("rotate_kubeconfig_secrets"),
                },
            }
        )
    )
    assert f.status == WARN


# --------------------------------------------------------------------------- WARN (H1: cloned server)
def test_b332_warn_not_fail_two_instances_of_the_same_server():
    """H1 (independent C-135 review): a VERY common benign pattern -- the SAME MCP
    server deployed twice under different names/scope (e.g. fs-a/fs-b scoped to two
    filesystem roots, or db-prod/db-staging pointed at two tiers of one Postgres MCP
    server). Sharing most of a real, non-generic tool-name set must NOT FAIL -- that
    is a category error (server identity), not a coverage gap. Downgraded to WARN
    (a deliberate, documented, test-pinned trade -- CLAUDE.md §2.5), never silenced.
    """
    shared_names = [
        "rotate_kubeconfig_secret",
        "provision_node_pool",
        "drain_node",
        "cordon_node",
        "taint_node",
    ]
    f = _b332_finding_from_surfaces(
        [_surface("fs-a", shared_names), _surface("fs-b", shared_names)]
    )
    assert f.status != FAIL
    assert f.status == WARN
    assert "deployed twice" in f.detail.lower() or "same server" in f.detail.lower()


def test_b332_clone_detection_does_not_suppress_a_genuine_single_tool_collision():
    """The clone-pair guard (_B332_CLONE_MIN_NAMES) must not swallow the genuine
    single-tool-collision attack shape -- a server exposing only ONE tool that happens
    to match another server's one tool is not "an identical whole surface", it's a
    real collision (this is exactly the bad_b332_mcp_exact_collision fixture's shape,
    re-pinned directly against the helper)."""
    f = _b332_finding_from_surfaces(
        [
            _surface("trusted-ops-mcp", ["rotate_kubeconfig_secret"]),
            _surface("shadow-mcp", ["rotate_kubeconfig_secret"]),
        ]
    )
    assert f.status == FAIL


# --------------------------------------------------------------------------- WARN (H2: non-English generic)
def test_b332_warn_not_fail_non_ascii_generic_name_convergence():
    """H2 (independent C-135 review, universality/CLAUDE.md §2.6): the curated
    generic-name allowlist is English-only by construction and cannot be translated
    into every language without hardcoding one lexicon after another. Two RU servers
    both exposing "поиск" ("search") is the SAME benign convergence the allowlist
    exists to protect, in a different script -- must NOT FAIL. Downgraded to WARN
    (reduced confidence, since this check cannot judge genericness in an arbitrary
    script), never silently trusted as PASS."""
    f = _b332_finding_from_surfaces(
        [_surface("ru-alpha", ["поиск"]), _surface("ru-beta", ["поиск"])]
    )
    assert f.status != FAIL
    assert f.status == WARN


def test_b332_warn_not_fail_non_ascii_generic_name_convergence_zh():
    f = _b332_finding_from_surfaces(
        [_surface("zh-alpha", ["搜索文件"]), _surface("zh-beta", ["搜索文件"])]
    )
    assert f.status != FAIL


# --------------------------------------------------------------------------- H4: truncation disclosure
def test_b332_warn_discloses_truncation_when_a_hit_survives_the_cap(monkeypatch):
    """H4 (independent C-135 review): when the pairwise (homoglyph/near-miss) scan
    hits its size cap but a real hit still survives INSIDE the scanned portion, the
    resulting verdict's detail must disclose that the scan was capped -- an earlier
    draft's truncation-disclosure branch sat AFTER the FAIL/WARN branches and was
    unreachable whenever either had already fired."""
    monkeypatch.setattr(_mcp_mod, "_B332_MAX_TOTAL_NAMES", 2)
    surfaces = [
        _surface("aaa", ["provision_cluster"]),
        _surface("bbb", ["provision_clusters"]),  # edit distance 1 from aaa's name
        _surface("ccc", ["unrelated_specific_tool_name"]),  # pushed past the cap
    ]
    f = _b332_finding_from_surfaces(surfaces)
    assert f.status == WARN
    assert "cap" in f.detail.lower()


def test_b332_exact_leg_is_never_truncated_by_the_pairwise_cap(monkeypatch):
    """H4: the exact-collision leg is an O(n) hash pass and must stay uncapped even
    when the O(n^2) pairwise cap is tiny -- a real exact collision must still FAIL."""
    monkeypatch.setattr(_mcp_mod, "_B332_MAX_TOTAL_NAMES", 1)
    surfaces = [
        _surface("aaa", ["alpha_only_tool"]),
        _surface("bbb", ["beta_only_tool"]),
        _surface("ccc", ["rotate_kubeconfig_secret"]),
        _surface("ddd", ["rotate_kubeconfig_secret"]),
    ]
    f = _b332_finding_from_surfaces(surfaces)
    assert f.status == FAIL
    assert any("rotate_kubeconfig_secret" in e for e in f.evidence)


# --------------------------------------------------------------------------- H6: manifest bare names
def test_b332_bare_tool_name_manifest_source_never_stripped():
    """H6 (independent C-135 review): a MANIFEST tool name is already bare, never
    OpenClaw-namespaced, so the strip must be SKIPPED for source == "manifest" even
    when the literal name happens to look like "<server>__something"."""
    assert (
        _b332_bare_tool_name("alpha__deploy_production", "alpha", "manifest")
        == "alpha__deploy_production"
    )


def test_b332_bare_tool_name_probe_and_trajectory_sources_stripped():
    assert _b332_bare_tool_name("mcp__alpha__search", "alpha", "probe-names") == "search"
    assert _b332_bare_tool_name("mcp__alpha__search", "alpha", "trajectory") == "search"
    assert _b332_bare_tool_name("alpha__search", "alpha", "probe-names") == "search"


def test_b332_manifest_literal_double_underscore_name_does_not_false_collide():
    """H6 integration: server "alpha" declares a tool literally named
    "alpha__deploy_production" (manifest source, already bare) and an UNRELATED server
    "beta" declares a genuinely different tool "deploy_production". An earlier draft's
    unconditional strip collapsed alpha's name down to "deploy_production" too,
    creating a false exact collision that never existed on the wire."""
    f = _b332_finding_from_surfaces(
        [
            _surface("alpha", ["alpha__deploy_production"]),
            _surface("beta", ["deploy_production"]),
        ]
    )
    assert f.status != FAIL


# --------------------------------------------------------------------------- names-only / probe-json
def test_b332_names_only_probe_json_exact_collision(tmp_path):
    """Explicit coverage of the check's PRIMARY use case: an `openclaw mcp probe --json`
    dump (completeness="names-only") with no description text at all still detects a
    real cross-server exact collision, because the OpenClaw-added
    "mcp__<server>__<tool>" namespacing is stripped back to the bare tool name before
    comparison."""
    probe = tmp_path / "probe.json"
    probe.write_text(
        json.dumps(
            {
                "servers": {"trusted-ops-mcp": {}, "shadow-mcp": {}},
                "tools": [
                    "mcp__trusted-ops-mcp__rotate_kubeconfig_secret",
                    "mcp__shadow-mcp__rotate_kubeconfig_secret",
                ],
            }
        )
    )
    surfaces = ms.from_probe_json(probe)
    assert len(surfaces) == 2
    assert all(s.completeness == "names-only" for s in surfaces)
    f = _b332_finding_from_surfaces(surfaces)
    assert f.status == FAIL
    assert any("rotate_kubeconfig_secret" in e for e in f.evidence)


def test_b332_names_only_probe_json_generic_overlap_clean(tmp_path):
    """Same names-only path, but the shared name is generic -- must not FAIL."""
    probe = tmp_path / "probe.json"
    probe.write_text(
        json.dumps(
            {
                "servers": {"docs-mcp": {}, "notes-mcp": {}},
                "tools": ["mcp__docs-mcp__search", "mcp__notes-mcp__search"],
            }
        )
    )
    surfaces = ms.from_probe_json(probe)
    f = _b332_finding_from_surfaces(surfaces)
    assert f.status == PASS


def test_b332_bare_tool_name_strips_openclaw_namespace():
    assert _b332_bare_tool_name("mcp__alpha__search", "alpha", "probe-names") == "search"
    assert _b332_bare_tool_name("alpha__search", "alpha", "probe-names") == "search"
    assert _b332_bare_tool_name("search", "alpha", "manifest") == "search"  # already bare


# --------------------------------------------------------------------------- allowlist unit coverage
def test_b332_generic_allowlist_matches_case_insensitively():
    assert _b332_is_generic("Search")
    assert _b332_is_generic("READ_FILE")
    assert not _b332_is_generic("rotate_kubeconfig_secret")
