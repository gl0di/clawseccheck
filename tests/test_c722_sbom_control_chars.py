"""C-722 item 3 -- ``--sbom`` output carries no control character from a component name,
and no name is changed in a way that merges it with another.

A skill directory, an MCP server key and a plugin id are chosen by whoever authored them.
The three SBOM formats (native, CycloneDX, SPDX) copied those names, and the version /
command / supplier fields read from the same place, into their values as they came: an
escape sequence, a bell, a carriage return. An SBOM is data, so nothing is deleted: the
text is ESCAPED, and the escape is injective (one backslash is written as two; a Cc, Zl or
Zp character, or a Cf character other than ZWNJ/ZWJ, is written ``\\uXXXX`` or
``\\UXXXXXXXX``), so two different names never render alike and the original can be
recovered. A name with no backslash and none of those characters is byte-identical to
before: ZWJ emoji sequences and Persian text keep their joiners.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from pathlib import Path

import pytest

from clawseccheck.collector import collect
from clawseccheck.sbom import (
    build_sbom, render_sbom, render_sbom_cyclonedx, render_sbom_spdx,
)

ESC = "\x1b"
HOSTILE_SKILL = "evil" + ESC + "[31mred\x07bell\rcr"
HOSTILE_MCP = "srv" + ESC + "[0m\x07\rend\x9b31m\x85x"
FORMATS = {
    "native": render_sbom,
    "cyclonedx": render_sbom_cyclonedx,
    "spdx": render_sbom_spdx,
}


def _home(tmp_path: Path, skill_names, mcp_names) -> Path:
    home = tmp_path / "home"
    for i, name in enumerate(skill_names):
        d = home / "skills" / name
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(f"---\nname: x\nversion: 1.2.3\n---\nHello {i}\n",
                                    encoding="utf-8")
    servers = {name: {"command": "npx", "args": ["-y", "pkg@1.0.0"]} for name in mcp_names}
    home.mkdir(parents=True, exist_ok=True)
    (home / "openclaw.json").write_text(json.dumps({"mcp": {"servers": servers}}),
                                        encoding="utf-8")
    os.chmod(home / "openclaw.json", 0o600)
    return home


def _unescape(text: str) -> str:
    """An independent decoder for the escape: ``\\\\`` is one backslash, ``\\uXXXX`` and
    ``\\UXXXXXXXX`` are that character."""
    def one(m):
        body = m.group(1)
        return "\\" if body == "\\" else chr(int(body[1:], 16))
    return re.sub(r"\\(\\|u[0-9a-f]{4}|U[0-9a-f]{8})", one, text)


def _strings(value):
    """Every string in a parsed document, keys included."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)


def _controls(text: str) -> list:
    return sorted({hex(ord(c)) for c in text if unicodedata.category(c) == "Cc"})


def _names(rendered: str, fmt: str) -> list:
    doc = json.loads(rendered)
    if fmt == "native":
        return [e["name"] for kind in ("skills", "mcp_servers", "plugins") for e in doc[kind]]
    if fmt == "cyclonedx":
        return [c["name"] for c in doc["components"]]
    return [p["name"] for p in doc["packages"]]


@pytest.fixture
def hostile_ctx(tmp_path):
    ctx = collect(_home(tmp_path, [HOSTILE_SKILL], [HOSTILE_MCP]))
    # The test is vacuous unless the hostile names really reached the inventory.
    assert any(ESC in n for n in ctx.installed_skills), list(ctx.installed_skills)
    assert any(ESC in e["name"] for e in build_sbom(ctx)["mcp_servers"])
    return ctx


# --------------------------------------------------------------- nothing raw survives
@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_no_control_character_survives_in_any_format(hostile_ctx, fmt):
    rendered = FORMATS[fmt](hostile_ctx)
    assert _controls(rendered.replace("\n", "")) == [], "the raw text carries a control character"
    leaked = {c for s in _strings(json.loads(rendered)) for c in _controls(s)}
    assert not leaked, f"{fmt} values carry control characters {sorted(leaked)}"
    # C1 and the bidi / zero-width / BOM class are escaped too.
    for text in _strings(json.loads(rendered)):
        assert not re.search("[\x80-\x9f\u200b\u202a-\u202e\u2066-\u2069\ufeff]", text), text


@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_the_escape_is_written_the_way_the_rule_says(hostile_ctx, fmt):
    names = _names(FORMATS[fmt](hostile_ctx), fmt)
    assert "evil\\u001b[31mred\\u0007bell\\u000dcr" in names
    assert "srv\\u001b[0m\\u0007\\u000dend\\u009b31m\\u0085x" in names


@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_the_original_name_is_recoverable(hostile_ctx, fmt):
    decoded = {_unescape(n) for n in _names(FORMATS[fmt](hostile_ctx), fmt)}
    assert {HOSTILE_SKILL, HOSTILE_MCP} <= decoded


def test_the_full_hash_of_a_hostile_component_is_still_attached(hostile_ctx):
    """The hash is looked up by the raw name; escaping the printed name must not lose it."""
    cdx = json.loads(render_sbom_cyclonedx(hostile_ctx))
    spdx = json.loads(render_sbom_spdx(hostile_ctx))
    for comp in cdx["components"]:
        content = comp["hashes"][0]["content"]
        assert len(content) == 64 and set(content) <= set("0123456789abcdef"), comp["name"]
    for pkg in spdx["packages"]:
        value = pkg["checksums"][0]["checksumValue"]
        assert len(value) == 64 and set(value) <= set("0123456789abcdef"), pkg["name"]


# ------------------------------------------------------- different names stay different
_LITERAL = "evil~" + hashlib.sha256(("evil" + ESC + "[2K").encode("utf-8")).hexdigest()[:8]
COLLIDING = ["evil", "e\x07vil", "ev\u200bil", "evil" + ESC + "[2K", "evil" + ESC + "[31m",
             "evil\r", _LITERAL]


@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_names_that_used_to_render_alike_render_differently(tmp_path, fmt):
    ctx = collect(_home(tmp_path, COLLIDING, []))
    names = _names(FORMATS[fmt](ctx), fmt)
    assert len(names) == len(COLLIDING) and len(set(names)) == len(COLLIDING), names
    assert sorted(_unescape(n) for n in names) == sorted(COLLIDING)


def test_the_cyclonedx_refs_and_spdx_ids_stay_unique_and_valid(tmp_path):
    ctx = collect(_home(tmp_path, COLLIDING, []))
    refs = [c["bom-ref"] for c in json.loads(render_sbom_cyclonedx(ctx))["components"]]
    assert len(set(refs)) == len(COLLIDING), refs
    assert "skill:evil" in refs, "the ordinary name keeps the plain ref"
    ids = [p["SPDXID"] for p in json.loads(render_sbom_spdx(ctx))["packages"]]
    assert len(set(ids)) == len(COLLIDING), ids
    assert all(re.fullmatch(r"SPDXRef-[A-Za-z0-9.\-]+", i) for i in ids), ids


# ------------------------------------------------------------- ordinary text is kept
ORDINARY = [
    "good-skill",
    "café-\u65e5\u672c",
    "\U0001F468\u200d\U0001F469\u200d\U0001F467",   # ZWJ emoji sequence
    "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645",   # Persian, with ZWNJ
]


@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_ordinary_unicode_names_are_unchanged(tmp_path, fmt):
    ctx = collect(_home(tmp_path, ORDINARY, ["good_mcp.server"]))
    names = _names(FORMATS[fmt](ctx), fmt)
    for name in ORDINARY + ["good_mcp.server"]:
        assert name in names, (name, names)


def test_cyclonedx_refs_for_ordinary_names_are_the_plain_ones(tmp_path):
    ctx = collect(_home(tmp_path, ORDINARY, ["good_mcp.server"]))
    refs = {c["bom-ref"] for c in json.loads(render_sbom_cyclonedx(ctx))["components"]}
    assert refs == {f"skill:{n}" for n in ORDINARY} | {"mcp_server:good_mcp.server"}


@pytest.mark.parametrize("fmt", sorted(FORMATS))
def test_a_backslash_is_doubled_and_recoverable(tmp_path, fmt):
    raw = "a\\b\\u0041"     # also looks like an escape: it must not decode to "A"
    ctx = collect(_home(tmp_path, [raw], []))
    names = _names(FORMATS[fmt](ctx), fmt)
    assert "a\\\\b\\\\u0041" in names, names
    assert raw in {_unescape(n) for n in names}


def test_a_tab_is_escaped_not_turned_into_a_space(tmp_path):
    ctx = collect(_home(tmp_path, ["a\tb"], []))
    assert "a\\u0009b" in _names(render_sbom(ctx), "native")


# --------------------------------------------------------------------------- plugins
def test_a_plugin_record_with_control_characters_is_escaped_and_recoverable(tmp_path):
    raw_id = "plug" + ESC + "[31m\x07\rin"
    ctx = collect(_home(tmp_path, [], []))
    ctx.plugin_index_records = [{
        "plugin_id": raw_id,
        "origin": "global" + ESC + "[0m",
        "enabled": True,
        "contracts": {"tool" + "\x07": {}},
        "manifest_path": "/x/openclaw.plugin.json",
        "root_dir": "/x",
        "source": "/x/index.js",
    }]
    for fmt, render in FORMATS.items():
        rendered = render(ctx)
        assert _controls(rendered.replace("\n", "")) == [], fmt
        assert raw_id in {_unescape(n) for n in _names(rendered, fmt)}, fmt


# ------------------------------------------------------------------------ the control
NORMAL_SKILL = "good-skill"
NORMAL_MCP = "good_mcp.server"
UNICODE_SKILL = "café-\u65e5\u672c"


@pytest.fixture
def normal_ctx(tmp_path):
    return collect(_home(tmp_path, [NORMAL_SKILL, UNICODE_SKILL], [NORMAL_MCP]))


def test_native_output_for_ordinary_names_is_byte_identical_to_the_raw_inventory(normal_ctx):
    old = json.dumps(build_sbom(normal_ctx), ensure_ascii=True, indent=2, sort_keys=True)
    assert render_sbom(normal_ctx) == old


def test_cyclonedx_output_for_ordinary_names_keeps_names_refs_and_hashes(normal_ctx):
    doc = json.loads(render_sbom_cyclonedx(normal_ctx))
    by_ref = {c["bom-ref"]: c for c in doc["components"]}
    assert set(by_ref) == {f"skill:{NORMAL_SKILL}", f"skill:{UNICODE_SKILL}",
                           f"mcp_server:{NORMAL_MCP}"}
    skill = by_ref[f"skill:{NORMAL_SKILL}"]
    assert skill["name"] == NORMAL_SKILL and skill["version"] == "1.2.3"
    assert by_ref[f"skill:{UNICODE_SKILL}"]["name"] == UNICODE_SKILL
    assert len(skill["hashes"][0]["content"]) == 64


def test_spdx_output_for_ordinary_names_keeps_names_and_versions(normal_ctx):
    doc = json.loads(render_sbom_spdx(normal_ctx))
    pkgs = {p["name"]: p for p in doc["packages"]}
    assert set(pkgs) == {NORMAL_SKILL, UNICODE_SKILL, NORMAL_MCP}
    assert pkgs[NORMAL_SKILL]["versionInfo"] == "1.2.3"
    assert pkgs[NORMAL_SKILL]["SPDXID"].startswith("SPDXRef-skill-good-skill-")
    assert len(pkgs[NORMAL_SKILL]["checksums"][0]["checksumValue"]) == 64


def test_the_control_check_would_catch_a_leak(hostile_ctx):
    """The positive control for the tests above: the raw inventory DOES carry the controls
    (so a renderer that skipped escaping would fail them)."""
    raw = json.dumps(build_sbom(hostile_ctx), ensure_ascii=False)
    assert _controls(raw), "the hostile fixture must carry a control character"
