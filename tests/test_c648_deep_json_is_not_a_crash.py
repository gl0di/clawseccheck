"""A hostile JSON document nested far deeper than a real one must be read or disclosed,
never abort the audit or the vet - on every supported Python.

How deep a document `json.loads` follows is the interpreter's own limit, and the limit
moved by a factor of fifty between the Pythons this tool supports. Measured 2026-10-05
with `json.loads("[" * n + "]" * n)`: the deepest document that parses is 994 levels on
CPython 3.9.25, 9,997 on 3.12.3 and about 58,000 on 3.14.4 (the 3.14 figure moves by a
few dozen from run to run). Two things follow, and both are pinned here:

* 3.14 hands our code documents that 3.12 refused outright, so any place that formats or
  walks a parsed value can now see one. `vet_plugin` called `str()` on a `skills` entry and
  on `openclaw.extensions` entries: a 50,000-level entry parsed on 3.14 and then raised
  `RecursionError` out of the vet (and on 3.12 and earlier a few hundred levels were
  enough to make the same text a path longer than the file-name limit, so `Path.is_dir`
  raised `OSError`).
* The readers that guard only `ValueError` abort when the parser gives up. Measured before
  the fix: a `package.json` or a stray `*.json` file deeper than the interpreter's limit
  aborted `--vet-plugin`; a paired device's `scopes_json` / `approved_scopes_json` (200 KB
  at 100,000 levels - under the byte cap) aborted the whole audit.

So every case below is parametrised over depths that the interpreters disagree about, and
the expectation is taken from what `json.loads` does in THIS run - never from a version
number. 500 parses everywhere, 5,000 parses on 3.12 and 3.14, 50,000 parses on 3.14 only,
100,000 parses nowhere.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_paired_device_operator_authority, vet_plugin
from clawseccheck.collector import (
    LIMIT_DOMAIN_PAIRED,
    Context,
    _MAX_PAIRED_DEVICE_JSON_BYTES,
    _collect_paired_devices_sqlite,
    collect,
    limit_hits_for,
)
from test_b176_paired_devices_sqlite_migration import (
    _DEVICE_PAIRING_PAIRED_DDL,
    _migrated_home,
)

DEPTHS = [500, 5_000, 50_000, 100_000]


def _deep(depth: int) -> str:
    return "[" * depth + "]" * depth


def _json_parses(text: str) -> bool:
    """Whether this interpreter's own `json.loads` follows `text` to the end."""
    try:
        json.loads(text)
    except RecursionError:
        return False
    return True


def test_premise_the_deepest_depth_is_unparseable_here_and_the_shallowest_parses():
    """If a future Python parses 100,000 levels, the 'unparseable' arm below stops running
    and every test here would pass without exercising it - raise DEPTHS when this fails."""
    assert _json_parses(_deep(DEPTHS[0]))
    assert not _json_parses(_deep(DEPTHS[-1])), "raise the deepest depth in DEPTHS"


def _plugin(tmp_path, manifest: str, extra: dict | None = None):
    root = tmp_path / "plug"
    root.mkdir()
    (root / "openclaw.plugin.json").write_text(manifest, encoding="utf-8")
    for name, body in (extra or {}).items():
        (root / name).write_text(body, encoding="utf-8")
    return root


# ---------------------------------------------------------------- manifest `skills`
@pytest.mark.parametrize("depth", DEPTHS)
def test_a_deep_skills_entry_is_noted_not_a_crash(tmp_path, depth):
    """`skills: [<deep list>]`. The entry is not a path, so it is reported as a skills entry
    that is not present - the same note a shallow non-string entry already got - and the
    vet carries on. If this interpreter cannot parse the manifest at all, that is the
    ordinary honest UNKNOWN."""
    manifest = '{"id":"d","configSchema":{},"skills":[%s]}' % _deep(depth)
    f = vet_plugin(_plugin(tmp_path, manifest))  # must not raise
    if _json_parses(manifest):
        assert f.status == PASS, f.detail
        assert any("manifest skills entry not present" in e for e in f.evidence), f.evidence
        # Bounded text: the note never carries the whole document.
        assert all(len(e) < 400 for e in f.evidence), [len(e) for e in f.evidence]
    else:
        assert f.status == UNKNOWN
        assert "could not parse" in f.detail.lower()


def test_an_ordinary_skills_entry_reads_exactly_as_before(tmp_path):
    """Control: a plain string entry and a small non-string one keep their text."""
    f = vet_plugin(_plugin(tmp_path, '{"id":"d","configSchema":{},"skills":["nothere", [1, 2]]}'))
    assert f.status == PASS, f.detail
    assert any("not present in the package: 'nothere'" in e for e in f.evidence), f.evidence
    assert any("not present in the package: '[1, 2]'" in e for e in f.evidence), f.evidence


# ------------------------------------------------ package.json `openclaw.extensions`
@pytest.mark.parametrize("depth", DEPTHS)
def test_a_deep_package_extensions_entry_is_not_a_crash(tmp_path, depth):
    pkg = '{"name":"p","version":"1.0.0","openclaw":{"extensions":[%s]}}' % _deep(depth)
    f = vet_plugin(_plugin(tmp_path, '{"id":"d","configSchema":{}}', {"package.json": pkg}))
    if _json_parses(pkg):
        assert f.status == PASS, f.detail  # parsed, read, nothing to report
    else:
        # Beyond this interpreter's parser: disclosed as an unreadable package.json.
        assert f.status == WARN, f.detail
        assert any("unreadable/unparseable package.json" in e for e in f.evidence), f.evidence


@pytest.mark.parametrize("depth", DEPTHS)
def test_a_deep_package_json_is_read_or_disclosed_never_a_crash(tmp_path, depth):
    f = vet_plugin(_plugin(tmp_path, '{"id":"d","configSchema":{}}', {"package.json": _deep(depth)}))
    # A list is not an object, so it is "unreadable/unparseable" either way.
    assert f.status == WARN, f.detail
    assert any("unreadable/unparseable package.json" in e for e in f.evidence), f.evidence


# ---------------------------------------------------- stray *.json in the plugin tree
@pytest.mark.parametrize("depth", DEPTHS)
def test_a_deep_json_file_in_the_tree_is_disclosed_not_a_crash(tmp_path, depth):
    """The tree sweep reads every `*.json` looking for embedded MCP server specs. One the
    parser cannot follow is NOT 'no spec here': it is disclosed as not examined (WARN), so
    nesting cannot be used to hide a spec from the vet. One it can follow is read as usual."""
    doc = '{"mcpServers":{"s":{"command":"echo","args":["hi"]}},"pad":%s}' % _deep(depth)
    f = vet_plugin(_plugin(tmp_path, '{"id":"d","configSchema":{}}', {"mcp.json": doc}))
    if _json_parses(doc):
        assert "nested too deeply" not in " ".join(f.evidence)
        assert "1 embedded MCP spec" in f.detail, f.detail  # still found and vetted
    else:
        assert f.status == WARN, f.detail
        assert any(
            "nested too deeply for this scanner's parser (mcp.json)" in e for e in f.evidence
        ), f.evidence
        assert "0 embedded MCP spec" in f.detail  # it really was not examined


# ------------------------------------------------- paired-device scopes (the audit)
def _home_with_scopes(tmp_path, column: str, value: str):
    home = _migrated_home(tmp_path, f"h-{column}", rows=[])
    conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
    conn.execute(_DEVICE_PAIRING_PAIRED_DDL)
    conn.execute(
        f"INSERT INTO device_pairing_paired (device_id, public_key, {column}, "
        "created_at_ms, approved_at_ms) VALUES ('d1', 'pk', ?, 1700000000000, 1700000000000)",
        (value,),
    )
    conn.commit()
    conn.close()
    return home


@pytest.mark.parametrize("column", ["scopes_json", "approved_scopes_json"])
@pytest.mark.parametrize("depth", [500, 5_000, 100_000])
def test_a_deep_scopes_value_is_read_or_reported_unreadable_never_a_crash(
    tmp_path, column, depth,
):
    """Before the fix a value past the parser's limit raised RecursionError out of the
    collector and aborted the audit (the deepest case is 200 KB, under the byte cap)."""
    nested = _deep(depth)
    assert len(nested) < _MAX_PAIRED_DEVICE_JSON_BYTES
    home = _home_with_scopes(tmp_path, column, nested)
    ctx = Context(home=home)
    _collect_paired_devices_sqlite(home, ctx)  # must not raise
    assert ctx.paired_devices_sqlite_found is True
    if _json_parses(nested):
        assert ctx.paired_devices_sqlite_parse_error is False
        assert "d1" in ctx.paired_devices_sqlite
    else:
        # Unreadable, said so: B176 turns this into UNKNOWN, never a device with no scopes.
        assert ctx.paired_devices_sqlite_parse_error is True
        assert ctx.paired_devices_sqlite == {}
        assert any("nested deeper than this reader's JSON parser follows" in e for e in ctx.errors)
        finding = check_paired_device_operator_authority(ctx)
        assert finding.status == UNKNOWN, finding.detail
        assert not limit_hits_for(ctx, LIMIT_DOMAIN_PAIRED)  # a distinct cause, not a size cap


def test_the_audit_itself_survives_the_deepest_scopes_value(tmp_path):
    """End to end through collect(): the whole-audit abort the byte cap did not prevent."""
    home = _home_with_scopes(tmp_path, "scopes_json", _deep(DEPTHS[-1]))
    ctx = collect(home)  # must not raise
    assert ctx.paired_devices_sqlite_parse_error is True
    assert check_paired_device_operator_authority(ctx).status == UNKNOWN


@pytest.mark.parametrize("depth", [500, 5_000])
def test_detection_is_kept_where_the_parser_can_follow(tmp_path, depth):
    """Positive control: a deep tail must not hide a real scope. A list holding
    `operator.admin` next to a deeply nested element still WARNs whenever this
    interpreter parses it - the fix only changes what happens where it cannot."""
    value = '["operator.admin", %s]' % _deep(depth)
    home = _home_with_scopes(tmp_path, "scopes_json", value)
    ctx = collect(home)
    finding = check_paired_device_operator_authority(ctx)
    if _json_parses(value):
        assert finding.status == WARN, finding.detail
        assert any("operator.admin" in e for e in finding.evidence)
    else:
        assert finding.status == UNKNOWN, finding.detail
