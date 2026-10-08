"""A hostile JSON document nested far deeper than a real one is read or disclosed - never a
crash, and (for the paired-device columns) never an answer that depends on the machine.

Two different regimes live in this file, on purpose.

* The paired-device `scopes_json` / `approved_scopes_json` columns are read with OUR limit,
  `configloader.MAX_JSON_NESTING` levels, enforced on the text before any parser runs. A
  value nested deeper makes the whole table UNKNOWN (a WARN inside the same unreadable value
  cannot be salvaged); a value within the limit is read. How deep `json.loads` follows is the
  interpreter's business and not a constant - measured 2026-10-05 with
  `json.loads("[" * n + "]" * n)`: 991 levels on CPython 3.9.25, 9,997 on 3.12.3, and on
  3.14.4 the process STACK SIZE decides - 57,974 with the default 8 MB stack, more than
  400,000 under `ulimit -s 65536` (a CI runner's larger stack). So those tests derive every
  expectation from the limit and none from the interpreter.
* `vet_plugin` reads UNTRUSTED third-party manifests and has no limit of our own: one would
  turn a manifest padded past it into a way to hide what it declares. It keeps the
  interpreter's own recursion guard, so there a document is read or disclosed depending on
  what `json.loads` does in this run (never on a version number), and the shallowest depth
  parses everywhere. Beyond the guard the readers must degrade, never abort:
  `vet_plugin` used to call `str()` on a `skills` entry and on `openclaw.extensions` entries
  and raised `RecursionError` out of the vet on a document 3.14 parsed but 3.12 refused.
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
from clawseccheck.configloader import MAX_JSON_NESTING as LIMIT
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


def test_premise_the_shallowest_depth_parses_everywhere():
    """`vet_plugin` reads an UNTRUSTED manifest and has no nesting limit of our own (one would
    let a manifest padded past it hide what it declares), so below it the interpreter's
    parser decides where a document stops parsing. 500 levels parse on every supported
    Python; the deepest depth below does NOT fail to parse on every Python (on 3.14 the
    figure follows the process stack size and a large stack follows more than 400,000
    levels), so the arms below branch on what `json.loads` does HERE and nothing asserts
    which arm that is. The 'parser gave up' arm is therefore also pinned deterministically,
    by `test_the_parser_giving_up_degrades_the_vet_to_unknown`."""
    assert _json_parses(_deep(DEPTHS[0]))


def test_the_parser_giving_up_degrades_the_vet_to_unknown(tmp_path, monkeypatch):
    """The C-135 degrade arm, forced: whatever depth an interpreter's parser gives up at, a
    `RecursionError` out of the manifest read is an honest UNKNOWN, never an aborted vet."""
    def give_up(*_a, **_k):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(json, "loads", give_up)
    f = vet_plugin(_plugin(tmp_path, '{"id":"d","configSchema":{}}'))
    assert f.status == UNKNOWN
    assert "could not parse" in f.detail.lower()


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
# The paired-device columns are read with OUR limit (`configloader.MAX_JSON_NESTING`), so
# nothing in this section takes an expectation from what `json.loads` does in the running
# interpreter, and no test branches on a version. "Too deep" there is an honest UNKNOWN: the
# column cannot be read, and a WARN inside the same unreadable value cannot be salvaged.
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


# A 400,000-level value is 800 KB - over `_MAX_PAIRED_DEVICE_JSON_BYTES`, so the row would
# be excluded by the byte cap (a different, already-tested channel) before any JSON is read.
# 100,000 levels (200 KB) is the deepest value that still reaches the reader.
SCOPE_DEPTHS = [150, LIMIT, LIMIT + 1, 1_500, 20_000, 100_000]


def test_the_scope_depths_straddle_the_limit_on_both_sides():
    assert max(d for d in SCOPE_DEPTHS if d <= LIMIT) == LIMIT
    assert min(d for d in SCOPE_DEPTHS if d > LIMIT) == LIMIT + 1


@pytest.mark.parametrize("column", ["scopes_json", "approved_scopes_json"])
@pytest.mark.parametrize("depth", SCOPE_DEPTHS)
def test_a_deep_scopes_value_is_read_or_reported_unreadable_never_a_crash(
    tmp_path, column, depth,
):
    """Before round 1 a value past the interpreter's parser limit raised RecursionError out
    of the collector and aborted the whole audit (the deepest case is 200 KB, under the byte
    cap). Now the answer is ours: within the limit the row is read; beyond it the table is
    reported unreadable, with the limit named."""
    nested = _deep(depth)
    assert len(nested) < _MAX_PAIRED_DEVICE_JSON_BYTES
    home = _home_with_scopes(tmp_path, column, nested)
    ctx = Context(home=home)
    _collect_paired_devices_sqlite(home, ctx)  # must not raise
    assert ctx.paired_devices_sqlite_found is True
    if depth <= LIMIT:
        assert ctx.paired_devices_sqlite_parse_error is False
        assert "d1" in ctx.paired_devices_sqlite
    else:
        # Unreadable, said so: B176 turns this into UNKNOWN, never a device with no scopes.
        assert ctx.paired_devices_sqlite_parse_error is True
        assert ctx.paired_devices_sqlite == {}
        assert any(
            f"nested deeper than the {LIMIT} levels this reader follows" in e for e in ctx.errors
        ), ctx.errors
        finding = check_paired_device_operator_authority(ctx)
        assert finding.status == UNKNOWN, finding.detail
        assert not limit_hits_for(ctx, LIMIT_DOMAIN_PAIRED)  # a distinct cause, not a size cap


@pytest.mark.parametrize("depth", [LIMIT + 1, 20_000, 100_000])
def test_the_audit_itself_survives_a_deep_scopes_value(tmp_path, depth):
    """End to end through collect(): the whole-audit abort the byte cap did not prevent. The
    depths include one a 3.14 with a large stack would have parsed; the answer is the same."""
    home = _home_with_scopes(tmp_path, "scopes_json", _deep(depth))
    ctx = collect(home)  # must not raise
    assert ctx.paired_devices_sqlite_parse_error is True
    assert check_paired_device_operator_authority(ctx).status == UNKNOWN


@pytest.mark.parametrize("depth", [150, LIMIT])
def test_a_deep_scopes_value_within_the_limit_is_read_as_a_value(tmp_path, depth):
    home = _home_with_scopes(tmp_path, "scopes_json", _deep(depth))
    ctx = collect(home)
    assert ctx.paired_devices_sqlite_parse_error is False
    # A list of lists is a list: kept, with no operator scope in it.
    assert check_paired_device_operator_authority(ctx).status == PASS


@pytest.mark.parametrize("depth", [150, LIMIT, LIMIT + 1, 1_500])
def test_detection_is_kept_within_the_limit_and_never_cleared_beyond_it(tmp_path, depth):
    """Positive control: a deep tail must not hide a real scope. A list holding
    `operator.admin` next to a deeply nested element still WARNs while the value is within
    the limit; beyond it the table is UNKNOWN - never PASS, never a silently dropped scope."""
    value = '["operator.admin", %s]' % _deep(depth - 1)
    home = _home_with_scopes(tmp_path, "scopes_json", value)
    ctx = collect(home)
    finding = check_paired_device_operator_authority(ctx)
    if depth <= LIMIT:
        assert finding.status == WARN, finding.detail
        assert any("operator.admin" in e for e in finding.evidence)
    else:
        assert finding.status == UNKNOWN, finding.detail
