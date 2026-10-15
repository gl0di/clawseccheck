"""B176 over a paired-device store with ONE unreadable scopes value: a WARN found in OTHER,
readable rows stands, and what was not read is disclosed. Nothing inside an unreadable value
is salvaged - a scopes list holding one too-deep element is unreadable whole, `operator.admin`
beside it included, and its device is UNKNOWN, never a WARN and never clean.

`configloader.MAX_JSON_NESTING` (C-648) makes a JSON value nested deeper than 200 levels
unreadable on every interpreter. Applied to the SQLite store (`device_pairing_paired`) that
first turned ONE device's too-deep `approved_scopes_json` into "the whole table is
unreadable": device d1 holding `operator.admin` in a perfectly readable column stopped being
a WARN and became UNKNOWN, because device d2 (a different row) carried a hostile value.
B176's own contract is the opposite - "a WARN found in what WAS scanned stands regardless;
only a verdict built on ABSENCE degrades" - so an unreadable scopes column makes just that
device unreadable, says so, and leaves every other device's verdict alone.

What is pinned here:

* the SQLite store: d1 `operator.admin` + d2 with an unreadable (too deep OR malformed)
  `scopes_json` / `approved_scopes_json` is a WARN naming d1, with the unreadable device
  disclosed in `fix` (never in `detail`, which a fingerprint hashes); with no readable
  admin the answer is UNKNOWN, never PASS;
* the legacy `devices/paired.json` is ONE document, so a document nested too deeply cannot
  be read at all: UNKNOWN as a whole by design (a WARN inside that same unreadable document
  cannot be salvaged) - but its detail says the file nests too deeply, not
  that it "is not valid JSON" (it is valid), while a genuinely invalid file keeps its
  original detail byte for byte;
* no expectation branches on an interpreter version or on what `json.loads` follows.
"""
from __future__ import annotations

import sqlite3

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_paired_device_operator_authority
from clawseccheck.collector import Context, collect, _collect_paired_devices_sqlite
from clawseccheck.configloader import MAX_JSON_NESTING as LIMIT
from test_b176_paired_devices_sqlite_migration import (
    _DEVICE_PAIRING_PAIRED_DDL,
    _migrated_home,
)

ADMIN = '["operator.admin"]'
READ = '["operator.read"]'

# What `fix` says when a device's scopes could not be read. Asserted as a fragment so the
# wording can be tuned without touching every test; the fragment is the load-bearing claim.
UNREAD = "could not be read"


def _deep(depth: int) -> str:
    return "[" * depth + "]" * depth


def _home(tmp_path, name: str, rows: list[dict]):
    """A migrated home whose `device_pairing_paired` holds *rows* (column -> value)."""
    home = _migrated_home(tmp_path, name, rows=[])
    conn = sqlite3.connect(home / "state" / "openclaw.sqlite")
    conn.execute(_DEVICE_PAIRING_PAIRED_DDL)
    for row in rows:
        cols = {"public_key": "pk", "created_at_ms": 1700000000000,
                "approved_at_ms": 1700000000000, **row}
        conn.execute(
            f"INSERT INTO device_pairing_paired ({', '.join(cols)}) "
            f"VALUES ({', '.join('?' for _ in cols)})",
            tuple(cols.values()),
        )
    conn.commit()
    conn.close()
    return home


def _b176(home):
    ctx = Context(home=home)
    _collect_paired_devices_sqlite(home, ctx)
    return check_paired_device_operator_authority(ctx), ctx


def _d1_admin():
    return {"device_id": "d1", "scopes_json": ADMIN}


# ------------------------------------------------ the SQLite store: one bad row, one WARN
BAD_COLUMNS = ["approved_scopes_json", "scopes_json"]
UNREADABLE = {
    "too deep": _deep(LIMIT + 1),
    "far too deep": _deep(20_000),
    "malformed": "{not valid json",
    "truncated": '["operator.admin"',
}


@pytest.mark.parametrize("column", BAD_COLUMNS)
@pytest.mark.parametrize("kind", sorted(UNREADABLE))
def test_a_warn_in_a_readable_row_stands_beside_an_unreadable_row(tmp_path, column, kind):
    home = _home(tmp_path, "h", [_d1_admin(), {"device_id": "d2", column: UNREADABLE[kind]}])
    f, ctx = _b176(home)
    assert f.status == WARN, (f.status, f.detail)
    assert any("deviceId=d1" in e and "operator.admin" in e for e in f.evidence), f.evidence
    assert ctx.paired_devices_sqlite_parse_error is False  # the table WAS read
    # The unreadable remainder is disclosed, and it is d2 that is named, not d1.
    assert UNREAD in f.fix and "d2" in f.fix, f.fix
    assert not any("d2" in e for e in f.evidence), f.evidence  # d2 is unread, not a WARN device
    # `detail` is what a fingerprint hashes: it is byte-identical to the WARN of a store
    # whose d2 is perfectly readable, so a user's ignore entry for this finding survives.
    clean = _home(tmp_path, "clean", [_d1_admin(), {"device_id": "d2", "scopes_json": READ}])
    f_clean, _ = _b176(clean)
    assert f_clean.status == WARN
    assert f.detail == f_clean.detail
    assert UNREAD not in f_clean.fix


@pytest.mark.parametrize("column", BAD_COLUMNS)
def test_too_deep_and_malformed_give_the_same_shape(tmp_path, column):
    """The same WARN, the same disclosure fragment, the same evidence - the only difference
    is the cause the disclosure names."""
    deep = _home(tmp_path, "deep",
                 [_d1_admin(), {"device_id": "d2", column: _deep(LIMIT + 1)}])
    bad = _home(tmp_path, "bad",
                [_d1_admin(), {"device_id": "d2", column: "{not valid json"}])
    f_deep, _ = _b176(deep)
    f_bad, _ = _b176(bad)
    assert f_deep.status == f_bad.status == WARN
    assert f_deep.detail == f_bad.detail
    assert f_deep.evidence == f_bad.evidence
    assert UNREAD in f_deep.fix and UNREAD in f_bad.fix
    assert "d2" in f_deep.fix and "d2" in f_bad.fix


@pytest.mark.parametrize("column", BAD_COLUMNS)
def test_the_unreadable_row_may_hold_the_admin_scope_in_its_other_column(tmp_path, column):
    """d2's `approved_scopes_json` is unreadable but its readable `scopes_json` already
    holds the admin scope: d2 is itself a WARN device, and is not ALSO listed as unread."""
    other = "scopes_json" if column == "approved_scopes_json" else "approved_scopes_json"
    home = _home(tmp_path, "h", [{"device_id": "d2", column: _deep(LIMIT + 1), other: ADMIN}])
    f, _ = _b176(home)
    assert f.status == WARN
    assert any("deviceId=d2" in e for e in f.evidence), f.evidence


@pytest.mark.parametrize("column", BAD_COLUMNS)
@pytest.mark.parametrize("kind", sorted(UNREADABLE))
def test_no_readable_admin_beside_an_unreadable_row_is_unknown_never_pass(
    tmp_path, column, kind,
):
    home = _home(tmp_path, "h", [
        {"device_id": "d1", "scopes_json": READ},
        {"device_id": "d2", column: UNREADABLE[kind]},
    ])
    f, _ = _b176(home)
    assert f.status == UNKNOWN, (f.status, f.detail)
    assert f.status != PASS
    assert UNREAD in f.detail and "d2" not in f.detail  # said so, without naming a device
    assert "d2" in f.fix


@pytest.mark.parametrize("column", BAD_COLUMNS)
@pytest.mark.parametrize("depth", [LIMIT + 1, 1_500, 100_000])
def test_a_store_whose_only_row_is_too_deep_is_still_unknown(tmp_path, column, depth):
    """Nothing in the table could be read: the same unreadable-table answer as before."""
    home = _home(tmp_path, "h", [{"device_id": "d1", column: _deep(depth)}])
    f, ctx = _b176(home)
    assert f.status == UNKNOWN, f.detail
    assert ctx.paired_devices_sqlite_parse_error is True
    assert ctx.paired_devices_sqlite == {}


@pytest.mark.parametrize("column", BAD_COLUMNS)
def test_two_rows_all_too_deep_is_unknown(tmp_path, column):
    home = _home(tmp_path, "h", [
        {"device_id": "d1", column: _deep(LIMIT + 1)},
        {"device_id": "d2", column: _deep(LIMIT + 1)},
    ])
    f, _ = _b176(home)
    assert f.status == UNKNOWN, f.detail


@pytest.mark.parametrize("column", BAD_COLUMNS)
def test_a_value_exactly_at_the_limit_is_read_and_nothing_is_disclosed(tmp_path, column):
    home = _home(tmp_path, "h", [_d1_admin(), {"device_id": "d2", column: _deep(LIMIT)}])
    f, ctx = _b176(home)
    assert f.status == WARN
    assert UNREAD not in f.fix
    assert "d2" in ctx.paired_devices_sqlite


@pytest.mark.parametrize("column", ["tokens_json", "roles_json", "node_surface_json"])
@pytest.mark.parametrize("depth", [LIMIT + 1, 20_000])
def test_a_deep_value_in_another_column_does_not_touch_the_warn(tmp_path, column, depth):
    """Control: these columns were never the problem, and B176 does not read them."""
    home = _home(tmp_path, "h", [_d1_admin(), {"device_id": "d2", column: _deep(depth)}])
    f, _ = _b176(home)
    assert f.status == WARN
    assert any("deviceId=d1" in e for e in f.evidence), f.evidence
    assert UNREAD not in f.fix


def test_the_entry_of_an_unreadable_row_never_looks_like_a_device_with_no_scopes(tmp_path):
    home = _home(tmp_path, "h", [_d1_admin(),
                                 {"device_id": "d2", "approved_scopes_json": _deep(LIMIT + 1)}])
    _, ctx = _b176(home)
    d2 = ctx.paired_devices_sqlite["d2"]
    assert d2["scopesUnparsed"] is True
    assert d2["approvedScopes"] is None and d2["scopes"] is None
    assert ctx.paired_devices_sqlite["d1"]["scopesUnparsed"] is False
    # and the text report carries it too
    assert any(f"nested deeper than the {LIMIT} levels" in e for e in ctx.errors), ctx.errors


def test_the_audit_itself_reaches_the_warn_through_collect(tmp_path):
    home = _home(tmp_path, "h", [_d1_admin(),
                                 {"device_id": "d2", "approved_scopes_json": _deep(100_000)}])
    ctx = collect(home)  # must not raise
    f = check_paired_device_operator_authority(ctx)
    assert f.status == WARN, f.detail
    assert UNREAD in f.fix


def test_clean_store_is_still_pass_and_a_null_column_is_not_unreadable(tmp_path):
    """A NULL / empty scopes column is the ordinary shape (a device approved with only one of
    the two), not an unreadable one - it must not read as a disclosure or as UNKNOWN."""
    home = _home(tmp_path, "h", [
        {"device_id": "d1", "scopes_json": READ},
        {"device_id": "d2", "approved_scopes_json": READ, "scopes_json": ""},
        {"device_id": "d3"},
    ])
    f, _ = _b176(home)
    assert f.status == PASS, f.detail


def test_a_readable_admin_with_nothing_unreadable_has_no_disclosure(tmp_path):
    f, _ = _b176(_home(tmp_path, "h", [_d1_admin()]))
    assert f.status == WARN
    assert UNREAD not in f.fix


# ------------------------------------------------------------ the legacy devices/paired.json
LEGACY_DETAIL_INVALID = (
    "devices/paired.json present but not valid JSON — cannot evaluate paired "
    "device operator authority."
)
LEGACY_FIX_INVALID = (
    "Review devices/paired.json manually for paired devices holding standing "
    "operator authority."
)


def _legacy(tmp_path, text: str):
    home = tmp_path / "legacy"
    (home / "devices").mkdir(parents=True)
    (home / "devices" / "paired.json").write_text(text, encoding="utf-8")
    return home


def _legacy_doc(junk_depth: int) -> str:
    """d1 holds operator.admin; a junk key beside it nests `junk_depth` levels below the
    top-level object (so the document is `junk_depth + 1` levels deep)."""
    return '{"d1":{"deviceId":"d1","scopes":["operator.admin"]},"junk":%s}' % _deep(junk_depth)


@pytest.mark.parametrize("junk_depth", [LIMIT, 1_500, 20_000])
def test_a_legacy_file_nested_too_deep_is_unknown_and_not_called_invalid(tmp_path, junk_depth):
    f = check_paired_device_operator_authority(
        Context(home=_legacy(tmp_path, _legacy_doc(junk_depth)))
    )
    assert f.status == UNKNOWN, f.detail
    assert "not valid JSON" not in f.detail, f.detail
    assert f"deeper than the {LIMIT} levels" in f.detail, f.detail
    assert "devices/paired.json" in f.detail
    assert "could not be read" in f.detail
    assert f.fix and f.fix != LEGACY_FIX_INVALID  # advice for THIS case, in `fix`
    assert "not valid JSON" not in f.fix
    assert "openclaw devices list" in f.fix


def test_a_legacy_file_exactly_at_the_limit_is_read_and_warns(tmp_path):
    f = check_paired_device_operator_authority(
        Context(home=_legacy(tmp_path, _legacy_doc(LIMIT - 1)))
    )
    assert f.status == WARN, f.detail
    assert any("deviceId=d1" in e for e in f.evidence), f.evidence


@pytest.mark.parametrize("text", ['{"d1": ', "{not json", '{"d1":{"scopes":["operator.admin"]}'])
def test_a_genuinely_invalid_legacy_file_keeps_its_detail_byte_for_byte(tmp_path, text):
    f = check_paired_device_operator_authority(Context(home=_legacy(tmp_path, text)))
    assert f.status == UNKNOWN
    assert f.detail == LEGACY_DETAIL_INVALID
    assert f.fix == LEGACY_FIX_INVALID


def test_a_normal_legacy_file_with_operator_admin_still_warns(tmp_path):
    doc = '{"d1":{"deviceId":"d1","platform":"linux","scopes":["operator.admin"]}}'
    f = check_paired_device_operator_authority(Context(home=_legacy(tmp_path, doc)))
    assert f.status == WARN, f.detail
    assert any("deviceId=d1" in e and "operator.admin" in e for e in f.evidence), f.evidence
    assert "not valid JSON" not in f.detail and "deeper" not in f.detail
