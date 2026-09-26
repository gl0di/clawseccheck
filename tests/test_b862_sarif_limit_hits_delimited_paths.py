"""B-862 — second-pass review of B-633 (see docs/... task, B-862): B-633's basename
reduction stopped at the first whitespace/quote/paren inside a matched path, so a path
containing one of those characters still leaked everything past it, and one real
producer cluster (`collector._collect_plugin_trust`'s byte-cap branches) interpolated
`db_path` with NO delimiter at all -- both survived into `analysis_completeness.
limit_hits`. A Windows UNC path (`\\\\server\\share\\...`) was not matched by either
regex alternative and passed through completely untouched.

Fixed:
  1. `sarif._NON_HOME_ABS_PATH_RE` now has dedicated lookaround alternatives for a
     path wrapped in parens or single quotes that match up to the delimiter's own
     close, not the first whitespace inside it -- so a space in the path no longer
     truncates the reduction.
  2. `collector._collect_plugin_trust`'s bare `{db_path}` interpolations (the byte-cap
     and record-count `note_limit` calls) now quote `db_path` like every sibling
     producer in the file already does, restoring the invariant the regex leans on.
  3. Bare and delimited UNC path tokens are now matched and reduced too.

NOT fixed, accepted residual (see the comment above `_NON_HOME_ABS_PATH_RE` in
sarif.py for the full C-135 reasoning): a path that contains the SAME character used
to delimit it (an apostrophe inside a single-quoted path) still leaks past that
apostrophe, because matching to the LAST quote in the sentence instead would mis-span
across the two independently-quoted paths `_flag_shadowed_cron_store` can emit in one
message. Pinned here in the direction that must NOT silently start passing (so a
future "fix" that reintroduces the greedy/unsound approach gets caught) as well as the
direction that must keep working (the plain-space case, no apostrophe involved).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from clawseccheck.collector import (
    LIMIT_DOMAIN_PLUGIN,
    Context,
    _collect_plugin_trust,
    _MAX_PLUGIN_TRUST_BYTES,
    limit_hits_for,
)
from clawseccheck.sarif import _sarif_limit_hit_text, render_sarif

SENSITIVE = "Acme Corp Client"


# --------------------------------------------------------------------------------
# 1. Space-in-path, delimited by parens -- the real `_config_workspace_dirs` shape
#    (`"custom workspace 'name' resolves outside the audited --home (PATH)"`).
# --------------------------------------------------------------------------------

def test_paren_wrapped_path_with_a_space_is_reduced_to_basename():
    entry = (
        f"custom workspace 'w' resolves outside the audited --home "
        f"(/mnt/backup/{SENSITIVE}/workspace) — bootstrap/skills read from there"
    )
    out = _sarif_limit_hit_text(entry)
    assert SENSITIVE not in out, out
    assert "workspace)" in out, out  # basename survives, still useful for a reader


# --------------------------------------------------------------------------------
# 2. Space-in-path, delimited by single quotes -- the real `cron store '...'` shape.
# --------------------------------------------------------------------------------

def test_quote_wrapped_path_with_a_space_is_reduced_to_basename():
    entry = f"cron store '/mnt/backup/{SENSITIVE}/jobs.json' exceeded the 5MB cap"
    out = _sarif_limit_hit_text(entry)
    assert SENSITIVE not in out, out
    assert "'jobs.json'" in out, out


# --------------------------------------------------------------------------------
# 3. Accepted residual: an apostrophe INSIDE a single-quoted path collides with the
#    delimiter itself. Pinned both ways -- see module docstring.
# --------------------------------------------------------------------------------

def test_apostrophe_inside_a_quoted_path_is_the_documented_residual():
    entry = "cron store '/mnt/backup/Bob's stuff/jobs.json' exceeded the 5MB cap"
    out = _sarif_limit_hit_text(entry)
    # The residual: content after the apostrophe survives verbatim.
    assert "stuff/jobs.json" in out, out
    # What must NOT regress back to (B-633's original bug): the reduction still runs
    # at all, and the segment BEFORE the apostrophe is gone.
    assert "/mnt/backup" not in out, out


# --------------------------------------------------------------------------------
# 4. UNC paths -- bare and delimited -- previously passed through untouched.
# --------------------------------------------------------------------------------

def test_bare_unc_path_is_reduced_to_basename():
    entry = r"cron store \\server\share\jobs.json exceeded the 5MB cap"
    out = _sarif_limit_hit_text(entry)
    assert "server" not in out, out
    assert "share" not in out, out
    assert "jobs.json" in out, out


def test_quote_wrapped_unc_path_is_reduced_to_basename():
    entry = r"cron store '\\server\share\jobs.json' exceeded the 5MB cap"
    out = _sarif_limit_hit_text(entry)
    assert "server" not in out, out
    assert "'jobs.json'" in out, out


def test_paren_wrapped_unc_path_is_reduced_to_basename():
    entry = r"custom workspace 'w' resolves outside the audited --home (\\server\share\ws)"
    out = _sarif_limit_hit_text(entry)
    assert "server" not in out, out
    assert "ws)" in out, out


# --------------------------------------------------------------------------------
# 5. Ordinary prose must still be left alone (no regression on B-633's own
#    adversarial case, re-pinned here against the WIDER regex).
# --------------------------------------------------------------------------------

def test_ordinary_slash_prose_is_still_untouched():
    entry = "bootstrap/skills read from there are outside the scoped audit"
    assert _sarif_limit_hit_text(entry) == entry


# --------------------------------------------------------------------------------
# 6. Collector-level: the bare `{db_path}` producer cluster (item 2 of the review)
#    now quotes db_path like every sibling producer -- proven end to end through
#    render_sarif with a home directory that itself contains a space.
# --------------------------------------------------------------------------------

def _home_with_oversized_plugin_index(tmp_path: Path) -> "tuple[Context, Path]":
    home = tmp_path / SENSITIVE / "home"
    state = home / "state"
    state.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    db_path = state / "openclaw.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE config_machine_state "
            "(state_key TEXT PRIMARY KEY, value_json TEXT, updated_at_ms INTEGER)"
        )
        padding = "x" * (_MAX_PLUGIN_TRUST_BYTES + 1000)
        raw = (
            '{"index": {"installRecords": {}, "plugins": []}, "revision": 1, "pad": "'
            + padding + '"}'
        )
        assert len(raw) > _MAX_PLUGIN_TRUST_BYTES
        conn.execute(
            "INSERT INTO config_machine_state VALUES (?,?,?)",
            ("plugins.installedIndex", raw, 0),
        )
        conn.commit()
    finally:
        conn.close()
    ctx = Context(home=home)
    _collect_plugin_trust(home, ctx)
    return ctx, db_path


def test_plugin_trust_cap_message_quotes_db_path(tmp_path):
    """Pins the collector.py source fix directly: revert the quoting on any of the
    `_collect_plugin_trust` `note_limit` calls and this goes red.

    ctx.limit_hits stays verbatim (B-617 invariant), so the sensitive segment IS
    present here -- the point of this test is that the FULL path is now wrapped in a
    single quote on both sides, the same convention every sibling producer in
    collector.py already uses (and the exact shape `sarif._NON_HOME_ABS_PATH_RE`'s new
    quote-delimited alternative depends on)."""
    ctx, db_path = _home_with_oversized_plugin_index(tmp_path)
    hits = limit_hits_for(ctx, LIMIT_DOMAIN_PLUGIN)
    assert any("exceeded the" in h and "cap" in h for h in hits), hits
    assert any(f"'{db_path}'" in h for h in hits), hits


def test_plugin_trust_cap_message_does_not_leak_via_sarif(tmp_path):
    """End to end: BOTH fixes together (quoting at the source + delimiter-aware
    reduction in sarif.py) keep the sensitive path segment out of the SARIF copy,
    while ctx.limit_hits itself stays untouched."""
    ctx, _db_path = _home_with_oversized_plugin_index(tmp_path)
    before = list(ctx.limit_hits)

    doc = json.loads(render_sarif([], ctx=ctx))
    sarif_hits = doc["runs"][0]["properties"]["analysis_completeness"]["limit_hits"]

    assert any("exceeded the" in h and "cap" in h for h in sarif_hits), sarif_hits
    for h in sarif_hits:
        assert SENSITIVE not in h, h

    # Non-mutation of the stored, verbatim copy.
    assert ctx.limit_hits == before
    assert any(SENSITIVE in h for h in ctx.limit_hits), ctx.limit_hits
