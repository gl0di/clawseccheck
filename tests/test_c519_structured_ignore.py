"""CLAWSECCHECK-C-519 — structured `.clawseccheckignore` entries.

The headline finding: the OLD `load_ignore()` never split a trailing `#` comment off
an entry line (`if line and not line.startswith("#"): entries.add(line)` added the
WHOLE line, comment included), so `docs/USAGE.md`'s own shipped example —
``B14            # accept the egress-surface advisory`` verbatim — produced the entry
``"B14            # accept the egress-surface advisory"``, which matches no
`Finding.id` or fingerprint ever and silently suppressed nothing. This file first
pins that bug is fixed, then covers the new optional `author=`/`date=`/`expires=`
fields it made possible: structured attribution, auto-expiry, and
`--show-suppressed` disclosure -- all built on the SAME `load_ignore()` set every
existing consumer (`apply()`, `dead_entries()`, `risk.risk_paths(..., ignore=...)`)
already used, so no second/competing suppression mechanism was added.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

from clawseccheck import audit
from clawseccheck.baseline import (
    IgnoreEntry,
    _parse_ignore_line,
    apply,
    load_ignore,
    load_ignore_entries,
)
from clawseccheck.catalog import CRITICAL, FAIL
from clawseccheck.cli import main
from clawseccheck.report import render_report
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = str(FIXTURES / "home_vuln")

_YESTERDAY = (date.today() - timedelta(days=1)).isoformat()
_TOMORROW = (date.today() + timedelta(days=365)).isoformat()


def _run(capsys, *argv):
    code = main(list(argv))
    cap = capsys.readouterr()
    return code, cap.out, cap.err


# --------------------------------------------------------------------------------------
# _parse_ignore_line — the parser itself
# --------------------------------------------------------------------------------------

def test_parse_line_with_no_comment_at_all():
    e = _parse_ignore_line("B14")
    assert e == IgnoreEntry(entry="B14", author=None, date=None, expires=None,
                             reason=None, expired=False)


def test_parse_line_with_plain_comment_no_structured_fields():
    e = _parse_ignore_line("B14            # accept the egress-surface advisory")
    assert e.entry == "B14"
    assert e.author is None and e.date is None and e.expires is None
    assert e.reason == "accept the egress-surface advisory"
    assert e.expired is False


def test_parse_line_with_all_structured_fields():
    e = _parse_ignore_line(
        "B12:1a2b3c4d   # author=dave date=2026-09-10 expires=2026-12-10 accept it"
    )
    assert e.entry == "B12:1a2b3c4d"
    assert e.author == "dave"
    assert e.date == "2026-09-10"
    assert e.expires == "2026-12-10"
    assert e.reason == "accept it"


def test_parse_line_structured_fields_in_any_order_and_leftover_text_is_reason():
    e = _parse_ignore_line("B2  # expires=2026-12-10 accept it author=dave")
    assert e.author == "dave"
    assert e.expires == "2026-12-10"
    assert e.reason == "accept it"


def test_parse_line_structured_fields_only_no_leftover_reason():
    e = _parse_ignore_line("B2  # author=dave date=2026-09-10")
    assert e.reason is None


def test_parse_line_blank_returns_none():
    assert _parse_ignore_line("") is None
    assert _parse_ignore_line("   ") is None


def test_parse_line_full_line_comment_returns_none():
    assert _parse_ignore_line("# just a note, no entry") is None


def test_parse_line_whitespace_then_bare_hash_returns_none():
    assert _parse_ignore_line("   # trailing note only") is None


def test_parse_line_expires_in_the_past_is_expired():
    e = _parse_ignore_line(f"B2  # expires={_YESTERDAY}")
    assert e.expired is True


def test_parse_line_expires_in_the_future_is_not_expired():
    e = _parse_ignore_line(f"B2  # expires={_TOMORROW}")
    assert e.expired is False


def test_parse_line_unparseable_expires_is_not_treated_as_expired():
    """An unparseable expires= is disclosed via the raw string (still visible in
    --show-suppressed) rather than guessed either way -- never silently drops a
    suppression on a typo, never keeps one alive forever either."""
    e = _parse_ignore_line("B2  # expires=not-a-date")
    assert e.expires == "not-a-date"
    assert e.expired is False


def test_parse_line_entry_blank_after_stripping_comment_returns_none():
    assert _parse_ignore_line("   # only a comment, nothing before it") is None


# --------------------------------------------------------------------------------------
# load_ignore_entries / load_ignore
# --------------------------------------------------------------------------------------

def test_load_ignore_strips_trailing_comment_the_original_bug(tmp_path):
    """The exact line docs/USAGE.md ships, verbatim -- must now suppress B14 and
    ONLY B14, not the whole raw line with its comment attached."""
    (tmp_path / ".clawseccheckignore").write_text(
        "B14            # accept the egress-surface advisory\n"
    )
    assert load_ignore(tmp_path) == {"B14"}


def test_load_ignore_entries_includes_expired_load_ignore_excludes_them(tmp_path):
    (tmp_path / ".clawseccheckignore").write_text(
        f"B14\nB2:ab12cd34   # expires={_YESTERDAY}\nB7\n"
    )
    entries = load_ignore_entries(tmp_path)
    assert {e.entry for e in entries} == {"B14", "B2:ab12cd34", "B7"}
    assert [e.expired for e in entries if e.entry == "B2:ab12cd34"] == [True]
    # Auto-expiry falls out of load_ignore()'s filter for free -- no separate
    # expiry-aware code path needed in apply()/dead_entries()/risk.risk_paths().
    assert load_ignore(tmp_path) == {"B14", "B7"}


def test_load_ignore_entries_empty_for_missing_file(tmp_path):
    assert load_ignore_entries(tmp_path / "nope") == []


def test_load_ignore_backward_compat_legacy_file_no_comments(tmp_path):
    """A pre-C-519 file with bare ids/fingerprints and no comments at all must behave
    identically to before: every line is one active entry."""
    (tmp_path / ".clawseccheckignore").write_text("# comment\n\nB14\nB2:ab12cd34\n  B7  \n")
    assert load_ignore(tmp_path) == {"B14", "B2:ab12cd34", "B7"}


def test_load_ignore_future_expires_still_suppresses(tmp_path):
    (tmp_path / ".clawseccheckignore").write_text(f"B14  # expires={_TOMORROW}\n")
    assert load_ignore(tmp_path) == {"B14"}


# --------------------------------------------------------------------------------------
# End to end: an expired entry stops suppressing
# --------------------------------------------------------------------------------------

def test_expired_entry_no_longer_suppresses_in_a_real_audit(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}")
    _, findings, _ = audit(tmp_path)
    from clawseccheck.catalog import WARN
    target = next(f for f in findings if f.status == WARN)
    (tmp_path / ".clawseccheckignore").write_text(
        f"{target.id}  # expires={_YESTERDAY}\n"
    )
    _, findings2, _ = audit(tmp_path)
    reaudited = next(f for f in findings2 if f.id == target.id)
    assert not reaudited.suppressed, (
        "an expired ignore entry must not suppress -- the whole point of "
        "expires= is that it stops applying once the date passes"
    )


def test_unexpired_structured_entry_still_suppresses_in_a_real_audit(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}")
    _, findings, _ = audit(tmp_path)
    from clawseccheck.catalog import WARN
    target = next(f for f in findings if f.status == WARN)
    (tmp_path / ".clawseccheckignore").write_text(
        f"{target.id}  # author=dave date=2026-09-10 expires={_TOMORROW} reviewed\n"
    )
    _, findings2, _ = audit(tmp_path)
    assert next(f for f in findings2 if f.id == target.id).suppressed


# --------------------------------------------------------------------------------------
# Regression: structured metadata changes nothing about the CRITICAL/HIGH-still-counts
# invariant -- no second/competing suppression mechanism was introduced.
# --------------------------------------------------------------------------------------

def test_structured_entry_suppressing_critical_still_caps_score_and_warns(tmp_path):
    """End to end through the REAL .clawseccheckignore file + apply() + compute() +
    render_report() -- not the synthetic Finding construction test_baseline.py's
    equivalent test uses -- to prove a structured comment doesn't change the
    score-capping/WARNING behavior for a suppressed CRITICAL FAIL."""
    _, findings, _ = audit(VULN, include_native=False, include_host=False,
                            include_sockets=False, include_deptree=False,
                            include_dist=False)
    b2 = next(f for f in findings if f.id == "B2")
    assert b2.severity == CRITICAL and b2.status == FAIL
    (tmp_path / ".clawseccheckignore").write_text(
        f"B2  # author=dave date=2026-09-10 expires={_TOMORROW} reviewed and accepted\n"
    )
    parsed_ignore = load_ignore(tmp_path)
    assert parsed_ignore == {"B2"}
    apply(findings, parsed_ignore)
    assert b2.suppressed
    out = render_report(findings, compute(findings))
    assert "WARNING: a CRITICAL finding (B2) is suppressed" in out
    assert compute(findings).score <= 49


# --------------------------------------------------------------------------------------
# CLI: --show-suppressed attribution + expired-entries disclosure
# --------------------------------------------------------------------------------------

def _home_with_ignore(tmp_path: Path, ignore_text: str) -> str:
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text(json.dumps({"gateway": {"bind": "0.0.0.0"}}),
                                         encoding="utf-8")
    (home / ".clawseccheckignore").write_text(ignore_text, encoding="utf-8")
    return str(home)


def test_show_suppressed_annotates_structured_entry(tmp_path, capsys):
    home = _home_with_ignore(tmp_path, "B2  # author=dave date=2026-09-10 reviewed\n")
    _, out, _ = _run(capsys, "--show-suppressed", "--home", home)
    assert "author=dave" in out
    assert "date=2026-09-10" in out


def test_show_suppressed_marks_legacy_entry_unattributed(tmp_path, capsys):
    home = _home_with_ignore(tmp_path, "B2\n")
    _, out, _ = _run(capsys, "--show-suppressed", "--home", home)
    assert "[unattributed]" in out


def test_show_suppressed_plain_comment_with_no_fields_is_unattributed(tmp_path, capsys):
    home = _home_with_ignore(tmp_path, "B2  # accept the egress-surface advisory\n")
    _, out, _ = _run(capsys, "--show-suppressed", "--home", home)
    assert "[unattributed]" in out


def test_show_suppressed_lists_expired_entries_separately(tmp_path, capsys):
    home = _home_with_ignore(tmp_path, f"B2  # expires={_YESTERDAY}\n")
    _, out, _ = _run(capsys, "--show-suppressed", "--home", home)
    assert "expired ignore(s) no longer applied" in out
    assert f"expired {_YESTERDAY}" in out
    # An expired entry is neither "suppressed in this run" nor "match nothing" (dead) --
    # it gets its own, distinct disclosure so the reader knows exactly why it's not
    # suppressing rather than reading it as fixed or fingerprint-drifted.
    assert "match nothing in this run" not in out


def test_show_suppressed_no_expired_section_when_none_are_expired(tmp_path, capsys):
    home = _home_with_ignore(tmp_path, "B2\n")
    _, out, _ = _run(capsys, "--show-suppressed", "--home", home)
    assert "expired ignore(s)" not in out
