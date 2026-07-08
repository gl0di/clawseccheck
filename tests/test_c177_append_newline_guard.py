"""C-177 (secondary) — secure_append_text must not merge onto a dangling line.

Root cause: a crash/power-loss mid-write can leave a JSONL journal (history.jsonl,
events.jsonl) truncated WITHOUT a trailing newline. The next secure_append_text()
call used to blindly append, silently concatenating the new line onto the
truncated one with no separator — turning one recoverable truncated record into
a permanent unparseable merged line (not cleaned up by rotation either, since it
also just skips lines it can't json.loads()).

secure_append_text() now checks whether the file already ends in a newline and
inserts one first if not. Offline, stdlib only, tmp_path sandbox.
"""
from __future__ import annotations

from clawseccheck.safeio import secure_append_text


def test_append_after_truncated_no_trailing_newline_inserts_separator(tmp_path):
    p = tmp_path / "journal.jsonl"
    p.write_bytes(b'{"a":1}\n{"b":2')  # simulated crash mid-write: no trailing \n
    secure_append_text(p, '{"c":3}\n')
    lines = p.read_text().splitlines()
    assert lines == ['{"a":1}', '{"b":2', '{"c":3}']


def test_append_after_normal_trailing_newline_no_extra_blank_line(tmp_path):
    p = tmp_path / "journal.jsonl"
    p.write_bytes(b'{"a":1}\n')
    secure_append_text(p, '{"b":2}\n')
    assert p.read_text() == '{"a":1}\n{"b":2}\n'


def test_append_to_nonexistent_file_creates_it_cleanly(tmp_path):
    p = tmp_path / "journal.jsonl"
    secure_append_text(p, '{"a":1}\n')
    assert p.read_text() == '{"a":1}\n'


def test_append_to_empty_file_no_leading_blank_line(tmp_path):
    p = tmp_path / "journal.jsonl"
    p.write_bytes(b"")
    secure_append_text(p, '{"a":1}\n')
    assert p.read_text() == '{"a":1}\n'
