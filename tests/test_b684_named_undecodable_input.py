"""B-684: a file the user picked is not a defect in this tool.

    $ audit.py --judged report.pdf          # a file --pdf wrote
    clawseccheck: unexpected internal error (UnicodeDecodeError); re-run with --debug …
    open an issue: https://github.com/gl0di/clawseccheck/issues

Two halves, and only one of them was wrong.

**The loudness is correct and stays.** B-561 considered exactly this input and decided both
undecodable shapes must keep `rc 1`, empty stdout and no artifact rather than degrade to the
`note:` an OSError gets — because a note ends in `rc 0` and a full report, handing back a
normal-looking result to someone who named the wrong file. This task was originally filed
prescribing that degradation and had to be retracted: the fix it asked for had already been
implemented once and removed on reasoning.

**The anonymity was the defect**, and B-561 said so itself: *"Naming the path in them is a
separate improvement to the crash handler, not this one."* The failure named no file, gave no
reason beyond an exception class, and asked for a bug report about the caller's own typo.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawseccheck.cli import UnusableInputPath, main  # noqa: E402

_FLAGS = ["--judged", "--propose-ignore"]


def _base(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    return ["--home", str(home), "--data-dir", str(tmp_path / "data")]


def _binary(tmp_path):
    """Bytes that are not valid UTF-8 in any encoding the reader would accept."""
    p = tmp_path / "report.pdf"
    p.write_bytes(b"%PDF-1.4\n\xff\xfe\x00\x01binary junk\n%%EOF\n")
    return p


@pytest.mark.parametrize("flag", _FLAGS)
def test_an_undecodable_file_is_named_not_bug_reported(tmp_path, capsys, flag):
    rc = main([flag, str(_binary(tmp_path)), *_base(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out.strip() == ""
    assert "report.pdf" in captured.err
    assert "not valid UTF-8" in captured.err
    # The half that was wrong.
    assert "unexpected internal error" not in captured.err
    assert "open an issue" not in captured.err


@pytest.mark.parametrize("flag", _FLAGS)
def test_a_tilde_user_that_does_not_exist_gets_the_same_treatment(tmp_path, capsys, flag):
    """`expanduser()` raises RuntimeError, not OSError — the second shape B-561 names."""
    rc = main([flag, "~nosuchuser999/x.json", *_base(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 1
    assert captured.out.strip() == ""
    assert "names no account" in captured.err
    assert "open an issue" not in captured.err


@pytest.mark.parametrize("flag", _FLAGS)
def test_the_failure_is_still_loud(tmp_path, capsys, flag):
    """The half B-561 protects, pinned separately from the wording.

    If a later change routes these through the `note:` path, this fails: a note ends in
    rc 0 and a full report on stdout, which is the degradation B-561 removed. Wording is
    cosmetic; this is the contract.
    """
    rc = main([flag, str(_binary(tmp_path)), *_base(tmp_path)])
    captured = capsys.readouterr()
    assert rc != 0
    assert captured.out.strip() == ""


@pytest.mark.parametrize("flag", _FLAGS)
def test_a_readable_file_that_is_not_json_still_gets_the_quiet_note(tmp_path, capsys, flag):
    """The control, and the boundary this fix must not cross.

    An unparseable-but-readable payload is a STATEMENT from the judge that yields nothing;
    a file that cannot be decoded is the ABSENCE of a statement. B-561 draws that line and
    this fix stays on its own side of it: the note path keeps rc 0 and its report.
    """
    notes = tmp_path / "notes.txt"
    notes.write_text("hello, not json\n", encoding="utf-8")
    rc = main([flag, str(notes), *_base(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "not valid JSON" in captured.err
    assert "unexpected internal error" not in captured.err


@pytest.mark.parametrize("flag", _FLAGS)
def test_an_unopenable_path_still_gets_its_note(tmp_path, capsys, flag):
    """The OSError family is untouched — B-561's own scope, still `note:` + rc 0."""
    rc = main([flag, str(tmp_path / "gone.json"), *_base(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "no such file or directory" in captured.err


def test_the_path_is_redacted():
    """B-581: this text reaches stderr unconditionally and a typed path routinely carries
    the operator's OS username, so it is composed through `_redact_home_paths` like every
    sibling diagnostic.

    Asserted on the composer rather than through a run, because `_redact_home_paths` is a
    PATTERN over `/home/<user>` / `/Users/<user>` / `C:\\Users\\<user>` — not a lookup of
    `$HOME`. A test that redirects `HOME` to a `tmp_path` proves nothing: the redirected
    path is not home-shaped, so nothing matches and the assertion passes or fails for the
    wrong reason. (Verified against a real run too, where the message read
    `clawseccheck: ~/.cache/…/bin.pdf: not valid UTF-8 text …`.)
    """
    exc = UnusableInputPath("/home/someone/report.pdf", "not valid UTF-8 text")
    assert exc.text == "~/report.pdf: not valid UTF-8 text"
    assert "someone" not in exc.text


def test_the_exception_carries_its_composed_text():
    """The handler prints `exc.text` rather than re-deriving it, so a second reader cannot
    word the same failure differently."""
    exc = UnusableInputPath("/x/y.json", "not valid UTF-8 text")
    assert exc.text == "/x/y.json: not valid UTF-8 text"
    assert exc.raw_path == "/x/y.json"
