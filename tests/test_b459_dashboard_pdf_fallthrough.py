"""B-459 second half — `--dashboard --pdf` must not discard the audit on a failed write.

The first half of this task (commit `1c4b083`) fixed the deferred `--dashboard --full --pdf`
branch and the missing-parent-directory case. Three independent review passes then found the
same unfixed sibling: the NON-deferred branch — plain `--dashboard --pdf`, the exact pair the
guided flow documents — still did `except OSError: return 1`, so a write failure threw away
the analysis. Reproduced before this fix at rc=1 with 59 bytes of stdout: no card, no
headline, no findings.

The two compositions this branch serves want opposite answers, and both are pinned here:

* bare `--pdf <path>` — the artifact IS the deliverable, so a failed write is a failed run
  and exit 1 is the deliberate contract (`tests/test_cli_exit_codes.py` owns it too);
* `--dashboard --pdf <path>` — the dashboard is the deliverable and the PDF is its delivery,
  so the run must fall through and render.
"""

import contextlib
import io
import json
import pathlib
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from clawseccheck import cli  # noqa: E402


def _home(tmp_path: pathlib.Path) -> pathlib.Path:
    home = tmp_path / "home"
    (home / "workspace" / "skills").mkdir(parents=True)
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({
        "meta": {"lastTouchedVersion": "2026.7.1"},
        "gateway": {"bind": "127.0.0.1:8080",
                    "auth": {"mode": "token", "token": "a-very-long-token-of-32-chars!!"}},
        "tools": {"profile": "minimal", "exec": {"mode": "ask"}},
    }), encoding="utf-8")
    cfg.chmod(0o600)
    return home


def _run(tmp_path, extra, *, failing_writer=True, writer="secure_write_bytes"):
    """Run the real CLI with a report writer forced to fail.

    The failure is forced through the WRITER, never through filesystem permissions: root
    ignores mode bits, so a chmod-based test would pass for the wrong reason wherever the
    suite runs as root. Same discipline as tests/test_b459_report_dest.py.

    *writer* matters and is not boilerplate: the PDF goes through `secure_write_bytes` while
    `--html` / `--sarif` / `--save` / `--badge` go through `secure_write_text`. The first
    draft of this file patched only the bytes writer and asserted an exit code for the text
    flags — so those runs never failed at all, succeeded normally, and the assertion was
    measuring nothing. A test that cannot fail for the reason it names is worse than absent.

    Returns ``(rc, stdout, stderr)`` — C-449 moved the standalone `(could not write ...)`
    diagnostics to stderr, so a caller that only cares about the artifact stream still reads
    ``out`` and a caller checking the diagnostic itself now reads ``err``.
    """
    home = _home(tmp_path)
    argv = list(extra) + ["--home", str(home),
                          "--data-dir", str(tmp_path / "data"),
                          "--no-history", "--ascii"]
    out_buf, err_buf = io.StringIO(), io.StringIO()
    ctx = (mock.patch.object(cli, writer, side_effect=OSError("disk on fire"))
           if failing_writer else contextlib.nullcontext())
    with ctx:
        with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
            rc = cli.main(argv)
    return rc, out_buf.getvalue(), err_buf.getvalue()


def test_dashboard_pdf_renders_the_audit_when_the_write_fails(tmp_path):
    """The defect itself: the user loses the audit because a file could not be written."""
    out_pdf = tmp_path / "out" / "r.pdf"
    rc, out, _err = _run(tmp_path, ["--dashboard", "--pdf", str(out_pdf)])
    assert rc == 0, "a failed delivery must not fail the run that produced the analysis"
    # `--dashboard --pdf`'s inline-substitution note is B-459's, deliberately left on
    # stdout (C-449 did not touch this branch — see its own comment in cli.py).
    assert "could not write PDF report" in out
    assert "showing the full report inline" in out
    # The audit itself, not just an apology. Pre-fix this was 59 bytes.
    assert "ClawSecCheck" in out
    assert "Inventory by subject" in out
    assert len(out) > 800, f"audit looks truncated: {len(out)} bytes"


def test_bare_pdf_still_exits_nonzero_when_the_write_fails(tmp_path):
    """The contract that must NOT change. With no dashboard asked for, the PDF is the whole
    deliverable — a run that produced nothing the user asked for has failed, and callers
    scripting `--pdf out.pdf || handle` depend on that.

    C-449: bare `--pdf`'s diagnostic moved to stderr (matching the success note and the
    other standalone artifact flags below) — stdout must stay clean of it.
    """
    out_pdf = tmp_path / "out" / "r.pdf"
    rc, out, err = _run(tmp_path, ["--pdf", str(out_pdf)])
    assert rc == 1
    assert "could not write PDF report" not in out
    assert "could not write PDF report" in err
    assert "showing the full report inline" not in err


def test_a_rider_says_nothing_about_a_pdf_that_was_never_written(tmp_path):
    """Found while writing this fix, not by the reviewers.

    With `--dashboard --pdf --trend` the rider branch emits an attach instruction and, under
    `--full`, a note reading "The report states this on its own first page". Falling through
    on a failed write carried execution into that block with no file on disk, so the tool
    would describe a document that does not exist — the same class of untrue statement about
    an artifact that this task exists to close. `_emit_attach_instruction` already no-ops on
    None; the note did not.
    """
    out_pdf = tmp_path / "out" / "r.pdf"
    rc, out, _err = _run(tmp_path, ["--dashboard", "--pdf", str(out_pdf), "--trend", "--full"])
    assert rc == 0
    assert "carries the findings only" not in out
    assert "states this on its own first page" not in out
    assert str(out_pdf) not in out, "named a file that was never written"


def test_the_successful_path_is_unchanged(tmp_path):
    """A guard against fixing the failure case by breaking the success case."""
    out_pdf = tmp_path / "out" / "r.pdf"
    rc, out, err = _run(tmp_path, ["--dashboard", "--pdf", str(out_pdf)], failing_writer=False)
    assert rc == 0
    assert out_pdf.exists() and out_pdf.stat().st_size > 0
    assert "could not write PDF report" not in out
    assert "could not write PDF report" not in err


@pytest.mark.parametrize("flag", ["--html", "--sarif", "--save", "--badge"])
def test_other_standalone_artifact_flags_keep_their_exit_contract(tmp_path, flag):
    """Scope guard: this change touched only the PDF branch's discrimination. The other
    artifact flags are the deliverable when asked for alone, and a failed write there is
    still a failed run.

    Patched at `secure_write_text` — these four do not go through the bytes writer the PDF
    uses, and patching the wrong one makes this assertion vacuous rather than red.

    C-449: `--save`'s diagnostic is untouched (still stdout, out of this task's scope); the
    other three moved to stderr, matching bare `--pdf` above. Checking the union of both
    streams keeps this one assertion valid for all four without hard-coding which stream
    each uses — that split is pinned precisely by C-449's own tests instead.
    """
    dest = tmp_path / "out" / "artifact"
    rc, out, err = _run(tmp_path, [flag, str(dest)], writer="secure_write_text")
    assert rc == 1
    assert "could not" in (out + err).lower(), \
        "a failed write must say so, not just exit nonzero"
