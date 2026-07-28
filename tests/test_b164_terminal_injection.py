"""B-164 — attacker-controlled config strings must not carry terminal-control
sequences into the human report.

``report._sanitize`` strips ANSI/OSC/CSI, C0 controls and bidi from untrusted data,
but the capability-graph and credential-surface renderers interpolated MCP server
names / tool names raw — so a server keyed with an OSC window-title set or a CSI
erase-line sequence reached stdout (and a ``--save`` file) verbatim, enabling
terminal spoofing / prior-output erasure. Both surfaces render on the DEFAULT run
(no ``--full``). Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import Finding
from clawseccheck.cli import main
from clawseccheck.collector import Context
from clawseccheck.report import (
    _capability_graph_lines,
    _credential_surface_lines,
    render_report,
)
from clawseccheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE_HOME = str(FIXTURES / "home_safe")

# A real terminal-spoofing primitive: OSC-0 window-title set (ESC ] 0 ; ... BEL),
# then CSI erase-line / cursor-up / erase-line to blank and overwrite prior output.
_ESC = "\x1b"
_BEL = "\x07"
_EVIL_NAME = "legit-tool" + _ESC + "]0;PWNED" + _BEL + _ESC + "[2K" + _ESC + "[1A" + "evil"
_EVIL_TOOL = "do_thing" + _ESC + "[31m" + _ESC + "]52;c;BASE64" + _BEL  # incl. OSC-52 clipboard


def _evil_ctx() -> Context:
    c = Context(home=Path("/nonexistent"))
    # tokenPassthrough puts the name on the credential-surface map too; tools[].name and
    # the server key both flow into the capability graph.
    c.config = {"mcp": {"servers": {_EVIL_NAME: {
        "url": "https://x.example.com",
        "tokenPassthrough": True,
        "tools": [{"name": _EVIL_TOOL}],
    }}}}
    return c


def _assert_no_control(text: str) -> None:
    assert _ESC not in text, "raw ESC sequence reached output"
    assert _BEL not in text, "raw BEL reached output"


def test_capability_graph_lines_strip_terminal_escapes():
    lines = _capability_graph_lines(_evil_ctx())
    assert lines, "expected a capability graph for a config with an MCP server"
    joined = "\n".join(lines)
    _assert_no_control(joined)
    assert "legit-tool" in joined, "visible label text must survive sanitization"


def test_credential_surface_lines_strip_terminal_escapes():
    lines = _credential_surface_lines(_evil_ctx())
    _assert_no_control("\n".join(lines))


def test_render_report_default_run_has_no_raw_escapes():
    ctx = _evil_ctx()
    out = render_report([], compute([]), ctx=ctx)  # default run: no --full, color off
    _assert_no_control(out)
    assert "legit-tool" in out, "the MCP node should still be visible, just neutralised"


# ---------------------------------------------------------------------------
# B-350 — cli.py's `--full` vet-mcp UNKNOWN-summary line: the quiet path
# (`_emit(f"VET-MCP: {_sanitize(vm_findings[0].detail)}")`) already sanitized
# vmf.detail; the verbose/loud path printed the same detail raw
# (`_emit(f"{vm_icon} {vmf.detail}")`). Not exploitable today (vet_mcp's own
# UNKNOWN detail is engine-authored), but the two paths must sanitize the same
# way regardless of who eventually feeds Finding.detail. Pin both.
# ---------------------------------------------------------------------------

_EVIL_VMF_DETAIL = (
    "MCP unreachable" + _ESC + "]0;PWNED" + _BEL + _ESC + "[2K" + _ESC + "[1A" + "evil"
)


def _evil_vet_mcp(*_args, **_kwargs):
    return [Finding(
        id="B-TEST", title="unreachable", severity="LOW", status="UNKNOWN",
        detail=_EVIL_VMF_DETAIL, fix="n/a", framework="test",
    )]


def test_full_verbose_vet_mcp_unknown_detail_is_sanitized(monkeypatch, capsys):
    monkeypatch.setattr("clawseccheck.cli.vet_mcp", _evil_vet_mcp)
    main(["--home", SAFE_HOME, "--no-native", "--no-history", "--full"])
    out = capsys.readouterr().out
    _assert_no_control(out)
    assert "MCP unreachable" in out, "visible detail text must survive sanitization"


def test_full_quiet_vet_mcp_unknown_detail_is_sanitized(monkeypatch, capsys):
    monkeypatch.setattr("clawseccheck.cli.vet_mcp", _evil_vet_mcp)
    main(["--home", SAFE_HOME, "--no-native", "--no-history", "--full", "--quiet"])
    out = capsys.readouterr().out
    _assert_no_control(out)
    assert "MCP unreachable" in out, "visible detail text must survive sanitization"


def test_full_verbose_and_quiet_vet_mcp_unknown_detail_match_sanitization(monkeypatch, capsys):
    # Both paths must strip the exact same control sequences from the exact same
    # detail string — pins that the loud path uses the same sanitizer as quiet,
    # not merely "some" sanitizer.
    from clawseccheck.report import _sanitize
    expected = _sanitize(_EVIL_VMF_DETAIL)

    monkeypatch.setattr("clawseccheck.cli.vet_mcp", _evil_vet_mcp)
    main(["--home", SAFE_HOME, "--no-native", "--no-history", "--full"])
    verbose = capsys.readouterr().out
    main(["--home", SAFE_HOME, "--no-native", "--no-history", "--full", "--quiet"])
    quiet = capsys.readouterr().out

    assert expected in verbose
    assert expected in quiet
