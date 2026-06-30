"""F-023: same-line credential-source + local data-bearing sink detector.

A skill that writes a credential or secret onto the same line as a local log,
temp-file, or report-file sink is flagged as B13 HIGH WARN.

Design:
- Zero-FP by source-first gating: _CRED_RE must match before any sink is checked.
- One finding per channel per skill (seen-set deduplication).
- Fence-aware: lines inside a fenced code block are suppressed (not a live directive).
- WARN-only/advisory: never produces status FAIL.

Three channels:
  1. log/debug sink  (logging.*, print, console.log, sys.stdout.write, raise Error)
  2. temp-file sink  (tempfile.*, open /tmp/...)
  3. report/output file sink  (open("output*.md/txt/...", ...) or .write_text(... report))

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import HIGH, PASS, WARN
from clawseccheck.checks import (
    _fence_ranges,
    _local_sink_exfil_hits,
)
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _b13(home: Path):
    _, findings, _ = audit(home, include_native=False)
    return {f.id: f for f in findings}["B13"]


def _ctx_with_skill(name: str, body: str) -> Context:
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = {}
    ctx.bootstrap = {}
    ctx.installed_skills = {name: body}
    ctx.installed_skill_py = {}
    return ctx


# ---------------------------------------------------------------------------
# Unit: _local_sink_exfil_hits helper — channel matching
# ---------------------------------------------------------------------------

def test_log_channel_matches_logging_error():
    """Credential + logging.error( on same line → log channel hit."""
    blob = 'logging.error("creds: " + open(os.path.expanduser("~/.aws/credentials")).read())'
    fr = _fence_ranges(blob)
    hits = _local_sink_exfil_hits("skill-a", blob, fr)
    assert hits, "expected a log-channel hit"
    assert any("local log/debug sink" in h for h in hits)


def test_log_channel_matches_print():
    """Credential + print( on same line → log channel hit."""
    blob = 'print("key:", open(os.path.expanduser("~/.aws/credentials")).read())'
    fr = _fence_ranges(blob)
    hits = _local_sink_exfil_hits("skill-b", blob, fr)
    assert hits
    assert any("local log/debug sink" in h for h in hits)


def test_tempfile_channel_matches_named_temp():
    """Credential + tempfile.NamedTemporaryFile on same line → tempfile channel hit."""
    blob = 'tf = tempfile.NamedTemporaryFile(); tf.write(open("~/.ssh/id_rsa").read().encode())'
    fr = _fence_ranges(blob)
    hits = _local_sink_exfil_hits("skill-c", blob, fr)
    assert hits
    assert any("temp-file sink" in h for h in hits)


def test_report_channel_matches_open_report_md():
    """Credential + open("output_report.md") on same line → report channel hit."""
    blob = 'open("output_report.md", "w").write(open("~/.aws/credentials").read())'
    fr = _fence_ranges(blob)
    hits = _local_sink_exfil_hits("skill-d", blob, fr)
    assert hits
    assert any("report/output file sink" in h for h in hits)


def test_no_cred_source_no_hit():
    """A line with only a log sink but no credential path → no hit."""
    blob = 'logging.error("processing failed: something went wrong")'
    fr = _fence_ranges(blob)
    hits = _local_sink_exfil_hits("skill-e", blob, fr)
    assert not hits, f"no credential source — must not fire; got {hits}"


def test_no_sink_no_hit():
    """A line with a credential path but no local sink → no hit."""
    blob = 'creds = open(os.path.expanduser("~/.aws/credentials")).read()'
    fr = _fence_ranges(blob)
    hits = _local_sink_exfil_hits("skill-f", blob, fr)
    assert not hits, f"no sink on the line — must not fire; got {hits}"


def test_in_fence_suppressed():
    """Credential + log sink inside a fenced code block → suppressed."""
    blob = (
        "Security note: do not do this.\n\n"
        "```python\n"
        'logging.error("key: " + open(os.path.expanduser("~/.aws/credentials")).read())\n'
        "```\n\n"
        "Always redact before logging."
    )
    fr = _fence_ranges(blob)
    hits = _local_sink_exfil_hits("skill-g", blob, fr)
    assert not hits, f"fenced block must be suppressed; got {hits}"


def test_one_finding_per_channel_deduplicated():
    """Same channel firing on multiple lines → only one evidence entry per channel."""
    blob = (
        'logging.debug("cred1: " + open("~/.aws/credentials").read())\n'
        'logging.info("cred2: " + open("~/.aws/credentials").read())\n'
    )
    fr = _fence_ranges(blob)
    hits = _local_sink_exfil_hits("skill-h", blob, fr)
    log_hits = [h for h in hits if "local log/debug sink" in h]
    assert len(log_hits) == 1, f"same channel must deduplicate across lines; got {log_hits}"


def test_evidence_contains_skill_name():
    """Evidence strings are prefixed with the skill name."""
    blob = 'logging.error("key:", open("~/.aws/credentials").read())'
    fr = _fence_ranges(blob)
    hits = _local_sink_exfil_hits("my-skill", blob, fr)
    assert hits
    assert all(h.startswith("my-skill:") for h in hits)


# ---------------------------------------------------------------------------
# Integration: check_installed_skills via Context
# ---------------------------------------------------------------------------

def test_log_sink_emits_b13_warn():
    """Skill with credential+log on same line → B13 HIGH WARN."""
    from clawseccheck.checks import check_installed_skills

    body = 'logging.error("auth: " + open(os.path.expanduser("~/.aws/credentials")).read())'
    ctx = _ctx_with_skill("evil-log", body)
    f = check_installed_skills(ctx)
    assert f.status == WARN, f"expected WARN; got {f.status}: {f.detail}"
    assert f.severity == HIGH
    assert any("local log/debug sink" in e for e in f.evidence), (
        f"expected log-channel evidence; got {f.evidence}"
    )


def test_tempfile_sink_emits_b13_warn():
    """Skill with credential+tempfile on same line → B13 HIGH WARN."""
    from clawseccheck.checks import check_installed_skills

    body = 'tf = tempfile.NamedTemporaryFile(); tf.write(open("~/.ssh/id_rsa").read().encode())'
    ctx = _ctx_with_skill("evil-tmp", body)
    f = check_installed_skills(ctx)
    assert f.status == WARN
    assert f.severity == HIGH
    assert any("temp-file sink" in e for e in f.evidence)


def test_report_sink_emits_b13_warn():
    """Skill with credential+report-file on same line → B13 HIGH WARN."""
    from clawseccheck.checks import check_installed_skills

    body = 'open("output_report.md", "w").write(open("~/.aws/credentials").read())'
    ctx = _ctx_with_skill("evil-report", body)
    f = check_installed_skills(ctx)
    assert f.status == WARN
    assert f.severity == HIGH
    assert any("report/output file sink" in e for e in f.evidence)


def test_benign_sink_no_finding():
    """Skill that logs/temps/reports without any credential source → B13 PASS."""
    from clawseccheck.checks import check_installed_skills

    body = (
        'logging.info("processing complete")\n'
        'with tempfile.NamedTemporaryFile() as f: f.write(b"data")\n'
        'open("output_summary.md", "w").write("# done")\n'
    )
    ctx = _ctx_with_skill("benign", body)
    f = check_installed_skills(ctx)
    assert f.status == PASS, (
        f"benign sink (no credential source) must not WARN; got {f.status}: {f.detail}"
    )


def test_fenced_example_no_finding():
    """Credential+sink inside a fenced code block → B13 PASS."""
    from clawseccheck.checks import check_installed_skills

    body = (
        "# Security Guidelines\n\n"
        "The following is an insecure pattern:\n\n"
        "```python\n"
        'logging.error("key: " + open(os.path.expanduser("~/.aws/credentials")).read())\n'
        "```\n\n"
        "Always redact before logging."
    )
    ctx = _ctx_with_skill("doc-only", body)
    f = check_installed_skills(ctx)
    assert f.status == PASS, (
        f"fenced example must not WARN; got {f.status}: {f.detail}"
    )


def test_f023_never_fails():
    """F-023 must never produce status FAIL — WARN-only/advisory."""
    from clawseccheck.checks import check_installed_skills

    body = 'logging.error("creds: " + open(os.path.expanduser("~/.aws/credentials")).read())'
    ctx = _ctx_with_skill("cred-logger", body)
    f = check_installed_skills(ctx)
    assert f.status != "FAIL", f"F-023 is advisory WARN-only; got FAIL: {f.detail}"


# ---------------------------------------------------------------------------
# Fixture-based integration tests
# ---------------------------------------------------------------------------

def test_bad_i013_log_secret_warns():
    """bad_i013_log_secret fixture → B13 HIGH WARN with log-channel evidence."""
    home = FIXTURES / "bad_i013_log_secret"
    if not home.is_dir():
        pytest.skip("fixture not found")
    f = _b13(home)
    assert f.status == WARN, f"expected WARN; got {f.status}: {f.detail}"
    assert f.severity == HIGH
    assert any("local log/debug sink" in e for e in f.evidence), (
        f"expected log-channel evidence; got {f.evidence}"
    )


def test_bad_i013_tempfile_secret_warns():
    """bad_i013_tempfile_secret fixture → B13 HIGH WARN with tempfile-channel evidence."""
    home = FIXTURES / "bad_i013_tempfile_secret"
    if not home.is_dir():
        pytest.skip("fixture not found")
    f = _b13(home)
    assert f.status == WARN, f"expected WARN; got {f.status}: {f.detail}"
    assert f.severity == HIGH
    assert any("temp-file sink" in e for e in f.evidence), (
        f"expected tempfile-channel evidence; got {f.evidence}"
    )


def test_bad_i013_report_secret_warns():
    """bad_i013_report_secret fixture → B13 HIGH WARN with report-channel evidence."""
    home = FIXTURES / "bad_i013_report_secret"
    if not home.is_dir():
        pytest.skip("fixture not found")
    f = _b13(home)
    assert f.status == WARN, f"expected WARN; got {f.status}: {f.detail}"
    assert f.severity == HIGH
    assert any("report/output file sink" in e for e in f.evidence), (
        f"expected report-channel evidence; got {f.evidence}"
    )


def test_clean_i013_benign_sink_passes():
    """clean_i013_benign_sink fixture → B13 PASS (sinks present but no credential)."""
    home = FIXTURES / "clean_i013_benign_sink"
    if not home.is_dir():
        pytest.skip("fixture not found")
    f = _b13(home)
    assert f.status == PASS, (
        f"benign-sink fixture must not WARN; got {f.status}: {f.detail}"
    )


def test_clean_i013_doc_example_passes():
    """clean_i013_doc_example fixture → B13 PASS (credential+sink inside fenced block)."""
    home = FIXTURES / "clean_i013_doc_example"
    if not home.is_dir():
        pytest.skip("fixture not found")
    f = _b13(home)
    assert f.status == PASS, (
        f"doc-example fixture must not WARN; got {f.status}: {f.detail}"
    )
