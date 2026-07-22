"""Tests for C-253 (Judge epic part (a)): the judge as noise-remover on the
user's OWN config -- automatic proposer of .clawseccheckignore entries.

Covers:
- build_ignore_proposals() only ever considers the same borderline population
  build_judge_packet() already offers to the judge (UNKNOWN + FN-prone WARN) --
  a FAIL-status finding (the only kind that can cap the score) can NEVER be
  selected, structurally, even when a crafted verdicts file claims SAFE for one.
- Only a "SAFE" verdict produces a proposal; anything else (SUSPICIOUS,
  DANGEROUS, unknown value, no verdict at all) does not.
- Suppressed findings and ordinary (non-FN-prone) WARN findings are excluded,
  matching build_judge_packet's own exclusions.
- The proposed "entry" is exactly baseline.fingerprint(f) -- the same string
  baseline.apply() already matches against .clawseccheckignore lines.
- render_ignore_proposals_json(): envelope shape, deterministic, and takes no
  path/home argument at all -- it cannot write to disk by construction.
- baseline.append_entries(): creates the file if absent, dedups already-present
  entries, writes an optional leading comment line.
- The existing safety net is untouched: a suppressed WARN-status B13 (or a
  suppressed CRITICAL FAIL) still returns True from
  report.surfaced_despite_suppression() -- this feature gains no new authority
  over what that predicate already guarantees.
- CLI: --propose-ignore (path + stdin) is read-only; --apply-ignore-proposals
  is confirmation-gated (EOF aborts loudly, "n" aborts quietly, --yes applies),
  dedups on repeated apply, and an applied entry actually suppresses the
  finding in a subsequent --json run.
- The applied write is still --monitor drift: adding entries via
  baseline.append_entries changes ignore_hash exactly like any other edit to
  .clawseccheckignore, so the existing HIGH "your .clawseccheckignore changed"
  alert fires -- this feature adds no new authority beyond what the existing
  suppression + drift-detection machinery already provides.

C-135 (2026-07-22, independent adversarial review) additions:
- A finding with more than one evidence entry (an aggregate spanning multiple
  skills, e.g. B100/B65/.../B156's real shape) is never proposed -- a SAFE
  verdict scoped to one target cannot safely suppress the whole aggregate,
  which would silently hide OTHER, unreviewed skills' evidence too.
- --apply-ignore-proposals refuses any "entry" not shaped like a real
  fingerprint() output (rejects a bare "B1"/"B2"/"B20" a tampered, not
  genuinely --propose-ignore-produced, proposals file could carry) --
  baseline.is_fingerprint() is the single source of that shape check.
- baseline.append_entries() writes via safeio.secure_append_text (symlink-safe,
  O_NOFOLLOW) rather than a plain open(); a symlinked .clawseccheckignore
  raises OSError instead of writing through it, and cli.py surfaces that as a
  clear error rather than a crash or a silent no-op.

All tests are offline, read-only except where explicitly exercising a write
path, stdlib-only.
"""
from __future__ import annotations

import json
import os

import pytest

from clawseccheck.adjudication import build_ignore_proposals, render_ignore_proposals_json
from clawseccheck.baseline import append_entries, fingerprint, is_fingerprint, load_ignore
from clawseccheck.catalog import CRITICAL, FAIL, HIGH, MEDIUM, PASS, UNKNOWN, WARN, Finding
from clawseccheck.monitor import diff, snapshot
from clawseccheck.report import surfaced_despite_suppression

# ---------------------------------------------------------------------------
# build_ignore_proposals() -- population + verdict filtering
# ---------------------------------------------------------------------------

def _safe_map(*pairs):
    """{(finding_id, target): {"verdict": "SAFE", "votes": None}} for each pair."""
    return {(fid, target): {"verdict": "SAFE", "votes": None} for fid, target in pairs}


def test_unsuppressed_unknown_with_safe_verdict_is_proposed():
    f = Finding("C99", "t", MEDIUM, UNKNOWN, "unknown detail", "fix it", "fw")
    proposals = build_ignore_proposals([f], _safe_map(("C99", "C99")))
    assert len(proposals) == 1
    assert proposals[0]["finding_id"] == "C99"
    assert proposals[0]["entry"] == fingerprint(f)


def test_fn_prone_warn_with_safe_verdict_is_proposed():
    f = Finding("B13", "t", HIGH, WARN, "warn detail", "fix it", "fw",
                evidence=["skillx: notify pattern"])
    proposals = build_ignore_proposals([f], _safe_map(("B13", "skillx")))
    assert len(proposals) == 1
    assert proposals[0]["finding_id"] == "B13"


def test_ordinary_warn_not_in_fn_prone_set_is_never_proposed():
    f = Finding("B21", "t", HIGH, WARN, "warn detail", "fix it", "fw")
    proposals = build_ignore_proposals([f], _safe_map(("B21", "B21")))
    assert proposals == []


def test_suppressed_finding_is_never_proposed():
    f = Finding("C99", "t", MEDIUM, UNKNOWN, "unknown detail", "fix it", "fw", suppressed=True)
    proposals = build_ignore_proposals([f], _safe_map(("C99", "C99")))
    assert proposals == []


@pytest.mark.parametrize("verdict", ["SUSPICIOUS", "DANGEROUS", "MAYBE_EVIL_IDK", ""])
def test_non_safe_verdict_is_never_proposed(verdict):
    f = Finding("C99", "t", MEDIUM, UNKNOWN, "unknown detail", "fix it", "fw")
    verdicts_map = {("C99", "C99"): {"verdict": verdict, "votes": None}}
    assert build_ignore_proposals([f], verdicts_map) == []


def test_no_verdict_submitted_is_never_proposed():
    f = Finding("C99", "t", MEDIUM, UNKNOWN, "unknown detail", "fix it", "fw")
    assert build_ignore_proposals([f], {}) == []


def test_structural_guarantee_fail_status_finding_never_proposed_even_if_claimed_safe():
    """The security-critical guarantee: a FAIL-status finding (the only kind
    that can cap the score) is never even a CANDIDATE for a proposal, because
    build_ignore_proposals only iterates the same _is_borderline population
    build_judge_packet does (UNKNOWN / FN-prone WARN). A crafted verdicts file
    claiming SAFE for a capping CRITICAL FAIL must have zero effect.
    """
    capping_fail = Finding("B2", "t", CRITICAL, FAIL, "fail detail", "fix", "fw")
    verdicts_map = _safe_map(("B2", "B2"))
    assert build_ignore_proposals([capping_fail], verdicts_map) == []


def test_pass_finding_never_proposed_even_if_claimed_safe():
    f = Finding("B1", "t", HIGH, PASS, "pass detail", "fix", "fw")
    assert build_ignore_proposals([f], _safe_map(("B1", "B1"))) == []


def test_proposal_entry_matches_baseline_fingerprint_exactly():
    f = Finding("C99", "t", MEDIUM, UNKNOWN, "unknown detail here", "fix it", "fw")
    proposals = build_ignore_proposals([f], _safe_map(("C99", "C99")))
    assert proposals[0]["entry"] == fingerprint(f)
    # And that fingerprint is exactly what baseline.apply() would match against
    # a .clawseccheckignore line -- confirmed indirectly via the CLI round-trip
    # tests below, not re-derived here.


def test_multi_target_aggregate_finding_is_never_proposed():
    """C-135: a Finding aggregating hits across multiple skills (>1 evidence
    entry -- B100/B65/etc.'s real shape) must never be proposed, even with a
    SAFE verdict for its first target, because suppressing it would silence
    every OTHER bundled skill's evidence too, on a verdict that only ever
    covered the first one.
    """
    f = Finding("B100", "t", MEDIUM, WARN, "combined detail for skillA and skillB",
                "fix", "fw", evidence=["skillA: clickfix pattern", "skillB: clickfix pattern"])
    proposals = build_ignore_proposals([f], _safe_map(("B100", "skillA")))
    assert proposals == []


def test_single_target_finding_is_still_proposed():
    """Sanity check that the >1-evidence guard doesn't over-broaden: a
    single-skill finding (the common case) is unaffected."""
    f = Finding("B100", "t", MEDIUM, WARN, "single skill detail", "fix", "fw",
                evidence=["skillA: clickfix pattern"])
    proposals = build_ignore_proposals([f], _safe_map(("B100", "skillA")))
    assert len(proposals) == 1


def test_zero_evidence_finding_is_still_proposed():
    f = Finding("C99", "t", MEDIUM, UNKNOWN, "unknown detail", "fix it", "fw", evidence=[])
    proposals = build_ignore_proposals([f], _safe_map(("C99", "C99")))
    assert len(proposals) == 1


def test_deterministic_ordering():
    findings = [
        Finding("C99", "t", MEDIUM, UNKNOWN, "d", "f", "fw"),
        Finding("B13", "t", HIGH, WARN, "d", "f", "fw", evidence=["zzz: x"]),
        Finding("B100", "t", HIGH, WARN, "d", "f", "fw", evidence=["aaa: x"]),
    ]
    verdicts_map = _safe_map(("C99", "C99"), ("B13", "zzz"), ("B100", "aaa"))
    first = build_ignore_proposals(findings, verdicts_map)
    second = build_ignore_proposals(list(reversed(findings)), dict(verdicts_map))
    assert first == second
    assert [p["finding_id"] for p in first] == sorted(p["finding_id"] for p in first)


def test_empty_findings_and_verdicts_never_raise():
    assert build_ignore_proposals([], {}) == []
    assert build_ignore_proposals(None, {}) == []


# ---------------------------------------------------------------------------
# render_ignore_proposals_json() -- envelope + read-only-by-construction
# ---------------------------------------------------------------------------

def test_render_ignore_proposals_json_envelope_shape():
    f = Finding("C99", "t", MEDIUM, UNKNOWN, "unknown detail", "fix it", "fw")
    verdicts_raw = json.dumps({"verdicts": [{"finding_id": "C99", "target": "C99", "verdict": "SAFE"}]})
    out = render_ignore_proposals_json([f], verdicts_raw=verdicts_raw, version="9.9.9")
    data = json.loads(out)
    assert data["tool"] == "clawseccheck"
    assert data["version"] == "9.9.9"
    assert isinstance(data["proposedIgnoreEntries"], list)
    assert len(data["proposedIgnoreEntries"]) == 1
    assert "PROPOSED ONLY" in data["note"]


def test_render_ignore_proposals_json_takes_no_path_argument():
    """Structural read-only guarantee: the function signature has no path/home
    parameter at all, so it cannot write to disk -- confirmed via introspection
    rather than a filesystem check, which would only prove "didn't write this
    time", not "cannot write"."""
    import inspect
    params = inspect.signature(render_ignore_proposals_json).parameters
    assert set(params) == {"findings", "verdicts_raw", "version"}


def test_render_ignore_proposals_json_malformed_verdicts_degrades_to_empty():
    f = Finding("C99", "t", MEDIUM, UNKNOWN, "unknown detail", "fix it", "fw")
    out = render_ignore_proposals_json([f], verdicts_raw="not json {{{", version="1.0.0")
    assert json.loads(out)["proposedIgnoreEntries"] == []


def test_render_ignore_proposals_json_empty_findings():
    out = render_ignore_proposals_json([], verdicts_raw="{}", version="1.0.0")
    assert json.loads(out)["proposedIgnoreEntries"] == []


# ---------------------------------------------------------------------------
# baseline.append_entries()
# ---------------------------------------------------------------------------

def test_append_entries_creates_file_when_absent(tmp_path):
    written = append_entries(tmp_path, ["B10:aabbcc11"])
    assert written == 1
    p = tmp_path / ".clawseccheckignore"
    assert p.exists()
    assert "B10:aabbcc11" in load_ignore(tmp_path)


def test_append_entries_writes_leading_comment(tmp_path):
    append_entries(tmp_path, ["B10:aabbcc11"], comment="judge-proposed, applied 2026-07-22")
    text = (tmp_path / ".clawseccheckignore").read_text(encoding="utf-8")
    assert text.splitlines()[0] == "# judge-proposed, applied 2026-07-22"


def test_append_entries_dedups_already_present(tmp_path):
    (tmp_path / ".clawseccheckignore").write_text("B10:aabbcc11\n", encoding="utf-8")
    written = append_entries(tmp_path, ["B10:aabbcc11", "B11:ddeeff22"])
    assert written == 1
    ignore = load_ignore(tmp_path)
    assert ignore == {"B10:aabbcc11", "B11:ddeeff22"}


def test_append_entries_no_new_entries_returns_zero_and_does_not_touch_file(tmp_path):
    (tmp_path / ".clawseccheckignore").write_text("B10:aabbcc11\n", encoding="utf-8")
    before = (tmp_path / ".clawseccheckignore").stat().st_mtime_ns
    written = append_entries(tmp_path, ["B10:aabbcc11"])
    assert written == 0
    assert (tmp_path / ".clawseccheckignore").stat().st_mtime_ns == before


# ---------------------------------------------------------------------------
# The existing safety net is untouched (epic residual/DoD pin)
# ---------------------------------------------------------------------------

def test_suppressed_sensitive_warn_status_b13_still_surfaces():
    """B13 is in SENSITIVE_SUPPRESSED_IDS -- even at WARN status (the only
    status build_ignore_proposals could ever have offered a SAFE verdict on),
    a suppressed B13 must still surface. This is report.py's existing
    predicate; pinned here so it stays tied to this feature's DoD.
    """
    f = Finding("B13", "t", HIGH, WARN, "warn detail", "fix it", "fw", suppressed=True)
    assert surfaced_despite_suppression(f) is True


def test_suppressed_capping_critical_fail_still_surfaces():
    f = Finding("B2", "t", CRITICAL, FAIL, "fail detail", "fix", "fw", suppressed=True)
    assert surfaced_despite_suppression(f) is True


def test_suppressed_ordinary_warn_not_sensitive_does_not_force_surface():
    f = Finding("B21", "t", HIGH, WARN, "warn detail", "fix it", "fw", suppressed=True)
    assert surfaced_despite_suppression(f) is False


# ---------------------------------------------------------------------------
# --monitor drift: an applied proposal is still detected as a normal edit
# ---------------------------------------------------------------------------

def test_applying_a_proposal_is_still_monitor_drift(tmp_path):
    from clawseccheck import audit

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    ctx1, f1, s1 = audit(tmp_path)
    base = snapshot(ctx1, f1, s1)
    assert base["ignore_hash"] == ""

    append_entries(tmp_path, ["C99:deadbeef"], comment="judge-proposed, applied 2026-07-22")

    ctx2, f2, s2 = audit(tmp_path)
    alerts = diff(base, snapshot(ctx2, f2, s2))
    levels = [lvl for lvl, _msg in alerts]
    assert "HIGH" in levels
    assert any(".clawseccheckignore" in msg for _, msg in alerts)


# ---------------------------------------------------------------------------
# CLI: --propose-ignore (read-only) + --apply-ignore-proposals (confirmation-gated)
# ---------------------------------------------------------------------------

def _judge_packet_first_unknown_id(tmp_path):
    """Run a real audit and return (finding_id, target) of some real UNKNOWN
    finding, so the CLI round-trip tests exercise a genuine finding rather
    than a synthetic one."""
    from clawseccheck import audit
    ctx, findings, _score = audit(tmp_path)
    for f in findings:
        if f.status == UNKNOWN and not f.suppressed:
            return f.id, f.id  # _target_from_evidence falls back to f.id with no evidence
    raise AssertionError("fixture produced no UNKNOWN finding to test against")


def test_cli_propose_ignore_is_read_only(tmp_path, capsys):
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    fid, target = _judge_packet_first_unknown_id(tmp_path)
    verdicts_path = tmp_path / "verdicts.json"
    verdicts_path.write_text(json.dumps(
        {"verdicts": [{"finding_id": fid, "target": target, "verdict": "SAFE"}]}
    ), encoding="utf-8")

    rc = main(["--home", str(tmp_path), "--propose-ignore", str(verdicts_path),
               "--no-native", "--no-host"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["proposedIgnoreEntries"], "expected at least one proposal"
    assert not (tmp_path / ".clawseccheckignore").exists(), \
        "--propose-ignore must never write .clawseccheckignore"


def test_cli_propose_ignore_reads_from_stdin(tmp_path, capsys, monkeypatch):
    import io

    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    fid, target = _judge_packet_first_unknown_id(tmp_path)
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(
        {"verdicts": [{"finding_id": fid, "target": target, "verdict": "SAFE"}]}
    )))
    rc = main(["--home", str(tmp_path), "--propose-ignore", "-", "--no-native", "--no-host"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["proposedIgnoreEntries"]


def _propose(tmp_path, capsys) -> dict:
    from clawseccheck.cli import main
    fid, target = _judge_packet_first_unknown_id(tmp_path)
    verdicts_path = tmp_path / "verdicts.json"
    verdicts_path.write_text(json.dumps(
        {"verdicts": [{"finding_id": fid, "target": target, "verdict": "SAFE"}]}
    ), encoding="utf-8")
    rc = main(["--home", str(tmp_path), "--propose-ignore", str(verdicts_path),
               "--no-native", "--no-host"])
    assert rc == 0
    proposal = capsys.readouterr().out
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_text(proposal, encoding="utf-8")
    return proposal_path


def test_cli_apply_ignore_proposals_eof_aborts_loudly(tmp_path, capsys, monkeypatch):
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    proposal_path = _propose(tmp_path, capsys)

    def _raise_eof(*_a, **_k):
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_eof)
    rc = main(["--home", str(tmp_path), "--apply-ignore-proposals", str(proposal_path)])
    assert rc == 1
    assert not (tmp_path / ".clawseccheckignore").exists()


def test_cli_apply_ignore_proposals_declined_aborts_quietly(tmp_path, capsys, monkeypatch):
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    proposal_path = _propose(tmp_path, capsys)

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "n")
    rc = main(["--home", str(tmp_path), "--apply-ignore-proposals", str(proposal_path)])
    assert rc == 0
    assert not (tmp_path / ".clawseccheckignore").exists()


def test_cli_apply_ignore_proposals_yes_flag_applies_without_prompt(tmp_path, capsys):
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    proposal_path = _propose(tmp_path, capsys)

    rc = main(["--home", str(tmp_path), "--apply-ignore-proposals", str(proposal_path), "--yes"])
    assert rc == 0
    assert (tmp_path / ".clawseccheckignore").exists()


def test_cli_apply_ignore_proposals_confirmed_applies(tmp_path, capsys, monkeypatch):
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    proposal_path = _propose(tmp_path, capsys)

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "y")
    rc = main(["--home", str(tmp_path), "--apply-ignore-proposals", str(proposal_path)])
    assert rc == 0
    assert (tmp_path / ".clawseccheckignore").exists()


def test_cli_apply_ignore_proposals_end_to_end_suppresses_in_next_report(tmp_path, capsys):
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    fid, target = _judge_packet_first_unknown_id(tmp_path)
    proposal_path = _propose(tmp_path, capsys)

    rc = main(["--home", str(tmp_path), "--apply-ignore-proposals", str(proposal_path), "--yes"])
    assert rc == 0
    capsys.readouterr()

    rc = main(["--home", str(tmp_path), "--json", "--no-native", "--no-host"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    matched = [f for f in data["findings"] if f["id"] == fid]
    assert matched and matched[0]["suppressed"] is True


def test_cli_apply_ignore_proposals_missing_file(tmp_path):
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    rc = main(["--home", str(tmp_path), "--apply-ignore-proposals",
               str(tmp_path / "does-not-exist.json")])
    assert rc == 1


def test_cli_apply_ignore_proposals_malformed_json(tmp_path):
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text("not json {{{", encoding="utf-8")
    rc = main(["--home", str(tmp_path), "--apply-ignore-proposals", str(bad)])
    assert rc == 1


def test_cli_apply_ignore_proposals_wrong_shape(tmp_path):
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"no_proposals_key": []}), encoding="utf-8")
    rc = main(["--home", str(tmp_path), "--apply-ignore-proposals", str(wrong)])
    assert rc == 1


def test_cli_apply_ignore_proposals_empty_list_is_a_noop(tmp_path, capsys):
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"proposedIgnoreEntries": []}), encoding="utf-8")
    rc = main(["--home", str(tmp_path), "--apply-ignore-proposals", str(empty)])
    assert rc == 0
    assert not (tmp_path / ".clawseccheckignore").exists()


# ---------------------------------------------------------------------------
# C-135: is_fingerprint() shape guard
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("entry", ["B10:d326cc57", "C99:00000000", "RISK-03:abcdef12"])
def test_is_fingerprint_accepts_real_shapes(entry):
    assert is_fingerprint(entry) is True


@pytest.mark.parametrize("entry", [
    "B1", "B2", "B20", "B13",           # bare check ids -- the exact injection risk
    "B10:", "B10", ":d326cc57",         # missing half
    "B10:D326CC57",                    # uppercase hex -- fingerprint() always lowercases
    "B10:d326cc5",                     # 7 hex chars, not 8
    "B10:d326cc571",                   # 9 hex chars, not 8
    "B10:d326cc5g",                    # non-hex trailing char
    "", None, 42, ["B10:d326cc57"],
])
def test_is_fingerprint_rejects_bare_ids_and_garbage(entry):
    assert is_fingerprint(entry) is False


def test_cli_apply_ignore_proposals_rejects_bare_id_injection(tmp_path, capsys):
    """C-135: a tampered proposals file with a bare "B20" entry (not something a
    genuine --propose-ignore run could ever produce) must be refused, not
    silently applied via apply()'s bare-id match."""
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps({"proposedIgnoreEntries": [{"entry": "B20"}]}), encoding="utf-8")

    rc = main(["--home", str(tmp_path), "--apply-ignore-proposals", str(tampered), "--yes"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "not shaped like a real fingerprint" in out
    assert "B20" in out
    assert not (tmp_path / ".clawseccheckignore").exists()


def test_cli_apply_ignore_proposals_rejects_bare_id_but_applies_valid_siblings(tmp_path):
    """A mixed file (one tampered bare-id entry alongside a genuine fingerprint)
    applies only the valid one -- rejection of one entry must not sink the rest."""
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    mixed = tmp_path / "mixed.json"
    mixed.write_text(json.dumps({"proposedIgnoreEntries": [
        {"entry": "B20"},
        {"entry": "C99:d326cc57"},
    ]}), encoding="utf-8")

    rc = main(["--home", str(tmp_path), "--apply-ignore-proposals", str(mixed), "--yes"])
    assert rc == 0
    ignore = load_ignore(tmp_path)
    assert ignore == {"C99:d326cc57"}


# ---------------------------------------------------------------------------
# C-135: symlink-safe write
# ---------------------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="O_NOFOLLOW symlink refusal is POSIX-only (C-160)")
def test_append_entries_refuses_a_symlinked_ignore_file(tmp_path):
    outside = tmp_path.parent / f"outside-{tmp_path.name}.clawseccheckignore"
    outside.write_text("", encoding="utf-8")
    try:
        (tmp_path / ".clawseccheckignore").symlink_to(outside)
        with pytest.raises(OSError):
            append_entries(tmp_path, ["B10:d326cc57"])
        assert "B10:d326cc57" not in outside.read_text(encoding="utf-8")
    finally:
        outside.unlink(missing_ok=True)


@pytest.mark.skipif(os.name == "nt", reason="O_NOFOLLOW symlink refusal is POSIX-only (C-160)")
def test_cli_apply_ignore_proposals_symlinked_ignore_file_errors_cleanly(tmp_path, capsys):
    from clawseccheck.cli import main

    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    outside = tmp_path.parent / f"outside2-{tmp_path.name}.clawseccheckignore"
    outside.write_text("", encoding="utf-8")
    try:
        (tmp_path / ".clawseccheckignore").symlink_to(outside)
        proposal = tmp_path / "proposal.json"
        proposal.write_text(json.dumps({"proposedIgnoreEntries": [{"entry": "C99:d326cc57"}]}),
                             encoding="utf-8")
        rc = main(["--home", str(tmp_path), "--apply-ignore-proposals", str(proposal), "--yes"])
        assert rc == 1
        out = capsys.readouterr().out
        assert "could not write" in out
        assert "C99:d326cc57" not in outside.read_text(encoding="utf-8")
    finally:
        outside.unlink(missing_ok=True)
