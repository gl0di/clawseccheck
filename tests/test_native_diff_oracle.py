"""C-415 — scripts/native_diff_oracle.py, the differential-vs-native recall oracle.

Fully offline: `run_native_raw`'s subprocess call is mocked exactly the way
`tests/test_native.py` already mocks `native.run_native_audit`'s (same idiom,
applied to this script's own `shutil`/`subprocess` references), and `audit()` is
never pointed at a real home outside `tmp_path`/fixtures.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "native_diff_oracle.py"


def _load_oracle():
    spec = importlib.util.spec_from_file_location("_native_diff_oracle", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oracle = _load_oracle()


def _mock_native(monkeypatch, stdout, exe="/usr/bin/openclaw"):
    monkeypatch.setattr(oracle.shutil, "which", lambda *_a, **_k: exe)
    monkeypatch.setattr(oracle, "_untrusted_exec_reason", lambda _exe: None)

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
    monkeypatch.setattr(oracle.subprocess, "run", fake_run)


def _fake_finding(fid, status="WARN"):
    return SimpleNamespace(id=fid, status=status, severity="MEDIUM",
                           title=f"title for {fid}", detail=f"detail for {fid}",
                           suppressed=False)


# --------------------------------------------------------------------- run_native_raw

def test_run_native_raw_not_found(monkeypatch):
    monkeypatch.setattr(oracle.shutil, "which", lambda *_a, **_k: None)
    status, raw, note = oracle.run_native_raw()
    assert status == "not_found"
    assert raw == []
    assert "PATH" in note


def test_run_native_raw_reuses_the_untrusted_exec_guard(monkeypatch):
    """B-014: this script must refuse exactly like native.run_native_audit does --
    never bypass the guard for its own convenience."""
    monkeypatch.setattr(oracle.shutil, "which", lambda *_a, **_k: "/tmp/fake-openclaw")
    monkeypatch.setattr(oracle, "_untrusted_exec_reason",
                        lambda _exe: "group/world-writable install path")
    status, raw, note = oracle.run_native_raw()
    assert status == "skipped"
    assert raw == []
    assert "not run" in note


def test_run_native_raw_extracts_raw_checkid_not_lossy_id(monkeypatch):
    """The whole reason this script does not reuse native.run_native_audit: the real
    per-finding key is checkId, and _to_finding's _pick("id","check","rule") never
    matches it. This test pins that the RAW dict (with checkId intact) comes through."""
    payload = json.dumps({"findings": [
        {"checkId": "gateway.trusted_proxies_missing", "severity": "warn",
         "title": "Reverse proxy headers are not trusted"},
    ]})
    _mock_native(monkeypatch, payload)
    status, raw, note = oracle.run_native_raw()
    assert status == "ok"
    assert raw[0]["checkId"] == "gateway.trusted_proxies_missing"
    assert "1 raw" in note


def test_run_native_raw_handles_a_timeout(monkeypatch):
    monkeypatch.setattr(oracle.shutil, "which", lambda *_a, **_k: "/usr/bin/openclaw")
    monkeypatch.setattr(oracle, "_untrusted_exec_reason", lambda _exe: None)

    def raiser(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="openclaw", timeout=5)
    monkeypatch.setattr(oracle.subprocess, "run", raiser)
    status, raw, note = oracle.run_native_raw(timeout=5)
    assert status == "timeout"
    assert raw == []
    assert "5" in note


def test_run_native_raw_handles_unparseable_output(monkeypatch):
    _mock_native(monkeypatch, "not json at all")
    status, raw, note = oracle.run_native_raw()
    assert status == "error"
    assert raw == []


# --------------------------------------------------------------------- classification

def test_diff_classifies_every_registry_entry_by_its_recorded_classification(monkeypatch):
    payload = json.dumps({"findings": [
        {"checkId": "summary.attack_surface", "severity": "info", "title": "x"},
        {"checkId": "gateway.trusted_proxies_missing", "severity": "warn", "title": "y"},
        {"checkId": "security.trust_model.multi_user_heuristic", "severity": "warn", "title": "z"},
    ]})
    monkeypatch.setattr(
        oracle, "run_native_raw",
        lambda *a, **k: ("ok", oracle._extract(json.loads(payload)), "3 raw"),
    )
    monkeypatch.setattr(oracle, "audit", lambda home, **kw: (None, [_fake_finding("B26")], None))

    result = oracle.diff_against_native("~/.openclaw")
    by_id = {r["checkId"]: r for r in result["matched_or_classified"]}
    assert by_id["summary.attack_surface"]["classification"] == oracle.INFORMATIONAL
    assert by_id["security.trust_model.multi_user_heuristic"]["our_ids"] == ["B26"]
    # gap_confirmed rows are reported in native_only_or_needs_triage, not matched_or_classified
    gap_rows = {r["checkId"]: r for r in result["native_only_or_needs_triage"]}
    assert gap_rows["gateway.trusted_proxies_missing"]["classification"] == oracle.GAP_CONFIRMED


def test_diff_defaults_an_unregistered_checkid_to_needs_triage_never_silently_covered(monkeypatch):
    payload = json.dumps({"findings": [
        {"checkId": "totally.new.thing", "severity": "warn", "title": "brand new"},
    ]})
    monkeypatch.setattr(
        oracle, "run_native_raw",
        lambda *a, **k: ("ok", oracle._extract(json.loads(payload)), "1 raw"),
    )
    monkeypatch.setattr(oracle, "audit", lambda home, **kw: (None, [], None))

    result = oracle.diff_against_native("~/.openclaw")
    rows = result["native_only_or_needs_triage"]
    assert len(rows) == 1
    assert rows[0]["classification"] == oracle.NEEDS_TRIAGE


def test_coarse_hint_ranks_by_token_overlap_and_is_only_a_hint():
    findings = [_fake_finding("B26"), _fake_finding("A1")]
    findings[0].title = "Multi-user heuristic warning"
    findings[0].detail = "trust boundary spans multiple users"
    findings[1].title = "Lethal Trifecta"
    findings[1].detail = "unrelated"
    hits = oracle._coarse_hint("security.trust_model.multi_user_heuristic",
                               "Potential multi-user setup detected", findings)
    assert hits and hits[0][0] == "B26"
    # it is a HINT only: neither result carries a classification of its own here --
    # that only ever comes from NATIVE_CHECKID_NOTES or the needs_triage default.
    assert all(len(h) == 3 for h in hits)


def test_native_status_not_ok_is_reported_as_unknown_never_as_clean(monkeypatch):
    monkeypatch.setattr(oracle, "run_native_raw", lambda *a, **k: ("not_found", [], "no PATH"))
    monkeypatch.setattr(oracle, "audit", lambda home, **kw: (None, [], None))
    result = oracle.diff_against_native("~/.openclaw")
    out = oracle.render(result)
    assert "UNKNOWN coverage" in out
    assert "no gaps found" not in out.lower() or "never read" in out.lower()


def test_ours_fired_excludes_pass_and_suppressed():
    findings = [
        _fake_finding("B1", "PASS"),
        _fake_finding("B2", "WARN"),
        SimpleNamespace(id="B3", status="FAIL", severity="HIGH", title="t", detail="d",
                        suppressed=True),
        _fake_finding("B4", "FAIL"),
    ]
    result = {"ours_fired": sorted(
        f.id for f in findings if f.status != "PASS" and not f.suppressed
    )}
    assert result["ours_fired"] == ["B2", "B4"]


# --------------------------------------------------------------------- registry hygiene

def test_registry_entries_are_well_formed():
    valid = {oracle.INFORMATIONAL, oracle.COVERED, oracle.GAP_CONFIRMED,
            oracle.RELATED_NOT_SAME}
    for checkid, (cls, our_ids, reason) in oracle.NATIVE_CHECKID_NOTES.items():
        assert isinstance(checkid, str) and checkid
        assert cls in valid, f"{checkid}: unknown classification {cls!r}"
        assert isinstance(our_ids, tuple)
        assert isinstance(reason, str) and reason.strip(), (
            f"{checkid}: empty reason -- a classification without a reason is a "
            "silencer, same rule fleet_fp_gate.py's diagnoses already enforce"
        )


def test_exit_code_reflects_whether_anything_needs_attention(monkeypatch):
    monkeypatch.setattr(oracle, "run_native_raw", lambda *a, **k: ("ok", [], "0 raw"))
    monkeypatch.setattr(oracle, "audit", lambda home, **kw: (None, [], None))
    result = oracle.diff_against_native("~/.openclaw")
    gaps = [r for r in result["native_only_or_needs_triage"]
            if r["classification"] in (oracle.GAP_CONFIRMED, oracle.NEEDS_TRIAGE)]
    assert not gaps  # nothing native-side at all -> nothing to flag


def test_cli_exits_cannot_run_when_native_is_unavailable(monkeypatch, capsys):
    monkeypatch.setattr(oracle, "run_native_raw", lambda *a, **k: ("not_found", [], "no PATH"))
    monkeypatch.setattr(oracle, "audit", lambda home, **kw: (None, [], None))
    rc = oracle.main(["--home", "~/.openclaw"])
    assert rc == oracle.EXIT_CANNOT_RUN
    assert "UNKNOWN coverage" in capsys.readouterr().out


def test_cli_json_mode_is_valid_json(monkeypatch, capsys):
    monkeypatch.setattr(oracle, "run_native_raw", lambda *a, **k: ("ok", [], "0 raw"))
    monkeypatch.setattr(oracle, "audit", lambda home, **kw: (None, [], None))
    rc = oracle.main(["--home", "~/.openclaw", "--json"])
    assert rc == oracle.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["native_status"] == "ok"
