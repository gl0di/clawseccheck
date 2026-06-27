"""Tests for compute_blast_radius and its integration into render_json / render_report.

All tests are offline and deterministic — no network calls, no file writes.
"""
from __future__ import annotations

import json

from clawseccheck.catalog import FAIL, PASS, WARN, HIGH, MEDIUM, Finding
from clawseccheck.report import compute_blast_radius, render_json, render_report
from clawseccheck.scoring import compute, ScoreResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score(**kw) -> ScoreResult:
    defaults = dict(score=50, grade="D", capped=False, raw_score=50,
                    failed_critical=0, failed_high=0)
    defaults.update(kw)
    return ScoreResult(**defaults)


def _fail(cid: str = "B1", severity: str = HIGH) -> Finding:
    return Finding(cid, f"Check {cid}", severity, FAIL, "detail", "fix", "fw")


def _pass(cid: str = "B2") -> Finding:
    return Finding(cid, f"Check {cid}", MEDIUM, PASS, "ok", "ok", "fw")


def _warn(cid: str = "B3") -> Finding:
    return Finding(cid, f"Check {cid}", MEDIUM, WARN, "detail", "fix", "fw")


class _Ctx:
    """Minimal stub matching the ctx interface used by render_json / render_report."""
    def __init__(self, cfg: dict):
        self.config = cfg


# ---------------------------------------------------------------------------
# Unit: compute_blast_radius
# ---------------------------------------------------------------------------

class TestComputeBlastRadius:
    def test_empty_config_returns_zero_values(self):
        br = compute_blast_radius({}, "B1")
        assert br == {"open_channels": 0, "has_exec": False, "has_write": False, "secret_paths": 0}

    def test_open_channels_counts_dm_open(self):
        cfg = {"channels": {"slack": {"dmPolicy": "open"}}}
        br = compute_blast_radius(cfg, "B1")
        assert br["open_channels"] == 1

    def test_open_channels_counts_group_open(self):
        cfg = {"channels": {"teams": {"groupPolicy": "open"}}}
        br = compute_blast_radius(cfg, "B1")
        assert br["open_channels"] == 1

    def test_two_open_channels(self):
        cfg = {
            "channels": {
                "slack": {"dmPolicy": "open"},
                "teams": {"groupPolicy": "open"},
            }
        }
        br = compute_blast_radius(cfg, "B1")
        assert br["open_channels"] == 2

    def test_closed_channel_not_counted(self):
        cfg = {"channels": {"slack": {"dmPolicy": "restricted"}}}
        br = compute_blast_radius(cfg, "B1")
        assert br["open_channels"] == 0

    def test_has_exec_true_when_exec_mode_set(self):
        cfg = {"tools": {"exec": {"mode": "full"}}}
        br = compute_blast_radius(cfg, "B1")
        assert br["has_exec"] is True

    def test_has_exec_false_when_no_exec_mode(self):
        cfg = {"tools": {"exec": {}}}
        br = compute_blast_radius(cfg, "B1")
        assert br["has_exec"] is False

    def test_has_write_true_for_fs_write(self):
        cfg = {"tools": {"allow": ["fs_write", "read"]}}
        br = compute_blast_radius(cfg, "B1")
        assert br["has_write"] is True

    def test_has_write_true_for_apply_patch(self):
        cfg = {"tools": {"allow": ["apply_patch"]}}
        br = compute_blast_radius(cfg, "B1")
        assert br["has_write"] is True

    def test_has_write_false_when_no_write_tools(self):
        cfg = {"tools": {"allow": ["read", "search"]}}
        br = compute_blast_radius(cfg, "B1")
        assert br["has_write"] is False

    def test_has_write_gateway_allow(self):
        cfg = {"gateway": {"tools": {"allow": ["fs_write"]}}}
        br = compute_blast_radius(cfg, "B1")
        assert br["has_write"] is True

    def test_secret_paths_counts_secret_keys(self):
        # A key matching SECRET_KEY_RE with value >= 16 chars
        cfg = {"auth": {"apiToken": "a" * 20}}
        br = compute_blast_radius(cfg, "B1")
        assert br["secret_paths"] >= 1

    def test_secret_paths_zero_when_no_secrets(self):
        cfg = {"name": "myclaw", "version": 1}
        br = compute_blast_radius(cfg, "B1")
        assert br["secret_paths"] == 0

    def test_finding_cid_ignored_in_current_impl(self):
        """finding_cid is accepted but currently unused — different CIDs give same result."""
        cfg = {}
        assert compute_blast_radius(cfg, "B1") == compute_blast_radius(cfg, "B54")

    def test_returns_dict_with_expected_keys(self):
        br = compute_blast_radius({}, "B1")
        assert set(br.keys()) == {"open_channels", "has_exec", "has_write", "secret_paths"}

    def test_types_are_correct(self):
        br = compute_blast_radius({}, "B1")
        assert isinstance(br["open_channels"], int)
        assert isinstance(br["has_exec"], bool)
        assert isinstance(br["has_write"], bool)
        assert isinstance(br["secret_paths"], int)


# ---------------------------------------------------------------------------
# Integration: render_json — blast_radius in FAIL findings when ctx provided
# ---------------------------------------------------------------------------

class TestRenderJsonBlastRadius:
    def test_fail_finding_has_blast_radius_when_ctx_given(self):
        findings = [_fail("B1")]
        score = compute(findings)
        ctx = _Ctx({"channels": {"slack": {"dmPolicy": "open"}}})
        data = json.loads(render_json(findings, score, ctx=ctx))
        fail_findings = [f for f in data["findings"] if f["status"] == FAIL]
        assert len(fail_findings) == 1
        assert "blast_radius" in fail_findings[0]

    def test_blast_radius_structure_correct(self):
        findings = [_fail("B1")]
        score = compute(findings)
        ctx = _Ctx({"tools": {"exec": {"mode": "full"}, "allow": ["fs_write"]}})
        data = json.loads(render_json(findings, score, ctx=ctx))
        br = data["findings"][0]["blast_radius"]
        assert set(br.keys()) == {"open_channels", "has_exec", "has_write", "secret_paths"}

    def test_blast_radius_values_reflect_config(self):
        cfg = {
            "channels": {"slack": {"dmPolicy": "open"}},
            "tools": {"exec": {"mode": "full"}, "allow": ["fs_write"]},
        }
        findings = [_fail("B1")]
        score = compute(findings)
        data = json.loads(render_json(findings, score, ctx=_Ctx(cfg)))
        br = data["findings"][0]["blast_radius"]
        assert br["open_channels"] == 1
        assert br["has_exec"] is True
        assert br["has_write"] is True

    def test_pass_finding_has_no_blast_radius(self):
        findings = [_pass("B2")]
        score = compute(findings)
        ctx = _Ctx({"channels": {"slack": {"dmPolicy": "open"}}})
        data = json.loads(render_json(findings, score, ctx=ctx))
        pass_findings = [f for f in data["findings"] if f["status"] == PASS]
        assert len(pass_findings) == 1
        assert "blast_radius" not in pass_findings[0]

    def test_warn_finding_has_no_blast_radius(self):
        findings = [_warn("B3")]
        score = compute(findings)
        ctx = _Ctx({})
        data = json.loads(render_json(findings, score, ctx=ctx))
        warn_findings = [f for f in data["findings"] if f["status"] == WARN]
        assert len(warn_findings) == 1
        assert "blast_radius" not in warn_findings[0]

    def test_fail_finding_has_no_blast_radius_without_ctx(self):
        """When ctx=None (no ctx provided), blast_radius must not appear."""
        findings = [_fail("B1")]
        score = compute(findings)
        data = json.loads(render_json(findings, score))
        assert "blast_radius" not in data["findings"][0]

    def test_multiple_fail_findings_all_get_blast_radius(self):
        findings = [_fail("B1"), _fail("B4", severity=MEDIUM)]
        score = compute(findings)
        ctx = _Ctx({})
        data = json.loads(render_json(findings, score, ctx=ctx))
        fail_findings = [f for f in data["findings"] if f["status"] == FAIL]
        assert all("blast_radius" in f for f in fail_findings)

    def test_existing_json_keys_unaffected(self):
        """Adding blast_radius must not disturb any existing top-level keys."""
        findings = [_fail("B1")]
        score = compute(findings)
        data = json.loads(render_json(findings, score, ctx=_Ctx({})))
        for key in ("score", "grade", "capped", "raw_score", "trifecta",
                    "findings", "next_actions", "capability_graph",
                    "secret_reachability", "intentAttestationRequests"):
            assert key in data, f"existing key '{key}' missing after blast_radius change"


# ---------------------------------------------------------------------------
# Integration: render_report — blast line opt-in via verbose=True
# ---------------------------------------------------------------------------

class TestRenderReportBlastRadius:
    def test_blast_line_absent_by_default(self):
        """Without verbose=True, no blast: line should appear."""
        findings = [_fail("B1")]
        score = compute(findings)
        ctx = _Ctx({"channels": {"slack": {"dmPolicy": "open"}}})
        out = render_report(findings, score, ctx=ctx)
        assert "blast:" not in out

    def test_blast_line_absent_without_ctx(self):
        """verbose=True but no ctx — still no blast line."""
        findings = [_fail("B1")]
        score = compute(findings)
        out = render_report(findings, score, verbose=True)
        assert "blast:" not in out

    def test_blast_line_appears_with_verbose_and_ctx(self):
        findings = [_fail("B1")]
        score = compute(findings)
        ctx = _Ctx({})
        out = render_report(findings, score, ctx=ctx, verbose=True)
        assert "blast:" in out

    def test_blast_line_format(self):
        """The blast line must contain the four field names."""
        cfg = {
            "channels": {"slack": {"dmPolicy": "open"}},
            "tools": {"exec": {"mode": "full"}, "allow": ["fs_write"]},
        }
        findings = [_fail("B1")]
        score = compute(findings)
        out = render_report(findings, score, ctx=_Ctx(cfg), verbose=True)
        assert "channels=1" in out
        assert "exec=true" in out
        assert "write=true" in out
        assert "secrets=" in out

    def test_blast_line_not_emitted_for_warn_finding(self):
        findings = [_warn("B3")]
        score = compute(findings)
        out = render_report(findings, score, ctx=_Ctx({}), verbose=True)
        assert "blast:" not in out

    def test_blast_line_not_emitted_for_pass_finding(self):
        findings = [_pass("B2"), _pass("B5")]
        score = compute(findings)
        out = render_report(findings, score, ctx=_Ctx({}), verbose=True)
        assert "blast:" not in out

    def test_verbose_does_not_break_existing_report_content(self):
        """Adding verbose=True must not remove any previously-present content."""
        findings = [_fail("B1"), _pass("B2")]
        score = compute(findings)
        ctx = _Ctx({})
        normal_out = render_report(findings, score, ctx=ctx)
        verbose_out = render_report(findings, score, ctx=ctx, verbose=True)
        # Everything in the non-verbose output should still be in verbose output
        # (blast lines are additive, not replacing anything).
        # Check a few anchor strings.
        for anchor in ("Check B1", "fix", "blast:"):
            # anchor present in verbose
            assert anchor in verbose_out, f"'{anchor}' missing from verbose output"
        # The non-verbose output must NOT have blast:
        assert "blast:" not in normal_out
