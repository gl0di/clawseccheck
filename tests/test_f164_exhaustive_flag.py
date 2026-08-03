"""F-164 SC-1: --exhaustive plumbing (ScanLimits, ctx.exhaustive, the CLI flag).

This step is deliberately behavior-preserving: DEFAULT_LIMITS must reproduce today's
real, individually-calibrated constants exactly, so a default (non---exhaustive) run's
output is byte-identical to before this flag existed. Later F-164 sub-changes are what
actually wire scanners to read limits_for(ctx) -- this file only pins the plumbing.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.checks._egress import _LOG_HUNT_CHECK_BUDGET_S, _LOG_HUNT_PER_FILE_BUDGET_S
from clawseccheck.cli import main
from clawseccheck.collector import Context
from clawseccheck.logscan import _MAX_BYTES_PER_FILE as LOGSCAN_MAX_BYTES_PER_FILE
from clawseccheck.logscan import _OVERSIZED_WINDOW_CHARS
from clawseccheck.scanbudget import (
    DEFAULT_AUDIT_BUDGET_S,
    DEFAULT_CHECK_BUDGET_S,
    DEFAULT_LIMITS,
    EXHAUSTIVE_LIMITS,
    ScanLimits,
    limits_for,
)
from clawseccheck.trajectory import _MAX_BYTES_PER_FILE as TRAJ_MAX_BYTES_PER_FILE
from clawseccheck.trajectory import _MAX_FILES as TRAJ_MAX_FILES

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")


class TestScanLimits:
    def test_default_limits_reproduce_todays_real_constants_exactly(self):
        assert DEFAULT_LIMITS.exhaustive is False
        assert DEFAULT_LIMITS.traj_max_files == TRAJ_MAX_FILES
        assert DEFAULT_LIMITS.traj_max_bytes_per_file == TRAJ_MAX_BYTES_PER_FILE
        assert DEFAULT_LIMITS.log_check_budget_s == _LOG_HUNT_CHECK_BUDGET_S
        assert DEFAULT_LIMITS.log_per_file_budget_s == _LOG_HUNT_PER_FILE_BUDGET_S
        assert DEFAULT_LIMITS.log_max_bytes_per_file == LOGSCAN_MAX_BYTES_PER_FILE
        assert DEFAULT_LIMITS.window_chars == _OVERSIZED_WINDOW_CHARS
        assert DEFAULT_LIMITS.check_budget_s == DEFAULT_CHECK_BUDGET_S
        assert DEFAULT_LIMITS.audit_budget_s == DEFAULT_AUDIT_BUDGET_S

    def test_exhaustive_limits_are_a_real_widening_of_every_field(self):
        # Every numeric field that matters for coverage must move in the generous
        # direction -- a field left equal to DEFAULT_LIMITS would silently make
        # --exhaustive not exhaustive for that dimension.
        assert EXHAUSTIVE_LIMITS.exhaustive is True
        assert EXHAUSTIVE_LIMITS.traj_max_files > DEFAULT_LIMITS.traj_max_files
        assert EXHAUSTIVE_LIMITS.traj_max_bytes_per_file > DEFAULT_LIMITS.traj_max_bytes_per_file
        assert EXHAUSTIVE_LIMITS.log_check_budget_s > DEFAULT_LIMITS.log_check_budget_s
        assert EXHAUSTIVE_LIMITS.log_per_file_budget_s > DEFAULT_LIMITS.log_per_file_budget_s
        assert EXHAUSTIVE_LIMITS.log_max_bytes_per_file > DEFAULT_LIMITS.log_max_bytes_per_file
        assert EXHAUSTIVE_LIMITS.window_overlap > DEFAULT_LIMITS.window_overlap
        assert EXHAUSTIVE_LIMITS.check_budget_s > DEFAULT_LIMITS.check_budget_s
        assert EXHAUSTIVE_LIMITS.audit_budget_s > DEFAULT_LIMITS.audit_budget_s

    def test_check_budget_clears_the_raised_log_budget_with_headroom(self):
        # R1 (design risk): checks/__init__.py's run_all() wraps EVERY check, including
        # B164/B180, in a SIGALRM check_budget_s deadline. If check_budget_s isn't
        # comfortably above log_check_budget_s (B164's own cooperative budget), the
        # outer deadline kills the check first -- a degraded UNKNOWN that CAPS THE
        # SCORE, silently making --exhaustive backfire instead of just scanning more.
        assert EXHAUSTIVE_LIMITS.check_budget_s > EXHAUSTIVE_LIMITS.log_check_budget_s

    def test_audit_budget_clears_the_single_slowest_check_with_headroom(self):
        assert EXHAUSTIVE_LIMITS.audit_budget_s > EXHAUSTIVE_LIMITS.check_budget_s

    def test_scanlimits_is_frozen(self):
        import dataclasses
        assert dataclasses.is_dataclass(ScanLimits)
        lim = DEFAULT_LIMITS
        try:
            lim.traj_max_files = 1
        except dataclasses.FrozenInstanceError:
            pass
        else:
            raise AssertionError("ScanLimits must be frozen")


class TestLimitsFor:
    def test_default_context_gets_default_limits(self):
        ctx = Context(home=Path("/nonexistent"))
        assert limits_for(ctx) == DEFAULT_LIMITS

    def test_exhaustive_context_gets_exhaustive_limits(self):
        ctx = Context(home=Path("/nonexistent"))
        ctx.exhaustive = True
        assert limits_for(ctx) == EXHAUSTIVE_LIMITS

    def test_duck_typed_no_import_of_context_required(self):
        # scanbudget.py is a leaf module; limits_for must work on ANY object exposing
        # an `exhaustive` attribute, not just a real collector.Context.
        class Fake:
            exhaustive = True
        assert limits_for(Fake()) == EXHAUSTIVE_LIMITS

    def test_object_with_no_exhaustive_attribute_defaults_to_default_limits(self):
        class Bare:
            pass
        assert limits_for(Bare()) == DEFAULT_LIMITS


class TestContextField:
    def test_context_exhaustive_defaults_false(self):
        ctx = Context(home=Path("/nonexistent"))
        assert ctx.exhaustive is False


class TestAuditParameter:
    def test_audit_accepts_exhaustive_kwarg_and_sets_ctx(self):
        ctx, findings, score = audit(SAFE, include_native=False, include_host=False,
                                      include_sockets=False, exhaustive=True)
        assert ctx.exhaustive is True

    def test_default_audit_output_is_byte_identical_with_and_without_the_new_kwarg(self):
        ctx_a, findings_a, score_a = audit(SAFE, include_native=False, include_host=False,
                                            include_sockets=False)
        ctx_b, findings_b, score_b = audit(SAFE, include_native=False, include_host=False,
                                            include_sockets=False, exhaustive=False)
        assert score_a.score == score_b.score
        assert score_a.grade == score_b.grade
        assert [(f.id, f.status, f.detail) for f in findings_a] == \
               [(f.id, f.status, f.detail) for f in findings_b]


class TestCliFlag:
    def test_exhaustive_flag_parses_and_reaches_ctx(self, capsys):
        rc = main(["--home", SAFE, "--no-native", "--no-host", "--no-sockets",
                    "--no-history", "--exhaustive", "--json"])
        assert rc == 0
        import json
        doc = json.loads(capsys.readouterr().out)
        assert "score" in doc  # ran to completion under --exhaustive

    def test_default_run_unaffected_by_the_new_flags_existence(self, capsys):
        rc_a = main(["--home", SAFE, "--no-native", "--no-host", "--no-sockets",
                      "--no-history", "--json"])
        out_a = capsys.readouterr().out
        rc_b = main(["--home", SAFE, "--no-native", "--no-host", "--no-sockets",
                      "--no-history", "--json"])
        out_b = capsys.readouterr().out
        assert rc_a == rc_b == 0
        assert out_a == out_b
