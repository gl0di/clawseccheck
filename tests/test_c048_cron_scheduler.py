"""C048 — advisory UNKNOWN for top-level `cron` scheduler persistence surface.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN
from clawseccheck.checks import check_cron_scheduler
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_HEBREW = re.compile(r"[֐-׿]")


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def test_c048_cron_present_is_unknown():
    f = check_cron_scheduler(_ctx({"cron": {"nightly": {"task": "healthcheck"}}}))
    assert f.status == UNKNOWN
    assert any("cron" in line.lower() for line in f.evidence)


def test_c048_cron_absent_is_pass():
    f = check_cron_scheduler(_ctx({"gateway": {"bind": "127.0.0.1:8080"}}))
    assert f.status == PASS


def test_c048_empty_cron_is_pass():
    f = check_cron_scheduler(_ctx({"cron": {}}))
    assert f.status == PASS


def test_c048_never_fails():
    f = check_cron_scheduler(_ctx({"cron": "daily"}))
    assert f.status == UNKNOWN



def test_c048_bad_fixture_unknown():
    assert check_cron_scheduler(collect(FIXTURES / "bad_c048_cron_scheduler")).status == UNKNOWN


def test_c048_clean_fixture_passes():
    assert check_cron_scheduler(collect(FIXTURES / "clean_c048_cron_scheduler")).status == PASS


def test_c048_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_c048_cron_scheduler", include_native=False)
    ids = {f.id for f in findings}
    assert "C048" in ids, f"C048 not in audit findings: {sorted(ids)}"
