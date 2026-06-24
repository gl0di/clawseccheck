"""B56 (NC-4) Control-UI cross-origin allow-all + B57 (NC-8) plugin approve-all.

Grounded fields (docs.openclaw.ai/gateway/security):
  gateway.controlUi.allowedOrigins           — list; ["*"] = explicit allow-all origins
  plugins.entries.<name>.config.permissionMode — "approve-all" is the tracked dangerous value

Both FAIL only on the explicit dangerous value; default/absent → UNKNOWN/PASS (no FP).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import check_controlui_origins, check_plugin_permission_mode
from clawseccheck.collector import Context, collect
from clawseccheck.i18n import tp

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_HEBREW = re.compile(r"[֐-׿]")


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


# ---------------------------------------------------------------------------
# B56 — Control-UI allowedOrigins
# ---------------------------------------------------------------------------

def test_b56_wildcard_list_fails():
    f = check_controlui_origins(_ctx({"gateway": {"controlUi": {"allowedOrigins": ["*"]}}}))
    assert f.status == FAIL
    assert any("*" in line for line in f.evidence)


def test_b56_wildcard_string_fails():
    f = check_controlui_origins(_ctx({"gateway": {"controlUi": {"allowedOrigins": "*"}}}))
    assert f.status == FAIL


def test_b56_explicit_origins_pass():
    f = check_controlui_origins(
        _ctx({"gateway": {"controlUi": {"allowedOrigins": ["https://ui.example.test"]}}})
    )
    assert f.status == PASS


def test_b56_unset_is_unknown():
    f = check_controlui_origins(_ctx({"gateway": {"controlUi": {"enabled": True}}}))
    assert f.status == UNKNOWN


def test_b56_fail_detail_localized_he():
    f = check_controlui_origins(_ctx({"gateway": {"controlUi": {"allowedOrigins": ["*"]}}}))
    assert _HEBREW.search(tp(f.detail, "he")), f"B56 FAIL detail not localized: {f.detail!r}"


def test_b56_bad_fixture_fails():
    assert check_controlui_origins(collect(FIXTURES / "bad_b56_controlui_origins")).status == FAIL


def test_b56_clean_fixture_passes():
    assert check_controlui_origins(collect(FIXTURES / "clean_b56_controlui_origins")).status == PASS


# ---------------------------------------------------------------------------
# B57 — plugin permissionMode=approve-all
# ---------------------------------------------------------------------------

def test_b57_approve_all_fails_and_names_plugin():
    cfg = {"plugins": {"entries": {"acpx": {"config": {"permissionMode": "approve-all"}}}}}
    f = check_plugin_permission_mode(_ctx(cfg))
    assert f.status == FAIL
    assert any("acpx" in line and "approve-all" in line for line in f.evidence)


def test_b57_one_offender_among_many_fails():
    cfg = {"plugins": {"entries": {
        "safe": {"config": {"permissionMode": "ask"}},
        "risky": {"config": {"permissionMode": "approve-all"}},
    }}}
    f = check_plugin_permission_mode(_ctx(cfg))
    assert f.status == FAIL
    assert any("risky" in line for line in f.evidence)
    assert not any("safe" in line for line in f.evidence)


def test_b57_ask_passes():
    cfg = {"plugins": {"entries": {"acpx": {"config": {"permissionMode": "ask"}}}}}
    assert check_plugin_permission_mode(_ctx(cfg)).status == PASS


def test_b57_no_plugins_is_unknown():
    assert check_plugin_permission_mode(_ctx({"gateway": {}})).status == UNKNOWN


def test_b57_fail_detail_localized_he():
    cfg = {"plugins": {"entries": {"acpx": {"config": {"permissionMode": "approve-all"}}}}}
    f = check_plugin_permission_mode(_ctx(cfg))
    assert _HEBREW.search(tp(f.detail, "he")), f"B57 FAIL detail not localized: {f.detail!r}"


def test_b57_bad_fixture_fails():
    assert check_plugin_permission_mode(collect(FIXTURES / "bad_b57_plugin_approve_all")).status == FAIL


def test_b57_clean_fixture_passes():
    assert check_plugin_permission_mode(collect(FIXTURES / "clean_b57_plugin_approve_all")).status == PASS


# ---------------------------------------------------------------------------
# Both checks are wired into the audit and fire on their fixtures
# ---------------------------------------------------------------------------

def test_both_checks_registered_in_audit():
    from clawseccheck import audit
    _, findings, _ = audit(FIXTURES / "bad_b56_controlui_origins", include_native=False)
    ids = {f.id for f in findings}
    assert {"B56", "B57"} <= ids, f"B56/B57 not both in audit findings: {sorted(ids)}"
