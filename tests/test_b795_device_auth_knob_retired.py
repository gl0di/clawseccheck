"""B-795 — B48's dangerous-flags entry for
``gateway.controlUi.dangerouslyDisableDeviceAuth`` warned about a retired, do-nothing
config key.

Grounded against the installed dist (openclaw@2026.9.3 and re-confirmed on 2026.9.4,
``legacy-*.mjs``): a ``defineLegacyConfigMigration`` entry named
``"dangerouslyDisableDeviceAuth"`` whose message reads *"gateway.controlUi.
dangerouslyDisableDeviceAuth is retired and ignored. Control UI browsers pair through
the normal device flow; run \\"openclaw doctor --fix\\" to remove the legacy key."* —
setting the key to ``true`` no longer disables Control-UI device-identity auth or does
anything else. Before this fix, B48's flat ``_DANGER_FIXED`` table FAILed
unconditionally on any build, framing dead legacy config as a live control-plane auth
bypass.

Same shape as ``test_c471_retired_subjects.py``: a version-scoped subject, not a
retracted one — the leg must stay exactly as it was for any fleet build old enough to
still honour the key.
"""
from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import check_dangerous_overrides
from clawseccheck.collector import Context

RETIRED = "2026.9.3"  # the grounded cutover — see checks/_config.py's own caveat
HONOURED = "2026.9.2"
_CFG = {"gateway": {"controlUi": {"dangerouslyDisableDeviceAuth": True}}}


def _ctx(config, installed=None):
    c = Context(home=Path("/nonexistent"))
    c.config = config
    c.config_found = True
    if installed is not None:
        c.installed_dist_version = installed
    return c


def _b48(config, installed=None):
    return check_dangerous_overrides(_ctx(config, installed))


def test_retired_build_does_not_fail():
    r = _b48(_CFG, RETIRED)
    assert r.status != FAIL, (
        f"B48 FAILed on a key OpenClaw {RETIRED} ignores entirely (detail: {r.detail!r})"
    )
    assert r.status == PASS
    assert not any("dangerouslyDisableDeviceAuth" in e for e in (r.evidence or []))


def test_retired_build_names_the_stale_key_instead_of_hiding_it():
    """The finding is not silent about the leftover line — it explains it is inert."""
    detail = _b48(_CFG, RETIRED).detail or ""
    assert "dangerouslyDisableDeviceAuth" in detail
    assert "retired" in detail
    assert "doctor --fix" in detail
    # Must not claim a live exposure any more.
    assert "device identity auth disabled" not in detail


def test_a_later_build_is_also_retired():
    r = _b48(_CFG, "2026.9.4")
    assert r.status == PASS


def test_the_same_key_still_fails_on_a_build_that_honours_it():
    r = _b48(_CFG, HONOURED)
    assert r.status == FAIL
    assert any("dangerouslyDisableDeviceAuth" in e for e in r.evidence)


def test_an_undeterminable_build_keeps_the_original_fail():
    """Silence/PASS would be a claim about a build we cannot see — the conservative
    default matches every other version-scoped subject in this codebase (C-471,
    B-783): an unknown build keeps the pre-existing verdict."""
    r = _b48(_CFG)
    assert r.status == FAIL
    assert any("dangerouslyDisableDeviceAuth" in e for e in r.evidence)


def test_absent_key_is_unaffected_on_any_build():
    for installed in (RETIRED, HONOURED, None):
        r = _b48({"gateway": {"port": 19001}}, installed)
        assert r.status == PASS
        assert "dangerouslyDisableDeviceAuth" not in (r.detail or "")


def test_a_real_fail_alongside_the_retired_key_still_fails_and_still_explains_it():
    """The retirement note must not get lost when a genuinely dangerous flag also
    fires — folded into whichever finding actually returns, same idiom B10/B175 use."""
    cfg = {
        "gateway": {"controlUi": {"dangerouslyDisableDeviceAuth": True}},
        "agents": {"defaults": {"sandbox": {"docker": {
            "dangerouslyAllowContainerNamespaceJoin": True}}}},
    }
    r = _b48(cfg, RETIRED)
    assert r.status == FAIL
    assert any("ContainerNamespaceJoin" in e for e in r.evidence)
    assert not any("dangerouslyDisableDeviceAuth" in e for e in r.evidence)
    assert "doctor --fix" in (r.detail or "")
