"""B-635 — `assessed` and `_danger_coverage_gap` used to read `pool[0].ctx` alone, so
both were blind on the plugin path: `pool[0]` is the `PLUGIN-VET` container, which never
sets `.ctx` (only `.bundled_contexts`). A bundled skill that hit a collector cap (size /
file-count / nesting, or an unreadable file) contributed nothing to either consumer, so
the plugin's headline was not floored where it should have been.

Fixed by folding both consumers over `_pool_contexts(pool)` — the same two-source fold
(`f.ctx` on any pool member, `f.bundled_contexts` on the plugin container) `_pool_capabilities`
already used for `has_code`/`families` since B-628.

Built from the dossier's own inputs (`SimpleNamespace` contexts, a real `_plugin_finding`
container), matching this suite's existing precedent in test_b628_plugin_code_measurable.py,
rather than materialising real files past a real collector cap.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from types import SimpleNamespace

from clawseccheck.catalog import HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import _custom
from clawseccheck.checks._mcp import _plugin_finding
from clawseccheck.dossier import build_profile


def _axis(profile, name):
    for a in profile.axes:
        if a.axis == name:
            return a
    raise AssertionError(f"axis {name!r} not in profile")


def test_a_bundled_skill_hitting_a_collector_cap_floors_the_plugin_headline():
    """The reported case: a bundled skill's OWN context recorded a cap hit
    (`ctx.limit_hits`) and its own B13 verdict is UNKNOWN (not enough content read to
    reach a confident PASS) -- nothing else about the plugin looks wrong. Before B-635
    this rendered a clean "INSTALL" headline one line above an axis admitting it never
    finished looking; after, the coverage gap floors it to CAUTION/WARN.
    """
    ctx_capped = SimpleNamespace(
        installed_skills={"bundled": object()},
        installed_skill_py={"bundled": [("run.py", "print('hi')\n")]},
        limit_hits=["bundled skill 'bundled' hit the per-skill file cap"],
    )
    # The bundled skill's own B13 pass could not reach a verdict within the cap --
    # engine_degraded is deliberately False and the detail deliberately omits "coverage
    # is incomplete", so this finding can ONLY floor the headline through leg 2
    # (ctx.limit_hits), not legs 1 or 3 -- isolating exactly what B-635 fixes.
    b13_unknown = _custom(
        "B13", HIGH, UNKNOWN,
        "No installed third-party skill could be fully inspected within limits.",
        "Re-run with more headroom.",
    )
    container = _plugin_finding(
        "HIGH", UNKNOWN, "plugin 'demo': scan incomplete", "Re-run without a budget cap."
    )
    container.bundled_contexts = [ctx_capped]
    container.ring_findings = [b13_unknown]

    profile = build_profile(container, "demo", "plugin")

    assert _axis(profile, "danger").status == UNKNOWN, _axis(profile, "danger").reason
    # Non-vacuity: every OTHER axis must look clean, or a floor there (not the coverage
    # gap) could explain the result below and this test would prove nothing about B-635.
    for name in ("build", "behavior", "persistence", "connections"):
        axis = _axis(profile, name)
        assert axis.status == PASS, f"{name}: {axis.status} ({axis.reason})"

    assert profile.overall_status == WARN, (
        f"expected the coverage gap to floor the headline to WARN, got "
        f"{profile.overall_status!r} — a bundled skill's cap hit went unseen"
    )
    assert profile.verdict == "CAUTION", profile.verdict


def test_b_a_fully_scanned_clean_plugin_is_not_floored():
    """Negative control: the same shape, but the bundled skill's scan actually
    completed (no `limit_hits`, a real B13 PASS instead of an UNKNOWN) -- the floor
    must not fire on a target nothing was ever held back on."""
    ctx_clean = SimpleNamespace(
        installed_skills={"bundled": object()},
        installed_skill_py={"bundled": [("run.py", "print('hi')\n")]},
        limit_hits=[],
    )
    container = _plugin_finding(
        "LOW", PASS, "plugin 'demo': no issues found", "",
    )
    container.bundled_contexts = [ctx_clean]
    container.ring_findings = []

    profile = build_profile(container, "demo", "plugin")

    assert _axis(profile, "danger").status == PASS, _axis(profile, "danger").reason
    assert profile.overall_status == PASS, (
        f"a fully-scanned clean plugin must not be floored: got {profile.overall_status!r}"
    )
    assert profile.verdict == "INSTALL", profile.verdict


def test_c_assessed_reaches_a_bundled_context_not_just_pool_zero():
    """Unit-level: `assessed`'s own fold, isolated from `_danger_coverage_gap` (no
    `limit_hits`, no UNKNOWN danger finding at all -- an empty pool[0] that carries no
    `.ctx` of its own must still see a bundled skill's `installed_skills`)."""
    ctx_with_skill = SimpleNamespace(
        installed_skills={"bundled": object()},
        installed_skill_py={"bundled": [("run.py", "print('hi')\n")]},
        limit_hits=[],
    )
    container = _plugin_finding("LOW", UNKNOWN, "plugin 'demo': nothing fired", "")
    container.bundled_contexts = [ctx_with_skill]
    container.ring_findings = []

    profile = build_profile(container, "demo", "plugin")

    # Every axis reads PASS ("looked, nothing found"), never the "not assessed" UNKNOWN
    # -- which is what `assessed=False` would have forced on every empty bucket.
    for axis in profile.axes:
        assert axis.status == PASS, f"{axis.axis}: {axis.status} ({axis.reason})"
