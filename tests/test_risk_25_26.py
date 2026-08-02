"""RISK-25 (I-030) and RISK-26 (I-031): pure finding-correlation chains.

Both rules read NO config themselves -- only `_finding_status(findings, "<id>")` on
findings already emitted by other checks (B325/B174 for RISK-25; B175/B26/B171/B179 for
RISK-26). See clawseccheck/risk.py around "I-030 / RISK-25" and "I-031 / RISK-26" for the
design rationale. That is the whole safety argument these tests exist to pin: since
every leg is a synthetic Finding injected here (never a crafted config), a chain firing
can only ever be attributed to the correlation logic itself, never to some check this
file accidentally re-triggers.

Idiom mirrors tests/test_risk.py's RISK-23 section (`_anchor` / `extra_findings=`):
anchors/legs are synthetic Findings appended to a real (empty-config) run_all() result,
relying on `_finding_status`'s documented "last entry wins" override semantics.

B-435 update: RISK-26's B171/B179 arms also read the correlated Finding's `.evidence`
(never fresh config) to discriminate a genuinely ingress-shaped WARN sub-signal from a
non-ingress one folded into the same status -- see `_r26_b171_ingress_arm`/
`_r26_b179_ingress_arm` in risk.py. The synthetic-leg tests below cover that logic in
isolation; the `Risk26EndToEnd` section at the bottom of this file runs the two false-
positive repros (and a genuine-fire case) through the real checks via `audit()`, per
CLAWSECCHECK-B-435's own test plan -- the bug shipped precisely because no end-to-end
fixture existed, only synthetic legs.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, HIGH, MEDIUM, PASS, UNKNOWN, WARN, Finding
from clawseccheck.checks import run_all
from clawseccheck.collector import Context
from clawseccheck.risk import risk_paths

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# ──────────────────────────────────────────────────────────────────────────────
# Helpers (mirrors tests/test_risk.py's _ctx / _paths / _anchor)
# ──────────────────────────────────────────────────────────────────────────────


def _ctx(cfg: dict) -> Context:
    ctx = Context(home=Path("/nonexistent"))
    ctx.config = cfg
    return ctx


def _paths(cfg: dict, extra_findings=None):
    ctx = _ctx(cfg)
    f = run_all(ctx)
    if extra_findings:
        f = list(f) + list(extra_findings)
    return risk_paths(ctx, f)


def _leg(cid: str, status: str = WARN, evidence: list | None = None) -> Finding:
    """A synthetic Finding used purely to set one leg's status (and, for B171/B179,
    evidence — see B-435) for correlation."""
    return Finding(cid, "synthetic leg", HIGH, status, "detail", "fix", "Test",
                    evidence=evidence or [])


def _ids(paths):
    return [p.id for p in paths]


# ──────────────────────────────────────────────────────────────────────────────
# RISK-25 -- B325 (WARN) + B174 (WARN|FAIL)
# ──────────────────────────────────────────────────────────────────────────────


def test_risk25_both_legs_fire():
    paths = _paths({}, extra_findings=[_leg("B325", WARN), _leg("B174", WARN)])
    p = next((p for p in paths if p.id == "RISK-25"), None)
    assert p is not None, _ids(paths)
    assert p.id == "RISK-25"
    assert p.severity == MEDIUM


def test_risk25_b174_fail_also_fires():
    """Docstring says B174 in (WARN, FAIL) satisfies the leg -- pin the FAIL branch too."""
    paths = _paths({}, extra_findings=[_leg("B325", WARN), _leg("B174", FAIL)])
    assert any(p.id == "RISK-25" for p in paths), _ids(paths)


def test_risk25_only_b325_no_fire():
    paths = _paths({}, extra_findings=[_leg("B325", WARN)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_only_b174_no_fire():
    paths = _paths({}, extra_findings=[_leg("B174", WARN)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_neither_leg_no_fire():
    paths = _paths({})
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_b325_pass_does_not_count():
    """B325 must be exactly WARN -- a PASS (canonical feed) must not satisfy the leg."""
    paths = _paths({}, extra_findings=[_leg("B325", PASS), _leg("B174", WARN)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_b325_fail_does_not_count():
    """B325 is documented WARN-only (never FAIL); the rule's own predicate is
    `!= WARN: return None`, so even a hypothetical FAIL must not satisfy this leg."""
    paths = _paths({}, extra_findings=[_leg("B325", FAIL), _leg("B174", WARN)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_b325_unknown_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B325", UNKNOWN), _leg("B174", WARN)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_b174_pass_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B325", WARN), _leg("B174", PASS)])
    assert not any(p.id == "RISK-25" for p in paths)


def test_risk25_b174_unknown_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B325", WARN), _leg("B174", UNKNOWN)])
    assert not any(p.id == "RISK-25" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# RISK-26 -- B175 (FAIL only) + at least one of B26/B171/B179 (WARN|FAIL)
#
# B-435: B171/B179's WARN status is not uniformly ingress-shaped (see risk.py's
# `_r26_b171_ingress_arm`/`_r26_b179_ingress_arm` docstrings), so the synthetic WARN
# legs below carry the same evidence text the real checks emit for the genuinely
# ingress-shaped sub-case, matching the marker each helper looks for. The
# `*_narrow_warn_does_not_fire` tests below pin the opposite: a WARN whose evidence is
# ONLY the non-ingress sub-signal must not count.
# ──────────────────────────────────────────────────────────────────────────────

_B171_ABSENT_GATE_EVIDENCE = [
    "commands.bash enabled (run arbitrary host shell commands (raw RCE))",
    "commands.ownerAllowFrom/allowFrom not configured — any sender the connected, "
    "non-open channel(s) already authorize is treated as command-owner",
]
_B171_USEACCESSGROUPS_ONLY_EVIDENCE = [
    "commands.bash enabled (run arbitrary host shell commands (raw RCE))",
    "commands.useAccessGroups=false — access-group enforcement layer disabled",
]
_B179_WEBHOOK_EVIDENCE = [
    "hooks.enabled — inbound webhook hooks endpoint + mapping execution pipeline enabled",
]
_B179_INTERNAL_ONLY_EVIDENCE = [
    "hooks.internal.enabled — internal hook runtime enabled (all configured internal "
    "hooks may load)",
]


def test_risk26_b175_plus_b26_fires():
    paths = _paths({}, extra_findings=[_leg("B175", FAIL), _leg("B26", WARN)])
    p = next((p for p in paths if p.id == "RISK-26"), None)
    assert p is not None, _ids(paths)
    assert p.id == "RISK-26"
    assert p.severity == HIGH
    assert "quoted/history" in " ".join(p.chain).lower()


def test_risk26_b175_plus_b171_fires():
    paths = _paths({}, extra_findings=[
        _leg("B175", FAIL), _leg("B171", WARN, evidence=_B171_ABSENT_GATE_EVIDENCE),
    ])
    p = next((p for p in paths if p.id == "RISK-26"), None)
    assert p is not None, _ids(paths)
    assert "command surface" in " ".join(p.chain).lower()


def test_risk26_b175_plus_b179_fires():
    paths = _paths({}, extra_findings=[
        _leg("B175", FAIL), _leg("B179", WARN, evidence=_B179_WEBHOOK_EVIDENCE),
    ])
    p = next((p for p in paths if p.id == "RISK-26"), None)
    assert p is not None, _ids(paths)
    assert "webhook" in " ".join(p.chain).lower()


def test_risk26_b175_plus_b171_fail_also_fires():
    """B171 FAIL is never ambiguous (only reached via a wildcard-open gate or a
    no-gate-at-all open channel, both real) -- it counts with NO evidence needed,
    unlike WARN. Pin the FAIL branch too, not just WARN."""
    paths = _paths({}, extra_findings=[_leg("B175", FAIL), _leg("B171", FAIL)])
    assert any(p.id == "RISK-26" for p in paths), _ids(paths)


def test_risk26_all_three_ingress_arms_all_named_in_chain():
    paths = _paths({}, extra_findings=[
        _leg("B175", FAIL),
        _leg("B26", WARN),
        _leg("B171", WARN, evidence=_B171_ABSENT_GATE_EVIDENCE),
        _leg("B179", WARN, evidence=_B179_WEBHOOK_EVIDENCE),
    ])
    p = next(p for p in paths if p.id == "RISK-26")
    chain_text = " ".join(p.chain).lower()
    assert "quoted/history" in chain_text
    assert "command surface" in chain_text
    assert "webhook" in chain_text


# ──────────────────────────────────────────────────────────────────────────────
# B-435: B171/B179 WARN narrowed to their genuinely ingress-shaped sub-signal.
# ──────────────────────────────────────────────────────────────────────────────


def test_risk26_b171_useaccessgroups_only_warn_does_not_fire():
    """Repro B (CLAWSECCHECK-B-435): commands.ownerAllowFrom IS a real, scoped list;
    the only WARN driver is commands.useAccessGroups=false, a secondary enforcement
    layer, not sender scope. Must not count as an ingress arm."""
    paths = _paths({}, extra_findings=[
        _leg("B175", FAIL), _leg("B171", WARN, evidence=_B171_USEACCESSGROUPS_ONLY_EVIDENCE),
    ])
    assert not any(p.id == "RISK-26" for p in paths), _ids(paths)


def test_risk26_b179_hooks_internal_only_warn_does_not_fire():
    """Repro A (CLAWSECCHECK-B-435): hooks.internal.enabled is LOCAL startup module
    loading, not a network-reachable inbound surface -- hooks.enabled (the real
    webhook toggle) is absent. Must not count as an ingress arm."""
    paths = _paths({}, extra_findings=[
        _leg("B175", FAIL), _leg("B179", WARN, evidence=_B179_INTERNAL_ONLY_EVIDENCE),
    ])
    assert not any(p.id == "RISK-26" for p in paths), _ids(paths)


def test_risk26_b171_absent_gate_and_useaccessgroups_still_fires():
    """Both WARN drivers present (gate absent AND useAccessGroups=false) -- the
    absent-gate marker alone is sufficient, regardless of what else co-occurs."""
    paths = _paths({}, extra_findings=[
        _leg("B175", FAIL), _leg("B171", WARN,
                                  evidence=_B171_ABSENT_GATE_EVIDENCE
                                  + ["commands.useAccessGroups=false — access-group "
                                     "enforcement layer disabled"]),
    ])
    assert any(p.id == "RISK-26" for p in paths), _ids(paths)


def test_risk26_b179_hooks_enabled_and_internal_both_set_still_fires():
    """hooks.enabled (real webhook) and hooks.internal.enabled (local loading) both
    configured together -- the genuine webhook evidence line alone is sufficient."""
    paths = _paths({}, extra_findings=[
        _leg("B175", FAIL), _leg("B179", WARN,
                                  evidence=_B179_WEBHOOK_EVIDENCE + _B179_INTERNAL_ONLY_EVIDENCE),
    ])
    assert any(p.id == "RISK-26" for p in paths), _ids(paths)


def test_risk26_only_b175_no_ingress_no_fire():
    """Leg A alone (no untrusted-ingress arm at all) must not fire."""
    paths = _paths({}, extra_findings=[_leg("B175", FAIL)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_only_ingress_leg_no_b175_no_fire():
    """Ingress arm alone, without B175==FAIL, must not fire."""
    paths = _paths({}, extra_findings=[_leg("B26", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)
    paths = _paths({}, extra_findings=[_leg("B171", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)
    paths = _paths({}, extra_findings=[_leg("B179", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_neither_leg_no_fire():
    paths = _paths({})
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_b175_warn_does_not_count_as_leg_a():
    """Docstring is explicit: only B175==FAIL proves the full unattended pipeline; its
    WARN branches (dormant-tool or partial-gap) must NOT satisfy this leg."""
    paths = _paths({}, extra_findings=[_leg("B175", WARN), _leg("B26", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_b175_pass_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B175", PASS), _leg("B26", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_b175_unknown_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B175", UNKNOWN), _leg("B26", WARN)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_ingress_leg_pass_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B175", FAIL), _leg("B26", PASS)])
    assert not any(p.id == "RISK-26" for p in paths)


def test_risk26_ingress_leg_unknown_does_not_count():
    paths = _paths({}, extra_findings=[_leg("B175", FAIL), _leg("B26", UNKNOWN)])
    assert not any(p.id == "RISK-26" for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# Both rules: robustness on empty / unrelated findings -- must never raise
# ──────────────────────────────────────────────────────────────────────────────


def test_empty_findings_list_does_not_raise():
    ctx = _ctx({})
    paths = risk_paths(ctx, [])
    assert not any(p.id in ("RISK-25", "RISK-26") for p in paths)


def test_unrelated_findings_only_does_not_raise():
    ctx = _ctx({})
    unrelated = [
        Finding("B1", "unrelated", HIGH, FAIL, "detail", "fix", "Test"),
        Finding("B999", "unrelated", MEDIUM, WARN, "detail", "fix", "Test"),
    ]
    paths = risk_paths(ctx, unrelated)
    assert not any(p.id in ("RISK-25", "RISK-26") for p in paths)


# ──────────────────────────────────────────────────────────────────────────────
# CLAWSECCHECK-B-435 end-to-end: the two false-positive repros and a genuine-fire
# case, run through the REAL checks via audit() -- never a synthetic Finding. This is
# the coverage gap the ticket names: the bug shipped because only synthetic legs were
# ever tested, so neither repro shape was ever exercised end-to-end.
# ──────────────────────────────────────────────────────────────────────────────


def _risk26_from_fixture(name: str):
    ctx, findings, _ = audit(FIXTURES / name, include_native=False, include_host=False)
    paths = risk_paths(ctx, findings)
    return next((p for p in paths if p.id == "RISK-26"), None)


def test_risk26_repro_a_local_hooks_only_does_not_fire():
    """Repro A (ticket): fixtures/home_safe + tools.profile:'coding' +
    skills.workshop.{autonomous.enabled, approvalPolicy:'auto'} + hooks.internal.enabled
    -- no hooks.enabled, so there is no inbound message path at all. B175 is FAIL and
    B179 is WARN (hooks.internal.enabled is a real, if local-only, load surface), but
    RISK-26 must not fire. (Fixture is named bad_*, not clean_*, despite testing a
    non-firing property: skills.workshop.autonomous+auto-approve alone is a genuine,
    independently-correct B175 FAIL regardless of RISK-26 -- fixtures/clean_* is an
    automatic zero-FAIL-across-the-whole-audit sweep (tests/test_fp_corpus.py) and this
    fixture legitimately has one, just not the RISK-26 one under test here.)"""
    assert _risk26_from_fixture("bad_risk26_workshop_local_hooks_only") is None


def test_risk26_repro_b_owner_scoped_commands_does_not_fire():
    """Repro B (ticket): same base + commands.{bash:true, ownerAllowFrom:['owner-123'],
    useAccessGroups:false} -- the gate IS scoped to the owner; useAccessGroups=false is
    only a secondary enforcement layer. B171 is WARN, but RISK-26 must not fire.
    (Fixture is named bad_*, not clean_*, for the same reason as the repro-A fixture
    above -- see its docstring.)"""
    assert _risk26_from_fixture("bad_risk26_workshop_owner_scoped_commands") is None


def test_risk26_genuine_open_webhook_still_fires_high():
    """RISK-26 must still fire HIGH on a genuine open webhook + autonomous workshop
    combination (hooks.enabled:true, the real inbound surface) -- the fix must not
    weaken real detection while closing the two false-positive repros above."""
    p = _risk26_from_fixture("bad_risk26_workshop_open_webhook")
    assert p is not None
    assert p.severity == HIGH
    assert "webhook" in " ".join(p.chain).lower()


def test_risk26_genuine_absent_command_gate_still_fires_high():
    """C-135 follow-up (independent review of B-435): the shipped e2e coverage proved
    the B179 narrowing fires end-to-end on a genuine positive (the webhook fixture
    above), but had no equivalent end-to-end fixture for B171's narrowed WARN arm --
    only a synthetic-Finding test (test_risk26_b175_plus_b171_fires) exercised that
    direction. `_r26_b171_ingress_arm` and check_privileged_commands_exposure's WARN
    evidence text (checks/_config.py) are coupled only by a literal substring match
    (`_B171_ABSENT_GATE_MARKER`); a future wording edit to the real check without a
    matching risk.py update would silently reopen the exact false-negative this
    marker exists to catch, and no test before this one would have caught it. Same
    base as the repro-B fixture, but commands.bash is enabled with NO owner/allow-from
    gate configured at all (not even a scoped one) -- B171 is WARN (not FAIL, since the
    channel isn't open) carrying the absent-gate marker, and RISK-26 must fire HIGH."""
    p = _risk26_from_fixture("bad_risk26_workshop_absent_gate_nonopen_channel")
    assert p is not None
    assert p.severity == HIGH
    assert "command surface" in " ".join(p.chain).lower()


# ──────────────────────────────────────────────────────────────────────────────
# Regression: existing chains must fire exactly as tests/test_risk.py already pins,
# i.e. RISK-25/RISK-26 must not have altered any other rule's behaviour as a side
# effect (both live in the same `risk_paths` dispatch list).
# ──────────────────────────────────────────────────────────────────────────────


def test_existing_risk01_unaffected():
    cfg = {
        "channels": {"telegram": {"groupPolicy": "open", "dmPolicy": "open"}},
        "tools": {"exec": {"security": "full"}},
        "agents": {"defaults": {"sandbox": {"mode": "off"}}},
    }
    paths = _paths(cfg)
    ids = _ids(paths)
    assert "RISK-01" in ids
    r01 = next(p for p in paths if p.id == "RISK-01")
    assert r01.severity == "CRITICAL"
    assert "telegram" in r01.chain[0]


def test_existing_risk23_unaffected():
    paths = _paths({}, extra_findings=[_leg("B99"), _leg("B150")])
    p = next((p for p in paths if p.id == "RISK-23"), None)
    assert p is not None, _ids(paths)
    assert p.severity == HIGH
