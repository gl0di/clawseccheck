"""C-645 -- B38 / RISK-05 / RISK-15: version-aware wording for the legacy SSRF alias.

`browser.ssrfPolicy.allowPrivateNetwork` is the retired flat alias of
`dangerouslyAllowPrivateNetwork`. Through OpenClaw 2026.9.6 the gateway's boot-time
self-heal folded it into the canonical key IN MEMORY on every start, so a config carrying
only the legacy key was a live bypass and "the agent browser can reach internal/metadata
IPs" was true today. OpenClaw 2026.9.7 REMOVED that self-heal: the strict schema rejects
the key (executed on 2026.9.6 and 2026.9.7 alike), startup rewrites nothing and the gateway
stops -- but `openclaw doctor --fix` would migrate a true value into the canonical key, so
the config is one Doctor run from a live SSRF bypass.

Dave ruled (2026-09-30): KEEP FAIL. Only the words change, and only on a build KNOWN to be
2026.9.7 or later; every other reader (older build, unknown build, pre-release) keeps the
original wording byte for byte. The sentences live in `checks/_shared.py` so B38, RISK-05
and RISK-15 cannot drift apart.

Each test below fails if the change is reverted: the 9.7 tests assert the new sentences, the
other-build tests assert the old ones, and the verdict tests pin FAIL on both sides.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, HIGH
from clawseccheck.checks import (
    check_browser_ssrf,
    run_all,
    _legacy_ssrf_alias_startup_blocked,
    _startup_repair_removed,
    _LEGACY_SSRF_ALIAS_970_FACT,
    _LEGACY_SSRF_ALIAS_970_ORDER,
)
from clawseccheck.collector import Context
from clawseccheck.risk import (
    RiskPath,
    _R05_WHY_MARKER,
    _R15_FIX_MARKER,
    _R15_WHY_MARKER,
    _reword_legacy_ssrf_alias,
    risk_paths,
)

NEW = "2026.9.7"
OLD = "2026.9.6"

_LEGACY = {"browser": {"ssrfPolicy": {"allowPrivateNetwork": True}}}
_CANON = {"browser": {"ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}}}
_BOTH = {"browser": {"ssrfPolicy": {"allowPrivateNetwork": True,
                                    "dangerouslyAllowPrivateNetwork": True}}}
_SECRETS = {"gateway": {"auth": {"password": "mysecret"}}}
_UNTRUSTED = {"channels": {"telegram": {"contextVisibility": "all",
                                        "dmPolicy": "allowlist",
                                        "groupPolicy": "allowlist"}}}

# The pre-2026.9.7 sentence, verbatim, that must survive on every other build.
_OLD_LEGACY_DETAIL = (
    "browser.ssrfPolicy.allowPrivateNetwork (legacy alias)=true — agent browser can "
    "reach internal/metadata IPs (169.254.169.254 cloud-credential theft)"
)
_OLD_LEGACY_FIX_SENTENCE = (
    "OpenClaw ORs it into dangerouslyAllowPrivateNetwork before the browser ever uses "
    "the policy"
)
_OLD_R05_WHY = (
    "The browser tool is allowed to reach private or internal network addresses "
    "(browser.ssrfPolicy.dangerouslyAllowPrivateNetwork is set or B38 fails), and the "
    "agent has access to sensitive credentials. A prompt-injection payload in a web page "
    "can redirect the browser to internal services (metadata APIs, credential stores) and "
    "exfiltrate the retrieved data."
)
_OLD_R15_LEG = (
    "and the browser is allowed to reach private/internal addresses "
    "(browser.ssrfPolicy.dangerouslyAllowPrivateNetwork, B38)."
)


def _ctx(cfg, installed):
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.installed_dist_version = installed
    return c


def _b38(cfg, installed):
    return check_browser_ssrf(_ctx(cfg, installed))


def _risk(cfg, installed, rid):
    ctx = _ctx(cfg, installed)
    paths = risk_paths(ctx, run_all(ctx))
    return next((p for p in paths if p.id == rid), None), [p.id for p in paths]


# ------------------------------------------------------------------ the predicate

def test_startup_repair_removed_truth_table():
    assert _startup_repair_removed(_ctx({}, "2026.9.7")) is True
    assert _startup_repair_removed(_ctx({}, "2026.10.1")) is True
    assert _startup_repair_removed(_ctx({}, "2027.1.1")) is True
    assert _startup_repair_removed(_ctx({}, "2026.9.6")) is False
    assert _startup_repair_removed(_ctx({}, "2026.7.1-2")) is False
    # unknown / unorderable builds keep the pre-9.7 wording rather than assert a fact
    assert _startup_repair_removed(_ctx({}, None)) is False
    assert _startup_repair_removed(_ctx({}, "")) is False
    assert _startup_repair_removed(_ctx({}, "2026.9.7-beta.1")) is False


def test_startup_repair_removed_never_reads_the_saved_by_stamp():
    # meta.lastTouchedVersion names the build that last SAVED the file; a downgrade since
    # would make "the gateway will not start" false. Only the installed build counts.
    cfg = {"meta": {"lastTouchedVersion": NEW}}
    assert _startup_repair_removed(_ctx(cfg, None)) is False
    assert _startup_repair_removed(_ctx(cfg, OLD)) is False


def test_alias_blocked_predicate_needs_literal_true_and_the_new_build():
    assert _legacy_ssrf_alias_startup_blocked(_ctx(_LEGACY, NEW), _LEGACY) is True
    assert _legacy_ssrf_alias_startup_blocked(_ctx(_BOTH, NEW), _BOTH) is True
    assert _legacy_ssrf_alias_startup_blocked(_ctx(_LEGACY, OLD), _LEGACY) is False
    assert _legacy_ssrf_alias_startup_blocked(_ctx(_LEGACY, None), _LEGACY) is False
    # the canonical key alone is live on every build: nothing to reword
    assert _legacy_ssrf_alias_startup_blocked(_ctx(_CANON, NEW), _CANON) is False
    # `is True`, not truthiness -- same coercion-proof gate as B38 itself
    for v in ("true", 1, [1], {"x": 1}, False, None):
        cfg = {"browser": {"ssrfPolicy": {"allowPrivateNetwork": v}}}
        assert _legacy_ssrf_alias_startup_blocked(_ctx(cfg, NEW), cfg) is False, v


# ------------------------------------------------------------------------- B38

def test_b38_legacy_only_on_2026_9_7_is_still_a_fail():
    f = _b38(_LEGACY, NEW)
    assert f.status == FAIL


def test_b38_legacy_only_on_2026_9_7_detail_says_the_true_thing():
    f = _b38(_LEGACY, NEW)
    assert "the gateway will not start" in f.detail
    assert "doctor --fix" in f.detail
    assert "dangerouslyAllowPrivateNetwork=true" in f.detail
    # the present-tense claim that stopped being true on 2026.9.7 is gone ...
    assert "— agent browser can reach" not in f.detail
    # ... and the loud consequence is still stated, as a future one
    assert "once migrated" in f.detail
    assert "169.254.169.254" in " ".join(f.evidence)


def test_b38_legacy_only_on_2026_9_7_fix_does_not_advise_migrating_a_true_value():
    f = _b38(_LEGACY, NEW)
    assert _LEGACY_SSRF_ALIAS_970_ORDER in f.fix
    assert _LEGACY_SSRF_ALIAS_970_FACT in f.fix
    # the old advice ("... and run 'openclaw doctor --fix' to migrate it") is exactly the
    # step that turns the flag live on this build
    assert "to migrate it." not in f.fix
    assert _OLD_LEGACY_FIX_SENTENCE not in f.fix
    assert "doctor --fix" in f.fix


@pytest.mark.parametrize("installed", [OLD, "2026.9.4", None, "2026.9.7-beta.1", ""])
def test_b38_legacy_only_on_other_builds_keeps_the_original_wording(installed):
    f = _b38(_LEGACY, installed)
    assert f.status == FAIL
    assert f.detail == _OLD_LEGACY_DETAIL
    assert _OLD_LEGACY_FIX_SENTENCE in f.fix
    assert "gateway will not start" not in f.detail + f.fix
    assert _LEGACY_SSRF_ALIAS_970_FACT not in f.detail + f.fix


def test_b38_verdict_is_fail_on_every_build():
    # Dave, 2026-09-30: KEEP FAIL. The wording is version-aware; the verdict is not.
    for installed in (None, "2026.8.2", OLD, NEW, "2026.9.8", "2026.10.1"):
        assert _b38(_LEGACY, installed).status == FAIL, installed
        assert _b38(_BOTH, installed).status == FAIL, installed


def test_b38_canonical_key_only_is_unchanged_on_2026_9_7():
    f = _b38(_CANON, NEW)
    assert f.status == FAIL
    assert "gateway will not start" not in f.detail + f.fix
    assert f.detail == _b38(_CANON, OLD).detail
    assert f.fix == _b38(_CANON, OLD).fix


def test_b38_nosandbox_only_is_unchanged_on_2026_9_7():
    cfg = {"browser": {"noSandbox": True}}
    assert _b38(cfg, NEW).detail == _b38(cfg, OLD).detail
    assert _b38(cfg, NEW).fix == _b38(cfg, OLD).fix


def test_b38_both_keys_on_2026_9_7_use_the_new_wording():
    # The legacy key is still in the file, so this config does not start on 2026.9.7 either.
    f = _b38(_BOTH, NEW)
    assert f.status == FAIL
    assert "dangerouslyAllowPrivateNetwork/allowPrivateNetwork (legacy alias)=true" in f.detail
    assert "the gateway will not start" in f.detail
    assert _LEGACY_SSRF_ALIAS_970_ORDER in f.fix


def test_b38_stamp_never_substitutes_for_the_installed_build():
    cfg = {"meta": {"lastTouchedVersion": NEW}, **_LEGACY}
    assert _b38(cfg, None).detail == _OLD_LEGACY_DETAIL
    assert _b38(cfg, OLD).detail == _OLD_LEGACY_DETAIL


def test_b38_legacy_false_or_string_is_not_a_trigger_on_2026_9_7():
    for v in (False, "true"):
        cfg = {"browser": {"ssrfPolicy": {"allowPrivateNetwork": v,
                                          "allowedHostnames": ["example.com"]}}}
        assert _b38(cfg, NEW).status != FAIL


# ------------------------------------------------------------------ RISK-05 / 15

def test_risk05_legacy_only_on_2026_9_7_still_fires_with_corrected_wording():
    cfg = {**_LEGACY, **_SECRETS}
    p, ids = _risk(cfg, NEW, "RISK-05")
    assert p is not None, ids
    assert p.severity == HIGH
    assert _LEGACY_SSRF_ALIAS_970_FACT in p.why
    assert "The browser tool is allowed to reach" not in p.why
    assert p.fix.endswith(_LEGACY_SSRF_ALIAS_970_ORDER)


def test_risk05_legacy_only_on_other_builds_keeps_the_original_text():
    cfg = {**_LEGACY, **_SECRETS}
    for installed in (None, OLD, "2026.9.7-beta.1"):
        p, ids = _risk(cfg, installed, "RISK-05")
        assert p is not None, (installed, ids)
        assert p.why == _OLD_R05_WHY, installed
        assert _LEGACY_SSRF_ALIAS_970_ORDER not in p.fix
        # and it is the SAME text the canonical key produces -- nothing legacy-specific
        canon, _ = _risk({**_CANON, **_SECRETS}, installed, "RISK-05")
        assert (p.why, p.fix) == (canon.why, canon.fix)


def test_risk05_canonical_key_is_unchanged_on_2026_9_7():
    p, _ = _risk({**_CANON, **_SECRETS}, NEW, "RISK-05")
    assert p is not None
    assert p.why == _OLD_R05_WHY
    assert _LEGACY_SSRF_ALIAS_970_ORDER not in p.fix


def test_risk15_legacy_only_on_2026_9_7_still_fires_with_corrected_wording():
    cfg = {**_UNTRUSTED, **_LEGACY}
    p, ids = _risk(cfg, NEW, "RISK-15")
    assert p is not None, ids
    assert p.severity == HIGH
    assert _LEGACY_SSRF_ALIAS_970_FACT in p.why
    assert _OLD_R15_LEG not in p.why
    assert _LEGACY_SSRF_ALIAS_970_ORDER in p.fix
    # the rest of the fix is untouched and the chain sentence still closes it
    assert "blockedHostnames" in p.fix
    assert p.fix.endswith(" Breaking either leg breaks the chain.")


def test_risk15_legacy_only_on_other_builds_keeps_the_original_text():
    for installed in (None, OLD, "2026.9.7-beta.1"):
        p, ids = _risk({**_UNTRUSTED, **_LEGACY}, installed, "RISK-15")
        assert p is not None, (installed, ids)
        assert _OLD_R15_LEG in p.why
        assert _LEGACY_SSRF_ALIAS_970_ORDER not in p.fix
        canon, _ = _risk({**_UNTRUSTED, **_CANON}, installed, "RISK-15")
        assert (p.why, p.fix) == (canon.why, canon.fix)


def test_risk15_canonical_key_is_unchanged_on_2026_9_7():
    p, _ = _risk({**_UNTRUSTED, **_CANON}, NEW, "RISK-15")
    assert p is not None
    assert _OLD_R15_LEG in p.why
    assert _LEGACY_SSRF_ALIAS_970_ORDER not in p.fix


def test_risk15_nosandbox_only_is_unchanged_on_2026_9_7():
    cfg = {**_UNTRUSTED, "browser": {"noSandbox": True}}
    new, _ = _risk(cfg, NEW, "RISK-15")
    old, _ = _risk(cfg, OLD, "RISK-15")
    assert new is not None and old is not None
    assert (new.why, new.fix) == (old.why, old.fix)


def test_risk_chains_still_fire_for_the_legacy_alias_on_every_build():
    # The trigger is untouched (Dave: keep FAIL) -- only wording is version-aware.
    for installed in (None, OLD, NEW):
        assert _risk({**_LEGACY, **_SECRETS}, installed, "RISK-05")[0] is not None
        assert _risk({**_UNTRUSTED, **_LEGACY}, installed, "RISK-15")[0] is not None


# ------------------------------------------- the post-hoc rewrite and its markers

def test_the_rewrite_markers_are_present_in_the_rules_own_text():
    # The rewrite swaps everything BEFORE a marker inside the rule's own literal; a marker
    # that drifted out of the literal would silently degrade it to the fail-closed branch.
    r05, _ = _risk({**_CANON, **_SECRETS}, None, "RISK-05")
    r15, _ = _risk({**_UNTRUSTED, **_CANON}, None, "RISK-15")
    assert _R05_WHY_MARKER in r05.why
    assert _R15_WHY_MARKER in r15.why
    assert _R15_FIX_MARKER in r15.fix
    assert r15.fix.endswith(_R15_FIX_MARKER)


def test_the_rewrite_keeps_the_rules_tail_text_verbatim():
    for cfg_base, rid, marker in (
        ({**_SECRETS}, "RISK-05", _R05_WHY_MARKER),
        ({**_UNTRUSTED}, "RISK-15", _R15_WHY_MARKER),
    ):
        old, _ = _risk({**cfg_base, **_CANON}, NEW, rid)
        new, _ = _risk({**cfg_base, **_LEGACY}, NEW, rid)
        assert old.why.partition(marker)[2] == new.why.partition(marker)[2]
        # the chain, title and severity are the rule's own -- only why/fix are reworded
        assert (old.title, old.chain, old.severity) == (new.title, new.chain, new.severity)


def test_the_rewrite_fails_closed_when_a_marker_has_drifted():
    ctx = _ctx(_LEGACY, NEW)
    drifted = RiskPath(id="RISK-XX", severity=HIGH, title="t", chain=["a"],
                       why="ORIGINAL WHY TEXT", fix="ORIGINAL FIX TEXT")
    got = _reword_legacy_ssrf_alias(drifted, ctx, _LEGACY, lead="CORRECTED LEAD.",
                                    why_marker=" no such marker",
                                    fix_marker=" nor this one")
    # the corrected lead is shown, and the original text is kept whole behind it
    assert got.why == "CORRECTED LEAD. ORIGINAL WHY TEXT"
    assert got.fix == "ORIGINAL FIX TEXT " + _LEGACY_SSRF_ALIAS_970_ORDER


def test_the_rewrite_returns_the_original_object_on_any_other_build():
    path = RiskPath(id="RISK-XX", severity=HIGH, title="t", chain=["a"],
                    why="W", fix="F")
    for installed in (None, OLD, "2026.9.7-beta.1"):
        got = _reword_legacy_ssrf_alias(path, _ctx(_LEGACY, installed), _LEGACY,
                                        lead="L.", why_marker=" W")
        assert got is path, installed


def test_generated_checks_doc_shows_the_reader_independent_risk_text():
    # scripts/gen_checks_docs.py reads the rules' own literals; a rewrite done by
    # restructuring the literal (an f-string slot, a conditional) leaks "{lead}" and "..."
    # placeholders into docs/CHECKS.md. The rules keep plain literals and rewrite afterwards.
    doc = (Path(__file__).resolve().parent.parent / "docs" / "CHECKS.md").read_text(
        encoding="utf-8")
    assert "{lead}" not in doc and "{browser_leg}" not in doc
    assert "The browser tool is allowed to reach private or internal network addresses" in doc
    assert "the browser is allowed to reach" in doc
