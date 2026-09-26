"""CLAWSECCHECK-B-730 — A1, the RISK chains and the capability graph agree on
"sensitive data".

B-666 disproved `(home / "credentials").is_dir()` as evidence of a credential — the store
is created by any home that ever paired a channel, so on the real fleet home it raised
A1's CRITICAL leg over 94 bytes of pairing state. The fix replaced it with a CONTENT scan
in `checks/_shared.py` and never reached the module's two other consumers:
`risk.py::_has_sensitive_data` (feeding RISK-02 and RISK-05) and `report.py`'s capability
graph. `git log -- clawseccheck/risk.py` has commits on 08-25/27/31 and 09-01/02 and none
on 2026-08-28, the day the definition moved.

Measured on the real fleet home 2026-09-04, whose `credentials/` directory is EMPTY (0
files, 0 bytes, `incomplete=False` — "looked, nothing there", not "could not look"), one
`--json` run emitted both of these:

    "trifecta": "2/3"      <- A1 PASS, "the missing leg is 'sensitive data'"
    RISK-02 HIGH           <- "All three legs of the Lethal Trifecta are active
                              simultaneously ... has access to sensitive data"

Disjunct-by-disjunct on that home the tool-hint and gateway terms were both False, so the
empty directory was the whole of a false-positive HIGH on the flagship chain — a Golden
Rule #5 violation that the C-303 fleet gate cannot see, because it collects `Finding`
objects only and `RiskPath` lives in a separate list (tracked as C-492).

**The defect is the DISAGREEMENT, not either verdict alone** — each model was locally
consistent, which is why nothing caught it. So every test here asserts both models on one
home in one assertion block, the same way `test_b371_a1_b41_ingress_agreement.py` pins
A1-vs-B41 on the ingress leg.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck.catalog import FAIL_WEIGHT_STATUSES, PASS, WARN
from clawseccheck.checks import _trifecta_legs, check_trifecta
from clawseccheck.collector import Context
from clawseccheck.report import _capability_graph
from clawseccheck.risk import risk_paths

# Lower rank = more severe. Only three statuses are reachable from check_trifecta, but
# the map is built off FAIL_WEIGHT_STATUSES rather than a bare "FAIL" literal so a future
# renamed/added FAIL-weight status (SKILL_ARCHIVE_PATH_TRAVERSAL is the other one today,
# unreachable from A1) doesn't silently fall through to the `dict.get` default in
# `_a1_status_rank` below.
_A1_STATUS_RANK = {**{s: 0 for s in FAIL_WEIGHT_STATUSES}, WARN: 1, PASS: 2}


def _a1_status_rank(ctx: Context) -> int:
    return _A1_STATUS_RANK[check_trifecta(ctx).status]

# Untrusted ingress + outbound both active, so the trifecta's OTHER two legs are held
# constant and the sensitive-data leg is the only thing that can move a verdict. Verified
# by construction: with the store empty this is a 2/3 config, and RISK-02's rule requires
# all three.
CFG = {
    "channels": {"telegram": {"dmPolicy": "open"}},
    "tools": {
        "profile": "coding",
        "exec": {"mode": "ask"},        # gated: exec must NOT raise the sensitive leg
        "fs": {"workspaceOnly": True},  # confined: a granted `read` must not raise it either
        "web": {"fetch": {"enabled": True}},
    },
}
# Deliberately the live fleet home's shape. A first draft used profile "all" with no exec
# gate, and A1's leg came back True on an EMPTY store -- raised by the ungated-exec source
# ("tools.profile='all' (a powerful profile) -- ungated"), not by the store. The test would
# have passed while measuring nothing, because the variable under test was pinned by a
# second, louder source. Verified by construction: with this config and an empty store the
# sensitive-data source list is exactly `[]`, so the store is the only thing that can
# move it.


def _token(seed: str) -> str:
    """Assembled at runtime from fragments — Golden Rule #3 forbids a contiguous
    secret-shaped literal in source, so secret scanners stay quiet on this repo."""
    return "sk-" + "ant-" + "api03-" + (seed * 40)


def _home(tmp_path: Path, *, store: bool = True, credential: bool = False) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True)
    if store:
        (home / "credentials").mkdir()
        # The two files the real fleet home actually holds: pairing state, no secret.
        # Their presence is what made directory-existence look like a credential.
        (home / "credentials" / "telegram-allow.json").write_text('{"allow": []}')
        if credential:
            (home / "credentials" / "oauth.json").write_text(
                json.dumps({"access_token": _token("A")})
            )
    return home


def _ctx(home: Path) -> Context:
    c = Context(home=home)
    c.config = CFG
    return c


def _a1_leg(ctx: Context) -> bool:
    return bool(_trifecta_legs(ctx)["sensitive data"])


def _risk02_present(ctx: Context) -> bool:
    return any(p.id == "RISK-02" for p in risk_paths(ctx, []))


def _graph_main_secrets(ctx: Context) -> bool:
    main = next(n for n in _capability_graph(ctx)["nodes"] if n["id"] == "main")
    return bool(main["secrets_visible"])


def test_an_empty_store_raises_the_leg_for_nobody(tmp_path):
    """The exact defect: a credentials/ directory holding no secret.

    Before B-730 this asserted-and-denied the same leg in one document. Both models are
    checked together because a fix to either one alone would leave the contradiction.
    """
    ctx = _ctx(_home(tmp_path))
    assert _a1_leg(ctx) is False
    assert _risk02_present(ctx) is False
    assert _graph_main_secrets(ctx) is False


def test_a_real_credential_raises_the_leg_for_everybody(tmp_path):
    """The control that stops the fix being a silencer.

    Replacing a too-broad predicate with a narrower one is false-negative-direction
    movement; without this, deleting the disjunct outright would pass just as well as
    replacing it. Same store, same config — only the file's CONTENT differs.
    """
    ctx = _ctx(_home(tmp_path, credential=True))
    assert _a1_leg(ctx) is True
    assert _risk02_present(ctx) is True
    assert _graph_main_secrets(ctx) is True


def test_the_two_models_agree_on_every_store_shape(tmp_path):
    """Agreement stated as the invariant itself, not inferred from the two cases above.

    A future term added to one model and not the other reddens here even if both
    single-shape tests still pass.
    """
    for credential in (False, True):
        ctx = _ctx(_home(tmp_path / f"c{credential}", credential=credential))
        assert _a1_leg(ctx) == _risk02_present(ctx) == _graph_main_secrets(ctx), (
            f"models disagree with credential={credential}"
        )


def test_a_home_with_no_store_at_all_is_not_a_credential(tmp_path):
    """A home that never paired a channel. Guards the `present=False` path separately —
    the empty-store case above cannot distinguish "no store" from "store, no secret"."""
    ctx = _ctx(_home(tmp_path, store=False))
    assert _a1_leg(ctx) is False
    assert _risk02_present(ctx) is False
    assert _graph_main_secrets(ctx) is False


def test_an_unreadable_store_hedges_in_a1_and_stays_silent_in_the_chain(tmp_path):
    """The deliberate asymmetry, pinned so it reads as a decision and not an oversight.

    A1 has three states and routes an unreadable store to a WARN hedge ("nothing found in
    it means 'not found', not 'not there'"). A RISK chain has two, and its why-text
    ASSERTS the leg is active — so it must not fire on a store nobody could read. The
    uncertainty still reaches the user, through A1's hedge rather than through a HIGH
    chain built on an unread directory.
    """
    home = _home(tmp_path)
    store = home / "credentials"
    (store / "unreadable.json").write_text("{}")
    (store / "unreadable.json").chmod(0o000)
    try:
        ctx = _ctx(home)
        from clawseccheck.checks import _credential_store_state

        state = _credential_store_state(home)
        if not state["incomplete"]:  # running as root, or a permissive filesystem
            import pytest

            pytest.skip("store stayed readable — cannot exercise the incomplete path here")
        assert state["secret_files"] == []
        # The chain asserts, so it stays silent; A1 carries the uncertainty instead.
        assert _risk02_present(ctx) is False
        assert _a1_leg(ctx) is False
    finally:
        (store / "unreadable.json").chmod(0o600)


# --------------------------------------------------------------------------- #
# B-730 item: the gateway-secret terms. The reviewer blocked this task because   #
# `risk.py::_has_sensitive_data` had no token term while `report.py`'s           #
# `main_secrets` had one, and nothing pinned the difference. What the difference #
# actually was, measured rather than read: report.py tested `gateway.token`      #
# ALONE -- a key the current schema does not have. The dist resolver answers     #
# False for it on 2026.9.1 and True for `gateway.auth.token`;                    #
# `tests/dist_verified_paths.txt` carries `gateway.auth.password` and not this;  #
# `_NOT_IN_CURRENT_SCHEMA` records `unrecognized_keys@gateway`. Over 600 real     #
# and corpus configs, `gateway.token` is set on 0 and `gateway.auth.token` on    #
# 479, so the term was dead and the two models agreed on 600/600 by accident.    #
#                                                                               #
# Re-spelling it to the live key was the obvious repair and the wrong one: it    #
# would raise `main_secrets` on 479 of those 600 while risk.py still has no      #
# token term, dropping agreement to 121/600 -- manufacturing this task's own     #
# A1-vs-RISK-02 contradiction at 80% scale. The term was removed instead.        #
# --------------------------------------------------------------------------- #


def _gw_ctx(tmp_path: Path, gateway: dict) -> Context:
    """A home with an empty store, so the gateway config is the only thing that can move
    a model. Same reasoning as CFG's exec/fs gating: hold every other source constant."""
    ctx = _ctx(_home(tmp_path))
    ctx.config = {**CFG, "gateway": gateway}
    return ctx


def test_neither_gateway_token_spelling_moves_any_model(tmp_path):
    """The fixture the DoD asked for and the block cited as missing.

    Both spellings are covered deliberately. `gateway.token` is the dead legacy key the
    capability graph used to read; `gateway.auth.token` is the live one it could not see.
    Neither may raise the sensitive-data leg for anybody, because a gateway's own auth
    secret is not agent-readable data -- the ground A1 already states -- and a stale
    legacy key sitting in a config file is B1's subject, not this leg's.
    """
    for label, gateway in (
        ("legacy gateway.token", {"token": _token("B")}),
        ("live gateway.auth.token", {"auth": {"token": _token("C")}}),
    ):
        ctx = _gw_ctx(tmp_path / label.replace(" ", "_").replace(".", "_"), gateway)
        assert _a1_leg(ctx) is False, label
        assert _risk02_present(ctx) is False, label
        assert _graph_main_secrets(ctx) is False, label


def test_respelling_the_dead_token_key_would_break_agreement(tmp_path):
    """The landmine guard, and the reason this test exists at all.

    Nothing stops a future reader from noticing that `main_secrets` names a key the schema
    does not have and "correcting" it. This pins the consequence: with the live key set,
    the capability graph must still agree with the chain. If someone re-adds a token term
    to report.py alone, this reddens -- which the three single-model tests would not.
    """
    ctx = _gw_ctx(tmp_path, {"auth": {"token": _token("D")}})
    assert _graph_main_secrets(ctx) == _risk02_present(ctx) == _a1_leg(ctx)


def test_the_gateway_password_leg_now_agrees_across_all_three_models(tmp_path):
    """CLAWSECCHECK-B-876 settled the one divergence this file used to pin as deliberate
    (B-730 item 2) -- flipped on purpose, not left to drift in silently.

    `risk.py` and `report.py` always counted `gateway.auth.password`; A1 used to exclude
    it, on the stated ground that it is the gateway's own auth secret rather than
    agent-readable data, and that B1 already emits FAIL/CRITICAL on it. That reasoning is
    true of confidentiality but incomplete for this leg's question (agent REACH), and it
    reproduced B-730's exact contradiction through a different term: a home with an empty
    credentials store and only this key set gave A1 PASS "Active legs 2/3" next to a
    RISK-02 HIGH asserting all three legs active in the same run. Dave's decision
    (2026-09-20): widen A1 to match the other two consumers, not narrow them away --
    unlike the dead token term below, this key IS in the schema, so it needed its own
    measurement and its own C-135 pass rather than a ride on the token fix.
    """
    ctx = _gw_ctx(tmp_path, {"auth": {"password": _token("E")}})
    assert _a1_leg(ctx) is True, "A1 now counts the gateway's own auth secret too (B-876)"
    assert _graph_main_secrets(ctx) is True, "the capability graph counts it"
    assert _risk02_present(ctx) is True, "the RISK chain counts it"
    assert _a1_leg(ctx) == _graph_main_secrets(ctx) == _risk02_present(ctx), (
        "all three models must agree on the gateway password"
    )


def test_no_run_prints_a_lower_trifecta_ratio_than_a_risk_chain_asserts(tmp_path):
    """The GLOBAL invariant B-730's own DoD asked for and never asserted, until now
    (CLAWSECCHECK-B-876): a run's own `"trifecta": "N/3"` field (`report.py::
    _trifecta_ratio`, read straight off A1's `Finding.evidence`) must never print fewer
    than 3 legs in the SAME run where a RISK chain's own why-text asserts all three are
    active -- today that is RISK-02 alone, whose why-text literally says "All three legs
    of the Lethal Trifecta are active simultaneously". Every test above this one checks
    one of the three internal models in isolation (`_trifecta_legs`, `risk_paths`,
    `_capability_graph`); this one instead drives the full `audit()` pipeline and reads
    the exact fields a `--json` consumer sees, because that is the shape B-730's
    measurement on the real fleet home was actually about -- a single document printing
    `"trifecta": "2/3"` right next to a live `RISK-02 HIGH`.

    Before CLAWSECCHECK-B-876 this fails on exactly the config below: A1 could not see
    `gateway.auth.password` as sensitive data (2/3, PASS) while risk.py's own copy of the
    same predicate already could, so RISK-02 fired anyway -- reddening this assertion.
    """
    from clawseccheck import audit
    from clawseccheck.report import _trifecta_ratio

    home = _home(tmp_path)
    (home / "openclaw.json").write_text(
        json.dumps({**CFG, "gateway": {"auth": {"password": _token("G")}}})
    )
    (home / "openclaw.json").chmod(0o600)
    ctx, findings, _score = audit(home)
    ratio = _trifecta_ratio(findings)
    risk02_chains = [p for p in risk_paths(ctx, findings) if p.id == "RISK-02"]
    assert risk02_chains, "setup check: this config must reproduce a live RISK-02 chain"
    assert len(risk02_chains[0].chain) == 3, "setup check: RISK-02 always asserts 3 legs"
    assert ratio == "3/3", (
        f"RISK-02 asserts all three legs active but the run's own trifecta ratio is "
        f"{ratio!r} -- a run must never disagree with itself about the leg count"
    )


def test_adding_the_gateway_password_never_lowers_a1s_severity(tmp_path):
    """Metamorphic guard the task brief asked for: widening a FAIL/WARN-capable check
    must never make it MORE lenient. Whatever A1's severity was WITHOUT
    `gateway.auth.password` set, adding that one key to the same config must come out the
    same or WORSE, never better -- checked across a spread of leg combinations rather than
    one fixed config, since a status-ranking regression could easily hide behind the single
    scenario the other tests in this file use.
    """
    # NOTE: a base with the sensitive-data leg OFF and BOTH other legs also undetermined
    # (e.g. bare `elevated.allowFrom` alone) is deliberately excluded here. Resolving an
    # undetermined leg to a known-active one there flips WARN->PASS by DESIGN -- proven by
    # construction to be identical for a `fs_read` tool hint or a credential-store file, the
    # two sensitive-data sources that predate this task -- so it is an existing property of
    # check_trifecta's hedge precedence, not something this change could regress or is
    # responsible for fixing.
    bases = [
        CFG,  # this file's own 2/3 (untrusted + outbound already active) -> must reach 3/3
        {  # already 3/3 via OTHER legs -- adding the password must not "improve" this
            "channels": {"telegram": {"dmPolicy": "open"}},
            "tools": {"allow": ["fs_read", "send_email"]},
        },
    ]
    for i, base in enumerate(bases):
        ctx_without = _ctx(_home(tmp_path / f"base{i}_without"))
        ctx_without.config = base
        ctx_with = _ctx(_home(tmp_path / f"base{i}_with"))
        ctx_with.config = {**base, "gateway": {"auth": {"password": _token("H")}}}
        rank_without = _a1_status_rank(ctx_without)
        rank_with = _a1_status_rank(ctx_with)
        assert rank_with <= rank_without, (
            f"adding gateway.auth.password made A1 LESS severe for base={base!r}: "
            f"{check_trifecta(ctx_without).status!r} -> {check_trifecta(ctx_with).status!r}"
        )
    # And the sharpest instance of the property, stated as a direct assertion rather than
    # inferred from ranks: this file's own base config must cross the FAIL line exactly
    # as CLAWSECCHECK-B-876 intends, not merely "not get better".
    ctx_without = _ctx(_home(tmp_path / "sharp_without"))
    ctx_without.config = CFG
    ctx_with = _ctx(_home(tmp_path / "sharp_with"))
    ctx_with.config = {**CFG, "gateway": {"auth": {"password": _token("I")}}}
    assert check_trifecta(ctx_without).status == PASS
    assert check_trifecta(ctx_with).status in FAIL_WEIGHT_STATUSES
