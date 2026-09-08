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

from clawseccheck.checks import _trifecta_legs
from clawseccheck.collector import Context
from clawseccheck.report import _capability_graph
from clawseccheck.risk import risk_paths

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


def test_the_gateway_password_asymmetry_is_the_one_known_divergence(tmp_path):
    """Pinned as a DELIBERATE state, not left unmeasured -- B-730 item 2.

    `risk.py` and `report.py` both count `gateway.auth.password`; A1 excludes it, on the
    stated ground that it is the gateway's own auth secret rather than agent-readable
    data, and that B1 already emits FAIL/CRITICAL on it. That is a real divergence and it
    is NOT fixed here: unlike the token term, this key IS in the schema, so removing it is
    an observable narrowing that needs its own measurement and its own C-135 pass.

    Asserting the disagreement rather than skipping it means the day someone settles it,
    this test reddens and forces the decision to be recorded instead of drifting in.
    """
    ctx = _gw_ctx(tmp_path, {"auth": {"password": _token("E")}})
    assert _a1_leg(ctx) is False, "A1 excludes the gateway's own auth secret"
    assert _graph_main_secrets(ctx) is True, "the capability graph counts it"
    assert _risk02_present(ctx) == _graph_main_secrets(ctx), (
        "whatever is decided, the chain and the graph must not diverge from each other"
    )
