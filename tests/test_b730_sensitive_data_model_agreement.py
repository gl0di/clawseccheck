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
