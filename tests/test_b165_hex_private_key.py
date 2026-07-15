"""B165 (C-200, hex-key leg of the crypto-wallet VALUE detection split off C-198):
a bare 0x + 64 hex-char value is SHAPE-IDENTICAL between an Ethereum private key
and a transaction/block hash — a naive shape-only regex would collide with
routine tx-hash discussion in any blockchain-dev skill (grounded during C-198).

Architect-ratified design (2026-07-13): co-occurrence gating — a wallet/key-domain
POSITIVE corroborator must be nearby AND a tx/transaction-hash-specific NEGATIVE
corroborator must be ABSENT nearby. Advisory, WARN-only (never scored, never FAIL).
The BIP39 mnemonic-wordlist leg of the original C-200 scope is explicitly deferred
(needs-decision — wordlist storage + FP-rate measurement never addressed).
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import SKILL_CONTENT_RING, check_hex_private_key_exposure
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# A 64-hex-char value, deliberately non-random / self-evidently a placeholder
# (never a real derived key) — same "obviously fake" convention as this project's
# other secret-shaped test fixtures (e.g. bad_c040_authkey's SSH key literal).
_HEX64 = "deadbeef" * 8


def _ctx(skills: dict[str, str]) -> Context:
    c = Context(home=Path("/nonexistent-b165"))
    c.config = {}
    c.bootstrap = {}
    c.installed_skills = skills
    return c


def test_no_installed_skills_is_unknown():
    assert check_hex_private_key_exposure(Context(home=Path("/x"))).status == UNKNOWN


def test_hex_value_near_private_key_wording_warns():
    blob = f"The wallet private key is 0x{_HEX64}"
    f = check_hex_private_key_exposure(_ctx({"s": blob}))
    assert f.status == WARN


def test_hex_value_near_wallet_wording_warns():
    blob = f"wallet.json contains: 0x{_HEX64}"
    f = check_hex_private_key_exposure(_ctx({"s": blob}))
    assert f.status == WARN


def test_evidence_never_echoes_raw_hex_value():
    """ZKDS: the finding must never carry the raw secret-shaped value, only the
    fact that one was found."""
    blob = f"The wallet private key is 0x{_HEX64}"
    f = check_hex_private_key_exposure(_ctx({"s": blob}))
    assert _HEX64 not in (f.detail or "")
    assert all(_HEX64 not in e for e in (f.evidence or []))


def test_hex_value_near_tx_hash_wording_stays_pass():
    """The core discriminator this check exists for: routine tx-hash discussion
    must NOT false-fire, even though the value is shape-identical to a private key."""
    blob = f"The transaction hash is 0x{_HEX64}"
    f = check_hex_private_key_exposure(_ctx({"s": blob}))
    assert f.status == PASS


def test_hex_value_near_block_hash_wording_stays_pass():
    blob = f"Query the block hash 0x{_HEX64} on the explorer."
    f = check_hex_private_key_exposure(_ctx({"s": blob}))
    assert f.status == PASS


def test_hex_value_near_etherscan_stays_pass():
    blob = f"View it on etherscan.io: 0x{_HEX64}"
    f = check_hex_private_key_exposure(_ctx({"s": blob}))
    assert f.status == PASS


def test_bare_hex_value_no_context_stays_pass():
    """Shape alone is never enough — no wallet/key wording nearby -> PASS."""
    blob = f"Some value: 0x{_HEX64} end of line."
    f = check_hex_private_key_exposure(_ctx({"s": blob}))
    assert f.status == PASS


def test_short_hex_value_does_not_match():
    """Fewer than 64 hex chars is not the shape this check targets (a real
    Ethereum private key / tx hash is exactly 32 bytes = 64 hex chars)."""
    blob = "The wallet private key is 0x" + "deadbeef" * 7  # 56 chars
    f = check_hex_private_key_exposure(_ctx({"s": blob}))
    assert f.status == PASS


def test_fenced_doc_example_stays_pass():
    blob = f"```\nprivate key example: 0x{_HEX64}\n```\nDocumented example, not executed.\n"
    f = check_hex_private_key_exposure(_ctx({"s": blob}))
    assert f.status == PASS


# --------------------------------------------------------------------------- fixtures


def test_clean_fixture_passes():
    ctx = collect(FIXTURES / "clean_b165_wallet_docs")
    f = check_hex_private_key_exposure(ctx)
    assert f.status == PASS, f"Expected PASS, got {f.status}: {f.detail}"


def test_bad_fixture_warns():
    ctx = collect(FIXTURES / "bad_b165_exposed_private_key")
    f = check_hex_private_key_exposure(ctx)
    assert f.status == WARN, f"Expected WARN, got {f.status}: {f.detail}"


def test_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_b165_exposed_private_key", include_native=False)
    ids = {f.id for f in findings}
    assert "B165" in ids, f"B165 not in audit findings: {sorted(ids)}"


def test_in_content_ring():
    """B165 must be in SKILL_CONTENT_RING so the pre-install --vet path runs it too."""
    assert check_hex_private_key_exposure in SKILL_CONTENT_RING


def test_never_scored():
    from clawseccheck.catalog import BY_ID

    assert BY_ID["B165"].scored is False
