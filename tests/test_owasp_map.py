"""OWASP Top 10 for LLM Apps 2025 coverage mapping (additive metadata, no verdict impact)."""
import json

from clawseccheck import audit, render_json
from clawseccheck.catalog import (
    AST_MAP,
    BY_ID,
    OWASP_AST_2026,
    OWASP_LLM_2025,
    OWASP_MAP,
    ast_for,
    owasp_for,
)


# ---- mapping integrity ----
def test_every_mapped_id_is_a_real_check():
    for cid in OWASP_MAP:
        assert cid in BY_ID, f"OWASP_MAP references unknown check id {cid!r}"


def test_every_code_is_a_valid_owasp_llm_2025_code():
    for cid, codes in OWASP_MAP.items():
        assert isinstance(codes, tuple)
        for code in codes:
            assert code in OWASP_LLM_2025, f"{cid} maps to unknown OWASP code {code!r}"


def test_owasp_for_unmapped_returns_empty():
    assert owasp_for("B50") == ()      # host-watch: intentionally unmapped
    assert owasp_for("ZZ99") == ()     # unknown id


def test_owasp_llm_2025_has_ten_canonical_codes():
    assert len(OWASP_LLM_2025) == 10
    assert set(OWASP_LLM_2025) == {f"LLM{n:02d}" for n in range(1, 11)}


# ---- the positioning claim: the multi-agent / agency arc maps to Excessive Agency ----
def test_multiagent_checks_map_to_excessive_agency():
    for cid in ("A1", "B45", "B46", "B47"):
        assert "LLM06" in owasp_for(cid), f"{cid} should map to LLM06 Excessive Agency"


def test_supply_chain_checks_map_to_llm03():
    for cid in ("B5", "B13", "B25", "B42"):
        assert "LLM03" in owasp_for(cid)


# ---- JSON surfacing ----
def test_render_json_includes_owasp_per_finding(tmp_path):
    _, findings, score = audit("fixtures/home_vuln", include_native=False, include_host=False)
    data = json.loads(render_json(findings, score))
    by_id = {f["id"]: f for f in data["findings"]}
    # every serialized finding carries an owasp list of valid codes
    for f in data["findings"]:
        assert "owasp" in f and isinstance(f["owasp"], list)
        for code in f["owasp"]:
            assert code in OWASP_LLM_2025
    # a mapped check exposes its codes; an unmapped one is an empty list (not absent)
    assert by_id["A1"]["owasp"] == ["LLM01", "LLM06"]
    assert by_id["B50"]["owasp"] == []
    # every serialized finding carries an ast list; codes are valid AST codes
    for f in data["findings"]:
        assert "ast" in f and isinstance(f["ast"], list)
        for code in f["ast"]:
            assert code in OWASP_AST_2026
    # B50: no LLM mapping but IS AST-governed (AST09), contrast verified
    assert by_id["B50"]["owasp"] == []
    assert by_id["B50"]["ast"] == ["AST09"]


# ---- OWASP Agentic Skills Top 10 (2026) ----

def test_owasp_ast_2026_has_ten_canonical_codes():
    assert len(OWASP_AST_2026) == 10
    assert set(OWASP_AST_2026) == {f"AST{n:02d}" for n in range(1, 11)}
    expected_titles = {
        "AST01": "Malicious Skills",
        "AST02": "Supply Chain Compromise",
        "AST03": "Over-Privileged Skills",
        "AST04": "Insecure Metadata",
        "AST05": "Untrusted External Instructions",
        "AST06": "Weak Isolation",
        "AST07": "Update Drift",
        "AST08": "Poor Scanning",
        "AST09": "No Governance",
        "AST10": "Cross-Platform Reuse",
    }
    for code, title in expected_titles.items():
        assert OWASP_AST_2026[code] == title, f"{code} title mismatch"


def test_every_ast_mapped_id_is_a_real_check():
    for cid in AST_MAP:
        assert cid in BY_ID, f"AST_MAP references unknown check id {cid!r}"


def test_every_ast_code_is_valid():
    for cid, codes in AST_MAP.items():
        assert isinstance(codes, tuple), f"{cid} AST_MAP value is not a tuple"
        for code in codes:
            assert code in OWASP_AST_2026, f"{cid} maps to unknown AST code {code!r}"


def test_ast_for_unmapped_returns_empty():
    assert ast_for("B1") == ()
    assert ast_for("ZZ99") == ()


def test_ast_positioning():
    assert "AST01" in ast_for("B13")
    for cid in ("B5", "B15", "B25", "B42"):
        assert "AST02" in ast_for(cid), f"{cid} should map to AST02"
    for cid in ("B3", "B8", "B18", "B31", "B32"):
        assert "AST03" in ast_for(cid), f"{cid} should map to AST03"
    assert ast_for("B62") == ("AST04",)
    for cid in ("B58", "B59", "B64"):
        assert "AST05" in ast_for(cid), f"{cid} should map to AST05"
    for cid in ("B4", "B48", "B70"):
        assert "AST06" in ast_for(cid), f"{cid} should map to AST06"
    assert "AST07" in ast_for("B33")
    assert "AST09" in ast_for("B16")


def test_b50_owasp_unmapped_but_ast_governed():
    assert owasp_for("B50") == ()
    assert ast_for("B50") == ("AST09",)


# ---- OWASP_MAP gap-fills (E-013) ----

def test_b58_b61_owasp_now_mapped():
    assert owasp_for("B58") == ("LLM01",)
    assert "LLM02" in owasp_for("B59")
    assert owasp_for("B60") == ("LLM01",)
    assert "LLM02" in owasp_for("B61")
    assert owasp_for("B64") == ("LLM01",)
