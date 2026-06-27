from __future__ import annotations

from pathlib import Path

from scripts.gen_checks_docs import build_checks_docs


def test_checks_doc_is_generated_from_source():
    doc_path = Path(__file__).resolve().parents[1] / "docs" / "CHECKS.md"
    assert doc_path.read_text(encoding="utf-8") == build_checks_docs()
