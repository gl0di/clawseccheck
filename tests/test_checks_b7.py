"""B7 — memory poisoning surface tests."""

from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.catalog import UNKNOWN, PASS, WARN
from clawseccheck.checks import check_memory_poisoning
from clawseccheck.collector import Context, collect
from clawseccheck.i18n import tp

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_HEBREW = re.compile(r"[֐-׿]")


def _ctx(config=None, bootstrap=None):
    c = Context(home=Path("/nonexistent"))
    c.config = config or {}
    c.bootstrap = bootstrap or {}
    c.installed_skills = {}
    return c


def test_b7_unknown_when_no_memory_surface():
    f = check_memory_poisoning(_ctx({"tools": {"profile": "minimal"}}))
    assert f.status == UNKNOWN
    assert f.detail == "No memory file found."


def test_b7_warn_when_memory_file_without_config_surface():
    f = check_memory_poisoning(_ctx(
        bootstrap={"workspace-home/MEMORY.md": "old memories"}
    ))
    assert f.status == WARN
    assert "untrusted input" in f.detail
    assert _HEBREW.search(tp(f.detail, "he"))


def test_b7_unknown_when_vector_surface_without_access_control():
    f = check_memory_poisoning(collect(FIXTURES / "bad_b7_memory_rag"))
    assert f.status == UNKNOWN
    assert "untrusted input" in f.detail


def test_b7_pass_when_vector_access_control_present():
    f = check_memory_poisoning(collect(FIXTURES / "clean_b7_memory_rag"))
    assert f.status == PASS


def test_b7_unknown_when_backend_set_to_external_like_value():
    f = check_memory_poisoning(_ctx({"memory": {"backend": "chromadb"}}))
    assert f.status == UNKNOWN


def test_b7_belongs_to_audit_set():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_b7_memory_rag", include_native=False)
    ids = {f.id for f in findings}
    assert "B7" in ids, f"B7 not present in audit findings: {sorted(ids)}"
