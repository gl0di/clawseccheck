"""C-716 item 1: ``--incident-open`` recorded an ``open`` incident, linked to A1/B16/C5, for a
home that holds no OpenClaw configuration at all (the audit's WARN/FAIL there describe the
absence of a setup, not a setup in trouble).

"Actionable" is unchanged: a status in ``catalog.ACTIONABLE_STATUSES`` (FAIL-weight or WARN).
New: the audit must also have FOUND a configuration (``ctx.config_found``). Offline; every
store lives under pytest's ``tmp_path``.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from clawseccheck.catalog import Finding

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SAFE = str(FIXTURES / "home_safe")
VULN = str(FIXTURES / "home_vuln")


def _f(id_="B1", status="FAIL") -> Finding:
    return Finding(id=id_, title="t", severity="HIGH", status=status, detail="d", fix="f",
                   framework="fr", evidence=[])


def _argv(home, data, *extra):
    return ["--home", str(home), "--data-dir", str(data), "--incident-open",
            "--no-deptree", "--no-host", *extra]


def _store_files(data: Path):
    return sorted(p.name for p in data.iterdir()) if data.exists() else []


# --------------------------------------------------------------- the CLI, end to end

class TestCliRefusesWithoutASetup:
    @pytest.mark.parametrize("kind", ["missing", "empty"])
    @pytest.mark.parametrize("as_json", [False, True])
    def test_no_config_home_is_refused_and_writes_nothing(self, tmp_path, capsys, kind, as_json):
        from clawseccheck.cli import main
        home = tmp_path / "home"
        if kind == "empty":
            home.mkdir()
        data = tmp_path / "data"
        rc = main(_argv(home, data, *(["--json"] if as_json else [])))
        out = capsys.readouterr()
        assert rc != 0
        assert "no OpenClaw configuration" in out.err
        assert "Incident" not in out.out and out.out.strip() == ""
        assert not any(n.startswith("incidents.jsonl") and not n.endswith(".lock")
                       for n in _store_files(data)), _store_files(data)

    @pytest.mark.parametrize("home", [SAFE, VULN], ids=["home_safe", "home_vuln"])
    def test_a_real_home_with_findings_still_opens_an_incident(self, tmp_path, capsys, home):
        from clawseccheck.cli import main
        data = tmp_path / "data"
        rc = main(_argv(home, data))
        out = capsys.readouterr()
        assert rc == 0, out.err
        assert "status: open" in out.out
        assert "incidents.jsonl" in _store_files(data)


# --------------------------------------------------------------- the function contract

class TestOpenIncidentFromAudit:
    def test_no_config_found_refuses_even_with_actionable_findings(self, tmp_path):
        from clawseccheck.incident import open_incident_from_audit
        store = tmp_path / "incidents.jsonl"
        rec, err = open_incident_from_audit(SimpleNamespace(config_found=False),
                                            [_f("A1", "FAIL"), _f("B16", "WARN")],
                                            path=store)
        assert (rec, err) == (None, "no_config_found")
        assert not store.exists()

    def test_config_found_with_actionable_findings_opens(self, tmp_path):
        from clawseccheck.incident import open_incident_from_audit
        store = tmp_path / "incidents.jsonl"
        rec, err = open_incident_from_audit(SimpleNamespace(config_found=True),
                                            [_f("A1", "FAIL"), _f("B16", "WARN"),
                                             _f("C5", "PASS")], path=store)
        assert err is None and rec["status"] == "open"
        assert store.exists()

    def test_config_found_with_nothing_actionable_still_refuses(self, tmp_path):
        from clawseccheck.incident import open_incident_from_audit
        store = tmp_path / "incidents.jsonl"
        rec, err = open_incident_from_audit(
            SimpleNamespace(config_found=True),
            [_f("A1", "PASS"), _f("B16", "UNKNOWN"), _f("C5", "INFO")], path=store)
        assert (rec, err) == (None, "no_actionable_findings")
        assert not store.exists()

    def test_a_duck_typed_ctx_without_the_flag_keeps_todays_behaviour(self, tmp_path):
        from clawseccheck.incident import open_incident_from_audit
        for ctx in (None, SimpleNamespace()):
            store = tmp_path / f"incidents-{id(ctx)}.jsonl"
            rec, err = open_incident_from_audit(ctx, [_f("A1", "FAIL")], path=store)
            assert err is None and rec["status"] == "open"
