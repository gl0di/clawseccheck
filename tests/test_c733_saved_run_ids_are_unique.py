"""C-733: two runs saved within the same second printed the same id, so `--diff` /
`--sbom-diff` could only ever load the second one. The id is the second-resolution
timestamp; a taken one now gets ``-2``, ``-3``, ... appended, for both stores, and a file
written before that (two rows with one id) still reads its last row.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json

from clawseccheck.catalog import CRITICAL, FAIL, Finding
from clawseccheck.cli import main
from clawseccheck.runstore import list_run_ids, load_run, save_run
from clawseccheck.sbom_runs import list_sbom_run_ids, load_sbom_run, save_sbom_run

_TS = "2026-03-04T05:06:07"
_SAFE = "fixtures/home_safe"


def _f(detail):
    return Finding("B2", "t", CRITICAL, FAIL, detail, "fix", "fw")


def test_three_findings_runs_in_one_second_get_three_ids(tmp_path):
    p = str(tmp_path / "runs.jsonl")
    ids = [save_run([_f(str(i))], p, when=_TS) for i in range(3)]
    assert ids == [_TS, _TS + "-2", _TS + "-3"]
    assert list_run_ids(p) == ids
    assert [load_run(i, p)["findings"][0]["detail"] for i in ids] == ["0", "1", "2"]


def test_three_sbom_runs_in_one_second_get_three_ids(tmp_path):
    p = str(tmp_path / "sbom_runs.jsonl")
    ids = [save_sbom_run({"skills": [{"name": str(i)}], "mcp_servers": [], "plugins": []},
                         p, when=_TS) for i in range(3)]
    assert ids == [_TS, _TS + "-2", _TS + "-3"]
    assert list_sbom_run_ids(p) == ids
    assert [load_sbom_run(i, p)["sbom"]["skills"][0]["name"] for i in ids] == ["0", "1", "2"]


def test_a_new_second_is_not_suffixed(tmp_path):
    p = str(tmp_path / "runs.jsonl")
    assert save_run([_f("a")], p, when=_TS) == _TS
    assert save_run([_f("b")], p, when="2026-03-04T05:06:08") == "2026-03-04T05:06:08"


def test_an_older_file_with_a_duplicate_id_still_reads_its_last_row(tmp_path):
    p = tmp_path / "runs.jsonl"
    save_run([_f("first")], str(p), when=_TS)
    save_run([_f("second")], str(p), when="2026-03-04T05:06:59")
    rows = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]
    rows[1]["ts"] = _TS                      # what a pre-4.4.0 writer could leave behind
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    assert load_run(_TS, str(p))["findings"][0]["detail"] == "second"
    assert save_run([_f("third")], str(p), when=_TS) == _TS + "-2"


def test_the_cli_prints_two_ids_for_two_saves_in_one_second(tmp_path, capsys, monkeypatch):
    import clawseccheck.runstore as rs

    class _Frozen:
        @staticmethod
        def now():
            class _T:
                @staticmethod
                def isoformat(timespec="seconds"):
                    return _TS
            return _T()

    monkeypatch.setattr(rs, "datetime", _Frozen)
    printed = []
    for _ in range(2):
        rc = main(["--home", _SAFE, "--data-dir", str(tmp_path), "--save-run", "--no-history",
                   "--no-host", "--no-deptree", "--no-native", "--no-sockets"])
        out = capsys.readouterr().out
        assert rc in (0, 1)
        printed += [line.split("run saved as ", 1)[1].split()[0].rstrip(").")
                    for line in out.splitlines() if "run saved as " in line]
    assert printed == [_TS, _TS + "-2"], printed
