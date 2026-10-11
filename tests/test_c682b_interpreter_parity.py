"""C-682: three callers of ``Path.resolve`` answer the same on a symlink loop whichever Python runs.

``Path.resolve()`` on a path that loops raises ``RuntimeError`` on 3.9-3.12 and returns the path
on 3.14. Three callers reached that difference with input a user's disk can hold:

  * ``sweep_plugins``: a plugin-index record whose ``rootDir`` loops aborted the whole sweep on
    3.12 and was silently dropped on 3.14 (the sweep then said "1 vetted, no known issue");
  * ``check_skill_install_tamper`` (B181): a ``lock.json``-recorded file that is a symlink loop
    crashed the check on 3.12 and was reported per file on 3.14;
  * ``check_backups`` (C3): a ``backups`` link beside the home that loops crashed the check on
    3.12 (``safeio.walk_dir_safely`` resolved its root) and gave its WARN on 3.14.

Each test runs the caller under BOTH ``resolve()`` contracts in one process (3.12's, which
raises on a loop, and 3.14's, which returns), the way ``test_c682b_vet_plugin_resolve.py``
does, so a regression fails on whichever interpreter the suite runs. Nothing reads a Python
version.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_backups, check_skill_install_tamper
from clawseccheck.checks._mcp import sweep_plugins
from clawseccheck.collector import Context, collect
from clawseccheck.safeio import walk_dir_safely
from test_f150_plugin_sweep import _make_home, _mk_plugin_dir, _plugin_rec

pytestmark = pytest.mark.skipif(os.name != "posix", reason="symlinks are POSIX-only")

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_CLEAN_B181 = _FIXTURES / "clean_b181_install_hashes_match"


def _resolve_314(self, strict=False):
    """3.14: ``os.path.realpath`` and nothing else, so a loop is returned, never raised."""
    return type(self)(os.path.realpath(self, strict=strict))


def _resolve_312(self, strict=False):
    """3.9-3.12: realpath, then a ``stat`` of the result, whose ELOOP becomes ``RuntimeError``."""
    out = _resolve_314(self, strict)
    if not strict:
        try:
            os.stat(out)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise RuntimeError(f"Symlink loop from {exc.filename!r}") from None
        except ValueError:
            pass
    return out


_CONTRACTS = {"312": _resolve_312, "314": _resolve_314}


def _under_both(monkeypatch, build, run, shape):
    """Build the fixture once, run *run* under each contract, return {contract: shape(result)}."""
    fixture = build()
    out = {}
    for which, fn in _CONTRACTS.items():
        monkeypatch.setattr(Path, "resolve", fn)
        out[which] = shape(run(fixture))
    return out


# ------------------------------------------------------------------ the contracts themselves


def test_the_two_contracts_really_differ_on_a_loop(tmp_path, monkeypatch):
    """The control for everything below: a loop is an error on one side, a path on the other."""
    os.symlink("loop", tmp_path / "loop")
    monkeypatch.setattr(Path, "resolve", _resolve_312)
    with pytest.raises(RuntimeError):
        (tmp_path / "loop").resolve()
    monkeypatch.setattr(Path, "resolve", _resolve_314)
    assert (tmp_path / "loop").resolve() == Path(os.path.realpath(tmp_path / "loop"))


# -------------------------------------------------------------- 1. sweep_plugins: a looping rootDir


def _sweep_home(tmp_path: Path) -> Path:
    good = _mk_plugin_dir(tmp_path / "plugins" / "good")
    os.symlink("self", tmp_path / "plugins" / "self")
    os.symlink("b", tmp_path / "plugins" / "a")
    os.symlink("a", tmp_path / "plugins" / "b")
    recs = [
        _plugin_rec("good", str(good)),
        _plugin_rec("selfloop", str(tmp_path / "plugins" / "self")),
        _plugin_rec("twolink", str(tmp_path / "plugins" / "a")),
        _plugin_rec("stale", str(tmp_path / "plugins" / "no-such-dir")),
    ]
    return _make_home(tmp_path, "home", recs)


def _sweep_shape(s) -> tuple:
    return (
        tuple(s.rows), s.counts(), s.complete, tuple(s.not_scanned()),
        tuple((n, f.status, f.detail, f.engine_degraded) for n, f in s.findings),
    )


def test_a_looping_plugin_root_is_a_disclosed_gap_never_dropped_never_a_crash(
        tmp_path, monkeypatch):
    shapes = _under_both(
        monkeypatch, lambda: _sweep_home(tmp_path),
        lambda home: sweep_plugins(home, narrate=False), _sweep_shape)
    assert shapes["312"] == shapes["314"]
    rows, counts, complete, not_scanned, findings = shapes["314"]
    by_name = dict((n, s) for n, s, _e in rows)
    assert by_name["good"] == PASS
    assert by_name["selfloop"] == "TRUNCATED" and by_name["twolink"] == "TRUNCATED"
    assert "stale" not in by_name                      # an absent root stays a quiet skip
    assert set(not_scanned) == {"selfloop", "twolink"}
    assert complete is False
    assert counts["safe"] == 1 and counts["truncated"] == 2   # never "no known issue"
    loops = [f for f in findings if f[0] in ("selfloop", "twolink")]
    assert len(loops) == 2
    assert all(f[1] == UNKNOWN and f[3] is True and "symlink" in f[2] for f in loops), loops


def test_a_looping_record_does_not_swallow_a_later_readable_record_of_the_same_directory(
        tmp_path, monkeypatch):
    """C-135 (C-682b): `realpath` collapses `loop/..` lexically, so a looping record that names
    the plugin directory through `<dir>/lp/..` shared a de-duplication key with a later,
    readable record of `<dir>` itself and hid it: the real plugin was never vetted."""
    def build():
        evil = _mk_plugin_dir(tmp_path / "plugins" / "evil")
        os.symlink("lp", evil / "lp")
        recs = [_plugin_rec("weird", str(evil / "lp" / "..")), _plugin_rec("evil", str(evil))]
        return _make_home(tmp_path, "home", recs)
    shapes = _under_both(monkeypatch, build,
                         lambda home: sweep_plugins(home, narrate=False), _sweep_shape)
    assert shapes["312"] == shapes["314"]
    by_name = dict((n, s) for n, s, _e in shapes["314"][0])
    assert by_name.get("evil") == PASS, by_name        # the readable record is still vetted
    assert by_name.get("weird") == "TRUNCATED", by_name


def test_a_sweep_without_a_looping_root_is_unchanged(tmp_path, monkeypatch):
    def build():
        good = _mk_plugin_dir(tmp_path / "plugins" / "good")
        return _make_home(tmp_path, "home", [_plugin_rec("good", str(good))])
    shapes = _under_both(monkeypatch, build,
                         lambda home: sweep_plugins(home, narrate=False), _sweep_shape)
    assert shapes["312"] == shapes["314"]
    assert shapes["314"][0] == (("good", PASS, shapes["314"][0][0][2]),)
    assert shapes["314"][2] is True


# -------------------------------------------- 2. B181: a recorded path that is a symlink loop


def _b181_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    shutil.copytree(_CLEAN_B181, home)
    skill = home / "workspace" / "skills" / "demo-skill"
    os.symlink("looped.bin", skill / "looped.bin")
    lock_path = home / "workspace" / ".clawhub" / "lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    files = lock["skills"]["demo-skill"]["verification"]["artifact"]["files"]
    files.append({"path": "looped.bin", "size": 1,
                  "sha256": hashlib.sha256(b"x").hexdigest()})
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    return home


def _finding_shape(f) -> tuple:
    return (f.id, f.status, f.severity, f.detail, f.fix, tuple(f.evidence or ()))


def test_a_recorded_path_that_loops_is_one_disclosed_gap_not_a_crash(tmp_path, monkeypatch):
    shapes = _under_both(
        monkeypatch, lambda: _b181_home(tmp_path),
        lambda home: check_skill_install_tamper(Context(home=home)), _finding_shape)
    assert shapes["312"] == shapes["314"]
    fid, status, _sev, _detail, _fix, evidence = shapes["314"]
    assert fid == "B181"
    assert status in (WARN, UNKNOWN) and status != PASS and status != FAIL, status
    assert any("looped.bin" in e for e in evidence), evidence


def test_the_same_fixture_without_the_loop_still_passes(tmp_path, monkeypatch):
    """The control: the copied clean fixture, untouched, stays a PASS under both contracts."""
    def build():
        home = tmp_path / "home"
        shutil.copytree(_CLEAN_B181, home)
        return home
    shapes = _under_both(monkeypatch, build,
                         lambda home: check_skill_install_tamper(Context(home=home)),
                         _finding_shape)
    assert shapes["312"] == shapes["314"]
    assert shapes["314"][1] == PASS


# ------------------------------------- 3. C3: a looping `backups` link beside the home


def _backups_home(tmp_path: Path) -> Path:
    home = tmp_path / "oc"
    (home / "workspace-home").mkdir(parents=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    (home / "workspace-home" / "SOUL.md").write_text("soul\n", encoding="utf-8")
    os.symlink("backups", tmp_path / "backups")
    return home


def test_a_looping_backups_link_gives_the_warn_on_either_contract(tmp_path, monkeypatch):
    shapes = _under_both(
        monkeypatch, lambda: _backups_home(tmp_path),
        lambda home: check_backups(collect(home)), _finding_shape)
    assert shapes["312"] == shapes["314"]
    assert shapes["314"][0] == "C3" and shapes["314"][1] == WARN


def test_walk_dir_safely_on_a_looping_root_returns_and_does_not_raise(tmp_path, monkeypatch):
    os.symlink("loop", tmp_path / "loop")
    results = {}
    for which, fn in _CONTRACTS.items():
        monkeypatch.setattr(Path, "resolve", fn)
        gaps: list = []
        results[which] = (walk_dir_safely(tmp_path / "loop", unreadable_dirs=gaps), len(gaps))
    assert results["312"] == results["314"]
    assert results["314"][0] == []


# ------------------------------------------------ 4. the CLI repros: no crash, same answer


def _cli(monkeypatch, tmp_path, capsys, which: str, argv: list) -> tuple:
    from clawseccheck.cli import main
    monkeypatch.setenv("HOME", str(tmp_path / f"home-{which}"))
    (tmp_path / f"home-{which}").mkdir(exist_ok=True)
    monkeypatch.setattr(Path, "resolve", _CONTRACTS[which])
    capsys.readouterr()
    rc = main(argv)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def _cli_both(monkeypatch, tmp_path, capsys, argv: list) -> dict:
    return {w: _cli(monkeypatch, tmp_path, capsys, w, argv) for w in _CONTRACTS}


def test_a_looping_vet_target_gets_a_judge_packet_on_either_contract(
        tmp_path, monkeypatch, capsys):
    """`--vet-skill <loop> --vet-judge-packet` used to exit 1 with 'unexpected internal error'
    on 3.12 (the fingerprint resolved the target) and print the packet on 3.14."""
    os.symlink("loop", tmp_path / "loop")
    res = _cli_both(monkeypatch, tmp_path, capsys,
                    ["--vet-skill", str(tmp_path / "loop"), "--vet-judge-packet", "--no-color"])
    assert res["312"] == res["314"]
    rc, out, err = res["314"]
    assert "unexpected internal error" not in err and '"targetFingerprint"' in out, (rc, err)


def test_the_fingerprint_of_a_loop_is_the_same_stable_digest(tmp_path, monkeypatch):
    from clawseccheck.adjudication import _vet_run_fingerprint
    os.symlink("loop", tmp_path / "loop")
    got = {}
    for which, fn in _CONTRACTS.items():
        monkeypatch.setattr(Path, "resolve", fn)
        got[which] = _vet_run_fingerprint(str(tmp_path / "loop"))
    assert got["312"] == got["314"] and len(got["314"]) == 16


def test_a_looping_home_can_be_monitored_on_either_contract(tmp_path, monkeypatch, capsys):
    """`--home <loop> --monitor` used to exit 1 with 'unexpected internal error' on 3.12
    (`_home_identity` resolved the home) and print the monitor banner on 3.14."""
    os.symlink("oc", tmp_path / "oc")
    res = _cli_both(monkeypatch, tmp_path, capsys,
                    ["--home", str(tmp_path / "oc"), "--monitor", "--no-color"])
    assert res["312"][0] == res["314"][0]
    for _rc, _out, err in res.values():
        assert "unexpected internal error" not in err, err
    assert res["312"][1] == res["314"][1]


def test_a_looping_advise_target_gets_advice_on_either_contract(tmp_path, monkeypatch, capsys):
    """`--advise <loop>` used to exit 1 with 'unexpected internal error' on 3.12
    (`_looks_like_quarantine` resolved the target) and print the advice on 3.14."""
    os.symlink("loop", tmp_path / "loop")
    res = _cli_both(monkeypatch, tmp_path, capsys,
                    ["--advise", str(tmp_path / "loop"), "--no-color"])
    assert res["312"] == res["314"]
    rc, out, err = res["314"]
    assert "unexpected internal error" not in err and out.strip(), (rc, err)


def test_a_looping_path_entry_does_not_crash_the_path_safety_check(tmp_path, monkeypatch):
    """A PATH entry that is a symlink loop, ahead of the real openclaw dir, crashed
    check_path_safety on 3.12 and gave its finding on 3.14."""
    from clawseccheck.checks import check_path_safety
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "openclaw"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    exe.chmod(0o755)
    os.symlink("lp", tmp_path / "lp")
    monkeypatch.setenv("PATH", f"{tmp_path / 'lp'}:{bin_dir}:/usr/bin")
    home = tmp_path / "oc"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    ctx = collect(home)
    ctx.include_host = True
    shapes = {}
    for which, fn in _CONTRACTS.items():
        monkeypatch.setattr(Path, "resolve", fn)
        shapes[which] = _finding_shape(check_path_safety(ctx))
    assert shapes["312"] == shapes["314"]
    assert shapes["314"][1] != UNKNOWN or "disabled" not in shapes["314"][3]


def test_the_remaining_loop_callers_agree_on_either_contract(tmp_path, monkeypatch):
    """invocation._resolve, livetestproof._within_home and monitorstore._state_path_digest all
    took a user- or agent-supplied path through Path.resolve."""
    from clawseccheck import invocation, livetestproof, monitorstore
    os.symlink("loop", tmp_path / "loop")
    loop = tmp_path / "loop"
    got = {}
    for which, fn in _CONTRACTS.items():
        monkeypatch.setattr(Path, "resolve", fn)
        got[which] = (
            invocation._resolve(str(loop)),
            livetestproof._within_home(loop, tmp_path),
            monitorstore._state_path_digest(loop),
        )
    assert got["312"] == got["314"]
