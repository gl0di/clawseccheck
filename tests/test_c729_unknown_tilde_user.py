"""C-729: a ``~user`` that names no account must not end the run with "unexpected internal
error (RuntimeError)".

``Path.expanduser()`` raises ``RuntimeError`` (not ``OSError``) for ``~nosuchuser/x``. About a
hundred bare calls let it escape: a config value such as ``agents.defaults.workspace`` took
the whole audit down with no report, and so did a path typed on the command line. Two answers,
one per source of the value:

* a CONFIG-derived value goes through ``pathprobe.expand_user``, which leaves the unresolvable
  path as written - what the platform itself does (it expands only ``~``, ``~/`` and ``~\\``)
  and a path that is simply not there;
* a path the USER typed is refused up front with ``UnusableInputPath`` (the wording
  ``--judged`` already had), because the fallback would make an output flag create a
  directory literally named ``~name``.
"""
from __future__ import annotations

import json
import os
import pwd
import subprocess
import sys
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_MANIFEST = _ROOT / "tests" / "grounded_schema_paths.txt"

_NOBODY = "nosuchuser_zz_c729"
_BAD = f"~{_NOBODY}/x"

# Options that take a value and are NOT a filesystem path the tool expands. A new option
# must be classified here or in `cli._PATH_OPTION_DESTS`; the walk below fails otherwise.
_NOT_A_PATH = {
    "watch_debounce": "seconds",
    "vet_source": "registry slug, URL or package name",
    "vet_plan": "registry slug, URL or package name",
    "incident_mark": "incident id and status",
    "incident_show": "incident id",
    "seed": "free text",
    "fail_on": "severity name",
    "exit_code_scheme": "scheme name",
    "diff": "run ids",
    "sbom_diff": "run ids",
    "explain": "finding id",
    "retest": "finding id",
    "format": "format name",
    "verify_baseline": "a reference value a previous --monitor run printed",
}


def _capture_parser(monkeypatch):
    """The real argparse parser, taken from `_main` without refactoring it."""
    from clawseccheck import cli

    class _Got(Exception):
        pass

    box = {}

    def fake_parse_args(self, argv=None, namespace=None):
        box["parser"] = self
        raise _Got

    monkeypatch.setattr(cli._SuggestingParser, "parse_args", fake_parse_args)
    with pytest.raises(_Got):
        cli._main([])
    return box["parser"]


def _value_taking(parser):
    """{dest: first option string} for every option that takes a value."""
    return {a.dest: a.option_strings[0] for a in parser._actions
            if a.option_strings and a.nargs != 0}


def _unclassified(value_taking, path_dests, not_path):
    """Options that take a value and are in neither table; table entries naming no option."""
    problems = [f"{opt} ({dest}) takes a value and is classified in neither table"
                for dest, opt in sorted(value_taking.items())
                if dest not in path_dests and dest not in not_path]
    problems += [f"{dest} is in a table but no option has it"
                 for dest in sorted(set(path_dests) | set(not_path)) if dest not in value_taking]
    problems += [f"{dest} is in both tables" for dest in sorted(set(path_dests) & set(not_path))]
    return problems


# ----------------------------------------------------------------------------- the helper


def test_the_unknown_account_really_does_not_exist_and_really_raises():
    """The control for everything below: the name is not an account, and the stdlib call the
    helper wraps does raise for it."""
    with pytest.raises(KeyError):
        pwd.getpwnam(_NOBODY)
    with pytest.raises(RuntimeError):
        Path(_BAD).expanduser()


def test_expand_user_equals_expanduser_wherever_that_resolves(monkeypatch, tmp_path):
    from clawseccheck import pathprobe

    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    me = pwd.getpwuid(os.getuid()).pw_name
    for raw in ("~", "~/x", "~/", f"~{me}", f"~{me}/x", "rel/x", "/abs/x", "", ".", "a~b/c",
                Path("~/p")):
        got = pathprobe.expand_user(raw)
        assert isinstance(got, Path), raw
        assert got == Path(raw).expanduser(), raw


def test_expand_user_leaves_an_unknown_account_as_written():
    from clawseccheck import pathprobe

    for raw in (_BAD, f"~{_NOBODY}", f"~{_NOBODY}/a/b", Path(_BAD)):
        assert pathprobe.expand_user(raw) == Path(raw), raw


def test_expand_user_refuses_the_current_users_tilde_when_there_is_no_home(monkeypatch):
    """`~` / `~/x` with neither HOME nor a passwd entry: never returned unexpanded. A
    literal `~/.clawseccheck` would be a directory under the WORKING directory, so the
    tool's own state would be written into, and read from, wherever it was started."""
    from clawseccheck import pathprobe

    def boom(self):
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(Path, "expanduser", boom)
    for raw in ("~", "~/x", "~/.clawseccheck/state.json", Path("~/x")):
        with pytest.raises(pathprobe.NoHomeDirectory):
            pathprobe.expand_user(raw)
    assert issubclass(pathprobe.NoHomeDirectory, RuntimeError)
    # an unknown account is a different fact and keeps its answer
    assert pathprobe.expand_user("~nobody_at_all/x") == Path("~nobody_at_all/x")


_NO_HOME_RUNNER = """
import os, pwd, sys
def _nope(*_a, **_k):
    raise KeyError("no passwd entry")
pwd.getpwuid = _nope
os.environ.pop("HOME", None)
sys.path.insert(0, sys.argv[1])
from clawseccheck.cli import main
sys.exit(main(sys.argv[2:]))
"""


@pytest.mark.parametrize("extra", [[], ["--monitor"], ["--json"], ["--watch-status"]],
                         ids=["audit", "monitor", "json", "watch-status"])
def test_no_home_directory_never_puts_the_store_under_the_working_directory(tmp_path, extra):
    """HOME unset and no passwd entry, with an explicit --home: the default store
    (`~/.clawseccheck`) cannot be located. The run must stop with one line and must not
    create - or read - a directory literally named `~` in the working directory."""
    import shutil

    repo = Path(__file__).resolve().parent.parent
    home = tmp_path / "audited"
    shutil.copytree(repo / "fixtures" / "home_safe", home)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    planted = cwd / "~" / ".clawseccheck"
    env = {k: v for k, v in os.environ.items() if k != "HOME"}
    r = subprocess.run([sys.executable, "-B", "-c", _NO_HOME_RUNNER, str(repo),
                        "--home", str(home), *extra],
                       cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 1, (r.returncode, r.stderr[-300:])
    assert r.stdout == ""
    assert "no home directory for the current user" in r.stderr and "Traceback" not in r.stderr
    assert "unexpected internal error" not in r.stderr
    assert not planted.exists() and sorted(os.listdir(cwd)) == []


# ------------------------------------------------------------------------- the config sweep


def _manifest_paths():
    root, rel = [], []
    for line in _MANIFEST.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("relative:"):
            rel.append(line[len("relative:"):])
        else:
            root.append(line)
    return root, rel


def _nest(dotted, value):
    node = value
    for seg in reversed(dotted.split(".")):
        node = {seg: node}
    return node


def _audit(tmp_path, monkeypatch, cfg):
    import clawseccheck

    home = tmp_path / "ohome"
    home.mkdir(exist_ok=True)
    cfg_file = home / "openclaw.json"
    cfg_file.write_text(json.dumps(cfg), encoding="utf-8")
    cfg_file.chmod(0o600)
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    (tmp_path / "user").mkdir(exist_ok=True)
    return clawseccheck.audit(home)[1]


def _sweep_configs():
    """(label, config) for every grounded config path, as a string and as a one-element list."""
    root, rel = _manifest_paths()
    for shape, wrap in (("str", lambda v: v), ("list", lambda v: [v])):
        for path in root:
            yield f"{path} [{shape}]", _nest(path, wrap(_BAD))
        for path in rel:
            yield (f"agents.list[0].{path} [{shape}]",
                   {"agents": {"list": [{"id": "main", **_nest(path, wrap(_BAD))}]}})
        for path in _EXTRA_KEYS:
            yield f"{path} [{shape}]", _nest(path, wrap(_BAD))


# Path-valued keys the package reads that the grounded-path manifest does not list.
_EXTRA_KEYS = ("skills.load.extraDirs", "plugins.load.paths", "logging.file",
               "diagnostics.cacheTrace.filePath", "browser.executablePath")


def _problems(tmp_path, monkeypatch, cases):
    problems = []
    n = 0
    for label, cfg in cases:
        n += 1
        try:
            findings = _audit(tmp_path, monkeypatch, cfg)
        except Exception as exc:  # noqa: BLE001 - the point of the sweep
            problems.append(f"{label}: raised {type(exc).__name__}: {exc}")
            continue
        errs = [f.id for f in findings if str(f.id).startswith("ERR:")]
        if errs:
            problems.append(f"{label}: {errs}")
    return n, problems


def test_no_config_path_holding_an_unknown_account_crashes_the_audit(tmp_path, monkeypatch):
    """Every grounded config path (root and per-agent-entry), plus the path-valued keys the
    manifest omits, holding `~nosuchuser/x` as a string and as a one-element list: the audit
    returns a report, and no check turns into an `ERR:` finding."""
    n, problems = _problems(tmp_path, monkeypatch, _sweep_configs())
    assert n >= 400, n  # anti-vacuity: the sweep really walks the manifest, twice
    assert not problems, f"{len(problems)} of {n}:\n" + "\n".join(problems)


def test_the_four_keys_named_in_the_report_and_the_per_agent_shapes(tmp_path, monkeypatch):
    cases = [
        ("agents.defaults.workspace", {"agents": {"defaults": {"workspace": _BAD}}}),
        ("agents.list[].workspace", {"agents": {"list": [{"id": "main", "workspace": _BAD}]}}),
        ("agents.entries.<id>.workspace",
         {"agents": {"entries": {"main": {"workspace": _BAD}}}}),
        ("skills.load.extraDirs[]", {"skills": {"load": {"extraDirs": [_BAD]}}}),
        ("diagnostics.cacheTrace.filePath",
         {"diagnostics": {"cacheTrace": {"filePath": _BAD, "enabled": True}}}),
        ("diagnostics.cacheTrace.filePath (not enabled)",
         {"diagnostics": {"cacheTrace": {"filePath": _BAD}}}),
    ]
    n, problems = _problems(tmp_path, monkeypatch, cases)
    assert n == len(cases)
    assert not problems, "\n".join(problems)


def test_an_unexpandable_path_reads_as_a_path_that_is_not_there(tmp_path, monkeypatch):
    """Verdict direction: `~nosuchuser/x` as a workspace / skill dir must give exactly the
    (id, status) a path that simply does not exist gives - an unresolvable path is a path
    that is not there, never a reason for a check to turn clean."""
    missing = str(tmp_path / "no" / "such" / "dir")
    shapes = (
        lambda v: {"agents": {"defaults": {"workspace": v}}},
        lambda v: {"agents": {"list": [{"id": "main", "workspace": v}]}},
        lambda v: {"skills": {"load": {"extraDirs": [v]}}},
    )
    for shape in shapes:
        a = _audit(tmp_path, monkeypatch, shape(_BAD))
        b = _audit(tmp_path, monkeypatch, shape(missing))
        assert sorted((f.id, str(f.status)) for f in a) == sorted((f.id, str(f.status)) for f in b)


# ---------------------------------------------------------------------------- the flag sweep


def test_every_option_that_takes_a_value_is_classified(monkeypatch):
    from clawseccheck import cli

    parser = _capture_parser(monkeypatch)
    problems = _unclassified(_value_taking(parser), set(cli._PATH_OPTION_DESTS), _NOT_A_PATH)
    assert not problems, "\n".join(problems)


def test_the_classification_walk_can_fail():
    """A control for the walk above: a new, unclassified option and a stale entry are both
    reported."""
    value_taking = {"home": "--home", "brand_new": "--brand-new"}
    assert _unclassified(value_taking, {"home"}, {}) == [
        "--brand-new (brand_new) takes a value and is classified in neither table"]
    assert _unclassified({"home": "--home"}, {"home", "gone"}, {}) == [
        "gone is in a table but no option has it"]
    assert _unclassified({"home": "--home"}, {"home"}, {"home": "x"}) == ["home is in both tables"]


def test_every_path_option_refuses_an_unknown_account_before_doing_anything(
        tmp_path, monkeypatch):
    """Through the real CLI in a subprocess with a throwaway HOME and working directory: the
    one-line refusal `--judged` already gave, exit 1, nothing on stdout, no traceback, and
    nothing created anywhere (no directory named `~nosuchuser...`)."""
    from clawseccheck import cli

    options = _value_taking(_capture_parser(monkeypatch))
    expected = (f"clawseccheck: {_BAD}: the '~user' in it names no account on this machine. "
                "Nothing was produced; fix the path and re-run.\n")
    assert len(cli._PATH_OPTION_DESTS) >= 20
    problems = []
    for dest in cli._PATH_OPTION_DESTS:
        opt = options[dest]
        work = tmp_path / dest
        home, cwd = work / "home", work / "cwd"
        home.mkdir(parents=True)
        cwd.mkdir()
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
               "PYTHONPATH": str(_ROOT)}
        r = subprocess.run(
            [sys.executable, "-c", "import sys;from clawseccheck.cli import main;sys.exit(main())",
             opt, _BAD],
            cwd=cwd, env=env, capture_output=True, text=True, timeout=120, check=False)
        seen = sorted(os.listdir(cwd)) + sorted(os.listdir(home))
        if (r.returncode, r.stdout, r.stderr, seen) != (1, "", expected, []):
            problems.append(f"{opt}: rc={r.returncode} stdout={len(r.stdout)}B "
                            f"stderr={r.stderr[-200:]!r} created={seen}")
    assert not problems, "\n".join(problems)


def test_the_refusal_names_the_tilde_alone_differently():
    """`~` / `~/x` fail with no home directory, not with an unknown account."""
    from clawseccheck import cli

    def boom(self):
        raise RuntimeError("Could not determine home directory.")

    args = types.SimpleNamespace(home="~/.openclaw")
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(Path, "expanduser", boom)
        with pytest.raises(cli.UnusableInputPath) as ei:
            cli._refuse_unexpandable_paths(args)
    assert "no home directory" in ei.value.text
    assert "names no account" not in ei.value.text


def test_the_refusal_leaves_everything_else_alone():
    from clawseccheck import cli

    ok = types.SimpleNamespace(
        home="~", save=None, state="", events="/abs/x", history="rel/x", data_dir="-",
        pdf="\x00pdf-auto\x00", vet_mcp="", judged="a~b", log="~root")
    cli._refuse_unexpandable_paths(ok)  # no exception
    bad = types.SimpleNamespace(home="~/.openclaw", log=_BAD)
    with pytest.raises(cli.UnusableInputPath) as ei:
        cli._refuse_unexpandable_paths(bad)
    assert ei.value.raw_path == _BAD
