"""C-721: output and shell edge cases found by functional testing.

Each class pins one item through the real CLI in a child process, because the defects
live in what a shell, a pipe or a terminal does to the tool's output - something an
in-process call cannot show.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SAFE = str(REPO_ROOT / "fixtures" / "home_safe")
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")

_QUIET = ["--no-history", "--no-deptree", "--no-host"]


def _env(**extra):
    env = dict(os.environ)
    env.update(extra)
    return env


def _cli(args, tmp_path, *, env=None, stdin_devnull=True):
    """Run the CLI to completion with its stdout and stderr captured as text."""
    cmd = [sys.executable, "-m", "clawseccheck", "--no-deptree", "--no-host", *args]
    return subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, encoding="utf-8",
                          errors="replace", timeout=450, env=env or _env(),
                          stdin=subprocess.DEVNULL if stdin_devnull else None)


def _cli_into_closed_pipe(args, env=None):
    """Start the CLI with stdout a pipe whose reader has already gone: `... | head -c 0`."""
    cmd = [sys.executable, "-m", "clawseccheck", "--no-deptree", "--no-host", *args]
    child = subprocess.Popen(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, encoding="utf-8", errors="replace",
                             env=env or _env(),
                             stdin=subprocess.DEVNULL)
    child.stdout.close()
    err = child.stderr.read()
    code = child.wait(timeout=450)
    child.stderr.close()
    return code, err


# --------------------------------------------------------------------------------------
# 1. A reader that closes the pipe early is normal use, not an internal error.
# --------------------------------------------------------------------------------------

_PIPE_SHAPES = {
    "json": ["--json"],
    "plain": [],
    "sbom": ["--sbom"],
    "dashboard": ["--dashboard"],
    "monitor": ["--monitor"],
}


@pytest.mark.parametrize("shape", sorted(_PIPE_SHAPES))
def test_a_closed_pipe_is_silent_and_exits_141_or_the_runs_own_code(shape, tmp_path):
    flags = _PIPE_SHAPES[shape]
    data = tmp_path / "data"
    args = ["--home", SAFE, *_QUIET, "--data-dir", str(data), *flags]
    own = _cli(["--home", SAFE, *_QUIET, "--data-dir", str(tmp_path / "ref"), *flags],
               tmp_path).returncode
    shutil.rmtree(data, ignore_errors=True)
    code, err = _cli_into_closed_pipe(args)
    for needle in ("BrokenPipe", "unexpected internal error", "Exception ignored",
                   "Traceback", "open an issue"):
        assert needle not in err, err[-600:]
    assert code in (141, own), (code, own, err[-600:])


def test_a_closed_pipe_message_check_is_not_vacuous(tmp_path):
    """Control: with the reader attached the same run prints its report and exits cleanly."""
    done = _cli(["--home", SAFE, *_QUIET, "--json"], tmp_path)
    assert done.returncode == 0
    assert "score" in json.loads(done.stdout)


# --------------------------------------------------------------------------------------
# 2. --save with a file name that is not valid UTF-8 (it arrives as surrogate escapes).
# --------------------------------------------------------------------------------------

def _home_with_skill_named(tmp_path, raw_name: bytes) -> Path:
    home = tmp_path / "home"
    shutil.copytree(SAFE, home)
    skill = os.fsencode(str(home)) + b"/workspace/skills/" + raw_name
    try:
        os.makedirs(skill)
    except OSError:  # a file system that refuses such a name (macOS) cannot show the bug
        pytest.skip("this file system refuses the undecodable skill name")
    with open(skill + b"/SKILL.md", "wb") as fh:
        fh.write(b"---\nname: odd\ndescription: x\n---\nhello\n")
    return home


def test_save_survives_an_undecodable_file_name_and_shows_it_as_json_does(tmp_path):
    home = _home_with_skill_named(tmp_path, b"bad\xffname")
    out = tmp_path / "report.md"
    done = _cli(["--home", str(home), *_QUIET, "--save", str(out)], tmp_path)
    assert done.returncode == 0, done.stderr[-600:]
    assert "unexpected internal error" not in done.stderr
    text = out.read_text(encoding="utf-8")
    # The same spelling --json gives the byte (a JSON escape), not a third one.
    raw_json = _cli(["--home", str(home), *_QUIET, "--json"], tmp_path).stdout
    assert "bad\\udcffname" in raw_json
    assert "bad\\udcffname" in text


def test_save_survives_a_non_ascii_skill_name_under_the_c_locale(tmp_path):
    home = _home_with_skill_named(tmp_path, "café".encode("utf-8"))
    out = tmp_path / "report.md"
    env = _env(LC_ALL="C", LANG="C", PYTHONUTF8="0", PYTHONCOERCECLOCALE="0")
    env.pop("PYTHONIOENCODING", None)
    done = _cli(["--home", str(home), *_QUIET, "--save", str(out)], tmp_path, env=env)
    assert done.returncode == 0, done.stderr[-600:]
    assert "unexpected internal error" not in done.stderr
    assert out.is_file() and out.read_text(encoding="utf-8").strip()


def test_save_of_ordinary_text_is_byte_for_byte_unchanged(tmp_path):
    from clawseccheck.safeio import secure_write_text
    target = tmp_path / "plain.txt"
    secure_write_text(target, "café — ok\n")
    assert target.read_bytes() == "café — ok\n".encode("utf-8")


# --------------------------------------------------------------------------------------
# 3. `--save ""` is a malformed invocation, like `--html ""`.
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("flag", ["--html", "--sarif", "--badge", "--pdf", "--save"])
@pytest.mark.parametrize("value", ["", "   "])
def test_an_empty_output_path_is_a_usage_error_with_exit_2(flag, value, tmp_path):
    done = _cli(["--home", SAFE, *_QUIET, flag, value], tmp_path)
    assert done.returncode == 2, (done.returncode, done.stdout[-300:], done.stderr[-300:])
    assert flag in done.stderr
    assert "empty" in done.stderr
    assert done.stdout.strip() == ""


def test_save_with_a_real_path_is_unaffected_by_the_empty_path_check(tmp_path):
    out = tmp_path / "ok.md"
    done = _cli(["--home", SAFE, *_QUIET, "--save", str(out)], tmp_path)
    assert done.returncode == 0, done.stderr[-300:]
    assert out.is_file()


# --------------------------------------------------------------------------------------
# 4. Under --json, stdout is exactly one JSON document: human trailers go to stderr.
# --------------------------------------------------------------------------------------

def _attest_file(tmp_path) -> str:
    p = tmp_path / "attest.json"
    p.write_text("{}", encoding="utf-8")
    return str(p)


@pytest.mark.parametrize("extra", [
    ["--save-run"],
    ["--save-sbom-run"],
    ["--exit-code"],
    ["--fail-on", "low"],
    ["--save", "REPORT"],
    ["--attest", "ATTEST"],
    ["--save-run", "--save", "REPORT"],
], ids=lambda e: " ".join(e))
def test_json_stdout_is_exactly_one_document(extra, tmp_path):
    sub = {"REPORT": str(tmp_path / "saved.md"), "ATTEST": _attest_file(tmp_path)}
    args = [sub.get(x, x) for x in extra]
    done = _cli(["--home", SAFE, *_QUIET, "--data-dir", str(tmp_path / "data"), "--json",
                 *args], tmp_path)
    assert done.returncode in (0, 1), done.stderr[-300:]
    json.loads(done.stdout)  # "Extra data" here is the bug


def test_json_sbom_with_save_sbom_run_is_one_document(tmp_path):
    done = _cli(["--home", SAFE, *_QUIET, "--data-dir", str(tmp_path / "data"), "--json",
                 "--sbom", "--save-sbom-run"], tmp_path)
    assert done.returncode == 0, done.stderr[-300:]
    json.loads(done.stdout)
    assert "SBOM run saved as" in done.stderr


@pytest.mark.parametrize("fmt", [(), ("--format", "cyclonedx"), ("--format", "spdx")],
                         ids=["native", "cyclonedx", "spdx"])
def test_sbom_with_save_sbom_run_is_one_document_without_json_too(tmp_path, fmt):
    """--sbom prints a JSON document whatever the flags say, so its "saved as" line never
    belongs on stdout."""
    done = _cli(["--home", SAFE, *_QUIET, "--data-dir", str(tmp_path / "data"),
                 "--sbom", "--save-sbom-run", *fmt], tmp_path)
    assert done.returncode == 0, done.stderr[-300:]
    json.loads(done.stdout)
    assert "SBOM run saved as" in done.stderr


def test_the_run_saved_line_moves_to_stderr_only_under_json(tmp_path):
    base = ["--home", SAFE, *_QUIET, "--save-run"]
    plain = _cli([*base, "--data-dir", str(tmp_path / "d1")], tmp_path)
    assert "(run saved as" in plain.stdout
    with_json = _cli([*base, "--data-dir", str(tmp_path / "d2"), "--json"], tmp_path)
    assert "(run saved as" in with_json.stderr
    assert "run saved as" not in with_json.stdout
    saved = _cli(["--home", SAFE, *_QUIET, "--json", "--save", str(tmp_path / "r.md")],
                 tmp_path)
    assert "(report saved to" in saved.stderr
    assert "report saved to" not in saved.stdout


@pytest.mark.parametrize("flag", ["--badge", "--html", "--sarif", "--pdf"])
def test_json_with_a_file_mode_says_it_has_no_effect_rather_than_trailing_the_document(
        flag, tmp_path):
    """These modes take over the run, so --json yields no document at all; that is
    disclosed on stderr (never a JSON document followed by a sentence)."""
    done = _cli(["--home", SAFE, *_QUIET, "--json", flag, str(tmp_path / "out.bin")],
                tmp_path)
    assert f"--json has no effect with {flag}" in done.stderr
    assert not done.stdout.lstrip().startswith("{")


# --------------------------------------------------------------------------------------
# 5. `--log` to a path that cannot be opened: one line, not logging's traceback block.
# --------------------------------------------------------------------------------------

def test_an_unopenable_log_file_is_one_stderr_line_and_the_run_carries_on(tmp_path):
    bad = str(tmp_path / "no" / "such" / "dir" / "x.log")
    args = ["--home", SAFE, *_QUIET, "--json"]
    reference = _cli(args, tmp_path)
    done = _cli([*args, "--log", bad], tmp_path)
    assert done.returncode == reference.returncode
    json.loads(done.stdout)
    for needle in ("Logging error", "Traceback", "--- "):
        assert needle not in done.stderr, done.stderr[-600:]
    lines = [ln for ln in done.stderr.splitlines() if "log file" in ln]
    assert len(lines) == 1, done.stderr[-600:]
    assert bad in lines[0]
    assert "No such file or directory" in lines[0]
    assert not os.path.exists(bad)


def test_the_log_handler_says_it_once_and_drops_the_rest(tmp_path, capsys):
    from clawseccheck.logsafe import get_logger
    bad = str(tmp_path / "missing" / "x.log")
    logger = get_logger(debug=True, logfile=bad)
    try:
        for i in range(5):
            logger.info("record %d", i)
    finally:
        get_logger()
    err = capsys.readouterr().err
    assert err.count("could not be opened") == 1, err
    assert "Logging error" not in err and "Traceback" not in err


# --------------------------------------------------------------------------------------
# 6. A --monitor run that loses the race for the baseline says so.
# --------------------------------------------------------------------------------------

_RACE_SENTENCE = "Another --monitor run updated the baseline while this one was running"


def _monitor_args(tmp_path):
    return ["--home", SAFE, *_QUIET, "--monitor",
            "--state", str(tmp_path / "state.json"),
            "--events", str(tmp_path / "events.jsonl"),
            "--history", str(tmp_path / "history.jsonl")]


def test_the_monitor_run_that_loses_the_baseline_race_says_so(tmp_path, monkeypatch, capsys):
    import contextlib

    from clawseccheck import cli
    args = _monitor_args(tmp_path)
    state = tmp_path / "state.json"
    assert cli.main(args) == 0  # the baseline every later run compares against
    capsys.readouterr()

    real_lock = cli.journal_lock
    raced = []

    @contextlib.contextmanager
    def lock_after_a_rival_wrote(path):
        with real_lock(path):
            if str(path) == str(state) and not raced:
                raced.append(True)  # the rival lands between our read and our write
                _status, current = cli.read_baseline(str(state))
                cli.save_state(str(state), {**current, "rival": "wrote-first"})
            yield

    monkeypatch.setattr(cli, "journal_lock", lock_after_a_rival_wrote)
    rc = cli.main(args)
    out = capsys.readouterr().out
    assert raced and rc == 0
    assert _RACE_SENTENCE in out
    assert "recorded nothing" in out
    assert "No new threats" not in out  # no all-clear for a run that wrote nothing
    assert json.loads(state.read_text(encoding="utf-8")).get("rival") == "wrote-first"


def test_a_monitor_run_that_wins_says_nothing_about_a_race(tmp_path, capsys):
    from clawseccheck import cli
    args = _monitor_args(tmp_path)
    assert cli.main(args) == 0
    capsys.readouterr()
    assert cli.main(args) == 0
    out = capsys.readouterr().out
    assert _RACE_SENTENCE not in out
    assert "No new threats" in out


# --------------------------------------------------------------------------------------
# 7. Nits: TERM=dumb, --ascii purity, an unreadable home under --json.
# --------------------------------------------------------------------------------------

class _FakeTty:
    def isatty(self):
        return True


def test_term_dumb_turns_colour_off_like_no_color():
    from clawseccheck.ansi import should_color
    assert should_color(stream=_FakeTty(), env={}) is True  # control: a tty colours
    assert should_color(stream=_FakeTty(), env={"TERM": "dumb"}) is False
    assert should_color(stream=_FakeTty(), env={"NO_COLOR": ""}) is False
    assert should_color(stream=_FakeTty(), env={"TERM": "xterm-256color"}) is True
    # FORCE_COLOR does not reopen a terminal that declared itself unable to show escapes.
    assert should_color(stream=_FakeTty(), env={"TERM": "dumb", "FORCE_COLOR": "1"}) is False


_ASCII_SHAPES = {
    "default": [],
    "full-fast": ["--full", "--fast"],
    "dashboard": ["--dashboard"],
    "monitor": ["--monitor"],
    "brief": ["--brief"],
}


@pytest.mark.parametrize("home", [SAFE, VULN], ids=["home_safe", "home_vuln"])
@pytest.mark.parametrize("shape", sorted(_ASCII_SHAPES))
def test_ascii_output_has_no_byte_above_0x7f(shape, home, tmp_path):
    args = ["--home", home, *_QUIET, "--ascii", *_ASCII_SHAPES[shape]]
    if shape == "monitor":
        args += ["--state", str(tmp_path / "s.json"), "--events", str(tmp_path / "e.jsonl"),
                 "--history", str(tmp_path / "h.jsonl")]
    done = subprocess.run([sys.executable, "-m", "clawseccheck", *args], cwd=REPO_ROOT,
                          capture_output=True, timeout=450, env=_env(),
                          stdin=subprocess.DEVNULL)
    assert done.stdout.strip(), done.stderr[-300:]
    bad = [i for i, b in enumerate(done.stdout) if b > 0x7F]
    assert not bad, done.stdout[max(0, bad[0] - 60):bad[0] + 12]


def test_the_ascii_check_can_fail(tmp_path):
    """Control: without --ascii the same --full --fast report does carry non-ASCII."""
    done = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", SAFE, *_QUIET, "--full", "--fast"],
        cwd=REPO_ROOT, capture_output=True, timeout=450, env=_env(PYTHONIOENCODING="utf-8"),
        stdin=subprocess.DEVNULL)
    assert any(b > 0x7F for b in done.stdout)


def test_ascii_does_not_touch_json_output(tmp_path):
    done = _cli(["--home", SAFE, *_QUIET, "--ascii", "--json"], tmp_path)
    json.loads(done.stdout)


def test_an_unreadable_home_under_json_is_one_json_object(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads a mode-000 directory, so the failure cannot be produced")
    locked = tmp_path / "locked"
    locked.mkdir()
    os.chmod(locked, 0)
    try:
        as_json = _cli(["--home", str(locked), *_QUIET, "--json"], tmp_path)
        plain = _cli(["--home", str(locked), *_QUIET], tmp_path)
    finally:
        os.chmod(locked, 0o700)
    assert as_json.returncode == plain.returncode == 1
    doc = json.loads(as_json.stdout)
    assert doc["tool"] == "clawseccheck" and doc["version"]
    assert doc["error"].startswith("Cannot read the OpenClaw home at ")
    assert doc["error"] in as_json.stderr  # stderr keeps the sentence
    assert plain.stdout.startswith("Cannot read the OpenClaw home at ")  # unchanged
