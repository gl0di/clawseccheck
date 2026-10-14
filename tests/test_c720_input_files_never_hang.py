"""C-720: a file named on an input flag never hangs the tool and never crashes it.

A named pipe given to `--attest`, `--judged`, `--state` ... blocked forever (an ordinary
open() of a FIFO waits for a writer), and a state or proposals file that was not UTF-8 ended
in "unexpected internal error". This drives every flag whose value is a path that is READ
through the real CLI, against every shape of file a user can name, with a hard timeout: the
timeout IS the no-hang assertion. The FIFO is never opened for writing by the test, so a
blocking open() on it has no way to return.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT_S = 30
SHAPES = ("fifo", "dir", "socket", "binary", "badutf8", "empty", "big")
NONREG = ("fifo", "socket")
UNDECODABLE = ("binary", "badutf8")

_COMMON = ["--no-native", "--no-deptree", "--no-host"]


def _shape_content(shape):
    if shape == "binary":
        return bytes(range(256)) * 8
    if shape == "badutf8":
        return b'{"a": "\xc3\x28", "b": "\xff\xfe"}\n'
    if shape == "empty":
        return b""
    if shape == "big":
        return json.dumps({"x": ["y" * 60] * 50000}).encode()   # about 3 MB of JSON
    raise AssertionError(shape)


# flag-id -> (argv with {p} for the path, {home}/{skill} placeholders;
#             rc for a FIFO/socket, rc for undecodable bytes, rc for empty/big,
#             text the output must carry for a FIFO/socket ("" = identical to a missing path))
_J = "Nothing was judged"
FLAGS = {
    "--attest": (["--no-history", "--attest", "{p}"], 0, 0, 0, ""),
    "--judged": (["--no-history", "--judged", "{p}"], 0, 1, 0, "not a regular file"),
    "--propose-ignore": (["--no-history", "--propose-ignore", "{p}"], 0, 1, 0, "not a regular file"),
    "--judged-bundle": (["--no-history", "--full", "--judged-bundle", "{p}"], 0, 0, 0, "not a regular file"),
    "--vet-judged": (["--vet-skill", "{skill}", "--vet-judged", "{p}"], 0, 1, 0, "not a regular file"),
    "--apply-ignore-proposals": (["--apply-ignore-proposals", "{p}", "--yes"], 1, 1, 1, "not a regular file"),
    "--history": (["--history", "{p}"], 0, 0, 0, ""),
    "--history --trend": (["--trend", "--history", "{p}"], 0, 0, 0, "not a regular file"),
    "--events --watch-log": (["--watch-log", "--events", "{p}"], 0, 0, 0, "not a regular file"),
    "--events --brief": (["--brief", "--events", "{p}"], 0, 0, 0, ""),
    "--history --brief": (["--brief", "--history", "{p}"], 0, 0, 0, ""),
    "--state --brief": (["--brief", "--state", "{p}"], 0, 0, 0, ""),
    "--state --monitor": (["--monitor", "--state", "{p}"], 0, 0, 0,
                          "previous monitor baseline could not be read"),
    "--state --verify-baseline": (["--verify-baseline", "abcdef123456", "--state", "{p}"], 1, 1, 1, ""),
}
# Path-valued options that are NOT read as a file through this table, and why.
OTHER = {
    "--home": "a directory the audit walks (collector), not a single input file",
    "--data-dir": "a directory for our own store",
    "--save": "output", "--badge": "output", "--html": "output", "--sarif": "output",
    "--pdf": "output", "--log": "output (another task)",
    "--verify-baseline": "REFERENCE is a digest, not a path; its --state file is in the table",
}
# Path-valued options that are run through the CLI below but have no read-through-the-helper
# row, with the reason none is needed: each one stats the path first and never opens a
# non-regular file, so the assertion is "no hang, no crash" (plus, for the two trajectory
# modes, that a named FIFO is reported as a path problem rather than as an empty scan).
NO_HANG_ONLY = {
    "--vet-mcp": (["--vet-mcp", "{p}"], "NAME|FILE: a non-file is treated as a name, never opened"),
    "--analyze-trajectory": (["--analyze-trajectory", "{p}"], "is_file probe before any open"),
    "--behavioral": (["--behavioral", "{p}"], "is_file probe before any open"),
    "--advise": (["--advise", "{p}"], "a directory to assess; is_dir probe, never opened"),
    "--vet-skill": (["--vet-skill", "{p}"], "a directory to vet; is_dir probe, never opened"),
    "--vet-plugin": (["--vet-plugin", "{p}"], "a directory to vet; is_dir probe, never opened"),
}
TRAJECTORY = ("--analyze-trajectory", "--behavioral")


def _fill(argv, p, home, skill):
    return [a.replace("{p}", str(p)).replace("{home}", str(home)).replace("{skill}", str(skill))
            for a in argv]


def _run_cli(argv, cwd):
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env["PYTHONPATH"] = str(ROOT)
    env["HOME"] = str(cwd)
    cmd = [sys.executable, "-m", "clawseccheck", "--no-deptree", "--no-host"] + argv
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_S, cwd=str(cwd),
                           env=env, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, ""
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def _make_input(job_dir, shape):
    p = job_dir / "in"
    if shape == "fifo":
        os.mkfifo(p)
    elif shape == "dir":
        p.mkdir()
    elif shape == "socket":
        sock = socket.socket(socket.AF_UNIX)
        here = os.getcwd()
        os.chdir(job_dir)          # AF_UNIX paths are short; bind a relative name
        try:
            sock.bind("in")
        finally:
            os.chdir(here)
        return p, sock
    elif shape != "missing":
        p.write_bytes(_shape_content(shape))
    return p, None


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    base = tmp_path_factory.mktemp("c720")
    jobs, socks = [], []
    table = dict(FLAGS)
    table.update({k: (v[0], None, None, None, "") for k, v in NO_HANG_ONLY.items()})
    for flag, (argv, *_rest) in table.items():
        for shape in SHAPES + ("missing",):
            jd = base / f"{len(jobs)}"
            jd.mkdir()
            home = jd / "home"
            shutil.copytree(ROOT / "fixtures" / "home_safe", home)
            skill = jd / "skill"
            shutil.copytree(ROOT / "fixtures" / "clean_b61_normal_skill", skill)
            p, sock = _make_input(jd, shape)
            if sock is not None:
                socks.append(sock)
            full = ["--home", str(home), "--data-dir", str(jd / "dd")] + _COMMON + _fill(argv, p, home, skill)
            jobs.append((flag, shape, full, jd))
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            outs = list(pool.map(lambda j: _run_cli(j[2], j[3]), jobs))
    finally:
        for s in socks:
            s.close()
    out = {(j[0], j[1]): (rc, text.replace(str(base), "<T>")) for j, (rc, text) in zip(jobs, outs)}
    shutil.rmtree(base, ignore_errors=True)
    return out


def test_every_path_valued_option_is_in_a_table():
    """New input flag => a decision here (read it through the table, or say why not)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env["PYTHONPATH"] = str(ROOT)
    help_text = subprocess.run([sys.executable, "-m", "clawseccheck", "--no-deptree", "--no-host",
                                "--help"], capture_output=True,
                               text=True, timeout=TIMEOUT_S, env=env, cwd=str(ROOT)).stdout
    found = set(re.findall(
        r"^\s+(--[a-z0-9-]+)(?:, -\w)? \[?(?:PATH|FILE|DIR|REFERENCE|NAME\|FILE)\]?(?=\s|$)",
        help_text, re.M))
    assert found, "could not read the option list from --help"
    covered = {f.split()[0] for f in FLAGS}
    # exactly one table per option
    assert not (covered & set(OTHER)) and not (covered & set(NO_HANG_ONLY))
    assert not (set(OTHER) & set(NO_HANG_ONLY))
    unknown = found - covered - set(OTHER) - set(NO_HANG_ONLY)
    assert not unknown, f"path-valued option(s) with no entry in the C-720 tables: {sorted(unknown)}"


@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("flag", sorted(FLAGS) + sorted(NO_HANG_ONLY))
def test_no_hang_no_crash(results, flag, shape):
    rc, text = results[(flag, shape)]
    assert rc is not None, f"{flag} {shape}: no answer within {TIMEOUT_S}s (hang)"
    assert "Traceback" not in text, f"{flag} {shape}: traceback"
    assert "unexpected internal error" not in text, f"{flag} {shape}: crashed"
    if flag in TRAJECTORY and shape in NONREG:
        assert rc == results[(flag, "missing")][0] == 1, f"{flag} {shape}: rc {rc}\n{text[-400:]}"
        assert "not a regular file" in text, f"{flag} {shape}: not reported\n{text[-400:]}"
    if flag not in FLAGS:
        return
    _argv, rc_nonreg, rc_undecodable, rc_text, note = FLAGS[flag]
    if shape in NONREG:
        assert rc == rc_nonreg, f"{flag} {shape}: rc {rc}\n{text[-600:]}"
        assert note in text, f"{flag} {shape}: expected {note!r} in the output\n{text[-600:]}"
        # the same exit code as a path that does not exist
        assert rc == results[(flag, "missing")][0]
    elif shape in UNDECODABLE:
        assert rc == rc_undecodable, f"{flag} {shape}: rc {rc}\n{text[-600:]}"
    elif shape in ("empty", "big"):
        assert rc == rc_text, f"{flag} {shape}: rc {rc}\n{text[-600:]}"


def test_undecodable_state_is_a_corrupt_baseline_and_is_replaced(tmp_path):
    """The monitor said "internal error" on every run until the user deleted the file."""
    home = tmp_path / "home"
    shutil.copytree(ROOT / "fixtures" / "home_safe", home)
    state = tmp_path / "state.json"
    state.write_bytes(b'{"a": "\xc3\x28"}\xff\xfe')
    argv = ["--home", str(home), "--data-dir", str(tmp_path / "dd"), *_COMMON,
            "--monitor", "--state", str(state)]
    rc, text = _run_cli(argv, tmp_path)
    assert rc == 0 and "previous monitor baseline could not be read" in text, text[-600:]
    assert json.loads(state.read_text(encoding="utf-8"))      # replaced by a real baseline
    rc2, text2 = _run_cli(argv, tmp_path)                       # and the next run reads it
    assert rc2 == 0 and "could not be read" not in text2, text2[-600:]


def test_valid_files_still_work(tmp_path):
    """Controls: the same flags with a regular, valid file behave as they did."""
    home = tmp_path / "home"
    shutil.copytree(ROOT / "fixtures" / "home_safe", home)
    skill = tmp_path / "skill"
    shutil.copytree(ROOT / "fixtures" / "clean_b61_normal_skill", skill)
    from clawseccheck.attest import template
    att = tmp_path / "att.json"
    att.write_text(json.dumps(template()), encoding="utf-8")
    judged = tmp_path / "judged.json"
    judged.write_text("{}", encoding="utf-8")
    prop = tmp_path / "prop.json"
    prop.write_text(json.dumps({"proposedIgnoreEntries": []}), encoding="utf-8")
    base = ["--home", str(home), "--data-dir", str(tmp_path / "dd"), *_COMMON]
    for argv in (["--no-history", "--attest", str(att)],
                 ["--no-history", "--judged", str(judged)],
                 ["--no-history", "--propose-ignore", str(judged)],
                 ["--no-history", "--full", "--judged-bundle", str(judged)],
                 ["--vet-skill", str(skill), "--vet-judged", str(judged)]):
        rc, text = _run_cli(base + argv, tmp_path)
        assert rc == 0, (argv, text[-400:])
        assert "not a regular file" not in text and "could not read" not in text, (argv, text[-400:])
    rc, text = _run_cli(base + ["--apply-ignore-proposals", str(prop), "--yes"], tmp_path)
    assert "could not read" not in text and "Traceback" not in text, text[-400:]
    for _ in range(2):      # second run reads the baseline the first one saved
        rc, text = _run_cli(base + ["--monitor", "--state", str(tmp_path / "s.json")], tmp_path)
        assert rc == 0 and "could not be read" not in text, text[-400:]


def test_reader_contract(tmp_path):
    """The helper itself: bounded, never opens a FIFO blocking, follows symlinks."""
    from clawseccheck import safeio
    fifo = tmp_path / "f"
    os.mkfifo(fifo)
    link = tmp_path / "l"
    link.symlink_to(fifo)
    reg = tmp_path / "r"
    reg.write_bytes(b"a\r\nb")
    for p in (fifo, link, Path("/dev/null")):
        with pytest.raises(safeio.NotARegularFile) as ei:
            safeio.read_user_file(p)
        assert ei.value.strerror == "not a regular file"
    with pytest.raises(IsADirectoryError):
        safeio.read_user_file(tmp_path)
    with pytest.raises(FileNotFoundError):
        safeio.read_user_file(tmp_path / "nope")
    assert safeio.read_user_file(reg) == b"a\r\nb"
    assert safeio.read_user_text(reg) == reg.read_text(encoding="utf-8") == "a\nb"
    with pytest.raises(safeio.UserFileTooLarge):
        safeio.read_user_file(reg, max_bytes=3)
    reg.write_bytes(b"\xff")
    with pytest.raises(UnicodeDecodeError):
        safeio.read_user_text(reg)
