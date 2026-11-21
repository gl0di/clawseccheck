"""B-1115 - a `clawseccheck` console script on PATH is used only when it runs THIS install.

A pipx copy of an older release on PATH made `machine_command_prefix()` write scheduler jobs
that would run that other version, not the one that wrote them. The script now counts only
when its shebang interpreter's prefix equals `sys.prefix`; an unreadable shebang (a Windows
`.exe` launcher) keeps the old trust.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from clawseccheck import invocation as inv

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shebang console scripts")

_MAIN = str(Path(inv.__file__).resolve().parent / "__main__.py")


def _console(bindir: Path, first_lines: str) -> Path:
    bindir.mkdir(parents=True, exist_ok=True)
    script = bindir / "clawseccheck"
    script.write_text(first_lines + "import sys\nfrom clawseccheck.cli import main\n", encoding="utf-8")
    script.chmod(0o755)
    return script


@pytest.fixture
def started_as_module(monkeypatch):
    monkeypatch.setattr(sys, "argv", [_MAIN], raising=False)


def _this_interp() -> str:
    return os.path.join(os.path.abspath(sys.prefix), "bin", "python3")


def test_a_foreign_install_on_path_is_not_used(tmp_path, monkeypatch, started_as_module):
    other = tmp_path / "venvs" / "clawseccheck"
    _console(tmp_path / "bin", f"#!{other}/bin/python\n")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    assert inv._console_script_for_this_install() is None
    prefix = inv.machine_command_prefix()
    assert str(tmp_path / "bin" / "clawseccheck") not in prefix
    assert "audit.py" in prefix or " -m clawseccheck" in prefix


def test_the_running_install_s_console_script_is_used(tmp_path, monkeypatch, started_as_module):
    script = _console(tmp_path / "bin", f"#!{_this_interp()}\n")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    assert inv._console_script_for_this_install() == str(script)
    assert inv.machine_command_prefix() == inv._display_path(str(script))


def test_a_venv_that_links_to_the_system_python_is_still_foreign(tmp_path, monkeypatch):
    """Not symlink-resolved: a venv's bin/python usually points at the system interpreter."""
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").symlink_to(sys.executable)
    _console(tmp_path / "bin", f"#!{venv_bin / 'python'}\n")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    assert inv._console_script_for_this_install() is None


def test_env_shebang_resolves_on_path(tmp_path, monkeypatch):
    pybin = Path(os.path.abspath(sys.prefix)) / "bin"
    _console(tmp_path / "bin", "#!/usr/bin/env python3\n")
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{pybin}")
    interp = inv._console_script_interpreter(str(tmp_path / "bin" / "clawseccheck"))
    assert interp is not None and Path(interp).name.startswith("python")


@pytest.mark.parametrize("line", [
    "'''exec' \"/opt/long path/venv/bin/python\" \"$0\" \"$@\"\n",
    "'''exec' /opt/venv/bin/python \"$0\" \"$@\"\n",
])
def test_pips_sh_trampoline_is_read(tmp_path, line):
    script = _console(tmp_path / "bin", "#!/bin/sh\n" + line + "' '''\n")
    interp = inv._console_script_interpreter(str(script))
    assert interp in ("/opt/long path/venv/bin/python", "/opt/venv/bin/python")


def test_an_unreadable_shebang_keeps_the_old_trust(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "clawseccheck"
    script.write_bytes(b"MZ\x90\x00 a launcher binary")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    assert inv._console_script_for_this_install() == str(script)


def test_the_human_form_does_not_name_a_foreign_install(tmp_path, monkeypatch):
    """`command_prefix()` falls back to which() only when argv[0] told nothing."""
    _console(tmp_path / "bin", f"#!{tmp_path}/elsewhere/bin/python\n")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    monkeypatch.setattr(sys, "argv", ["/usr/lib/some-host/embed"], raising=False)
    if inv._shim_beside_the_package() is None:
        pytest.skip("no audit.py beside the package in this layout")
    assert inv.command_prefix().startswith("python3 ")
