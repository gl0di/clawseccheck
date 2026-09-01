"""B-707 — the host-monitor scan asked about the auditor's PATH, not about the host.

Every monitor in `hostwatch.py` is located with `shutil.which`, and `shutil.which` answers a
question about the CURRENT PROCESS'S PATH. For a scheduled run that is a different question
with a different answer: a classic user crontab runs with `PATH=/usr/bin:/bin`, which excludes
`/usr/sbin` and `/usr/local/bin`, and a systemd timer inherits whatever its unit specifies —
often nothing.

Measured on this machine before the fix (openclaw 2026.8.2, monitors as actually installed):

    real shell PATH        tunnel_transport present ["Tailscale", "ngrok"]
    PATH=/usr/bin:/bin     tunnel_transport present ["Tailscale"]          <- ngrok lost
    PATH unset             tunnel_transport present ["Tailscale"]
    PATH=""                tunnel_transport unknown []                     <- class lost

`ngrok` is at /usr/local/bin and `ufw`/`nft`/`iptables` at /usr/sbin — exactly the directories
a cron PATH drops. The host did not change between those runs; only the question did.

Found by verifying B-703's DoD rather than by reading: two `--monitor` runs on one data-dir,
PATH set then emptied, produced different baseline references and a coverage-loss note.
"""
import os
import shutil
import stat
import tempfile
from pathlib import Path

import pytest

from clawseccheck import hostwatch


@pytest.fixture()
def path_env(monkeypatch):
    """Set PATH to an exact value (or remove it) for one test."""
    def _set(value):
        if value is None:
            monkeypatch.delenv("PATH", raising=False)
        else:
            monkeypatch.setenv("PATH", value)
    return _set


def _classes(**kw):
    return {k: (v.get("status"), tuple(v.get("found") or ()))
            for k, v in hostwatch.detect(**kw).get("classes", {}).items()}


# ======================================================================================
# 1. The property, on this machine: the answer must not depend on the run shape
# ======================================================================================

@pytest.mark.parametrize("path_value", [None, "", "/usr/bin:/bin"],
                         ids=["unset", "empty", "user-crontab"])
def test_the_host_answer_does_not_change_with_the_auditors_path(path_env, path_value):
    """The actual property, asserted as EQUALITY against the interactive answer rather than
    as an expectation about any particular monitor — whatever this host has, a scheduled run
    has to see the same thing, because the host is the same.
    """
    interactive = _classes()
    path_env(path_value)
    scheduled = _classes()
    differing = {k for k in interactive if interactive[k] != scheduled.get(k)}
    assert not differing, (
        "the host-monitor answer moved with the auditor's PATH: "
        + "; ".join(f"{k}: {interactive[k]} -> {scheduled.get(k)}" for k in sorted(differing)))


def test_the_equality_above_is_not_vacuous():
    """Without a monitor to find, the test above passes on any implementation. This asserts
    the corpus it runs against is non-empty on this machine — and SKIPS rather than fails
    where it is not, since a host with no monitors installed is a legitimate state.
    """
    found = sum(len(v[1]) for v in _classes().values())
    if not found:
        pytest.skip("no host monitors installed here — the equality test cannot discriminate")
    assert found > 0


# ======================================================================================
# 2. The resolver itself, on a constructed tree — deterministic, no reliance on this host
# ======================================================================================

def _fake_bin(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    exe = directory / name
    exe.write_text("#!/bin/sh\n")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return exe


def test_the_resolver_prefers_path_over_the_fallback(path_env, monkeypatch):
    """PATH first, always. An operator who put a monitor earlier on PATH than the system copy
    means that one, and the fallback must not silently prefer a different binary — that would
    make the fix a correctness regression dressed as a robustness win.
    """
    tmp = Path(tempfile.mkdtemp(prefix="b707-"))
    on_path = _fake_bin(tmp / "early", "suricata")
    fallback_dir = tmp / "sysbin"
    _fake_bin(fallback_dir, "suricata")

    path_env(str(tmp / "early"))
    monkeypatch.setattr(hostwatch, "_SYSTEM_PATH_FALLBACK", (str(fallback_dir),))
    resolve = hostwatch._default_path_resolver("Linux")
    assert resolve("suricata") == str(on_path)


def test_the_resolver_finds_a_system_binary_that_path_omits(path_env, monkeypatch):
    """The case the fix exists for: the binary is installed in a conventional system
    directory and the process PATH does not list it."""
    tmp = Path(tempfile.mkdtemp(prefix="b707-"))
    fallback_dir = tmp / "sysbin"
    planted = _fake_bin(fallback_dir, "auditctl")

    path_env(str(tmp / "nothing-here"))
    monkeypatch.setattr(hostwatch, "_SYSTEM_PATH_FALLBACK", (str(fallback_dir),))
    resolve = hostwatch._default_path_resolver("Linux")
    assert resolve("auditctl") == str(planted)


def test_the_resolver_still_answers_none_for_a_binary_that_is_not_there(path_env, monkeypatch):
    """The control. Without it, "always return a path" satisfies both tests above, and an
    absent monitor would be reported as present — the direction that actually harms, since
    this scan's output feeds "is anyone watching?"."""
    tmp = Path(tempfile.mkdtemp(prefix="b707-"))
    (tmp / "sysbin").mkdir(parents=True)
    path_env(str(tmp / "nothing-here"))
    monkeypatch.setattr(hostwatch, "_SYSTEM_PATH_FALLBACK", (str(tmp / "sysbin"),))
    resolve = hostwatch._default_path_resolver("Linux")
    assert resolve("definitely-not-a-real-monitor-binary") is None


def test_windows_keeps_plain_shutil_which():
    """The fallback list is POSIX and meaningless on Windows, where `_detect_windows` also
    corroborates through `winreg` rather than PATH alone. Asserted by identity so a future
    edit cannot quietly wrap it."""
    assert hostwatch._default_path_resolver("Windows") is shutil.which
    assert hostwatch._default_path_resolver("Linux") is not shutil.which


def test_every_fallback_directory_is_absolute_and_conventional():
    """A relative entry would resolve against the auditor's cwd — which a cron job does not
    control either, so it would reintroduce the same class of bug in a new place."""
    assert hostwatch._SYSTEM_PATH_FALLBACK, "an empty list would make the fallback decorative"
    for d in hostwatch._SYSTEM_PATH_FALLBACK:
        assert d.startswith("/"), d
        assert d.split("/")[-1] in {"bin", "sbin"}, d


# ======================================================================================
# 3. The injection contract the suite depends on is untouched
# ======================================================================================

def test_an_injected_resolver_still_wins_over_the_default():
    """Every other hostwatch test passes `which=`. If the default resolver ever displaced an
    injected one the suite would start reading this developer's real filesystem, which is
    both non-deterministic and a doctrine violation."""
    called = []

    def fake(name):
        called.append(name)
        return None

    hostwatch.detect(root="/nonexistent-root-for-b707", system="Linux", which=fake)
    assert called, "the injected resolver was never consulted"
    assert all(isinstance(n, str) for n in called)


def test_the_default_resolver_runs_no_subprocess():
    """`hostwatch`'s own doctrine, asserted on the source: PATH is READ, never executed.
    Comments and docstring stripped first — the prose says "no subprocess", and a scan that
    reads its own explanation as the violation can only be satisfied by deleting the
    sentence that explains it.
    """
    source = (Path(hostwatch.__file__)).read_text(encoding="utf-8")
    body = source.split("def _default_path_resolver", 1)[1].split("\ndef ", 1)[0]
    code = body.split('"""', 2)[-1]
    code = "\n".join(ln for ln in code.splitlines() if not ln.lstrip().startswith("#"))
    for forbidden in ("subprocess", "popen", "os.system", "os.exec"):
        assert forbidden not in code.lower(), forbidden


def test_the_fallback_does_not_consult_the_environment_it_is_replacing(monkeypatch):
    """The fallback must be a fixed list, not something derived from PATH — deriving it from
    the very variable that is missing would make it a no-op exactly when it is needed."""
    tmp = Path(tempfile.mkdtemp(prefix="b707-"))
    planted = _fake_bin(tmp / "sysbin", "zeek")
    monkeypatch.setattr(hostwatch, "_SYSTEM_PATH_FALLBACK", (str(tmp / "sysbin"),))
    resolve = hostwatch._default_path_resolver("Linux")
    for path_value in ("", None, "/nowhere"):
        if path_value is None:
            monkeypatch.delenv("PATH", raising=False)
        else:
            monkeypatch.setenv("PATH", path_value)
        assert resolve("zeek") == str(planted), f"PATH={path_value!r}"


def test_os_and_shutil_are_imported_at_module_level():
    """The resolver runs on every audit; a deferred import inside it would add a file-system
    stat to the hot path for no benefit. Cheap structural pin."""
    assert hostwatch.os is os
    assert hostwatch.shutil is shutil
