"""C5 Native binary PATH safety tests."""
import os
from pathlib import Path

from clawseccheck.checks import check_path_safety
from clawseccheck.collector import Context


def _ctx():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.include_host = True  # these tests exercise the host-PATH scan (B-021 gate)
    return c


# ---- non-POSIX -> UNKNOWN ----
def test_c5_non_posix_unknown(monkeypatch):
    from clawseccheck import checks
    monkeypatch.setattr(checks, "_is_posix", lambda: False)
    result = check_path_safety(_ctx())
    assert result.status == "UNKNOWN"
    assert result.id == "C5"


# ---- openclaw not on PATH -> UNKNOWN ----
def test_c5_not_on_path_unknown(monkeypatch):
    import shutil
    from clawseccheck import checks
    monkeypatch.setattr(checks, "_is_posix", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    result = check_path_safety(_ctx())
    assert result.status == "UNKNOWN"
    assert result.id == "C5"


# ---- binary dir is group/world-writable -> WARN ----
def test_c5_writable_binary_dir_warns(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks

    # Create a fake openclaw binary in a world-writable dir.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh\necho openclaw")
    fake_exe.chmod(0o755)

    bin_dir.chmod(0o777)   # world-writable — should trigger WARN
    try:
        monkeypatch.setattr(checks, "_is_posix", lambda: True)
        monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
        # PATH only contains the binary dir itself (no dirs before it).
        monkeypatch.setenv("PATH", str(bin_dir))

        result = check_path_safety(_ctx())
        assert result.status == "WARN"
        assert result.id == "C5"
        assert any("binary dir" in e for e in result.evidence)
    finally:
        bin_dir.chmod(0o755)


# ---- earlier PATH dir is group/world-writable -> WARN ----
def test_c5_writable_earlier_path_dir_warns(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks

    # A tight dir for the real binary.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh\necho openclaw")
    fake_exe.chmod(0o755)
    bin_dir.chmod(0o755)  # tight

    # A world-writable dir that comes BEFORE bin_dir in PATH.
    evil_dir = tmp_path / "evil"
    evil_dir.mkdir()
    evil_dir.chmod(0o777)
    try:
        monkeypatch.setattr(checks, "_is_posix", lambda: True)
        monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
        monkeypatch.setenv("PATH", f"{evil_dir}{os.pathsep}{bin_dir}")

        result = check_path_safety(_ctx())
        assert result.status == "WARN"
        assert result.id == "C5"
        assert any("before openclaw dir" in e for e in result.evidence)
    finally:
        evil_dir.chmod(0o755)


# ---- later PATH dir writable (AFTER openclaw dir) -> PASS (not a shadow risk) ----
def test_c5_writable_later_path_dir_passes(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh\necho openclaw")
    fake_exe.chmod(0o755)
    bin_dir.chmod(0o755)

    # A world-writable dir that comes AFTER bin_dir — not a shadow risk.
    later_dir = tmp_path / "later"
    later_dir.mkdir()
    later_dir.chmod(0o777)
    try:
        monkeypatch.setattr(checks, "_is_posix", lambda: True)
        monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
        monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{later_dir}")

        result = check_path_safety(_ctx())
        assert result.status == "PASS"
        assert result.id == "C5"
    finally:
        later_dir.chmod(0o755)


# ---- all dirs tight -> PASS ----
def test_c5_tight_path_passes(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh\necho openclaw")
    fake_exe.chmod(0o755)
    bin_dir.chmod(0o755)

    pre_dir = tmp_path / "usr_bin"
    pre_dir.mkdir()
    pre_dir.chmod(0o755)

    monkeypatch.setattr(checks, "_is_posix", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
    monkeypatch.setenv("PATH", f"{pre_dir}{os.pathsep}{bin_dir}")

    result = check_path_safety(_ctx())
    assert result.status == "PASS"
    assert result.id == "C5"


# ---- precision: a group-only (775) dir must NOT be called "world-writable" ----
def test_c5_group_only_dir_says_group_not_world(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh")
    fake_exe.chmod(0o755)
    bin_dir.chmod(0o775)   # group-writable ONLY (o=r-x, no world write)
    try:
        monkeypatch.setattr(checks, "_is_posix", lambda: True)
        monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
        monkeypatch.setenv("PATH", str(bin_dir))

        result = check_path_safety(_ctx())
        assert result.status == "WARN"
        joined = " ".join(result.evidence)
        assert "group-writable" in joined
        # the overstatement the field round flagged: never claim world-write on a 775 dir
        assert "world-writable" not in joined
        assert "group/world-writable" not in joined
    finally:
        bin_dir.chmod(0o755)


# ---- precision: a 0o757 (world-only-ish) dir says world-writable ----
def test_c5_world_writable_dir_says_world(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh")
    fake_exe.chmod(0o755)
    bin_dir.chmod(0o757)   # world-writable, group not
    try:
        monkeypatch.setattr(checks, "_is_posix", lambda: True)
        monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
        monkeypatch.setenv("PATH", str(bin_dir))

        result = check_path_safety(_ctx())
        assert result.status == "WARN"
        joined = " ".join(result.evidence)
        assert "world-writable" in joined
        assert "group- and world-writable" not in joined
    finally:
        bin_dir.chmod(0o755)


# ---- precision: a 0o777 dir reports BOTH bits ----
def test_c5_group_and_world_writable_dir_says_both(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh")
    fake_exe.chmod(0o755)
    bin_dir.chmod(0o777)
    try:
        monkeypatch.setattr(checks, "_is_posix", lambda: True)
        monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
        monkeypatch.setenv("PATH", str(bin_dir))

        result = check_path_safety(_ctx())
        assert result.status == "WARN"
        joined = " ".join(result.evidence)
        assert "group- and world-writable" in joined
    finally:
        bin_dir.chmod(0o755)


# ---- advisory: scored=False ----
def test_c5_is_not_scored(monkeypatch, tmp_path):
    import shutil
    from clawseccheck import checks

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_exe = bin_dir / "openclaw"
    fake_exe.write_text("#!/bin/sh")
    fake_exe.chmod(0o755)
    bin_dir.chmod(0o755)

    monkeypatch.setattr(checks, "_is_posix", lambda: True)
    monkeypatch.setattr(shutil, "which", lambda name: str(fake_exe))
    monkeypatch.setenv("PATH", str(bin_dir))

    result = check_path_safety(_ctx())
    assert result.scored is False


# B-021: C5 is a host-filesystem check -> gated by include_host (--no-host).

def test_c5_skipped_when_host_scan_disabled(monkeypatch):
    """With host scanning off (include_host=False), C5 must not stat the host -> UNKNOWN."""
    from clawseccheck.catalog import UNKNOWN
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.include_host = False  # e.g. --no-host
    # Even on a POSIX box with a real PATH, the gate short-circuits before any stat().
    result = check_path_safety(c)
    assert result.status == UNKNOWN
    assert "no-host" in (result.detail or "").lower() or "host-filesystem" in (result.detail or "").lower()


def test_c5_default_context_is_host_disabled():
    """A bare Context defaults include_host=False -> C5 UNKNOWN (no incidental host stat)."""
    from clawseccheck.catalog import UNKNOWN
    assert check_path_safety(Context(home=Path("/nonexistent"))).status == UNKNOWN
