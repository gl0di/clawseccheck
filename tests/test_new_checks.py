"""B17 autonomy/heartbeat, B18 subagents, B19 data-at-rest."""
from pathlib import Path

from clawcheck.checks import check_autonomy, check_data_atrest, check_subagents
from clawcheck.collector import Context


def _ctx(cfg=None, bootstrap=None, home="/x"):
    c = Context(home=Path(home))
    c.config = cfg or {}
    c.bootstrap = bootstrap or {}
    return c


# ---- B17 autonomy / heartbeat ----
def test_b17_heartbeat_file_warns():
    assert check_autonomy(_ctx({}, {"workspace/HEARTBEAT.md": "x"})).status == "WARN"


def test_b17_heartbeat_config_warns():
    assert check_autonomy(_ctx({"agents": {"defaults": {"heartbeat": {"every": "1m"}}}})).status == "WARN"


def test_b17_no_autonomy_unknown():
    assert check_autonomy(_ctx({}, {})).status == "UNKNOWN"


# ---- B18 subagents ----
def test_b18_subagents_risky_no_approval_warns():
    c = _ctx({"agents": {"subagents": {"maxConcurrent": 4}},
              "tools": {"elevated": {"allowFrom": ["o"]}}})
    assert check_subagents(c).status == "WARN"


def test_b18_subagents_risky_with_approval_passes():
    c = _ctx({"agents": {"subagents": {"maxConcurrent": 4}},
              "tools": {"elevated": {"allowFrom": ["o"]}, "confirm": True}})
    assert check_subagents(c).status == "PASS"


def test_b18_subagents_no_risky_unknown():
    assert check_subagents(_ctx({"agents": {"subagents": {"maxConcurrent": 4}}})).status == "UNKNOWN"


def test_b18_no_subagents_unknown():
    assert check_subagents(_ctx({})).status == "UNKNOWN"


# ---- B19 data at-rest ----
def test_b19_loose_memory_dir_warns(tmp_path):
    m = tmp_path / "workspace" / "memory"
    m.mkdir(parents=True)
    m.chmod(0o777)
    assert check_data_atrest(_ctx({}, home=str(tmp_path))).status == "WARN"


def test_b19_tight_memory_dir_passes(tmp_path):
    m = tmp_path / "workspace" / "memory"
    m.mkdir(parents=True)
    m.chmod(0o700)
    assert check_data_atrest(_ctx({}, home=str(tmp_path))).status == "PASS"


def test_b19_no_dirs_unknown(tmp_path):
    assert check_data_atrest(_ctx({}, home=str(tmp_path))).status == "UNKNOWN"


def test_b19_windows_is_unknown(monkeypatch, tmp_path):
    from clawcheck import checks
    monkeypatch.setattr(checks, "_is_posix", lambda: False)
    assert check_data_atrest(_ctx({}, home=str(tmp_path))).status == "UNKNOWN"
