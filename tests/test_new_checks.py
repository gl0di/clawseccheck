"""B17 autonomy/heartbeat, B18 subagents, B19 data-at-rest."""
from pathlib import Path

from clawseccheck.checks import check_autonomy, check_data_atrest, check_subagents
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


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


# ---- B-129: HEARTBEAT.md content-blindness fix ----

def test_b17_heartbeat_file_with_real_task_lines_warns():
    """Clean-behavior confirmation: real task content still fires the WARN."""
    text = "# Heartbeat tasks\n\nCheck inbox every 5 minutes and reply to urgent emails.\n"
    f = check_autonomy(_ctx({}, {"workspace/HEARTBEAT.md": text}))
    assert f.status == "WARN"


def test_b17_heartbeat_file_empty_no_config_is_unknown():
    """B-129 clean fixture: an empty HEARTBEAT.md with no config key -> UNKNOWN, not WARN."""
    f = check_autonomy(_ctx({}, {"workspace/HEARTBEAT.md": ""}))
    assert f.status == "UNKNOWN"


def test_b17_heartbeat_file_whitespace_only_no_config_is_unknown():
    f = check_autonomy(_ctx({}, {"workspace/HEARTBEAT.md": "   \n\n\t\n"}))
    assert f.status == "UNKNOWN"


def test_b17_heartbeat_file_comments_only_no_config_is_unknown():
    """B-129 clean fixture: a disabled, comments-only template must not be reported as an
    active schedule."""
    text = (
        "# HEARTBEAT.md template\n"
        "# Add real task entries below to enable heartbeat scheduling.\n"
        "<!-- Example: check inbox every 5 minutes -->\n"
    )
    f = check_autonomy(_ctx({}, {"workspace/HEARTBEAT.md": text}))
    assert f.status == "UNKNOWN"
    assert "no task content" in f.detail.lower()


def test_b17_heartbeat_file_multiline_html_comment_only_is_unknown():
    text = (
        "# template\n"
        "<!--\n"
        "check inbox every 5 minutes\n"
        "reply to urgent emails\n"
        "-->\n"
    )
    f = check_autonomy(_ctx({}, {"workspace/HEARTBEAT.md": text}))
    assert f.status == "UNKNOWN"


def test_b17_heartbeat_file_comments_only_but_cron_config_still_warns():
    """A comments-only HEARTBEAT.md alongside a real cron config key must still WARN —
    the config-key signal is independent of file content."""
    text = "# template only\n<!-- disabled -->\n"
    f = check_autonomy(_ctx({"cron": {"schedule": "*/5 * * * *"}}, {"workspace/HEARTBEAT.md": text}))
    assert f.status == "WARN"


def test_b17_clean_fixture_disabled_template_end_to_end():
    """clean_b17_heartbeat_template_disabled: a real on-disk, comments-only HEARTBEAT.md
    with no heartbeat/cron config key, through the real collect() -> check_autonomy()
    path -> UNKNOWN, not the old filename-only MEDIUM WARN."""
    ctx = collect(FIXTURES / "clean_b17_heartbeat_template_disabled")
    f = check_autonomy(ctx)
    assert f.status == "UNKNOWN"
    assert "no task content" in f.detail.lower()


def test_b17_heartbeat_file_text_after_html_comment_close_counts_as_content():
    text = "<!-- note --> Check inbox every 5 minutes\n"
    f = check_autonomy(_ctx({}, {"workspace/HEARTBEAT.md": text}))
    assert f.status == "WARN"


# ---- B18 subagents ----
def test_b18_subagents_risky_no_approval_warns():
    c = _ctx({"agents": {"subagents": {"maxConcurrent": 4}},
              "tools": {"elevated": {"allowFrom": ["o"]}}})
    assert check_subagents(c).status == "WARN"


def test_b18_subagents_risky_with_approval_passes():
    c = _ctx({"agents": {"subagents": {"maxConcurrent": 4}},
              "tools": {"elevated": {"allowFrom": ["o"]}, "exec": {"mode": "ask"}}})
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
    from clawseccheck import checks
    monkeypatch.setattr(checks._shared, "_is_posix", lambda: False)
    assert check_data_atrest(_ctx({}, home=str(tmp_path))).status == "UNKNOWN"


# ---- F-120: session transcripts + install-backups (path-aware at-rest exposure) ----
def _touch(p: Path, mode: int) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{}")  # stat-only check never reads content — keep it benign
    p.chmod(mode)


def test_b19_loose_transcript_in_traversable_home_warns(tmp_path):
    home = tmp_path / "openclaw"
    t = home / "agents" / "main" / "sessions" / "s1.jsonl"
    _touch(t, 0o644)  # world-readable transcript
    for d in (home, home / "agents", home / "agents" / "main", t.parent):
        d.chmod(0o755)  # whole chain world-traversable -> genuinely reachable
    f = check_data_atrest(_ctx({}, home=str(home)))
    assert f.status == "WARN", f.detail
    assert "s1.jsonl" in " ".join(f.evidence or [])


def test_b19_loose_transcript_sealed_in_tight_home_passes(tmp_path):
    # FP-safety / reference-fleet case: a 0o644 transcript sealed inside a 0o700 home is
    # UNREACHABLE by other users -> no spurious WARN (the umask-default flood this guards).
    home = tmp_path / "openclaw"
    t = home / "agents" / "main" / "sessions" / "s1.jsonl"
    _touch(t, 0o644)
    for d in (home / "agents" / "main", home / "agents"):
        d.chmod(0o755)
    home.chmod(0o700)  # home sealed -> nothing inside is reachable
    assert check_data_atrest(_ctx({}, home=str(home))).status == "PASS"


def test_b19_codex_home_loose_transcript_reachable_warns(tmp_path):
    # the codex-home rollout transcripts that are 0o664 by default — flagged only when the
    # path to them is actually traversable by others.
    home = tmp_path / "openclaw"
    t = home / "agents" / "main" / "agent" / "codex-home" / "sessions" / "2026" / "r.jsonl"
    _touch(t, 0o644)
    for d in (home, home / "agents", home / "agents" / "main", home / "agents" / "main" / "agent",
              t.parent.parent, t.parent):
        d.chmod(0o755)
    assert check_data_atrest(_ctx({}, home=str(home))).status == "WARN"


def test_b19_world_readable_install_backup_warns(tmp_path):
    home = tmp_path / "openclaw"
    b = home / ".openclaw-install-backups" / "openclaw.json.bak"
    _touch(b, 0o644)
    for d in (home, b.parent):
        d.chmod(0o755)
    f = check_data_atrest(_ctx({}, home=str(home)))
    assert f.status == "WARN", f.detail
    assert ".openclaw-install-backups" in " ".join(f.evidence or [])


def test_b19_transcript_collection_is_capped(tmp_path):
    from clawseccheck.checks._egress import _collect_atrest_transcripts
    sess = tmp_path / "agents" / "main" / "sessions"
    sess.mkdir(parents=True)
    for i in range(210):
        (sess / f"s{i}.jsonl").write_text("{}")
    assert len(_collect_atrest_transcripts(tmp_path)) <= 200
