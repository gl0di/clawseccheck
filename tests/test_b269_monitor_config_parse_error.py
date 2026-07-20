"""B-269: an unreadable/unparseable openclaw.json must not fabricate removals or let the
grade rise silently.

When the config cannot be read or parsed the collector falls back to ``ctx.config = {}``,
so every config-derived snapshot dimension (mcp / mcp_detail / channels / gateway_bind)
collapses to empty. ``monitor.diff()`` used to read that emptiness as fact and write
"MCP server 'X' was removed." / "Gateway bind changed: '127.0.0.1' -> ''" into the
hash-chained journal against a byte-identical config — while the score *rose*, because the
checks that would have failed had silently become UNKNOWN and UNKNOWN is excluded from the
score denominator. Restoring readability then fired a burst of CRITICAL "NEW MCP server
connected" alerts against the hollowed-out baseline.

Read-only and offline: everything runs against committed fixtures or ``tmp_path``.
"""
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.catalog import BY_ID, FAIL, UNKNOWN
from clawseccheck.cli import main
from clawseccheck.monitor import diff, load_state, snapshot

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CLEAN = FIXTURES / "clean_mon_config_readable"
TRUNCATED = FIXTURES / "bad_mon_config_truncated"

_FABRICATION_MARKERS = (
    "was removed",
    "no longer being read",
    "no longer configured",
    "removed since last check",
    "Gateway bind changed",
    "NEW MCP server",
    "NEW channel",
    "NEW skill installed",
)


def _snap(home, prev=None):
    ctx, findings, score = audit(home)
    return ctx, snapshot(ctx, findings, score, prev=prev)


def _coverage_alerts(alerts):
    return [(lvl, msg) for lvl, msg in alerts if "Could not read openclaw.json" in msg]


def _fabricated(alerts):
    return [(lvl, msg) for lvl, msg in alerts
            if any(marker in msg for marker in _FABRICATION_MARKERS)]


# --------------------------------------------------------------------------- clean

def test_clean_fixture_snapshot_carries_no_parse_error_marker():
    """CLEAN: the readable config produces a normal snapshot with real config dimensions."""
    ctx, snap = _snap(CLEAN)
    assert ctx.config_parse_error is False
    assert "config_parse_error" not in snap
    assert "config_baseline" not in snap
    assert list(snap["mcp"]) == ["weather"]
    assert list(snap["channels"]) == ["telegram"]
    assert snap["gateway_bind"] == "127.0.0.1"


def test_clean_fixture_repeat_run_is_silent():
    """CLEAN: two runs over an unchanged readable config produce no alerts at all."""
    _, first = _snap(CLEAN)
    _, second = _snap(CLEAN, prev=first)
    assert diff(first, second) == []


# ----------------------------------------------------------------------------- bad

def test_truncated_config_sets_parse_error_and_preserves_baseline():
    """BAD: a truncated openclaw.json keeps the last known-good config dimensions."""
    _, good = _snap(CLEAN)
    ctx, blind = _snap(TRUNCATED, prev=good)

    assert ctx.config_parse_error is True
    assert blind["config_parse_error"] is True
    assert blind["config_baseline"] == "carried"
    # The baseline was preserved, NOT overwritten with the collapsed empty view.
    assert blind["mcp"] == good["mcp"]
    assert blind["mcp_detail"] == good["mcp_detail"]
    assert blind["channels"] == good["channels"]
    assert blind["gateway_bind"] == good["gateway_bind"]


def test_truncated_config_emits_coverage_alert_and_no_fabricated_removals():
    """BAD: exactly one coverage-collapse alert, zero fabricated removals/rebinds."""
    _, good = _snap(CLEAN)
    _, blind = _snap(TRUNCATED, prev=good)
    alerts = diff(good, blind)

    coverage = _coverage_alerts(alerts)
    assert len(coverage) == 1, f"expected one coverage alert, got: {alerts}"
    assert coverage[0][0] == "HIGH"
    assert _fabricated(alerts) == [], f"fabricated drift on a blind run: {alerts}"


def test_coverage_alert_names_the_unknown_count_and_warns_about_the_grade():
    """BAD: the alert reports how much coverage was lost and that the grade is not
    comparable — the DoD's 'caution line', without touching scoring."""
    _, good = _snap(CLEAN)
    ctx, blind = _snap(TRUNCATED, prev=good)
    _, findings, _ = audit(TRUNCATED)
    # match the implementation exactly: the snapshot's check map omits suppressed findings
    unknown = sum(1 for f in findings
                  if f.status == UNKNOWN and not getattr(f, "suppressed", False))

    msg = _coverage_alerts(diff(good, blind))[0][1]
    assert f"{unknown} check(s) report UNKNOWN" in msg
    assert "not comparable" in msg
    assert "reduced coverage, not improved security" in msg


def test_blind_run_score_rise_is_not_reported_as_improvement_or_drop():
    """BAD: the score genuinely rises when checks collapse to UNKNOWN. diff() must not
    compare across that boundary in EITHER direction (per the DoD, scoring is unchanged —
    only the comparison is declined)."""
    _, good = _snap(CLEAN)
    _, blind = _snap(TRUNCATED, prev=good)
    assert blind["score"] != good["score"], (
        "fixture no longer demonstrates the score shift this test pins"
    )
    assert not [m for _, m in diff(good, blind) if "score dropped" in m.lower()]
    assert not [m for _, m in diff(blind, good) if "score dropped" in m.lower()]


def test_restore_run_reports_recovery_and_fabricates_nothing():
    """BAD -> CLEAN: coming back from a blind run must not fire the CRITICAL 'NEW MCP
    server connected' burst against a hollowed-out baseline."""
    _, good = _snap(CLEAN)
    _, blind = _snap(TRUNCATED, prev=good)
    _, restored = _snap(CLEAN, prev=blind)

    alerts = diff(blind, restored)
    assert _fabricated(alerts) == [], f"fabricated drift on the restore run: {alerts}"
    assert any(lvl == "INFO" and "readable again" in msg for lvl, msg in alerts)
    assert not any(lvl == "CRITICAL" for lvl, _ in alerts)


# ------------------------------------------------------- unreadable (chmod 000) path

@pytest.fixture()
def unreadable_home(tmp_path):
    """A copy of the clean fixture whose openclaw.json is mode 000 (unreadable)."""
    home = tmp_path / "home"
    shutil.copytree(CLEAN, home)
    cfg = home / "openclaw.json"
    cfg.chmod(0o600)
    yield home, cfg
    # always restore so tmp_path cleanup can remove the tree
    if cfg.exists():
        cfg.chmod(0o600)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the read bit")
def test_unreadable_config_end_to_end_config_bytes_never_change(unreadable_home):
    """The whole B-269 repro, end to end: the config file is byte-identical throughout,
    so every 'removed' / 'NEW' alert the old code emitted was fabricated."""
    home, cfg = unreadable_home
    before = cfg.read_bytes()

    _, good = _snap(home)
    cfg.chmod(0o000)
    ctx_blind, blind = _snap(home, prev=good)
    blind_alerts = diff(good, blind)

    cfg.chmod(0o600)
    assert cfg.read_bytes() == before, "the repro must not modify the config"
    _, restored = _snap(home, prev=blind)
    restore_alerts = diff(blind, restored)

    assert ctx_blind.config_parse_error is True
    assert _fabricated(blind_alerts) == [], blind_alerts
    assert _fabricated(restore_alerts) == [], restore_alerts
    assert len(_coverage_alerts(blind_alerts)) == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the read bit")
def test_unreadable_config_does_not_lose_a_real_change_made_while_blind(unreadable_home):
    """Nothing is lost, only deferred: an MCP server added while the config was
    unreadable is reported against the preserved baseline on the next readable run."""
    home, cfg = unreadable_home
    _, good = _snap(home)

    cfg.chmod(0o000)
    _, blind = _snap(home, prev=good)

    cfg.chmod(0o600)
    conf = json.loads(cfg.read_text())
    conf["mcp"]["servers"]["planted"] = {"command": "npx", "args": ["-y", "evil@1.0.0"]}
    cfg.write_text(json.dumps(conf))
    cfg.chmod(0o600)
    _, restored = _snap(home, prev=blind)

    alerts = diff(blind, restored)
    assert any(lvl == "CRITICAL" and "planted" in msg for lvl, msg in alerts), alerts


# ------------------------------------------------------------------ UNKNOWN baseline

def test_first_ever_run_blind_records_an_unknown_baseline():
    """UNKNOWN path: a blind run with no previous state has nothing to carry forward, so
    it must say the baseline is unknown rather than claim the empty view as fact."""
    _, blind = _snap(TRUNCATED, prev=None)
    assert blind["config_parse_error"] is True
    assert blind["config_baseline"] == "unknown"
    assert diff(None, blind) == []


def test_second_blind_run_does_not_launder_an_unknown_baseline_into_carried():
    """UNKNOWN path: blind-after-blind-with-no-baseline stays 'unknown' — an empty view
    must never be promoted to a known-good baseline just by being repeated."""
    _, blind1 = _snap(TRUNCATED, prev=None)
    _, blind2 = _snap(TRUNCATED, prev=blind1)
    assert blind2["config_baseline"] == "unknown"
    assert _fabricated(diff(blind1, blind2)) == []


def test_recovering_from_an_unknown_baseline_says_so_and_fabricates_nothing():
    """UNKNOWN path: with no known-good baseline the config dimensions are not compared at
    all — the first readable run establishes the baseline instead of reporting every
    configured server as brand new."""
    _, blind = _snap(TRUNCATED, prev=None)
    _, restored = _snap(CLEAN, prev=blind)
    alerts = diff(blind, restored)

    assert _fabricated(alerts) == [], alerts
    assert any("measured from this run onward" in msg for _, msg in alerts)


def test_now_failing_is_not_fabricated_when_the_previous_run_was_blind():
    """A check reading UNKNOWN only because the previous run could not parse the config
    was not passing then; re-reading it as FAIL is the config becoming legible again."""
    prev = {"score": 50, "grade": "D", "skills": {}, "bootstrap": {}, "checks": {"B2": UNKNOWN},
            "config_parse_error": True, "config_baseline": "carried"}
    curr = {"score": 49, "grade": "F", "skills": {}, "bootstrap": {}, "checks": {"B2": FAIL}}
    assert not [m for _, m in diff(prev, curr) if "Now FAILING" in m]


def test_now_failing_still_fires_for_a_genuine_transition_after_a_blind_run():
    """The suppression above is narrow: only UNKNOWN -> FAIL out of a blind run is muted.
    A check that was PASSing before the blind window is still announced — going silent
    would trade a fabricated claim for a false negative."""
    prev = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {"B2": "PASS"},
            "config_parse_error": True, "config_baseline": "carried"}
    curr = {"score": 49, "grade": "F", "skills": {}, "bootstrap": {}, "checks": {"B2": FAIL}}
    assert [m for _, m in diff(prev, curr) if "Now FAILING" in m]


def test_now_failing_out_of_a_blind_run_is_downranked_and_disclosed():
    """A non-UNKNOWN status recorded during a blind run is NOT a trustworthy baseline.

    Measured on the real ~/.openclaw: with openclaw.json momentarily absent, A1 reads
    WARN — not UNKNOWN — off the collapsed ``ctx.config == {}`` view, and the run scores
    C/79 against the true F/49. A guard keyed only on UNKNOWN therefore let a definite
    HIGH "Now FAILING" reach the tamper-evident journal on the next run with nothing
    changed. The alert must still fire (silence would be a false negative) but at reduced
    strength and carrying the caveat.
    """
    prev = {"score": 79, "grade": "C", "skills": {}, "bootstrap": {}, "checks": {"B2": "WARN"},
            "config_parse_error": True, "config_baseline": "carried"}
    curr = {"score": 49, "grade": "F", "skills": {}, "bootstrap": {}, "checks": {"B2": FAIL}}

    hits = [(lvl, m) for lvl, m in diff(prev, curr) if "Now FAILING" in m]
    assert hits, "a genuine transition must not be silently dropped"
    levels = {lvl for lvl, _ in hits}
    assert levels == {"MEDIUM"}, f"must be down-ranked out of a blind run, got {levels}"
    assert all("not a trustworthy baseline" in m for _, m in hits), (
        "the caveat must travel with the alert into the journal"
    )


def test_a_clean_baseline_still_yields_the_definite_undownranked_alert():
    """The down-ranking is scoped to blind runs only — a normal comparison is unchanged.

    B-280: the definite alert now carries the check's CATALOG severity rather than a flat
    "HIGH" literal, so this asserts against ``BY_ID`` instead of a hardcoded level. What
    the test actually guards is unchanged: a clean baseline produces the full-strength
    alert with no "untrustworthy baseline" caveat, never the blind-run MEDIUM.
    """
    prev = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {"B2": "PASS"}}
    curr = {"score": 49, "grade": "F", "skills": {}, "bootstrap": {}, "checks": {"B2": FAIL}}

    hits = [(lvl, m) for lvl, m in diff(prev, curr) if "Now FAILING" in m]
    assert [lvl for lvl, _ in hits] == [BY_ID["B2"].severity]
    assert all("not a trustworthy baseline" not in m for _, m in hits)


# --------------------------------------------------------------------- CLI end-to-end

@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the read bit")
def test_cli_monitor_passes_prev_state_so_the_baseline_survives(tmp_path, capsys):
    """The cli --monitor call site must hand the previous state to snapshot(), or the
    fix never reaches a real user. Writes only inside tmp_path."""
    home = tmp_path / "home"
    shutil.copytree(CLEAN, home)
    cfg = home / "openclaw.json"
    cfg.chmod(0o600)
    state = tmp_path / "state.json"
    events = tmp_path / "events.jsonl"
    argv = ["--home", str(home), "--monitor", "--no-native", "--no-history",
            "--state", str(state), "--events", str(events), "--ascii"]

    assert main(argv) == 0
    capsys.readouterr()
    baseline = load_state(state)
    assert list(baseline["mcp"]) == ["weather"]

    cfg.chmod(0o000)
    try:
        assert main(argv) == 0
        out = capsys.readouterr().out
    finally:
        cfg.chmod(0o600)

    saved = load_state(state)
    assert saved["config_parse_error"] is True
    assert saved["mcp"] == baseline["mcp"], "the CLI overwrote the known-good baseline"
    assert saved["gateway_bind"] == baseline["gateway_bind"]
    assert "Could not read openclaw.json" in out
    for marker in ("was removed", "Gateway bind changed"):
        assert marker not in out, f"CLI printed fabricated drift: {marker}"


def test_state_file_stays_owner_only(tmp_path, capsys):
    """Regression guard: threading prev through must not change the at-rest mode."""
    state = tmp_path / "state.json"
    assert main(["--home", str(CLEAN), "--monitor", "--no-native", "--no-history",
                 "--state", str(state), "--events", str(tmp_path / "e.jsonl"),
                 "--ascii"]) == 0
    capsys.readouterr()
    assert stat.S_IMODE(state.stat().st_mode) == 0o600


# ------------------------------------------- C-135 FIX2: config ABSENT, not just unreadable
#
# collector.py:1648 defines ``config_parse_error = config_found and not parsed_ok`` — a
# config that is simply NOT THERE this run (``config_found`` False) leaves
# ``config_parse_error`` False too, so B-269's original guard alone never fired for it:
# ``_degrade_snapshot()`` never ran, ``trust_removals`` stayed True, and the collapsed
# ``ctx.config = {}`` view got written into the baseline as fact. Benign triggers: the
# ``jq ... > tmp && mv tmp openclaw.json`` atomic-replace window, ``mv openclaw.json
# openclaw.json.bak`` mid-troubleshooting, a home not yet mounted on a cron-driven run.

@pytest.fixture()
def readable_home(tmp_path):
    """A copy of the clean fixture with a normally-readable openclaw.json."""
    home = tmp_path / "home"
    shutil.copytree(CLEAN, home)
    (home / "openclaw.json").chmod(0o600)
    return home


def test_config_momentarily_absent_is_treated_as_blind_not_empty(readable_home):
    """The file vanishing (not just becoming unparseable) must be treated exactly like
    the unparseable case: blind, baseline carried forward, nothing fabricated."""
    home = readable_home
    cfg = home / "openclaw.json"
    ctx_good, good = _snap(home)
    assert ctx_good.config_found is True

    stash = home / "openclaw.json.stash"
    cfg.rename(stash)
    try:
        ctx_blind, blind = _snap(home, prev=good)
        alerts = diff(good, blind)
    finally:
        stash.rename(cfg)

    # The collector's own attribute is unaffected by this fix (collector.py is out of
    # scope) — it genuinely stays False for "absent", as designed. The snapshot layer is
    # what widens the blind predicate to cover this case too.
    assert ctx_blind.config_found is False
    assert ctx_blind.config_parse_error is False
    assert blind["config_parse_error"] is True
    assert blind["config_baseline"] == "carried"
    assert blind["mcp"] == good["mcp"]
    assert blind["mcp_detail"] == good["mcp_detail"]
    assert blind["channels"] == good["channels"]
    assert blind["gateway_bind"] == good["gateway_bind"]

    coverage = _coverage_alerts(alerts)
    assert len(coverage) == 1, f"expected one coverage alert, got: {alerts}"
    assert _fabricated(alerts) == [], f"fabricated drift on a blind run: {alerts}"


def test_config_absent_then_restored_fabricates_nothing(readable_home):
    """BAD -> CLEAN across a momentary absence: no fabricated burst either way."""
    home = readable_home
    cfg = home / "openclaw.json"
    before = cfg.read_bytes()
    _, good = _snap(home)

    stash = home / "openclaw.json.stash"
    cfg.rename(stash)
    _, blind = _snap(home, prev=good)
    stash.rename(cfg)
    assert cfg.read_bytes() == before, "the repro must not modify the config"

    _, restored = _snap(home, prev=blind)
    alerts = diff(blind, restored)
    assert _fabricated(alerts) == [], f"fabricated drift on the restore run: {alerts}"
    assert any(lvl == "INFO" and "readable again" in msg for lvl, msg in alerts)
    assert not any(lvl == "CRITICAL" for lvl, _ in alerts)


def test_second_consecutive_absent_run_stays_blind(readable_home):
    """The config stays missing for TWO consecutive runs — the widened predicate must
    keep carrying the baseline forward rather than reverting to trusting an empty view
    on the second blind run (mirrors the pre-existing multi-run parse-error chain)."""
    home = readable_home
    cfg = home / "openclaw.json"
    _, good = _snap(home)

    stash = home / "openclaw.json.stash"
    cfg.rename(stash)
    try:
        _, blind1 = _snap(home, prev=good)
        _, blind2 = _snap(home, prev=blind1)
    finally:
        stash.rename(cfg)

    assert blind2["config_parse_error"] is True
    assert blind2["config_baseline"] == "carried"
    assert blind2["mcp"] == good["mcp"]
    assert _fabricated(diff(blind1, blind2)) == [], diff(blind1, blind2)


def test_home_that_never_had_a_config_is_never_treated_as_blind(tmp_path):
    """A user who genuinely never configured OpenClaw (config_found always False) must
    not get a permanent 'Could not read openclaw.json' alert — the widened predicate is
    gated on the PREVIOUS snapshot having had real config content."""
    home = tmp_path / "home"
    home.mkdir()
    ctx1, run1 = _snap(home)
    assert ctx1.config_found is False
    assert "config_parse_error" not in run1
    assert run1["config_ever_seen"] is False

    ctx2, run2 = _snap(home, prev=run1)
    assert ctx2.config_found is False
    assert "config_parse_error" not in run2
    assert run2["config_ever_seen"] is False

    assert diff(run1, run2) == []


def test_config_created_for_the_first_time_is_not_a_blind_transition(tmp_path):
    """The mirror image: no config at all -> a real config appears. This is normal setup,
    not a recovery from blindness, so no 'readable again' framing and no fabrication."""
    home = tmp_path / "home"
    home.mkdir()
    _, run1 = _snap(home)
    assert run1["config_ever_seen"] is False

    (home / "openclaw.json").write_text(json.dumps({"gateway": {"bind": "127.0.0.1"}}))
    (home / "openclaw.json").chmod(0o600)
    ctx2, run2 = _snap(home, prev=run1)

    assert ctx2.config_found is True
    assert run2["config_ever_seen"] is True
    assert "config_parse_error" not in run2
    assert not any("readable again" in msg for _, msg in diff(run1, run2))
