"""B-275: diff() had no removal branch for bootstrap files or channels.

Every sibling snapshot dimension alerts on removal — skills, MCP servers, persistent
memory files, host monitors — but deleting one of the agent's bootstrap files, or
de-configuring a channel, was completely silent. Modifying the same bootstrap file *is*
reported HIGH, so the asymmetry manufactured false confidence: the cheapest way to drop
the agent's standing guardrails was also the only way that produced no alert at all.

SOUL/AGENTS/TOOLS/MEMORY/memory.md were incidentally covered because the separate memory
dimension tracks them too; IDENTITY/USER/HEARTBEAT/BOOTSTRAP.md were covered by nothing.

Read-only and offline: everything runs against committed fixtures or ``tmp_path``.
"""
import json
import shutil
import sys
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.collector import BOOTSTRAP_FILES
from clawseccheck.monitor import diff, snapshot

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
CLEAN = FIXTURES / "clean_mon_guardrails_present"
REMOVED = FIXTURES / "bad_mon_guardrails_removed"

# The four names the memory dimension does NOT track, so before this fix their removal
# was invisible in every dimension.
UNCOVERED = ("IDENTITY.md", "USER.md", "HEARTBEAT.md", "BOOTSTRAP.md")


def _snap(home, prev=None):
    ctx, findings, score = audit(home)
    return snapshot(ctx, findings, score, prev=prev)


def _bootstrap_removals(alerts):
    return [(lvl, msg) for lvl, msg in alerts
            if "Bootstrap file no longer being read" in msg]


def _memory_removals(alerts):
    return [(lvl, msg) for lvl, msg in alerts if "Persistent memory file removed" in msg]


def _channel_removals(alerts):
    return [(lvl, msg) for lvl, msg in alerts if "no longer configured" in msg]


# --------------------------------------------------------------------------- clean

def test_clean_fixture_intact_guardrails_produce_no_removal_alert():
    """CLEAN: guardrail files present in both runs — nothing is reported."""
    first = _snap(CLEAN)
    second = _snap(CLEAN, prev=first)
    alerts = diff(first, second)
    assert alerts == [], alerts


def test_clean_fixture_carries_all_six_guardrail_files():
    """CLEAN: the fixture actually contains what the bad half removes (guards against a
    vacuous pass if a fixture file is ever dropped)."""
    snap = _snap(CLEAN)
    names = {Path(k).name for k in snap["bootstrap"]}
    assert {"AGENTS.md", "SOUL.md", *UNCOVERED} <= names, names


# ----------------------------------------------------------------------------- bad

def test_removed_guardrails_are_reported_once_each():
    """BAD: five deleted bootstrap files, five alerts — including SOUL.md, which the
    memory dimension also tracks and which must NOT be reported twice."""
    before = _snap(CLEAN)
    after = _snap(REMOVED, prev=before)
    alerts = diff(before, after)

    removed = _bootstrap_removals(alerts)
    reported = sorted(Path(msg.split("read: ", 1)[1].split(" (", 1)[0]).name
                      for _, msg in removed)
    assert reported == sorted(["SOUL.md", *UNCOVERED]), reported
    # de-duplication: SOUL.md is a memory file too, but a single deletion is one event
    assert _memory_removals(alerts) == [], _memory_removals(alerts)


def test_removed_channel_is_reported():
    """BAD: the de-configured telegram channel is reported at INFO."""
    alerts = diff(_snap(CLEAN), _snap(REMOVED))
    removed = _channel_removals(alerts)
    assert len(removed) == 1, removed
    assert removed[0][0] == "INFO"
    assert "telegram" in removed[0][1]


def test_deleting_guardrails_raises_the_score_yet_is_no_longer_silent():
    """The original repro: deleting the files that carry the standing guardrails made the
    score go UP and reported nothing. The score behaviour is unchanged by design — the
    silence is what this fix removes."""
    _, _, clean_score = audit(CLEAN)
    _, _, gone_score = audit(REMOVED)
    assert gone_score.score >= clean_score.score, (
        "fixture no longer demonstrates the false-confidence repro"
    )
    assert _bootstrap_removals(diff(_snap(CLEAN), _snap(REMOVED)))


# ---------------------------------------------------------------------- severity

def test_bootstrap_removal_is_medium_not_high():
    """Pinned deliberately. Removal is also ordinary housekeeping — retiring a
    HEARTBEAT.md you never used is not an attack — and unlike a content change there is no
    poisoning signal in the event itself, only lost coverage. A *modification* stays HIGH."""
    prev = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"workspace-home/USER.md": "h1"}, "checks": {}}
    curr = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}}
    removed = _bootstrap_removals(diff(prev, curr))
    assert [lvl for lvl, _ in removed] == ["MEDIUM"], removed


def test_bootstrap_removal_wording_states_the_observation_not_malice():
    prev = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"workspace-home/USER.md": "h1"}, "checks": {}}
    curr = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}}
    msg = _bootstrap_removals(diff(prev, curr))[0][1]
    assert "no longer being read" in msg
    assert "deleted, moved, or no longer readable" in msg
    assert "Confirm you intended this" in msg
    for loaded in ("attack", "malicious", "attacker", "compromise"):
        assert loaded not in msg.lower(), f"alert asserts malice via {loaded!r}: {msg}"


def test_bootstrap_removal_wording_does_not_assert_a_consequence_it_cannot_know():
    """C-135 FIX3: a key disappearing from the scan-order-dependent bootstrap map is not
    proof the agent stopped reading the underlying file (see the FIX1 move-detection
    tests below) — the alert must stop at the observation, not claim standing guardrails
    stopped reaching the agent."""
    prev = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"workspace-home/USER.md": "h1"}, "checks": {}}
    curr = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}}
    msg = _bootstrap_removals(diff(prev, curr))[0][1]
    assert "no longer reach the agent" not in msg
    assert "approval, spending or tool-use guardrails" not in msg


def test_bootstrap_modification_is_still_high():
    """The pre-existing HIGH content-drift branch is untouched."""
    prev = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"workspace-home/USER.md": "h1"}, "checks": {}}
    curr = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"workspace-home/USER.md": "h2"}, "checks": {}}
    assert any(lvl == "HIGH" and "changed since last check" in msg
               for lvl, msg in diff(prev, curr))


def test_channel_removal_is_info_not_high():
    """De-configuring a channel SHRINKS the reachable surface and users retire channels
    routinely — worth journalling, not worth alarming over."""
    prev = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "channels": {"telegram": "h1"}}
    curr = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "channels": {}}
    removed = _channel_removals(diff(prev, curr))
    assert [lvl for lvl, _ in removed] == ["INFO"], removed


# ------------------------------------------------------- per-name + full-set coverage

@pytest.mark.parametrize("name", UNCOVERED)
def test_each_previously_uncovered_name_alerts_on_its_own(tmp_path, name):
    """Each of the four names no dimension covered before, deleted individually."""
    home = tmp_path / "home"
    shutil.copytree(CLEAN, home)
    (home / "openclaw.json").chmod(0o600)
    before = _snap(home)

    (home / "workspace-home" / name).unlink()
    alerts = diff(before, _snap(home, prev=before))

    removed = _bootstrap_removals(alerts)
    assert len(removed) == 1, removed
    assert removed[0][1].endswith(
        "or no longer readable). Confirm you intended this.")
    assert name in removed[0][1]


@pytest.mark.skipif(
    sys.platform == "darwin",
    reason="BOOTSTRAP_FILES deliberately lists both 'MEMORY.md' and 'memory.md' as distinct "
    "real-world namings; on macOS's default case-insensitive (but case-preserving) APFS "
    "the two collapse onto the same inode, so writing both leaves only one file on disk "
    "and this test's unlink loop hits a FileNotFoundError on the second name — a fixture "
    "limitation of case-insensitive filesystems, not a check bug",
)
def test_all_nine_bootstrap_files_are_reported_with_no_partial_list(tmp_path):
    """Deleting all nine BOOTSTRAP_FILES reports all nine — previously only the five the
    memory dimension happened to cover were reported, with no note the list was partial."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text("{}")
    (home / "openclaw.json").chmod(0o600)
    ws = home / "workspace-home"
    ws.mkdir()
    for name in BOOTSTRAP_FILES:
        (ws / name).write_text(f"# {name}\n\nStanding guardrail notes.\n")

    before = _snap(home)
    assert len(before["bootstrap"]) == len(BOOTSTRAP_FILES)

    for name in BOOTSTRAP_FILES:
        (ws / name).unlink()
    alerts = diff(before, _snap(home, prev=before))

    reported = sorted(Path(msg.split("read: ", 1)[1].split(" (", 1)[0]).name
                      for _, msg in _bootstrap_removals(alerts))
    assert reported == sorted(BOOTSTRAP_FILES), reported
    assert _memory_removals(alerts) == [], "memory dimension double-reported"


# ------------------------------------------------- B-269 x B-275 interaction (fp guard)

def test_blind_config_run_does_not_fabricate_bootstrap_or_channel_removals(tmp_path):
    """An unreadable openclaw.json drops config-declared workspace roots out of the
    collected view. The new removal branches must not turn that collection artifact into a
    deletion alert (verified: a custom agents.defaults.workspace bootstrap file really
    does vanish from ctx.bootstrap while the config is unreadable)."""
    home = tmp_path / "home"
    home.mkdir()
    custom = home / "my-space"
    custom.mkdir()
    (custom / "USER.md").write_text("# User\n\nAlways ask before running a command.\n")
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps({
        "agents": {"defaults": {"workspace": str(custom)}},
        "channels": {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
    }))
    cfg.chmod(0o600)

    before = _snap(home)
    assert before["bootstrap"], "fixture must start with a config-declared bootstrap file"
    assert before["channels"], "fixture must start with a configured channel"

    cfg.chmod(0o000)
    try:
        blind = _snap(home, prev=before)
        alerts = diff(before, blind)
    finally:
        cfg.chmod(0o600)

    assert _bootstrap_removals(alerts) == [], alerts
    assert _channel_removals(alerts) == [], alerts
    assert _memory_removals(alerts) == [], alerts
    assert any("Could not read openclaw.json" in msg for _, msg in alerts)


def test_a_real_deletion_during_a_blind_window_is_deferred_not_lost(tmp_path):
    """Suppressing removals on a blind run defers the report to the next readable run —
    it does not drop it."""
    home = tmp_path / "home"
    shutil.copytree(CLEAN, home)
    cfg = home / "openclaw.json"
    cfg.chmod(0o600)
    before = _snap(home)

    cfg.chmod(0o000)
    try:
        blind = _snap(home, prev=before)
        assert _bootstrap_removals(diff(before, blind)) == []
        (home / "workspace-home" / "USER.md").unlink()
    finally:
        cfg.chmod(0o600)

    alerts = diff(blind, _snap(home, prev=blind))
    removed = _bootstrap_removals(alerts)
    assert len(removed) == 1 and "USER.md" in removed[0][1], alerts


# ------------------------------------------------- C-135 FIX1: key-move detection

# ctx.bootstrap is keyed "<workspace-label>/<NAME>.md", where the label depends on scan
# order plus a resolved-path de-dup (collector.py). The exact same inode, byte-identical
# content, still read by the agent, can land under a DIFFERENT key after a benign
# refactor. diff() must pair a removed key with a same-content-hash added key and treat
# it as a MOVE (silent), while a genuine deletion — no added counterpart to pair with —
# must still fire MEDIUM. Both directions are pinned below; a fix that only proved the
# silent half could just as easily be masking real deletions.

_BOOT = ("SOUL.md", "AGENTS.md", "USER.md")


def test_symlink_alias_cleanup_is_silent(tmp_path):
    """Benign trigger (a): the real bootstrap files live on a shared mount;
    workspace-home/*.md are symlinks to them. Deleting the now-redundant symlinks does
    not stop the agent reading the same inodes via the config-declared workspace — this
    must produce ZERO alerts."""
    home = tmp_path / "home"
    real = tmp_path / "mnt" / "ws"
    real.mkdir(parents=True)
    home.mkdir()
    for n in _BOOT:
        (real / n).write_text(f"# {n}\nAlways ask before spending money.\n")
        (real / n).chmod(0o600)
    (home / "openclaw.json").write_text(json.dumps({
        "agents": {"defaults": {"workspace": str(real)}},
        "gateway": {"bind": "127.0.0.1"},
    }))
    (home / "openclaw.json").chmod(0o600)
    wsh = home / "workspace-home"
    wsh.mkdir()
    for n in _BOOT:
        (wsh / n).symlink_to(real / n)

    before = _snap(home)
    assert before["bootstrap"], "fixture must start with bootstrap files collected"

    for n in _BOOT:
        (wsh / n).unlink()
    after = _snap(home, prev=before)

    for n in _BOOT:
        assert (real / n).is_file(), "the real files must still be on disk, unmodified"

    assert diff(before, after) == [], diff(before, after)


def test_workspace_rename_is_silent(tmp_path):
    """Benign trigger (b): the user renames their custom workspace directory and updates
    the config to match. Same bytes, still read by the agent, just under a new label —
    this must also produce ZERO alerts (measured pre-fix: 5x MEDIUM)."""
    home = tmp_path / "home"
    home.mkdir()
    ws = home / "my-space"
    ws.mkdir()
    for n in _BOOT:
        (ws / n).write_text(f"# {n}\nAlways ask before spending money.\n")
        (ws / n).chmod(0o600)

    def cfg(value):
        (home / "openclaw.json").write_text(json.dumps({
            "agents": {"defaults": {"workspace": value}},
            "gateway": {"bind": "127.0.0.1"},
        }))
        (home / "openclaw.json").chmod(0o600)

    cfg("my-space")
    before = _snap(home)
    assert before["bootstrap"], "fixture must start with bootstrap files collected"

    ws.rename(home / "agent-space")
    cfg("agent-space")
    after = _snap(home, prev=before)

    assert diff(before, after) == [], diff(before, after)


def test_genuine_guardrail_deletion_is_not_masked_by_move_detection(tmp_path):
    """The other direction: an attacker (or the user) deletes guardrail files with NO
    benign move to explain the disappearance away — move-pairing must never turn a real
    deletion into silence. Mirrors the FN check in the reviewer's fn_and_fix.py repro."""
    home = tmp_path / "home"
    home.mkdir()
    ws = home / "my-space"
    ws.mkdir()
    boot = ("SOUL.md", "AGENTS.md", "USER.md", "HEARTBEAT.md", "IDENTITY.md")
    for n in boot:
        (ws / n).write_text(f"# {n}\nAlways ask before spending money.\n")
        (ws / n).chmod(0o600)
    (home / "openclaw.json").write_text(json.dumps({
        "agents": {"defaults": {"workspace": "my-space"}},
        "gateway": {"bind": "127.0.0.1"},
    }))
    (home / "openclaw.json").chmod(0o600)

    before = _snap(home)
    for n in ("USER.md", "HEARTBEAT.md", "IDENTITY.md"):
        (ws / n).unlink()
    after = _snap(home, prev=before)

    removed = _bootstrap_removals(diff(before, after))
    assert len(removed) == 3, removed
    assert all(lvl == "MEDIUM" for lvl, _ in removed), removed
    reported_names = {Path(msg.split("read: ", 1)[1].split(" (", 1)[0]).name
                      for _, msg in removed}
    assert reported_names == {"USER.md", "HEARTBEAT.md", "IDENTITY.md"}, reported_names


def test_move_pairing_does_not_swallow_an_unrelated_deletion():
    """A removed key must only be paired away when some ADDED key carries the identical
    hash — an unrelated addition in the same run (different content) must not mask it."""
    prev = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"workspace-home/USER.md": "h-user"}, "checks": {}}
    curr = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"workspace-home/NOTES.md": "h-different"}, "checks": {}}
    alerts = diff(prev, curr)
    removed = _bootstrap_removals(alerts)
    assert len(removed) == 1 and "USER.md" in removed[0][1], alerts
    assert any("New bootstrap file appeared" in m and "NOTES.md" in m for _, m in alerts)


def test_move_pairing_handles_duplicate_hashes_deterministically():
    """Two removed keys share the SAME content hash as two added keys (e.g. SOUL.md and
    AGENTS.md moved together under a renamed workspace) — pairing must match every
    removed key to a distinct added key, not crash, and not double-report."""
    prev = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"a/SOUL.md": "same", "a/AGENTS.md": "same"}, "checks": {}}
    curr = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"b/SOUL.md": "same", "b/AGENTS.md": "same"}, "checks": {}}
    assert diff(prev, curr) == []


def test_move_pairing_extra_added_key_with_matching_hash_is_a_new_file(tmp_path):
    """Cardinality mismatch: one removed key, two added keys share its hash. Exactly one
    pairs as the move; the other genuinely new key is still reported (coincidental
    identical content is not proof it is the SAME file)."""
    prev = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"a/SOUL.md": "same"}, "checks": {}}
    curr = {"score": 90, "grade": "A", "skills": {},
            "bootstrap": {"b/SOUL.md": "same", "c/SOUL.md": "same"}, "checks": {}}
    alerts = diff(prev, curr)
    assert _bootstrap_removals(alerts) == [], alerts
    added = [m for _, m in alerts if "New bootstrap file appeared" in m]
    assert len(added) == 1, alerts


# --------------------------------------------------- C-135 FIX4: channel shorthand form

def test_channel_shorthand_true_is_not_treated_as_removed(tmp_path):
    """A channel written in shorthand ("telegram": true) is live, not absent — switching
    an existing dict-shaped channel to shorthand must not read as 'no longer configured'
    (the channel is still reachable)."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text(json.dumps(
        {"channels": {"telegram": {"dmPolicy": "allowlist"}}}))
    (home / "openclaw.json").chmod(0o600)
    before = _snap(home)
    assert before["channels"], "fixture must start with a configured channel"

    (home / "openclaw.json").write_text(json.dumps({"channels": {"telegram": True}}))
    (home / "openclaw.json").chmod(0o600)
    after = _snap(home, prev=before)

    alerts = diff(before, after)
    assert _channel_removals(alerts) == [], alerts


def test_channel_shorthand_unchanged_across_runs_is_silent(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text(json.dumps({"channels": {"telegram": True}}))
    (home / "openclaw.json").chmod(0o600)
    before = _snap(home)
    after = _snap(home, prev=before)
    assert diff(before, after) == []


def test_channel_shorthand_flip_reports_a_change_not_a_removal(tmp_path):
    """true -> false is a real openness/auth-relevant change; must surface as a review
    nudge, never as a fabricated 'no longer configured'."""
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text(json.dumps({"channels": {"telegram": True}}))
    (home / "openclaw.json").chmod(0o600)
    before = _snap(home)

    (home / "openclaw.json").write_text(json.dumps({"channels": {"telegram": False}}))
    (home / "openclaw.json").chmod(0o600)
    after = _snap(home, prev=before)

    alerts = diff(before, after)
    assert _channel_removals(alerts) == [], alerts
    assert any(lvl == "MEDIUM" and "openness/auth changed" in m for lvl, m in alerts), alerts
