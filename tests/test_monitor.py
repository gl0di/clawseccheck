"""Built-in monitor: snapshot + change detection (deterministic, offline)."""
from pathlib import Path

from clawcheck import audit, diff, load_state, save_state, snapshot
from clawcheck.report import render_monitor
from clawcheck.scoring import compute

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _levels(alerts):
    return [lvl for lvl, _ in alerts]


def test_snapshot_has_expected_shape():
    ctx, findings, score = audit(FIXTURES / "home_safe")
    snap = snapshot(ctx, findings, score)
    assert snap["version"] == 1 and snap["grade"] in "ABCDF"
    assert "checks" in snap and "skills" in snap and "bootstrap" in snap
    assert snap["bootstrap"]  # home_safe has a SOUL.md


def test_first_run_is_baseline_no_alerts():
    snap = {"score": 100, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}}
    assert diff(None, snap) == []


def test_new_installed_skill_is_critical_alert():
    prev = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {}}
    curr = {"score": 90, "grade": "A", "skills": {"evil": "abc"}, "bootstrap": {}, "checks": {}}
    alerts = diff(prev, curr)
    assert "CRITICAL" in _levels(alerts)
    assert any("evil" in m for _, m in alerts)


def test_changed_skill_and_bootstrap_drift():
    prev = {"score": 90, "grade": "A", "skills": {"s": "h1"},
            "bootstrap": {"workspace/SOUL.md": "b1"}, "checks": {}}
    curr = {"score": 90, "grade": "A", "skills": {"s": "h2"},
            "bootstrap": {"workspace/SOUL.md": "b2"}, "checks": {}}
    msgs = " ".join(m for _, m in diff(prev, curr))
    assert "CHANGED" in msgs and "drift" in msgs


def test_score_drop_and_new_failing_check():
    prev = {"score": 85, "grade": "B", "skills": {}, "bootstrap": {}, "checks": {"B2": "PASS"}}
    curr = {"score": 49, "grade": "F", "skills": {}, "bootstrap": {}, "checks": {"B2": "FAIL"}}
    msgs = " ".join(m for _, m in diff(prev, curr))
    assert "dropped" in msgs and "Now FAILING" in msgs


def test_no_change_no_alerts():
    snap = {"score": 100, "grade": "A", "skills": {"s": "h"},
            "bootstrap": {"x": "b"}, "checks": {"B1": "PASS"}}
    assert diff(snap, dict(snap)) == []


def test_state_roundtrip(tmp_path):
    snap = {"version": 1, "score": 78, "grade": "C", "skills": {}, "bootstrap": {}, "checks": {}}
    path = tmp_path / "state.json"
    save_state(path, snap)
    assert load_state(path) == snap
    assert load_state(tmp_path / "missing.json") is None


def test_monitor_end_to_end_detects_new_skill(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}")
    ctx1, f1, s1 = audit(tmp_path)
    base = snapshot(ctx1, f1, s1)
    sk = tmp_path / "skills" / "newcomer"
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text("---\nname: newcomer\ndescription: x\n---\nhello")
    ctx2, f2, s2 = audit(tmp_path)
    alerts = diff(base, snapshot(ctx2, f2, s2))
    assert any("newcomer" in m for _, m in alerts)
    assert "No new threats" not in render_monitor(alerts, compute([]))


# ---- ignore_hash governance tests ----

def test_snapshot_includes_ignore_hash_absent(tmp_path):
    """snapshot includes ignore_hash='' when .clawcheckignore is absent."""
    (tmp_path / "openclaw.json").write_text("{}")
    ctx, findings, score = audit(tmp_path)
    snap = snapshot(ctx, findings, score)
    assert "ignore_hash" in snap
    assert snap["ignore_hash"] == ""


def test_snapshot_includes_ignore_hash_present(tmp_path):
    """snapshot includes the sha256 of .clawcheckignore when it exists."""
    import hashlib
    (tmp_path / "openclaw.json").write_text("{}")
    content = "B14\n"
    (tmp_path / ".clawcheckignore").write_text(content)
    ctx, findings, score = audit(tmp_path)
    snap = snapshot(ctx, findings, score)
    expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
    assert snap["ignore_hash"] == expected


def test_ignore_hash_change_triggers_high_alert():
    """diff alerts HIGH when ignore_hash changes between snapshots."""
    prev = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "ignore_hash": "aabbcc"}
    curr = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "ignore_hash": "ddeeff"}
    alerts = diff(prev, curr)
    assert "HIGH" in _levels(alerts)
    assert any(".clawcheckignore" in m for _, m in alerts)


def test_ignore_hash_unchanged_no_alert():
    """diff does NOT alert when ignore_hash is the same."""
    snap = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "ignore_hash": "aabbcc"}
    assert diff(snap, dict(snap)) == []


def test_ignore_hash_absent_to_present_triggers_alert():
    """Adding .clawcheckignore for the first time ('' -> hash) triggers alert."""
    prev = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "ignore_hash": ""}
    curr = {"score": 90, "grade": "A", "skills": {}, "bootstrap": {}, "checks": {},
            "ignore_hash": "abc123"}
    alerts = diff(prev, curr)
    assert "HIGH" in _levels(alerts)


def test_monitor_end_to_end_ignore_hash_change(tmp_path):
    """End-to-end: adding a .clawcheckignore triggers a HIGH alert in next run."""
    (tmp_path / "openclaw.json").write_text("{}")
    ctx1, f1, s1 = audit(tmp_path)
    base = snapshot(ctx1, f1, s1)
    assert base["ignore_hash"] == ""

    # Add a .clawcheckignore file between runs
    (tmp_path / ".clawcheckignore").write_text("B14\n")
    ctx2, f2, s2 = audit(tmp_path)
    alerts = diff(base, snapshot(ctx2, f2, s2))
    assert "HIGH" in _levels(alerts)
    assert any(".clawcheckignore" in m for _, m in alerts)
