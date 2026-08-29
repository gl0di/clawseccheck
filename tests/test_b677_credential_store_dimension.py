"""CLAWSECCHECK-B-677 — the watch can see OpenClaw's credential store change.

B-666 taught A1 to read `<home>/credentials` for a plaintext credential, so the AUDIT
treats its contents as security-relevant. The WATCH could not see it move. Measured through
the real CLI on a copy of `fixtures/home_safe` before this was built:

    first credential lands, completing the trifecta   -> CRITICAL (A1 now FAILING)
    a SECOND credential lands, leg already up         -> 0 alerts
    an existing credential is REPLACED (token swap)   -> 0 alerts

Only the first was covered, and only coincidentally — A1 moved because that file completed a
2/3 config, a property of the config rather than of the credential. The other two are the
security-relevant ones.

Secret-shaped values are assembled at runtime from fragments so no contiguous literal exists
here (CLAUDE.md section 2.3). Offline, read-only, tmp_path only.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck.monitor import WATCHED_DIMENSIONS, snapshot
from clawseccheck.monitordims._credentials import _credentials_sig, _diff_credentials

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"


def _token(seed: str) -> str:
    return "sk-" + "ant-" + "api03-" + (seed * 40)


def _run(prev, curr):
    alerts, notes = [], []
    _diff_credentials((prev, curr), alerts, lambda c, m: notes.append((c, m)))
    return alerts, notes


def _rec(files, incomplete=False, reason=""):
    return {"files": files, "incomplete": incomplete, "reason": reason}


def _f(digest, plaintext=True):
    return {"digest": digest, "plaintext": plaintext}


# ---------------------------------------------------------------- the arm


def test_an_unchanged_store_says_nothing():
    same = _rec({"oauth.json": _f("aaaa")})
    assert _run(same, same) == ([], [])


def test_a_new_plaintext_credential_is_medium_and_names_the_file():
    alerts, _ = _run(_rec({}), _rec({"oauth.json": _f("aaaa")}))
    assert len(alerts) == 1 and alerts[0][0] == "MEDIUM"
    assert "credentials/oauth.json" in alerts[0][1]


def test_a_replaced_credential_is_medium():
    """The token-swap case, which nothing in the tree reported before."""
    alerts, _ = _run(_rec({"oauth.json": _f("aaaa")}), _rec({"oauth.json": _f("bbbb")}))
    assert len(alerts) == 1 and alerts[0][0] == "MEDIUM"
    assert "replaced" in alerts[0][1]


def test_a_new_file_with_no_credential_in_it_is_only_info():
    """OpenClaw writes pairing and allow-list state into this directory routinely — the
    real machine holds exactly two such files and no credential. Paging on those would
    make the dimension noise on every pairing."""
    alerts, _ = _run(_rec({}), _rec({"telegram-pairing.json": _f("aaaa", plaintext=False)}))
    assert len(alerts) == 1 and alerts[0][0] == "INFO"


def test_a_removal_is_info():
    alerts, _ = _run(_rec({"oauth.json": _f("aaaa")}), _rec({}))
    assert len(alerts) == 1 and alerts[0][0] == "INFO"
    assert "no longer" in alerts[0][1]


def test_a_truncated_walk_discloses_and_suppresses_removals():
    """The `_skills.py` frontier rule: a walk that could not finish cannot tell 'removed'
    from 'never read', and a burst of fabricated removal notices is the worse harm."""
    alerts, notes = _run(_rec({"oauth.json": _f("aaaa")}),
                         _rec({}, incomplete=True, reason="it holds more than 200 files"))
    assert [a for a in alerts if "no longer" in a[1]] == []
    assert notes and "not read in full" in notes[0][1]


def test_an_addition_is_still_reported_under_a_truncated_walk():
    """Anti-vacuity for the rule above: a cap makes ABSENCE unreliable, not presence. A
    file we positively read is evidence whatever else we missed."""
    alerts, _ = _run(_rec({}), _rec({"oauth.json": _f("aaaa")}, incomplete=True))
    assert [a for a in alerts if a[0] == "MEDIUM"], alerts


def test_a_damaged_or_absent_record_is_skipped_rather_than_guessed():
    for bad in (None, {}, {"files": "nope"}):
        assert _run(bad if isinstance(bad, dict) else _rec({}), {"files": None}) == ([], [])
    assert _diff_credentials(None, [], lambda c, m: None) is None


# ---------------------------------------------------------------- the signature


def test_the_signature_records_names_and_digests_never_values():
    """Section 8: this dimension's subject is by definition secret-bearing, so what it
    stores is the one thing that must be checked rather than assumed."""
    token = _token("B")
    state = {"present": True, "secret_files": ["oauth.json"], "incomplete": False,
             "reason": "", "digests": {"oauth.json": "deadbeefdeadbeef"}}
    blob = json.dumps(_credentials_sig(state))
    assert token not in blob
    assert "oauth.json" in blob and "deadbeefdeadbeef" in blob


def test_an_unscanned_store_records_nothing_at_all():
    """The conditional-key contract: absent means 'that layer did not run', never 'the
    store is empty'. Writing `{}` for an unscanned store would make the next run read a
    genuinely empty store as a wholesale removal."""
    assert _credentials_sig(None) == {}
    assert _credentials_sig({"present": False}) == {}


def test_the_key_is_declared_but_not_written_by_a_bare_snapshot():
    ctx_snap = snapshot(*_audit(FIXTURES / "home_safe"))
    assert "credential_store" in WATCHED_DIMENSIONS
    assert "credential_store" not in ctx_snap, "must be conditional on the caller scanning"


def _audit(home):
    from clawseccheck import audit
    ctx, findings, score = audit(str(home))
    return ctx, findings, score


def test_the_shell_is_what_hands_the_scan_in():
    """The CALL SITE, not the helper. `_credential_store_state` has its own tests and would
    stay green with the `credentials=` argument dropped."""
    cli = (REPO / "clawseccheck" / "cli.py").read_text(encoding="utf-8")
    assert "credentials=_credentials_snap" in cli
    assert "_credential_store_state(ctx.home)" in cli


# ---------------------------------------------------------------- end to end


@pytest.fixture()
def home(tmp_path):
    h = tmp_path / "home"
    shutil.copytree(FIXTURES / "home_safe", h)
    os.chmod(h / "openclaw.json", 0o600)
    (h / "credentials").mkdir()
    (h / "credentials" / "oauth.json").write_text(
        json.dumps({"access_token": _token("B")}), encoding="utf-8")
    os.chmod(h / "credentials" / "oauth.json", 0o600)
    return h


def _monitor(home, store):
    res = subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", "--monitor", "--json",
         "--home", str(home), "--data-dir", str(store)],
        cwd=REPO, capture_output=True, text=True, timeout=900)
    return json.loads(res.stdout)


def test_the_two_previously_invisible_transitions_now_surface(home, tmp_path):
    """The measurement this task exists for, repeated through the real CLI."""
    store = tmp_path / "store"
    _monitor(home, store)
    _monitor(home, store)
    assert _monitor(home, store)["alerts"] == [], "not steady before the change"

    (home / "credentials" / "second.json").write_text(
        json.dumps({"token": "ghp_" + ("C" * 36)}), encoding="utf-8")
    os.chmod(home / "credentials" / "second.json", 0o600)
    added = _monitor(home, store)["alerts"]
    assert [a for a in added
            if "credential store" in a["message"] and a["severity"] == "MEDIUM"], added

    (home / "credentials" / "oauth.json").write_text(
        json.dumps({"access_token": _token("Z")}), encoding="utf-8")
    os.chmod(home / "credentials" / "oauth.json", 0o600)
    replaced = _monitor(home, store)["alerts"]
    assert [a for a in replaced if "replaced" in a["message"]], replaced


def test_no_credential_value_ever_reaches_the_stored_state_or_the_journal(home, tmp_path):
    store = tmp_path / "store"
    _monitor(home, store)
    _monitor(home, store)
    for name in ("state.json", "events.jsonl"):
        path = store / name
        if path.is_file():
            assert _token("B") not in path.read_text(encoding="utf-8"), name
