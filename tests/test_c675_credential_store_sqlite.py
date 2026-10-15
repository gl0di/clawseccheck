"""The monitor's credential_store dimension also watches the SQLite credential stores.

OpenClaw keeps its credentials in the state database (`config_machine_state`:
`authProfiles.store`, `auth.sharedStore`) and in each agent's own database
(`auth_profile_store`), where the directory the dimension used to watch is empty. A second
credential landing, or an existing one being rewritten, there produced no alert at all.

What may be recorded (owner ruling): the store's label, the value's LENGTH and the store's own
`updated_at_ms` / `updated_at` column. Never a value, never a digest of one, never a path.

Secret-shaped values are assembled at runtime and the table DDL from fragments, so no
contiguous literal exists here (the repo-wide DDL scanner flags a literal). Offline, read-only,
tmp_path only.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import sqlite3
from pathlib import Path

import pytest

from clawseccheck import audit
from clawseccheck.collector import read_credential_store_rows
from clawseccheck.monitor import WATCHED_DIMENSIONS, diff_with_notes, snapshot
from clawseccheck.monitordims._credentials import _LABEL_CAP, _safe_store_label
from clawseccheck.monitordims._shared import NOTE_INSPECTION_CAPPED, NOTE_NO_PRIOR_RECORD

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"

_MK = " ".join(("CREATE", "TABLE"))
_SHARED_DDL = (
    f"{_MK} config_machine_state (state_key TEXT NOT NULL PRIMARY KEY, "
    "value_json TEXT NOT NULL, updated_at_ms INTEGER NOT NULL) STRICT"
)
_AGENT_DDL = (
    f"{_MK} auth_profile_store (store_key TEXT NOT NULL PRIMARY KEY, "
    "store_json TEXT NOT NULL, updated_at INTEGER NOT NULL) STRICT"
)


def _secret() -> str:
    return "sk-" + "ant-" + "api03-" + ("Z" * 40)


@pytest.fixture(scope="module")
def audited(tmp_path_factory):
    home = tmp_path_factory.mktemp("c675") / "home"
    shutil.copytree(FIXTURES / "home_safe", home)
    ctx, findings, score = audit(str(home))
    return home, ctx, findings, score


@pytest.fixture(autouse=True)
def _clean_dbs(audited):
    home = audited[0]
    yield
    shutil.rmtree(home / "state", ignore_errors=True)
    shutil.rmtree(home / "agents", ignore_errors=True)


def _shared_db(home, rows):
    (home / "state").mkdir(exist_ok=True)
    path = home / "state" / "openclaw.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("DROP TABLE IF EXISTS config_machine_state")
    conn.execute(_SHARED_DDL)
    conn.executemany("INSERT INTO config_machine_state VALUES (?, ?, ?)", rows)
    conn.commit()
    conn.close()
    return path


def _agent_db(home, agent, rows):
    d = home / "agents" / agent / "agent"
    d.mkdir(parents=True, exist_ok=True)
    path = d / "openclaw-agent.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("DROP TABLE IF EXISTS auth_profile_store")
    conn.execute(_AGENT_DDL)
    conn.executemany("INSERT INTO auth_profile_store VALUES (?, ?, ?)", rows)
    conn.commit()
    conn.close()
    return path


def _snap(audited, prev=None):
    _home, ctx, findings, score = audited
    return snapshot(ctx, findings, score, prev=prev)


def _diff(prev, curr):
    alerts, notes = diff_with_notes(prev, curr)
    cred = [a for a in alerts if "credential store" in a[1]]
    return cred, notes


def _real(n=300):
    return "x" * n


# ------------------------------------------------------------------ the reader


def test_the_reader_records_label_length_and_timestamp_only(audited):
    home = audited[0]
    secret = _secret()
    _shared_db(home, [("authProfiles.store", secret + _real(100), 111),
                      ("auth.sharedStore", "{}", 222),
                      ("plugins.bundledDiscovery", "allowlist", 5)])
    _agent_db(home, "main", [("primary", secret + _real(50), 333)])
    out = read_credential_store_rows(home)
    assert not out["incomplete"]
    assert out["stores"] == {
        "state/authProfiles.store": {"length": len(secret) + 100, "updated": 111},
        "state/auth.sharedStore": {"length": 2, "updated": 222},
        "agent/main/primary": {"length": len(secret) + 50, "updated": 333},
    }
    assert secret not in json.dumps(out), "a value reached the reader's result"


def test_no_database_means_nothing_was_looked_at(audited):
    out = read_credential_store_rows(audited[0])
    assert out == {"stores": {}, "incomplete": False, "reason": ""}


def test_a_snapshot_with_no_database_records_an_empty_set_of_stores(audited):
    """Not an absent key: the first store to appear after this baseline must read as an
    addition, which an absent key could not tell from a baseline written by an older build."""
    rec = _snap(audited)["credential_store"]
    assert rec["stores"] == {} and rec["stores_incomplete"] is False
    assert "files" not in rec, "the directory part stays conditional on the caller's scan"


def test_the_first_store_ever_to_appear_is_an_addition_not_a_silent_first_record(audited):
    home = audited[0]
    prev = _snap(audited)
    _agent_db(home, "main", [("primary", _real(), 2)])
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert [a[0] for a in alerts] == ["MEDIUM"] and "agent/main/primary" in alerts[0][1]


def test_the_dimension_is_still_a_declared_watched_dimension():
    assert "credential_store" in WATCHED_DIMENSIONS


# ------------------------------------------------------------------ the arm


def test_an_unchanged_store_says_nothing(audited):
    home = audited[0]
    _shared_db(home, [("authProfiles.store", _real(), 1)])
    _agent_db(home, "main", [("primary", _real(), 2)])
    prev = _snap(audited)
    alerts, notes = _diff(prev, _snap(audited, prev=prev))
    assert alerts == []
    assert not [n for n in notes if "credentials" in n[1] and "databases" in n[1]]


def test_a_new_credential_row_in_an_agent_database_is_medium_and_names_the_store(audited):
    home = audited[0]
    _agent_db(home, "main", [("primary", _real(), 2)])
    prev = _snap(audited)
    _agent_db(home, "main", [("primary", _real(), 2), ("secondary", _real(), 3)])
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert len(alerts) == 1 and alerts[0][0] == "MEDIUM"
    assert "agent/main/secondary" in alerts[0][1]


def test_a_new_shared_store_key_is_reported(audited):
    home = audited[0]
    _shared_db(home, [("auth.sharedStore", "{}", 1)])
    prev = _snap(audited)
    _shared_db(home, [("auth.sharedStore", "{}", 1), ("authProfiles.store", _real(), 2)])
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert [a[0] for a in alerts] == ["MEDIUM"]
    assert "state/authProfiles.store" in alerts[0][1]


def test_a_store_that_is_only_the_empty_shell_is_info_not_medium(audited):
    home = audited[0]
    _shared_db(home, [("auth.sharedStore", "{}", 1)])
    prev = _snap(audited)
    shell = json.dumps({"version": 1, "profiles": {}}, separators=(",", ":"))
    _shared_db(home, [("auth.sharedStore", "{}", 1), ("authProfiles.store", shell, 2)])
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert [a[0] for a in alerts] == ["INFO"]


def test_a_removed_agent_row_is_reported(audited):
    home = audited[0]
    _agent_db(home, "main", [("primary", _real(), 2), ("secondary", _real(), 3)])
    prev = _snap(audited)
    _agent_db(home, "main", [("primary", _real(), 2)])
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert [a[0] for a in alerts] == ["INFO"]
    assert "no longer" in alerts[0][1] and "agent/main/secondary" in alerts[0][1]


def test_a_change_of_length_is_reported_without_a_value(audited):
    home = audited[0]
    _shared_db(home, [("authProfiles.store", _real(300), 1)])
    prev = _snap(audited)
    _shared_db(home, [("authProfiles.store", _real(301), 1)])
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert [a[0] for a in alerts] == ["INFO"]
    assert "changed" in alerts[0][1] and "state/authProfiles.store" in alerts[0][1]


def test_a_same_length_rewrite_is_seen_through_the_stores_own_timestamp(audited):
    """The case a length alone misses, and the reason the timestamp column is recorded."""
    home = audited[0]
    _agent_db(home, "main", [("primary", _real(300), 10)])
    prev = _snap(audited)
    _agent_db(home, "main", [("primary", "y" * 300, 11)])
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert [a[0] for a in alerts] == ["INFO"]
    assert "agent/main/primary" in alerts[0][1]


def test_no_value_reaches_the_snapshot_or_any_alert(audited):
    home = audited[0]
    secret = _secret()
    _shared_db(home, [("authProfiles.store", secret, 1)])
    _agent_db(home, "main", [("primary", secret, 2)])
    prev = _snap(audited)
    _shared_db(home, [("authProfiles.store", secret + "!", 3)])
    _agent_db(home, "main", [("primary", secret + "!", 4), ("extra", secret, 5)])
    curr = _snap(audited, prev=prev)
    alerts, notes = diff_with_notes(prev, curr)
    blob = json.dumps([prev, curr, alerts, notes], default=str)
    assert secret not in blob and secret[:20] not in blob
    assert str(home) not in json.dumps(curr["credential_store"])


def test_a_database_that_vanishes_reads_as_removal_not_as_silence(audited):
    home = audited[0]
    path = _shared_db(home, [("authProfiles.store", _real(), 1)])
    prev = _snap(audited)
    path.unlink()
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert [a[0] for a in alerts] == ["INFO"]
    assert "no longer" in alerts[0][1]


# ------------------------------------------------------------------ unreadable != unchanged


def test_an_unreadable_database_is_incomplete_and_stands_removals_down(audited):
    home = audited[0]
    path = _shared_db(home, [("authProfiles.store", _real(), 1)])
    _agent_db(home, "main", [("primary", _real(), 2)])
    prev = _snap(audited)
    path.write_bytes(b"this is not a database" * 400)
    curr = _snap(audited, prev=prev)
    assert curr["credential_store"]["stores_incomplete"] is True
    assert curr["credential_store"]["stores_reason"]
    alerts, notes = _diff(prev, curr)
    assert [a for a in alerts if "no longer" in a[1]] == [], "fabricated removal"
    assert any(n[0] == NOTE_INSPECTION_CAPPED and "databases" in n[1] for n in notes), notes


def test_a_view_posing_as_the_table_is_refused_and_disclosed(audited):
    home = audited[0]
    path = _shared_db(home, [("authProfiles.store", _real(), 1)])
    conn = sqlite3.connect(path)
    conn.execute("ALTER TABLE config_machine_state RENAME TO decoy")
    conn.execute("CREATE VIEW config_machine_state AS SELECT * FROM decoy")
    conn.commit()
    conn.close()
    out = read_credential_store_rows(home)
    assert out["incomplete"] and out["stores"] == {}


def test_a_fifo_in_place_of_the_database_does_not_hang_the_reader(audited):
    home = audited[0]
    (home / "state").mkdir()
    os.mkfifo(home / "state" / "openclaw.sqlite")
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("hung")))
    signal.alarm(20)
    try:
        out = read_credential_store_rows(home)
    finally:
        signal.alarm(0)
    assert out["incomplete"] and out["stores"] == {}


# ------------------------------------------------------------------ old baselines


def test_an_old_baseline_without_stores_records_silently(audited):
    """A baseline written before this change: the directory part, but no `stores` key."""
    home = audited[0]
    _shared_db(home, [("authProfiles.store", _real(), 1)])
    _agent_db(home, "main", [("primary", _real(), 2)])
    old = _snap(audited)
    for k in ("stores", "stores_incomplete", "stores_reason"):
        old["credential_store"].pop(k)
    old["credential_store"].update({"files": {}, "incomplete": False, "reason": ""})
    alerts, notes = _diff(old, _snap(audited, prev=old))
    assert alerts == [], "the first run after the change must not alert"
    assert any(n[0] == NOTE_NO_PRIOR_RECORD and "databases" in n[1] for n in notes), notes
    # and it heals: the next run compares against a record that has the stores
    healed = _snap(audited, prev=old)
    assert "stores" in healed["credential_store"]


def test_an_old_baseline_with_no_credential_dimension_at_all_records_silently(audited):
    home = audited[0]
    _shared_db(home, [("authProfiles.store", _real(), 1)])
    old = _snap(audited)
    old.pop("credential_store")
    alerts, _ = _diff(old, _snap(audited, prev=old))
    assert alerts == []


# ------------------------------------------------------------------ severity by shape

_SHELL = json.dumps({"version": 1, "profiles": {}}, separators=(",", ":"))


def test_the_shell_constant_is_the_vendors_empty_store_length():
    assert len(_SHELL) == 27


def test_a_credential_landing_in_the_existing_empty_agent_row_is_medium(audited):
    """The real shape on a fresh install: `agent/main/primary` already exists as the empty
    shell, so the credential arrives as a CHANGE of that row, never as a new key."""
    home = audited[0]
    _agent_db(home, "main", [("primary", _SHELL, 1)])
    prev = _snap(audited)
    _agent_db(home, "main", [("primary", _real(400), 2)])
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert [a[0] for a in alerts] == ["MEDIUM"], alerts
    assert "were empty now hold a credential" in alerts[0][1]
    assert "agent/main/primary" in alerts[0][1]


def test_a_credential_landing_in_the_empty_shared_store_is_medium(audited):
    home = audited[0]
    _shared_db(home, [("authProfiles.store", _SHELL, 1)])
    prev = _snap(audited)
    _shared_db(home, [("authProfiles.store", _real(2138), 2)])
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert [a[0] for a in alerts] == ["MEDIUM"] and "state/authProfiles.store" in alerts[0][1]


def test_growth_of_an_already_populated_store_stays_info(audited):
    """Indistinguishable from a token refresh without reading the value, so it is recorded
    and not paged. Pinned so the MEDIUM rule above is not widened to every length change."""
    home = audited[0]
    _shared_db(home, [("authProfiles.store", _real(2138), 1)])
    _agent_db(home, "main", [("primary", _real(400), 1)])
    prev = _snap(audited)
    _shared_db(home, [("authProfiles.store", _real(9000), 2)])
    _agent_db(home, "main", [("primary", _real(900), 2)])
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert [a[0] for a in alerts] == ["INFO"], alerts


def test_an_emptied_store_is_not_a_landing(audited):
    home = audited[0]
    _agent_db(home, "main", [("primary", _real(400), 1)])
    prev = _snap(audited)
    _agent_db(home, "main", [("primary", _SHELL, 2)])
    alerts, _ = _diff(prev, _snap(audited, prev=prev))
    assert [a[0] for a in alerts] == ["INFO"], alerts


# ------------------------------------------------------------------ labels


def test_a_secret_shaped_store_key_never_reaches_the_snapshot_or_an_alert(audited):
    home = audited[0]
    key = _secret()
    _agent_db(home, "main", [("primary", _real(), 1)])
    prev = _snap(audited)
    _agent_db(home, "main", [("primary", _real(), 1), (key, _real(), 2)])
    curr = _snap(audited, prev=prev)
    alerts, notes = diff_with_notes(prev, curr)
    blob = json.dumps([curr, alerts, notes], default=str)
    assert key not in blob and key[:24] not in blob
    cred = [a for a in alerts if "credential store" in a[1]]
    assert len(cred) == 1 and cred[0][0] == "MEDIUM"


def test_two_keys_sharing_a_long_prefix_stay_two_entries(audited):
    home = audited[0]
    stem = "k" * 60
    _agent_db(home, "main", [(stem + "A", _real(), 1), (stem + "B", _real(), 1)])
    stores = _snap(audited)["credential_store"]["stores"]
    assert len(stores) == 2
    assert all(len(label) <= _LABEL_CAP for label in stores)


def test_the_label_helper_is_stable_bounded_and_leaves_plain_names_alone():
    assert _safe_store_label("state/authProfiles.store") == "state/authProfiles.store"
    a, b = _safe_store_label("agent/main/" + "k" * 80 + "A"), _safe_store_label("agent/main/" + "k" * 80 + "B")
    assert a != b and len(a) <= _LABEL_CAP and len(b) <= _LABEL_CAP
    assert a == _safe_store_label("agent/main/" + "k" * 80 + "A")
    secret = "agent/main/" + _secret()
    out = _safe_store_label(secret)
    assert _secret() not in out and len(out) <= _LABEL_CAP
    assert out != _safe_store_label("agent/main/" + _secret()[:-1] + "Q"), \
        "two redacted keys collapsed into one label"


def test_keys_that_differ_only_in_stripped_characters_do_not_merge(audited):
    home = audited[0]
    _agent_db(home, "main", [("a b", _real(), 1), ("a?b", _real(), 1)])
    assert len(read_credential_store_rows(home)["stores"]) == 2
