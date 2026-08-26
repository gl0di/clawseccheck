"""B-659(b) — the plugin trust surface is watched, and a blind run cannot fabricate from it.

A plugin runs inside the agent, so `plugins.allow` is a trust grant. Before this it reached
the monitor only if some check's status happened to move, and measured on
`fixtures/home_safe` an appended entry moved none of 188 — the run printed the all-clear.

Every field is read off the INSTALLED dist's own zod schema for `plugins`
(`zod-schema-O9ml_nmo.js`: `enabled`, `allow`, `deny`, `load`, `slots`, `entries`,
`bundledDiscovery`), and the three newly-dug paths were added to the shipped manifest and
re-verified by regenerating `tests/dist_verified_paths.txt` against that schema — 122 paths
to 125, nothing dropped. `plugins.load` and `plugins.mcp` are deliberately out of scope.

**Direction is the calibration.** Only loosening is reported. Tightening is the user doing
the right thing, and announcing it teaches them to ignore the dimension; reordering cannot
fire at all because the signature sorts. Half this file is the silence side, which is the
half that decides whether a dimension is worth having.

**Which test actually guards `_CONFIG_DIMENSIONS`, established by mutation rather than by
assumption.** Dropping `plugins` from that tuple reddens
`test_the_blind_run_carries_the_plugin_surface_forward` — and NOT
`test_a_blind_run_over_a_fully_populated_config_produces_no_alert_at_all`, which this file
first claimed was the guard. The reason is worth writing down, because it decides how the
next dimension has to be tested: this arm is presence-guarded on both sides, so against a
collapsed `{}` it simply skips and stays silent. The blind run therefore fabricates nothing
IMMEDIATELY; what it does is overwrite the baseline with the collapsed view, so the run after
recovery compares against `{}` and reports every surviving entry as newly allowed. The damage
is deferred by one run, which is exactly the shape a "no alert this run" assertion cannot see.

Both are kept. The carry-forward test is the one with teeth here; the no-alert test still
covers the other half of the family — an arm that is NOT presence-guarded, where the collapse
becomes an alert on the spot — and it needs no one to remember to name a new dimension.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck import monitor
from clawseccheck.cli import main
from clawseccheck.monitor import _CONFIG_DIMENSIONS, WATCHED_DIMENSIONS, diff


def _snap(plugins=None, **kw) -> dict:
    base = {
        "version": monitor.SNAPSHOT_VERSION,
        "checks": {},
        "graded": True,
        "score": 50,
        "raw_score": 50,
        "grade": "F",
        "scope": ["host"],
        "watched": list(WATCHED_DIMENSIONS),
        "config_ever_seen": True,
        "config_file_sha256": "a" * 64,
        "config_resolved_sha256": "b" * 64,
        "mcp": {},
        "mcp_detail": {},
        "channels": {},
        "gateway_bind": "127.0.0.1",
    }
    if plugins is not None:
        base["plugins"] = plugins
    base.update(kw)
    return base


def _plugin_alerts(prev: dict, curr: dict) -> list[tuple[str, str]]:
    # Prefix, not an enumeration of the sentences: an arm added later would otherwise be
    # invisible to every silence assertion in this file, which is where the value is. This
    # makes "every plugin alert starts with Plugin" a convention the file depends on — one
    # arm was written as "Bundled-plugin discovery..." and was silently uncounted here until
    # its own positive test caught it.
    return [(lvl, msg) for lvl, msg in diff(prev, curr) if msg.startswith("Plugin")]


# ---------------------------------------------------------------- registration

def test_the_dimension_is_registered_as_config_derived():
    """Not a substitute for the blind-run test below — a companion to it. This says what the
    intent is; that one says the intent was carried out."""
    assert "plugins" in _CONFIG_DIMENSIONS
    assert "plugins" in WATCHED_DIMENSIONS


# ---------------------------------------------------------------- loosening speaks

def test_an_id_added_to_allow_is_reported():
    alerts = _plugin_alerts(_snap({"allow": ["trentclaw"]}),
                            _snap({"allow": ["attacker", "trentclaw"]}))
    assert len(alerts) == 1, alerts
    lvl, msg = alerts[0]
    assert lvl == "MEDIUM"
    assert "attacker" in msg
    assert "trentclaw" not in msg, "an unchanged entry must not be reported as newly allowed"


def test_an_id_removed_from_deny_is_reported():
    alerts = _plugin_alerts(_snap({"deny": ["evil"]}), _snap({"deny": []}))
    assert len(alerts) == 1 and alerts[0][0] == "MEDIUM", alerts
    assert "evil" in alerts[0][1]


def test_the_global_switch_opening_is_reported():
    alerts = _plugin_alerts(_snap({"enabled": False}), _snap({"enabled": True}))
    assert len(alerts) == 1 and alerts[0][0] == "MEDIUM", alerts


def test_a_new_registry_entry_is_info_not_medium():
    """The installed dist documents `entries` as "updated by provider setup flows", so
    OpenClaw writes one whenever the user configures a provider. Treating a routine write as
    a trust change is how a dimension earns a permanent place in the ignore list."""
    alerts = _plugin_alerts(_snap({"entries": {"codex": True}}),
                            _snap({"entries": {"codex": True, "telegram": True}}))
    assert len(alerts) == 1 and alerts[0][0] == "INFO", alerts
    assert "telegram" in alerts[0][1]


def test_a_registered_but_disabled_plugin_being_switched_on_is_medium():
    """Found by the C-135 pass as a silent case: the key already exists, so the new-entry
    arm cannot fire, and a keys-only signature could not see the flag move. A plugin
    becoming live is not a provider being configured, so it is not INFO."""
    alerts = _plugin_alerts(_snap({"entries": {"dormant": False}}),
                            _snap({"entries": {"dormant": True}}))
    assert len(alerts) == 1 and alerts[0][0] == "MEDIUM", alerts
    assert "dormant" in alerts[0][1]


def test_switching_a_plugin_off_says_nothing():
    assert _plugin_alerts(_snap({"entries": {"x": True}}),
                          _snap({"entries": {"x": False}})) == []


def test_compat_discovery_is_reported_because_it_bypasses_the_allow_list():
    """The allowlist's OFF SWITCH, and the reason every arm above could be defeated in
    silence. `plugins.bundledDiscovery == "compat"` sets `bypassAllowlist`, leaving
    `allowSet` undefined so every bundled plugin becomes eligible
    (`dist/bundled-compat-yOgFRqvZ.js`) — while the allow list itself never moves."""
    alerts = _plugin_alerts(_snap({"allow": ["trentclaw"], "bundled_discovery": "allowlist"}),
                            _snap({"allow": ["trentclaw"], "bundled_discovery": "compat"}))
    assert len(alerts) == 1 and alerts[0][0] == "MEDIUM", alerts
    assert "bypasses" in alerts[0][1]


def test_leaving_compat_mode_says_nothing():
    assert _plugin_alerts(_snap({"bundled_discovery": "compat"}),
                          _snap({"bundled_discovery": "allowlist"})) == []


def test_a_slot_being_reassigned_is_reported():
    """A slot names the plugin that OWNS memory or the context engine and puts it in the
    startup scope, so it is a trust move that touches neither list."""
    alerts = _plugin_alerts(_snap({"slots": {"memory": "memory-core"}}),
                            _snap({"slots": {"memory": "attacker"}}))
    assert len(alerts) == 1 and alerts[0][0] == "MEDIUM", alerts
    assert "attacker" in alerts[0][1]


def test_an_unchanged_slot_says_nothing():
    assert _plugin_alerts(_snap({"slots": {"memory": "memory-core"}}),
                          _snap({"slots": {"memory": "memory-core"}})) == []


# ------------------------------------------- C-135: a rename is not a grant
#
# Six false positives from one omission: the signature stored raw strings and the arm did a
# raw set difference, while OpenClaw compares ids through `normalizePluginId` — trim,
# lowercase, alias table (`dist/config-state-CtMlHVRM.js`), plus the `openai-codex` legacy
# migration (`dist/legacy-config-migrations--PhUdsg4.js`). Every identity-preserving
# re-spelling was a set difference, and always on a LOOSENING arm, because a re-spelling adds
# the new form to `allow` and removes the old from `deny` in the same edit.
#
# These run against `_plugins_sig` rather than hand-built snapshots, because normalization
# happens there — asserting on hand-normalized dicts would test nothing.

def _sig(plugins: dict) -> dict:
    from types import SimpleNamespace
    return monitor._plugins_sig(SimpleNamespace(config={"plugins": plugins}))


def test_openclaw_doctor_fix_migrating_a_retired_id_is_not_a_grant():
    """The worst of the six: `openclaw doctor --fix` rewrites `openai-codex` to `openai`
    across allow AND deny at once, which produced two MEDIUM alerts — one of them asserting
    that a plugin which is still denied had left the block list."""
    before = _sig({"allow": ["trentclaw", "openai-codex"],
                   "deny": ["openai-codex", "shady-plugin"]})
    after = _sig({"allow": ["trentclaw", "openai"], "deny": ["openai", "shady-plugin"]})
    assert _plugin_alerts(_snap(before), _snap(after)) == []


def test_an_alias_replaced_by_its_canonical_id_is_not_a_grant():
    for alias, canonical in (("google-gemini-cli", "google"),
                             ("minimax-portal", "minimax"),
                             ("minimax-portal-auth", "minimax")):
        before = _sig({"allow": ["trentclaw", alias]})
        after = _sig({"allow": ["trentclaw", canonical]})
        assert _plugin_alerts(_snap(before), _snap(after)) == [], (alias, canonical)


def test_collapsing_two_aliases_into_one_deny_entry_is_not_a_loosening():
    """The case that most directly inverted the direction calibration: both ids normalize to
    `minimax`, so writing one canonical entry denies the same thing more robustly — and it
    was announced as a block list losing two plugins."""
    before = _sig({"deny": ["minimax-portal", "minimax-portal-auth"]})
    after = _sig({"deny": ["minimax"]})
    assert _plugin_alerts(_snap(before), _snap(after)) == []


def test_re_casing_and_whitespace_are_not_changes():
    for spelling in ("OpenAI", " openai ", "\topenai\n", "OPENAI"):
        before = _sig({"allow": ["trentclaw", spelling], "deny": [spelling.upper()]})
        after = _sig({"allow": ["trentclaw", "openai"], "deny": ["openai"]})
        assert _plugin_alerts(_snap(before), _snap(after)) == [], spelling


def test_a_genuinely_different_id_still_fires_after_normalisation():
    """The control for the whole normalisation block. Without it, `_plugin_id` returning a
    constant would satisfy every test above."""
    before = _sig({"allow": ["openai"]})
    after = _sig({"allow": ["openai", "attacker"]})
    alerts = _plugin_alerts(_snap(before), _snap(after))
    assert len(alerts) == 1 and "attacker" in alerts[0][1], alerts


def test_a_unicode_confusable_id_is_not_folded_into_the_real_one():
    """Normalisation must not become a laundering step: a Cyrillic lookalike is a DIFFERENT
    plugin and adding it is a real grant."""
    before = _sig({"allow": ["openai"]})
    after = _sig({"allow": ["openai", "op\u0435nai"]})   # CYRILLIC SMALL LETTER IE
    assert len(_plugin_alerts(_snap(before), _snap(after))) == 1


# ---------------------------------------------------------------- tightening is silent

def test_an_id_removed_from_allow_says_nothing():
    assert _plugin_alerts(_snap({"allow": ["a", "b"]}), _snap({"allow": ["a"]})) == []


def test_an_id_added_to_deny_says_nothing():
    assert _plugin_alerts(_snap({"deny": []}), _snap({"deny": ["evil"]})) == []


def test_the_global_switch_closing_says_nothing():
    assert _plugin_alerts(_snap({"enabled": True}), _snap({"enabled": False})) == []


def test_reordering_says_nothing():
    """The signature sorts, so this cannot fire — pinned because a future refactor that
    stopped sorting would turn every config rewrite into an alert."""
    assert _plugin_alerts(_snap({"allow": ["a", "b"]}), _snap({"allow": ["b", "a"]})) == []


def test_an_unchanged_surface_says_nothing():
    surface = {"enabled": True, "allow": ["a"], "deny": ["b"], "entries": {"c": True}}
    assert _plugin_alerts(_snap(dict(surface)), _snap(dict(surface))) == []


# ---------------------------------------------------------------- absence and junk

def test_a_baseline_predating_the_dimension_says_nothing():
    """One quiet run after the upgrade, then it compares. The coverage note tells the user
    the dimension had nothing to compare against; an alert would be a claim about a state
    the previous run never recorded."""
    prev = _snap()                      # no plugins key at all
    assert "plugins" not in prev
    assert _plugin_alerts(prev, _snap({"allow": ["attacker"]})) == []


def test_a_list_appearing_for_the_first_time_says_nothing():
    """Configuring an allowlist where there was none is tightening: before, everything the
    loader found could load. Reporting it would punish the user for locking things down."""
    assert _plugin_alerts(_snap({}), _snap({"allow": ["a"]})) == []


def test_junk_in_the_record_is_skipped_rather_than_reported():
    """A hand-edited or truncated state file must not become a finding, and must not crash."""
    for bad in ("not-a-list", None, 42, {"nested": True}):
        assert _plugin_alerts(_snap({"allow": bad}), _snap({"allow": ["a"]})) == [], bad
        assert _plugin_alerts(_snap({"allow": ["a"]}), _snap({"allow": bad})) == [], bad


def test_a_non_dict_dimension_is_skipped():
    assert _plugin_alerts(_snap("garbage"), _snap({"allow": ["a"]})) == []


# ---------------------------------------------------------------- the general guard

def _write(home: Path, body: dict) -> None:
    home.mkdir(exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps(body), encoding="utf-8")
    os.chmod(cfg, 0o600)


_POPULATED = {
    "gateway": {"bind": "127.0.0.1:8080",
                "auth": {"mode": "token", "token": "a-very-long-token-of-32-chars!!"}},
    "channels": {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
    "plugins": {"enabled": True, "allow": ["trentclaw"], "deny": ["evil"],
                "bundledDiscovery": "allowlist", "slots": {"memory": "memory-core"},
                "entries": {"codex": {}}},
    "mcp": {"servers": {"one": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}},
}


def test_a_blind_run_over_a_fully_populated_config_produces_no_alert_at_all(tmp_path, capsys):
    """THE guard for the whole `_CONFIG_DIMENSIONS` contract, tested by consequence.

    Every modelled config namespace is populated, then the file is made unreadable. A
    dimension missing from `_CONFIG_DIMENSIONS` collapses to its empty view and the diff
    reads that as a removal — the B-269 fabrication burst. Because this asserts on the
    ABSENCE of any alert rather than on the contents of a list, a config dimension added
    later that forgets the list fails here without anyone remembering to name it.
    """
    home, store = tmp_path / "home", tmp_path / "store"
    _write(home, _POPULATED)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    capsys.readouterr()

    os.chmod(home / "openclaw.json", 0o000)
    try:
        main(["--monitor", "--home", str(home), "--data-dir", str(store)])
        out = capsys.readouterr().out
    finally:
        os.chmod(home / "openclaw.json", 0o600)

    fabricated = [ln for ln in out.splitlines()
                  if ("removed" in ln.lower() or "no longer" in ln.lower()
                      or "Plugin(s)" in ln or "changed:" in ln)]
    assert not fabricated, (
        "a run that could not read the settings file reported drift from them:\n"
        + "\n".join(fabricated))


def test_the_blind_run_carries_the_plugin_surface_forward(tmp_path, capsys):
    """The other half: not merely silent, but the last known-good value is KEPT, so the run
    after recovery compares against a real record rather than re-baselining on an empty one.
    Silence with a collapsed baseline would defer the fabrication by one run, not stop it."""
    home, store = tmp_path / "home", tmp_path / "store"
    _write(home, _POPULATED)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    before = json.loads((store / "state.json").read_text(encoding="utf-8"))["plugins"]
    assert before["allow"] == ["trentclaw"], before

    os.chmod(home / "openclaw.json", 0o000)
    try:
        main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    finally:
        os.chmod(home / "openclaw.json", 0o600)
    capsys.readouterr()
    after = json.loads((store / "state.json").read_text(encoding="utf-8"))["plugins"]
    assert after == before, f"the blind run overwrote the plugin baseline: {before} -> {after}"


# ---------------------------------------------------------------- end to end

def test_the_filed_repro_now_alerts(tmp_path, capsys):
    """`plugins.allow` gaining an entry, through the real CLI, under the flags the shipped
    cron recipe emits. Before this the same run printed "No new threats among what was
    compared" and exited 0."""
    home, store = tmp_path / "home", tmp_path / "store"
    _write(home, _POPULATED)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    capsys.readouterr()

    body = json.loads(json.dumps(_POPULATED))
    body["plugins"]["allow"].append("attacker-plugin")
    _write(home, body)
    rc = main(["--monitor", "--home", str(home), "--data-dir", str(store),
               "--exit-code", "--fail-on", "medium"])
    out = capsys.readouterr().out
    assert "attacker-plugin" in out, out
    assert rc == 3, f"the drift did not reach the machine channel (rc={rc})"
