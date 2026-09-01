"""F-183 — reading OpenClaw's machine-owned config store, strictly key-scoped.

OpenClaw 2026.8.1 moved three settings this tool audits OUT of `openclaw.json` and into
`config_machine_state` in its own state database. That is a new CATEGORY of schema change:
the setting did not move within the JSON, it left the JSON, so every `dig(cfg, …)` reader
of those keys is looking somewhere the runtime no longer writes.

The security case, verbatim from `state-migrations.config-machine-state-*.js`::

    else if (Array.isArray(plugins?.allow) && plugins.allow.length > 0 &&
             (typeof meta?.lastTouchedVersion !== "string" ||
              compareOpenClawVersions(meta.lastTouchedVersion,
                                      BUNDLED_DISCOVERY_STATE_CUTOVER_VERSION) === -1)) {
        ...
        if (!hasCanonicalState) entries.push(["plugins.bundledDiscovery", "compat"]);
    }

`"compat"` makes `withBundledPluginEnablementCompat` set `bypassAllowlist`, leaving
`allowSet` undefined so every bundled plugin becomes eligible (`bundled-compat-*.js`). So
an UPGRADE can switch a restrictive plugin allowlist into bypass mode with the user having
written nothing — and the population it happens to is exactly the one that took the trouble
to write an allowlist.

The reader is an explicit allowlist of three `state_key`s, never a table dump: the same
database holds live OAuth tokens under `authProfiles.store` and `auth.sharedStore` (both
measured present on a real machine), so a generic reader would turn a security audit into a
credential leak.
"""
import json
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

import clawseccheck.checks as C
from clawseccheck.collector import CONFIG_MACHINE_STATE_KEYS, collect
from clawseccheck.monitordims._plugins import _diff_plugins, _plugins_sig

SECRET = "oauth-token-that-must-never-be-read"


def _home(state_rows=None, cfg=None, *, table="config_machine_state", make_db=True):
    home = Path(tempfile.mkdtemp(prefix="f183-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg if cfg is not None else {}))
    os.chmod(path, 0o600)
    if make_db:
        state = home / "state"
        state.mkdir()
        con = sqlite3.connect(state / "openclaw.sqlite")
        try:
            con.execute(
                f"CREATE TABLE {table} "
                "(state_key TEXT PRIMARY KEY, value_json TEXT, updated_at_ms INTEGER)")
            for key, value in (state_rows or []):
                con.execute(f"INSERT INTO {table} VALUES (?,?,?)", (key, value, 0))
            con.commit()
        finally:
            con.close()
    return home


# ------------------------------------------------------------------ the reader

def test_a_set_key_is_read():
    ctx = collect(_home([("plugins.bundledDiscovery", '"compat"')]))
    assert ctx.config_machine_state_read is True
    assert ctx.config_machine_state["plugins.bundledDiscovery"] == "compat"


def test_all_three_allowlisted_keys_are_read():
    ctx = collect(_home([
        ("plugins.bundledDiscovery", '"allowlist"'),
        ("cron.store", '"/tmp/elsewhere.sqlite"'),
        ("hooks.internal.installs", '{"h1": {}}'),
    ]))
    assert set(ctx.config_machine_state) == set(CONFIG_MACHINE_STATE_KEYS)


@pytest.mark.parametrize("kwargs,label", [
    (dict(make_db=False), "no state database at all"),
    (dict(table="something_else"), "a state DB predating the table"),
], ids=["no-db", "no-table"])
def test_an_unreadable_store_is_undetermined_not_absent(kwargs, label):
    """"Could not look" and "looked, nothing there" are different answers. Collapsing them
    is the lying-clean this reader exists to prevent (Golden Rule #4)."""
    ctx = collect(_home([], **kwargs))
    assert ctx.config_machine_state_read is False, label
    assert ctx.config_machine_state == {}


def test_a_readable_store_with_no_matching_row_is_a_stronger_statement():
    ctx = collect(_home([]))
    assert ctx.config_machine_state_read is True
    assert ctx.config_machine_state == {}


def test_a_row_whose_value_is_not_json_is_present_but_unreadable():
    """Recording it as absent would let a consumer answer "not set" about a row that
    exists."""
    ctx = collect(_home([("plugins.bundledDiscovery", "not json at all")]))
    assert ctx.config_machine_state_read is True
    assert "plugins.bundledDiscovery" not in ctx.config_machine_state
    assert "plugins.bundledDiscovery" in ctx.config_machine_state_unparsed


def test_an_oversized_value_is_present_and_not_read():
    """Every reader in this module is bounded; this one reads a value whole, so it needs a
    bound too. Found by the C-135 pass: a hostile or corrupt store can hold a multi-megabyte
    `hooks.internal.installs` record, and reading it unbounded is this reader's only
    denial-of-service surface. Over the cap is "present and not read", never "absent" —
    a consumer must not answer "not set" about a row it declined to parse.
    """
    import json as _json
    huge = _json.dumps({f"hook{i}": {"pad": "y" * 200} for i in range(20000)})
    assert len(huge) > 256 * 1024
    ctx = collect(_home([("hooks.internal.installs", huge),
                         ("plugins.bundledDiscovery", '"compat"')]))
    assert "hooks.internal.installs" not in ctx.config_machine_state
    assert "hooks.internal.installs" in ctx.config_machine_state_unparsed
    # and it does not blind its neighbour
    assert ctx.config_machine_state["plugins.bundledDiscovery"] == "compat"


@pytest.mark.parametrize("value", [None, b"\x00\x01"], ids=["null", "blob"])
def test_a_non_text_value_is_present_and_not_read(value):
    ctx = collect(_home([("plugins.bundledDiscovery", value)]))
    assert "plugins.bundledDiscovery" in ctx.config_machine_state_unparsed


def test_a_corrupt_row_does_not_blind_its_neighbours():
    ctx = collect(_home([
        ("plugins.bundledDiscovery", "}{ broken"),
        ("cron.store", '"/tmp/real.sqlite"'),
    ]))
    assert ctx.config_machine_state["cron.store"] == "/tmp/real.sqlite"
    assert ctx.config_machine_state_unparsed == {"plugins.bundledDiscovery"}


# ------------------------------------------------------- the key scope, proven

def test_a_key_outside_the_allowlist_is_never_read():
    """The mutation target. Change the query to `SELECT *` (or widen the key tuple) and
    this fails — which is the whole guarantee, since the same database holds live OAuth
    tokens two rows away from the ones we want."""
    ctx = collect(_home([
        ("authProfiles.store", json.dumps({"access_token": SECRET})),
        ("auth.sharedStore", json.dumps({"refresh_token": SECRET})),
        ("plugins.bundledDiscovery", '"compat"'),
    ]))
    assert set(ctx.config_machine_state) == {"plugins.bundledDiscovery"}
    assert SECRET not in json.dumps(ctx.config_machine_state)
    assert SECRET not in json.dumps(sorted(ctx.config_machine_state_unparsed))


def test_the_allowlist_is_exactly_the_three_migrated_keys():
    assert set(CONFIG_MACHINE_STATE_KEYS) == {
        "plugins.bundledDiscovery", "cron.store", "hooks.internal.installs"}


def test_the_query_binds_the_allowlist_rather_than_selecting_everything():
    """A source-level companion to the behavioural test above: `SELECT *` would still pass
    the row-count assertions if someone later filtered in Python, and filtering after the
    fact means the secret was read into this process first."""
    source = (Path(__file__).resolve().parent.parent
              / "clawseccheck" / "collector.py").read_text()
    body = source.split("def _collect_config_machine_state", 1)[1].split("\ndef ", 1)[0]
    assert "SELECT state_key, value_json FROM config_machine_state" in body
    assert "WHERE state_key IN" in body
    # Comments stripped first: the source says "there is no `SELECT *`" in prose, and an
    # assertion that reads its own explanation as the violation is a guard that can only
    # be silenced by deleting the sentence explaining it.
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
    assert "SELECT *" not in code


def test_nothing_from_a_non_allowlisted_row_reaches_a_rendered_report():
    """Asserted on the RENDERED text, not on the reader's return: a value that never leaves
    the reader is safe, and one that reaches a report is not, however it got there.

    Scoped to rows outside the allowlist, which is where the credentials are. An
    allowlisted value may legitimately be named — `cron.store` is the user's own path and
    the shadow finding is useless without it — but `hooks.internal.installs` is reported
    as a COUNT, never as its record, so its keys are checked here too.
    """
    from clawseccheck import audit
    from clawseccheck.report import render_report
    home = _home([
        ("authProfiles.store", json.dumps({"access_token": SECRET})),
        ("auth.sharedStore", json.dumps({"refresh_token": SECRET})),
        ("plugins.bundledDiscovery", '"compat"'),
        ("hooks.internal.installs", json.dumps({f"hook-{SECRET}": {}})),
    ], cfg={"hooks": {"enabled": True}})
    _ctx, findings, score = audit(home)
    rendered = render_report(findings, score, ctx=_ctx, verbose=True)
    assert SECRET not in rendered
    assert SECRET not in json.dumps([f.__dict__ for f in findings], default=str)


# ------------------------------------------------------- the monitor can see it

def test_the_signature_records_the_state_value():
    sig = _plugins_sig(collect(_home([("plugins.bundledDiscovery", '"compat"')])))
    assert sig["bundled_discovery_state"] == "compat"


def test_the_signature_leaves_the_key_absent_when_the_store_cannot_be_read():
    """Absent, not a fabricated "allowlist" — so an unreadable store can never manufacture
    an alert, and can never suppress one either."""
    sig = _plugins_sig(collect(_home([], make_db=False)))
    assert "bundled_discovery_state" not in sig


@pytest.mark.parametrize("prev,curr,fires", [
    ({}, {"bundled_discovery_state": "compat"}, True),
    ({"bundled_discovery_state": "allowlist"}, {"bundled_discovery_state": "compat"}, True),
    ({"bundled_discovery_state": "compat"}, {"bundled_discovery_state": "compat"}, False),
    ({"bundled_discovery_state": "compat"}, {}, False),
    ({}, {"bundled_discovery": "compat"}, True),
    ({}, {"bundled_discovery": "compat", "bundled_discovery_state": "compat"}, True),
    ({}, {}, False),
], ids=["appears", "allowlist-to-compat", "unchanged", "disappears",
        "config-key-still-watched", "both-at-once", "nothing"])
def test_the_compat_arm_fires_on_either_source(prev, curr, fires):
    alerts = []
    _diff_plugins((prev, curr), alerts, True)
    hits = [a for a in alerts if "compat mode" in a[1]]
    assert bool(hits) is fires
    assert len(hits) <= 1, "one setting, one alert — not one per source"


def test_the_state_alert_says_where_the_value_came_from():
    """A user told to check their config would find nothing there. The wording has to say
    the value lives in OpenClaw's own store and that an upgrade can have written it."""
    alerts = []
    _diff_plugins(({}, {"bundled_discovery_state": "compat"}), alerts, True)
    text = alerts[0][1]
    assert "state store" in text
    assert "openclaw.json" in text


def test_the_arm_was_dead_before_this_change():
    """Non-vacuity, stated as the defect it fixes: the config-only signature could never
    hold `compat` on a 2026.8.1 machine, because the runtime does not read the value from
    the config at all — so the arm below it had nothing to fire on."""
    sig = _plugins_sig(collect(_home(
        [("plugins.bundledDiscovery", '"compat"')],
        cfg={"plugins": {"allow": ["a"]}})))
    assert "bundled_discovery" not in sig, "the config key is genuinely absent here"
    assert sig["bundled_discovery_state"] == "compat"


# ------------------------------------------------------- the other two consumers

def test_b179_sees_installs_held_in_the_state_store():
    ctx = collect(_home([("hooks.internal.installs", '{"h1": {}, "h2": {}}')],
                        cfg={"hooks": {"enabled": True}}))
    finding = next(f for f in C.run_all(ctx) if f.id == "B179")
    assert any("2 internal hook install(s)" in e for e in (finding.evidence or []))


def _home_with_default_cron(state_rows, cfg=None):
    """The shadow check only runs once the DEFAULT `<home>/cron/jobs.json` has been read —
    its whole subject is "we scanned that file while the runtime uses another store"."""
    home = _home(state_rows, cfg)
    cron = home / "cron"
    cron.mkdir()
    (cron / "jobs.json").write_text(json.dumps({"version": 1, "jobs": []}))
    return home


def test_the_cron_store_shadow_check_reads_the_state_value():
    """`cron.store` moved too, so a shadow this check exists to catch would have gone
    unreported on a current build."""
    ctx = collect(_home_with_default_cron([("cron.store", '"/tmp/somewhere-else.sqlite"')]))
    assert ctx.cron_store_shadowed is True


def test_the_config_key_still_wins_when_the_store_has_nothing():
    """A machine on an older OpenClaw keeps its config-held value."""
    ctx = collect(_home_with_default_cron([], cfg={"cron": {"store": "/tmp/legacy.sqlite"}}))
    assert ctx.cron_store_shadowed is True


def test_no_shadow_is_claimed_when_neither_source_names_a_store():
    """The control: without it, "always shadowed" passes both assertions above."""
    ctx = collect(_home_with_default_cron([]))
    assert ctx.cron_store_shadowed is False


def test_a_capped_state_walk_is_disclosed_not_reported_as_no_store(tmp_path):
    """The `walk_dir_safely(max_files=100)` that locates the DB can stop before reaching it.
    Returning silently would make "we stopped looking" indistinguishable from "there is no
    state store" — a silent completeness claim over a capped scan (GR#4), which is exactly
    what tests/test_paired_call_sites.py exists to catch. It caught this one.

    Five sibling readers sit in that guard's `_EXEMPT` list; the list says in its own words
    that it is debt and must not be extended, so this discloses instead.
    """
    from clawseccheck.collector import Context, _collect_config_machine_state

    home = tmp_path / "oc"
    state = home / "state"
    state.mkdir(parents=True)
    for n in range(150):                      # over the cap of 100
        (state / f"zz-{n:03d}.tmp").write_bytes(b"")

    # Deliberately no `openclaw.sqlite`. An earlier draft of this test put one in the
    # directory expecting the cap to hide it; the walk order is the filesystem's, not
    # sorted, so the DB landed inside the first 100 and the test proved nothing. The
    # property is not "the cap hid this specific file" — it is that after stopping early
    # we cannot know whether the store was there, and must not answer as if we could.
    ctx = Context(home=home, config={}, config_path=home / "openclaw.json")
    _collect_config_machine_state(home, ctx)

    assert ctx.config_machine_state_read is False, "nothing was read — that part is right"
    assert any("stopped listing" in e and "openclaw.sqlite" in e for e in ctx.errors), \
        f"the cap must be disclosed, got: {ctx.errors}"


def test_an_ordinary_empty_state_dir_stays_quiet(tmp_path):
    """The control. Without it, "always append an error" satisfies the test above, and the
    UNDETERMINED path would grow a permanent false note on every machine with no state DB.
    """
    from clawseccheck.collector import Context, _collect_config_machine_state

    home = tmp_path / "oc"
    (home / "state").mkdir(parents=True)
    ctx = Context(home=home, config={}, config_path=home / "openclaw.json")
    _collect_config_machine_state(home, ctx)

    assert ctx.config_machine_state_read is False
    assert not [e for e in ctx.errors if "stopped listing" in e]
