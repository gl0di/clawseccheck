"""B-527 — the drift baseline's config digest must see an ``$include`` fragment edit.

``config_file_sha256`` (C-417) only covers the root config file's bytes: a fragment
merged in via ``$include`` can change a config's whole security posture (gateway bind,
MCP servers, ...) while the root bytes stay identical, so that digest alone cannot see it.

``config_resolved_sha256`` closes the gap by hashing ``ctx.config`` — the dict
``configloader.load_openclaw_config`` already produced by resolving every fragment on the
SAME read that captured the root digest — rather than re-reading the fragments, which would
reopen the exact TOCTOU race ``_config_file_digest`` was written to avoid.

Offline, read-only of tmp_path, stdlib only.
"""
from __future__ import annotations

from types import SimpleNamespace

from clawseccheck import audit, diff, snapshot
from clawseccheck.monitor import SNAPSHOT_VERSION, _config_resolved_digest


def _write(p, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


# ---------------------------------------------------------------- the repro itself


def test_fragment_only_edit_moves_resolved_digest_but_not_root_digest(tmp_path):
    _write(tmp_path / "openclaw.json", '{"$include": "./gateway.json5"}')
    _write(tmp_path / "gateway.json5", '{"gateway": {"bind": "127.0.0.1"}}')
    ctx1, f1, s1 = audit(tmp_path)
    snap1 = snapshot(ctx1, f1, s1)
    assert snap1["gateway_bind"] != "0.0.0.0"  # sanity: fixture reflects the fragment

    _write(tmp_path / "gateway.json5", '{"gateway": {"bind": "0.0.0.0"}}')
    ctx2, f2, s2 = audit(tmp_path)
    snap2 = snapshot(ctx2, f2, s2)

    assert snap1["config_file_sha256"] == snap2["config_file_sha256"], (
        "the root file's bytes never changed; this digest is documented root-only"
    )
    assert snap1["config_resolved_sha256"] != snap2["config_resolved_sha256"], (
        "a fragment edit that changed the effective config must move the resolved digest"
    )


# ---------------------------------------------------------------- add / remove a fragment


def test_fragment_added_moves_the_resolved_digest(tmp_path):
    _write(tmp_path / "openclaw.json", '{"tools": {"web": {"fetch": {"enabled": true}}}}')
    ctx1, f1, s1 = audit(tmp_path)
    snap1 = snapshot(ctx1, f1, s1)

    _write(tmp_path / "extra.json5", '{"gateway": {"bind": "0.0.0.0"}}')
    _write(tmp_path / "openclaw.json",
           '{"tools": {"web": {"fetch": {"enabled": true}}}, "$include": "./extra.json5"}')
    ctx2, f2, s2 = audit(tmp_path)
    snap2 = snapshot(ctx2, f2, s2)

    assert snap1["config_resolved_sha256"] != snap2["config_resolved_sha256"]


def test_fragment_removed_moves_the_resolved_digest(tmp_path):
    _write(tmp_path / "extra.json5", '{"gateway": {"bind": "0.0.0.0"}}')
    _write(tmp_path / "openclaw.json", '{"$include": "./extra.json5"}')
    ctx1, f1, s1 = audit(tmp_path)
    snap1 = snapshot(ctx1, f1, s1)

    _write(tmp_path / "openclaw.json", "{}")
    ctx2, f2, s2 = audit(tmp_path)
    snap2 = snapshot(ctx2, f2, s2)

    assert snap1["config_resolved_sha256"] != snap2["config_resolved_sha256"]


# ---------------------------------------------------------------- ordering independence


def test_resolved_digest_does_not_depend_on_key_insertion_order():
    a = SimpleNamespace(config={"gateway": {"bind": "127.0.0.1"}, "tools": {"web": True}})
    b = SimpleNamespace(config={"tools": {"web": True}, "gateway": {"bind": "127.0.0.1"}})
    assert _config_resolved_digest(a) == _config_resolved_digest(b)


def test_resolved_digest_is_absent_only_when_there_is_no_dict_to_hash():
    # An empty dict is a genuine successfully-parsed config (an "openclaw.json" of "{}")
    # and gets a real digest, same as config_file_sha256 would for an empty root file —
    # only the ABSENCE of a config dict (never collected / not yet loaded) is "".
    assert _config_resolved_digest(SimpleNamespace(config={})) != ""
    assert _config_resolved_digest(SimpleNamespace()) == ""
    assert _config_resolved_digest(SimpleNamespace(config=None)) == ""


# ---------------------------------------------------------------- blind paths stay blind


def test_unreadable_fragment_is_disclosed_not_read_as_unchanged(tmp_path):
    # $include names a fragment that does not exist -> configloader raises -> collector
    # marks config_parse_error, never populates ctx.config. Neither digest may appear:
    # an absent key must never be misread as "this run confirmed no change".
    _write(tmp_path / "openclaw.json", '{"$include": "./missing.json5"}')
    ctx, findings, score = audit(tmp_path)
    assert ctx.config_parse_error is True
    snap = snapshot(ctx, findings, score)
    assert "config_file_sha256" not in snap
    assert "config_resolved_sha256" not in snap


def test_cyclic_fragment_is_disclosed_not_read_as_unchanged(tmp_path):
    _write(tmp_path / "a.json5", '{"$include": "./b.json5"}')
    _write(tmp_path / "b.json5", '{"$include": "./a.json5"}')
    _write(tmp_path / "openclaw.json", '{"$include": "./a.json5"}')
    ctx, findings, score = audit(tmp_path)
    assert ctx.config_parse_error is True
    snap = snapshot(ctx, findings, score)
    assert "config_file_sha256" not in snap
    assert "config_resolved_sha256" not in snap


# ---------------------------------------------------------------- the first-run-after-upgrade cost


def test_new_field_alone_produces_no_alert_against_a_pre_change_baseline(tmp_path):
    """The measured cost of shipping this field on an EXISTING baseline.

    A real user's stored baseline predates ``config_resolved_sha256`` — it simply lacks
    the key, the same shape every prior C-417/F-170/F-174 field addition left behind.
    ``diff()`` never reads the new key (it is store-only, like ``config_file_sha256`` was
    at C-417), so its bare appearance in ``curr`` must change nothing about the alerts a
    run already produced without it — not even a note.
    """
    _write(tmp_path / "openclaw.json", '{"$include": "./gateway.json5"}')
    _write(tmp_path / "gateway.json5", '{"gateway": {"bind": "127.0.0.1"}}')
    ctx, findings, score = audit(tmp_path)
    curr = snapshot(ctx, findings, score)
    assert "config_resolved_sha256" in curr  # this build does write it

    pre_change_baseline = dict(curr)
    del pre_change_baseline["config_resolved_sha256"]

    with_new_field = diff(pre_change_baseline, curr)
    curr_without_field = dict(curr)
    del curr_without_field["config_resolved_sha256"]
    without_new_field = diff(pre_change_baseline, curr_without_field)

    assert with_new_field == without_new_field, (
        "the new key's mere presence in curr must not change a single alert"
    )


def test_snapshot_version_unchanged_field_is_purely_additive(tmp_path):
    # Deliberately NOT bumped: nothing reads config_resolved_sha256 yet (store-only, the
    # same staged shape C-417 used), so there is no comparison for an old baseline to lack.
    _write(tmp_path / "openclaw.json", "{}")
    ctx, findings, score = audit(tmp_path)
    snap = snapshot(ctx, findings, score)
    assert snap["version"] == SNAPSHOT_VERSION == 8
    assert "config_resolved_sha256" in snap
