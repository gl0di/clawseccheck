"""C-135 hardening for the adopted JSON5/$include loader and its plugin-manifest caller.

Two missing-bounds defects an adversarial pass found in the adopted configloader work: an
$include sibling fan-out could expand to fanout**depth fragment reads and hang the audit,
and a deeply-nested plugin manifest made loads_json5 raise RecursionError (not ValueError),
which escaped vet_plugin's except and aborted the vet. Both must now degrade, never hang or
crash. Offline, read-only of the tmp_path sandbox, stdlib only.
"""
from __future__ import annotations

import pytest

from clawseccheck.catalog import UNKNOWN
from clawseccheck.checks import vet_plugin
from clawseccheck.configloader import ConfigLoadError, load_openclaw_config


def _write(p, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_include_fanout_is_bounded_not_hung(tmp_path):
    # A doubling sibling fan-out ({$include:['./next','./next']} chained) would expand to
    # 2**depth fragment reads and hang; the global fragment budget stops it fast (C-135).
    depth = 12  # 2**12 = 4096 reads without the cap
    for i in range(depth):
        _write(tmp_path / f"a{i}.json5",
               '{"$include": ["./a%d.json5", "./a%d.json5"]}' % (i + 1, i + 1))
    _write(tmp_path / f"a{depth}.json5", '{"leaf": 1}')
    _write(tmp_path / "openclaw.json", '{"$include": ["./a0.json5", "./a0.json5"]}')
    with pytest.raises(ConfigLoadError):
        load_openclaw_config(tmp_path / "openclaw.json", root_byte_limit=5_000_000)


def test_legitimate_include_dag_still_loads(tmp_path):
    # A modest, legitimate include set (well under the budget) must still resolve normally —
    # the DoS cap must not break real configs.
    _write(tmp_path / "base.json5", '{"gateway": {"bind": "127.0.0.1"}}')
    _write(tmp_path / "extra.json5", '{"tools": {"web": {"fetch": {"enabled": true}}}}')
    _write(tmp_path / "openclaw.json", '{"$include": ["./base.json5", "./extra.json5"]}')
    cfg = load_openclaw_config(tmp_path / "openclaw.json", root_byte_limit=5_000_000)
    assert cfg["gateway"]["bind"] == "127.0.0.1"
    assert cfg["tools"]["web"]["fetch"]["enabled"] is True


def test_deep_plugin_manifest_degrades_to_unknown(tmp_path):
    # A deeply-nested plugin manifest makes loads_json5 raise RecursionError (not ValueError);
    # vet_plugin must catch it and return UNKNOWN, not abort the whole vet (C-135).
    root = tmp_path / "plug"
    _write(root / "openclaw.plugin.json", "[" * 20000 + "]" * 20000)
    f = vet_plugin(root)
    assert f.status == UNKNOWN
    assert "could not parse" in f.detail.lower()
