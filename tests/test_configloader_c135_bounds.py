"""C-135 hardening for the adopted JSON5/$include loader and its plugin-manifest caller.

Two missing-bounds defects an adversarial pass found in the adopted configloader work: an
$include sibling fan-out could expand to fanout**depth fragment reads and hang the audit,
and a deeply-nested plugin manifest made loads_json5 raise RecursionError (not ValueError),
which escaped vet_plugin's except and aborted the vet. Both must now degrade, never hang or
crash. Offline, read-only of the tmp_path sandbox, stdlib only.
"""
from __future__ import annotations

import json

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


def _json_parses(text: str) -> bool:
    """Whether THIS interpreter's own `json.loads` follows `text` to the end.

    How deep a document it can follow is the interpreter's business, not ours: measured
    2026-10-05 with `json.loads("[" * n + "]" * n)`, the largest n that parses is 994 on
    CPython 3.9.25, 9,997 on 3.12.3 and about 58,000 on 3.14.4 (that last figure moves by
    a few dozen from run to run). A test about a deeply nested manifest therefore asks the
    interpreter instead of assuming an answer.
    """
    try:
        json.loads(text)
    except RecursionError:
        return False
    return True


@pytest.mark.parametrize("depth", [500, 20_000, 100_000])
def test_deep_plugin_manifest_degrades_to_unknown(tmp_path, depth):
    # A deeply-nested plugin manifest used to make loads_json5 raise RecursionError (not
    # ValueError); vet_plugin must catch it and return UNKNOWN, not abort the whole vet
    # (C-135). The three depths cover the three outcomes the interpreters disagree about:
    # 500 parses on every supported Python, 20,000 parses on 3.14 only, 100,000 on none.
    # Either way the verdict is the same honest UNKNOWN; only the reason differs, and
    # which reason is expected is decided by what json.loads does HERE, not by a version.
    text = "[" * depth + "]" * depth
    root = tmp_path / "plug"
    _write(root / "openclaw.plugin.json", text)
    f = vet_plugin(root)
    assert f.status == UNKNOWN
    if _json_parses(text):
        # Parsed: a list, so the manifest is refused for not being an object.
        assert "not a json object" in f.detail.lower()
    else:
        # Not parseable by this interpreter: the C-135 degrade arm.
        assert "could not parse" in f.detail.lower()
