"""C-746: OpenClaw 2026.10.6 stopped refusing an EMPTY ``plugins.installs`` record.

Measured by diffing the 2026.10.5 and 2026.10.6 retired-config finders: the key is named only when
its value is not a record, or is a record with at least one entry. Doctor "repairs empty
retired-plugin metadata" instead of refusing the update over it. Until this task B382 told a
2026.10.6 user that Doctor would stop on ``{"plugins": {"installs": {}}}``.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, WARN
from clawseccheck.checks import check_retired_config_keys_invalid
from clawseccheck.collector import Context


def _run(installs, build):
    c = Context(home=Path("/nonexistent"))
    c.config = {"plugins": {"installs": installs}}
    c.config_found = True
    c.installed_dist_version = build
    return check_retired_config_keys_invalid(c)


def test_an_empty_record_passes_on_2026_10_6_and_warns_before():
    assert _run({}, "2026.10.6").status == PASS
    for build in ("2026.10.1", "2026.10.4", "2026.10.5"):
        f = _run({}, build)
        assert f.status == WARN and f.evidence == ["plugins.installs"], build


@pytest.mark.parametrize("value", [{"a": {}}, {"a": None}, [], [1], None, "x", "", 0, False, 7])
@pytest.mark.parametrize("build", ["2026.10.4", "2026.10.5", "2026.10.6"])
def test_every_other_present_value_is_still_named(value, build):
    f = _run(value, build)
    assert f.status == WARN and f.evidence == ["plugins.installs"], (value, build)


def test_past_the_validated_window_the_finder_is_not_applied_at_all():
    f = _run({}, "2026.10.7")
    assert f.status == PASS and "was NOT checked" in f.detail
