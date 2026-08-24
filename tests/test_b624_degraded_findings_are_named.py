"""A report must not send the reader to look at findings it does not show.

B-624. The degraded-checks banner ended: *"…or review the affected finding(s) below for an
unreadable-input detail."* Measured on a home whose `openclaw.json` is present but
unparseable: **33 degraded checks, and `grep -c unparseable` on that same report returned
0.** Nothing below was marked, and nothing could be — every degraded finding is `UNKNOWN`,
and the default render does not print `UNKNOWN` findings at all. The instruction could not be
followed by anyone.

The machine surface could not answer it either. `engine_degraded` is a field on `Finding`,
but it was absent from the per-finding dicts `--json` emits, so a consumer saw two aggregate
numbers it could neither reconcile nor attribute:

    degraded_count                 33   (every degraded finding)
    undetermined.engine_degraded   16   (the SCORED subset of the same set)

Two different populations, no way to name a single member of either. Both now derive from
the published flag, which is what turns a count into a list.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json
import subprocess
import sys

_UNPARSEABLE = "{ this is not json at all "


def _blind_home(tmp_path):
    home = tmp_path / "blind"
    home.mkdir()
    (home / "openclaw.json").write_text(_UNPARSEABLE, encoding="utf-8")
    return home


def _healthy_home(tmp_path):
    home = tmp_path / "ok"
    home.mkdir()
    (home / "openclaw.json").write_text(
        json.dumps({"channels": {}, "tools": {"allow": ["read_file"]}}), encoding="utf-8")
    return home


def _run(home, tmp_path, *extra):
    out = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", str(home),
         "--data-dir", str(tmp_path / "d"), "--no-history", *extra],
        capture_output=True, text=True,
    )
    return out.stdout


def test_the_banner_names_the_degraded_checks_it_used_to_point_at(tmp_path):
    """The reproduction this task was filed on."""
    text = _run(_blind_home(tmp_path), tmp_path)

    # Non-vacuity: the run must actually have degraded checks, or every assertion below
    # passes over a report that had nothing to disclose.
    assert "could not reach a reliable verdict" in text, text[:400]

    assert "Affected:" in text, text[:600]
    assert "engine_degraded" in text, "the banner must say where the full set is"
    # The promise it could not keep is gone.
    assert "review the affected finding(s) below" not in text


def test_the_named_list_is_capped_and_says_what_it_cut(tmp_path):
    """A silent cut here would recreate the same defect one level down: a list that ends
    without saying it ended is a claim that this was all of them."""
    text = _run(_blind_home(tmp_path), tmp_path)
    line = next(ln for ln in text.splitlines() if "Affected:" in ln)
    assert "more" in line, line
    named = line.split("Affected:")[1].split("(all carry")[0]
    assert named.count(",") <= 8, f"cap is not holding: {line}"


def test_a_healthy_run_gets_no_banner_at_all(tmp_path):
    """The control. A banner on every run is furniture within a week."""
    text = _run(_healthy_home(tmp_path), tmp_path)
    assert "could not reach a reliable verdict" not in text
    assert "Affected:" not in text


def test_the_two_aggregate_numbers_both_derive_from_the_published_flag(tmp_path):
    """The defect was not that the numbers disagreed — they describe different populations.
    It was that neither could be attributed to a finding, so a consumer could not tell."""
    payload = json.loads(_run(_blind_home(tmp_path), tmp_path, "--json"))
    findings = payload["findings"]

    assert all("engine_degraded" in f for f in findings), "field must be always-present"
    flagged = [f for f in findings if f["engine_degraded"]]

    assert len(flagged) > 10, f"probe produced only {len(flagged)} degraded findings"
    assert len(flagged) == payload["degraded_count"]
    assert sum(1 for f in flagged if f["scored"]) == payload["undetermined"]["engine_degraded"]

    # Every degraded finding is UNKNOWN — which is exactly why the old banner could not
    # point at them in a render that shows FAIL/WARN.
    assert {f["status"] for f in flagged} == {"UNKNOWN"}


def test_a_healthy_run_publishes_the_flag_as_false_rather_than_omitting_it(tmp_path):
    """An absent key and a false one are different claims to a consumer that uses `.get()`."""
    payload = json.loads(_run(_healthy_home(tmp_path), tmp_path, "--json"))
    assert payload["findings"], "probe produced no findings"
    assert all(f["engine_degraded"] is False for f in payload["findings"])
    assert payload["degraded_count"] == 0
