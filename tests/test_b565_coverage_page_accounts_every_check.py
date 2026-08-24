"""B-565: the COVERAGE page must account for every catalog check, and must never
claim coverage it did not measure. Offline, read-only, stdlib only.

The defect had two halves, and the second is the one that bites:

1. `_BUCKET_SUBJECTS` was a hand-written tuple that excluded `skills`/`mcp`/`plugins`
   because those get a per-instance count instead. So 68 of 188 catalog checks
   (skills 55 + mcp 13) appeared in neither the numerator nor the denominator of the
   page whose entire job is to say what did and did not get checked.

2. `page["mcp"]` was `{"total": n, "scanned": n, "not_scanned": []}` — `scanned` equal
   to `total` by construction, consulting no finding. That row could not report a gap
   for any config, ever. Measured on a config with three MCP servers it printed
   "3 of 3 scanned" while 9 of 13 MCP checks were UNKNOWN, four of them HIGH.

Both halves were invisible because the page rendered instance counts and check counts
in one identically-formatted unlabelled list.
"""
from __future__ import annotations

import json
import os

from clawseccheck import coverage as cov
from clawseccheck.catalog import BY_ID, SUBJECT_OF, SUBJECT_ORDER, Finding
from clawseccheck.collector import collect
from clawseccheck.report import _mcp_inventory


def _finding(id_: str, status: str = "PASS") -> Finding:
    return Finding(id=id_, title="synthetic", severity="LOW", status=status,
                   detail="synthetic detail", fix="synthetic fix", framework="Test")


def _ids_for(subject: str) -> list[str]:
    return [cid for cid, m in BY_ID.items() if SUBJECT_OF.get(m.surface) == subject]


def _mcp_home(tmp_path):
    """A home whose config declares three MCP servers, so the MCP rows are non-trivial.

    The C-135 warning on this task was explicit: on a box with `mcp: 0 of 0` a naive fix
    looks correct while still hiding the check counts behind the instance counts. Every
    MCP assertion below therefore runs against a config that actually has servers, and
    asserts that it does (`_mcp_inventory` non-empty) before concluding anything —
    without that control a broken `collect()` path would make these tests pass by
    inspecting nothing, which is how the first attempt at this measurement went.
    """
    cfg = tmp_path / "openclaw.json"
    cfg.write_text(json.dumps({"mcp": {"servers": {
        "files": {"command": "npx", "args": ["-y", "server-filesystem", "."]},
        "github": {"command": "npx", "args": ["-y", "server-github"]},
        "shell": {"command": "bash", "args": ["-lc", "mcp-shell"]},
    }}}))
    os.chmod(cfg, 0o600)
    return collect(tmp_path)


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------

def test_every_catalog_check_is_accounted_for_exactly_once(tmp_path):
    """The guard the defect needed. Not "does `subject_coverage` cover every subject"
    (it now does so by construction, deriving the set from `SUBJECT_OF`) but "does the
    assembled PAGE still carry every one" — the drop happened during assembly, where
    `page[subject]` was overwritten by the instance entry and the check numbers for
    that subject went nowhere.
    """
    ctx = _mcp_home(tmp_path)
    page = cov.build_coverage_page(ctx, [])

    # The tally is selected by the ENTRY'S SHAPE, not by importing the module constant
    # that the fix introduced: an instance-counted entry is the one carrying a `note`.
    # Run against the pre-fix tree, the first draft of this test raised AttributeError on
    # `cov._INSTANCE_SUBJECTS` before reaching the assertion below — so it went red on the
    # defect for the wrong reason and never actually exercised the census. A guard that
    # only fails because a name is missing proves nothing about the behaviour it names.
    seen: dict[str, str] = {}
    for subject, entry in page.items():
        tally = entry.get("checks")
        if tally is None and "note" not in entry:
            tally = entry
        if tally is None:
            continue
        for cid in tally["not_scanned"]:
            assert cid not in seen, f"{cid} accounted twice ({seen.get(cid)} and {subject})"
            seen[cid] = subject

    # every id is not_scanned here because no findings were supplied — which makes this
    # a complete census of the catalog rather than a sample of whatever fired today
    assert set(seen) == set(BY_ID), (
        f"{len(set(BY_ID) - set(seen))} catalog checks are on no subject's page row: "
        f"{sorted(set(BY_ID) - set(seen))[:12]}"
    )
    assert len(seen) > 100, "non-vacuity: the census must have inspected a real catalog"


def test_every_check_owning_subject_is_placed_in_exactly_one_list():
    """Staleness control. A subject added to `SUBJECT_OF` tomorrow lands in
    `_CHECK_OWNING_SUBJECTS` automatically; this fails the build if nobody decided
    whether its page row leads with checks or with instances."""
    placed = set(cov._BUCKET_SUBJECTS) | set(cov._INSTANCE_SUBJECTS)
    owning = set(cov._CHECK_OWNING_SUBJECTS)
    assert owning <= placed, f"unplaced check-owning subject(s): {sorted(owning - placed)}"
    assert placed <= set(SUBJECT_ORDER), f"subject not renderable: {sorted(placed - set(SUBJECT_ORDER))}"
    assert not (set(cov._BUCKET_SUBJECTS) & set(cov._INSTANCE_SUBJECTS))


# ---------------------------------------------------------------------------
# The mcp row: it must MEASURE, not assert
# ---------------------------------------------------------------------------

def test_mcp_check_tally_responds_to_findings(tmp_path):
    """The regression pin for half 2. The old row was `scanned = len(inventory)` with no
    finding consulted, so no input could move it. This asserts the tally is a function
    of the findings — the property whose absence was the defect."""
    ctx = _mcp_home(tmp_path)
    assert _mcp_inventory(ctx), "control: this config must declare MCP servers"

    mcp_ids = _ids_for("mcp")
    assert len(mcp_ids) >= 5, "control: the mcp subject must own real checks"

    empty = cov.build_coverage_page(ctx, [])["mcp"]["checks"]
    assert empty["scanned"] == 0
    assert len(empty["not_scanned"]) == empty["total"] == len(mcp_ids)

    one = cov.build_coverage_page(ctx, [_finding(mcp_ids[0])])["mcp"]["checks"]
    assert one["scanned"] == 1, "a resolved MCP check must move the tally"
    assert mcp_ids[0] not in one["not_scanned"]


def test_mcp_unknown_check_is_not_counted_as_scanned(tmp_path):
    """An UNKNOWN MCP check is exactly what the old row hid behind '3 of 3 scanned'."""
    ctx = _mcp_home(tmp_path)
    mcp_ids = _ids_for("mcp")
    page = cov.build_coverage_page(ctx, [_finding(mcp_ids[0], status="UNKNOWN")])
    assert page["mcp"]["checks"]["scanned"] == 0
    assert mcp_ids[0] in page["mcp"]["checks"]["not_scanned"]


def test_mcp_instance_row_still_reports_the_servers(tmp_path):
    """The per-instance count was never wrong — it answers "did we look at each server".
    The fix adds a second question underneath; it must not replace the first."""
    ctx = _mcp_home(tmp_path)
    page = cov.build_coverage_page(ctx, [])
    assert page["mcp"]["total"] == 3
    assert page["mcp"]["scanned"] == 3


# ---------------------------------------------------------------------------
# The rendering: two units may share a line only if both are named
# ---------------------------------------------------------------------------

def test_every_rendered_row_names_its_unit(tmp_path):
    ctx = _mcp_home(tmp_path)
    lines = cov.coverage_page_lines(cov.build_coverage_page(ctx, []))
    assert lines, "control: the page must render something"
    for line in lines:
        if " of " not in line or line.startswith("   "):
            continue
        tallies = [seg for seg in line.split(";") if " of " in seg]
        for seg in tallies:
            assert any(u in seg for u in ("checks", "skills", "servers", "plugins")), (
                f"unlabelled tally — a reader cannot tell what was counted: {line!r}"
            )


def test_skills_check_tally_is_rendered_even_when_the_sweep_did_not_run(tmp_path):
    """The sweep is absent on a plain audit and on `--fast`. The skill CHECKS still ran,
    so dropping the tally when there is no sweep would re-hide the gap on exactly the
    runs with nothing else to speak for it."""
    ctx = _mcp_home(tmp_path)
    page = cov.build_coverage_page(ctx, [], skill_sweep=None)
    assert page["skills"]["total"] is None, "control: this run has no sweep"
    assert page["skills"]["checks"]["total"] == len(_ids_for("skills"))

    row = next(ln for ln in cov.coverage_page_lines(page) if ln.startswith(" Skills:"))
    assert "checks scanned" in row, f"check tally missing from a sweepless row: {row!r}"


def test_plugins_has_no_check_tally_because_it_owns_no_checks():
    """`plugins` is in SUBJECT_ORDER but routes no catalog check, so inventing a
    '0 of 0 checks' tally for it would be noise asserting a coverage question that does
    not exist for that subject."""
    assert _ids_for("plugins") == []
    assert "plugins" not in cov._CHECK_OWNING_SUBJECTS


def test_page_lines_ascii_only(tmp_path):
    """`coverage_page_lines` documents that it has no glyphs to degrade and therefore
    ignores `ascii_only`. That claim has to stay true as wording changes."""
    ctx = _mcp_home(tmp_path)
    for line in cov.coverage_page_lines(cov.build_coverage_page(ctx, [])):
        line.encode("ascii")
