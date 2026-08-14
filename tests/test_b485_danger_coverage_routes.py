"""B-485 — every way a vet scan can fail to COVER its target must floor the headline.

## Why prose-matching was replaced

``dossier._danger_coverage_gap`` decides whether a Danger-axis ``UNKNOWN`` is the benign
"there was nothing to scan" (a docs-only skill) or the non-benign "there is content here
and we never got to read it". Before B-485 it answered that question with two legs:

1. ``ctx.limit_hits`` — structural, but only bumped by the collector's own size/file/
   nesting caps and by ``note_limit`` on an unreadable file; and
2. the literal English substring ``"coverage is incomplete"`` in a finding's ``detail``.

Leg 2 is the defect. It made a *verdict* depend on how a producer happened to word a
sentence, so any producer that discloses a coverage gap in different words has no signal
at all — and one already did. ``check_installed_skills``' parse-error branch
(``checks/_vet.py``) emits

    UNKNOWN  could not analyze <skill>: scripts/helper.py — parse error(s);
             file(s) not scanned by the AST/taint layer

It calls no ``note_limit`` (so leg 1 is empty) and does not use leg 2's phrasing. Result,
measured on HEAD before this change: the Danger axis printed that it never got to look,
and the headline one line above it read ``INSTALL`` with ``rc=0`` — which
``docs/USAGE.md`` documents as an install gate. A green light over an unread file.

The replacement keys on ``Finding.engine_degraded``, which ``catalog.py`` already defines
as "the single source of truth for 'this UNKNOWN is engine-side'" and which
``scoring.DEGRADED_CHECK_CAP`` already consumes on the full-audit path. The parse-error
branch had been setting it since B-455; the dossier was simply the one consumer that
ignored it. Keying on the flag closes the whole class — every present and future
producer of an engine-side UNKNOWN — instead of the one instance, and it cannot be lost
by a reword. Leg 2 survives only as a documented fallback for hand-built ``Finding``
objects in unit tests that carry neither a real ``ctx`` nor the flag; ``test_b092_
coverage_gap.py`` is its only consumer, and it is now last, not first.

## What this module pins

One case per route the B-485 grounding proved reachable, asserted through the REAL entry
points (``--vet-skill`` / ``--advise``) rather than by calling the predicate, plus the
two controls that hold the line in the other direction:

* R2 parse error (the reported route) — was INSTALL, must be CAUTION.
* R3 collector size/file cap, R4 unreadable file — already CAUTION, must stay.
* R6 content-ring budget exhaustion (``VET-COVERAGE``) — already CAUTION, must stay.
* R7 native stowaway / opaque binary blob — reaches CAUTION via a stowaway WARN, not via
  a coverage disclosure; pinned so the difference stays visible.
* Control A: a skill with genuinely nothing to scan stays INSTALL (B-092's distinction —
  "nothing to scan" is a legitimately clean result and must not be swallowed).
* Control B: a clean, fully-readable skill stays INSTALL (the regression direction).

R1 (a ring check that raises is swallowed by ``_run_content_ring``'s bare ``except``,
producing no finding at all) is a KNOWN, UNCLOSED residual: an empty bucket carries no
signal for any predicate to read, so it needs a producer change, not this one. It is
pinned below as unclosed so nobody reads this module as having fixed it.

Stdlib-only, offline, writes only under pytest's ``tmp_path``.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import vet_skill
from clawseccheck.cli import main
from clawseccheck.dossier import _danger_coverage_gap, build_profile

_FRONTMATTER = (
    "---\nname: {name}\ndescription: A small benign skill for testing.\n---\n\n"
    "# {name}\n\nDoes one ordinary thing. Ask before reading other files.\n"
)


def _skill(tmp_path: Path, name: str, files: dict) -> Path:
    """Build a minimal, benign skill directory. `files` values may be str or bytes."""
    sk = tmp_path / name
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text(_FRONTMATTER.format(name=name), encoding="utf-8")
    for rel, body in files.items():
        p = sk / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(body, bytes):
            p.write_bytes(body)
        else:
            p.write_text(body, encoding="utf-8")
    return sk


def _profile(sk: Path):
    return build_profile(vet_skill(str(sk)), str(sk), "skill")


def _danger(profile):
    return next(a for a in profile.axes if a.axis == "danger")


def _vet_cli(capsys, sk: Path) -> tuple[int, str]:
    """Run the real ``--vet-skill`` entry point and return (rc, stdout)."""
    rc = main(["--vet-skill", str(sk), "--ascii"])
    return rc, capsys.readouterr().out


def _advise_cli(capsys, sk: Path) -> tuple[int, str]:
    """Run the real ``--advise`` entry point and return (rc, stdout)."""
    rc = main(["--advise", str(sk), "--ascii"])
    return rc, capsys.readouterr().out


def _assert_floored(capsys, sk: Path) -> None:
    """Both Mode C entry points must say CAUTION and exit non-zero for this target."""
    rc, out = _vet_cli(capsys, sk)
    assert rc == 1, out
    assert "CAUTION" in out, out
    assert "INSTALL" not in out.replace("DO-NOT-INSTALL", ""), out

    rc_a, out_a = _advise_cli(capsys, sk)
    assert rc_a == 1, out_a
    assert "CAUTION" in out_a, out_a
    assert "this looks safe to install" not in out_a, out_a


def _assert_clean(capsys, sk: Path) -> None:
    """Both Mode C entry points must say INSTALL and exit zero for this target."""
    rc, out = _vet_cli(capsys, sk)
    assert rc == 0, out
    assert "INSTALL" in out and "DO-NOT-INSTALL" not in out, out
    assert "CAUTION" not in out, out

    rc_a, out_a = _advise_cli(capsys, sk)
    assert rc_a == 0, out_a
    assert "this looks safe to install" in out_a, out_a


# ── R2: the reported route — a bundled file the AST layer could not parse ────────

def test_r2_unparseable_bundled_file_floors_the_headline(tmp_path, capsys):
    """The route B-485 was filed for. Before this change: INSTALL, rc=0."""
    sk = _skill(tmp_path, "r2", {
        "scripts/helper.py": "This file is English prose, not Python.\nIt will not parse.\n",
    })
    _assert_floored(capsys, sk)


def test_r2_is_keyed_on_the_flag_and_not_on_the_old_prose(tmp_path):
    """Non-vacuity for the replacement: R2's finding carries the structural flag and
    does NOT contain the substring the retired primary leg matched on, so the floor
    below can only be coming from ``engine_degraded``."""
    sk = _skill(tmp_path, "r2flag", {
        "scripts/helper.py": "This file is English prose, not Python.\nIt will not parse.\n",
    })
    f = vet_skill(str(sk))
    assert f.status == UNKNOWN
    assert f.engine_degraded is True
    assert "coverage is incomplete" not in (f.detail or "")
    assert "parse error" in (f.detail or "")

    p = _profile(sk)
    assert _danger(p).status == UNKNOWN
    assert p.overall_status == WARN
    assert p.verdict == "CAUTION"


def test_r2_json_verdict_agrees_with_the_text_dossier(tmp_path, capsys):
    """The machine-readable surface must not disagree with the rendered one."""
    sk = _skill(tmp_path, "r2json", {"scripts/helper.py": "Not python at all.\n"})
    rc = main(["--vet-skill", str(sk), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert data["verdict"] == "CAUTION"


# ── R3 / R4: the collector's own coverage limits (already closed — must stay) ────

def test_r3_collector_size_cap_floors_the_headline(tmp_path, capsys):
    """A file past the per-skill size cap: content exists and was not scanned."""
    sk = _skill(tmp_path, "r3", {
        "scripts/ok.py": "def f():\n    return 1\n",
        "big.txt": "A" * 3_000_000,
    })
    _assert_floored(capsys, sk)


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permissions, so the "
                                              "unreadable-file route cannot be built")
def test_r4_unreadable_bundled_file_floors_the_headline(tmp_path, capsys):
    sk = _skill(tmp_path, "r4", {"scripts/locked.py": 'import os\nos.system("echo hi")\n'})
    locked = sk / "scripts" / "locked.py"
    os.chmod(locked, 0o000)
    try:
        assert not os.access(locked, os.R_OK), "the file is still readable; test is vacuous"
        _assert_floored(capsys, sk)
    finally:
        os.chmod(locked, stat.S_IRUSR | stat.S_IWUSR)


# ── R6: the content ring's own budget (VET-COVERAGE) ────────────────────────────

def test_r6_ring_budget_exhaustion_floors_the_headline(tmp_path, capsys, monkeypatch):
    """The ring's cooperative ceiling emits a synthetic ``VET-COVERAGE`` UNKNOWN that is
    already ``engine_degraded=True``. Forced deterministically with a tiny-but-nonzero
    budget (``cpu_deadline(0.0)`` disables the cap outright), through the real ring code
    and the real CLI — no clock monkeypatching, no hand-built Finding."""
    from clawseccheck.checks import _vet as vet_mod

    real_ring = vet_mod._run_content_ring

    def _starved(ctx, target_budget_s=None):
        return real_ring(ctx, target_budget_s=1e-9)

    monkeypatch.setattr(vet_mod, "_run_content_ring", _starved)

    sk = _skill(tmp_path, "r6", {"scripts/ok.py": "def f():\n    return 1\n" * 200})
    f = vet_skill(str(sk))
    pool = [f, *getattr(f, "ring_findings", [])]
    gap = [fx for fx in pool if fx.id == "VET-COVERAGE"]
    assert gap, f"budget path did not fire; pool={[fx.id for fx in pool]}"
    assert gap[0].status == UNKNOWN and gap[0].engine_degraded is True
    _assert_floored(capsys, sk)


# ── R7: binary content excluded from scanning ───────────────────────────────────

@pytest.mark.parametrize("name,blob", [
    ("r7elf", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 4096),   # native stowaway
    ("r7blob", bytes(range(256)) * 300),                       # opaque, non-ELF
])
def test_r7_binary_content_does_not_read_as_install(tmp_path, capsys, name, blob):
    """Pinned as it really is. A binary is excluded from the AST/taint layer without any
    coverage disclosure — the Danger axis stays PASS and the headline is floored only by
    the separate stowaway/binary WARN. That is a weaker guarantee than R2-R6 get (a
    reworded or dropped WARN would take the floor with it), and it is a producer-side
    residual, not something this predicate can reach: nothing in the danger bucket is
    UNKNOWN, so there is no coverage gap to detect."""
    sk = _skill(tmp_path, name, {"assets/data.bin": blob})
    p = _profile(sk)
    assert _danger(p).status == WARN
    assert _danger_coverage_gap([f for f in p.findings], None) is False
    _assert_floored(capsys, sk)


# ── R1: the known, unclosed residual ────────────────────────────────────────────

def test_r1_a_raising_ring_check_is_still_an_open_residual(tmp_path, monkeypatch):
    """NOT fixed here, pinned so nobody believes it is.

    ``_run_content_ring``'s bare ``except Exception: continue`` swallows a raising ring
    check with no finding, no ``note_limit`` and no ``skipped`` entry — so the danger
    bucket carries no UNKNOWN at all. No predicate over that bucket can see an absence;
    closing R1 requires the handler to emit a disclosure, which lives in
    ``checks/_vet.py``. The bare ``except`` itself must keep holding: a hostile skill
    must never be able to crash the vet.
    """
    from clawseccheck.checks import _vet as vet_mod

    def _explode(ctx):
        raise RuntimeError("ring check blew up")

    ring = list(vet_mod.SKILL_CONTENT_RING)
    assert ring, "the content ring is empty; this test would be vacuous"
    monkeypatch.setattr(vet_mod, "SKILL_CONTENT_RING", [_explode] + ring[1:])

    sk = _skill(tmp_path, "r1", {"scripts/ok.py": "x = 1\n"})
    p = _profile(sk)                     # must not raise
    assert p.verdict in {"INSTALL", "CAUTION", "DO-NOT-INSTALL"}
    assert not any(f.status == UNKNOWN for f in _danger(p).findings), (
        "R1 now produces an UNKNOWN in the danger bucket — the residual is closed; "
        "delete this pin and assert the floor instead"
    )


# ── Controls: the distinction the check exists for must survive ─────────────────

def test_control_nothing_to_scan_stays_install(tmp_path, capsys):
    """B-092's distinction. A docs-only skill has nothing to scan — that is a
    legitimately clean result, not a coverage gap, and must keep its INSTALL. If this
    ever fails, the two UNKNOWN flavours have been collapsed into one and users are being
    punished for shipping prose."""
    sk = tmp_path / "docsonly"
    sk.mkdir()
    (sk / "SKILL.md").write_text(_FRONTMATTER.format(name="docsonly"), encoding="utf-8")
    (sk / "README.md").write_text("# Notes\n\nJust prose. No code at all.\n", encoding="utf-8")
    _assert_clean(capsys, sk)


def test_control_a_clean_readable_skill_stays_install(tmp_path, capsys):
    """The regression direction: byte-identical to R2 except the helper parses."""
    sk = _skill(tmp_path, "ctrl", {"scripts/helper.py": 'def hello():\n    return "world"\n'})
    p = _profile(sk)
    assert _danger(p).status == PASS
    assert p.overall_status == PASS
    _assert_clean(capsys, sk)


# ── The retired leg survives only as the documented unit-test fallback ──────────

def test_prose_leg_is_last_resort_only(tmp_path):
    """``_danger_coverage_gap``'s third leg still answers for a hand-built ``Finding``
    with no ``ctx`` and no flag (``tests/test_b092_coverage_gap.py``'s shape), and still
    stays quiet on a benign "nothing to scan" UNKNOWN — but it is no longer what any real
    producer depends on. Called directly on purpose: this leg is reachable ONLY from a
    unit test, which is the whole reason it is documented as a fallback."""
    from clawseccheck.catalog import Finding

    def _f(status, detail="", degraded=False):
        return Finding("B13", "t", "HIGH", status, detail, "fix", "fw", False,
                       engine_degraded=degraded)

    assert _danger_coverage_gap([_f(UNKNOWN, "... coverage is incomplete ...")], None) is True
    assert _danger_coverage_gap([_f(UNKNOWN, "no MCP servers configured")], None) is False
    assert _danger_coverage_gap([_f(PASS, "", degraded=True)], None) is False
    assert _danger_coverage_gap([], None) is False
