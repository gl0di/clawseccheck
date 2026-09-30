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
* R1 a raising ring check (any axis, not just danger) — was silently swallowed with no
  finding at all, now floors the headline; see the CLOSED section below for the history.
* P1-P4 (C-634) the same class through ``--vet-plugin``: loose plugin Python that is over
  the 2 MB scan cap (P1), unparseable (P2) or unreadable (P3) - was INSTALL / Danger PASS /
  rc 0 (a padded ``exec`` loader walked straight through an install gate), must be CAUTION
  / Danger UNKNOWN / rc 1; P4 is the ``--json`` surface agreeing. The fixtures use a VALID
  manifest so no unrelated Build WARN can carry the verdict on its own.
* Control A: a skill with genuinely nothing to scan stays INSTALL (B-092's distinction —
  "nothing to scan" is a legitimately clean result and must not be swallowed).
* Control B: a clean, fully-readable skill stays INSTALL (the regression direction).

## R1's history (closed)

R1 — a ring check that raises is swallowed by ``_run_content_ring``'s bare ``except``,
producing no finding at all — stayed a KNOWN, UNCLOSED residual through two prior
attempts:

1. 2026-08-08 (``f3c7025``): routed through ``note_limit()`` directly and RETRACTED. At
   the time ``_danger_coverage_gap`` had only the two legs described above, so ANY
   disclosure here forced ``CAUTION`` unconditionally — a benign skill whose only script
   used a ``match`` statement (3.10+) read ``INSTALL`` on 3.12 but ``CAUTION`` on the 3.9
   CI floor, with "no narrow variant" able to tell "unparseable because hostile" apart
   from "unparseable because newer than the scanner".
2. 2026-08-14 (``3fe2554``): closed the *reported* route (B13's own parse-error branch,
   R2 above) by keying on ``Finding.engine_degraded`` instead — but left this ring-level
   ``except`` exactly as retracted, because an empty bucket carries no flag for that leg
   to read either. A hand-built ring check that raises a bare ``RuntimeError`` (no parse
   involved, so B13 has no coincident reason to also flag it) proved the overall verdict
   could still read ``INSTALL``/PASS with a crashed check and zero disclosure.
3. This change closes it: the crash is folded into the SAME ``coverage_gap_finding()`` /
   ``note_limit()`` disclosure R2 and R6 already use (no second channel), which is
   already ``engine_degraded=True`` and already routed to the *danger* bucket by
   ``dossier._AXIS_BY_ID`` on purpose. That makes the 2026-08-08 objection apply again in
   principle (a crash on ANY axis now floors the headline unconditionally, same as a
   parse error does) — but the objection's own conclusion has since been superseded, not
   avoided: ``3fe2554`` already accepted the identical version-skew shape for B13 as
   BOUNDED (the gap can only withhold a clean verdict, never manufacture
   ``DO-NOT-INSTALL`` — see ``test_version_skew_on_a_modern_syntax_skill_is_bounded`` in
   ``test_b485_vet_coverage_gap.py``), and this fix produces the exact same bounded shape
   for a ring-check crash. What does NOT close here: the crashed check's own axis line
   (e.g. "Behavior: PASS") still reads clean — only the headline is floored, because
   danger is still the only axis with a coverage-gap lever, and giving every axis one is
   a separate, undecided change.

Stdlib-only, offline, writes only under pytest's ``tmp_path``.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import vet_plugin, vet_skill
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


# ── R1: closed — a raising ring check now floors the headline ───────────────────
#
# History (kept, not deleted — see the module docstring's "R1's history" section for
# the two prior attempts): this test used to be named ...is_still_an_open_residual and
# asserted the ABSENCE of a fix ("must not produce an UNKNOWN in the danger bucket").
# It now asserts the fix's presence, through the real CLI entry points, the same way
# R2–R7 above do.

def test_r1_a_raising_ring_check_now_floors_the_headline(tmp_path, capsys, monkeypatch):
    """``_run_content_ring``'s bare ``except Exception: continue`` used to swallow a
    raising ring check with no finding, no ``note_limit`` and no ``skipped`` entry — an
    empty bucket no predicate could see, on ANY axis (not only danger, unlike R2–R6).
    Proven via a bare ``RuntimeError`` rather than the one natural trigger
    (``ScriptProseCoverageIncomplete``) specifically because it has NO coincident B13
    parse failure to lean on — this is the case that showed the overall verdict, not
    just one axis line, could still read clean.
    """
    from clawseccheck.checks import _vet as vet_mod

    def _explode(ctx):
        raise RuntimeError("ring check blew up")

    ring = list(vet_mod.SKILL_CONTENT_RING)
    assert ring, "the content ring is empty; this test would be vacuous"
    monkeypatch.setattr(vet_mod, "SKILL_CONTENT_RING", [_explode] + ring[1:])

    sk = _skill(tmp_path, "r1", {"scripts/ok.py": "x = 1\n"})
    p = _profile(sk)                     # must not raise — the bare except still holds
    danger_unknowns = [f for f in _danger(p).findings if f.status == UNKNOWN]
    assert danger_unknowns, (
        "R1 regressed — a raising ring check produced no UNKNOWN in the danger bucket "
        "again; the bare except in _run_content_ring is silent"
    )
    assert danger_unknowns[0].engine_degraded is True
    assert "raised an unexpected error" in (danger_unknowns[0].detail or "")
    assert p.verdict == "CAUTION"
    assert p.overall_status == WARN
    _assert_floored(capsys, sk)


def test_r1_crash_is_bounded_never_do_not_install(tmp_path, monkeypatch):
    """The same bound B-092/B-485 hold everywhere else: a coverage gap may only WITHHOLD
    a clean verdict, never manufacture a DO-NOT-INSTALL. A crash alone must read
    CAUTION, not the FAIL-equivalent — matching the precedent this fix relies on
    (``test_version_skew_on_a_modern_syntax_skill_is_bounded`` in
    ``test_b485_vet_coverage_gap.py``)."""
    from clawseccheck.checks import _vet as vet_mod

    def _explode(ctx):
        raise RuntimeError("ring check blew up")

    ring = list(vet_mod.SKILL_CONTENT_RING)
    monkeypatch.setattr(vet_mod, "SKILL_CONTENT_RING", [_explode] + ring[1:])

    sk = _skill(tmp_path, "r1bound", {"scripts/ok.py": "x = 1\n"})
    p = _profile(sk)
    assert p.verdict == "CAUTION"
    assert p.overall_status == WARN


def test_r1_a_hostile_ring_check_still_cannot_crash_vet(tmp_path, monkeypatch):
    """The bare ``except`` contract this fix must not weaken: a ring check raising
    something exotic (not just ``RuntimeError``) still degrades to a disclosure, never
    an unhandled exception reaching the caller."""
    from clawseccheck.checks import _vet as vet_mod

    class _Exotic(Exception):
        pass

    def _explode(ctx):
        raise _Exotic("still not allowed to break --vet")

    ring = list(vet_mod.SKILL_CONTENT_RING)
    monkeypatch.setattr(vet_mod, "SKILL_CONTENT_RING", [_explode] + ring[1:])

    sk = _skill(tmp_path, "r1hostile", {"scripts/ok.py": "x = 1\n"})
    p = _profile(sk)                     # must not raise
    assert p.verdict == "CAUTION"


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


# -- P1-P4 (C-634): loose plugin Python the Danger pass could not read -----------------
#
# `vet_plugin`'s tree sweep recorded a loose plugin `.py` it could not read, parse or fit
# under the scan cap in `unanalysed_code` and a `coverage:` note - neither of which moves
# the verdict - so padding the shipped `bad_b13_fetch_to_exec` loader past 2 MB (or making
# it unparseable) turned DO-NOT-INSTALL into INSTALL / Danger PASS / rc 0. Every fixture
# here uses a VALID manifest: an invalid one draws an unrelated Build WARN that alone makes
# `status != PASS` true, which is why the B-636 disclosure tests never saw this bug.

_REPO = Path(__file__).resolve().parent.parent
_LOADER = (_REPO / "fixtures" / "bad_b13_fetch_to_exec" / "skills" / "bootstrap-helper"
           / "scripts" / "post_install.py")
_BENIGN_PY = (
    "import json\n"
    "import pathlib\n\n\n"
    "def main():\n"
    '    target = pathlib.Path(__file__).with_name("settings.json")\n'
    '    target.write_text(json.dumps({"theme": "light"}))\n'
)
_UNPARSEABLE_PY = 'print "py2"\nexec "danger"\n'
_PLUGIN_SKILL_MD = (
    "---\nname: text-tool\ndescription: Formats text.\n---\n\n"
    "# text-tool\n\nFormats text locally. No network access, no shell.\n"
)


def _plugin(tmp_path: Path, name: str, files: dict | None = None) -> Path:
    """A plugin with a VALID manifest, one clean bundled skill and optional loose files."""
    root = tmp_path / name
    root.mkdir(parents=True)
    (root / "openclaw.plugin.json").write_text(
        json.dumps({
            "id": "demo",
            "configSchema": {"type": "object", "additionalProperties": False},
            "skills": ["skills"],
        }),
        encoding="utf-8",
    )
    skill = root / "skills" / "text-tool"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(_PLUGIN_SKILL_MD, encoding="utf-8")
    for rel, body in (files or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return root


def _plugin_profile(root: Path):
    return build_profile(vet_plugin(str(root)), str(root), "plugin")


def _plugin_cli(capsys, flag: str, root: Path) -> tuple[int, str]:
    rc = main([flag, str(root), "--ascii"])
    return rc, capsys.readouterr().out


def _assert_plugin_floored(capsys, root: Path) -> None:
    """--vet-plugin AND --advise must say CAUTION and exit 1 for this plugin."""
    rc, out = _plugin_cli(capsys, "--vet-plugin", root)
    assert rc == 1, out
    assert "CAUTION" in out, out
    assert "INSTALL" not in out.replace("DO-NOT-INSTALL", ""), out

    rc_a, out_a = _plugin_cli(capsys, "--advise", root)
    assert rc_a == 1, out_a
    assert "CAUTION" in out_a, out_a
    assert "this looks safe to install" not in out_a, out_a


def _assert_plugin_clean(capsys, root: Path) -> None:
    rc, out = _plugin_cli(capsys, "--vet-plugin", root)
    assert rc == 0, out
    assert "INSTALL" in out and "DO-NOT-INSTALL" not in out, out
    assert "CAUTION" not in out, out

    rc_a, out_a = _plugin_cli(capsys, "--advise", root)
    assert rc_a == 0, out_a
    assert "this looks safe to install" in out_a, out_a


def _py_gaps(f) -> list:
    """The C-634 sub-findings: B13 UNKNOWN naming unread plugin Python."""
    return [r for r in f.ring_findings
            if r.id == "B13" and r.status == UNKNOWN
            and "could not analyze plugin Python" in (r.detail or "")]


def _padded_loader() -> str:
    from clawseccheck.checks._mcp import _PLUGIN_PY_MAX_BYTES

    return _LOADER.read_text(encoding="utf-8") + "# pad\n" * (_PLUGIN_PY_MAX_BYTES // 6 + 1000)


def _assert_gap_profile(root: Path, reason: str) -> None:
    """Shared P1-P3 assertions on the structured profile, not only the rendered text."""
    f = vet_plugin(str(root))
    gaps = _py_gaps(f)
    assert len(gaps) == 1, [(r.id, r.status, r.detail) for r in f.ring_findings]
    assert gaps[0].engine_degraded is True
    assert "run.py" in gaps[0].detail and reason in gaps[0].detail
    # The remediation prose lives in `fix`, never `detail` (fingerprint() hashes detail).
    assert "Inspect the flagged file(s) manually" in gaps[0].fix
    assert "Inspect the flagged" not in gaps[0].detail
    assert getattr(f, "unanalysed_code", None) == ["run.py"]

    p = build_profile(f, str(root), "plugin")
    assert _danger(p).status == UNKNOWN
    assert p.overall_status == WARN
    assert p.verdict == "CAUTION"


def test_plugin_fixture_pieces_are_what_the_cases_below_assume():
    """Non-vacuity: the loader really is a loader, and the padding really crosses the cap."""
    from clawseccheck.checks._mcp import _PLUGIN_PY_MAX_BYTES

    body = _LOADER.read_text(encoding="utf-8")
    assert "urlopen" in body and "exec(compile(" in body
    assert len(_padded_loader().encode("utf-8")) > _PLUGIN_PY_MAX_BYTES


def test_c1_a_valid_manifest_plugin_with_no_python_is_install(tmp_path, capsys):
    """The control that makes every case below mean something: with no Python at all this
    exact fixture is INSTALL / Danger PASS / rc 0, so a CAUTION further down can only come
    from the Python file, not from the manifest."""
    root = _plugin(tmp_path, "c1")
    assert _danger(_plugin_profile(root)).status == PASS
    _assert_plugin_clean(capsys, root)


def test_c2_a_benign_parseable_loose_python_file_stays_install(tmp_path, capsys):
    """The false-UNKNOWN control: byte-identical to P2 except the file parses."""
    root = _plugin(tmp_path, "c2", {"run.py": _BENIGN_PY})
    f = vet_plugin(str(root))
    assert _py_gaps(f) == []
    assert getattr(f, "unanalysed_code", None) == []
    assert _danger(build_profile(f, str(root), "plugin")).status == PASS
    _assert_plugin_clean(capsys, root)


def test_c3_the_loader_under_the_cap_convicts_so_the_padding_is_what_hides_it(tmp_path,
                                                                                 capsys):
    """Non-vacuity for P1: the same loader, trimmed to fit under the cap, is
    DO-NOT-INSTALL. The bug is that the pad alone turned that into INSTALL."""
    from clawseccheck.checks._mcp import _PLUGIN_PY_MAX_BYTES

    body = _LOADER.read_text(encoding="utf-8") + "# pad\n" * 1000
    assert len(body.encode("utf-8")) < _PLUGIN_PY_MAX_BYTES
    root = _plugin(tmp_path, "c3", {"run.py": body})
    p = _plugin_profile(root)
    assert _danger(p).status == FAIL
    assert p.verdict == "DO-NOT-INSTALL"
    rc, out = _plugin_cli(capsys, "--vet-plugin", root)
    assert rc == 1 and "DO-NOT-INSTALL" in out, out


def test_p1_an_oversized_loose_plugin_python_file_floors_the_headline(tmp_path, capsys):
    """The reported route: pad the loader past 2 MB. Was INSTALL / Danger PASS / rc 0."""
    root = _plugin(tmp_path, "p1", {"run.py": _padded_loader()})
    from clawseccheck.checks._mcp import _PLUGIN_PY_MAX_BYTES
    assert (root / "run.py").stat().st_size > _PLUGIN_PY_MAX_BYTES, "control: over the cap"

    _assert_gap_profile(root, "scan cap")
    _assert_plugin_floored(capsys, root)


def test_p2_an_unparseable_loose_plugin_python_file_floors_the_headline(tmp_path, capsys):
    root = _plugin(tmp_path, "p2", {"run.py": _UNPARSEABLE_PY})
    _assert_gap_profile(root, "could not parse")
    _assert_plugin_floored(capsys, root)


def test_p3_an_unreadable_loose_plugin_python_file_floors_the_headline(
    tmp_path, capsys, monkeypatch
):
    """Root-proof: the read is made to fail deterministically rather than via chmod 000
    (which root ignores, forcing a skip that would leave this route unpinned in CI images
    that run as root)."""
    root = _plugin(tmp_path, "p3", {"run.py": _BENIGN_PY})
    real_read_text = Path.read_text

    def _read_text(self, *a, **kw):
        if self.name == "run.py":
            raise PermissionError(13, "denied", str(self))
        return real_read_text(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", _read_text)
    _assert_gap_profile(root, "could not be read")
    _assert_plugin_floored(capsys, root)


def test_p4_json_verdict_agrees_with_the_text_dossier(tmp_path, capsys):
    root = _plugin(tmp_path, "p4", {"run.py": _UNPARSEABLE_PY})
    rc = main(["--vet-plugin", str(root), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert data["verdict"] == "CAUTION"


def test_a_plugin_python_gap_alone_is_bounded_never_do_not_install(tmp_path):
    """A gap may only WITHHOLD a clean verdict, never manufacture a conviction: the same
    bound `test_r1_crash_is_bounded_never_do_not_install` holds for the skill path."""
    for name, body in (("bound-py2", _UNPARSEABLE_PY), ("bound-big", _padded_loader())):
        root = _plugin(tmp_path, name, {"run.py": body})
        f = vet_plugin(str(root))
        assert f.status != FAIL, (name, f.status)
        p = build_profile(f, str(root), "plugin")
        assert p.verdict == "CAUTION", (name, p.verdict)
        assert _danger(p).status == UNKNOWN, name


def test_a_real_conviction_still_wins_over_an_unreadable_sibling(tmp_path, capsys):
    """An UNKNOWN sibling must not downgrade a FAIL: loader at install.py + unparseable
    other.py stays DO-NOT-INSTALL with Danger FAIL."""
    root = _plugin(tmp_path, "mixed-fail", {
        "install.py": _LOADER.read_text(encoding="utf-8"),
        "other.py": _UNPARSEABLE_PY,
    })
    f = vet_plugin(str(root))
    assert len(_py_gaps(f)) == 1, "the gap is still reported alongside the conviction"
    p = build_profile(f, str(root), "plugin")
    assert _danger(p).status == FAIL
    assert p.verdict == "DO-NOT-INSTALL"
    rc, out = _plugin_cli(capsys, "--vet-plugin", root)
    assert rc == 1 and "DO-NOT-INSTALL" in out, out


def test_a_gap_and_a_js_warn_signal_still_read_caution_with_the_gap_present(tmp_path):
    """Mixed: the UNKNOWN rides along in ring_findings next to a WARN-level JS signal."""
    root = _plugin(tmp_path, "mixed-warn", {
        "run.py": _UNPARSEABLE_PY,
        "index.js": "const m = require(process.env.PLUGIN_MODULE);\n",
    })
    f = vet_plugin(str(root))
    assert len(_py_gaps(f)) == 1, [(r.id, r.status) for r in f.ring_findings]
    assert any("runtime JS/TS" in e for e in (f.evidence or [])), f.evidence
    p = build_profile(f, str(root), "plugin")
    assert p.verdict == "CAUTION"


def test_p2_does_not_read_as_a_truncated_scan(tmp_path, capsys):
    """Why this is a B13 UNKNOWN and not a VET-COVERAGE finding: a per-file gap is not a
    truncation, so the Persistence / Connections wording must stay the B-628 "no reader
    for it" text (tests/test_b628_plugin_code_measurable.py::test_i)."""
    root = _plugin(tmp_path, "p2wording", {"run.py": _UNPARSEABLE_PY})
    f = vet_plugin(str(root))
    assert [r for r in f.ring_findings if r.id == "VET-COVERAGE"] == []
    rc, out = _plugin_cli(capsys, "--vet-plugin", root)
    assert rc == 1
    assert "has no reader for" in out, out
    assert "did not cover the whole target" not in out, out


def test_exactly_at_the_cap_is_analysed_and_one_byte_over_is_a_gap(tmp_path, monkeypatch):
    """`>` not `>=`: a file of exactly the cap is read; one more byte is not."""
    monkeypatch.setattr("clawseccheck.checks._mcp._PLUGIN_PY_MAX_BYTES", 1000)
    at_cap = "x = 1\n" + "#" * (1000 - len("x = 1\n") - 1) + "\n"
    assert len(at_cap.encode("utf-8")) == 1000

    ok = _plugin(tmp_path, "atcap", {"run.py": at_cap})
    f_ok = vet_plugin(str(ok))
    assert _py_gaps(f_ok) == [] and getattr(f_ok, "unanalysed_code", None) == []

    over = _plugin(tmp_path, "overcap", {"run.py": at_cap + "#"})
    f_over = vet_plugin(str(over))
    assert len(_py_gaps(f_over)) == 1
    assert getattr(f_over, "unanalysed_code", None) == ["run.py"]


def test_files_the_sweep_never_opens_are_not_gaps(tmp_path):
    """A `.py` symlink and a `.py` under node_modules are skipped by the walk on purpose;
    neither may turn into an unread-code finding."""
    outside = tmp_path / "outside.py"
    outside.write_text(_UNPARSEABLE_PY, encoding="utf-8")
    root = _plugin(tmp_path, "skipped", {"node_modules/dep/index.py": _UNPARSEABLE_PY})
    (root / "link.py").symlink_to(outside)
    f = vet_plugin(str(root))
    assert _py_gaps(f) == []
    assert getattr(f, "unanalysed_code", None) == []
    assert _danger(build_profile(f, str(root), "plugin")).status == PASS


def test_unparseable_python_inside_a_bundled_skill_is_not_double_counted(tmp_path):
    """That branch is dispatched to vet_skill (which already emits its own B13 UNKNOWN);
    the loose-Python finding must not stack a second one on top."""
    root = _plugin(tmp_path, "inside", {"skills/text-tool/scripts/helper.py": _UNPARSEABLE_PY})
    f = vet_plugin(str(root))
    assert _py_gaps(f) == []
    assert getattr(f, "unanalysed_code", None) == []
    assert any(r.id == "B13" and r.status == UNKNOWN and "parse error" in (r.detail or "")
               for r in f.ring_findings), [(r.id, r.status, r.detail) for r in f.ring_findings]


def test_a_split_payload_behind_an_oversized_file_is_never_danger_pass(tmp_path):
    """The small parseable stub execs a sibling the scan cannot read: whatever the stub's
    own verdict, Danger must not be PASS."""
    root = _plugin(tmp_path, "split", {
        "stub.py": 'exec(open("big.py").read())\n',
        "big.py": _padded_loader(),
    })
    p = _plugin_profile(root)
    assert _danger(p).status != PASS
    assert p.verdict != "INSTALL"


def _budget_starved_at_the_loose_python_read(monkeypatch) -> None:
    """Report the CPU budget exhausted exactly when the sweep is about to read `run.py`.

    Keyed on the caller's own state rather than a call count, so an unrelated extra
    `cpu_exceeded` call added to the sweep cannot silently move the trip point: the
    per-file Python branch is the only call site with `fp.name == "run.py"` and an empty
    `gap`. Once tripped it stays exhausted, like a real deadline.
    """
    import sys

    state = {"tripped": False}

    def _exceeded(deadline):
        if state["tripped"]:
            return True
        loc = sys._getframe(1).f_locals
        fp = loc.get("fp")
        if fp is not None and fp.name == "run.py" and loc.get("gap") == "":
            state["tripped"] = True
        return state["tripped"]

    monkeypatch.setattr("clawseccheck.checks._mcp.cpu_exceeded", _exceeded)


def test_a_budget_cut_python_file_is_reported_once_not_twice(tmp_path, monkeypatch):
    """The budget gap already rides `budget_hit`'s VET-COVERAGE finding; it must not also
    grow a B13 UNKNOWN naming the same fact."""
    root = _plugin(tmp_path, "budget-before", {"run.py": _BENIGN_PY})
    _budget_starved_at_the_loose_python_read(monkeypatch)
    f = vet_plugin(str(root))

    assert any("scan budget was reached before it was read" in e for e in (f.evidence or [])), \
        f.evidence
    assert len([r for r in f.ring_findings if r.id == "VET-COVERAGE"]) == 1
    assert _py_gaps(f) == []
    assert _danger(build_profile(f, str(root), "plugin")).status == UNKNOWN


def test_a_budget_exceeded_mid_analysis_is_reported_once_not_twice(tmp_path, monkeypatch):
    """The other budget phrase: ScanBudgetExceeded raised by the AST pass itself."""
    from clawseccheck import skillast
    from clawseccheck.scanbudget import ScanBudgetExceeded

    real = skillast.analyze_python

    def _analyze(source, rel, *a, **kw):
        if rel == "run.py":
            raise ScanBudgetExceeded
        return real(source, rel, *a, **kw)

    monkeypatch.setattr(skillast, "analyze_python", _analyze)
    root = _plugin(tmp_path, "budget-while", {"run.py": _BENIGN_PY})
    f = vet_plugin(str(root))

    assert any("scan budget was reached while it was being read" in e
               for e in (f.evidence or [])), f.evidence
    assert len([r for r in f.ring_findings if r.id == "VET-COVERAGE"]) == 1
    assert _py_gaps(f) == []


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
