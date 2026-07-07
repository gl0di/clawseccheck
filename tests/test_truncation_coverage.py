"""B-074: silent truncation is a coverage blind spot. A skill padded with benign filler
past the per-skill byte/file cap used to have its tail (where a payload could hide) dropped
with zero disclosure — --vet returned a clean PASS. Now the cap hit is recorded in
ctx.limit_hits and check_installed_skills surfaces UNKNOWN (ranked above the WARN buckets),
never a clean PASS. Normal-size skills are unaffected.

Fixture sizes are computed from the real collector.py constants (not hardcoded) — this
cap has moved twice already (60KB -> 200KB -> 1MB, B-144 follow-ups) and hardcoded sizes
broke each time.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import vet_skill
from clawseccheck.collector import _MAX_BYTES_PER_SKILL, _MAX_FILE_BYTES

# Each fixture file must individually stay under _MAX_FILE_BYTES (else it's dropped
# whole by collect_skill_files before the per-skill budget/entropy-sampling logic ever
# sees it) while the SUM across files comfortably exceeds _MAX_BYTES_PER_SKILL.
_PER_FILE = min(_MAX_FILE_BYTES - 1, int(_MAX_BYTES_PER_SKILL * 0.75))


def _vet(files: dict) -> str:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "s"
        d.mkdir()
        (d / "SKILL.md").write_text("---\nname: s\ndescription: helper\n---\n# s\n", encoding="utf-8")
        for name, content in files.items():
            (d / name).write_text(content, encoding="utf-8")
        return vet_skill(str(d))


def test_skill_padded_past_text_cap_is_unknown_not_pass():
    # Benign filler exceeding the per-skill text cap; the tail is unscanned.
    line = "# a totally benign filler line repeated many times\n"
    pad = line * (int(_MAX_BYTES_PER_SKILL * 1.2 // len(line)) + 1)
    f = _vet({"big.md": pad})
    assert f.status == UNKNOWN
    assert "truncat" in f.detail.lower() or "cap" in f.detail.lower()


def test_normal_size_skill_stays_pass():
    f = _vet({"readme.md": "# hi\njust a small helper that formats text.\n"})
    assert f.status == PASS


# ---------------------------------------------------------------------------
# F-087: padding-anomaly evasion signal — a genuinely degenerate/uniform cut
# tail (not just "repetitive text with ordinary variety") escalates UNKNOWN to
# WARN; a real high-entropy oversized asset, or repetitive-but-varied prose
# (see test_skill_padded_past_text_cap_is_unknown_not_pass above), stays UNKNOWN.
# ---------------------------------------------------------------------------

def test_skill_padded_with_single_repeated_byte_warns():
    # the classic "omnicogg" shape: a single repeated character, far past the cap.
    # Split across TWO files (each under the per-file cap, _MAX_FILE_BYTES) so the
    # per-skill budget slices the SECOND file mid-way (giving the tail-entropy sampler
    # something to see) rather than the first file being dropped whole by the per-file
    # cap before the per-skill slicing logic ever runs.
    f = _vet({"aaa_first.md": "A" * _PER_FILE, "zzz_second.md": "A" * _PER_FILE})
    assert f.status == WARN
    assert "padding" in f.detail.lower() or "low-entropy" in f.detail.lower()
    assert "s" in f.evidence  # the fixture skill's own name ("s") — matches ctx.padding_anomalies


def test_skill_padded_with_repeated_symbol_warns():
    # A repeated dash run is another zero-variety filler shape (distinct from a
    # single repeated LETTER, covered above) — same low-entropy family, WARN.
    # NOTE: deliberately not an alternating-whitespace (" \n"*N) run — that shape
    # trips a separate, pre-existing pathological-regex slowdown elsewhere in the
    # content-ring scan (tracked as CLAWSECCHECK-B-100, not this task's concern).
    f = _vet({"aaa_first.md": "-" * _PER_FILE, "zzz_second.md": "-" * _PER_FILE})
    assert f.status == WARN


def test_skill_high_entropy_oversized_tail_stays_unknown():
    # A hex dump of random bytes (~4.0 bits/byte, well above the 3.0 threshold)
    # simulates high-entropy content with no evasion shape — must NOT WARN. (Uses
    # hex rather than base64: a giant base64 blob independently trips this
    # project's own hidden-payload decode signatures, which is a different,
    # unrelated check — not what this test is isolating.) Split across two files,
    # same reasoning as the low-entropy tests above — must exercise the per-skill
    # slice+entropy-sample path, not just the blunter per-file-cap drop.
    import os

    n = _PER_FILE // 2  # hex() doubles byte count back to _PER_FILE chars
    f = _vet({
        "aaa_first.md": os.urandom(n).hex(),
        "zzz_second.md": os.urandom(n).hex(),
    })
    assert f.status == UNKNOWN
    assert "padding" not in f.detail.lower()
