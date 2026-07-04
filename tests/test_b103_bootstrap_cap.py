"""B-103: bootstrap files must be read with a size cap.

An uncapped `read_text` on AGENTS.md/SOUL.md/… let a huge (or maliciously padded)
bootstrap file load whole into memory and turned the B58 quadratic regex from
"bounded by cap" into genuinely unbounded. The bootstrap read now mirrors the
skill-path cap: at most `_MAX_FILE_BYTES` per file, streamed (never over-allocated),
with a `limit_hit` recorded so downstream checks surface UNKNOWN rather than
silently scan a clipped file.
"""
from __future__ import annotations

from clawseccheck.collector import _MAX_FILE_BYTES, collect


def test_oversized_bootstrap_is_capped_and_flagged(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text("A" * (_MAX_FILE_BYTES + 50_000), encoding="utf-8")

    ctx = collect(tmp_path)

    assert "AGENTS.md" in ctx.bootstrap
    assert len(ctx.bootstrap["AGENTS.md"]) == _MAX_FILE_BYTES  # sliced to the cap
    assert any("AGENTS.md" in h for h in ctx.limit_hits)


def test_small_bootstrap_read_fully_no_limit_hit(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}", encoding="utf-8")
    (tmp_path / "SOUL.md").write_text("hello soul", encoding="utf-8")

    ctx = collect(tmp_path)

    assert ctx.bootstrap["SOUL.md"] == "hello soul"
    assert not any("SOUL.md" in h for h in ctx.limit_hits)
