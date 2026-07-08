"""C-171 (LOW): two bookkeeping/reporting bugs in decompress_and_classify() —
neither touches the actual archive-safety GUARDS (path-traversal, symlink-not-
followed, per-file/total/file-count/ratio caps), which all still enforce the same
limits; only the reporting/reachability around them is fixed here.

(1) Dead-code expansion-ratio check in the gzip/bz2/xz branches: the
    `if compressed_size > 10240: ratio = ...` block used to be nested INSIDE the
    preceding cumulative-size `if ...: ... return` block, after its unconditional
    `return` — making it unreachable. It is now a sibling `if`, matching the
    already-correct ZIP/TAR branches.

(2) A symlink/hardlink member inside a tar archive used to be dropped via
    `if not member.isreg(): continue` with zero trace — unlike a symlink sitting
    directly in a skill directory, which walk_dir_safely() records into
    ctx.symlink_skips and is surfaced as a WARN via the B13 vet check
    ("symlink / path-escape not followed: ..."). Tar-embedded symlink members
    are now recorded into ctx.symlink_skips the same way.
"""
from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import tarfile
from pathlib import Path

import pytest

from clawseccheck.catalog import WARN
from clawseccheck.checks import vet_skill
from clawseccheck.collector import (
    _ARCHIVE_MAX_EXPANSION_RATIO,
    _ARCHIVE_MAX_FILE_BYTES,
    _ARCHIVE_MAX_TOTAL_BYTES,
    Context,
    collect_skill_files,
    decompress_and_classify,
)

# ---------------------------------------------------------------------------
# (1) expansion-ratio check reachability for gzip / bz2 / xz
# ---------------------------------------------------------------------------

_COMPRESSORS = {
    "gzip": gzip.compress,
    "bz2": bz2.compress,
    "xz": lzma.compress,
}


@pytest.mark.parametrize("fmt", ["gzip", "bz2", "xz"])
def test_ratio_check_fires_for_single_shot_formats_without_tripping_byte_caps(fmt):
    """Craft a case that is only over the expansion-ratio cap (>100x), while both
    absolute byte caps (per-file 1,000,000 / total 20,000,000) stay comfortably
    unbroken — so only the (previously dead) ratio check can be what catches it.

    Because a single gzip/bz2/xz stream's own decompressed payload is capped at
    _ARCHIVE_MAX_FILE_BYTES, on its own it can never mathematically clear the
    ratio threshold against a compressed_size just over the 10240-byte gate (that
    would need decompressed content in excess of the file-size cap). So this
    pre-seeds archive_stats["cumulative_decompressed_size"] to simulate prior
    sibling members already having accumulated size within the SAME archive family
    (exactly how the ZIP/TAR loops naturally build up cumulative across multiple
    members) — a legitimate, minimal way to exercise this level's own ratio
    branch in isolation.
    """
    # Incompressible payload -> compressed_size stays close to the payload size,
    # comfortably over the 10240-byte gate, while this level's own decompressed
    # contribution (10500 bytes) is tiny compared to either byte cap.
    payload = os.urandom(10500)
    compressed = _COMPRESSORS[fmt](payload)
    assert len(compressed) > 10240

    # Pre-seed cumulative so that, once this level's small decompressed payload is
    # added, the ratio (cumulative / this level's compressed_size) clears the
    # >100x threshold, while the running total stays far under the 20MB cap.
    preseed = int(_ARCHIVE_MAX_EXPANSION_RATIO * len(compressed) * 1.2)
    assert preseed + len(payload) < _ARCHIVE_MAX_TOTAL_BYTES
    assert len(payload) < _ARCHIVE_MAX_FILE_BYTES

    archive_stats = {
        "total_files_count": 0,
        "cumulative_decompressed_size": preseed,
        "compressed_size": len(compressed),
    }

    ctx = Context(home=Path("/nonexistent"))
    decompress_and_classify(ctx, Path("/nonexistent"), compressed, f"payload.{fmt}", depth=1, archive_stats=archive_stats)

    assert any("expansion ratio" in hit for hit in ctx.limit_hits), (
        f"ratio check for {fmt} did not fire; limit_hits={ctx.limit_hits}"
    )
    assert ctx.file_manifest.get(f"payload.{fmt}") == "capped(ratio)"
    # Confirm neither absolute byte cap is what caught it (that would mask the bug).
    assert not any("Max file decompressed size" in hit for hit in ctx.limit_hits)
    assert not any("Max cumulative size" in hit for hit in ctx.limit_hits)


# ---------------------------------------------------------------------------
# (2) tar-embedded symlink member disclosure
# ---------------------------------------------------------------------------


def _make_tar_with_symlink(tmp_path: Path, name: str) -> Path:
    archive_path = tmp_path / f"{name}.tar"
    with tarfile.open(archive_path, mode="w") as tf:
        skill_md = b"---\nname: %b\ndescription: test\n---\nhello\n" % name.encode()
        info = tarfile.TarInfo(name="SKILL.md")
        info.size = len(skill_md)
        tf.addfile(info, io.BytesIO(skill_md))

        real_body = b"print('hi')\n"
        info2 = tarfile.TarInfo(name="real.py")
        info2.size = len(real_body)
        tf.addfile(info2, io.BytesIO(real_body))

        link_info = tarfile.TarInfo(name="link_to_secret.py")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "/etc/passwd"
        tf.addfile(link_info)
    return archive_path


def test_tar_symlink_member_recorded_in_symlink_skips(tmp_path):
    archive = _make_tar_with_symlink(tmp_path, "with_symlink")

    ctx = Context(home=tmp_path)
    collect_skill_files(archive, ctx)

    assert ctx.symlink_skips, "tar-embedded symlink member was dropped with no audit trace"
    assert any("link_to_secret.py" in entry and "/etc/passwd" in entry for entry in ctx.symlink_skips)


def test_vet_discloses_archive_symlink_member_not_directory_only(tmp_path):
    """The B13 'symlink / path-escape not followed' warning must fire for an archive
    target too, not only for symlinks found while walking a plain directory."""
    archive = _make_tar_with_symlink(tmp_path, "vet_with_symlink")

    f = vet_skill(archive)
    assert f.status == WARN, f"expected WARN, got {f.status}: {f.detail}"
    assert "symlink" in f.detail.lower()
