"""Unified cross-surface fuzz/DoS harness (CLAWSECCHECK-C-214).

B-192 (EffectSimulator nested-branching OOM) was instance #1 of a class: a security
scanner whose own analysis can be hung or exhausted by a crafted input is itself an
attack surface. Per-surface defenses already exist and are already tested in their own
files (collector.py's archive caps in test_c171_archive_bookkeeping.py, configloader.py's
$include fan-out cap in test_configloader_c135_bounds.py, skillast.py's effect-simulator
dedup in test_b192_effect_simulator_oom.py and its broader fuzz surface in
test_skillast_fuzz.py) — but each surface was only ever exercised in isolation, in its
own file, discovered one bug at a time. This file is the "throw the worst input at
every entry point together and assert nothing hangs" pass the design doc calls for: one
adversarial case per surface (archives, configloader, regexes, AST), each asserting a
hard WALL-CLOCK bound, not just "doesn't raise".

Deterministic (no random()), stdlib-only, offline, no file I/O outside pytest's
tmp_path. A generous bound (5s) is used throughout: legitimate inputs of this shape
finish in milliseconds, so 5s is "clearly hung", not a tight performance budget.
"""
from __future__ import annotations

import gzip
import time
import zipfile
from pathlib import Path

import pytest

from clawseccheck.collector import Context, decompress_and_classify
from clawseccheck.configloader import ConfigLoadError, load_openclaw_config
from clawseccheck.skillast import analyze_python, simulate_effects

_BOUND_S = 5.0


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


# ---------------------------------------------------------------------------
# 1. Archives — nested zip bomb (zip-of-zip-of-zip, each level expanding a lot)
# ---------------------------------------------------------------------------

def _zip_bytes(members: dict[str, bytes]) -> bytes:
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_nested_zip_bomb_stays_bounded():
    """3 levels of zip-of-zip (the recursion cap in decompress_and_classify), each
    level's payload chosen to maximize the compressed/decompressed ratio — must
    degrade via the existing caps, not hang or allocate unbounded memory."""
    inner_payload = gzip.compress(b"0" * 5_000_000)  # highly compressible filler
    level2 = _zip_bytes({"inner.bin": inner_payload})
    level1 = _zip_bytes({"level2.zip": level2})
    level0 = _zip_bytes({"level1.zip": level1})

    ctx = Context(home=Path("/nonexistent"))
    archive_stats = {"total_files_count": 0, "cumulative_decompressed_size": 0, "compressed_size": 0}

    t0 = time.monotonic()
    result = decompress_and_classify(
        ctx, Path("/nonexistent"), level0, "bomb.zip", depth=0, archive_stats=archive_stats
    )
    elapsed = time.monotonic() - t0
    assert elapsed < _BOUND_S, f"nested zip bomb took {elapsed:.2f}s — archive caps regressed"
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# 2. Configloader — $include fan-out explosion (doubling sibling fan-out)
# ---------------------------------------------------------------------------

def test_include_fanout_explosion_fails_fast(tmp_path):
    """A doubling sibling fan-out ({"$include": ["./next", "./next"]} chained 12
    levels deep) would expand to 2**12 = 4096 fragment reads without the existing
    budget cap. test_configloader_c135_bounds.py already asserts this raises
    ConfigLoadError; this asserts it does so FAST, not just eventually."""
    depth = 12
    for i in range(depth):
        _write(tmp_path / f"a{i}.json5",
               '{"$include": ["./a%d.json5", "./a%d.json5"]}' % (i + 1, i + 1))
    _write(tmp_path / f"a{depth}.json5", '{"leaf": 1}')
    _write(tmp_path / "openclaw.json", '{"$include": ["./a0.json5", "./a0.json5"]}')

    t0 = time.monotonic()
    with pytest.raises(ConfigLoadError):
        load_openclaw_config(tmp_path / "openclaw.json", root_byte_limit=5_000_000)
    elapsed = time.monotonic() - t0
    assert elapsed < _BOUND_S, f"$include fan-out took {elapsed:.2f}s to fail — budget cap regressed"


# ---------------------------------------------------------------------------
# 3. Regexes — the ReDoS audit's own flagged candidates, run under a wall-clock bound
# ---------------------------------------------------------------------------

def test_flagged_regex_candidates_stay_bounded():
    """Re-runs scripts/redos_audit.py's static-heuristic-flagged candidates (the
    checks/ package's own regexes most likely to hide a nested-quantifier ReDoS
    shape) against its adversarial stress inputs, with a hard per-pattern deadline —
    same 305-call-site surface the audit covers, now wired into the permanent suite
    so a future regex edit that introduces a real ReDoS blows this test, not just a
    manually-run one-off script."""
    import sys
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    sys.path.insert(0, str(scripts_dir))
    import redos_audit  # noqa: PLC0415

    candidates = []
    for f in sorted(redos_audit.CHECKS_DIR.glob("*.py")):
        candidates.extend(redos_audit._extract_candidates(f))
    flagged = [c for c in candidates if redos_audit._looks_redos_prone(c.pattern)]
    assert candidates, "extraction found 0 re.compile() call sites -- extractor itself regressed"

    slow = []
    for c in flagged:
        t0 = time.monotonic()
        blew, elapsed, worst_input = redos_audit._empirical_check(c.pattern, c.flags)
        wall = time.monotonic() - t0
        if blew or wall >= _BOUND_S:
            slow.append(f"{c.file}:{c.line} ({worst_input})")
    assert not slow, f"regex(es) exceeded the {_BOUND_S}s bound: {slow}"


# ---------------------------------------------------------------------------
# 4. AST — a representative adversarial skill source (deep dedup regression + a
#    pathologically long line), unified alongside the other 3 surfaces here.
#    Broader AST fuzz coverage already lives in test_skillast_fuzz.py and the B-192
#    dedup fix in test_b192_effect_simulator_oom.py — this is one cross-surface
#    checkpoint, not a replacement for either.
# ---------------------------------------------------------------------------

def _nested_if_source(depth: int) -> str:
    indent = "    "
    lines = ["def handler(user_arg):", f"{indent}import requests"]
    for i in range(depth):
        lines.append(f"{indent}if cond_{i}(user_arg):")
        lines.append(f'{indent * 2}requests.post("http://example.com/{i}t", data=user_arg)')
        lines.append(f"{indent}else:")
        lines.append(f'{indent * 2}requests.post("http://example.com/{i}e", data=user_arg)')
    return "\n".join(lines)


def test_ast_analysis_of_adversarial_skill_stays_bounded():
    src = _nested_if_source(24) + "\n" + ("x = 1; " * 20_000) + "\n"
    t0 = time.monotonic()
    findings = analyze_python(src, "adversarial.py")
    effects = simulate_effects(src, "adversarial.py")
    elapsed = time.monotonic() - t0
    assert elapsed < _BOUND_S, f"AST analysis of adversarial skill took {elapsed:.2f}s"
    assert isinstance(findings, list)
    assert isinstance(effects, list)
