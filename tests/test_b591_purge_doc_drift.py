"""B-591: `_PURGE_FILENAMES` and docs/USAGE.md's purge scope sentence must never drift apart.

`_PURGE_FILENAMES` (clawseccheck/cli.py) grew from the original four store files to eight
when F-162 deliberately added the four default-named report renderer outputs to the
whitelist (see that constant's own comment) — but `--help`, `_run_purge`'s docstring, and
docs/USAGE.md's "Uninstall / cleanup" section kept saying "four" and promising that
"anything else you keep under that path is untouched". That promise was false for a report
saved at ClawSecCheck's own default filename: `--purge --yes` deleted it silently, and no
test caught the drift because none compared the whitelist to the doc's prose. This does.

Offline, read-only, stdlib only — reads the shipped docs/USAGE.md and clawseccheck/cli.py
source text; writes nothing.
"""
from __future__ import annotations

import re
from pathlib import Path

from clawseccheck.cli import _PURGE_FILENAMES

REPO = Path(__file__).resolve().parents[1]
USAGE = REPO / "docs" / "USAGE.md"
CLI_SOURCE = Path(__file__).resolve().parents[1] / "clawseccheck" / "cli.py"

# The "Uninstall / cleanup" paragraph in docs/USAGE.md that enumerates exactly what --purge
# touches. Bounded start/end anchors so a rewrite that keeps the same shape still matches.
_SCOPE_START = "only ever touches its own known files"
_SCOPE_END = "lock sidecars"


def _extract_scope_filenames(text: str) -> "set[str]":
    """Pull every backtick-quoted `name.ext` between the scope sentence's start/end anchors."""
    start = text.index(_SCOPE_START)
    end = text.index(_SCOPE_END, start)
    window = text[start:end]
    return set(re.findall(r"`([\w.-]+\.\w+)`", window))


def test_purge_filenames_match_usage_doc_scope_sentence():
    """The whitelist and USAGE.md's enumerated file list must be exactly the same set."""
    documented = _extract_scope_filenames(USAGE.read_text(encoding="utf-8"))
    assert documented == set(_PURGE_FILENAMES), (
        f"docs/USAGE.md's purge scope sentence lists {sorted(documented)} but "
        f"_PURGE_FILENAMES is {sorted(_PURGE_FILENAMES)} — re-ground one to match the "
        f"other (B-591)."
    )


def test_purge_doc_drift_guard_bites_when_they_disagree():
    """Prove the comparison actually catches a mismatch, not just a vacuous pass.

    Reproduces the exact historical bug (docs enumerating only the original four store
    files) and the mirror case (code silently dropping a name docs still promise).
    """
    documented = _extract_scope_filenames(USAGE.read_text(encoding="utf-8"))
    real = set(_PURGE_FILENAMES)
    assert documented == real  # sanity: the two agree right now (previous test proves it)

    stale_four_only = documented - {
        "openclaw-security-badge.svg", "openclaw-security-report.html",
        "openclaw-security-report.sarif", "openclaw-security-report.pdf",
    }
    assert stale_four_only != real, "guard failed to notice docs undershooting the whitelist"

    narrowed_code = real - {"coverage.json"}
    assert narrowed_code != documented, "guard failed to notice code undershooting the docs"


def test_no_stale_four_file_claim_survives_in_cli_source():
    """Regression pin for the exact stale phrases the independent verification found."""
    source = CLI_SOURCE.read_text(encoding="utf-8")
    assert "all four known files" not in source
    assert (
        'help="delete ClawSecCheck\'s local store (history/events/state/coverage '
        'files + their lock sidecars) and exit — confirmation-gated unless '
        '--yes is also given; nothing else is touched")'
    ) not in source
