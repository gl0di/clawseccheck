#!/usr/bin/env python3
"""Dev-only performance-refactor equivalence check over the fixtures/ corpus.
Stdlib-only, read-only, no network.

Refactors of the normalization pipeline (translate-table merges, ASCII fast-paths,
per-blob memoization, and similar) are claimed to be semantically identity-preserving
-- this script is the empirical check on that claim, run over the WHOLE shipped
fixture corpus rather than trusting a refactor's own unit tests alone (the same
"independent verification" spirit as scripts/redos_audit.py).

Usage:
    # snapshot before editing:
    python3 scripts/perf_equivalence.py --dump /tmp/before.json

    # snapshot after editing:
    python3 scripts/perf_equivalence.py --dump /tmp/after.json

    # compare the two snapshots:
    python3 scripts/perf_equivalence.py --diff /tmp/before.json /tmp/after.json

No switch, no env var, no branch in shipped code -- this tool drives the SAME
`audit()` + `render_json()` path the CLI's --json flag does (fully offline:
include_native=False, include_host=False, the audit() defaults), over every
top-level fixtures/* home directory, and records sha256(render_json bytes) per
fixture. Any diff between two snapshots means something changed that fixture's
observable output -- if the change under test was meant to be a no-op refactor,
that is a hard stop, not something to paper over.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from clawseccheck import audit, render_json  # noqa: E402
from clawseccheck.baseline import load_ignore  # noqa: E402
from clawseccheck.risk import risk_paths  # noqa: E402

FIXTURES_DIR = REPO_ROOT / "fixtures"


def _corpus() -> list[Path]:
    """Every top-level fixtures/* home directory (mirrors the convention already
    used by tests/test_fp_corpus.py and tests/test_b315_unscored_never_fails.py).
    Excludes `__pycache__` -- a pytest-generated artifact from importing
    fixtures/conftest.py, not a fixture, and its presence/absence is an accident of
    whether a test session already ran, which would otherwise make two snapshots
    spuriously disagree on fixture-set membership rather than on any real content."""
    return sorted(
        d for d in FIXTURES_DIR.iterdir()
        if d.is_dir() and not d.name.startswith(".") and d.name != "__pycache__"
    )


def _render(home: Path) -> str:
    """Run the same pipeline `clawseccheck --json` does over *home*."""
    ctx, findings, score = audit(home)
    ignore = load_ignore(home)
    paths = [p for p in risk_paths(ctx, findings, ignore=ignore) if not p.suppressed]
    return render_json(findings, score, risk=paths, ctx=ctx)


def _dump(out_path: Path) -> None:
    homes = _corpus()
    fixtures: dict[str, str] = {}
    errors: dict[str, str] = {}
    for home in homes:
        name = home.name
        try:
            body = _render(home)
        except Exception as exc:  # noqa: BLE001 -- record per-fixture, don't abort the sweep
            errors[name] = f"{type(exc).__name__}: {exc}"
            continue
        fixtures[name] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    payload = {"count": len(homes), "fixtures": fixtures, "errors": errors}
    out_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Dumped {len(fixtures)} fixture hash(es), {len(errors)} error(s), "
          f"{len(homes)} home(s) total, to {out_path}")


def _diff(before_path: Path, after_path: Path) -> int:
    before = json.loads(before_path.read_text(encoding="utf-8"))
    after = json.loads(after_path.read_text(encoding="utf-8"))
    before_hashes, after_hashes = before.get("fixtures", {}), after.get("fixtures", {})
    before_errors, after_errors = before.get("errors", {}), after.get("errors", {})

    def _state(name: str, hashes: dict, errs: dict) -> str:
        if name in hashes:
            return hashes[name]
        if name in errs:
            return f"ERROR:{errs[name]}"
        return "MISSING"

    all_names = sorted(
        set(before_hashes) | set(after_hashes) | set(before_errors) | set(after_errors)
    )
    diffs = []
    for name in all_names:
        b = _state(name, before_hashes, before_errors)
        a = _state(name, after_hashes, after_errors)
        if b != a:
            diffs.append((name, b, a))

    print(f"Compared {len(all_names)} fixture(s): {len(diffs)} difference(s).")
    for name, b, a in diffs:
        print(f"  DIFF {name}: before={b[:20]} after={a[:20]}")
    return 1 if diffs else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--dump", metavar="FILE",
        help="run the corpus and write sha256(render_json) per fixture to FILE",
    )
    group.add_argument(
        "--diff", metavar=("BEFORE", "AFTER"), nargs=2,
        help="compare two --dump snapshots and report every fixture that differs",
    )
    args = ap.parse_args()

    if args.dump:
        _dump(Path(args.dump))
        return 0

    before_path, after_path = args.diff
    return _diff(Path(before_path), Path(after_path))


if __name__ == "__main__":
    raise SystemExit(main())
