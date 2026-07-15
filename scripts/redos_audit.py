#!/usr/bin/env python3
"""Dev-only static ReDoS audit over every `re.compile(...)` literal in `clawseccheck/
checks/` (CLAWSECCHECK-C-214). Stdlib-only (`ast` + `re`), read-only, no network.

A security scanner whose own regex engine can be hung by a crafted input is itself an
attack surface (B-192 was instance #1 of this class, in the AST effect simulator, not
the regex layer — this closes the analogous gap for the ~290 `re.compile()` calls in
checks/, which had never been audited wholesale, only reactively point-fixed after a
specific bug (B100/B102) was found).

Two passes:

  1. STATIC shape heuristic — walks every checks/*.py file with `ast`, extracts every
     `re.compile(<string literal>, ...)` call's pattern text + file:line, and flags
     patterns containing a classically ReDoS-prone SHAPE: a quantified group that
     itself contains a quantifier ((X+)+, (X*)*, (X+)*, (X*)+), or an alternation
     inside a quantified group where both branches can match the same character
     ((a|a)+-style ambiguity). This is a heuristic, not a proof — plenty of flagged
     shapes turn out fine once you look at the actual literal characters involved
     (this script's own report says so explicitly; do not treat "flagged" as "broken").

  2. EMPIRICAL confirmation — for every flagged pattern, actually run it against a
     handful of adversarial strings built from characters that appear in the pattern
     itself (so the stress input is plausible for THAT regex, not generic filler),
     each wrapped in a hard wall-clock budget via signal.alarm. A pattern that blows
     the budget is REPORTED, not touched — this script never edits a regex; fixing a
     confirmed hit is a separate, deliberate follow-up (same "test-only" doctrine as
     the rest of C-214).

Usage:
    python3 scripts/redos_audit.py                  # full audit, both passes
    python3 scripts/redos_audit.py --static-only     # pass 1 only (fast)
"""
from __future__ import annotations

import argparse
import ast
import re
import signal
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKS_DIR = REPO_ROOT / "clawseccheck" / "checks"

# Per-candidate empirical timeout. Generous relative to any legitimate regex on a
# short crafted string (which should return in microseconds) but short enough that
# a genuinely catastrophic pattern is caught fast and the whole audit stays snappy.
_EMPIRICAL_TIMEOUT_S = 1.0
_STRESS_LENGTHS = (20, 30, 40)


_RE_FLAG_NAMES = {"I", "IGNORECASE", "M", "MULTILINE", "S", "DOTALL", "X", "VERBOSE",
                  "A", "ASCII", "U", "UNICODE"}


@dataclass
class Candidate:
    file: str
    line: int
    pattern: str
    flags: int = 0


class _TimeoutError(Exception):
    pass


def _alarm_handler(signum, frame):  # noqa: ARG001
    raise _TimeoutError()


def _flag_value(expr: ast.AST) -> int:
    """Resolve a `re.X` / `re.X | re.Y | ...` flags expression to its real int value via
    getattr(re, name) -- never eval() -- so e.g. re.VERBOSE actually behaves like
    re.VERBOSE in the empirical check below (VERBOSE in particular changes matching
    semantics completely: whitespace/comments in the pattern become literal instead of
    ignored, so skipping this would silently test a DIFFERENT regex than the real one)."""
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.BitOr):
        return _flag_value(expr.left) | _flag_value(expr.right)
    if isinstance(expr, ast.Attribute) and expr.attr in _RE_FLAG_NAMES:
        return int(getattr(re, expr.attr, 0))
    if isinstance(expr, ast.Name) and expr.id in _RE_FLAG_NAMES:
        return int(getattr(re, expr.id, 0))
    return 0  # unresolvable (e.g. a variable) -- fall back to no flags, not a crash


def _extract_candidates(path: Path) -> list[Candidate]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, ValueError):
        return []
    out: list[Candidate] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr != "compile":
            continue
        if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "re"):
            continue
        if not node.args:
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            continue  # dynamically-built pattern -- can't statically extract, skip
        flags = 0
        if len(node.args) > 1:
            flags = _flag_value(node.args[1])
        for kw in node.keywords:
            if kw.arg == "flags":
                flags = _flag_value(kw.value)
        out.append(Candidate(file=str(path.relative_to(REPO_ROOT)), line=node.lineno,
                              pattern=first.value, flags=flags))
    return out


# Nested-quantifier shapes: a quantified group containing another quantifier one level
# in. Deliberately simple (no full regex parser) -- a heuristic pre-filter, not a proof.
_NESTED_QUANT_RE = re.compile(
    r"\([^()]*[+*][^()]*\)[+*]"      # (...+...)+  or  (...*...)*  etc, one level deep
    r"|\([^()]*\)\{[0-9,]+\}[+*]"    # (...){m,n}+ style double-quantification
)
# Alternation with overlapping single-char branches inside a quantified group, e.g.
# (a|a)+ or (a|ab)* -- a classic ambiguous-alternation ReDoS shape.
_AMBIGUOUS_ALT_RE = re.compile(r"\([^()|]{0,3}\|[^()]{0,3}\)[+*]")


def _looks_redos_prone(pattern: str) -> bool:
    return bool(_NESTED_QUANT_RE.search(pattern) or _AMBIGUOUS_ALT_RE.search(pattern))


def _stress_strings(pattern: str) -> list[str]:
    """Build a few adversarial strings out of characters that actually appear in the
    pattern's literal alphabet (falls back to a generic set), each a long run of a
    repeated char followed by one guaranteed non-match char to force backtracking."""
    literal_chars = sorted({c for c in pattern if c.isalnum()})[:4] or ["a", "0"]
    strings = []
    for ch in literal_chars:
        for n in _STRESS_LENGTHS:
            strings.append(ch * n + "\x00")  # NUL rarely matches anything meaningful
    # Line-oriented variant: a pattern with a literal "\n" in its source is very likely
    # scanning multi-line text (frontmatter blocks, fenced code, etc.) — the single-char
    # repeats above never contain a newline at all, so they can't stress that shape.
    # Many short non-matching "lines" with no closing delimiter is the natural adversarial
    # input for that case (mirrors an attacker-supplied SKILL.md with no closing '---').
    if "\\n" in pattern:
        for n in (200, 2000, 20000):
            strings.append("x\n" * n)
    return strings


def _empirical_check(pattern: str, flags: int = 0) -> tuple[bool, float, str | None]:
    """Returns (blew_budget, worst_elapsed_seconds, worst_input_repr).

    Recompiles WITH the candidate's own real flags (e.g. re.VERBOSE) — VERBOSE in
    particular changes matching semantics completely (whitespace/comments in the
    pattern become literal instead of ignored), so testing without it would silently
    stress a DIFFERENT regex than the one that actually ships.
    """
    try:
        compiled = re.compile(pattern, flags)
    except re.error:
        return False, 0.0, None  # pattern didn't even compile standalone -- not our problem here
    worst_elapsed = 0.0
    worst_input = None
    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    try:
        for s in _stress_strings(pattern):
            signal.setitimer(signal.ITIMER_REAL, _EMPIRICAL_TIMEOUT_S)
            start = time.monotonic()
            try:
                compiled.search(s)
                elapsed = time.monotonic() - start
            except _TimeoutError:
                elapsed = _EMPIRICAL_TIMEOUT_S
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
            if elapsed > worst_elapsed:
                worst_elapsed = elapsed
                worst_input = f"{s[0]!r}*{len(s) - 1}+NUL"
            if elapsed >= _EMPIRICAL_TIMEOUT_S:
                return True, elapsed, worst_input
    finally:
        signal.signal(signal.SIGALRM, old_handler)
    return False, worst_elapsed, worst_input


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--static-only", action="store_true", help="skip the empirical confirmation pass")
    args = ap.parse_args()

    all_candidates: list[Candidate] = []
    for f in sorted(CHECKS_DIR.glob("*.py")):
        all_candidates.extend(_extract_candidates(f))

    print(f"Extracted {len(all_candidates)} re.compile(<literal>) call site(s) from {CHECKS_DIR}.\n")

    flagged = [c for c in all_candidates if _looks_redos_prone(c.pattern)]
    print(f"=== Pass 1 (static shape heuristic): {len(flagged)}/{len(all_candidates)} flagged ===")
    for c in flagged:
        print(f"  {c.file}:{c.line}  {c.pattern[:90]!r}")
    print()

    if args.static_only:
        return 0

    print(f"=== Pass 2 (empirical, {_EMPIRICAL_TIMEOUT_S}s budget per candidate) ===")
    confirmed = []
    for c in flagged:
        blew, elapsed, worst_input = _empirical_check(c.pattern, c.flags)
        verdict = "CONFIRMED HANG" if blew else f"clean ({elapsed * 1000:.1f}ms worst-case)"
        print(f"  {c.file}:{c.line}  {verdict}" + (f"  input={worst_input}" if blew else ""))
        if blew:
            confirmed.append(c)

    print()
    if confirmed:
        print(f"{len(confirmed)} pattern(s) CONFIRMED to hang on a crafted input:")
        for c in confirmed:
            print(f"  {c.file}:{c.line}  {c.pattern!r}")
        print("\nNot fixed here (test-only doctrine) -- file a follow-up per pattern.")
    else:
        print("0 confirmed hangs. All statically-flagged shapes were empirically clean on "
              "the stress inputs tried here (a heuristic pre-filter over-flags more than it "
              "misses, by design) -- see RESULTS.md for what this does and does not prove.")
    return 1 if confirmed else 0


if __name__ == "__main__":
    raise SystemExit(main())
