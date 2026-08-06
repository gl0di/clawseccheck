# Contributing to ClawSecCheck

Thanks for helping make OpenClaw setups safer. This project has a few hard
rules that make contributions easy to accept — please read them first.

## Ground rules (non-negotiable)

- **Local-only, forever.** No network calls, no telemetry, no phone-home.
  Everything the tool reads and writes stays on the user's machine.
- **Read-only by default.** The tool inspects; it never mutates the user's
  OpenClaw setup.
- **Zero runtime dependencies.** Pure Python standard library, Python 3.9+.
  `pytest`/`ruff` are dev-only tools, never imports.
- **No secrets in source** — not in code, tests, or fixtures. Test values that
  must look like secrets are assembled at runtime from fragments.
- **No fabricated facts.** Every OpenClaw config field path a check reads must
  exist in the real OpenClaw schema. When a check can't determine state, it
  reports `UNKNOWN` — never a guessed PASS/FAIL.

## Dev setup

```bash
git clone https://github.com/gl0di/clawseccheck
cd clawseccheck
python3 -m pip install pytest ruff   # the package itself has zero deps
```

## Tests and lint

```bash
python3 -m pytest -q     # full suite — 100% pass required, no skips
ruff check .             # must be clean
```

Tests are **offline and read-only**: no network, nothing written outside
pytest's `tmp_path`. CI runs the suite on Python 3.9 and 3.12, plus
markdownlint (`markdownlint-cli@0.44.0`) over the docs.

## Adding or changing a check

Read [docs/CHECK_AUTHORING.md](docs/CHECK_AUTHORING.md) first. In short, every
check needs:

- a `CheckMeta` entry in the catalog (one entry per check ID — an ID, once
  shipped, keeps its meaning),
- a **clean fixture** (the finding must not fire) and a **bad fixture** (it
  must), plus explicit `UNKNOWN`-path coverage,
- zero false-positive FAILs on realistic configs — precision is this project's
  reputation; a noisy check will not be merged,
- if the check reads a **new** OpenClaw config `dig()` path, a matching entry
  in `tests/grounded_schema_paths.txt` — `test_dig_paths_match_shipped_manifest`
  in `tests/test_schema_grounding.py` runs unconditionally (no recon
  dependency) and hard-fails an ungrounded path,
- a regenerated `docs/CHECKS.md` (`python3 scripts/gen_checks_docs.py --write`).

## Pull requests

- Target `main`. CI (tests on 3.9/3.12, ruff, markdownlint, secret scan) must
  be green; review is required to merge.
- **Two more CI checks, in a `commit-integrity` job, hard-fail a PR
  (`.github/workflows/ci.yml`) — know them before you push:**
  - **No AI co-author trailers.** It greps your commit range for a
    `Co-authored-by:` line naming an AI tool (Claude, Anthropic, Cursor,
    Copilot, Aider, Codeium) and exits 1 if one is found. Using an AI tool to
    help write a commit is fine; just don't leave its co-author trailer in
    the message — reword the commit (`git commit --amend`, or an interactive
    rebase for an older commit) to drop the trailer, then push again.
  - **No agent config files in the tree.** It fails if `CLAUDE.md`,
    `CLAUDE.local.md`, `.claude`, `.cursorrules`, `.cursor`, `.aider`, or
    `.copilot` is tracked by git. Add the file to `.gitignore` and
    `git rm --cached` it, then push again.
- **Conventional Commits**: `feat: …`, `fix: …`, `docs: …`, `test: …`,
  `security: …`, `refactor: …`, `ci: …`. Subject in English, imperative,
  concise; the body explains *why* when it isn't obvious.
- Keep commits atomic; update the affected docs in the same PR (docs must never
  lag the code they describe).
- **First-time contributors sign a CLA** — one comment on your PR, once, for all
  future contributions. See below for what it means.

## Contributor License Agreement

Your first pull request will get a bot comment asking you to sign
[CLA.md](CLA.md) by replying with a single sentence. It takes a moment and you
only ever do it once.

Being upfront about why, because a contributor should know before signing rather
than discover it later:

- **ClawSecCheck is and stays MIT.** Your contribution ships in the free, open
  tool under the same licence as everything else here.
- **You keep your copyright.** The CLA is a licence, not an assignment — your own
  code remains yours to use anywhere else.
- **The maintainer may also use contributions in commercial products** built on
  this engine, without asking again. That is the substantive term, and it is the
  reason the agreement exists at all.

If that trade isn't for you, please don't sign — [open an
issue](https://github.com/gl0di/clawseccheck/issues) instead. A precise bug
report or a reproduction case is a genuinely valuable contribution and needs no
agreement whatsoever.

The project's name and logo are separate from its code and are not covered by
the MIT licence — see [TRADEMARK.md](TRADEMARK.md).

## Reporting issues

- **Bugs / false positives / false negatives:**
  [open an issue](https://github.com/gl0di/clawseccheck/issues) with your
  ClawSecCheck version, OpenClaw version, OS, and the relevant `--json` output.
  Secret *values* are redacted in that output, but read it before posting and
  never paste raw secrets.
- **Security vulnerabilities:** privately, per [SECURITY.md](SECURITY.md) —
  not in a public issue.

## Releases

Maintainer-only; the protocol lives in [docs/RELEASING.md](docs/RELEASING.md).
