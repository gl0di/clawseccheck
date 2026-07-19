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
- a regenerated `docs/CHECKS.md` (`python3 scripts/gen_checks_docs.py --write`).

## Pull requests

- Target `main`. CI (tests on 3.9/3.12, ruff, markdownlint, secret scan) must
  be green; review is required to merge.
- **Conventional Commits**: `feat: …`, `fix: …`, `docs: …`, `test: …`,
  `security: …`, `refactor: …`, `ci: …`. Subject in English, imperative,
  concise; the body explains *why* when it isn't obvious.
- Keep commits atomic; update the affected docs in the same PR (docs must never
  lag the code they describe).

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
