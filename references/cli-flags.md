# ClawSecCheck — additional CLI flags

Less common but available flags. The everyday tool routing lives in `SKILL.md`
(the guided flow + "Natural-language to tool quick map"); these are the long tail,
kept here so the always-loaded playbook stays lean.

- `--ascii` — plain output for terminals that cannot render unicode (auto-detected).
- `--save PATH` — write the report to a local file.
- `--sarif PATH` — write a local SARIF 2.1.0 file (for CI / GitHub Code Scanning; never uploaded).
  Works with `--vet`/`--vet-mcp` too, as a side output alongside the human report.
- `--json` with `--vet`/`--vet-mcp` — emits a vetting JSON object (`mode`, `target`, `verdict`,
  `findings[]`). No score: vetting is not a scored audit. Exit code is 1 on SUSPICIOUS/DANGEROUS.
- `--fail-under N` — exit with code 1 if score is below N (useful for CI pipelines).
- `--exit-code` — exit 1 if any unsuppressed FAIL finding exists.
- `--verbose` / `--debug` / `--log PATH` — local logging with secret redaction.
- `--no-native` — skip the built-in `openclaw security audit` (for offline / hermetic testing).
- `--no-update-notice` — suppress the offline "your build may be stale" reminder
  (also via `CLAWSECCHECK_NO_UPDATE_NOTICE=1`). The reminder is offline-only — never a network call.
- `--verify-self` — print SHA-256 digest of ClawSecCheck's source files for tamper detection.
- `--show-suppressed` — list any findings the user has silenced via `.clawseccheckignore`.
- `--ask` — emit a JSON attestation template (the facts config can't show: real tool inventory,
  approval gating, host monitors). The running agent fills it from its own ground truth.
- `--attest PATH` — enrich the audit with that self-report; enables B43 (capability blast-radius)
  and B44 (self-report ⇄ config drift) at `ATTESTED` confidence. Read-only; introspection only.
- `--watch-log` — print the Agent Watch event journal (a local timeline of what changed across
  `--monitor` runs); `--events PATH` points it at a different journal file.

**Mode precedence.** Most flags above select a single mode; only one runs per invocation
(resolved in a fixed order, `--json` winning over `--card` on the default report path). If you
pass a second mode, or a modifier the chosen mode can't use (e.g. `--save` with `--fix`, or
`--exit-code` with `--sarif`), ClawSecCheck prints a `note: …` to **stderr** naming what was
ignored and continues — machine-readable stdout (`--json`/`--sarif`) stays clean. `--no-history`
is honored everywhere except `--trend`/`--monitor`, which record a score point as part of their job.
