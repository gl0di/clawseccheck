# Hardening backlog

Tracked from the v0.17.1 internal code review (2026-06-20). None of these is a remote-exploitable
vulnerability — ClawSecCheck is local and read-only — they are defense-in-depth / honesty hardening.
Severity is relative to a security *tool's* own bar. Cross-referenced with [THREAT_COVERAGE.md](THREAT_COVERAGE.md).

## Code-review findings (existing code)

- [x] **H1 · should-fix · `clawseccheck/collector.py:103` — symlink-directory escape.**
  `_read_installed_skills` checks `sd.is_dir()` (which follows symlinks) but not `sd.is_symlink()`.
  A directory symlink under `skills/` (e.g. `evil -> /some/dir`) whose target holds a `SKILL.md`
  causes the tool to read text files outside the declared audit surface. The file-level guard in
  `_read_skill_text` does not stop directory-level entry.
  **Fix:** add `if sd.is_symlink(): continue` before the `sd.is_dir()` check. Test: symlinked skill
  dir is skipped.

- [x] **H2 · should-fix · report path — secret values not redacted in the report.**
  `logsafe.redact()` runs on log output only, never on the rendered report/`--save`/HTML/JSON.
  B1 is safe (it prints key *paths*, not values), but the B13 base64-decoded payload preview
  (`checks.py` ~740) can decode hostile content into a secret-shaped string (`sk-ant-…`) that then
  appears in `detail`/evidence unredacted.
  **Fix:** run `redact()` on decoded-payload previews before they enter evidence, or `redact()` the
  final report body before emit. Test: a skill whose base64 decodes to a secret-shaped string is
  redacted in the report.

- [x] **H3 · should-fix · `baseline.py` / `report.py` — silent suppression of CRITICAL.**
  Suppressing a finding drops it from the score *and* the default report, so a suppressed CRITICAL
  silently uncaps the score (F can become A) with no visible trace except `--show-suppressed`.
  There is also no reason/expiry on suppressions.
  **Fix:** always render a "Suppressed (still counts against trust)" section listing any suppressed
  HIGH/CRITICAL in the default report; optionally support `reason`/`expires` per entry. Test:
  suppressing a CRITICAL keeps it visible in the report and is flagged in the score explanation.

- [x] **H4 · nit · `clawseccheck/native.py:114` — non-zero exit swallowed.**
  `proc.returncode` is never checked; a non-zero exit from `openclaw security audit` with parseable
  JSON still yields status `"ok"`. **Fix:** surface the exit code in the note (and treat non-zero +
  no data as `error`).

- [x] **H5 · nit · `parse_bind_host` — IPv6 zone-id loopback false positive.**
  `::1%eth0` and link-local `fe80::…%zone` are classified as exposed (the LOOPBACK set has bare
  `::1`). **Fix:** strip `%zone` before classification and treat `::1`/`fe80::` accordingly.

- [x] **H6 · nit · `clawseccheck/collector.py` — no per-skill file-count cap.**
  Byte caps exist (`_MAX_BYTES_PER_SKILL`, `_MAX_FILE_BYTES`, `_MAX_SKILLS`) but a single skill with
  thousands of tiny files still iterates them all via `rglob`. **Fix:** add a file-count guard in the
  `_read_skill_text` loop.

**Verified safe (no action):** scanned skill text is never executed (regex-only); single subprocess
is fixed-argv, no `shell=True`, with timeout; no `eval`/`exec`/`pickle`/`os.system`/network anywhere;
stdlib-only; HTML output escaped after sanitize; sanitizer (`_sanitize`) has no found bypass;
`render_html` `private_body` is trusted static text; blocker fixes (BLK-01..04) correct; catalog ↔
implementation consistent; scoring caps (49/79) and grade bands correct.

## Code-review findings — 0.20.0/0.21.0 checkpoint (fixed in 0.21.1)

Adversarial review of the Host Watch (0.20.0) and Deeper-Vetting (0.21.0) code. All fixed in 0.21.1
with regression tests; the FP fixes are strictly detection-narrowing, so they cannot add a false FAIL.

- [x] **R1 · zero-FP · `skillast.py` — `GETATTR_INDIRECTION` crit-fired on ordinary dynamic dispatch.**
  `getattr(obj, runtime_name)()` (normal plugin dispatch) was flagged `crit` (FAIL). Now crit only for a
  dangerous attribute *literal* or a dynamic attr on a *dangerous module* (os/subprocess/…); ordinary
  dynamic dispatch is `info` (escalate-only).
- [x] **R2 · zero-FP · `checks.py` `_SKILL_INJECTION` — "hide-from-user"/"exfiltration" prose FP.**
  "Do not notify the user on every sync" / "never send your API key to a third party" raised HIGH FAIL.
  Now dual-use rules fire ONLY alongside a real cred/exfil signal; only the canonical
  "ignore previous instructions" fires standalone.
- [x] **R3 · robustness · `skillast.py` — "never raises" contract.** `_tainted_names` ran outside the
  try; `OverflowError` not caught. Wrapped; `_MAX_FINDINGS_PER_FILE` cap moved to loop top.
- [x] **R4 · robustness · `hostwatch.py` — corrupt plist + false macOS audit PASS.** `_alf_globalstate`
  now catches `struct.error`; macOS OpenBSM reports UNKNOWN (file presence ≠ enabled on <=13, deprecated
  on >=14) instead of a false PASS.
- [x] **R5 · hygiene · `cli.py` — `--vet-mcp` evidence + `--vet` detail not sanitized.** Attacker-
  controlled MCP/skill strings reached the terminal raw; now `_sanitize`-d (mirrors the `--vet` evidence).

**Verified safe (no action):** hostwatch executes nothing and makes no network call (`shutil.which` reads
PATH only); host checks can never return FAIL and never KeyError; RISK-10 fires only on positive
evidence (all four visibility classes `absent` + powerful agent); `skillast` is parse-only (no
compile/exec/eval/import of skill content); `_is_own_source` still exempts the scanner.

## Suggested order

1. **H1, H3, H2** — small, security/honesty-relevant → fold into a `0.17.2` patch with regression tests.
2. **H4–H6** — opportunistic, same patch.
3. **Coverage (phase 0.18.0):** ✅ **B26** (untrusted-context exposure via `contextVisibility`) and
   ✅ **B33** (known-vulnerable version gate) shipped in 0.18.0 wave 1. B27 (action-gate) / B28 (taint)
   have no OpenClaw config surface and are covered combinationally (risk engine + B21/B8/B22) — not
   shipped as redundant scored checks. Next waves: B29/B31 (reachability + effective-tools), B41/B42.

## Recommended issues to open

One GitHub issue per H-item and per roadmap gap (B26–B28 as one epic). These are intentionally kept
in-repo first rather than as public issues — promote to issues when ready to work them.
