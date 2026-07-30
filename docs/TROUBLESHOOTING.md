# ClawSecCheck — Troubleshooting

This page is for when **ClawSecCheck itself** is the problem — the command isn't found,
it crashes, OpenClaw never picks it up, or a scan hangs. If instead you're looking at a
grade, a finding, or output you don't understand, that's a question about *your audited
setup*, not the engine — see [FAQ.md](FAQ.md) instead.

---

## `clawseccheck: command not found`

This means the console script isn't on your `PATH` — usually because ClawSecCheck was
installed with plain `pip install` into an environment that isn't active, or because
`pipx`'s own bin directory isn't on `PATH` yet.

- Run it as a module instead — this works whenever the package is importable, console
  script or not:

  ```bash
  python3 -m clawseccheck --home ~/.openclaw
  ```

- If you used `pipx`, make sure its shims are on `PATH`:

  ```bash
  pipx ensurepath   # then open a new shell
  ```

- If you're running the bundled skill copy (installed by OpenClaw, not pip/pipx), there
  is no console script at all — invoke the script directly instead:

  ```bash
  python3 audit.py --home ~/.openclaw   # from inside the skill's own directory
  ```

## `ImportError` / `ModuleNotFoundError` after a manual install

ClawSecCheck has **zero third-party runtime dependencies** — Python's standard library
is all it needs. So an `ImportError` for anything other than a `clawseccheck` submodule
almost always means an incomplete or partial copy, not a missing dependency:

- Confirm the whole `clawseccheck/` package directory made it over — a partial `git
  clone`, a truncated archive extraction, or copying only some files under the OpenClaw
  skills directory will produce exactly this error.
- Confirm you're running Python from the directory that actually contains
  `clawseccheck/` (or that it's on `sys.path`) — a stray same-named file or a shell
  running from the wrong working directory is the next most common cause.
- Re-install from scratch rather than patching a partial copy — see
  [USAGE.md's install section](USAGE.md#install--run) for every supported install path.

## Wrong Python version

ClawSecCheck needs **Python 3.9 or newer**. `pip`/`pipx` enforce this automatically for
that install path — but the skill's actual install path (an unpacked copy under
OpenClaw's own skills directory) never goes through pip, so nothing stops it from being
run under an older interpreter that just happens to be the system default `python3`.

Recent releases fail fast with a plain one-line message (`clawseccheck: needs Python
3.9+ (found X.Y)`) instead of a confusing error somewhere deep in a module. If you don't
see that message and something still looks wrong on an older Python, that's itself a
sign the interpreter is too old — check with:

```bash
python3 --version
```

If it's below 3.9, point OpenClaw (or your own invocation) at a newer interpreter —
`python3.9`, `python3.11`, etc. — whatever your system provides alongside the default.

## OpenClaw doesn't list the skill, or never runs it

If asking your agent to audit your setup does nothing (no error, just silence), OpenClaw
likely never discovered the skill in the first place. Check, in order:

1. **The skill is actually unpacked where OpenClaw looks for skills.** OpenClaw reads
   installed skills from under its home, most commonly `~/.openclaw/workspace/skills/`
   — confirm the `clawseccheck` directory (containing `SKILL.md`, `audit.py`, and the
   `clawseccheck/` package) actually landed there, not somewhere else on disk.
2. **`SKILL.md` is present at the skill's root and has valid frontmatter.** It needs a
   `name:` and a `description:` field in the YAML front matter block at the top of the
   file at minimum — a truncated download or a copy that dropped the front matter will
   make the skill invisible to OpenClaw without necessarily producing an error you see.
3. **Re-run the install command** rather than debugging a half-finished copy:

   ```bash
   openclaw skills install @gl0di/clawseccheck     # from ClawHub
   openclaw skills install git:gl0di/clawseccheck  # or straight from GitHub
   ```

If the skill *is* listed but a specific invocation still does nothing, fall back to
running it directly from a terminal (see the sections above and below) — that isolates
whether the problem is ClawSecCheck or the surrounding OpenClaw session.

## The scan hangs, or is cut short

ClawSecCheck bounds its own runtime so a pathological input (a hostile skill, or just an
unlucky regex) degrades to an honest `UNKNOWN` instead of hanging forever: a generous
15-second budget per individual check, and a 120-second budget for a whole plain audit.
Deeper modes (`--vet` on a single target, a full `--vet-all` sweep, `--full`) carry their
own larger budgets for the same reason, since they read much more content.

If a run exceeds its budget, you'll see a plain message on stderr saying the scan was
cut short and that no verdict from that run is reliable — this is a bounded-input safety
net doing its job, not silent data loss. There is deliberately **no resume or checkpoint
mechanism** — the fix is to re-run narrower:

- Drop to `--fast` if you're running `--full` (skips the slower deep phases).
- Target a single skill or plugin with `--vet <path>` instead of a full sweep.
- Point `--home` at a smaller or more specific config location if you were scanning
  something unusually large.

If a *plain* audit (no flags) still hits its budget, that's unusual enough to be worth
reporting — see "Filing a good bug report" below, and include `--debug` output.

## Where the diagnostics live

- `--debug` — re-raises the real exception with its full traceback instead of the clean
  one-line message. This is the single most useful flag for figuring out what actually
  broke; include its output (redacted, see below) in any bug report.
- `--verbose` — INFO-level breadcrumbs on stderr, without needing a full traceback.
- `--log <path>` — also writes log output to a file, useful for a hang you want to
  inspect after the fact.
- `--verify-self` — prints a SHA-256 digest of ClawSecCheck's own source, so you can
  confirm the installed copy matches a trusted release. It only proves the copy wasn't
  casually tampered with; it does **not** prove the copy is bug-free, and a digest
  computed from a compromised copy can't be trusted on its own — see ["trust no
  one"](USAGE.md#important--trust-no-one-including-this-skill) in the user guide for how
  to verify it against a signed release checksum instead of just trusting the tool's own
  output.

## Filing a good bug report

Before you file, try `--debug` — it usually points straight at the cause. If it doesn't,
[open an issue](https://github.com/gl0di/clawseccheck/issues) with:

- The version: `clawseccheck --version` (or `python3 audit.py --version` for the bundled
  copy).
- The exact command you ran (flags and all).
- The full output of that command re-run with `--debug` added.
- Your OS and Python version (`python3 --version`).

**Please redact before pasting.** ClawSecCheck's own design never prints a raw exception
message or secret value to the terminal precisely because they can carry a path,
username, or config value — but a full traceback under `--debug` can still legitimately
include local file paths as part of the stack frames. Scan it yourself before posting,
and if you're also attaching `clawseccheck --json` output because a *finding* looks
wrong rather than the engine crashing, note that it redacts secret **values** but still
shows key names and paths — read it over before sharing either way.

---

*This page covers the engine failing. For a finding, a grade, or output you don't
understand, see [FAQ.md](FAQ.md) instead.*
