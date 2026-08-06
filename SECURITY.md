# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest release | Fully supported |
| Previous minor release | Critical security fixes only |
| Older releases | Unsupported — please update (`openclaw skills update clawseccheck`) |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities — use one of
the private channels below so the issue can be assessed and patched before public
disclosure.

**Preferred:** [GitHub Security Advisories](https://github.com/gl0di/clawseccheck/security/advisories/new)
(private, coordinated disclosure).

**Alternative:** email the maintainer at `gllodi@gmail.com`.

### What to include

- ClawSecCheck version (`clawseccheck --version`).
- Python version and OS.
- A clear description of the vulnerability and its impact.
- Steps to reproduce or a minimal proof-of-concept.

### What NOT to include

**Do not paste real secrets, API keys, tokens, passwords, or other credentials** in
issue reports, advisory drafts, or email. Redact all sensitive values before sharing.
If reproduction requires a config file, replace secret values with placeholders such
as `<REDACTED>` or `sk-XXXX`.

## Scope

ClawSecCheck is a **local, read-only** audit tool. Its read scope is bounded and
documented: your OpenClaw config, bootstrap markdown, installed-skill text, OpenClaw log
files and agent session logs, the ClawHub CLI's own token-store path outside the OpenClaw
home (B182, credential-hygiene check), and three default-on scans, each individually
disabled with its own flag: a host-posture scan beyond OpenClaw's own scope (`--no-host`:
security-tool config paths and binaries on `PATH`, the text of a few known firewall config
files, the names of proxy-shaped env vars, and on Windows read-only
`HKEY_LOCAL_MACHINE` registry queries), a socket scan (`--no-sockets`: `/proc/net/tcp{,6}`
and a read-only `/proc/*/fd` walk), and an npm dependency-tree walk (`--no-deptree`:
`node_modules` under the installed OpenClaw package, outside the OpenClaw home —
manifests and install-time targets only, nothing executed). `SKILL.md` and
[`SECURITY_MODEL.md`](SECURITY_MODEL.md) list the full surface. It writes only its own
state under `~/.clawseccheck/` — by default a one-line score-history entry (opt out with
`--no-history`), and other files only when you ask (`--save`, `--badge`, `--html`,
`--sarif`, `--pdf`, `--monitor`, `--log`). The one named exception, opt-in and
confirmation-gated: `--apply-ignore-proposals` appends previously-proposed entries to
`<home>/.clawseccheckignore` inside the audited OpenClaw home. Otherwise it never writes
to your OpenClaw config, and it makes no network calls. Findings stay on your machine.

For the full breakdown of the tool's own capability surface, least-privilege posture,
data-handling/redaction discipline, tamper-evident audit trail, and the forward-looking
policy for any future fix/apply mode, see [`SECURITY_MODEL.md`](SECURITY_MODEL.md).

In-scope issues include:

- Logic bugs that produce false PASS results for genuinely unsafe configs.
- Output channels that could be exploited for prompt injection (the text report,
  `--json`, `--sarif`, `--html`, `--pdf`) — anywhere untrusted config or skill content
  reaches a reader without being sanitized as quoted evidence.
- Any code path that reads, writes, or executes more than the documented scope.
- Dependency or supply-chain issues in the publish workflow.

Out of scope:

- Vulnerabilities in OpenClaw itself (report those to the OpenClaw project).
- Issues only reproducible by a malicious local user who already has filesystem access.

## Response timeline

We aim to acknowledge reports within 5 business days and to release a patch within 30
days for confirmed issues. Complex issues may take longer; we will communicate delays.

## Pre-release hygiene

The full maintainer release checklist (tests, doc alignment, dependency review,
signed release assets) lives in [`docs/RELEASING.md`](docs/RELEASING.md). It
exists to prevent release drift — code, docs, and operational security guidance
must always describe the same shipped behavior.
