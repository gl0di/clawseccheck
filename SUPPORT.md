# Support

Where to go depends on what you're reporting — routing this correctly *before*
you post matters, especially if a reproduction case would otherwise involve
pasting a real secret.

| What you have | Where it goes |
|---|---|
| A lying PASS, a bypass, or a way to evade a specific check | **Private** — [GitHub Security Advisories](https://github.com/gl0di/clawseccheck/security/advisories/new). See [SECURITY.md](SECURITY.md). Never a public thread. |
| An attack class or check idea we don't cover yet | [Discussions](https://github.com/gl0di/clawseccheck/discussions) — this is a capability gap, not a vulnerability. |
| A clean config/skill that got flagged | [Discussions → False positive](https://github.com/gl0di/clawseccheck/discussions) — false alarms are treated seriously, but they aren't a security report. |
| A crash, traceback, or a broken flag | [Issues](https://github.com/gl0di/clawseccheck/issues). |
| Usage questions | [Discussions](https://github.com/gl0di/clawseccheck/discussions) or the [User guide](docs/USAGE.md) / [FAQ](docs/FAQ.md). |

## Never paste secrets

Discussions and issues are **public and indexed**. Never paste real secrets,
API keys, tokens, passwords, or other credentials in a thread — redact all
sensitive values first. If a reproduction needs a config file, replace secret
values with placeholders such as `<REDACTED>` or `sk-XXXX`.

## Before you post

- Check [Troubleshooting](docs/TROUBLESHOOTING.md) if the tool itself won't
  run or crashes.
- Include your ClawSecCheck version (`clawseccheck --version`), OpenClaw
  version, OS, and the relevant `--json` output (secret *values* are already
  redacted in that output — read it before posting regardless).

See [CONTRIBUTING.md](https://github.com/gl0di/clawseccheck/blob/main/CONTRIBUTING.md)
for the full contribution and PR workflow.
