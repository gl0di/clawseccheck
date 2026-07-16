<p align="center">
  <img src="docs/assets/banner.png" alt="ClawSecCheck — local, read-only security audit for your OpenClaw agent" width="820">
</p>

<p align="center">
  <b>Find out how safe your OpenClaw agent really is — in one command, without a single byte leaving your machine.</b><br>
  <sub><i>The claw that checks your claws.</i></sub>
</p>

<p align="center">
  <a href="https://github.com/gl0di/clawseccheck/releases"><img src="https://img.shields.io/github/v/tag/gl0di/clawseccheck?label=version&color=E34234&labelColor=2b2b2b" alt="version"></a>
  <a href="https://github.com/gl0di/clawseccheck/actions/workflows/ci.yml"><img src="https://github.com/gl0di/clawseccheck/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://clawhub.ai/gl0di/clawseccheck"><img src="https://img.shields.io/badge/ClawHub-clawseccheck-FF6B47?labelColor=2b2b2b" alt="ClawHub"></a>
  <img src="https://img.shields.io/badge/python-3.9%2B-E8A33D?labelColor=2b2b2b" alt="Python 3.9+">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-E34234?labelColor=2b2b2b" alt="License: MIT"></a>
</p>

Your OpenClaw agent can read your files, hold your credentials, and act on your
behalf. **ClawSecCheck tells you whether that power is locked down.** It reads
your configuration and your installed skills, scores the setup **A–F**, and
explains the most urgent holes in plain language — each finding says what is
wrong, why it matters, and what a fix looks like.

It is **free, local, and read-only**: no API key, no network calls, no
telemetry. It never changes your OpenClaw setup, and your data never leaves
your machine.

## Quick start

Inside OpenClaw (recommended):

```bash
openclaw skills install clawseccheck             # from ClawHub
openclaw skills install git:gl0di/clawseccheck   # or straight from GitHub
```

Then just ask your agent:

> "Audit my OpenClaw setup with clawseccheck."

Or run it standalone (zero dependencies, Python 3.9+):

```bash
pipx install git+https://github.com/gl0di/clawseccheck
clawseccheck                       # audits ~/.openclaw by default
```

More ways to run it (in-repo `audit.py`, Windows notes, color/ASCII options):
see the **[User guide](docs/USAGE.md)**.

## What you get

<p align="center">
  <img src="docs/assets/report.png" alt="A real ClawSecCheck terminal report: score, grade, and findings grouped by area" width="760">
</p>

A real report from a deliberately vulnerable test setup looks like this:

```text
ClawSecCheck - OpenClaw Security Audit
============================================
Score: 49/100   Grade: F
(capped from 61 - open CRITICAL finding)

[Privilege & Execution]
[CRITICAL]  Lethal Trifecta (untrusted input x sensitive data x outbound)
    why: All three legs are active - your agent takes outside input, can reach
    sensitive data, and can act outbound; one injected prompt is enough to
    exfiltrate everything.
```

- **A score and grade (A–F)** with honest caps: an open CRITICAL finding can
  never hide behind a good grade.
- **Findings grouped by area, most urgent first** — every finding explains
  itself in plain language and carries structured fix data in `--json`/SARIF.
- **A shareable badge** (`--card` / `--badge`) that shows only the grade and
  score — never your findings.

## What it finds

| Area | The question it answers |
|---|---|
| Exposure & network | Can strangers reach your agent (open gateway, open DMs/groups, missing TLS, weak sender identity)? |
| Privilege & execution | Could one injected message run commands or write files (sandbox off, no approval gates, the Lethal Trifecta)? |
| Installed skills & plugins | Is anything you installed malicious or risky (ClawHavoc-class malware, hidden payloads, credential theft, supply-chain traps)? |
| Prompt-injection surface | Can untrusted text steer your agent (bootstrap files, injected chat context, hidden or obfuscated directives)? |
| Secrets & data at rest | Are tokens, keys, and conversation data lying around readable (plaintext secrets, loose file permissions, leaky logs)? |
| Monitoring & readiness | Would you even notice a compromise (drift monitoring, host defenses, incident evidence trail)? |

On top of the individual checks, a **risk engine** looks for dangerous
*combinations* — chains like "untrusted input → reachable secrets → outbound
tool" that make a compromise trivial.

Full reference: **[the generated catalog of 130+ checks](docs/CHECKS.md)** and
the **[OWASP / threat-model coverage matrix](docs/THREAT_COVERAGE.md)**.

## Vet a skill before you install it

OpenClaw skills are not sandboxed — an installed skill runs with your agent's
full permissions, and the ClawHavoc campaign showed what that costs. So
ClawSecCheck also works as a **pre-install scanner**:

```bash
clawseccheck --vet ./some-skill        # malware/injection scan before enabling (type autodetected)
clawseccheck --vet-source npm:somepkg  # reputation gate before anything is even downloaded
clawseccheck --vet-mcp                 # audit the MCP servers your agent already trusts
```

The verdict is a risk dossier: SAFE / SUSPICIOUS / DANGEROUS, with an A–F grade
across five axes. Details in the [User guide](docs/USAGE.md).

## Is it safe to run?

The tool that audits your agent should survive an audit itself:

- **Read-only** with respect to your OpenClaw setup — it never touches
  `openclaw.json`, your skills, or your bootstrap files. It writes only its own
  local history under `~/.clawseccheck/` (opt out with `--no-history`, remove
  with `--purge`).
- **Offline by design.** No network calls, no telemetry, no upload — a feature
  that could exfiltrate simply does not exist in the codebase.
- **Zero dependencies.** Pure Python standard library; nothing to typosquat.
  The whole engine is readable source in [`clawseccheck/`](clawseccheck/).
- **Signed releases.** Every release ships a `SHA256SUMS.txt` signed with
  keyless [cosign](https://github.com/sigstore/cosign); `clawseccheck
  --verify-self` prints your copy's digest to compare. Verify the reference:

```bash
# Get the release assets (adjust the version):
curl -LO https://github.com/gl0di/clawseccheck/releases/download/vX.Y.Z/SHA256SUMS.txt
curl -LO https://github.com/gl0di/clawseccheck/releases/download/vX.Y.Z/SHA256SUMS.txt.bundle

cosign verify-blob \
  --bundle SHA256SUMS.txt.bundle \
  --certificate-identity-regexp "^https://github.com/gl0di/clawseccheck/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
```

The full self-defense posture — capability surface, redaction discipline, what
happens if the host itself is compromised — is documented in
[SECURITY_MODEL.md](SECURITY_MODEL.md) and the [FAQ](docs/FAQ.md).

## Output formats & CI

```bash
clawseccheck --json                  # machine-readable result
clawseccheck --sarif results.sarif   # SARIF 2.1.0 for GitHub Code Scanning
clawseccheck --html report.html      # standalone HTML report (private)
clawseccheck --badge grade.svg       # shareable grade badge
clawseccheck --fail-under 70         # CI gate: exit 1 if score < 70
clawseccheck --exit-code             # CI gate: exit 1 on any unsuppressed FAIL
```

## Honest limitations

A clean report means "no known attack pattern matched" — **not** "this setup is
safe." ClawSecCheck is a static, heuristic audit: it bounds what your agent
*can* do, not how it behaves under a live attack, and external benchmarks show
its precision is high but its recall against novel malicious samples is the
weak point. `UNKNOWN` is always reported as `UNKNOWN` and excluded from the
score — never silently marked safe. The full, unvarnished list is in the
[User guide](docs/USAGE.md#honest-limitations) and
[SECURITY_MODEL.md](SECURITY_MODEL.md).

## Documentation

| Document | What it covers |
|---|---|
| [User guide](docs/USAGE.md) | Every flag, recipe, monitoring mode, and trust detail |
| [Check catalog](docs/CHECKS.md) | All checks: verdict semantics, remediation, risk chains (generated) |
| [Threat coverage](docs/THREAT_COVERAGE.md) | OWASP LLM Top 10 / Agentic threat mapping |
| [Output schema](docs/OUTPUT_SCHEMA.md) | The frozen `--json` / SARIF contract |
| [Attestation](docs/ATTESTATION.md) | The `--ask` / `--attest` self-report layer |
| [FAQ](docs/FAQ.md) | Common questions, including the compromised-host protocol |
| [Security model](SECURITY_MODEL.md) | ClawSecCheck's own capability surface and self-defense |
| [Contributing](CONTRIBUTING.md) | Dev setup, tests, how to author a new check |

## Feedback, security, license

- **Bugs / false positives:** [open an issue](https://github.com/gl0di/clawseccheck/issues)
  with `clawseccheck --json` output (secret values are redacted — but read it
  before posting) and your OpenClaw version.
- **Vulnerabilities:** privately, via [SECURITY.md](SECURITY.md).
- **License:** [MIT](LICENSE). Maintained by [gl0di](https://github.com/gl0di)
  <gllodi@gmail.com>.
