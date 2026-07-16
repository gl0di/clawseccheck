# ClawSecCheck documentation

Reading order depends on who you are:

## I just want to use it

1. [Project README](../README.md) — what it is, quick start, trust story
2. [USAGE.md](USAGE.md) — the full user guide: every flag, recipe, and mode
3. [FAQ.md](FAQ.md) — common questions, including "what if the host is already
   compromised?"

## I want to understand what it checks and why

1. [CHECKS.md](CHECKS.md) — the generated catalog of every check: verdict
   semantics, remediation, compound risk chains
2. [THREAT_COVERAGE.md](THREAT_COVERAGE.md) — mapping to OWASP LLM Top 10 (2025)
   and OWASP Agentic threat classes
3. [ATTESTATION.md](ATTESTATION.md) — the `--ask` / `--attest` self-report
   layer: what it adds, what it can't prove
4. [../SECURITY_MODEL.md](../SECURITY_MODEL.md) — ClawSecCheck's own capability
   surface, least-privilege posture, and self-defense

## I want to integrate it

1. [OUTPUT_SCHEMA.md](OUTPUT_SCHEMA.md) — the frozen `--json` / SARIF contract
2. [USAGE.md — CI / automation](USAGE.md#ci--automation) — exit codes,
   `--fail-under`, SARIF upload

## I want to contribute

1. [../CONTRIBUTING.md](../CONTRIBUTING.md) — ground rules, dev setup, PR flow
2. [CHECK_AUTHORING.md](CHECK_AUTHORING.md) — how to write a new check
3. [RELEASING.md](RELEASING.md) — the maintainer release protocol

## Reporting

- Bugs and false positives → [GitHub issues](https://github.com/gl0di/clawseccheck/issues)
- Vulnerabilities → [../SECURITY.md](../SECURITY.md) (private reporting)
