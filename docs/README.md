# ClawSecCheck documentation

Reading order depends on who you are:

## I just want to use it

1. [Project README](../README.md) — what it is, quick start, trust story
2. [USAGE.md](USAGE.md) — the user guide: recipes, monitoring modes, and trust details
3. [FAQ.md](FAQ.md) — common questions, including "what if the host is already
   compromised?"
4. [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — when ClawSecCheck itself won't run,
   crashes, or OpenClaw doesn't see it (not a question about your audited setup)

## I want to understand what it checks and why

1. [CHECKS.md](CHECKS.md) — the generated catalog of every check: verdict
   semantics, remediation, compound risk chains
2. [THREAT_COVERAGE.md](THREAT_COVERAGE.md) — mapping to OWASP LLM Top 10 (2025)
   and OWASP Agentic threat classes
3. [ATTESTATION.md](ATTESTATION.md) — the `--ask` / `--attest` self-report
   layer: what it adds, what it can't prove
4. [../SECURITY_MODEL.md](../SECURITY_MODEL.md) — ClawSecCheck's own capability
   surface, least-privilege posture, and self-defense

## I want the reasoning behind a design decision

Analysis and decision records. They change no code and are not a reference —
read one when you want to know *why* something is the way it is.

1. [design/severity-separability.md](design/severity-separability.md) — why
   FAIL-only recall is roughly half a static peer's, measured on
   SkillTrustBench, and what the recommendation costs
2. [design/judge-topology.md](design/judge-topology.md) — why the LLM judge
   lives in the host agent and never inside the scanner
3. [design/agent-knowledge-enrichment.md](design/agent-knowledge-enrichment.md) —
   whether that agent may add what it knows to a finding, and the four gates
   that bound it

## I want to integrate it

1. [OUTPUT_SCHEMA.md](OUTPUT_SCHEMA.md) — the frozen `--json` / SARIF contract
2. [USAGE.md — CI / automation](USAGE.md#ci--automation) — exit codes,
   `--fail-under`, SARIF upload

## I am the agent running this skill

These are loaded on demand from [SKILL.md](../SKILL.md), not read front to back.
They live outside it so its always-in-context body stays small.

1. [FLOW_CHOICES.md](FLOW_CHOICES.md) — the Step 5 branch protocols
2. [ISOLATION.md](ISOLATION.md) — the context firewall for untrusted content

## I want to contribute

1. [CONTRIBUTING.md](https://github.com/gl0di/clawseccheck/blob/main/CONTRIBUTING.md) — ground rules, dev setup, PR flow
2. [THREAT_INTAKE.md](THREAT_INTAKE.md) — which threat sources are watched, and the
   five-bucket triage that decides what a new signal actually changes
3. [CHECK_AUTHORING.md](CHECK_AUTHORING.md) — how to write a new check
4. [RELEASING.md](RELEASING.md) — the maintainer release protocol

## Reporting

- Bugs and false positives → [GitHub issues](https://github.com/gl0di/clawseccheck/issues)
- Vulnerabilities → [../SECURITY.md](../SECURITY.md) (private reporting)
