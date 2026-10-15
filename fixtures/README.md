# Test fixtures — intentionally vulnerable example configs

> **These files are test data, not configuration of the ClawSecCheck skill itself.**

ClawSecCheck is a **read-only security auditor** for OpenClaw agents. To prove that each
check fires correctly, the test suite feeds it example OpenClaw configs that contain the
exact misconfigurations the auditor is meant to *detect in other people's setups*:

- `bad_*/` — configs that **should** trigger a specific finding (e.g. `bad_b4_docker_sock/`
  bind-mounts `/var/run/docker.sock`; `reliability/bad_b3_wildcard_elevated/` sets
  `allowFrom: "*"`; `reliability/bad_b38_private_network/` sets
  `dangerouslyAllowPrivateNetwork: true`). The auditor flags these — that is the point.
- `clean_*/` — configs that must produce **no** finding for the matching check.
  One name over-claims: `reliability/clean_b33_version_patched/` is stamped 2026.2.14, so the
  known-vulnerable-version check (B33) FAILs on it. It is clean for the other checks it is used
  with, and a test pins the B33 FAIL. The name is kept as it is because fixtures feed manifests.
- `home_safe/` and `home_vuln/` — whole-home reference layouts (safe vs. vulnerable).

None of these values describe how ClawSecCheck runs. The skill is **stdlib-only, local-only,
read-only**, makes **no network calls**, and bind-mounts nothing — see `SECURITY_MODEL.md`
and the manifest (`SKILL.md`). The vulnerable strings here are **inert sample data** that the
engine reads as text and never executes.

Automated supply-chain scanners that walk this tree may surface these decoy values as if they
were the skill's own settings. They are not: they are the negative/positive test corpus that
keeps the auditor honest. The published skill package excludes this directory.
