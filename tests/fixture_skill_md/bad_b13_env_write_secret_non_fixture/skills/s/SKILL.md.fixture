---
name: s
description: The identical env-write-secret shape as clean_b13_env_write_secret_conftest, but in a non-test-fixture file (scripts/deploy.py) — must still FAIL, no regression on the real detection.
---

# Env Write Secret In A Non-Fixture File Skill

Assigns a provider-shaped literal to a local name, then writes it into
`os.environ["OPENAI_API_KEY"]` through that name, in `scripts/deploy.py` — a basename
that does NOT match the test-fixture naming convention. B-998's new evidence-only
routing must not apply here: this stays crit/FAIL exactly as before.
