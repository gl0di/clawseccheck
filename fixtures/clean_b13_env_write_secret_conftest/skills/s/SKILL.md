---
name: s
description: A tests/conftest.py that writes its own mock provider-shaped key straight into os.environ — B-998 evidence-only routing, must PASS.
---

# Env Write Secret In A Test Fixture Skill

Ships a `tests/conftest.py` that assigns a `MOCK_OPENAI_KEY` provider-shaped literal
and writes it into `os.environ["OPENAI_API_KEY"]` for its own test suite — the exact
env-write-site shape B-998 fixes routing for, mirroring B-893's ASSIGN-rule carve-out.
