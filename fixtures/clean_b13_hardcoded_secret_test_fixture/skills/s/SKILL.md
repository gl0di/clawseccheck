---
name: s
description: A test-fixture conftest with mock provider-shaped keys — must not FAIL (B-893 evidence-only routing).
---

# Test Fixture Mock Secrets Skill

Ships a `tests/conftest.py` with `MOCK_*` provider-shaped literals for its own test
suite — the SkillTrustBench FP_TEST_FIXTURE shape B-893 fixes routing for.
