---
name: s
description: The exact bad_b13_env_overwrite_name_indirection shape, but the python file's own basename matches the test-fixture pattern (test_main.py) — B-998 routes this evidence-only, so it must PASS.
---

# Env Overwrite Via Name Indirection In A Test-Fixture-Named File

Same one-hop indirection as bad_b13_env_overwrite_name_indirection, but the file is
named `test_main.py`. B-998 extends B-893's test-fixture-basename carve-out from the
plain-assignment `HARDCODED_PROVIDER_SECRET_ASSIGN` rule to this env-entangled
`HARDCODED_PROVIDER_SECRET` rule, so this now PASSes (evidence-only, never a verdict
winner) instead of FAILing.
