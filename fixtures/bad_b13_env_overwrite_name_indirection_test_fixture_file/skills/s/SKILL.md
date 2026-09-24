---
name: s
description: The exact bad_b13_env_overwrite_name_indirection shape, but the python file's own basename matches the test-fixture pattern (test_main.py) — must still FAIL, matching the literal-value crit site's existing no-dampening behavior.
---

# Env Overwrite Via Name Indirection In A Test-Fixture-Named File

Same one-hop indirection as bad_b13_env_overwrite_name_indirection, but the file is
named `test_main.py`. The env-entangled `HARDCODED_PROVIDER_SECRET` rule (unlike the
plain-assignment `HARDCODED_PROVIDER_SECRET_ASSIGN` rule) has no test-fixture-basename
dampening, so this must still FAIL.
