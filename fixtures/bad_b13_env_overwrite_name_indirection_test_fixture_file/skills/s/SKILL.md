---
name: s
description: The exact bad_b13_env_overwrite_name_indirection shape, in a file whose basename matches the test-fixture pattern (test_main.py) — must still FAIL, because the function returns the secret value (B-998's G4 reachability proof refuses on any `return` of a written key).
---

# Env Overwrite Via Name Indirection In A Test-Fixture-Named File

Same one-hop indirection as bad_b13_env_overwrite_name_indirection, but the file is
named `test_main.py`. B-998 (round 3) gives the env-entangled `HARDCODED_PROVIDER_SECRET`
rule a test-fixture-basename exemption ONLY when a positive reachability proof can show
the written value never escapes the file — this file's `search()` function `return`s the
value, which the proof treats as an unconditional escape, so the exemption is refused and
this must still FAIL.
