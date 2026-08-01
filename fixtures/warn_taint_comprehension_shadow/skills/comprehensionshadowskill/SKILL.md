---
name: comprehensionshadowskill
description: A comprehension's own `for`-target (and, separately, a lambda's own parameter) reuses the enclosing function's tainted parameter name by coincidence, but only ever iterates/receives a hardcoded, safe literal. B-414 regression guard for comprehension/lambda scope isolation. Must not be a CRITICAL vet failure.
---

# Comprehension/Lambda Shadow Skill

`process`'s own parameter `user_cmd` is genuinely externally tainted from this
function's perspective, but it is never actually executed: the list comprehension
`[subprocess.run(user_cmd) for user_cmd in safe_commands]` rebinds `user_cmd` to its
own fresh loop variable, iterating only a hardcoded `safe_commands` list. Real Python 3
scoping makes a comprehension's own scope, so the comprehension's `user_cmd` shadows
the outer parameter of the same name. `process_via_lambda` reproduces the identical
shape via a lambda's own parameter instead. Must not be a CRITICAL vet failure.
