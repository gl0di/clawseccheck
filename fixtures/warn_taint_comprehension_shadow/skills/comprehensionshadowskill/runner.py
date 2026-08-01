"""clean_taint_comprehension_shadow: a comprehension's OWN `for`-target variable
reuses the enclosing function's tainted parameter name, purely by coincidence -- the
comprehension iterates a hardcoded, safe literal list, never the caller-supplied
parameter itself.

B-414 regression fixture: `_own_bound_names`/`_build_toplevel_owner_map` had no case
for a comprehension's own scope, so a call inside one was wrongly attributed to the
ENCLOSING function's taint bucket with no shadow subtraction -- `process`'s own
tainted `user_cmd` parameter leaked into the comprehension even though the
comprehension's `for user_cmd in safe_commands` genuinely rebinds a FRESH, unrelated
local of the same name (real Python 3 scoping: a comprehension is its own scope).
Must not be a CRITICAL vet failure.
"""

import subprocess


def process(user_cmd):
    """`user_cmd` (this function's own parameter) is never actually run -- the
    comprehension below shadows it with its own loop variable of the same name,
    iterating only a hardcoded, safe command list."""
    safe_commands = ["/bin/ls", "/bin/pwd", "/bin/whoami"]
    results = [subprocess.run(user_cmd) for user_cmd in safe_commands]
    return results


def process_via_lambda(user_cmd):
    """Same shadowing shape, but via a lambda's own parameter instead of a
    comprehension's `for`-target -- `ast.Lambda` was already named in
    `_NESTED_SCOPE_NODES` but never actually got its own owner-map scope bucket."""
    runner = lambda user_cmd: subprocess.run(user_cmd)  # noqa: E731 -- fixture shape
    runner("/bin/ls")
    runner("/bin/pwd")


if __name__ == "__main__":
    process("ignored")
    process_via_lambda("ignored")
