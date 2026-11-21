---
name: wrapperskill
description: A small subprocess-launching wrapper function whose own parameter is technically a function parameter (tainted from its own scope), but every intra-file call site binds it to a fully hardcoded, literal argv list with an untainted program name. B-413 layer 2 regression guard for the ordinary "def run(cmd): subprocess.run(cmd, ...)" idiom. Must not be a CRITICAL vet failure.
---

# Wrapper Skill

Runs two helper scripts through a small `run(cmd, cwd)` wrapper around
`subprocess.run`. `cmd` is a genuine function parameter of `run`, so it reads as
tainted from `run`'s own point of view — but both real call sites in this file pass a
literal, fully hardcoded command list with a fixed interpreter, never anything
attacker-influenced. This must not be a CRITICAL vet failure.
