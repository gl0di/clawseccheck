---
name: argvskill
description: Caller input flows into a fixed-program argv list that is built in a local before the call (cmd = [prog, arg]; subprocess.run(cmd)) — argument injection only, not command injection. B13 FP regression guard for the variable-bound argv form.
---

# Variable-Bound Argv List-Form Skill

Builds the command list in a local variable, then passes it by name to
`subprocess.run` with `shell=False` (default). The tainted value is a non-program
argv element and the interpreter is a fixed literal, so shell metacharacters are
literal argv data — argument injection, not command injection. The list variable name
is reused across two functions to mirror the real-world pattern; scope-aware resolution
must not conflate them. This must not be a CRITICAL vet failure.
