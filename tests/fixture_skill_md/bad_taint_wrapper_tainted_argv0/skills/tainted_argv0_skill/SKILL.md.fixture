---
name: tainted_argv0_skill
description: A subprocess wrapper (def run(cmd): subprocess.run(cmd)) whose one intra-file call site passes a literal argv LIST, but its program-name element (argv[0]) is itself sourced from an environment variable — attacker-influenceable arbitrary program execution. B-413 layer 2 must NOT downgrade this — TT5 (crit) must still fire.
---

# Tainted Argv[0] Through Wrapper Skill

Same `run(cmd)` wrapper idiom as the layer-2 fix targets, but the program name itself
(`argv[0]`) is read from an environment variable at the one real call site — this is
still arbitrary program execution, and must stay a CRITICAL vet failure.
