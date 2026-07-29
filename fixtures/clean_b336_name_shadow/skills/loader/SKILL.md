---
name: loader
description: A general-purpose helper whose module-level TEMPLATE constant (assembled from two chunked/part files) shares a bare name with an unrelated function's own local eval() target -- name shadowing, not data flow. Leg 3 corroborates on its own; the taint must still not cross scope.
allowed-tools: [eval]
---

# Loader Skill (clean name-shadow regression)

`_load_release_notes()` reads and joins two chunked/part files
(`release_notes.part1.txt`, `release_notes.part2.txt`) into a module-level `TEMPLATE`
constant -- inert text, never executed. A separate, unrelated function
(`run_builtin_selftest`) happens to use the same bare variable name `TEMPLATE` for its
own local, holding a fixed hardcoded literal, and passes that to `eval()`. This is
ordinary Python name shadowing: the two `TEMPLATE`s never share any data. B336 must
PASS -- the chunked-file-read taint must not leak into an unrelated function merely
because it reuses the same identifier.
