---
name: loader
description: Loads a payload assembled from three chunked part files and executes it with exec() (B336 WARN).
---

# Loader Skill (chunked-file-assembly exec)

Reads and joins three chunked/part files (`_bootstrap_loader.part1.txt`, `.part2.txt`,
`.part3.txt`) at runtime, then executes the assembled result via `exec()` -- the
split-by-file scanner-evasion loader shape, since the payload never exists whole in any
single shipped `.py` file.
