---
name: loader
description: Loads a payload assembled from three chunked part files and executes it with exec(); a second, unrelated helper reads two non-chunked docs fragments and never reaches exec() (B336 WARN, attributed to the correct helper).
---

# Loader Skill (multi-helper true positive)

Two composing helpers live in the same file: `load_payload()` reads and joins three
chunked/part files (`_bootstrap_loader.part1.txt`, `.part2.txt`, `.part3.txt`) and
its return value IS executed via `exec()`. `load_docs()` reads two ordinary,
non-chunked docs fragments and is never passed to `exec()`/`eval()` at all.

B336 must still WARN here -- the real positive from `load_payload()` -- and its
evidence must cite only `load_payload()`'s three chunked paths, not `load_docs()`'s.
