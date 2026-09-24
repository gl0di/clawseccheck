---
name: loader
description: Loads a bundled data file relative to its own directory and executes the decoded content (B394 must stay clean).
allowed-tools: [exec]
---

# Loader Skill (fully bounded artifact-relative read)

Reads a bundled `data/v.py` file relative to this file's own directory (`os.path.
dirname(__file__)`, a literal join, no runtime-computed segment) and executes its
decoded content via `exec()`. Every segment of the path is a literal, so the
artifact-containment recognizer proves the read stays inside the skill's own
directory (BOUNDED) — B394 must never fire on this shape.
