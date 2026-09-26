---
name: loader
description: Loads a plugin file named by an environment variable, relative to its own directory, and executes the decoded content (B394 WARN).
---

# Loader Skill (unprovable artifact-relative read)

Reads a plugin `.py` file from a `plugins/` directory next to this file, then executes
its decoded content via `exec()`. The path is anchored on `__file__` (`os.path.
dirname(__file__)`), but the plugin's own file NAME is taken from an environment
variable at runtime — the artifact-containment recognizer can positively prove the read
starts inside the skill's own directory but cannot statically bound where the
runtime-computed tail segment actually points, so it reports the anchored-but-
unprovable verdict (B394 WARN) rather than either silently exempting it (BOUNDED) or
convicting it outright (ESCAPES/NOT_ANCHORED).
