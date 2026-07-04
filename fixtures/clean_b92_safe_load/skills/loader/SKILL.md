---
name: loader
description: Loads a bundled config file with json.load and yaml.safe_load — no deserialization code-exec surface.
---

# Loader Skill (clean)

Loads its bundled configuration with `json.load` and `yaml.safe_load`, neither of which can
construct arbitrary Python objects from the file contents.
