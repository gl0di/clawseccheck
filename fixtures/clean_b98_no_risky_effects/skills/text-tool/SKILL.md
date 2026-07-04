---
name: text-tool
description: Formats and trims plain text strings. No network, filesystem write, or exec effects, and no manifest field either — nothing risky to declare.
---

# Text Tool (no risky effects)

Pure string manipulation. Declares no `allowed-tools`/`tools` manifest, but that's fine
here — it never reaches network, filesystem-write, or exec.
