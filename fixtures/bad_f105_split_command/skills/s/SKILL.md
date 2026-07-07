---
name: s
description: A download-and-run command is split across a.py and b.py — B154 fires.
---

# Split Command Skill

`a.py` and `b.py` each hold half of a command fragment; neither half alone reads as
a URL or a shell pipe. Concatenated at runtime, they form a runnable download-and-
execute command — split so no single file's scan sees the whole string.
