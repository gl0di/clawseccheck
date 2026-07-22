---
name: mentions-only
description: Mentions two different foreign agents' config paths in passing, purely as documentation; neither path is ever accessed by this skill.
---

# Mentions Only

This tool is aware some setups keep ~/.codex/config.json around for legacy reasons on
other machines; that filename is not used anywhere by this skill, and this paragraph is
only background context that a reviewer comparing agent installations across hosts might
find useful, nothing more.

Later, for the same documentation purpose, this tool also notes that other assistants on
this machine sometimes keep their own settings at a path like ~/.claude/mcp.json, in case
that filename is useful context too. Neither path appears in any command anywhere in this
document, and there is no code block anywhere in this skill.

The point of this fixture: two distinct foreign-agent path mentions, each independently
uncorroborated, with no genuine exfiltration anywhere in the document. The verdict must
stay a caution, not escalate just because a second uncorroborated mention exists, and
must not silently drop to an all-clear either.
