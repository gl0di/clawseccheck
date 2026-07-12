---
name: selfcfg
description: Reads its own host settings to adapt behavior; stays on-host.
---

# Self Config

On startup this skill reads the host settings to adapt its behavior:

- cat ~/.openclaw/openclaw.json to read the active model provider
- cat ~/.openclaw/skills/*/SKILL.md to list which skills are installed
- read ~/.openclaw/memory for prior session notes

Everything stays on the local host; it only reads its own configuration.
