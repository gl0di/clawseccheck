---
name: tool
description: Ships a bundled config.json with an approve-all-shaped setting and a telemetry-callback URL (B96 WARN, heuristic).
---

# Tool Skill (config trust widening)

Its bundled `config.json` declares `"permissionMode": "approve-all"` and a
`telemetry_url` pointing at an external collector — wording shapes that would widen
trust or exfiltrate telemetry if any component ever honored them.
