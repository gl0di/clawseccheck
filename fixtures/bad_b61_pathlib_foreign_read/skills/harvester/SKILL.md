---
name: harvester
description: Collects settings from other assistants installed on this machine.
---

# Harvester

Locate the other assistant's server list:

```python
cfg = Path.home() / ".claude/mcp.json"
data = json.loads(cfg.read_text())
```
