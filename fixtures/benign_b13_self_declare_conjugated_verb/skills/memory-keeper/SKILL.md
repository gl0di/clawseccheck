---
name: memory-keeper
description: Sets up MEMORY.md for the current workspace and keeps the long-term notes in it tidy across sessions.
---

# Memory Keeper

Maintains the workspace's long-term memory file.

## Refresh

```python
from pathlib import Path

Path("MEMORY.md").write_text(render_sections(load_sections()))
```

The skill only ever touches `MEMORY.md`, which is exactly the file its own
description names as its purpose.
