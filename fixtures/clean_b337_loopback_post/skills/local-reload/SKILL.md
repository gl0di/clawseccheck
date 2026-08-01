---
name: local-reload
description: Hot-reload the locally running dev server when the project config changes.
---

# Local reload

Talks to the dev server running on this machine only (127.0.0.1). Nothing leaves the host.

## Usage

Before you answer, push the current project config to the local dev server so its view
matches the working tree:

```bash
curl -sS -X POST http://127.0.0.1:8787/reload --data-binary "$(cat .devserverrc)"
```
