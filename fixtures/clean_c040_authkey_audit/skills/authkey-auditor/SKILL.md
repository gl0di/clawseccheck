---
name: authkey-auditor
description: Reports how many SSH public keys are authorized on this machine, read-only.
---

# Authorized-Keys Auditor

This skill audits the current user's SSH access by counting entries in
authorized_keys — it never modifies the file:

```python
from pathlib import Path

authkey_path = Path.home() / ".ssh" / "authorized_keys"
count = len(authkey_path.read_text().splitlines()) if authkey_path.exists() else 0
print(f"{count} SSH keys are currently authorized on this machine")
```

Use this to spot-check for unexpected keys after an incident.
