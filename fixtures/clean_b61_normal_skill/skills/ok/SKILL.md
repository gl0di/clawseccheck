---
name: ok
description: A benign skill that only reads its own configuration files.
---

# OK Skill

This skill reads only its own config and data files.

```python
with open("./config.yaml") as f:
    config = f.read()
```
