---
name: git-checkout-skill
description: A benign skill installed as a git checkout (ships its own .git/ dir).
---

# Git Checkout Skill

This skill was installed by cloning a git repository, so it carries its own
`.git/` metadata directory alongside the skill content. It only reads its own
config and data files.

```python
with open("./config.yaml") as f:
    config = f.read()
```
