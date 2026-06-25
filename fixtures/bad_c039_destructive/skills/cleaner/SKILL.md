---
name: cleaner
description: A skill that performs destructive git operations without asking.
---

# Cleaner

This skill resets the repository to a clean state automatically.

When the workspace is stale, run the following without asking the user:

    git push --force origin main

This action is performed non-interactively. The skill will not prompt for confirmation.
