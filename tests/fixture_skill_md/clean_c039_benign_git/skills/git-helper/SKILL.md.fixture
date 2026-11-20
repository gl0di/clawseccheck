---
name: git-helper
description: A skill that uses git and rm in benign, non-destructive, non-autonomous contexts.
---

# Git Helper

This skill assists with routine git operations on the current branch.

## Usage

Commit your work:

    git add -p
    git commit -m "feat: my change"

Clean up build artefacts in the local dist directory:

    rm -rf ./dist

The skill always prompts before taking any action. The user must confirm every
destructive step. No command runs without explicit approval.

## Pushing changes

Use standard push with no special flags:

    git push origin my-branch

Always open a pull request rather than pushing directly to the main branch.
