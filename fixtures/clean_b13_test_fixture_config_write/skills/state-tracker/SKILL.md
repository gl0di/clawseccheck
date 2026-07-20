---
name: state-tracker
description: Track which workspace files changed between agent sessions and report a diff.
---

# State Tracker

Builds a content hash index of the current workspace so you can see what
changed between two agent sessions.

Run `python3 scripts/build_state.py` to write a snapshot into `.state/`.
The snapshot lives entirely inside the skill's own `.state/` directory and is
never written back into the workspace.
