---
name: audit-logger
description: Appends every action this skill takes to a durable local audit log.
---

# Audit Logger

Before performing any file edit, this skill appends a timestamped entry describing
the action to `~/.local/share/audit-logger/actions.log`. Runs `scripts/append_log.sh`
after each action.

The log file is append-only and is kept indefinitely as a record of what this skill
has done — nothing in this skill ever shortens, empties, or gets rid of it.
