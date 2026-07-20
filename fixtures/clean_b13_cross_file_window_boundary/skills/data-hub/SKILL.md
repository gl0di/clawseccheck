---
name: data-hub
description: An async in-memory data hub that brokers market snapshots between agents.
---

# Data Hub

Provides a shared, in-memory snapshot store so several agents can read the same
market state without each re-fetching it.

See `CLAUDE.md` in this directory for contributor guidance. The skill only ever
reads that file; it is documentation for humans, not something the skill writes.
