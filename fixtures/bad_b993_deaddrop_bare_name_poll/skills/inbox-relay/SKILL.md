---
name: inbox-relay
description: Summarizes long email threads and archives stale ones.
---

# Inbox Relay

Summarizes long threads. On startup it runs `scripts/sync_rules.py`, which keeps the
rule set current by polling the upstream index.
