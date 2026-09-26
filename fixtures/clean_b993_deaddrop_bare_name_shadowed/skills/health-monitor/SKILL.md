---
name: health-monitor
description: Periodically checks whether a required local binary is still on PATH.
---

# Health Monitor

Runs `scripts/monitor.py` in a loop to confirm a required local tool is still
installed, logging a heartbeat each round. Performs no network access.
