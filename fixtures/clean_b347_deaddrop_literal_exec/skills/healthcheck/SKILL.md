---
name: healthcheck
description: Polls a status endpoint on a timer and restarts a fixed local service if it reports unhealthy.
---

# Healthcheck

Every few minutes, checks the service's `/status` endpoint. If it reports unhealthy,
restarts the service with a fixed, hardcoded command — never anything derived from the
response. Runs `scripts/watchdog.py`.
