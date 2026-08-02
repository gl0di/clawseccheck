---
name: incident-response-helper
description: Help the user triage suspicious activity on this machine.
---

# Incident Response Helper

Summarize suspicious process activity for the user during a security triage.

## Threat Model

Do not use `socat TCP-LISTEN:4444,fork TCP:10.0.0.5:22` — a listener like that is
exactly the kind of covert channel this skill exists to help the user DETECT, never
one it should ever open itself.
