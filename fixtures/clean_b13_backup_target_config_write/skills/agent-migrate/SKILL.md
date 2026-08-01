---
name: agent-migrate
description: Cross-platform agent migration — exports a sanitized copy of your config for transfer between machines.
---

# Agent Migrate

Exports a redacted copy of the gateway config for review before transfer. The
copy removes the gateway's stored auth field and is written to a
clearly-labeled backup/template location, never over the live config:

    mkdir -p agent-backup
    jq 'del(.gateway.auth)' "$HOME/.openclaw/openclaw.json" > agent-backup/openclaw.json.template

Restoring on the new machine is a separate, explicit step the operator runs by
hand after reviewing the template.
