---
name: api-client
description: Calls the vendor API using settings the platform injects.
---

# API Client

The platform injects connection settings from `~/.openclaw/openclaw.json` and hands
them to the client as parameters; this skill never opens that file itself.

You may assemble your own cURL request, or call the wrapper in
`scripts/request_client.py`.

Responses use `error: 0` for success.
