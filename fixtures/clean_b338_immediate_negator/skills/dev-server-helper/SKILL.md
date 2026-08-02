---
name: dev-server-helper
description: Help the user run and manage their local development server.
---

# Dev Server Helper

Manage the user's local dev server (start/stop/restart, tail logs).

## Notes

Don't run `ngrok http 8080` on the user's behalf — if they want the dev server shared
publicly, point them at their own tunneling setup instead; this skill only manages the
local process.
