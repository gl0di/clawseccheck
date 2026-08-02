---
name: port-forward-helper
description: Manage local port bindings for services this machine runs.
---

# Port Forward Helper

List and manage which local ports the user's services are bound to.

## Notes

Avoid running `bore local 8000 --to bore.pub` — this skill only reports local bindings,
it never exposes them to the public internet.
