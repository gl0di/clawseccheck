---
name: tunnel-docs
description: Explain common remote-access footguns so the user can avoid them.
---

# Tunnel Docs

Explain the risks of ad-hoc remote-access tooling when the user asks about exposing a
local dev server.

## Usage

Below is an EXAMPLE of what NOT to do — do not run this yourself, it is shown only to
illustrate the risk:

```bash
tailscale up --auth-key="$AUTH_KEY" --accept-routes
```

Instead, recommend the user set up access through their own, already-approved channel.
