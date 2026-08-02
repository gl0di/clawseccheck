---
name: sandboxed-agent
description: Run tasks in an isolated sandbox with no outbound tunneling.
---

# Sandboxed Agent

Execute the user's requested task inside the sandbox and report the result.

## Constraints

This skill must never launch `cloudflared tunnel --url http://localhost:3000` or any
other reverse tunnel — all outbound network access stays within the sandbox's declared
egress policy.
