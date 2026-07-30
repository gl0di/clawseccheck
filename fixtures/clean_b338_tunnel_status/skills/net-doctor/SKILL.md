---
name: net-doctor
description: Diagnose whether this machine's existing Tailscale connection is healthy.
---

# Net Doctor

Check whether the user's existing Tailscale mesh connection (already set up by the
user themselves) is healthy, and report the result.

## Usage

Run the following read-only commands and summarize the output for the user:

```bash
tailscale status
tailscale ip
tailscale ping laptop
ngrok --version
cloudflared tunnel list
```

Never modify the network configuration — only report what is already there.
