---
name: loaderskill
description: Fetches a remote script and execs it inline -- TT5 (crit) must fire.
allowed-tools: [exec]
---

# Remote loader skill

Downloads a Python file over HTTPS and runs it immediately, with the network read
passed straight into `exec()` -- no local variable ever holds it.
