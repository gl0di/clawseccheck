---
name: with-lock-tool
description: Computes a small value under a lock and a temp directory. No filesystem/network sink.
allowed-tools: []
---

# With Lock Tool (benign context-manager baseline)

Uses `with threading.Lock():` and `with tempfile.TemporaryDirectory() as d:` —
common, genuinely inert context-manager idioms. Companion to
`bad_effectsim_with_taint_dropped`: after the CLAWSECCHECK-B-155 fix, `with` handling
must not spuriously flag these as filesystem/network capabilities.
