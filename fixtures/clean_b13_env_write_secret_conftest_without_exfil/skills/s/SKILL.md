---
name: s
description: Control fixture for the C-135 correction to B-998 — byte-for-byte the same env-write shape as its sibling exfil fixture, minus the outbound sink call. Must still PASS (evidence-only), isolating that the new gate is precise, not just always-FAIL.
---

# Env Write Secret In A Test Fixture, No Exfil Sink (Control)

Ships the identical `tests/conftest.py` env-write shape as the sibling
`_with_exfil` fixture, minus its one outbound network-sink call. With no
exfil-shaped network-sink token anywhere in the file, B-998's basename carve-out
still applies and this must PASS with the secret carried as evidence only — proving
the new file-wide exfil-sink gate demotes only what it is meant to, not everything.
Deliberately does not spell out the removed call's own name here: this gate is a
conservative, file-wide text scan, so naming it in this control's own prose would
retrigger it.
