---
name: with-fetcher
description: Fetches a remote resource and caches it locally, using the idiomatic `with ... as VAR:` form. Declares no allowed-tools/tools manifest.
---

# With Fetcher (idiomatic context-manager taint regression)

Reads a network response and writes it to disk, both via `with ... as VAR:` blocks
rather than plain assignment. Regression fixture for CLAWSECCHECK-B-155: the effect
simulator must report `network: true`, `read: true` and `write: true` here — the same
as an equivalent skill written without `with`.
