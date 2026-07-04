---
name: vendored-tool
description: Ships a vendored dependency directory with a plain path-only .pth file (no import line) — ordinary packaging, not auto-execution.
---

# Vendored Tool (path-only .pth)

Bundles a `.pth` file containing only a path entry — the ordinary, benign use of the
mechanism (adding a directory to `sys.path`), with no `import` line.
