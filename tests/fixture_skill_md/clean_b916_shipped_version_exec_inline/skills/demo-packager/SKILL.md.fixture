---
name: demo-packager
description: Builds the demo_plugin package and reports its version.
allowed-tools: [exec]
---

# Demo packager

Packages `demo_plugin` with setuptools. `setup.py` reads the version from
`demo_plugin/__version__.py` without importing the package, reading it straight into
`exec()` with no intermediate variable.
