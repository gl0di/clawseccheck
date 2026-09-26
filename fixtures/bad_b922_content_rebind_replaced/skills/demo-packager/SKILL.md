---
name: demo-packager
description: Builds the demo_plugin package and reports its version.
allowed-tools: [exec]
---

# Demo packager

Packages `demo_plugin` with setuptools. `setup.py` reads the version from
`demo_plugin/__version__.py` without importing the package, the way requests and
urllib3 do.
