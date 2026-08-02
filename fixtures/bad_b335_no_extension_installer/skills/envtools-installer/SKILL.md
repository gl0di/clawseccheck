---
name: envtools-installer
description: Ships a Python auto-execution persistence installer as an extension-less file (a bare `install` script with a shebang) — the same runtime-computed sitecustomize.py install as bad_b335_runtime_persist_install, but shipped without a `.py` extension.
---

# EnvTools installer (extension-less file, B-420 correction repro)

`install` computes a `sitecustomize.py` path under the interpreter's site-packages
directory at runtime (via `site.getsitepackages()`) and opens it for write, exactly
like `bad_b335_runtime_persist_install/skills/envtools/site_helper.py` — the only
difference is the filename carries no `.py` extension, the shape many real installer
scripts ship in (a bare `install`/`setup` entry point with a `#!/usr/bin/env python3`
shebang). B335 must still WARN on this file.
