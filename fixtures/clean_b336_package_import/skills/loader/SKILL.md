---
name: loader
description: A genuine multi-file Python package that imports sibling modules normally -- no open/read/exec surface.
---

# Loader Skill (clean multi-file package)

A normal multi-file Python package: `loader.py` imports its `pkg` sibling package via
ordinary `from . import x` / `from .pkg import helper` statements. No file is ever
opened, read, or passed to `exec`/`eval` -- Python's own import machinery loads the
code, not a runtime file-read-and-join helper.
