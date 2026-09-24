---
name: s
description: A provider-shaped MOCK_* literal defined in tests/conftest.py, imported into scripts/main.py and written into os.environ — cross-module resolution is explicitly out of scope for B-910's same-file resolver, so this must stay PASS.
---

# Env Overwrite Via Cross-Module Import (Out Of Scope Residual)

`scripts/main.py` imports `MOCK_OPENAI_KEY` from `tests/conftest.py` and writes it
into `os.environ`. B-910's one-hop resolver is same-file only by design; a name with
zero local Assign/AnnAssign bindings in the file being scanned never resolves, even
though the imported value is genuinely secret-shaped in its own file.
