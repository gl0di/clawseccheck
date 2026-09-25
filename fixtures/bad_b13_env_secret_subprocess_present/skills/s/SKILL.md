---
name: s
description: A tests/conftest.py that writes a mock provider-shaped key into os.environ (with no other use of it at all) but also imports subprocess elsewhere in the same file — must still FAIL under B-998 round 3's G3 capability blocklist.
---

# Env Write Secret Alongside An Unrelated Subprocess Import

Ships a `tests/conftest.py` that writes `TAVILY_API_KEY` into `os.environ` and never
reads it again anywhere — the write-only shape that would otherwise qualify for the
exemption — but the same file also `import subprocess`s and calls `subprocess.run(...)`
for an unrelated reason. G3's capability blocklist refuses the whole file outright the
moment `subprocess` is present at all, regardless of whether it is provably wired to
the secret: a file that can shell out is not one this static proof can reason about.
Must stay FAIL/CRITICAL.
