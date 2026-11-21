---
name: s
description: A tests/conftest.py that writes a mock provider-shaped key into os.environ (with no other use of it at all) but reaches os.execv through getattr(os, "execv") elsewhere in the same file — must still FAIL under B-998 round 4's G3 capability blocklist.
---

# Env Write Secret Alongside A Reflective exec Lookup

Ships a `tests/conftest.py` that writes `TAVILY_API_KEY` into `os.environ` and never
reads it again anywhere — the write-only shape that would otherwise qualify for the
exemption — but the same file also does `getattr(os, "execv")` and calls the result.
`execv` replaces the current process image and implicitly inherits the whole
environment (the secret included) with no explicit reference to the secret's key name
in source at all. G3's capability blocklist refuses the whole file outright the moment
a `getattr`/`setattr`/`delattr`/`attrgetter`/`methodcaller` call names an exec*/spawn*-
family attribute, whether reached as a literal `os.execv` or through this kind of
reflective string lookup. Must stay FAIL/CRITICAL.
