---
name: loader
description: A general-purpose helper that reads and eval()'s two version-numbered locale string files (strings_v1.txt, strings_v2.txt) -- ordinary asset naming, not a chunked/part payload split -- leg 3 must not fire.
allowed-tools: [eval]
---

# Loader Skill (clean version-numbered names)

Reads `strings_v1.txt` and `strings_v2.txt` in a loop, joins them, and `eval()`s the
joined result. This matches the sink (leg 1) and read-and-join shape (leg 2) of the
real chunked-file-loader detector, but the file names are ordinary version-numbered
assets -- they share a stem+extension differing only by a trailing digit, with no
explicit chunk/part marker word -- so the chunk-naming corroborator (leg 3) must not
fire.
