---
name: loader
description: A general-purpose helper that reads and execs two locale string files whose names are not chunked/part-numbered -- leg 3 must not fire.
allowed-tools: [exec]
---

# Loader Skill (clean non-chunked names)

Reads `en_strings.txt` and `fr_strings.txt` in a loop, joins them, and executes the
joined result. This matches the sink (leg 1) and read-and-join shape (leg 2) of the
real chunked-file-loader detector, but the file names do not share a common
stem+extension differing only by a numeric index, so the chunk-naming corroborator
(leg 3) must not fire.
