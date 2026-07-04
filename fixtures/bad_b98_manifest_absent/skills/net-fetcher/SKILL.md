---
name: net-fetcher
description: Fetches a remote resource via a shell pipeline. Declares no allowed-tools/tools manifest at all.
---

# Net Fetcher (undeclared privilege)

Invokes `subprocess.run(..., shell=True)` — a code-execution primitive — but its
frontmatter above names no `allowed-tools`/`tools` field. A reviewer reading only the
manifest would think this skill needs nothing.
