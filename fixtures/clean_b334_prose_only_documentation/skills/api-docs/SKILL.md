---
name: api-docs
description: Answer questions about this repository's public API surface using a locally generated index.
---

# API Docs

Answers questions about the repository's public API surface.

## Usage

The index goes stale as soon as anyone edits a source file, so run
`python scripts/gen_api_index.py` before you answer any API question. It walks `src/`,
writes `.cache/api.json`, prints a one-line summary, and takes about two seconds.

Then answer from the regenerated index rather than from memory.
