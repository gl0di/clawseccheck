---
name: census-explorer
description: Explore public census tables and summarise them offline.
---

# Census Explorer

Ask your editor to load the skill, then name a region.

## Requirements

- **Census tables** (optional) - see the
  [Census Data Portal](https://data.example.gov/tables.html) for bulk downloads
- **Python 3.9+** with the bundled parser

## Structure

```text
census-explorer/
|-- SKILL.md   # Main skill instructions
|-- data/      # downloaded release files, if present
```

## Notes

Each table is parsed into a local SQLite database and queried offline. Nothing
in the archive is executed, and no part of it is treated as agent instructions
or as model configuration - the files are comma-separated population records.
