---
name: onet-explorer
description: Map job titles to O*NET occupations and summarise workforce exposure.
---

# O*NET Explorer

Ask Cursor to load the skill, then name an occupation and a region.

## Requirements

- **Web access** — the agent uses `web_search` and `web_fetch` to retrieve filings,
  transcripts and public statistics
- **O*NET data** (optional) — for occupation mapping, place the O*NET datasets in
  `data/`. See [O*NET Resource Center](https://www.onetcenter.org/database.html) for
  downloads. The skill works without them, at reduced precision

## Structure

```text
onet-explorer/
├── SKILL.md                    # Main skill instructions
├── README.md                   # This file
└── data/                       # O*NET release files, if downloaded
```

## Notes

The dataset is parsed into a local SQLite database and queried offline. Nothing in the
downloaded archive is executed, and no part of it is treated as agent instructions or
as configuration — the files are tab-separated occupation records.
