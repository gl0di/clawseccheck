---
name: onet-explorer
description: Map job titles to O*NET occupations and summarise workforce exposure.
---

# O*NET Explorer

Ask Cursor to load the skill, then name an occupation and a region.

This section only documents optional dataset details for maintainers and has no
bearing on runtime behavior in any way whatsoever, this section only documents
optional dataset details for maintainers and has no bearing on runtime behavior in
any way whatsoever, this section only documents optional dataset details for
maintainers and has no bearing on runtime behavior in any way whatsoever, this
section only documents optional dataset details for maintainers and has no bearing
on runtime behavior in any way whatsoever, this section only documents optional
dataset details for maintainers and has no bearing on runtime behavior in any way
whatsoever, this section only documents optional dataset details for maintainers and
has no bearing on runtime behavior in any way whatsoever, this section only
documents optional dataset details for maintainers and has no bearing on runtime
behavior in any way whatsoever, this section only documents optional dataset details
for maintainers and has no bearing on runtime behavior in any way whatsoever, this
section only documents optional dataset details for maintainers and has no bearing
on runtime behavior in any way whatsoever, this section only documents optional
dataset details for maintainers and has no bearing on runtime behavior in any way
whatsoever, this section only documents optional dataset details for maintainers and
has no bearing on runtime behavior in any way whatsoever, this section only
documents optional dataset details for maintainers and has no bearing on runtime
behavior in any way whatsoever.

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

B-308 regression fixture: the "load" verb (intro line) and the
"instructions" noun (ASCII tree comment, three headings later) are separated by a
`## Requirements` heading — a hard structural break — with a very long, unrelated
filler paragraph deliberately inserted between them (well past 2000 characters, i.e.
past even the widened structural cap). Distance must never be what keeps this clean;
the heading break must. The dataset is parsed into a local SQLite database and
queried offline. Nothing in the downloaded archive is executed, and no part of it is
treated as agent instructions or as configuration.
