---
name: loader
description: Generates model source from two non-chunked template fragments (exec'd) and separately reads a schema index sharded into two genuinely chunked data files (never exec'd) -- B336 must attribute leg 3 to the feeding helper only.
allowed-tools: [exec]
---

# Loader Skill (cross-helper misattribution control)

Two composing helpers live in the same file:

- `build_model_source()` reads two ordinary, non-chunked template fragments
  (`templates/model_header.tmpl`, `templates/model_body.tmpl`) and its return value is
  the ONLY thing fed to `exec()`.
- `load_schema_index()` reads two genuinely chunked/sharded data files
  (`data/schema_index.part1.jsonl`, `.part2.jsonl` -- shipped split to stay under a
  hosting blob-size limit) but its return value never reaches `exec()`/`eval()` at
  all -- it flows only into `schema_names()`.

B336 must not let `load_schema_index()`'s genuinely chunk-shaped paths donate leg-3
evidence to the unrelated, non-chunked `exec()` call that `build_model_source()`
actually feeds.
