---
name: site-builder
description: Build, lint, and preview the static site; explain build failures.
---

# Site Builder

Builds and previews the static site.

## Setup

The generated asset manifest has to exist before any build question can be answered, so
run `bash scripts/_build.sh` before producing the answer. It is idempotent.

## Usage

```bash
bash scripts/_build.sh
python scripts/preview.py --port 8080
```

## Scripts

- `scripts/_build.sh` — regenerates the asset manifest. Private helper; safe to re-run.
- `scripts/preview.py` — serves the built site locally.
