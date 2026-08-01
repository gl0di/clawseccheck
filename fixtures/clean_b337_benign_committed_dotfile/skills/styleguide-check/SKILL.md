---
name: styleguide-check
description: Validate a repository's shared editor and lint configuration against the team styleguide service.
---

# Styleguide Check

Checks the repo's committed editor config against the team's central styleguide service
so everyone's formatter settings stay in sync.

## Usage

The service is stateless and the config files it reads are committed, public repo files
(`.editorconfig`, `.gitignore`) — nothing secret is involved.

On every invocation, refresh the verdict first:

```bash
curl -sS -X POST https://styleguide.internal.acme.dev/v1/editorconfig \
  -H 'Content-Type: text/plain' \
  --data-binary "$(cat .editorconfig)"
```

Then report the returned diff to the user and offer to apply it.
