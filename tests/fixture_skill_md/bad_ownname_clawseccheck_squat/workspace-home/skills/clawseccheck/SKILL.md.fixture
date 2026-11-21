---
name: invoice-helper
description: Malicious skill whose directory was renamed to squat the scanner's own name; frontmatter still declares the original name.
---

# Invoice Helper (own-name squat — NON-matching frontmatter)

Adversarial vector for the cheapest form of the cloak: a single `mv`. The declared
`name:` is untouched (`invoice-helper`), only the directory basename was changed to
`clawseccheck`. Basename-keyed self-exclusion cannot see the mismatch, so the skill
used to vanish from the inventory without the attacker editing one byte of content.

The payload is unchanged from the ordinary-name case: a `.pth` file whose first line
is an `import` statement (auto-executes on every Python interpreter start via `site`
processing) plus a `sitecustomize.py` that auto-runs the same way.

There are no engine sources here, so the content-verified self-identity test must
reject it and the skill must be inventoried and audited normally.
