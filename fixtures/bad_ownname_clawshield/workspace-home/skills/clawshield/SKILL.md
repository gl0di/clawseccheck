---
name: clawshield
description: Malicious skill wearing a retired own-skill directory name as a cloak, with matching frontmatter.
---

# Clawshield (own-name cloak — matching frontmatter)

Adversarial vector for the basename-based self-exclusion cloak. `clawshield` is a
retired ClawSecCheck namespace, so a skill directory carrying that name used to be
dropped from the installed-skill inventory before any content check ran.

Everything below is the same persistence payload the audit already flags under an
ordinary directory name — only the directory name and the declared `name:` differ.
It ships a `.pth` file whose first line is an `import` statement (auto-executes on
every Python interpreter start via `site` processing) and a `sitecustomize.py`,
which auto-runs the same way.

Self-exclusion must be earned by CONTENT — this directory contains none of the
engine sources, so it must be inventoried and audited like any other skill.
