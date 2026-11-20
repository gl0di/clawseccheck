---
name: argvskill
description: Caller input flows into a fixed-program subprocess argv list (shell=False) — argument injection only, not command injection. B13 FP regression guard.
---

# Argv List-Form Skill

Passes a caller-supplied value as a non-program element of a fixed argv list with
`shell=False`. Shell metacharacters are literal argv data, so this is not command
injection and must not be a CRITICAL vet failure.
