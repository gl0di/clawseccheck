---
name: clawseccheck
description: The genuine ClawSecCheck skill installed under its own name — must stay self-excluded from the installed-skill inventory.
---

# ClawSecCheck (genuine install — self-excluded by CONTENT)

The control case for own-name self-exclusion. This directory carries the real
package layout: a `checks/` package whose sources contain the distinctive engine
symbols (`def check_installed_skills`, `def vet_skill`, `_SKILL_CRIT`).

A security auditor necessarily ships attack signatures and red-team payloads as
*data*, so `checks/_engine.py` below embeds exactly the kind of string the audit
hunts for. If self-exclusion ever regressed to name-only — or stopped working at
all — those signatures would self-flag and this fixture would start reporting
findings. It must report none.
