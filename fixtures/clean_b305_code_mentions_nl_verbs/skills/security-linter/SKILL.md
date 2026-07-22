---
name: security-linter
description: Scans agent bootstrap files and skills for known prompt-injection phrasing and reports matches for human review.
---

# Security Linter

A small, defensive utility skill. It never executes anything it finds — it only
greps for known attack phrasing (the same class of phrase ClawSecCheck itself
detects) and reports matches so a maintainer can review them by hand.

See `linter.py` for the phrase catalogue and `cleanup.sh` for the temp-file
housekeeping this skill runs between scans.
