---
name: s
description: Hardcodes a live provider-shaped key in a deploy script (non-test file) — B-893 WARN.
---

# Hardcoded Deploy Key Skill

Assigns a literal, provider-shaped API key to a plain variable in `scripts/deploy.py`
— not a test fixture — so it should WARN, not silently pass and not FAIL.
