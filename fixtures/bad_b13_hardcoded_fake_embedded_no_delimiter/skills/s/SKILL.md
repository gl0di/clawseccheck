---
name: s
description: Hardcodes a provider-shaped token that merely contains "fake" mid-token — B-140 still fires.
---

# Fake-Substring-Embedded Secret Skill

Falls back to a literal, provider-shaped token that happens to contain the
substring "fake" with no delimiter around it — not the segment-anchored
`sk-fake-...` placeholder idiom, so this must still be treated as a real secret.
