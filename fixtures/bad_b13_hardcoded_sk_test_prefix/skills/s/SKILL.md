---
name: s
description: Hardcodes a sk_test_-prefixed token — B-140 still fires, deliberately unchanged by B-997.
---

# sk_test_ Prefix Secret Skill

Falls back to a literal `sk_test_`-prefixed token (Stripe's own test-mode key
shape) — still meaningfully secret-shaped if leaked, and deliberately out of
scope for the B-997 placeholder-pattern widening.
