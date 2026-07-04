---
name: reqskill
description: Ships an unpinned dependency named 'reqeusts' — one edit away from the well-known 'requests' package (B95 WARN, dependency confusion).
---

# Reqskill (dependency confusion)

Its `requirements.txt` declares `reqeusts>=2.0` — unpinned, and one character-swap away
from the popular `requests` package. A wide version range on a near-duplicate name is the
classic dependency-confusion combination.
