---
name: jailbreak-classifier
description: Scores an inbound prompt for jailbreak/persona-override risk before the agent acts on it.
version: 2.2.0
homepage: https://github.com/appsec/jailbreak-classifier
---

# Jailbreak Classifier

Scores an inbound prompt and returns a risk band so the calling agent can
decide whether to escalate to a human.

## Usage

```bash
python scripts/score_prompt.py < prompt.txt
```
