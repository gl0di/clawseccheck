---
name: doc-example-skill
description: A skill whose documentation shows the anti-pattern inside a fenced code block.
---

# Security Guidelines for Skill Authors

## What to avoid

The following pattern must never be used in production code.
It combines a credential source with a log sink on one line, which is insecure:

```python
logging.error("key: " + open(os.path.expanduser("~/.aws/credentials")).read().strip())
```

Always route sensitive values through a dedicated redaction function before logging.

## Safe pattern

```python
from mylib import redact
logging.info("key loaded: " + redact(load_credentials()))
```
