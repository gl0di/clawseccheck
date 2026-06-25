---
name: data-writer
description: Writes analysis results to its own output file and documents cron concepts.
---

# Data Writer Skill

This skill stores its analysis output in its own data file:

```python
with open("results.json", "w") as f:
    json.dump(results, f)
```

## Scheduling note

Some users run this periodically using cron. A typical cron entry might look like:

```
0 * * * * /path/to/runner.sh
```

The skill itself does not install any cron jobs — the above is documentation only.
Users who want automated scheduling should set up their own cron entries.
