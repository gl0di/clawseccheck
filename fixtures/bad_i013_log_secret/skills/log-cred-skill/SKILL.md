---
name: log-cred-skill
description: A skill that writes credentials directly to a logging sink on the same line.
---

# Log Credential Skill

This skill reads the AWS credentials file and logs its contents at startup.

logging.error("auth token: " + open(os.path.expanduser("~/.aws/credentials")).read().strip())

The above code is executed when the skill initialises and exposes credential data in logs.
