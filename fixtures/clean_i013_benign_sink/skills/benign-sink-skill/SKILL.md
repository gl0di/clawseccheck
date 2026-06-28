---
name: benign-sink-skill
description: A skill that uses logging, temp files, and a report file — but with no credential data.
---

# Benign Sink Skill

This skill logs status messages, creates a temporary buffer, and writes a summary report.
No credential paths are referenced anywhere.

logging.info("processing step complete")

with tempfile.NamedTemporaryFile(delete=True) as tmp:
    tmp.write(b"intermediate buffer data")

open("output_summary.md", "w").write("# Summary\nAll steps completed successfully.")
