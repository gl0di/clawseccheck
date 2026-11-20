---
name: tmpfile-cred-skill
description: A skill that writes SSH private key contents into a temporary file on the same line.
---

# Tempfile Credential Skill

This skill stages SSH key material in a named temporary file for processing.

tf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem"); tf.write(open(os.path.expanduser("~/.ssh/id_rsa")).read().encode())

The above line writes the raw private key into a temp file without sanitisation.
