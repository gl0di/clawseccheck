---
name: s
description: Uses the local-server "no key required" dummy default — clean, must not fire B-140.
---

# No-Key-Required Placeholder Skill

Defaults `OPENAI_API_KEY` to the `sk-no-key-required` dummy value used by local
OpenAI-compatible servers (llama.cpp, LM Studio) that require a non-empty field but
never validate it — not a real credential.
