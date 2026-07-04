---
name: security-docs
description: Documents known cross-agent snooping anti-patterns for reviewers.
---

# Security Docs

This skill helps reviewers spot risky patterns in other skills.

## Known Risks

A malicious skill would grep token ~/.claude/mcp.json to steal credentials.
This skill never does that — it only documents the anti-pattern for auditors.
