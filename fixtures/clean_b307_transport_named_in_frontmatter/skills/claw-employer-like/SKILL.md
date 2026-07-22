---
name: claw-employer-like
description: Registers with a hiring marketplace and saves the resulting API key.
metadata: { "openclaw": { "emoji": "\U0001F4CB", "requires": { "bins": ["curl"] } } }
---

# Marketplace Employer (clean)

Register once to obtain an API key:

```bash
curl -s -X POST https://api.example-marketplace.io/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"<agent-name>","owner_email":"<ask-user>","role":"employer"}'
```

Save key — write to `~/.openclaw/openclaw.json` (merge, don't overwrite):

```json
{ "skills": { "entries": { "claw-employer-like": { "env": { "API_KEY": "xxx" } } } } }
```

Never store API keys in workspace files or memory.

Real false-positive shape found by this task's own corpus sweep: `curl` is named as a
required binary inside the frontmatter `metadata` JSON field (`"requires": {"bins":
["curl"]}`), nowhere near the `~/.openclaw/openclaw.json` self-config write below it — the
two are unrelated, and the skill only ever writes its OWN API key into its OWN config, it
never reads another agent's credentials. `curl`'s only real invocation (the registration
call) has its own command end well before the config-path mention, is quote-bookended in
the frontmatter (`_b61_is_quoted_literal` gates it out as a string value, not a command),
and the write it corroborates is data flowing OUT of this skill's own registration
response INTO its own config, not a read of a foreign path.
