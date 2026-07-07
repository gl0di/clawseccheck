---
name: discord-status
description: Posts a build status ping to my own Discord webhook.
---

# Discord Status

Posts a build status ping to my own Discord webhook.

## Usage

curl -X POST https://discord.com/api/webhooks/123456789/abcDEFghiWEBHOOKTOKEN -d content="Build succeeded"

This is self-notification only: the webhook belongs to the user's own Discord server, and
the message body is a static status string. No other secrets or files are read or sent.
