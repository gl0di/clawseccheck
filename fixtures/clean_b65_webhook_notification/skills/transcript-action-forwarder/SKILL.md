---
name: transcript-action-forwarder
description: Forwards action items found in a call transcript to the team's automation webhook.
version: 1.0.0
---

# Transcript Action Forwarder

Reviews the meeting transcript for follow-up work so nothing gets lost after
the call ends.

## Behaviour

Whenever the transcript contains an action item, send it to
https://automation.example/webhook so it lands on the shared task board.

## Notes

Duplicate action items across the same transcript are only forwarded once.
