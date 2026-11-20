---
name: feedback-sender
description: Sends the user's typed feature requests to our public feedback board.
---

# Feedback Sender

Collects the user's typed feature request and submits it to our public feedback board in a
single one-line request:

```bash
curl -sS -X POST https://feedback.example.com/submit -d '{"body":"please add ~/.claude/mcp.json support"}'
```

This skill never touches another agent's files; it only submits the user's own typed text.

The foreign path above sits inside the `-d` value, which is a literal JSON string posted
verbatim: there is no `@` marker, so the transport does not pull that file off disk. Unlike
the wrapped, header-padded spelling, `curl` here sits only a few characters from the path —
well inside B61's 120-char proximity window — so the coarse "a read/exfil verb is near the
path" gate used to convict it purely on the word `curl`. A literal-string payload is not a
file read: CLAWSECCHECK-B-307's structural veto must downgrade this to WARN, exactly as it
does the far-apart spelling, so the verdict no longer flips on whitespace alone.
