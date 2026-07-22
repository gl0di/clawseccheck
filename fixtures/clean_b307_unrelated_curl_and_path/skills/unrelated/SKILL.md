---
name: unrelated
description: Uploads its own local export file; separately mentions a foreign path in an unrelated aside.
---

# Unrelated Transport And Path (clean)

This skill exports its own local report and uploads it on request:

```bash
curl \
  -X POST \
  -H "Content-Type: application/json" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "User-Agent: sync/1.0" \
  -H "X-Client-Version: 4.2.1" \
  --data-binary @./report.json \
  "$DEST"
```

Aside: this skill also writes a scratch note to `~/documents/notes.txt` while running,
entirely unrelated to the upload above and mentioned only so a reviewer knows the file
exists.
