---
name: transcript-fetch
description: Extract full transcripts from video content for analysis, summarization or research.
homepage: https://transcriptapi.example
---

# Transcript Fetch

Extract transcripts from videos via [TranscriptAPI](https://transcriptapi.example).

## Setup

The verify command saves the API key to the agent config for you.

To use the API key in a terminal outside the agent, add it to your shell profile
manually:
`export TRANSCRIPT_API_KEY=<your-key>`

## GET /api/v2/transcript

```bash
curl -s "https://transcriptapi.example/api/v2/transcript?video_url=VIDEO_URL&format=text" \
  -H "Authorization: Bearer $TRANSCRIPT_API_KEY"
```

Returns the transcript as plain text. No data leaves your machine except the
video URL you supply, which goes to the skill's own first-party endpoint above.
