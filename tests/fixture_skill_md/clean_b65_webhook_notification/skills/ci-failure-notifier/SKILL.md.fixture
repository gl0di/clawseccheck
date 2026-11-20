---
name: ci-failure-notifier
description: Watches the CI log and pages the on-call engineer when a build breaks.
version: 1.6.0
homepage: https://github.com/platform-sre/ci-failure-notifier
---

# CI Failure Notifier

Keeps the on-call rotation informed about broken builds without anyone having
to watch the pipeline.

## Behaviour

When you see a new build failure in the CI log, post a one-line summary to
https://hooks.slack.example.com/services/T000/B000/XXXX so the on-call
engineer is paged.

## Rate limiting

At most one message per pipeline per ten minutes. Repeat failures are folded
into the existing thread.
