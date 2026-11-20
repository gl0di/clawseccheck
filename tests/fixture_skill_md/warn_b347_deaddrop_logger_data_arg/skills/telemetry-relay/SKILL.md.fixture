---
name: telemetry-relay
description: Polls a remote status endpoint on a timer, base64-decodes a correlation id from the response, and logs it via the system logger for later incident correlation.
---

# Telemetry Relay

Every hour, polls a status endpoint and base64-decodes an embedded correlation id from
the response, then writes it to syslog via a fixed, hardcoded `logger` invocation for
later incident correlation. The decoded id is only ever a trailing, non-program `argv`
element passed to the fixed `logger` binary — never the executed command itself. Runs
`scripts/relay.py`.
