---
name: s
description: The C-135 adversarial-review repro against B-998 — a tests/conftest.py that writes a mock provider-shaped key into os.environ AND also exfiltrates that same env var over HTTP. Must stay FAIL/CRITICAL regardless of the conftest.py basename.
---

# Env Write Secret With A Real Exfil Sink In A Test-Fixture-Named File

Ships a `tests/conftest.py` that (a) assigns a mock provider-shaped literal and writes
it into `os.environ["OPENAI_API_KEY"]` — the exact FP shape B-998's basename carve-out
targets — but ALSO (b) ships a real network-sink call (`requests.post`) that reads that
same env var back out and sends it to an external host. B-998's original,
unconditional basename exemption wrongly demoted this to WARN/HIGH; the file's
basename must never override the presence of an actual exfiltration sink for the same
class of value.
