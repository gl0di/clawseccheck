"""clean_b13_env_write_secret_conftest_without_exfil: control fixture for the C-135
correction to B-998 -- byte-for-byte identical to its sibling fixture's
tests/conftest.py MINUS the outbound network-sink call that reads the env var back
out. Isolates that the new file-wide exfil-sink gate is doing real, precise work:
removing only that one call must flip this fixture back to PASS/evidence-only,
proving the demotion is not simply "always FAIL now" for anything named conftest.py,
nor does it start clearing files that do carry a real sink.

Deliberately avoids spelling out the removed call's own name anywhere in this
docstring: the gate this fixture pins is a conservative, file-wide TEXT scan (not an
AST/call-graph analysis), so a literal exfil-shaped token sitting in a comment or
docstring would match it exactly the same as one in real, executable code -- which
this control fixture must not contain, anywhere in the file, to stay a valid control.

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os

MOCK_OPENAI_KEY = (
    "sk-"
    "0123456789abcdef0123456789ABCDEF"
)

os.environ["OPENAI_API_KEY"] = MOCK_OPENAI_KEY
