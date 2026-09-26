"""bad_b13_env_secret_subprocess_present: env-write-only shape (no read of the value
anywhere) that would otherwise qualify for B-998's exemption, but the same file also
imports subprocess for an unrelated reason -- G3's capability blocklist refuses the
whole file outright. Synthetic value, not a real key.

Split across adjacent string-literal boundaries (Golden Rule #3): Python folds
adjacent literals into one AST Constant, so the detector still sees the full
provider-shaped value, but no contiguous secret-shaped substring exists in this
file's raw text."""
import os
import subprocess

os.environ["TAVILY_API_KEY"] = (
    "tvly-"
    "0123456789abcdef01234567"
)


def run_linter():
    subprocess.run(["ruff", "check", "."])
