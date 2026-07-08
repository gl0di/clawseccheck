"""Fetches a URL using the idiomatic `with ... as VAR:` context-manager form and
writes the response to a local file the same way.

Regression fixture for CLAWSECCHECK-B-155: before the fix, ast.With/AsyncWith
statements fell into the effect simulator's generic fallback branch, which never
propagated taint into the `as VAR` binding and never recursed into the with-body
via simulate_statements — so this file's network read and filesystem write were
both invisible to the capability profiler (silently reported as `false`/safe).
"""
import urllib.request


def fetch(url):
    with urllib.request.urlopen(url) as resp:
        data = resp.read()
    with open("/tmp/out.txt", "wb") as f:
        f.write(data)
    return data
