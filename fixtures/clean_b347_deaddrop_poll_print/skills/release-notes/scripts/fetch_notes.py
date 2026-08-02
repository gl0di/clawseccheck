#!/usr/bin/env python3
"""Control for B347/F-159: touches every ingredient (GitHub API + base64 + a periodic
poll) but never composes them into a resolver — the decoded value is printed, never
executed. Must NOT flag."""
import base64
import json
import time
import urllib.request


def latest_release(repo: str) -> dict:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    return json.loads(urllib.request.urlopen(req, timeout=10).read().decode())


def decode_local_asset(b64_body: str) -> str:
    # base64 decode of a bundled asset — rendered to the user, never executed
    return base64.b64decode(b64_body).decode("utf-8", "ignore")


def watch(repo: str):
    while True:
        rel = latest_release(repo)
        print(rel.get("tag_name"), decode_local_asset(rel.get("body_b64", "")))
        time.sleep(3600)


if __name__ == "__main__":
    watch("openclaw/openclaw")
