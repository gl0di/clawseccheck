from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit, render_json, render_report


def _seed_home(tmp_path: Path) -> Path:
    home = tmp_path / ".openclaw"
    home.mkdir()
    cfg = {
        "auth": {"profiles": {"google:owner@example.com": {}, "github:bot": {}}},
        "gateway": {"auth": {"token": "g" * 32}},
        "mcp": {
            "servers": {
                "local": {
                    "command": "node",
                    "args": [],
                    "env": {"*": "*"},
                    "tokenPassthrough": True,
                }
            }
        },
    }
    (home / "openclaw.json").write_text(json.dumps(cfg), encoding="utf-8")
    (home / ".env").write_text("API_TOKEN=env-secret\n", encoding="utf-8")
    (home / "workspace-home").mkdir()
    (home / "workspace-home" / ".envrc").write_text("export WORKSPACE_SECRET=1\n", encoding="utf-8")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_rsa").write_text("PRIVATE-KEY", encoding="utf-8")
    (home / ".config" / "google-chrome" / "Default").mkdir(parents=True)
    (home / ".config" / "google-chrome" / "Default" / "Cookies").write_text("cookie", encoding="utf-8")
    (home / "Library" / "Keychains").mkdir(parents=True)
    return home


def test_secret_reachability_map_is_in_json_and_report(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "runtime-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-runtime-secret")

    ctx, findings, score = audit(_seed_home(tmp_path), include_native=False, include_host=False)

    body = render_json(findings, score, ctx=ctx)
    data = json.loads(body)
    classes = {item["class"] for item in data["secret_reachability"]}

    assert {"env", ".env", "keychain", "cookies", "ssh", "cloud", "mcp-passthrough"} <= classes
    assert any(item["reachable"] for item in data["secret_reachability"])
    assert "runtime-secret" not in body
    assert "aws-runtime-secret" not in body

    report = render_report(findings, score, ctx=ctx)
    assert "Secret reachability map" in report
    assert "mcp-passthrough" in report
