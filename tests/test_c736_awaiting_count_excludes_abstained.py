"""C-736: the card said "235 item(s) awaiting adjudication ... 25 item(s) abstained" for a packet
of 235 - the abstained items were counted as awaiting too. They are in the packet but nobody is
waiting on them, so the awaiting count excludes them."""
from __future__ import annotations

import json

from clawseccheck.cli import main

HOME = "fixtures/home_vuln"


def _packet(capsys):
    main(["--home", HOME, "--judge-packet", "--no-history", "--no-host", "--no-deptree",
          "--no-native", "--no-sockets"])
    return json.loads(capsys.readouterr().out)["judgePacket"]


def test_abstained_items_are_not_counted_as_awaiting(capsys, tmp_path):
    packet = _packet(capsys)
    abst = [i for i in packet if "abstain" in i.get("verdict_schema", {})]
    assert abst and len(abst) < len(packet)
    bundle = tmp_path / "b.json"
    bundle.write_text(json.dumps({"judged": {"verdicts": [
        {"finding_id": i["finding_id"], "target": i["target"], "verdict": "ABSTAIN"} for i in abst]}}),
        encoding="utf-8")
    main(["--home", HOME, "--full", "--json", "--no-history", "--no-host", "--no-deptree",
          "--no-native", "--no-sockets", "--judged-bundle", str(bundle)])
    out = capsys.readouterr().out
    detail = [ln for ln in out.splitlines() if "awaiting adjudication" in ln]
    text = " ".join(detail)
    assert f"{len(packet) - len(abst)} item(s) awaiting adjudication" in text, text
    assert f"{len(abst)} item(s) abstained" in text, text
