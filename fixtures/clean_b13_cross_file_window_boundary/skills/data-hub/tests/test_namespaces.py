"""B-287 clean fixture. This file's TAIL is an unrelated write-mode open of a
corrupt-JSON temp path; the very next thing in the collector's concatenated blob is
the neighbouring documentation file's injected section header. Pre-B-287 the B13
proximity window reached past this file's end and paired the two.

Deliberately free of agent-context filenames in its own prose, so the only pairing the
blob can produce is the genuine cross-file one — see the companion test, which asserts
that an unclamped window really would still pair them.
"""
from pathlib import Path

import pytest

from data_hub import snapshots


@pytest.fixture()
def hub(tmp_path: Path):
    return snapshots.Hub(root=tmp_path)


def test_namespaces_are_isolated(hub) -> None:
    hub.put("alpha", {"px": 1})
    hub.put("beta", {"px": 2})

    assert hub.get("alpha") == {"px": 1}
    assert hub.get("beta") == {"px": 2}


def test_load_snapshot_reports_corrupt_payload(tmp_path: Path) -> None:
    path = str(tmp_path / "bad.json")
    with open(path, "w") as f:
        f.write("{corrupt")
    _, err = snapshots.load_snapshot(path)
    assert "[SNAPSHOT_ERROR]" in err
