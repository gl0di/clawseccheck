"""B-596: the packet advertised the entry contract and never the file that carries it back.

Driving the live agent on 2026-08-20, GPT-5.6 Luna followed `SKILL.md`'s guided flow exactly
and still lost its whole 25-verdict panel plus a full `--dashboard --full` re-run, because the
accepted bundle is two levels deep and nothing said so:

    SKILL.md:511  "the file … holding {"judged": {...}}"        <- inner shape elided
    SKILL.md:222  "feed it back as Step 3's judged bucket (see Step 3)"   <- points at the above
    --judge-packet's own output: per-item `verdict_schema` only  <- the ENTRY, not the envelope

Two cross-references forming a loop, and neither end naming `verdicts`. GPT-5.6 Sol inferred it
on the same build and first try — which is the argument FOR fixing it, not against: a documented
flow that only completes on the strongest available host model is not a documented flow.

The envelope now ships as data, attached to the items it describes (`bundleTemplate`), because
prose is what an agent has already summarised away by the time it needs the shape.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from clawseccheck.adjudication import build_bundle_template
from clawseccheck.pipeline import _LIVE_TEST_VERDICTS, split_judged_bundle
from clawseccheck.sar import _VERDICT_VALUES

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")


def _run(tmp_path: Path, *args: str, store: str = "state"):
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", VULN, "--no-history",
         "--data-dir", str(tmp_path / store), *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)})


def _assert_no_bundle_complaint(stderr: str) -> None:
    """Assert what these tests actually mean: the bundle drew no diagnostic.

    They originally asserted `"note:" not in stderr` — the absence of the whole stderr
    advice CHANNEL, to check the absence of one message on it. That happened to be true
    and stopped being true the moment B-605 put the card's relay instruction on the same
    channel. Narrowed to the two diagnostics a bundle can actually provoke: B-330's
    "produced no usable entries" and B-597's misplaced-content note (which names the flag).
    """
    assert "no usable entries" not in stderr, stderr[:400]
    assert "--judged-bundle" not in stderr, stderr[:400]


def _packet(tmp_path: Path) -> dict:
    proc = _run(tmp_path, "--judge-packet")
    return json.loads(proc.stdout)


# ------------------------------------------------------------------ the envelope ships

def test_the_packet_carries_the_envelope_it_expects_back(tmp_path):
    """The whole defect in one assertion: the packet used to describe an entry and not the
    file."""
    packet = _packet(tmp_path)
    assert "bundleTemplate" in packet
    assert packet["bundleTemplate"]["judged"] == {"verdicts": []}


def test_the_template_round_trips_through_the_parser(tmp_path):
    """Not two assertions about one shape — the artifact the packet hands over is fed to the
    thing that reads it, which is the only check that cannot be satisfied by a template that
    merely looks right."""
    template = _packet(tmp_path)["bundleTemplate"]
    dest = tmp_path / "b.json"
    dest.write_text(json.dumps(template), encoding="utf-8")

    proc = _run(tmp_path, "--dashboard", "--full", "--judged-bundle", str(dest), store="s2")
    assert proc.returncode in (0, 1), proc.stderr[:300]
    _assert_no_bundle_complaint(proc.stderr)


def test_the_template_filled_from_a_real_packet_item_is_applied(tmp_path):
    """The round trip that matters to a user: copy an item's ids into the skeleton and the
    verdict lands, rather than the report saying nothing was submitted."""
    packet = _packet(tmp_path)
    item = packet["judgePacket"][0]
    template = packet["bundleTemplate"]
    template["judged"]["verdicts"] = [{
        "finding_id": item["finding_id"], "target": item["target"],
        "verdict": "SAFE", "reason": "checked",
    }]
    dest = tmp_path / "f.json"
    dest.write_text(json.dumps(template), encoding="utf-8")

    proc = _run(tmp_path, "--dashboard", "--full", "--judged-bundle", str(dest), store="s3")
    assert "no verdicts submitted" not in proc.stdout
    _assert_no_bundle_complaint(proc.stderr)


# ------------------------------------------------- it cannot become a rubber stamp

def test_the_template_ships_no_verdict_anyone_could_submit_unchanged():
    """A pre-filled `"verdict": "SAFE"` would round-trip just as well and invite exactly the
    rubber-stamp the judge panel exists to prevent — an agent could submit the template
    untouched and have declared a finding safe without judging it."""
    t = build_bundle_template()
    assert t["judged"]["verdicts"] == []
    assert t["liveTest"]["verdicts"] == []
    assert t["liveTest"]["seed"] is None


def test_the_filled_shapes_live_outside_the_buckets():
    """`entryExample` is illustrative and must never be mistaken for submitted content — it
    sits beside the buckets, not inside them, so the parser never sees it."""
    t = build_bundle_template()
    assert "entryExample" in t
    assert "entryExample" not in t["judged"]
    parsed = split_judged_bundle(json.dumps(t))
    assert parsed["judged"] == {"verdicts": []}


# -------------------------------------------- the vocabulary cannot drift from the parser

def test_the_template_quotes_the_parsers_own_vocabularies():
    """The bug being fixed is a document that disagreed with the code. Re-spelling the
    verdict values by hand would reintroduce it one release later, so they are derived —
    asserted here against the same constants the parser gates on."""
    ex = build_bundle_template()["entryExample"]
    for value in _VERDICT_VALUES:
        assert value in ex["judged"]["verdict"]
    for value in _LIVE_TEST_VERDICTS:
        assert value in ex["liveTest"]["verdicts"][0]["verdict"]


def test_the_entry_example_names_every_required_key():
    """`finding_id`, `target` and `verdict` are what `_parse_verdicts` requires; an example
    missing one is how the next reader builds a bundle that parses to nothing."""
    ex = build_bundle_template()["entryExample"]["judged"]
    for key in ("finding_id", "target", "verdict"):
        assert key in ex


# ----------------------------------------------------------- the docs say it too

def test_skill_md_states_the_two_level_shape():
    """The doc test the task asked for: an agent reading `SKILL.md` alone must be able to
    build an accepted bundle, and the example must not drift from the parser."""
    flat = " ".join((REPO_ROOT / "SKILL.md").read_text(encoding="utf-8").split())
    assert '"judged": { "verdicts": [' in flat or '"judged": {"verdicts": [' in flat, \
        "SKILL.md no longer shows the two-level shape"
    assert "bundleTemplate" in flat


def test_the_reference_and_usage_docs_agree():
    for rel in ("references/cli-flags.md", "docs/USAGE.md"):
        flat = " ".join((REPO_ROOT / rel).read_text(encoding="utf-8").split())
        assert '"judged": {"verdicts"' in flat, rel
        assert "bundleTemplate" in flat, rel


def test_the_seed_caveat_travels_with_the_live_bucket():
    """An unseeded live verdict caps the run you are looking at but never reaches history —
    a distinction that used to be discoverable only in LIVE_INJECTION_CAP's docstring, which
    is not where an agent building a bundle is looking."""
    seed_text = build_bundle_template()["entryExample"]["liveTest"]["seed"]
    assert "--seed" in seed_text and "reproducible" in seed_text
    flat = " ".join((REPO_ROOT / "SKILL.md").read_text(encoding="utf-8").split())
    assert "unseeded VULNERABLE verdict" in flat


# ------------------------------------------------------ the rejection path is intact

def test_a_genuinely_malformed_bundle_is_still_reported(tmp_path):
    """B-330's diagnostic must not have been made unreachable by shipping a template — this
    task removes the NEED for the error, never the error."""
    dest = tmp_path / "bad.json"
    dest.write_text('{"judged": {"nope": []}}', encoding="utf-8")
    proc = _run(tmp_path, "--dashboard", "--full", "--judged-bundle", str(dest), store="s4")
    assert "no usable entries" in proc.stderr, proc.stderr[:400]
