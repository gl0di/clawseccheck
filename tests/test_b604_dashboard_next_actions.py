"""B-604: the Dashboard was the one verdict surface that offered the user nothing.

`--next` and the default report path both render `guide.render_next_actions`. The
`--dashboard` branch returned before reaching either, so the mode `SKILL.md` Step 3
designates as THE user-facing deliverable ended at its last findings section. Measured on
the real config: a card stating Grade F, 49/100 and two open CRITICALs, and then nothing to
do about them. Same shape as the B-379 family -- a mode branch returning early and missing
what the main path does.

`SKILL.md` does design an offer here (Step 3's "Section 6 -- Next menu"), but as prose the
host agent is asked to compose, and across four live Control-UI runs it reached the user
**0 of 4** -- no menu, no monitoring offer, no closing question. That is why this is wired
into the render rather than left to the document: across those same four runs the tool's
own CONTENT was relayed 4/4 (grade, score, the cap from 86, the live verdict) while prose
the host was asked to author was not.

Note on measurement: absolute character counts on the REAL config drift between runs (the
number of log sinks reached varies), so every size assertion here uses a fixture.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")

BLOCK = "What you can do next"


def _run(tmp_path: Path, *args: str, store: str = "state", home: str = VULN):
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", home, "--no-history",
         "--data-dir", str(tmp_path / store), *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)})


def _attest(tmp_path: Path) -> str:
    p = tmp_path / "att.json"
    p.write_text('{"schema":"clawseccheck-attest/1","tools":["exec_command"],'
                 '"proven_tools":[],"approval_gates":{"exec":"auto","send":"auto",'
                 '"write":"auto"},"approval_bypass_actors":[],'
                 '"untrusted_to_action":"ungated","host_monitors":[],'
                 '"paths":{"bootstrap":[],"openclaw_install":"/x"},"agents":[],'
                 '"delegation":[],"notes":"t"}', encoding="utf-8")
    return str(p)


def _bundle(tmp_path: Path) -> str:
    p = tmp_path / "bun.json"
    p.write_text('{"judged":{"verdicts":[]},"liveTest":{"seed":"b604","verdicts":'
                 '[{"tool":"canary","id":"canary","verdict":"RESISTANT"}]}}', encoding="utf-8")
    return str(p)


# ------------------------------------------------------- it reaches every dashboard shape

def test_plain_dashboard_offers_next_actions(tmp_path):
    """The regression pin: this shape ended at its last findings section."""
    proc = _run(tmp_path, "--dashboard")
    assert BLOCK in proc.stdout, proc.stdout[-400:]


def test_dashboard_full_offers_next_actions(tmp_path):
    proc = _run(tmp_path, "--dashboard", "--full", store="s2")
    assert BLOCK in proc.stdout, proc.stdout[-400:]


def test_the_graded_shape_offers_next_actions(tmp_path):
    """The shape SKILL.md's guided flow actually produces -- all five layers, a letter on
    the card. Covering only the ungraded default would leave the real deliverable unpinned."""
    proc = _run(tmp_path, "--dashboard", "--full", "--attest", _attest(tmp_path),
                "--judged-bundle", _bundle(tmp_path), "--pdf", str(tmp_path / "r.pdf"),
                store="s3")
    assert BLOCK in proc.stdout, proc.stdout[-400:]


def test_ascii_mode_offers_next_actions(tmp_path):
    proc = _run(tmp_path, "--dashboard", "--ascii", store="s4")
    assert BLOCK in proc.stdout
    assert "\U0001f99e" not in proc.stdout


# ------------------------------------------- it is part of the card, not a separate print

def test_the_block_is_inside_the_card_the_user_pastes(tmp_path):
    """It goes on stdout, inside the payload the B-605 relay instruction covers -- not on
    stderr beside it. An offer the host is not asked to relay is an offer the user never
    sees, which is the whole reason Section 6's prose version reached 0 of 4 live runs."""
    proc = _run(tmp_path, "--dashboard", store="i1")
    assert BLOCK in proc.stdout
    assert BLOCK not in proc.stderr


def test_the_disclosed_card_size_counts_the_block(tmp_path):
    """B-605's size disclosure reports the card's own length. Appending the block beside
    the card instead of into it would leave that number describing something smaller than
    what is printed -- a disclosure lying about the thing it discloses."""
    proc = _run(tmp_path, "--dashboard", "--full", store="i2")
    m = re.search(r"This card is ([\d,]+) characters", proc.stderr)
    assert m, proc.stderr[:500]
    disclosed = int(m.group(1).replace(",", ""))
    # stdout is the card plus the single newline `print` adds.
    assert abs(disclosed - len(proc.stdout)) <= 1, (disclosed, len(proc.stdout))
    assert BLOCK in proc.stdout


# ------------------------------------------------ the offer knows what kind of run it was

def test_an_ungraded_run_does_not_offer_a_grade_it_does_not_have(tmp_path):
    """`guide.suggest_actions` already adapts to `ScoreResult.graded`; this pins that the
    dashboard passes it the REAL score object rather than a default. On an ungraded run the
    badge item must say so instead of implying a letter exists."""
    out = _run(tmp_path, "--dashboard", store="g1").stdout
    tail = out[out.index(BLOCK):]
    assert "no grade" in tail.lower(), tail[-600:]


def test_a_graded_run_offers_the_grade(tmp_path):
    """The mirror. Together these two prove the block is keyed to this run's actual score
    state -- a block that read the same either way would tell us nothing."""
    out = _run(tmp_path, "--dashboard", "--full", "--attest", _attest(tmp_path),
               "--judged-bundle", _bundle(tmp_path), store="g2").stdout
    tail = out[out.index(BLOCK):]
    assert "no grade" not in tail.lower(), tail[-600:]


def test_the_offers_are_derived_from_findings_not_a_fixed_list(tmp_path):
    """`suggest_actions` gates each item on a finding, so the block must change when the
    finding does. The discriminator is chosen from what actually differs, not from what
    ought to: `home_safe` and `home_vuln` produce an IDENTICAL block here, because the two
    gating checks are B16 (host monitoring -- a property of this machine, not of the fixture)
    and B13 (needs installed skills, which neither fixture has). Declaring host monitors via
    `--attest` resolves B16 and drops the monitoring item, which is a difference the fixtures
    can actually express."""
    without = _run(tmp_path, "--dashboard", store="d1").stdout
    att = tmp_path / "mon.json"
    att.write_text('{"schema":"clawseccheck-attest/1","tools":["exec_command"],'
                   '"proven_tools":[],"approval_gates":{"exec":"auto","send":"auto",'
                   '"write":"auto"},"approval_bypass_actors":[],'
                   '"untrusted_to_action":"ungated","host_monitors":["kauditd","falcon"],'
                   '"paths":{"bootstrap":[],"openclaw_install":"/x"},"agents":[],'
                   '"delegation":[],"notes":"t"}', encoding="utf-8")
    with_mon = _run(tmp_path, "--dashboard", "--attest", str(att), store="d2").stdout
    assert BLOCK in without and BLOCK in with_mon
    assert "Turn on ongoing monitoring" in without
    assert "Turn on ongoing monitoring" not in with_mon[with_mon.index(BLOCK):], \
        "monitoring still offered after the attestation resolved B16"


# ------------------------------------ the constrained channel gets guidance, not silence

def test_compact_condenses_the_block_instead_of_dropping_it(tmp_path):
    """`--compact` exists to fit a message-capped channel. Appending the full 919-char block
    broke that outright -- `home_vuln` already renders 3,881 of Telegram's 4,096 there, which
    the existing budget test caught on the first suite run. Dropping the block instead would
    recreate B-604 on the one channel where a phone-sized reader most needs the guidance, so
    it condenses to a pointer, the way this mode already condenses its pipeline detail."""
    out = _run(tmp_path, "--dashboard", "--full", "--compact", store="c1").stdout
    assert BLOCK in out, out[-300:]
    assert "run --next" in out
    assert "Turn on ongoing monitoring" not in out, "full block still rendered under --compact"


def test_the_compact_card_still_fits_the_message_budget(tmp_path):
    """Pinned here as well as in `test_dashboard_card.py`, because that budget is the whole
    reason the compact form exists and the two tests would otherwise drift apart. Characters,
    not bytes -- the card is full of multi-byte box art and a byte count reads ~10% high."""
    for fixture, store in (("home_vuln", "c2"), ("home_safe", "c3")):
        out = _run(tmp_path, "--dashboard", "--full", "--compact", store=store,
                   home=str(REPO_ROOT / "fixtures" / fixture)).stdout
        assert len(out) <= 4096, (fixture, len(out))


def test_the_pointer_is_fixed_length_not_finding_derived(tmp_path):
    """Naming the top action would be more useful and would make the pointer's length vary
    with the finding -- and the problem being solved is a budget with no room to vary. Same
    string on a config whose actions differ."""
    plain = _run(tmp_path, "--dashboard", "--full", "--compact", store="c4").stdout
    att = tmp_path / "mon2.json"
    att.write_text('{"schema":"clawseccheck-attest/1","tools":["exec_command"],'
                   '"proven_tools":[],"approval_gates":{"exec":"auto","send":"auto",'
                   '"write":"auto"},"approval_bypass_actors":[],'
                   '"untrusted_to_action":"ungated","host_monitors":["kauditd","falcon"],'
                   '"paths":{"bootstrap":[],"openclaw_install":"/x"},"agents":[],'
                   '"delegation":[],"notes":"t"}', encoding="utf-8")
    with_mon = _run(tmp_path, "--dashboard", "--full", "--compact", "--attest", str(att),
                    store="c5").stdout
    line = "What you can do next: run --next for the ranked list."
    assert line in plain and line in with_mon


# -------------------------------------------------------------- scoped to the card itself

def test_dashboard_findings_stays_the_findings_block_alone(tmp_path):
    """`--dashboard-findings` prints Section 2 ALONE and SKILL.md offers it for exactly
    that. Appending an offer would change what "the findings block" means for every caller
    that asked for only it."""
    proc = _run(tmp_path, "--dashboard-findings", store="f1")
    assert BLOCK not in proc.stdout


def test_the_findings_are_unchanged_by_adding_the_block(tmp_path):
    """Verdict neutrality where it counts: this adds a rendered section, never a finding.
    The JSON verdict surface must be untouched."""
    proc = _run(tmp_path, "--json", store="n1")
    assert BLOCK not in proc.stdout


# ---------------------------------------------------------------------- the doc agrees

def test_skill_md_lists_the_block_in_the_fixed_order():
    """C-125. SKILL.md states the card's section order (F-153) as exhaustive; a section the
    tool prints and the list omits makes the doc false for every reader after this."""
    flat = " ".join((REPO_ROOT / "SKILL.md").read_text(encoding="utf-8").split())
    assert "What you can do next" in flat
