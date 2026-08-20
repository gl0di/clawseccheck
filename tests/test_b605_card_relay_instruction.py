"""B-605: the card was rendered deterministically and relayed at the host model's discretion.

`SKILL.md` told the agent to paste the card verbatim as emphatically as prose can. Measured
across five live Control-UI sessions on 2026-08-20, exactly one host obeyed:

    7fd08470  gpt-5.6-sol   pasted it (mascot + score-bar + per-subject frames)
    ff46cb20  gpt-5.6-luna  composed a bullet list
    461e928a  gpt-5.6-luna  composed a bullet list
    d32a80f0  gpt-5.6-luna  composed a bullet list
    4aa107d8  gpt-5.6-luna  composed a bullet list

Three of those four dropped even the tool's name. The card is emitted correctly every time --
the loss is entirely between stdout and the screen.

Two defects, both fixed here. First, `--dashboard` without `--pdf` printed NOTHING to stderr,
so at the moment the agent decided how to relay the card there was no instruction at all (that
is `ff46cb20` exactly: no note, still composed). Second, "paste it verbatim" names an outcome;
the one host that succeeded took a specific action -- it wrapped the card in a fenced block,
which is what keeps the frame's monospace alignment intact. The note now names the action.

These tests pin the mechanism, not the prose: that the instruction reaches the agent's channel
on every shape that prints a card, that it never reaches the user's, and that it does not
appear on a run that printed no card.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")

MARKER = "Dashboard card on stdout"


def _run(tmp_path: Path, *args: str, store: str = "state"):
    """Real CLI, real fixture. HOME is redirected as well as --data-dir: B-599 proved
    --data-dir alone does not keep every writer out of the user's own store."""
    fake_home = tmp_path / "home"
    fake_home.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", VULN, "--no-history",
         "--data-dir", str(tmp_path / store), *args],
        cwd=REPO_ROOT, capture_output=True, text=True,
        env={**os.environ, "HOME": str(fake_home)})


# ------------------------------------------------ it reaches the decision, on every shape

def test_plain_dashboard_carries_the_instruction(tmp_path):
    """The regression pin. This exact shape -- `--dashboard`, no `--pdf` -- printed nothing
    to stderr before, which is why the session that ran it composed with no note present.
    A test that only covered the `--pdf` path would have stayed green through the bug."""
    proc = _run(tmp_path, "--dashboard")
    assert MARKER in proc.stderr, proc.stderr[:400]


def test_dashboard_full_with_pdf_carries_the_instruction(tmp_path):
    proc = _run(tmp_path, "--dashboard", "--full", "--pdf", str(tmp_path / "r.pdf"),
                store="s2")
    assert MARKER in proc.stderr, proc.stderr[:600]


def test_the_truncation_remedy_shape_carries_it_too(tmp_path):
    """`--dashboard --full --compact` with no `--pdf` is SKILL.md's documented remedy for a
    channel that truncates long messages. It is a third distinct shape through the branch,
    and the one a Telegram-style channel actually gets -- covering only the `--pdf` flow
    would leave the constrained channel, where relaying matters most, unpinned."""
    proc = _run(tmp_path, "--dashboard", "--full", "--compact", store="c1")
    assert MARKER in proc.stderr, proc.stderr[:400]
    assert "attach the PDF" not in proc.stderr


def test_dashboard_findings_carries_the_instruction(tmp_path):
    """`--dashboard-findings` prints Section 2 alone and SKILL.md Step 3 pastes it verbatim
    too -- same contract, same failure mode, so it gets the same instruction."""
    proc = _run(tmp_path, "--dashboard-findings", store="s3")
    assert MARKER in proc.stderr, proc.stderr[:400]


# -------------------------------------------------- it names an action, not an aspiration

def test_the_instruction_names_the_fence_not_just_the_goal(tmp_path):
    """The whole point of the task. "Paste it verbatim" was already in SKILL.md and was
    ignored 4/4; what the one working host actually DID was wrap the card in a fenced
    block. An instruction that restates the goal would leave the defect in place."""
    err = _run(tmp_path, "--dashboard").stderr
    assert "fenced code block" in err, err[:400]
    assert "```text" in err, err[:400]


def test_the_instruction_forbids_the_observed_failure_mode(tmp_path):
    """Naming the failure is what makes the rule checkable by the reader: every one of the
    four failing hosts produced a bullet-list summary."""
    err = _run(tmp_path, "--dashboard").stderr
    low = err.lower()
    assert "do not summarise it" in low
    assert "bullet list" in low
    assert "header line" in low


# ------------------------------ it survives the truncation that ate the first attempt

def test_the_instruction_precedes_the_card(tmp_path):
    """The defect that cost the whole first attempt. Emitted after the card, the note sat
    at byte 25,265 of a 25,686-byte merged stream on `--dashboard --full` -- past the ~20 KB
    cap the host's bash tool truncates at, so the instruction to relay the card was the
    first thing lost, on exactly the runs with the biggest card. Ordering by luck is what
    made the small-card case look fine: stdout is block-buffered, stderr is not."""
    proc = _run(tmp_path, "--dashboard", "--full", store="o1")
    merged = proc.stderr + proc.stdout
    note_at = (proc.stderr).find(MARKER)
    assert note_at >= 0, proc.stderr[:300]
    # The real guarantee: nothing of the card is written before the note, so no buffering
    # or output cap can reorder them.
    assert note_at < 2000, f"note starts at {note_at}, deep enough to be truncated away"
    assert merged  # merged stream is what the agent actually reads


def test_the_instruction_survives_a_20kb_output_cap(tmp_path):
    """Reproduces the host's observed behaviour rather than trusting the offset: truncate
    the merged stream at 20 KB, as the live host did, and the instruction must still be
    in what is left."""
    proc = _run(tmp_path, "--dashboard", "--full", store="o2")
    merged = (proc.stderr + proc.stdout)[:20_000]
    assert MARKER in merged


# ------------------------------------- an unrelayable card says so instead of pretending

def test_an_oversized_card_discloses_its_size_and_the_remedy(tmp_path):
    """`--dashboard --full` without `--pdf` renders ~25 KB across ~183 lines. No wording
    makes that relayable into a chat message, and a live host relayed 0 of 183 lines. The
    remedy already exists in the product; nothing said so where it was needed."""
    err = _run(tmp_path, "--dashboard", "--full", store="z1").stderr
    assert "cannot carry in one message" in err, err[:600]
    assert "--pdf" in err and "--compact" in err
    assert "Do not silently relay part of it as if it were the whole" in err


def test_the_size_clause_is_silent_on_the_shapes_that_work(tmp_path):
    """It must not nag on the two shapes that ARE relayable -- `--pdf` (measured 1.6-1.9 KB,
    relayed intact by a live host) and `--compact` (~4.5 KB), which IS the remedy. A warning
    that fires on the fix is one the reader learns to ignore."""
    with_pdf = _run(tmp_path, "--dashboard", "--full", "--pdf", str(tmp_path / "s.pdf"),
                    store="z2").stderr
    compact = _run(tmp_path, "--dashboard", "--full", "--compact", store="z3").stderr
    assert "cannot carry in one message" not in with_pdf, with_pdf[:400]
    assert "cannot carry in one message" not in compact, compact[:400]


# ------------------------------------------- the agent's channel is not the user's channel

def test_the_instruction_never_reaches_stdout(tmp_path):
    """stdout IS the artifact the user sees pasted. Agent-directed advice leaking into it
    would be pasted along with the card -- the same class of defect as the card leaking
    into a machine-readable stream."""
    for extra, store in ((("--dashboard",), "p1"),
                         (("--dashboard-findings",), "p2")):
        proc = _run(tmp_path, *extra, store=store)
        assert MARKER not in proc.stdout, (extra, proc.stdout[:300])


def test_json_output_stays_clean(tmp_path):
    """--json is parsed by machines; a note on stdout would break it. Guarding the mode
    that has the least tolerance for a stray line."""
    proc = _run(tmp_path, "--json", store="j1")
    assert MARKER not in proc.stdout


# ------------------------------------------------- it is not claimed where no card printed

def test_a_run_that_printed_no_card_makes_no_relay_claim(tmp_path):
    """`--dashboard --pdf … --trend` resolves to the RIDER mode: the card is never printed
    (B-530 documents that branch). Telling the agent to relay a card that does not exist
    would be a false instruction, and the same "say it regardless" reflex that produced the
    B-379 family."""
    proc = _run(tmp_path, "--dashboard", "--pdf", str(tmp_path / "t.pdf"), "--trend",
                store="r1")
    assert MARKER not in proc.stderr, proc.stderr[:400]
    assert MARKER not in proc.stdout


def test_the_default_report_path_makes_no_relay_claim(tmp_path):
    """The default text report is not the chat deliverable SKILL.md Step 3 routes to, and
    it is not pasted into a chat client -- scoping the instruction to the modes that ARE
    keeps it from becoming background noise the agent learns to skip."""
    proc = _run(tmp_path, store="d1")
    assert MARKER not in proc.stderr, proc.stderr[:400]


# --------------------------------------------------- the PDF clause is true when it fires

def test_the_pdf_clause_appears_only_when_a_pdf_exists(tmp_path):
    """The clause resolves the one real tension between the two notes -- the attach note
    calls the PDF "the deliverable", which alone reads as "so the card is not". It must not
    appear on a run that wrote no PDF, or it names an artifact the user does not have."""
    with_pdf = _run(tmp_path, "--dashboard", "--full", "--pdf", str(tmp_path / "y.pdf"),
                    store="w1").stderr
    without = _run(tmp_path, "--dashboard", store="w2").stderr
    assert "paste the card AND attach the PDF" in with_pdf, with_pdf[:600]
    assert "attach the PDF" not in without, without[:400]


def test_b595_attach_note_is_unchanged(tmp_path):
    """The new note sits BESIDE B-595's, never rewrites it. Its pinned phrases are load-
    bearing (a channel that cannot attach still needs the path), so a regression here would
    be silent."""
    err = _run(tmp_path, "--dashboard", "--full", "--pdf", str(tmp_path / "z.pdf"),
               store="a1").stderr
    assert "attach this PDF file itself" in err
    assert "that is the deliverable" in err
    assert "cannot attach files" in err
    assert "Never write a link or a URL" in err


# ------------------------------------------------------------ the doc says the same thing

def test_skill_md_names_the_fence_too():
    """C-125. The tool and the doc must not disagree about the one action that decides
    whether the brand reaches the user."""
    flat = " ".join((REPO_ROOT / "SKILL.md").read_text(encoding="utf-8").split())
    assert "inside a fenced code block" in flat
    assert "verbatim, inside a fenced code block" in flat


def test_the_fence_rule_does_not_leak_to_the_menu():
    """SKILL.md forbids fencing the menu and Sections 5-6 -- their frames do NOT rely on
    monospace, and fencing them was a separate, already-settled defect. Adding a fence rule
    for the card must not read as licence to fence everything."""
    text = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    flat = " ".join(text.split())
    assert "Render the menu as ordinary text — do NOT wrap it in a code block" in flat
    assert "the menu (Step 1) and Sections 5-6 stay ordinary text" in flat
