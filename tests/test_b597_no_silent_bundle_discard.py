"""B-597: a misplaced `verdicts` key threw the whole judge panel away in silence.

Driving the live agent on 2026-08-20, `--dashboard --full` printed **Grade F 49/100**, the
agent told the user its mandatory judge panel had been applied, and the report said::

    · Second opinion (advisory) ·
    • 87 item(s) awaiting adjudication — no verdicts submitted.

The bundle it had just read::

    top-level keys: ['liveTest', 'verdicts']      # 'judged' absent

25 verdicts, discarded, with no note anywhere. "No verdicts submitted" is a false statement
about a file the tool parsed — Golden Rule #4 — and the `liveTest` bucket in the same file
*was* applied, which is why nothing looked wrong from the outside.

The shape is not one a user invents. `_parse_verdicts` told the agent its bundle "has no
top-level 'verdicts' array" — a sentence about the inside of the `judged` object — so the
agent moved the array to the file's top level. The tool is loud about a malformed inner
object and was silent about the misplacement its own message taught.

Two changes, and this file pins the INVARIANT behind both rather than their wording: no
recognisable bundle content is ever dropped without the run saying so, and "no verdicts
submitted" is printed only when the file genuinely carried none.

Offline, writes nothing outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from clawseccheck.adjudication import _parse_verdicts
from clawseccheck.pipeline import split_judged_bundle

REPO_ROOT = Path(__file__).resolve().parents[1]
VULN = str(REPO_ROOT / "fixtures" / "home_vuln")

_ENTRY = {"finding_id": "B101", "target": "B101", "verdict": "SAFE", "reason": "x"}
_LIVE = {"seed": "s", "verdicts": [{"tool": "canary", "id": "canary", "verdict": "RESISTANT"}]}


def _split(obj, capsys) -> tuple[dict, str]:
    out = split_judged_bundle(json.dumps(obj))
    return out, capsys.readouterr().err


def _run(tmp_path: Path, obj) -> subprocess.CompletedProcess:
    bundle = tmp_path / "b.json"
    bundle.write_text(json.dumps(obj), encoding="utf-8")
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", VULN, "--dashboard", "--full",
         "--judged-bundle", str(bundle),
         "--data-dir", str(tmp_path / "state"), "--no-history"],
        cwd=REPO_ROOT, capture_output=True, text=True)


# ------------------------------------------------------------------ the headline case

def test_a_misplaced_verdicts_array_is_never_dropped_in_silence(capsys):
    """The invariant. Whether it is accepted or refused is a design choice; being silent
    about it is not."""
    out, err = _split({"verdicts": [_ENTRY]}, capsys)
    assert err.strip(), "the run discarded recognisable content and said nothing"
    assert out["judged"] is not None


def test_the_report_no_longer_claims_no_verdicts_were_submitted(tmp_path):
    """End to end, through the real CLI. This is the sentence that was false."""
    proc = _run(tmp_path, {"verdicts": [_ENTRY]})
    assert "no verdicts submitted" not in proc.stdout
    assert "verdicts" in proc.stderr


def test_the_exact_live_run_shape(tmp_path, capsys):
    """`{"liveTest": …, "verdicts": […]}` — what the agent actually wrote. The liveTest
    bucket applying is precisely what made the loss invisible, so assert BOTH: it still
    applies, and the judged half is no longer lost beside it."""
    out, err = _split({"liveTest": _LIVE, "verdicts": [_ENTRY]}, capsys)
    assert out["liveTest"] == _LIVE, "F-155 bucket must be untouched by this fix"
    assert out["judged"] == {"verdicts": [_ENTRY]}
    assert err.strip()


# ------------------------------------------------------------- the deliberate choices

def test_an_explicit_judged_bucket_always_wins(capsys):
    """Guessing is a last resort, never a peer. If both are present the documented shape
    is authoritative — and the one that was ignored is still reported."""
    explicit = {"verdicts": [{"finding_id": "A", "target": "A", "verdict": "SAFE"}]}
    stray = [{"finding_id": "B", "target": "B", "verdict": "DANGEROUS"}]
    out, err = _split({"judged": explicit, "verdicts": stray}, capsys)
    assert out["judged"] == explicit
    assert "ignored" in err


def test_a_correct_bundle_is_unchanged_and_silent(capsys):
    """No new noise on the shape everyone should be writing — a diagnostic that fires on
    valid input is a diagnostic people learn to ignore."""
    good = {"judged": {"verdicts": [_ENTRY]}, "liveTest": _LIVE}
    out, err = _split(good, capsys)
    assert out["judged"] == good["judged"] and out["liveTest"] == _LIVE
    assert err == ""


def test_a_file_whose_keys_are_all_unrecognised_says_so(capsys):
    """The other way to lose a whole file quietly. B-562 covers a path that could not be
    READ; this is one that parsed into nothing."""
    out, err = _split({"judgements": [1], "notes": "x"}, capsys)
    assert all(not out[k] for k in ("attestation", "judged", "vetJudged", "liveTest"))
    assert "recognised bucket" in err


def test_the_note_never_echoes_the_users_own_keys(capsys):
    """`adjudication._note`'s contract: fixed text and counts only. A bundle key can carry
    a secret-shaped value, and a diagnostic is not a safe place to find that out."""
    secret_key = "aws" + "_secret_" + "access" + "_key"
    _out, err = _split({secret_key: "x", "another": 1}, capsys)
    assert "recognised bucket" in err
    assert secret_key not in err
    assert "another" not in err


def test_an_empty_verdicts_array_is_not_treated_as_content(capsys):
    """`{"verdicts": []}` carries nothing to lose, so there is nothing to announce."""
    out, err = _split({"verdicts": []}, capsys)
    assert out["judged"] is None
    assert "Applied it as the judged bucket" not in err


# ------------------------------------------ the message that taught the mistake

def test_the_parser_no_longer_says_top_level():
    """Which level is "top" depends on the caller — for `--judged` the payload IS the
    file, for `--judged-bundle` it is the `judged` object inside it. The word is what sent
    the agent to the wrong level, so it is gone rather than corrected to one caller's
    truth."""
    import io
    import contextlib
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        assert _parse_verdicts(json.dumps({"nope": []})) == {}
    text = err.getvalue()
    assert "top-level" not in text, text
    assert '"verdicts" array' in text
    # The entry contract must survive the rewording — it is the useful half.
    assert "finding_id" in text and "target" in text


@pytest.mark.parametrize("payload", ["", "   ", "{}"])
def test_an_empty_payload_stays_silent(payload, capsys):
    """`_payload_carries_content`'s rule, unchanged: "nothing submitted" is not an error,
    and cli.py passes "" when a path could not be read."""
    split_judged_bundle(payload)
    assert capsys.readouterr().err == ""


# ------------------------------------------------------------ nothing else moved

def test_bounds_and_never_raises_are_intact(capsys):
    """The bundle is untrusted input; this fix must not have given it a way to crash or
    to escape the size bound."""
    assert split_judged_bundle("not json")["judged"] is None
    assert split_judged_bundle('["a", "list"]')["judged"] is None
    assert split_judged_bundle(None)["judged"] is None            # type: ignore[arg-type]
    assert split_judged_bundle('{"verdicts": "not a list"}')["judged"] is None
    capsys.readouterr()
