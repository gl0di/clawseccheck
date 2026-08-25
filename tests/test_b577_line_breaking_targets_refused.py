"""B-577: a target that would break the line it is printed on must be refused.

B-487 established the hazard and refused via `_CONTROL_CHAR_RE = [\\x00-\\x1f\\x7f]`, on the
reasoning that no legitimate target carries a control character. That class is ASCII-only,
and three characters outside it are line boundaries to the consumer this output is written
for: U+0085 NEL, U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR.

Measured on the tree before the fix — seven ASCII separators refused, three not:

    sep      regex  refused  command-position lines
    \\n       True   True     0
    ...
    U+0085   False  False    3
    U+2028   False  False    3
    U+2029   False  False    3

and `--advise`, which the task had left unverified, printed `rm -rf <payload>` on a line of
its own for all three.

The separator set below is DERIVED by asking Python, not written down. An enumerated class
that looked exhaustive is exactly what produced the gap; a hand-written list here would
reproduce the defect inside its own guard, and would not notice a separator a future Python
starts splitting on.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import json

import pytest

from clawseccheck.catalog import Finding
from clawseccheck.dossier import build_profile
from clawseccheck.report import render_advise, render_advise_json, render_vet_plan

# `_breaks_the_line_it_is_printed_on` is imported INSIDE the three tests that need it, not
# here. On the pre-fix tree the name does not exist, and a module-level import turns every
# behavioural test in this file into a collection error — so none of them run, and the file
# proves nothing about the defect it is named for. Third time this shape appeared today
# (see tests/test_b565_* and tests/test_b636_*); the behavioural tests below must be able
# to fail on the OLD tree for the RIGHT reason.


def _line_separators() -> list[str]:
    """Every character `str.splitlines()` treats as a boundary, found by asking it.

    Swept over the BMP rather than a literal list — same derivation the fix uses, so the
    test cannot pass by agreeing with a mistake the fix also makes.
    """
    return [chr(c) for c in range(0x10000) if len(("a" + chr(c) + "b").splitlines()) == 2]


_SEPARATORS = _line_separators()

_BENIGN = [
    "requests",
    "npm:left-pad",
    "git:github.com/o/r@v1.2.3",
    "https://x.test/a?b=c#d",
    "clawhub:my-skill",
    "pypi:Django",
    "./local/path",
    "name with spaces",
    "emoji-\U0001F389-name",
    "Ünïcodé-nàme",
    "/tmp/quarantine-abc123",
]


def _profile(target: str):
    f = Finding(id="B13", title="t", severity="LOW", status="PASS", detail="d",
                fix="f", framework="Test")
    return build_profile([f], target, "skill")


def test_the_derivation_found_the_characters_this_bug_is_about():
    """Non-vacuity. If the sweep returned only the ASCII set — or nothing — every
    parametrised case below would pass while testing the wrong thing."""
    assert len(_SEPARATORS) >= 8, _SEPARATORS
    for ch in ("\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
        assert ch in _SEPARATORS, f"U+{ord(ch):04X} missing from the derived set"


@pytest.mark.parametrize("sep", _SEPARATORS, ids=lambda c: f"U+{ord(c):04X}")
def test_no_separator_puts_a_payload_in_command_position_in_a_plan(sep):
    plan = render_vet_plan(f"bare-name{sep}touch /tmp/PWNED")
    offending = [ln for ln in plan.splitlines() if ln.strip().startswith("touch")]
    assert not offending, offending


@pytest.mark.parametrize("sep", _SEPARATORS, ids=lambda c: f"U+{ord(c):04X}")
def test_no_separator_puts_rm_in_command_position_in_advise(sep):
    """The consumer B-577 listed as unverified. It shares the guard and it was reachable:
    `rm -rf` is the payload here, so the consequence is destructive rather than merely a
    printed command."""
    out = render_advise(_profile(f"/tmp/q{sep}rm -rf /tmp/PWNED"))
    offending = [ln for ln in out.splitlines() if ln.strip().startswith("rm -rf /tmp/PWNED")]
    assert not offending, offending


@pytest.mark.parametrize("sep", _SEPARATORS, ids=lambda c: f"U+{ord(c):04X}")
def test_no_separator_survives_into_the_advise_json_cleanup(sep):
    payload = json.loads(render_advise_json(_profile(f"/tmp/q{sep}rm -rf /tmp/PWNED"),
                                            version="test"))
    cleanup = payload.get("cleanup") or ""
    offending = [ln for ln in cleanup.splitlines() if ln.strip().startswith("rm -rf /tmp/PWNED")]
    assert not offending, cleanup


# ---------------------------------------------------------------------------
# The other direction: this is a narrowing, so benign output must not move
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("target", _BENIGN)
def test_benign_targets_still_render_a_plan(target):
    """B-487's anti-over-quoting guard, kept. Verified additionally against the pre-fix
    tree at implementation time: the sha256 over all three renderers for these eleven
    targets is byte-identical before and after, so the narrowing has no benign surface."""
    plan = render_vet_plan(target)
    assert "will not build" not in plan
    assert plan.strip()


@pytest.mark.parametrize("target", _BENIGN)
def test_benign_targets_still_get_a_cleanup_command(target):
    out = render_advise(_profile(target))
    assert "would break the line it is printed on" not in out


def test_control_characters_that_are_not_separators_are_still_refused():
    """The regex clause is not redundant: NUL, BEL and DEL are not split by
    `splitlines()`, and B-487's reasoning still refuses them."""
    from clawseccheck.report import _breaks_the_line_it_is_printed_on

    for ch in ("\x00", "\x07", "\x7f"):
        assert _breaks_the_line_it_is_printed_on(f"a{ch}b"), repr(ch)


def test_a_trailing_separator_is_caught():
    """`len(x.splitlines()) > 1` would miss this: a trailing separator splits to a single
    element. The predicate compares against `[x]` for exactly that reason."""
    from clawseccheck.report import _breaks_the_line_it_is_printed_on

    assert _breaks_the_line_it_is_printed_on("trailing\n")
    assert _breaks_the_line_it_is_printed_on("trailing\u2028")


def test_the_empty_target_is_not_treated_as_line_breaking():
    from clawseccheck.report import _breaks_the_line_it_is_printed_on

    assert not _breaks_the_line_it_is_printed_on("")


# ---------------------------------------------------------------------------
# Through the CLI, as B-487's own tests do
# ---------------------------------------------------------------------------

def test_cli_vet_plan_refuses_a_unicode_separator(tmp_path, capsys):
    from clawseccheck.cli import main

    rc = main(["--data-dir", str(tmp_path), "--no-history",
               "--vet-plan", "bare-name\u2028touch /tmp/PWNED_E2E"])
    out = capsys.readouterr().out
    assert "will not build" in out, out[:400]
    assert not [ln for ln in out.splitlines() if ln.strip().startswith("touch")]
    assert rc is not None


def test_cli_vet_plan_still_builds_for_a_benign_target(tmp_path, capsys):
    """Control for the test above: the refusal path must be reachable AND avoidable, or
    'no touch line' would pass for a CLI that refuses everything."""
    from clawseccheck.cli import main

    main(["--data-dir", str(tmp_path), "--no-history", "--vet-plan", "npm:left-pad"])
    out = capsys.readouterr().out
    assert "will not build" not in out
    assert "left-pad" in out
