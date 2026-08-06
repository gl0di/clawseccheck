"""B-487 — the printed commands must be safe to run, not merely safe to print.

## The defect

`render_vet_plan` interpolated the caller-supplied target into shell command lines with no
quoting at all, and `docs/FLOW_CHOICES.md` instructs the host agent to execute what it
prints ("(3) Run those commands yourself."). Rendering
`https://example.invalid/x; touch /tmp/PWNED_PROOF` emitted, verbatim:

    clawseccheck --vet-source https://example.invalid/x; touch /tmp/PWNED_PROOF   # 1: ...
    curl -fsSL https://example.invalid/x; touch /tmp/PWNED_PROOF -o "$QUARANTINE/download"

Two injected commands in one plan. `--vet-plan` is precisely the flow whose purpose is
handling an *untrusted* target — the identity string a user pastes from a web page, a
README, or a chat message — so the one input guaranteed not to be trusted was the one
interpolated raw.

Found by ClawHub's `skillSpector` scan of the published v3.60.0, not by us:
"its guided pre-install workflow can lead an agent to run shell/network commands built
from untrusted target text without safe quoting."

`render_advise` / `render_advise_json` had the same shape in their `rm -rf` cleanup lines,
in BOTH branches of the `_looks_like_quarantine()` gate.

## The contract these tests pin

1. No interpolated value can ever escape its argument position — asserted by round-tripping
   the emitted line through `shlex.split()` and requiring the payload to survive as ONE
   token. A bare `touch` token in command position is the failure.
2. `shlex.quote` is a no-op on safe strings, so ordinary targets must render byte-identically
   to the pre-fix output. Over-quoting would churn every golden output in the suite and make
   the plan harder to read for no security gain; that regression is pinned in
   `test_benign_targets_render_without_quoting`.
"""
from __future__ import annotations

import shlex

import pytest

from clawseccheck.dossier import build_profile
from clawseccheck.report import render_advise, render_advise_json, render_vet_plan

# Assembled at runtime so no contiguous "attack command" literal exists in the source and
# host secret/malware scanners stay quiet (CLAUDE.md §2.3 idiom).
_VERB = "touch"
_PAYLOAD = _VERB + " /tmp/clawseccheck-b487-should-never-run"

# One target per ecosystem branch of `render_vet_plan` — they take genuinely different code
# paths (npm/pypi build a package spec, git slices the raw target, url passes it through).
_HOSTILE_TARGETS = [
    pytest.param(f"https://example.invalid/x; {_PAYLOAD}", id="url-semicolon"),
    pytest.param(f"https://example.invalid/x && {_PAYLOAD}", id="url-and"),
    pytest.param(f"https://example.invalid/x | {_PAYLOAD}", id="url-pipe"),
    pytest.param(f"git:example.invalid/o/r$({_PAYLOAD})", id="git-cmdsub"),
    pytest.param(f"git:example.invalid/o/r@main; {_PAYLOAD}", id="git-ref-semicolon"),
    pytest.param(f"npm:left-pad; {_PAYLOAD}", id="npm-semicolon"),
    pytest.param(f"npm:left-pad@1.0.0 `{_PAYLOAD}`", id="npm-backtick"),
    pytest.param(f"pypi:requests; {_PAYLOAD}", id="pypi-semicolon"),
    pytest.param("spaced name here", id="plain-space"),
]

# Newline-bearing targets are handled by refusal, not by quoting — see
# test_control_character_target_is_refused_not_quoted for why quoting alone is unsound.
_CONTROL_CHAR_TARGETS = [
    pytest.param(f"bare-name\n{_PAYLOAD}", id="newline-bare"),
    pytest.param(f"https://example.invalid/x\n{_PAYLOAD}", id="newline-url"),
    pytest.param(f"npm:left-pad\r{_PAYLOAD}", id="carriage-return"),
]

_COMMAND_STARTS = ("curl", "git clone", "npm pack", "pip download", "clawseccheck ", "rm -rf")


def _command_lines(rendered: str) -> list[str]:
    """The lines a host agent would actually execute, trailing `# comment` stripped."""
    out = []
    for raw in rendered.splitlines():
        line = raw.strip()
        if line.startswith("#") or not any(line.startswith(c) for c in _COMMAND_STARTS):
            continue
        out.append(line.split("   #")[0].rstrip())
    return out


def _assert_no_escape(line: str, target: str) -> None:
    """The payload must survive as an ARGUMENT, never reach command position.

    `shlex.split` models how a POSIX shell words the line. If the injected verb ever comes
    back as a token of its own, the quoting failed — that token would be executed.
    """
    try:
        tokens = shlex.split(line)
    except ValueError as exc:  # unbalanced quotes — the shell would error or worse
        pytest.fail(f"emitted an unparseable command line for {target!r}: {line!r} ({exc})")
    assert _VERB not in tokens, (
        f"injected verb escaped into command position for target {target!r}\n  line: {line!r}"
    )
    # `;` `|` `&&` must never survive as shell operators either — shlex keeps them inside a
    # quoted token, so their presence as a standalone token means they stayed operative.
    for operator in (";", "|", "&&", "&"):
        assert operator not in tokens, (
            f"shell operator {operator!r} survived unquoted for target {target!r}\n"
            f"  line: {line!r}"
        )


# ------------------------------------------------------------------ render_vet_plan


@pytest.mark.parametrize("target", _HOSTILE_TARGETS)
def test_vet_plan_never_emits_an_escapable_command(target):
    lines = _command_lines(render_vet_plan(target))
    assert lines, f"no command lines rendered for {target!r} — the test is not exercising the fix"
    for line in lines:
        _assert_no_escape(line, target)


def test_vet_plan_the_original_reported_payload():
    """The exact reproduction from the bug report, kept as its own named case."""
    target = f"https://example.invalid/x; {_PAYLOAD}"
    rendered = render_vet_plan(target)
    # Before the fix this line ended the `curl` command and started a second one.
    assert f"; {_VERB}" not in rendered.replace(target, ""), (
        "an unquoted command separator is still reachable outside the target token"
    )
    for line in _command_lines(rendered):
        _assert_no_escape(line, target)


@pytest.mark.parametrize("target", _CONTROL_CHAR_TARGETS)
def test_control_character_target_is_refused_not_quoted(target):
    """`shlex.quote` is necessary but not sufficient when output is consumed line by line.

    A newline-bearing target quotes correctly as ONE shell argument, but the quoted token
    spans two rendered LINES. In the `#`-commented ecosystem branches that was a real
    shell-level escape, because `#` comments to end of LINE only: the tail of the target
    landed on an UNcommented line, putting its first word in command position. Verified on
    the pre-refusal build, where line 17 of the plan read
    `touch /tmp/x' has no resolvable ecosystem — ...` with no leading `#`.

    So the contract is refusal, not quoting: emit no command at all, and say why.
    """
    rendered = render_vet_plan(target)
    assert "I will not build a fetch plan" in rendered
    assert not _command_lines(rendered), "a refused plan must emit no runnable command"
    # every rendered line stands alone — the target cannot break the output's line structure
    assert _VERB not in rendered.split("target (escaped):")[0]
    for line in rendered.splitlines():
        assert "\r" not in line


def test_refusal_escapes_the_target_rather_than_printing_it_raw():
    """The refusal must not smuggle a line break into the very output it protects."""
    rendered = render_vet_plan(f"x\n{_PAYLOAD}")
    target_lines = [ln for ln in rendered.splitlines() if "target (escaped):" in ln]
    assert len(target_lines) == 1
    assert "\\n" in target_lines[0], "the newline should appear escaped, not as a real break"


_BENIGN_TARGETS = [
    "clawhub:some-skill",
    "npm:left-pad@1.0.0",
    "pypi:requests",
    "git:github.com/owner/repo@main",
    "git:github.com/owner/repo",
    "https://example.com/pkg.tgz",
    "some-bare-name",
]


@pytest.mark.parametrize("target", _BENIGN_TARGETS)
def test_benign_targets_render_without_quoting(target):
    """`shlex.quote` is a no-op on safe strings — ordinary plans must not grow quotes.

    This is the anti-over-quoting guard. It was verified against the pre-fix renderer at
    the time of the change: all seven targets rendered byte-identically. Asserting the
    absence of added quoting keeps that true without pinning the whole golden string, which
    would fight every unrelated wording change to the plan.
    """
    rendered = render_vet_plan(target)
    assert target in rendered, f"{target!r} should appear verbatim, unquoted"
    for line in _command_lines(rendered):
        assert "'" not in line, f"benign target gained shell quoting: {line!r}"


# ------------------------------------------------------- render_advise / _advise_json


# -------------------------------------------------------------- through the real CLI


def _cli(argv: list[str]) -> str:
    """Run the real entry point and return stdout. Project rule: verify end-to-end, not
    traces — a renderer-level assertion does not prove the flag a user actually types is
    safe."""
    import contextlib
    import io

    from clawseccheck.cli import main

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(argv)
    return buf.getvalue()


def test_cli_vet_plan_quotes_a_hostile_target():
    target = f"https://example.invalid/x; {_PAYLOAD}"
    out = _cli(["--vet-plan", target])
    lines = _command_lines(out)
    assert lines, "the CLI printed no command lines — the test is not exercising the flow"
    for line in lines:
        _assert_no_escape(line, target)


def test_cli_vet_plan_refuses_a_control_character_target():
    out = _cli(["--vet-plan", f"bare-name\n{_PAYLOAD}"])
    assert "I will not build a fetch plan" in out
    assert not _command_lines(out)


def _profile(tmp_path, name: str):
    """A minimal vetted skill, so `build_profile` has real engine output to shape."""
    from clawseccheck.checks import vet_skill

    skill = tmp_path / name
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: demo\ndescription: A demo skill.\n---\n\n# Demo\n\nDoes very little.\n"
    )
    return build_profile(vet_skill(str(skill)), str(skill), "skill")


def test_advise_cleanup_is_quoted_in_the_non_quarantine_branch(tmp_path):
    """`_looks_like_quarantine()` picks the wording; BOTH branches emit `rm -rf`.

    tmp_path is not under the system temp root for this purpose in every environment, so
    this exercises whichever branch applies — the assertion holds for both.
    """
    profile = _profile(tmp_path, "demo skill with spaces")
    for line in _command_lines(render_advise(profile)):
        _assert_no_escape(line, profile.target)


def test_advise_json_cleanup_is_quoted(tmp_path):
    import json

    profile = _profile(tmp_path, "demo skill with spaces")
    cleanup = json.loads(render_advise_json(profile, version="0.0.0"))["cleanup"]
    for line in _command_lines(cleanup):
        _assert_no_escape(line, profile.target)


def test_advise_path_with_a_space_does_not_widen_rm(tmp_path):
    """The benign trigger: a path containing a space turned `rm -rf` into a two-target
    delete. No metacharacter needed — this is why the second site mattered even though its
    input is usually agent-constructed from `mktemp -d`."""
    profile = _profile(tmp_path, "demo skill with spaces")
    for line in _command_lines(render_advise(profile)):
        if not line.startswith("rm -rf"):
            continue
        tokens = shlex.split(line)
        assert tokens[:2] == ["rm", "-rf"]
        assert len(tokens) == 3, f"rm -rf received {len(tokens) - 2} targets: {tokens!r}"
        assert tokens[2] == profile.target
