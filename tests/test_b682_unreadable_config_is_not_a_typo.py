"""B-682: "I could not read the config" is not "that name is not in the config".

`detect_vet_type` collapsed both into `cfg = {}`, so an unreadable `openclaw.json` gave
the same answer as one that was read and matched nothing — `"unknown"` — and `--vet
<a configured server name>` routed to the SKILL engine and came back as a path that is not
there. B-681 fixed the identical collapse one layer down in `vet_mcp`; this is the copy
that survived it.

Two design decisions this file pins, both departures from what the task first proposed:

* **No fifth return value.** `detect_vet_type` is exported from the package root's
  `__all__` and listed in `tests/checks_public_api.txt`; a fifth string would change a
  published contract, and an external caller branching exhaustively would silently take a
  wrong arm. The state lives in a pair-function instead, the shape this repo already uses
  for `read_judged_bundle` / `read_judged_bundle_with_problem`.
* **rc=2, not a fourth code.** `docs/USAGE.md` defines 2 as "the target could not be
  assessed at all", and a config that cannot be read makes classification impossible — so
  nothing was assessed and no verdict was produced, which is exactly that state. 2 is not
  "you mistyped"; that is one of several reasons it carries, and the message distinguishes
  them.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawseccheck.checks import detect_vet_type, detect_vet_type_with_reason  # noqa: E402
from clawseccheck.cli import main  # noqa: E402

_ONE_SERVER = '{"mcp": {"servers": {"weather": {"command": "npx", "args": ["-y", "w"]}}}}'
_TRUNCATED = '{"mcp": {"servers": {"weather"'


def _home(tmp_path, body, name="home"):
    home = tmp_path / name
    home.mkdir()
    (home / "openclaw.json").write_text(body, encoding="utf-8")
    return home


# ---------------------------------------------------------------------------
# The classifier
# ---------------------------------------------------------------------------

def test_an_unreadable_config_yields_a_reason(tmp_path):
    kind, reason = detect_vet_type_with_reason(
        "weather", home=str(_home(tmp_path, _TRUNCATED)))
    assert kind == "unknown"
    assert reason is not None
    assert "could not be read" in reason
    assert "undetermined" in reason


def test_a_readable_config_that_matches_nothing_yields_no_reason(tmp_path):
    """The control. Without it, a fix that always reports a reason passes the test above
    and makes every genuine typo blame the config."""
    kind, reason = detect_vet_type_with_reason(
        "no-such-server", home=str(_home(tmp_path, _ONE_SERVER)))
    assert kind == "unknown"
    assert reason is None


def test_no_config_at_all_is_not_reported_as_unreadable(tmp_path):
    """An ABSENT config is not an unreadable one, and this arm is the common case.

    With no `openclaw.json` there are no configured servers, so "this is not one" is a
    SOUND conclusion — nothing is undetermined. The first version of this fix collapsed the
    two and reported "could not be read" for every machine that has not installed OpenClaw
    (vetting a skill before installing is a documented use of `--vet`) and for every run of
    this suite, whose conftest redirects `$HOME` to a throwaway directory. An existing
    B-680 test caught it, which is why that test was left alone rather than re-grounded.
    """
    empty_home = tmp_path / "no-openclaw-here"
    empty_home.mkdir()
    assert detect_vet_type_with_reason("weather", home=str(empty_home)) == ("unknown", None)


def test_an_unreadable_config_directory_still_yields_a_reason(tmp_path):
    """The other side of the split: something IS there and we failed on it."""
    if os.geteuid() == 0:
        return  # root can read through mode 000
    home = _home(tmp_path, _ONE_SERVER)
    (home / "openclaw.json").chmod(0o000)
    try:
        kind, reason = detect_vet_type_with_reason("weather", home=str(home))
    finally:
        (home / "openclaw.json").chmod(0o600)
    assert kind == "unknown"
    assert reason is not None and "could not be read" in reason


def test_a_configured_name_is_still_mcp(tmp_path):
    assert detect_vet_type_with_reason(
        "weather", home=str(_home(tmp_path, _ONE_SERVER))) == ("mcp", None)


def test_a_target_on_disk_never_consults_the_config(tmp_path):
    """An unreadable config is irrelevant when the target is a real path — nothing is
    undetermined, because the question was never asked."""
    d = tmp_path / "somedir"
    d.mkdir()
    kind, reason = detect_vet_type_with_reason(
        str(d), home=str(_home(tmp_path, _TRUNCATED)))
    assert kind == "skill"
    assert reason is None


def test_the_public_name_is_unchanged(tmp_path):
    """`detect_vet_type` must return exactly the four values it always did.

    It is exported from the package root's `__all__`; widening it was the option this
    task rejected, and this is what would catch a later change that widens it anyway.
    """
    broken = str(_home(tmp_path, _TRUNCATED, "broken"))
    good = str(_home(tmp_path, _ONE_SERVER, "good"))
    d = tmp_path / "somedir"
    d.mkdir()
    for target, home in (("weather", broken), ("nope", good), ("weather", good),
                         (str(d), broken)):
        assert detect_vet_type(target, home=home) in ("plugin", "mcp", "skill", "unknown")
    assert detect_vet_type("weather", home=broken) == "unknown"
    assert detect_vet_type("weather", home=good) == "mcp"


def test_the_wrapper_agrees_with_the_pair(tmp_path):
    """One implementation, so the two can never drift."""
    for home_body in (_ONE_SERVER, _TRUNCATED):
        home = str(_home(tmp_path, home_body, f"h{len(home_body)}"))
        for target in ("weather", "nope"):
            assert detect_vet_type(target, home=home) == \
                detect_vet_type_with_reason(target, home=home)[0]


# ---------------------------------------------------------------------------
# What the user sees
# ---------------------------------------------------------------------------

def test_the_cli_names_the_unread_config(tmp_path, capsys):
    home = _home(tmp_path, _TRUNCATED)
    rc = main(["--vet", "weather", "--home", str(home),
               "--data-dir", str(tmp_path / "d")])
    err = capsys.readouterr().err
    assert rc == 2
    assert "no such file or directory" in err
    assert "could not be read" in err
    assert "undetermined" in err


def test_a_genuine_typo_does_not_blame_the_config(tmp_path, capsys):
    """The control for the message, matching the classifier control above."""
    home = _home(tmp_path, _ONE_SERVER)
    rc = main(["--vet", "no-such-server", "--home", str(home),
               "--data-dir", str(tmp_path / "d")])
    err = capsys.readouterr().err
    assert rc == 2
    assert "could not be read" not in err
    assert "undetermined" not in err


def test_advise_gets_the_same_treatment(tmp_path, capsys):
    home = _home(tmp_path, _TRUNCATED)
    rc = main(["--advise", "weather", "--home", str(home),
               "--data-dir", str(tmp_path / "d")])
    err = capsys.readouterr().err
    assert rc == 2
    assert "could not be read" in err


def test_the_config_path_is_redacted(tmp_path, capsys, monkeypatch):
    """B-581: we compose this path ourselves and it carries the operator's home, unlike
    the target, which the user typed and needs to see echoed back."""
    from clawseccheck import cli as _cli

    seen = []
    real = _cli._redact_home_paths
    monkeypatch.setattr(_cli, "_redact_home_paths", lambda t: seen.append(t) or real(t))
    home = _home(tmp_path, _TRUNCATED)
    main(["--vet", "weather", "--home", str(home), "--data-dir", str(tmp_path / "d")])
    assert any("could not be read" in t for t in seen), \
        "the undetermined reason must be composed through the redactor"


def test_the_pair_is_in_the_public_api_manifest():
    """§3.1: anything importable from `clawseccheck.checks` and used by a sibling or a
    test is listed, so the aggregator contract stays mechanical rather than remembered."""
    manifest = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "checks_public_api.txt")
    with open(manifest, encoding="utf-8") as fh:
        names = fh.read().split()
    assert "detect_vet_type" in names
    assert "detect_vet_type_with_reason" in names
