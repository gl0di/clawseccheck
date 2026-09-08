"""B-681: `--vet-mcp <name>` on a server that is not configured is a usage error.

Found while carrying out B-680's point 3 -- "check the sibling entry points for the same
shape". It is the same conflation pointed the other way, and worse for it:

    $ audit.py --vet-mcp definitely-not-a-server
    RISK DOSSIER - mcp 'definitely-not-a-server'    CAUTION
      Danger  UNKNOWN  Server 'definitely-not-a-server' not found in config at ...
    $ echo $?
    0

`0` is the code a CLEAN vet returns. A caller branching on `$?` was told "I checked it and
there is nothing to act on" about a subject that was never found -- so this failed toward
silence, where B-680's original shape at least exited non-zero.

The signal is a declared field (`Finding.subject_absent`), not the `detail` sentence: an
exit-code contract keyed on prose breaks the first time the prose is reworded.

Three neighbours must NOT move, and half this file exists to hold them:
  * `--vet-mcp` with no value -- its documented "every configured server" form;
  * a server that IS configured but cannot be judged -- an honest UNKNOWN;
  * a spec file that EXISTS but does not parse -- the subject is there, the assessment
    failed, which is the `--vet` "empty directory" case one surface over.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from clawseccheck.catalog import Finding  # noqa: E402
from clawseccheck.checks import vet_mcp  # noqa: E402
from clawseccheck.cli import main  # noqa: E402

_ONE_SERVER = (
    '{"mcp": {"servers": {"weather": {"command": "npx", "args": ["-y", "weather-mcp"]}}}}'
)


def _home(tmp_path, body=_ONE_SERVER):
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text(body, encoding="utf-8")
    return home


# ---------------------------------------------------------------------------
# The subject does not exist -> rc=2, reason on stderr, stdout empty
# ---------------------------------------------------------------------------

def test_unknown_server_name_is_a_usage_error(tmp_path, capsys):
    rc = main(["--vet-mcp", "no-such-server", "--home", str(_home(tmp_path))])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out.strip() == ""
    assert "no configured MCP server by that name" in captured.err
    assert "RISK DOSSIER" not in captured.err and "CAUTION" not in captured.err


def test_missing_spec_file_path_is_a_usage_error(tmp_path, capsys):
    """A path is resolved the same way a name is: absent from disk, absent from config."""
    rc = main([
        "--vet-mcp", str(tmp_path / "gone.json"), "--home", str(_home(tmp_path)),
    ])
    captured = capsys.readouterr()
    assert rc == 2
    assert captured.out.strip() == ""


def test_the_signal_is_a_field_not_a_sentence(tmp_path):
    """Pin the mechanism, not just the outcome.

    If a later edit reworded the detail and the CLI were reading that string, this test
    would still pass while the exit code silently reverted to 0. Reading the field is
    what makes that impossible, so the field is what gets asserted.
    """
    findings = vet_mcp(target="no-such-server", home=str(_home(tmp_path)))
    assert len(findings) == 1
    assert findings[0].subject_absent is True
    assert findings[0].status == "UNKNOWN"


def test_the_default_is_off(tmp_path):
    """An unaware producer keeps the ordinary UNKNOWN posture."""
    assert Finding(
        id="X", title="t", severity="LOW", status="UNKNOWN",
        detail="d", fix="f", framework="fw",
    ).subject_absent is False


# ---------------------------------------------------------------------------
# "Absent" is a claim, and it needs the config to have been read
# ---------------------------------------------------------------------------

def test_an_unreadable_config_is_undetermined_not_a_typo(tmp_path, capsys):
    """Found by trying to break this fix, before it shipped.

    Both config failures used to collapse into `cfg = {}`, so an empty server map and an
    unreadable one were the same value -- and the finding announced "not found in config"
    about a file nobody had managed to open. Harmless while it was only a sentence.

    Once it drove an exit code it stopped being harmless: a truncated openclaw.json made
    the tool tell a pipeline "you mistyped that name" about a server that may well be
    configured in the half of the file it never parsed. The verdict now says undetermined
    and keeps its dossier.
    """
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text('{"mcp": {"servers": {"weather"', encoding="utf-8")

    findings = vet_mcp(target="weather", home=str(home))
    assert findings[0].subject_absent is False
    assert findings[0].status == "UNKNOWN"
    assert "undetermined" in findings[0].detail

    rc = main(["--vet-mcp", "weather", "--home", str(home)])
    captured = capsys.readouterr()
    assert rc != 2
    assert "RISK DOSSIER" in captured.out


def test_a_missing_config_is_undetermined_too(tmp_path):
    """No config file at all is the same epistemic state as an unparseable one."""
    home = tmp_path / "home"
    home.mkdir()
    findings = vet_mcp(target="weather", home=str(home))
    assert findings[0].subject_absent is False
    assert "undetermined" in findings[0].detail


def test_a_readable_config_still_convicts_a_real_typo(tmp_path):
    """The control for the two above: reading the config is what earns the claim.

    Without this, a fix that simply never set the flag would pass both tests above and
    quietly restore the rc=0 bug.
    """
    findings = vet_mcp(target="no-such-server", home=str(_home(tmp_path)))
    assert findings[0].subject_absent is True


# ---------------------------------------------------------------------------
# The three neighbours that must not move
# ---------------------------------------------------------------------------

def test_no_target_is_still_every_configured_server(tmp_path, capsys):
    rc = main(["--vet-mcp", "--home", str(_home(tmp_path))])
    captured = capsys.readouterr()
    assert rc != 2
    assert "RISK DOSSIER" in captured.out


def test_a_configured_server_still_gets_its_dossier(tmp_path, capsys):
    rc = main(["--vet-mcp", "weather", "--home", str(_home(tmp_path))])
    captured = capsys.readouterr()
    assert rc != 2
    assert "RISK DOSSIER" in captured.out


def test_an_unparseable_spec_file_keeps_its_dossier(tmp_path, capsys):
    """The subject EXISTS; it is the assessment that failed.

    This is the `--vet` empty-directory case one surface over. Collapsing it into the
    usage error would trade one lying answer for another -- "you mistyped" said about a
    file the user really does have.
    """
    home = _home(tmp_path)
    spec = tmp_path / "spec.json"
    spec.write_text('{"not": "a spec"}', encoding="utf-8")
    rc = main(["--vet-mcp", str(spec), "--home", str(home)])
    captured = capsys.readouterr()
    assert rc != 2
    assert "RISK DOSSIER" in captured.out
    assert vet_mcp(target=str(spec), home=str(home))[0].subject_absent is False


def test_the_full_audit_path_cannot_reach_the_flag(tmp_path):
    """--full's embedded vet-mcp section passes target=None.

    Only the target-is-a-name branch sets the flag, so no audit run can pick up a usage
    error from a server it enumerated itself. Pinned because the flag now decides an exit
    code, and --full's exit code answers to a different contract entirely.
    """
    for f in vet_mcp(target=None, home=str(_home(tmp_path))):
        assert f.subject_absent is False
