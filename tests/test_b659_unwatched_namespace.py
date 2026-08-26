"""B-659 — a settings change this build does not model must not land under the all-clear.

C-418's contract is that `--monitor` prints no all-clear over a comparison it skipped. That
scoping is bounded by the same model that produced the blindness: it can only list a skip the
code KNOWS about. `_CONFIG_DIMENSIONS` is four fields — `mcp`, `mcp_detail`, `channels`,
`gateway_bind` — and everything else in the settings file (`plugins.*`, `tools.*`, `hooks.*`,
`cron`, `agents.*`, `browser.*`, `secrets.providers`) reaches the monitor only if some check's
STATUS happens to move. When none does, the edit was neither compared nor disclosed.

Measured before the fix, on `fixtures/home_safe`: appending an entry to `plugins.allow` — a
new trust grant, since that list decides which plugins may load — moved zero of 188 check
statuses, moved `config_file_sha256`, and produced `No new threats among what was compared`
with nothing in the un-compared list. That particular namespace is now a watched dimension
(B-659(b)) and so is named rather than noted; the end-to-end fixtures here moved to
`secrets.providers`, which is still unmodelled. The note is for whatever is unmodelled at the
time, so its fixture is expected to migrate as coverage grows — and when nothing is left
unmodelled, these tests failing is the correct way to find that out.

**Why this is a note and not an alert.** The monitoring epic explicitly rejected hashing the
parsed config as a catch-all ALERT: OpenClaw writes `meta.lastTouchedAt/Version` and
`wizard.lastRun*` itself, so an alert would fire on every upgrade carrying no security
content, and an unnamed "config hash changed" is unactionable. A note is a different channel
with a different contract — collapsed to a count unless the reader asks, never in the event
journal, and unable to page a scheduled job. `test_it_is_a_note_and_never_an_alert` and
`test_it_does_not_move_the_exit_code` are what keep it on that side of the line.

The narrowness tests matter as much as the positive one. A note that fired on every real
change would inflate the "N things could not be compared" count until nobody read it, which
is the same defect with the sign flipped.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck import monitor
from clawseccheck.cli import main
from clawseccheck.monitor import NOTE_CATEGORY_ORDER, diff_with_notes

_MARKER = "nothing this version compares inside it"
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _snap(**kw) -> dict:
    base = {
        "version": monitor.SNAPSHOT_VERSION,
        "checks": {},
        "graded": True,
        "score": 50,
        "raw_score": 50,
        "grade": "F",
        "scope": ["host"],
        "watched": list(monitor.WATCHED_DIMENSIONS),
        "config_ever_seen": True,
        "config_file_sha256": "a" * 64,
        "config_resolved_sha256": "b" * 64,
        "mcp": {},
        "mcp_detail": {},
        "channels": {},
        "gateway_bind": "127.0.0.1",
    }
    base.update(kw)
    return base


def _fired(prev: dict, curr: dict) -> bool:
    _alerts, notes = diff_with_notes(prev, curr)
    return any(_MARKER in s for _c, s in notes)


# ---------------------------------------------------------------- the defect

def test_a_moved_file_digest_with_no_named_drift_is_disclosed():
    assert _fired(_snap(), _snap(config_file_sha256="c" * 64))


def test_a_moved_resolved_digest_is_disclosed_too():
    """An `$include` fragment edit leaves the root file's bytes untouched, so only the
    resolved digest sees it. Until now nothing read that field at all."""
    assert _fired(_snap(), _snap(config_resolved_sha256="d" * 64))


# ---------------------------------------------------------------- the narrowness

def test_an_unchanged_file_says_nothing():
    """The control that keeps the false-positive gate — two runs over an unchanged home —
    silent. Without it every other assertion here is satisfied by a note that always fires."""
    assert not _fired(_snap(), _snap())


def test_a_named_config_change_does_not_also_get_the_note():
    """If the drift was already named, the change is accounted for; saying it again would be
    the same edit reported twice. The alert is asserted in the same test, so this cannot pass
    by the drift silently failing to be detected."""
    prev, curr = _snap(), _snap(gateway_bind="0.0.0.0", config_file_sha256="c" * 64)
    alerts, notes = diff_with_notes(prev, curr)
    assert any("Gateway bind changed" in m for _lvl, m in alerts), alerts
    assert not any(_MARKER in s for _c, s in notes), notes


def test_a_blind_run_does_not_add_it():
    """A run that could not read the settings file already says so, louder. Adding this on
    top would bury the one honest sentence that explains the whole run."""
    prev = _snap()
    curr = _snap(config_file_sha256="c" * 64, config_parse_error=True,
                 config_baseline="carried")
    assert not _fired(prev, curr)


def test_an_absent_digest_on_either_side_says_nothing():
    """Absence is not evidence of a change. A baseline predating the digest would otherwise
    report the whole file as having moved."""
    prev = _snap()
    del prev["config_file_sha256"]
    del prev["config_resolved_sha256"]
    assert not _fired(prev, _snap())


# ---------------------------------------------------------------- the channel

def test_it_is_a_note_and_never_an_alert():
    """The epic rejected the ALERT form of this idea for good reasons. Promoting it would
    re-open that rejection, so the boundary is pinned rather than left to a comment."""
    alerts, notes = diff_with_notes(_snap(), _snap(config_file_sha256="c" * 64))
    assert not any(_MARKER in m for _lvl, m in alerts), alerts
    hit = [c for c, s in notes if _MARKER in s]
    assert hit, notes
    for category in hit:
        assert category in NOTE_CATEGORY_ORDER
        assert category not in _SEVERITIES


# ---------------------------------------------------------------- end to end

def _home(tmp_path: Path, mutate=None) -> tuple[Path, Path]:
    home, store = tmp_path / "home", tmp_path / "store"
    home.mkdir(exist_ok=True)
    body = {
        "gateway": {"bind": "127.0.0.1:8080",
                    "auth": {"mode": "token", "token": "a-very-long-token-of-32-chars!!"}},
    }
    if mutate:
        mutate(body)
    cfg = home / "openclaw.json"
    cfg.write_text(json.dumps(body), encoding="utf-8")
    os.chmod(cfg, 0o600)
    return home, store


def _configure_secrets(body: dict) -> None:
    """An edit in a namespace this build models NEITHER as a dimension NOR through a check
    whose status moves. The original repro used `plugins.allow`, which B-659(b) has since
    promoted to a real dimension — so it now produces a NAMED alert and this note correctly
    stays quiet. Keeping the old fixture here would have pinned the note against a case it
    is no longer for."""
    body.setdefault("secrets", {})["providers"] = {"env": {"enabled": True}}


def test_an_edit_in_an_unmodelled_namespace_is_disclosed(tmp_path, capsys):
    """The shape the note exists for: the file changed, zero check statuses moved, no
    dimension moved, and before this the run printed the all-clear with nothing in the
    un-compared list."""
    home, store = _home(tmp_path)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    _home(tmp_path, _configure_secrets)
    main(["--monitor", "--home", str(home), "--data-dir", str(store), "--verbose"])
    out = capsys.readouterr().out
    assert "change(s) detected" not in out, (
        "fixture premise: this edit must name nothing, or the note is correctly suppressed "
        "and this test is measuring the wrong thing\n" + out)
    assert _MARKER in out, out


def test_it_does_not_move_the_exit_code(tmp_path, capsys):
    """A note must not page a scheduled job. `--fail-on low` is the widest selectable
    threshold, so if this ever became selectable it would show up here first."""
    home, store = _home(tmp_path)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    _home(tmp_path, _configure_secrets)
    rc = main(["--monitor", "--home", str(home), "--data-dir", str(store),
               "--exit-code", "--fail-on", "low"])
    capsys.readouterr()
    assert rc == 0, "a note reached the exit code — it must stay an advisory channel"


def test_it_never_reaches_the_event_journal(tmp_path, capsys):
    """Notes are not journaled. A note in `events.jsonl` would be a permanent, hash-chained
    record of something the run explicitly declined to conclude."""
    home, store = _home(tmp_path)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    _home(tmp_path, _configure_secrets)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    capsys.readouterr()
    journal = store / "events.jsonl"
    body = journal.read_text(encoding="utf-8") if journal.is_file() else ""
    assert _MARKER not in body, body


def test_a_run_that_named_a_check_regression_does_not_also_say_it_cannot_tell(tmp_path, capsys):
    """The self-contradiction this note shipped with for one afternoon.

    `tools.*` is not a watched dimension, so the first version of the suppression — "did any
    CONFIG DIMENSION alert fire?" — left the note firing beside three named regressions.
    Measured on `fixtures/home_safe` with `tools.profile` -> "all": the run printed

        No longer passing: Least privilege (elevated tools / allowlists) ...
        No longer passing: Filesystem-write tool exposure ...
        No longer passing: File tools workspace-only confinement disabled ...

    and then "this run cannot tell you what it was" — a sentence the same screen refuted
    three lines above. "Named" has to mean "this run already told the user something about
    the same edit", which includes a check status moving, not only a dimension.
    """
    home, store = tmp_path / "home", tmp_path / "store"
    home.mkdir()

    def write(body):
        cfg = home / "openclaw.json"
        cfg.write_text(json.dumps(body), encoding="utf-8")
        os.chmod(cfg, 0o600)

    base = {"gateway": {"bind": "127.0.0.1:8080",
                        "auth": {"mode": "token", "token": "a-very-long-token-of-32-chars!!"}},
            "tools": {"profile": "minimal", "exec": {"mode": "ask"}}}
    write(base)
    main(["--monitor", "--home", str(home), "--data-dir", str(store)])
    capsys.readouterr()

    widened = json.loads(json.dumps(base))
    widened["tools"]["profile"] = "all"
    write(widened)
    main(["--monitor", "--home", str(home), "--data-dir", str(store), "--verbose"])
    out = capsys.readouterr().out

    assert "No longer passing" in out, (
        "fixture premise: this edit must move a check status, or the test proves nothing\n"
        + out)
    assert _MARKER not in out, (
        "the run named regressions and then said it could not tell what changed:\n" + out)
