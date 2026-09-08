"""B-620: SARIF's `limit_hits` copy must never carry an absolute filesystem path.

`sarif.py` used to copy `ctx.limit_hits` into `analysis_completeness.limit_hits` verbatim.
At least one producer (`collector._config_workspace_dirs`, for an `agents.*.workspace`
value that expands `~`) interpolates the RESOLVED absolute path, so a SARIF file handed
to CI/a dashboard/an issue carried the operator's real `/home/<user>/...` -- PII, and
against the precedent `report._credential_surface_rel` already sets ("falling back to
`path.name` still tells the reader WHAT was found, never WHERE on disk").

The fix reuses `report._redact_home_paths` (B-381's helper for this exact shape,
already applied to the --dashboard card) rather than inventing a second redaction table --
scoped to the SARIF copy only, never to the stored `ctx.limit_hits`, because three
consumers (B13 in checks/_vet.py, dossier.py leg 2, cli.sweep_installed_skills) read that
string's exact text/truthiness for a verdict (B-617's note).

Every assertion here pairs "the leak is gone" with "the subject was not accidentally
emptied" (this repo's own C-135 lesson: a redaction test whose subject is absent proves
nothing).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent


def _home_with_workspace(tmp_path: Path, workspace_value: str) -> Path:
    """Like `_home`, but the config carries an ALREADY-ABSOLUTE workspace value instead
    of `~`. This suite's own `conftest.py:223` redirects `$HOME` to a `/tmp/...` sandbox
    for the whole session, so a value relying on `~` expansion can never land under a
    literal `/home/` or `/Users/` prefix here -- an already-absolute value sidesteps that
    and stays portable (no real developer's username embedded in this file)."""
    home = tmp_path / "home"
    home.mkdir()
    cfg = {
        "agents": {
            "list": [{"id": "main"}],
            "defaults": {"workspace": workspace_value},
        }
    }
    c = home / "openclaw.json"
    c.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(c, 0o600)
    return home


def _run(home: Path, tmp_path: Path, *extra: str) -> subprocess.CompletedProcess:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", "--home", str(home),
         "--data-dir", str(data), "--no-history", *extra],
        capture_output=True, text=True, cwd=str(_REPO),
    )


@pytest.mark.parametrize("workspace_value", [
    "/home/testuser/.cache/csc-b620-ws",
    "/Users/testuser/.cache/csc-b620-ws",
])
def test_sarif_limit_hits_redacts_production_home_prefixes_end_to_end(tmp_path, workspace_value):
    """Narrowed to what B-620 was filed about, and to what `report._redact_home_paths`
    actually covers: a literal `/home/<user>` or `/Users/<user>` prefix -- real `$HOME`
    on Linux/macOS (Windows' `C:\\Users\\<user>` is covered too, but pathlib on this
    Linux test runner won't treat a backslash string as absolute, so it is pinned at the
    string-substitution level instead -- see
    `test_render_sarif_redacts_via_the_shared_home_path_helper`).

    The workspace value is already absolute (not `~`) so the assertion is independent of
    this suite's own HOME-isolation fixture -- see `_home_with_workspace`'s docstring.
    """
    home = _home_with_workspace(tmp_path, workspace_value)
    sarif_path = tmp_path / "out.sarif"
    result = _run(home, tmp_path, "--sarif", str(sarif_path))
    assert result.returncode in (0, 1), result.stderr

    doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    hits = doc["runs"][0]["properties"]["analysis_completeness"]["limit_hits"]

    # Non-vacuity: the workspace-outside-home limit hit really fired.
    assert any("csc-b620-ws" in h for h in hits), hits

    username_prefix = workspace_value.rsplit("/.cache", 1)[0]  # e.g. "/home/testuser"
    for h in hits:
        assert username_prefix not in h, h
    # The redaction preserves the informative remainder (B-381's stated goal: still
    # useful for someone debugging a truncated scan), just without the username prefix.
    assert any(h.startswith("custom workspace") and "~/.cache/csc-b620-ws" in h for h in hits), hits


def test_sarif_limit_hits_still_leaks_a_non_home_absolute_path(tmp_path):
    """PINNED RESIDUAL -- not fixed by this change; reported to the coordinator as its
    own follow-up (B-620's diagnosis, not a new defect found independently).

    `report._redact_home_paths` / `_HOME_PATH_RE` is PREFIX-matching against the three
    literal shapes a real `$HOME` takes (`/home/<user>`, `/Users/<user>`,
    `C:\\Users\\<user>`) -- it is not a general basename reduction. A workspace (or,
    identically, a `--home`) that resolves under any OTHER root still reaches SARIF
    `limit_hits` VERBATIM today. This suite's own HOME-isolation fixture
    (`conftest.py:223`, `/tmp/pytest-of-.../isolated-homeN/...`) is one live instance;
    a real user running `clawseccheck --home /mnt/backup` is another.

    Deliberately a plain assertion of CURRENT behaviour -- no `xfail`/`skip` (forbidden
    here) -- so the next reader does not read the tests above and conclude SARIF is now
    fully path-clean. Closing this needs a basename-reduction helper for the SARIF copy
    specifically; that is a separate, deliberate decision (lossier than `~`-substitution
    -- see sarif.py's B-620 comment), not something to fold into this change silently.
    """
    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "elsewhere" / "csc-b620-ws"
    cfg = {
        "agents": {
            "list": [{"id": "main"}],
            "defaults": {"workspace": str(outside)},
        }
    }
    c = home / "openclaw.json"
    c.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(c, 0o600)

    sarif_path = tmp_path / "out.sarif"
    result = _run(home, tmp_path, "--sarif", str(sarif_path))
    assert result.returncode in (0, 1), result.stderr

    doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    hits = doc["runs"][0]["properties"]["analysis_completeness"]["limit_hits"]
    assert any("csc-b620-ws" in h for h in hits), hits  # non-vacuity

    resolved_outside = str(outside.resolve())
    assert any(resolved_outside in h for h in hits), (
        "residual behaviour changed -- either this is now fixed (replace this pin with "
        "a real no-leak assertion) or something else moved: " + repr(hits)
    )


def test_stored_ctx_limit_hits_is_untouched(tmp_path):
    """Verdict-neutrality (B-617's constraint): B13 / dossier leg 2 / cli.sweep_installed_skills
    read `ctx.limit_hits` verbatim, so the STORED string must still carry the absolute
    path -- only the SARIF copy may be redacted. Uses an already-absolute workspace value
    (not `~`/`Path.home()`) so the assertion needs no ambient-home read -- forbidden in
    this suite by `tests/test_b519_store_isolation.py`, which redirects `$HOME` for the
    whole session and would make a `Path.home()`-based comparison here pass vacuously."""
    sys.path.insert(0, str(_REPO))
    from clawseccheck import collector  # noqa: PLC0415

    workspace_value = "/home/testuser/.cache/csc-b620-ws"
    home = _home_with_workspace(tmp_path, workspace_value)
    ctx = collector.collect(str(home))
    assert any(workspace_value in h for h in ctx.limit_hits), ctx.limit_hits


def test_json_and_text_reports_do_not_leak_the_workspace_path(tmp_path):
    """DoD: sweep `--json` / the text renderer for the same exposure. Neither renders
    `ctx.limit_hits` directly (only `ctx.disclosures`, already bare-name per B-617, and a
    truthiness check), so this pins that they stay clean too. Same already-absolute
    workspace value as above -- no ambient-home read."""
    workspace_value = "/home/testuser/.cache/csc-b620-ws"
    home = _home_with_workspace(tmp_path, workspace_value)

    text = _run(home, tmp_path).stdout
    # Non-vacuity: the workspace-outside-home condition really fired and was rendered
    # (B-617's disclosure channel), so "the path never appears" is not true merely
    # because nothing relevant printed.
    assert "csc-b620-ws" in text, text
    assert workspace_value not in text, text

    payload = json.loads(_run(home, tmp_path, "--json").stdout)
    assert any(d["kind"] == "workspace_outside_home" for d in payload["disclosures"]), \
        payload["disclosures"]
    assert "limit_hits" not in payload, sorted(payload)
    blob = json.dumps(payload)
    assert workspace_value not in blob, blob


def test_render_sarif_does_not_mutate_ctx_limit_hits():
    """Unit-level pin, independent of the subprocess repro: `render_sarif` must build a
    NEW list, never rewrite `ctx.limit_hits` in place."""
    from clawseccheck.collector import Context
    from clawseccheck.sarif import render_sarif

    tainted = "custom workspace 'x' resolves outside the audited --home (/home/dave/x)"
    ctx = Context(home=Path("/tmp"))
    ctx.limit_hits = [tainted]

    render_sarif([], ctx=ctx)

    assert ctx.limit_hits == [tainted]


def test_render_sarif_redacts_via_the_shared_home_path_helper():
    """Single source of truth: the SARIF output must match `report._redact_home_paths`
    applied directly, not a second, independently-written redaction rule."""
    from clawseccheck.collector import Context
    from clawseccheck.report import _redact_home_paths
    from clawseccheck.sarif import render_sarif

    entries = [
        "custom workspace 'x' resolves outside the audited --home (/home/dave/.cache/x)",
        "cron store '/home/dave/.local/share/openclaw/cron/jobs.json' exceeded the cap",
        "custom workspace 'y' resolves outside the audited --home (/Users/dave/.cache/y)",
        "no path here at all",
    ]
    ctx = Context(home=Path("/tmp"))
    ctx.limit_hits = list(entries)

    doc = json.loads(render_sarif([], ctx=ctx))
    got = doc["runs"][0]["properties"]["analysis_completeness"]["limit_hits"]

    assert got == [_redact_home_paths(e) for e in entries]
    assert not any("/home/dave" in g for g in got), got


def test_sarif_limit_hits_empty_stays_empty():
    """The negative control for the non-vacuity guard above: nothing to redact must not
    become a non-empty list, and must not crash."""
    from clawseccheck.collector import Context
    from clawseccheck.sarif import render_sarif

    ctx = Context(home=Path("/tmp"))
    doc = json.loads(render_sarif([], ctx=ctx))
    assert doc["runs"][0]["properties"]["analysis_completeness"]["limit_hits"] == []
