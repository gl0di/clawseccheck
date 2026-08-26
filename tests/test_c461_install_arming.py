"""CLAWSECCHECK-C-461 (item 1) — `openclaw_install` is armed at exactly one call site,
in `cli.py`'s `--monitor` branch: `snapshot(..., install=_install_snap, ...)`. Its sibling
`skill_provenance` is pinned at that call site by
`tests/test_f174_monitor_arms.py::test_a_run_that_found_no_install_records_writes_no_
dimension_at_all` and `::test_a_decoy_lock_file_cannot_silence_a_downgrade_in_the_winning_
record` — both drive the real CLI. This dimension had no equivalent: every existing test
for it (`tests/test_f174_openclaw_install.py`, the "the OpenClaw install" section of
`tests/test_f174_monitor_arms.py`) calls `describe_install`/`diff_with_notes` directly, so
the call site itself could be changed to `install=None` and the whole suite would stay
green. This file closes that gap.

Hermetic by construction, matching `tests/test_f174_openclaw_install.py`'s idiom: a fake
npm package root is built under `tmp_path`, and `shutil.which` is monkeypatched to resolve
"openclaw" to it — so this test's outcome never depends on whether a real OpenClaw
happens to be installed on the machine running it (`describe_install`'s own resolution
goes through `deptree.find_package_root`, which is PATH-based and name-verified against
the manifest; patching the PATH lookup, rather than injecting a `which=` callable that the
CLI call site never accepts, is what actually reaches `cli.py`'s `_describe_install
("openclaw")` call with no keyword argument of its own).

`--no-host --no-native` are passed on every invocation here for the same reason: left on,
`checks/_capability.py`'s C5 and `native.py`'s `run_native_audit` both query
`shutil.which("openclaw")` too — C5 would stat whatever path the patched resolver names,
and `run_native_audit` would attempt to `subprocess.run` it. Turning both off keeps the
patched resolver's only reader the one this file is about.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from clawseccheck.cli import main
from clawseccheck.openclawdist import describe_install

# Left on so neither host-filesystem scanning nor the built-in-audit subprocess path ever
# reads the patched `shutil.which("openclaw")` — see the module docstring.
_ARGV_TAIL = ("--no-host", "--no-native")


def _pkg(root: Path, *, version: str = "2026.7.1-2", code: str = "console.log(1)\n") -> Path:
    """A minimal but real npm layout: a bin script, a package.json naming itself
    "openclaw" (the soundness gate `find_package_root` checks), and one file under
    dist/ so the code digest is non-empty. Mirrors `test_f174_openclaw_install.py`'s
    `_install` helper."""
    pkg = root / "node_modules" / "openclaw"
    (pkg / "bin").mkdir(parents=True, exist_ok=True)
    (pkg / "package.json").write_text(
        json.dumps({"name": "openclaw", "version": version,
                    "bin": {"openclaw": "bin/cli.js"}}),
        encoding="utf-8")
    (pkg / "bin" / "cli.js").write_text("#!/usr/bin/env node\n", encoding="utf-8")
    (pkg / "dist").mkdir(exist_ok=True)
    (pkg / "dist" / "main.js").write_text(code, encoding="utf-8")
    (pkg / "npm-shrinkwrap.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8")
    return pkg


def _which_resolving_to(pkg: "Path | None"):
    """A resolver that only ever answers for "openclaw" — the one name
    `deptree.find_package_root` (via `describe_install`), `checks/_capability.py`'s C5, and
    `native.py`'s `run_native_audit` all query it by. Never delegates to the real
    `shutil.which`: with `--no-host --no-native` in effect nothing else asks it for
    anything, and a delegating fallback would make the *other* names' answers depend on
    the host running this test, which is exactly what this fixture exists to avoid."""
    bin_path = str(pkg / "bin" / "cli.js") if pkg is not None else None

    def _which(name):
        return bin_path if name == "openclaw" else None

    return _which


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    (home / "openclaw.json").write_text('{"gateway": {"bind": "127.0.0.1"}}',
                                        encoding="utf-8")
    os.chmod(home / "openclaw.json", 0o600)
    return home


def test_a_resolvable_install_is_recorded_with_describe_installs_fields(
        tmp_path, monkeypatch, capsys):
    """THE POSITIVE HALF, and the whole point of this file. Proven by mutation: changing
    `install=_install_snap` to `install=None` at the cli.py call site leaves this
    dimension entirely unrecorded, and nothing else in the suite notices — every other
    test for it drives `describe_install`/`diff_with_notes` directly rather than the real
    CLI. This one does, and asserts the written state carries exactly what the leaf
    itself reports for this fixture."""
    pkg = _pkg(tmp_path)
    monkeypatch.setattr("shutil.which", _which_resolving_to(pkg))

    # Ground truth from the SAME patched resolver the CLI call site will use —
    # `describe_install("openclaw")` with no `which=` argument resolves through
    # `deptree._default_which()` -> `shutil.which`, which is exactly what is patched here.
    # Not a hand-typed expectation: it is what the leaf itself says about this fixture.
    expected = describe_install("openclaw").as_dimension()
    assert expected["code_sha256"], "precondition: the fixture must produce a real digest"
    assert expected["name"] == "openclaw"

    home, store = _home(tmp_path), tmp_path / "store"
    rc = main(["--monitor", "--home", str(home), "--data-dir", str(store), *_ARGV_TAIL])
    capsys.readouterr()
    assert rc == 0

    saved = json.loads((store / "state.json").read_text(encoding="utf-8"))
    assert "openclaw_install" in saved, (
        "a resolvable install must be recorded in state.json — this is the exact key "
        "`install=None` at the cli.py call site would drop"
    )
    assert saved["openclaw_install"] == expected


def test_an_unresolvable_install_is_absent_and_reported_as_a_note_not_an_alert(
        tmp_path, monkeypatch, capsys):
    """THE NEGATIVE CONTROL, through the real CLI.
    `test_an_install_that_could_not_be_located_is_a_note_and_never_an_alert`
    (tests/test_f174_monitor_arms.py) already pins this shape at `diff_with_notes`
    directly, on synthetic prev/curr dicts — it never exercises resolution at all. This
    drives two real `--monitor` runs over the same store: the first with the package
    resolvable (so the baseline carries the key), the second with `shutil.which`
    answering the way a cron job's narrow PATH really does for the same subject — nothing
    found — so the key must come out ABSENT from this run's own snapshot, and the
    resulting comparison must land as a note, never as an alert."""
    pkg = _pkg(tmp_path)
    home, store = _home(tmp_path), tmp_path / "store"
    argv = ["--monitor", "--home", str(home), "--data-dir", str(store), "--verbose",
            *_ARGV_TAIL]

    monkeypatch.setattr("shutil.which", _which_resolving_to(pkg))
    assert main(argv) == 0
    capsys.readouterr()
    baseline = json.loads((store / "state.json").read_text(encoding="utf-8"))
    assert "openclaw_install" in baseline, "precondition: the baseline must carry the key"

    monkeypatch.setattr("shutil.which", _which_resolving_to(None))
    assert main(argv) == 0
    said = capsys.readouterr().out
    curr = json.loads((store / "state.json").read_text(encoding="utf-8"))

    assert "openclaw_install" not in curr, (
        "a run that could not find the package must leave the key ABSENT from its own "
        "snapshot, not carry the previous run's value forward as though observed again"
    )
    assert "could not find it" in said, said
    assert "went BACKWARDS" not in said, said
    assert "program files changed" not in said, said
