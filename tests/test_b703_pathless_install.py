"""B-703 — resolving the installed OpenClaw when there is no PATH.

`find_package_root` located the package through `shutil.which`, and a cron job inherits
neither the user's PATH nor their cwd — `invocation.py` exists for exactly that reason. So
`ctx.installed_dist_version` could be a real version on an interactive run and `None` on a
scheduled one, on the same machine, minutes apart.

That mattered once something started BRANCHING on it. `_openclaw_generation` (B-700) mostly
chooses wording, but B9's absent-field branch lets it move a STATUS — so the alternation
could raise a spurious `--monitor` alert with nothing about the machine having changed.

The fallback is conventional global roots only, each one still name-verified: a directory
sitting at the expected path proves nothing, and `npm root -g` — which would be
authoritative — is a subprocess the doctrine forbids.
"""
import json
import os
import tempfile
from pathlib import Path

import pytest
from _realhome import REAL_HOME

from clawseccheck.deptree import _conventional_package_roots, find_package_root

def _fake_package(name, manifest_name=None):
    """A directory that looks like an installed npm package."""
    root = Path(tempfile.mkdtemp(prefix="b703-"))
    (root / "package.json").write_text(
        json.dumps({"name": manifest_name if manifest_name is not None else name,
                    "version": "1.0.0"}))
    return root


@pytest.fixture()
def real_home(monkeypatch):
    """conftest redirects $HOME so the suite cannot write into the developer's own
    directories (B-519). The resolver expands `~` on purpose — a cron job for user X has
    HOME=/home/X — so a test ABOUT that expansion has to put the real one back, using the
    mechanism conftest documents for exactly this case."""
    monkeypatch.setenv("HOME", str(REAL_HOME))
    return REAL_HOME


def test_the_install_is_found_with_no_path_at_all(real_home):
    """The property, on this machine: an emptied PATH must not change the answer."""
    with_path = find_package_root("openclaw")
    if with_path is None:
        pytest.skip("no installed OpenClaw to resolve")
    without_path = find_package_root("openclaw", which=lambda _n: None)
    assert without_path == with_path


def test_the_generation_does_not_flicker_between_run_shapes(real_home):
    """The property that actually mattered, asserted end to end rather than on the
    resolver: a scheduled run and an interactive run must agree about which OpenClaw is
    installed, because a consumer branches on it."""
    import clawseccheck
    from clawseccheck.checks._shared import _openclaw_generation

    if find_package_root("openclaw") is None:
        pytest.skip("no installed OpenClaw to resolve")

    home = Path(tempfile.mkdtemp(prefix="b703-home-"))
    config = home / "openclaw.json"
    config.write_text("{}")
    os.chmod(config, 0o600)

    interactive, _f, _s = clawseccheck.audit(home, include_dist=True)
    saved = os.environ.get("PATH")
    try:
        os.environ["PATH"] = ""          # what cron actually gives you
        scheduled, _f2, _s2 = clawseccheck.audit(home, include_dist=True)
    finally:
        if saved is not None:
            os.environ["PATH"] = saved
        else:                             # pragma: no cover - PATH is always set here
            os.environ.pop("PATH", None)

    assert scheduled.installed_dist_version == interactive.installed_dist_version
    assert _openclaw_generation(scheduled) == _openclaw_generation(interactive)


# ------------------------------------------------- the name check, on the new path too

def test_a_candidate_that_names_a_different_package_is_refused():
    """The soundness gate the PATH branch already had, applied to the fallback. Skipping
    it here while enforcing it above would put the weaker evidence on the less-observed
    path — which is the one a cron job takes."""
    impostor = _fake_package("openclaw", manifest_name="something-else")
    assert find_package_root("openclaw", which=lambda _n: None,
                             candidate_roots=[impostor]) is None


def test_a_candidate_naming_itself_correctly_is_accepted():
    """The control: without it, "always None" satisfies the test above."""
    genuine = _fake_package("openclaw")
    assert find_package_root("openclaw", which=lambda _n: None,
                             candidate_roots=[genuine]) == genuine


@pytest.mark.parametrize("bad", [
    Path("/definitely/not/here"),
], ids=["missing-directory"])
def test_a_missing_candidate_is_skipped_rather_than_raising(bad):
    genuine = _fake_package("openclaw")
    assert find_package_root("openclaw", which=lambda _n: None,
                             candidate_roots=[bad, genuine]) == genuine


def test_no_candidate_at_all_is_still_none():
    """`None` stays the honest answer — every consumer treats it as UNDETERMINED, and a
    fabricated root would be far worse than not knowing."""
    assert find_package_root("openclaw", which=lambda _n: None, candidate_roots=[]) is None


# ------------------------------------------------- the candidate list itself

def test_the_env_prefixes_npm_honours_come_first():
    """npm itself reads these, so a machine with a custom prefix is found by the same rule
    npm uses rather than by guessing."""
    saved = os.environ.get("npm_config_prefix")
    os.environ["npm_config_prefix"] = "/custom/prefix"
    try:
        roots = _conventional_package_roots("openclaw")
    finally:
        if saved is None:
            os.environ.pop("npm_config_prefix", None)
        else:
            os.environ["npm_config_prefix"] = saved
    assert roots[0] == Path("/custom/prefix/lib/node_modules/openclaw")


def test_the_candidate_list_is_package_scoped_and_absolute():
    roots = _conventional_package_roots("openclaw")
    assert roots, "an empty candidate list would make the fallback decorative"
    for root in roots:
        assert root.is_absolute()
        assert root.name == "openclaw", f"{root} is not scoped to the package"


def test_the_resolver_runs_no_subprocess():
    """`npm root -g` would be authoritative and is exactly what CLAUDE.md §1/§2 forbid at
    runtime. Asserted on the source, because a subprocess added later would otherwise pass
    every behavioural test above."""
    source = (Path(__file__).resolve().parent.parent
              / "clawseccheck" / "deptree.py").read_text()
    body = source.split("def _conventional_package_roots", 1)[1].split("\ndef ", 1)[0]
    # Docstring and comments stripped first: the prose says "no subprocess", and an
    # assertion that reads its own explanation as the violation can only be satisfied by
    # deleting the sentence that explains it. (Same trap as F-183's `SELECT *` guard.)
    code = body.split('"""', 2)[-1]
    code = "\n".join(ln for ln in code.splitlines() if not ln.lstrip().startswith("#"))
    for forbidden in ("subprocess", "popen", "os.system"):
        assert forbidden not in code.lower(), forbidden
