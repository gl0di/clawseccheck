"""C-745: the printed fetch plan must not run the target's build/lifecycle code."""
from clawseccheck.report import render_vet_plan


def _line(out, verb):
    return next(ln.strip() for ln in out.splitlines() if ln.strip().startswith(verb))


def test_pypi_fetch_is_wheels_only():
    out = render_vet_plan("pypi:requests==2.0")
    assert "--only-binary=:all:" in _line(out, "pip download")


def test_pypi_plan_says_stop_when_no_wheel():
    out = render_vet_plan("pypi:requests")
    assert "No wheel for this package? Stop and tell the user" in out
    assert "do NOT retry without" in out


def test_other_ecosystems_have_no_pip_note():
    assert "No wheel" not in render_vet_plan("npm:left-pad")


def test_plan_does_not_claim_containment():
    for t in ("pypi:x", "npm:x", "git:github.com/o/r", "https://x.test/a"):
        out = render_vet_plan(t).replace("$QUARANTINE", "$DIR").replace("QUARANTINE=", "DIR=").lower()
        assert "not a sandbox" in out
        assert "quarantine" not in out


def test_npm_line_ignores_scripts_and_git_specs_get_no_npm_line():
    assert "--ignore-scripts" in _line(render_vet_plan("npm:left-pad@1.0.0"), "npm pack")
    # a git spec makes npm run `prepare` while packing; `--ignore-scripts` was the first
    # answer, refusing the spec outright (and pointing at `git:`) is the one we keep
    for t in ("npm:github:owner/repo", "npm:owner/repo", "npm:git+https://example.test/o/r.git"):
        assert "npm pack" not in render_vet_plan(t), t


def test_git_clone_does_not_recurse_submodules():
    assert "--recurse-submodules" not in render_vet_plan("git:github.com/o/r@main")


# --- the security review of the first fix: only a plain REGISTRY spec gets a command --------

import pytest  # noqa: E402

from clawseccheck.report import render_vet_plan as _plan  # noqa: E402

_REFUSED = [
    "pypi:git+https://example.invalid/o/r",          # VCS: no wheel, pip BUILDS it
    "pypi:foo @ git+https://example.invalid/o/r",    # PEP 508 direct reference
    "pypi:https://example.invalid/x.tar.gz",         # direct sdist URL
    "pypi:./local",                                   # local path
    "pypi:foo[extra]",                                # extras are not a project name
    "npm:github:o/r",                                 # git dependency: npm runs `prepare`
    "npm:o/r",                                        # GitHub shorthand
    "npm:git+https://example.invalid/o/r.git",
    "npm:file:../x",
    "npm:https://example.invalid/x.tgz",
    "npm:alias@npm:left-pad",                         # alias
]


@pytest.mark.parametrize("target", _REFUSED)
def test_a_non_registry_spec_gets_no_package_manager_command(target):
    out = _plan(target)
    assert out.startswith("I will not build a fetch plan for this target.")
    assert "pip download" not in out and "npm pack" not in out
    assert "git:host/owner/repo" in out           # points at the form that fetches without running


@pytest.mark.parametrize("target,line", [
    ("pypi:requests==2.0", "pip download --only-binary=:all: --no-deps"),
    ("pypi:Django==4.2.1+cpu", "pip download --only-binary=:all: --no-deps"),
    ("npm:left-pad@1.0.0", "npm pack left-pad@1.0.0 --ignore-scripts"),
    ("npm:@scope/pkg@2", "npm pack @scope/pkg@2 --ignore-scripts"),
    ("npm:left-pad@latest", "npm pack left-pad@latest --ignore-scripts"),
])
def test_a_plain_registry_spec_still_gets_its_command(target, line):
    assert line in _plan(target)
