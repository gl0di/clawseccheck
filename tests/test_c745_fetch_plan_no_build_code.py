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


def test_npm_line_ignores_scripts_for_registry_and_git_specs():
    for t in ("npm:left-pad@1.0.0", "npm:github:owner/repo", "npm:owner/repo",
              "npm:git+https://example.test/o/r.git"):
        assert "--ignore-scripts" in _line(render_vet_plan(t), "npm pack"), t


def test_git_clone_does_not_recurse_submodules():
    assert "--recurse-submodules" not in render_vet_plan("git:github.com/o/r@main")
