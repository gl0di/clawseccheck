"""Tests for .github/workflows/ci.yml.

This file existed with ~1,300 lines of tests pinning the sibling publish workflow and
none at all pinning CI — so the gate that actually protects `main` could be narrowed
silently, while the one that ships to users could not. C-543/C-544 made the two
workflows depend on each other (the publish job reads the check-runs CI produces), and
a dependency nothing pins is a dependency that rots.

Read as YAML here rather than as text: these assertions are about structure (triggers,
concurrency, job names), not about wording.
"""
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml is not a runtime dep; skip where absent")

REPO_ROOT = Path(__file__).resolve().parents[1]
CI_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PUBLISH_PATH = REPO_ROOT / ".github" / "workflows" / "clawhub-publish.yml"


def _ci() -> dict:
    return yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))


def _triggers(doc: dict) -> dict:
    # PyYAML parses a bare `on:` key as the boolean True (the Norway problem), so accept
    # either spelling rather than asserting one and silently testing nothing.
    return doc.get("on") if "on" in doc else doc.get(True)


def test_push_is_filtered_to_the_long_lived_branches() -> None:
    """An unfiltered `push:` alongside `pull_request:` validates a PR branch twice.

    Measured on the v4.2.0 release: five CI runs where three would do — the dev push and
    the PR-opened event covered the same tree, and the tag push re-ran everything on a
    commit `main` had proven green 24 minutes earlier (~56 runner-minutes per run, the
    3.9 leg alone taking 23m32s).
    """
    push = _triggers(_ci())["push"]
    assert isinstance(push, dict) and "branches" in push, (
        "ci.yml's `push:` trigger must be filtered by branch — unfiltered, every PR "
        "branch push runs the matrix a second time on top of the pull_request event."
    )
    assert set(push["branches"]) == {"main", "dev"}, (
        f"Expected push filtered to main/dev, got {push['branches']!r}."
    )


def test_ci_does_not_run_on_tag_pushes() -> None:
    """A tag points at a commit `main` already validated; re-running is pure duplication.

    This is only safe because clawhub-publish.yml reads the SHA's existing check-runs
    instead of waiting for a fresh run — so the two assertions live together here: if
    someone removes the publish-side gate, this test's reason for existing is gone and
    the comment below is where they should land.
    """
    push = _triggers(_ci())["push"]
    assert "tags" not in push, (
        "ci.yml must not run on tag pushes: the tagged commit was already validated on "
        "main, and the publish workflow consumes those check-runs."
    )

    publish = PUBLISH_PATH.read_text(encoding="utf-8")
    assert "commits/${GITHUB_SHA}/check-runs" in publish, (
        "Dropping the tag trigger is only correct while the publish workflow gates on "
        "the SHA's existing check-runs. That gate is missing — restore it, or the "
        "release path consults no CI result at all."
    )


def test_concurrency_never_cancels_a_main_run() -> None:
    """Superseded runs should be cancelled — except on the branch a release is cut from.

    `main`'s check-runs are what the publish gate reads. Cancelling one because another
    commit landed would leave a SHA with an incomplete context set, which that gate
    (correctly) refuses to publish.
    """
    doc = _ci()
    conc = doc.get("concurrency")
    assert isinstance(conc, dict), "ci.yml must declare a `concurrency:` group."
    assert "${{ github.ref }}" in conc.get("group", ""), (
        "The concurrency group must be per-ref, or unrelated branches cancel each other."
    )
    cancel = str(conc.get("cancel-in-progress", ""))
    assert "refs/heads/main" in cancel and "!=" in cancel, (
        "cancel-in-progress must exempt main — a cancelled main run leaves the SHA "
        f"without the contexts the publish gate requires. Got: {cancel!r}"
    )


def test_required_contexts_exist_as_jobs() -> None:
    """The publish gate's required-context list must name jobs CI actually produces.

    A context that no job emits can never go green, so the gate would block every
    release; a job renamed here without updating the gate does the same thing. Pinning
    both sides against each other is what keeps the rename honest.
    """
    doc = _ci()
    jobs = doc["jobs"]

    # Read the value through YAML rather than by regex: the block is a literal scalar
    # inside a step's env, and a text scan bounded only by indentation swallows the
    # `run:` body that follows it.
    publish_doc = yaml.safe_load(PUBLISH_PATH.read_text(encoding="utf-8"))
    declared = [
        (step.get("env") or {}).get("REQUIRED_CONTEXTS")
        for step in publish_doc["jobs"]["publish"]["steps"]
    ]
    raw = next((v for v in declared if v), None)
    assert raw, "The publish gate must declare REQUIRED_CONTEXTS in its step env."
    contexts = [line.strip() for line in raw.splitlines() if line.strip()]
    assert contexts, "REQUIRED_CONTEXTS is empty — the gate would pass vacuously."

    # A matrix job's context is "<job> (<matrix values, comma-joined>)"; a plain job's is
    # just its name. Derive both shapes from ci.yml rather than hardcoding the six.
    produced = set()
    for name, job in jobs.items():
        include = (job.get("strategy") or {}).get("matrix", {}).get("include")
        if include:
            for combo in include:
                produced.add(f"{name} ({', '.join(str(v) for v in combo.values())})")
        else:
            produced.add(name)

    missing = [c for c in contexts if c not in produced]
    assert not missing, (
        f"The publish gate requires contexts no ci.yml job produces: {missing}. "
        f"ci.yml produces: {sorted(produced)}"
    )


def test_every_third_party_action_is_sha_pinned() -> None:
    """A floating tag can be moved; a SHA cannot.

    ci.yml runs on every push including PRs from forks, so an action resolved by tag is
    an arbitrary-code-execution surface that someone else controls.
    """
    unpinned = []
    for lineno, line in enumerate(CI_PATH.read_text(encoding="utf-8").splitlines(), 1):
        m = re.search(r"uses:\s*([^\s#]+)", line)
        if not m or m.group(1).startswith("./"):
            continue
        ref = m.group(1).split("@")[-1]
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            unpinned.append(f"{lineno}: {m.group(1)}")
    assert not unpinned, f"Actions must be pinned to a full commit SHA: {unpinned}"
