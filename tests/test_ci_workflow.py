"""Tests for .github/workflows/ci.yml.

~1,300 lines of tests pinned the sibling publish workflow and none pinned CI — so the
gate that protects `main` could be narrowed silently while the one that ships to users
could not. C-543/C-544 then made the two workflows depend on each other (the publish job
reads the check-runs CI produces), and a dependency nothing pins is one that rots.

Read as TEXT, not via pyyaml, for the reason tests/test_publish_workflow.py states in its
own docstring: the package is stdlib-only and CI installs exactly `pytest` and `ruff`. A
first version of this file used `pytest.importorskip("yaml")`, which passed locally (this
box happens to have pyyaml) and SKIPPED THE ENTIRE MODULE on every CI run — five guards
reporting green while never executing. That is the failure mode this project's §4 forbids,
and it was caught only by an independent pre-release review. Do not reintroduce a yaml
import here: if a future assertion genuinely needs a parser, add pyyaml to ci.yml's install
line so its absence reddens the build instead of silencing the file.
"""
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CI_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PUBLISH_PATH = REPO_ROOT / ".github" / "workflows" / "clawhub-publish.yml"


def _strip_comments(text: str) -> str:
    """Drop whole-line comments so prose about a key is never mistaken for the key."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _top_level_block(text: str, key: str) -> str:
    """Return the lines under a top-level `key:`, up to the next top-level key."""
    lines = _strip_comments(text).splitlines()
    out, collecting = [], False
    for line in lines:
        if re.match(rf"^{re.escape(key)}:", line):
            collecting = True
            out.append(line)
            continue
        if collecting:
            if line and not line[0].isspace():
                break
            out.append(line)
    return "\n".join(out)


def test_push_is_filtered_to_the_long_lived_branches() -> None:
    """An unfiltered `push:` alongside `pull_request:` validates a PR branch twice.

    Measured on the v4.2.0 release: five CI runs where three would do — the dev push and
    the PR-opened event covered the same tree, and the tag push re-ran everything on a
    commit `main` had proven green 24 minutes earlier (~56 runner-minutes per run, the
    3.9 leg alone 23m32s).
    """
    # PyYAML would read a bare `on:` as the boolean True; reading text sidesteps that
    # entirely, which is a second reason this module does not want a parser.
    block = _top_level_block(CI_PATH.read_text(encoding="utf-8"), "on")
    assert block, "ci.yml has no top-level `on:` block."

    branches = re.search(r"^\s+push:\s*\n\s+branches:\s*\[([^\]]*)\]", block, re.M)
    assert branches, (
        "ci.yml's `push:` trigger must be filtered by branch — unfiltered, every PR "
        f"branch push runs the matrix a second time on top of the pull_request event.\n"
        f"Got:\n{block}"
    )
    got = {b.strip().strip("'\"") for b in branches.group(1).split(",") if b.strip()}
    assert got == {"main", "dev"}, f"Expected push filtered to main/dev, got {sorted(got)}."


def test_ci_does_not_run_on_tag_pushes() -> None:
    """A tag points at a commit `main` already validated; re-running is pure duplication.

    This is only safe because clawhub-publish.yml reads the SHA's existing check-runs
    instead of waiting for a fresh run, so both halves are asserted together: if someone
    removes the publish-side gate, the test that justifies dropping the tag trigger fails
    and says why.
    """
    block = _top_level_block(CI_PATH.read_text(encoding="utf-8"), "on")
    assert not re.search(r"^\s+tags(-ignore)?:", block, re.M), (
        "ci.yml must not run on tag pushes: the tagged commit was already validated on "
        f"main, and the publish workflow consumes those check-runs.\nGot:\n{block}"
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
    block = _top_level_block(CI_PATH.read_text(encoding="utf-8"), "concurrency")
    assert block, "ci.yml must declare a top-level `concurrency:` group."
    assert "${{ github.ref }}" in block, (
        "The concurrency group must be per-ref, or unrelated branches cancel each other."
    )
    cancel = re.search(r"cancel-in-progress:\s*(.+)", block)
    assert cancel, "concurrency must set cancel-in-progress."
    expr = cancel.group(1).strip()
    assert "refs/heads/main" in expr and "!=" in expr, (
        "cancel-in-progress must exempt main — a cancelled main run leaves the SHA "
        f"without the contexts the publish gate requires. Got: {expr!r}"
    )


def _ci_contexts_on_push_to_main() -> set:
    """The check-run names ci.yml produces for a push to main.

    A matrix job's context is "<job> (<matrix values, comma-joined>)"; a plain job's is
    its name. Jobs gated on `pull_request` do not run on a push and so cannot be required.
    """
    text = _strip_comments(CI_PATH.read_text(encoding="utf-8"))
    jobs_block = text.split("\njobs:", 1)[1]
    produced = set()
    # Job keys sit at exactly two spaces of indent inside `jobs:`.
    for m in re.finditer(r"^  ([A-Za-z0-9_-]+):\s*$", jobs_block, re.M):
        name = m.group(1)
        start = m.end()
        nxt = re.search(r"^  [A-Za-z0-9_-]+:\s*$", jobs_block[start:], re.M)
        body = jobs_block[start:start + nxt.start()] if nxt else jobs_block[start:]
        if re.search(r"^\s+if:.*pull_request", body, re.M):
            continue
        combos = re.findall(r"^\s+- \{([^}]*)\}\s*$", body, re.M)
        if combos:
            for combo in combos:
                values = [p.split(":", 1)[1].strip().strip("'\"") for p in combo.split(",")]
                produced.add(f"{name} ({', '.join(values)})")
        else:
            produced.add(name)
    return produced


def _declared_required_contexts() -> list:
    """The contexts the publish gate requires, read out of its literal YAML block."""
    text = PUBLISH_PATH.read_text(encoding="utf-8")
    m = re.search(r"^(\s+)REQUIRED_CONTEXTS:\s*\|\s*$", text, re.M)
    assert m, "The publish gate must declare REQUIRED_CONTEXTS as a literal (|) block."
    indent = len(m.group(1))
    out = []
    for line in text[m.end():].splitlines()[1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= indent:
            break
        if line.strip():
            out.append(line.strip())
    return out


def test_required_contexts_match_the_jobs_ci_runs_on_main() -> None:
    """The gate's list and ci.yml's push-to-main jobs must be the SAME set, both ways.

    A one-directional check (every required context exists) lets the list be silently
    narrowed — delete five of six lines and it still passes — and lets a newly protected
    job be added without the release path ever requiring it. The gate's own comment
    concedes this list is a second copy of branch protection; equality in both directions
    is what keeps that copy honest.
    """
    contexts = _declared_required_contexts()
    assert contexts, "REQUIRED_CONTEXTS is empty — the gate would pass vacuously."

    produced = _ci_contexts_on_push_to_main()
    assert set(contexts) == produced, (
        "The publish gate's required contexts must equal the jobs ci.yml runs on a push "
        f"to main.\n  gate requires: {sorted(contexts)}\n  ci.yml produces: {sorted(produced)}\n"
        f"  only in gate: {sorted(set(contexts) - produced)}\n"
        f"  only in ci.yml: {sorted(produced - set(contexts))}"
    )


def test_the_gate_refuses_an_empty_context_list_in_the_shell() -> None:
    """The one fail-open path must be closed by the workflow, not only by this file.

    With REQUIRED_CONTEXTS empty the loop reads nothing, so pending/failed/missing all
    stay empty and the step announces "all required checks are green" having checked
    none. `set -u` catches unset but not empty, so the shell has to say so itself — a
    test cannot, because a test that is skipped (as this whole module once was in CI)
    protects nothing.
    """
    text = PUBLISH_PATH.read_text(encoding="utf-8")
    assert "REQUIRED_CONTEXTS is empty" in text, (
        "The gate step must fail explicitly on an empty REQUIRED_CONTEXTS."
    )
    guard = text.index("REQUIRED_CONTEXTS is empty")
    loop = text.index("for attempt in $(seq")
    assert guard < loop, "The empty-list guard must run before the polling loop."


def test_duplicate_check_runs_are_folded_worst_first() -> None:
    """One context name can appear more than once on a SHA, and order is not a contract.

    Measured on c26a8ba: each of the six required names appears twice, from two
    check-suites, because the endpoint's `latest` filter does not dedupe across suites.
    Taking the first row makes the verdict depend on the API's undocumented ordering — a
    green copy listed before a failed one would pass the gate.
    """
    text = PUBLISH_PATH.read_text(encoding="utf-8")
    gate = text[text.index("Gate — the commit being published"):]
    gate = gate[: gate.index("\n      - name:", 1)]
    assert "{print; exit}" not in gate, (
        "The gate must not stop at the first matching check-run: duplicates are real and "
        "their order is not guaranteed, so every row for a context has to be folded."
    )
    assert "select(.app.id ==" in gate, (
        "The check-run query must select the app branch protection pins these contexts "
        "to, or a same-named run from any other app could satisfy a required context."
    )
