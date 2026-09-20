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


# ---------------------------------------------------------------------------
# Hygiene + fail-closed commit-integrity
# ---------------------------------------------------------------------------
import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
import textwrap  # noqa: E402

import pytest  # noqa: E402

WORKFLOWS = REPO_ROOT / ".github" / "workflows"
# Labels dependabot.yml may use. Only "dependencies" is grounded in the repo's
# label list; the rest are the common GitHub defaults and are not verified here.
_KNOWN_LABELS = ("dependencies", "bug", "documentation", "enhancement")


def _job_blocks() -> dict:
    text = _strip_comments(CI_PATH.read_text(encoding="utf-8"))
    jobs = text.split("\njobs:", 1)[1]
    keys = list(re.finditer(r"^  ([A-Za-z0-9_-]+):\s*$", jobs, re.M))
    return {
        m.group(1): jobs[m.end(): keys[i + 1].start() if i + 1 < len(keys) else len(jobs)]
        for i, m in enumerate(keys)
    }


def test_every_job_has_a_bounded_timeout() -> None:
    for name, body in _job_blocks().items():
        m = re.search(r"^    timeout-minutes:\s*(\d+)\s*$", body, re.M)
        assert m and 1 <= int(m.group(1)) <= 120, f"job {name!r} needs timeout-minutes 1..120"


def test_permissions_are_read_only_at_top_level() -> None:
    block = _top_level_block(CI_PATH.read_text(encoding="utf-8"), "permissions")
    assert re.search(r"^\s+contents:\s*read\s*$", block, re.M), block
    assert not re.search(r":\s*write\b", block), block


def test_every_action_is_pinned_to_a_full_sha() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        for line in _strip_comments(path.read_text(encoding="utf-8")).splitlines():
            m = re.search(r"\buses:\s*(\S+)", line)
            if m and not m.group(1).startswith("./"):
                assert re.search(r"@[0-9a-f]{40}$", m.group(1)), f"{path.name}: {m.group(1)}"


def test_dead_and_unpinned_steps_are_gone() -> None:
    body = _strip_comments(CI_PATH.read_text(encoding="utf-8"))
    assert "Hunt advisory" not in body and "clawrange" not in body.lower()
    assert "pip install --upgrade" not in body and "--upgrade pip" not in body


def test_dependabot_labels_exist() -> None:
    text = (REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    section = text.split("labels:", 1)[1].split("commit-message:")[0]
    labels = re.findall(r'^\s+-\s+"([^"]+)"\s*$', section, re.M)
    assert labels and set(labels) <= set(_KNOWN_LABELS), labels


def test_dependabot_watches_the_ci_toolchain_manifests() -> None:
    """npm/pip ecosystems watch .github/tools, closing the update-channel blind spot.

    CLAWSECCHECK-C-548: before this, clawhub/markdownlint-cli (npm, `npm i -g`) and
    pytest/ruff (pip, inline `pip install`) had no update channel or advisory path —
    Dependabot's github-actions ecosystem only ever parses `uses:` lines.
    """
    text = (REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    for ecosystem in ("npm", "pip"):
        m = re.search(
            rf'package-ecosystem:\s*"{ecosystem}"\s*\n\s*directory:\s*"([^"]+)"',
            text,
        )
        assert m, f"No {ecosystem!r} package-ecosystem block found in dependabot.yml"
        assert m.group(1).rstrip("/").endswith(".github/tools"), (
            f"{ecosystem} ecosystem directory {m.group(1)!r} should scope to "
            ".github/tools, not the whole repo — a repo-root directory would also "
            "pick up the intentionally-vulnerable fixtures/**/requirements.txt "
            "test vectors, which must NOT be touched by Dependabot."
        )


def test_ci_uses_pinned_toolchain_manifests() -> None:
    """markdownlint-cli and pytest/ruff install from the pinned .github/tools manifests.

    CLAWSECCHECK-C-548: 'npm install -g markdownlint-cli@X' and a bare
    'pip install pytest==X ruff==Y' each resolve their own transitive tree fresh at
    install time, with no lockfile and no hash check. Both jobs now install from the
    committed .github/tools/package-lock.json ('npm ci --ignore-scripts') and
    .github/tools/requirements-ci.txt ('pip install --require-hashes').
    """
    markdownlint_body = _step_body("Install markdownlint-cli")
    assert "npm ci --ignore-scripts --prefix .github/tools" in markdownlint_body
    assert "GITHUB_PATH" in markdownlint_body
    assert "npm install -g" not in _strip_comments(CI_PATH.read_text(encoding="utf-8"))

    test_job_body = _job_blocks()["test"]
    assert (
        "pip install --require-hashes -r .github/tools/requirements-ci.txt"
        in test_job_body
    )


def _step_body(name_fragment: str) -> str:
    lines = CI_PATH.read_text(encoding="utf-8").splitlines()
    start = next(
        i for i, ln in enumerate(lines)
        if ln.strip().startswith("- name:") and name_fragment in ln
    )
    run_i = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == "run: |")
    indent = len(lines[run_i]) - len(lines[run_i].lstrip())
    body = []
    for ln in lines[run_i + 1:]:
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
            break
        body.append(ln)
    return textwrap.dedent("\n".join(body))


def test_range_step_has_no_expression_interpolation() -> None:
    assert "${{" not in _step_body("Resolve the commit range")


_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
}


def _git(cwd, *args):
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=cwd, env=_ENV, capture_output=True, text=True, check=True,
    ).stdout.strip()


def _commit(cwd, msg, author="gl0di <gl0di@users.noreply.github.com>"):
    _git(cwd, "commit", "--allow-empty", "-m", msg, "--author", author)
    return _git(cwd, "rev-parse", "HEAD")


def _bash(script, cwd, **env):
    out = cwd / "gh_output"
    r = subprocess.run(
        ["bash", "-e", "-c", script], cwd=cwd, capture_output=True, text=True,
        env={**_ENV, "GITHUB_OUTPUT": str(out), **env},
    )
    rng = ""
    if out.exists():
        m = re.search(r"range=(.*)", out.read_text())
        rng = m.group(1) if m else ""
    return r, rng


def _range(cwd, **env):
    return _bash(_step_body("Resolve the commit range"), cwd, **env)


def _chain(step, rng, cwd):
    return _bash(_step_body(step), cwd, RANGE=rng)


needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")

TRAILER = "\n\nCo-Authored-By: Claude <noreply@anthropic.com>"


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    return tmp_path


@needs_bash
def test_unresolvable_pr_base_fails_closed(repo) -> None:
    _commit(repo, "root")
    r, _ = _range(repo, EVENT="pull_request", BASE_REF="nope", BEFORE="", SHA="HEAD")
    assert r.returncode != 0 and "Cannot resolve" in r.stdout


@needs_bash
def test_unsupported_event_fails_closed(repo) -> None:
    _commit(repo, "root")
    r, _ = _range(repo, EVENT="schedule", BASE_REF="", BEFORE="", SHA="HEAD")
    assert r.returncode != 0


@needs_bash
def test_root_commit_push_inspects_whole_history(repo) -> None:
    sha = _commit(repo, "root")
    r, rng = _range(repo, EVENT="push", BASE_REF="", BEFORE="0" * 40, SHA=sha)
    assert r.returncode == 0 and "Inspecting 1 commit(s)" in r.stdout, r.stdout + r.stderr
    assert rng


@needs_bash
def test_force_push_missing_before_warns_and_still_inspects(repo) -> None:
    sha = _commit(repo, "root")
    r, rng = _range(repo, EVENT="push", BASE_REF="", BEFORE="1" * 40, SHA=sha)
    assert r.returncode == 0 and "::warning::" in r.stdout and "Inspecting 1" in r.stdout
    assert rng


@needs_bash
def test_multi_commit_push_range_covers_middle_commit(repo) -> None:
    before = _commit(repo, "root")
    _commit(repo, "middle" + TRAILER)
    tip = _commit(repo, "tip")
    r, rng = _range(repo, EVENT="push", BASE_REF="", BEFORE=before, SHA=tip)
    assert r.returncode == 0 and "Inspecting 2 commit(s)" in r.stdout
    r2, _ = _chain("No AI-agent co-author", rng, repo)
    assert r2.returncode == 1 and "AI co-author tag detected" in r2.stdout
    assert "OK: no AI co-author tags" not in r2.stdout


@needs_bash
def test_pr_range_and_clean_history_pass(repo) -> None:
    _commit(repo, "root")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    _commit(repo, "feature")
    r, rng = _range(repo, EVENT="pull_request", BASE_REF="main", BEFORE="", SHA="HEAD")
    assert r.returncode == 0 and rng == "origin/main..HEAD"
    r2, _ = _chain("No AI-agent co-author", rng, repo)
    assert r2.returncode == 0 and "OK: no AI co-author tags" in r2.stdout


@needs_bash
def test_coauthor_step_fails_closed_on_a_bad_range(repo) -> None:
    _commit(repo, "root")
    r, _ = _chain("No AI-agent co-author", "nosuchref..HEAD", repo)
    assert r.returncode != 0 and "OK: no AI co-author tags" not in r.stdout


@needs_bash
def test_author_check_allows_canonical_and_dependabot_flags_others(repo) -> None:
    _commit(repo, "a")
    _commit(repo, "b", "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>")
    _commit(repo, "c", "gl0di <130237002+gl0di@users.noreply.github.com>")
    r, _ = _chain("Author identity check", "HEAD", repo)
    assert r.returncode == 0 and "::warning::" not in r.stdout and "OK: author" in r.stdout
    _commit(repo, "d", "evil <gl0di@evil.example>")
    r, _ = _chain("Author identity check", "HEAD", repo)
    assert r.returncode == 0 and "::warning::" in r.stdout


@needs_bash
@pytest.mark.parametrize("case", ["push_before_is_sha", "push_force_on_main", "pr_head_is_base"])
def test_empty_range_falls_back_to_tip_and_still_catches_trailer(repo, case) -> None:
    _commit(repo, "root")
    sha = _commit(repo, "tip" + TRAILER)
    _git(repo, "update-ref", "refs/remotes/origin/main", sha)
    env = {
        "push_before_is_sha": dict(EVENT="push", BASE_REF="", BEFORE=sha, SHA=sha),
        "push_force_on_main": dict(EVENT="push", BASE_REF="", BEFORE="1" * 40, SHA=sha),
        "pr_head_is_base": dict(EVENT="pull_request", BASE_REF="main", BEFORE="", SHA=sha),
    }[case]
    r, rng = _range(repo, **env)
    assert r.returncode == 0 and "Inspecting 1 commit(s)" in r.stdout, r.stdout + r.stderr
    r2, _ = _chain("No AI-agent co-author", rng, repo)
    assert r2.returncode == 1 and "OK: no AI co-author tags" not in r2.stdout


# ---------------------------------------------------------------------------
# B-840: "No agent config files" was fail-open (root-only pathspec, no `set -e`)
# ---------------------------------------------------------------------------


@needs_bash
def test_agent_config_guard_catches_a_nested_config_file(repo) -> None:
    """A bare `git ls-files CLAUDE.md` pathspec matches only the repo root.

    Before B-840 this step passed with "OK" on a tracked sub/CLAUDE.md, since the
    pathspec never looked below the top level. The guard must inspect the whole
    tracked-file list so a match at any depth is caught.
    """
    (repo / "sub").mkdir()
    (repo / "sub" / "CLAUDE.md").write_text("nested agent config")
    _git(repo, "add", "sub/CLAUDE.md")
    _commit(repo, "add nested config")
    r, _ = _bash(_step_body("No agent config files"), repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "sub/CLAUDE.md" in r.stdout
    assert "OK: no agent config files in git tree" not in r.stdout


@needs_bash
def test_agent_config_guard_catches_a_nested_dotdir(repo) -> None:
    """Same defect, a different forbidden name: a nested `.claude/` directory."""
    (repo / "sub" / ".claude").mkdir(parents=True)
    (repo / "sub" / ".claude" / "settings.json").write_text("{}")
    _git(repo, "add", "sub/.claude/settings.json")
    _commit(repo, "add nested dotdir")
    r, _ = _bash(_step_body("No agent config files"), repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "sub/.claude/settings.json" in r.stdout


def test_agent_config_guard_passes_on_the_real_tree() -> None:
    """The real tree's only match is the allowlisted fixture; the guard stays green.

    Run against REPO_ROOT itself (not the `repo` fixture, which has no bash
    dependency requirement here since REPO_ROOT is a real git checkout).
    """
    if shutil.which("bash") is None:
        pytest.skip("bash not available")
    r, _ = _bash(_step_body("No agent config files"), REPO_ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "OK: no agent config files in git tree" in r.stdout


# ---------------------------------------------------------------------------
# B-840: "Author identity check" warned spuriously on an empty log
# ---------------------------------------------------------------------------


@needs_bash
def test_author_check_is_silent_on_an_empty_range(repo) -> None:
    """An empty range (e.g. a merge-only HEAD^! fallback) must not fake a warning.

    Before B-840, `grep -vE "$OK" <<<""` fed one blank line to grep, which "matched"
    (a blank line is not a canonical author) and printed "Non-canonical author(s)"
    with nothing after it — noise on every empty range.
    """
    _commit(repo, "root")
    r, _ = _chain("Author identity check", "HEAD..HEAD", repo)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "::warning::" not in r.stdout
    assert "OK: no non-merge commits in range to check" in r.stdout
