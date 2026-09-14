"""CLAWSECCHECK-C-522 — the three pipeline recipes in docs/USAGE.md's "Pipeline recipes"
section (GitHub Actions, GitLab CI, Jenkins) must actually work, not just look plausible.

Same discipline as tests/test_b658_recipe_exit_claim.py: the flags under test are PARSED
out of the shipped doc text, never restated here, so a doc edit that silently changes the
command is exactly what turns this suite red — restating the flags would let the recipe
and the test drift apart independently, which is the shape that shipped a false claim in
B-658. This already caught a real bug while it was being written: the first draft of the
GitLab recipe wrote `clawseccheck --json results.json` — but `--json` is a boolean flag
(`action="store_true"`, prints to stdout), not a path-taking option like `--sarif`, so
`results.json` was silently swallowed as an unrecognized positional argument and the
command exited 2. The fix is `--json --save results.json`.

Offline, read-only outside tmp_path, stdlib only.
"""
from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

import pytest

from clawseccheck.cli import main

REPO = Path(__file__).resolve().parent.parent
USAGE = REPO / "docs" / "USAGE.md"
FIXTURES = REPO / "fixtures"

_SECTION_START = "### Pipeline recipes"
_SECTION_END = "## More tools"

_COMMON_ARGV = ["--no-native", "--no-host", "--no-sockets", "--no-deptree", "--no-dist"]


def _section() -> str:
    text = USAGE.read_text(encoding="utf-8")
    start = text.index(_SECTION_START)
    end = text.index(_SECTION_END, start)
    return text[start:end]


def _recipe_blocks() -> "list[tuple[str, str]]":
    """[(name, block_body), ...] in document order — GitHub, GitLab, Jenkins. A single
    findall over the whole section, so a later per-recipe lookup can never accidentally
    span across two fences the way a fresh ad-hoc regex over the raw section text can
    (non-greedy `.*?` between two ``` markers keeps extending past an intermediate fence
    close/open pair whenever the content immediately inside the first fence doesn't
    satisfy the rest of the pattern) — every recipe test below reuses THIS parse.
    """
    section = _section()
    blocks = re.findall(r"```(?:yaml|groovy)\n(.*?)\n```", section, re.S)
    assert len(blocks) == 3, (
        f"expected exactly 3 fenced recipe blocks (GitHub/GitLab/Jenkins), found "
        f"{len(blocks)} — a recipe was added, removed, or its fence language changed"
    )
    return list(zip(["github", "gitlab", "jenkins"], blocks))


def _recipe_commands() -> dict:
    """{name: "flags..."} — the `clawseccheck <flags>` invocation parsed out of each
    block. Loose enough to match a YAML `run:` line, a GitLab `script:` list item, and a
    Groovy `sh '...'` string alike; stops at the closing quote/EOL so Jenkins' shell
    quoting is never captured as part of the flags.
    """
    out: dict = {}
    for name, body in _recipe_blocks():
        # The value-group's negative lookahead (?!--) is load-bearing: without it, a
        # flag immediately followed by another bare flag (`--json --save results.json`)
        # greedily swallows the second flag AS the first flag's "value", and the whole
        # match stops there — silently dropping the actual filename and every flag
        # after it. Caught by this suite itself the first time it ran.
        found = re.findall(
            r"clawseccheck ((?:--[A-Za-z-]+(?:\s+(?!--)[^\s'\"]+)?\s*)+)", body)
        assert found, f"{name} recipe has no `clawseccheck <flags>` invocation:\n{body}"
        out[name] = found[0].strip().rstrip("'\"")
    return out


def _argv_with_redirected_output(flags: str, tmp_path: Path) -> "tuple[list[str], Path]":
    """Split *flags* into argv, redirecting whatever output file it names (the value of
    --sarif, or of --save when combined with --json) into tmp_path so the test never
    writes into the repo checkout."""
    tokens = flags.split()
    out_path = None
    for i, tok in enumerate(tokens):
        if tok in ("--sarif", "--save") and i + 1 < len(tokens):
            out_path = tmp_path / Path(tokens[i + 1]).name
            tokens[i + 1] = str(out_path)
    assert out_path is not None, f"no --sarif/--save output filename found in: {flags}"
    return tokens, out_path


def _run(flags: str, home: str, tmp_path: Path) -> "tuple[int, Path]":
    argv, out_path = _argv_with_redirected_output(flags, tmp_path)
    rc = main(["--home", str(FIXTURES / home), *_COMMON_ARGV, *argv])
    return rc, out_path


# --------------------------------------------------------------------------------------

def test_exactly_three_recipes_each_name_a_fail_on_gate():
    """The claim the prose makes ("gates on --fail-on high") must be true of all three,
    not asserted once and assumed for the rest."""
    for name, flags in _recipe_commands().items():
        assert "--fail-on" in flags, f"{name}: recipe does not set --fail-on: {flags}"
        assert re.search(r"--fail-on\s+high", flags), (
            f"{name}: recipe's --fail-on value is not 'high' as the prose claims: {flags}")


@pytest.mark.parametrize("name", ["github", "gitlab", "jenkins"])
def test_the_emitted_flags_trip_the_gate_on_a_real_high_severity_fail(tmp_path, name):
    """fixtures/home_vuln carries unsuppressed HIGH/CRITICAL FAILs (A1, B1, B2, B3, B4 at
    minimum), so the exact flags each recipe emits must exit non-zero against it."""
    flags = _recipe_commands()[name]
    rc, out_path = _run(flags, "home_vuln", tmp_path)
    assert rc != 0, f"{name}: recipe's own flags returned 0 against a HIGH-FAIL fixture"
    assert out_path.exists() and out_path.stat().st_size > 0, (
        f"{name}: the gate tripping must not skip writing the report — "
        "the whole point of the recipe's continue-on-error/post.always plumbing")


@pytest.mark.parametrize("name", ["github", "gitlab", "jenkins"])
def test_the_emitted_flags_stay_quiet_on_a_clean_fixture(tmp_path, name):
    """Negative control: the same flags against fixtures/home_safe (0 HIGH+ FAILs) must
    exit 0 — without this, the positive test above could be passing because the flags
    always fail, which would prove nothing about the --fail-on threshold specifically."""
    flags = _recipe_commands()[name]
    rc, out_path = _run(flags, "home_safe", tmp_path)
    assert rc == 0, f"{name}: recipe's own flags returned {rc} against a clean fixture"
    assert out_path.exists() and out_path.stat().st_size > 0


@pytest.mark.parametrize("name", ["github", "jenkins"])
def test_the_sarif_recipes_write_valid_sarif_with_the_documented_severity_counts(name):
    """Grounds the doc's own claim that SARIF carries
    analysisCompleteness.failCountsBySeverity, for the two recipes (GitHub, Jenkins)
    that use --sarif."""
    flags = _recipe_commands()[name]
    with tempfile.TemporaryDirectory() as td:
        rc, out_path = _run(flags, "home_vuln", Path(td))
        assert rc != 0
        sarif = json.loads(out_path.read_text(encoding="utf-8"))
        counts = sarif["runs"][0]["properties"]["analysisCompleteness"][
            "failCountsBySeverity"]
        assert counts["high"] > 0 or counts["critical"] > 0, (
            f"{name}: SARIF's own severity counts disagree with the FAIL that "
            f"tripped --fail-on high: {counts}")


def test_the_json_recipe_writes_the_documented_fail_counts_by_severity():
    """Grounds the doc's claim for the GitLab recipe, which uses --json/--save instead
    of --sarif specifically because GitLab has no native SARIF viewer."""
    flags = _recipe_commands()["gitlab"]
    with tempfile.TemporaryDirectory() as td:
        rc, out_path = _run(flags, "home_vuln", Path(td))
        assert rc != 0
        payload = json.loads(out_path.read_text(encoding="utf-8"))
        counts = payload["fail_counts_by_severity"]
        assert counts["high"] > 0 or counts["critical"] > 0, counts


def test_the_gitlab_recipe_uses_json_not_sarif_and_makes_no_reports_claim():
    """The task's own instruction: state the GitLab SARIF limitation honestly rather
    than inventing a `reports:` mapping GitLab does not actually support for this
    tool's output shape."""
    blocks = dict(_recipe_blocks())
    gitlab = blocks["gitlab"]
    assert "--json" in gitlab and "--save" in gitlab
    assert "--sarif" not in gitlab
    assert "reports:" not in gitlab


def test_the_jenkins_recipe_archives_the_report_even_when_the_gate_trips():
    """The prose claims `post { always { ... } }` — assert the fence actually contains
    that Jenkins idiom rather than a plain post-success step that would skip the
    archive on exactly the run where the report matters most."""
    groovy = dict(_recipe_blocks())["jenkins"]
    assert "post" in groovy and "always" in groovy
    assert re.search(r"always\s*\{[^}]*archiveArtifacts", groovy, re.S), groovy


def test_the_github_recipe_uploads_sarif_and_still_fails_the_job_on_a_gate_trip():
    """`continue-on-error: true` on the audit step, by itself, would leave the JOB green
    even when the gate trips — assert the recipe also has the explicit follow-up step
    that turns the captured outcome back into a real failure."""
    github = dict(_recipe_blocks())["github"]
    assert "continue-on-error: true" in github
    assert "upload-sarif" in github
    assert re.search(r"if:\s*steps\.audit\.outcome\s*==\s*'failure'", github), github


def test_recipes_pin_an_install_tag_not_a_moving_branch():
    """Consistent with the pinning recommendation this file's own earlier `pipx install`
    example already gives — an unpinned `@main`/no-ref install would silently change
    behavior under a CI job nobody re-reviewed."""
    for name, block in _recipe_blocks():
        assert re.search(r"@v[\dX]", block), f"{name}: install line does not pin a tag:\n{block}"
