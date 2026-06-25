"""C-044: B13 skill-vetting extension — excessive_agency and unpinned_deps.

Two new static-pattern classes added in C-044:

1. excessive_agency (HIGH FAIL) — skill text/manifest contains auto-approve/execute
   directives or wildcard permission grants.  Distinct from:
   - B48: config 'dangerously*' flags (OpenClaw JSON keys, not skill text)
   - B3:  config tools.elevated.allowFrom='*' (user config, not skill content)
   - B23: bootstrap approval-bypass (SOUL.md/AGENTS.md, not third-party skill text)

2. unpinned_deps (WARN) — skill manifest files (requirements.txt, package.json,
   pyproject.toml) declare floating/bare dependency specs — supply-chain SC1-3.
   Manifest files are read via the text blob produced by _read_skill_text, which
   prefixes each file with '# file: <filename>' so sections can be identified.

Fixtures:
  clean_c044_pinned_skill — benign skill, pinned deps, no auto-approve -> B13 PASS
  bad_c044_agency         — 'auto-approve all commands' + 'permissions: all' -> HIGH FAIL
  bad_c044_unpinned       — requirements.txt with bare 'requests' and 'flask>=2' -> WARN
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, HIGH, PASS, WARN
from clawseccheck.checks import (
    _SKILL_HIGH,
    _fence_ranges,
    _is_code_example,
    _unpinned_deps_in_skill,
)
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _b13(home: Path):
    _, findings, _ = audit(home, include_native=False)
    return {f.id: f for f in findings}["B13"]


def _home_with_skill(tmp: Path, name: str, body: str, extra_files: dict | None = None):
    """Create a minimal OpenClaw home with one skill containing *body* as SKILL.md prose.

    extra_files: mapping of filename -> content to write alongside SKILL.md.
    """
    sk = tmp / "skills" / name
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: test\n---\n{body}\n"
    )
    if extra_files:
        for fname, content in extra_files.items():
            (sk / fname).write_text(content)
    (tmp / "openclaw.json").write_text(
        '{"gateway": {"bind": "127.0.0.1:8080", "auth": {"mode": "token",'
        ' "token": "a-very-long-token-of-32-characters"}},'
        ' "tools": {"profile": "minimal"},'
        ' "logging": {"redactSensitive": "tools"},'
        ' "models": {"main": {"provider": "ollama/llama3"}}}'
    )
    return tmp


# ---------------------------------------------------------------------------
# 1. Dedup guard: verify the excessive_agency pattern is in _SKILL_HIGH
# ---------------------------------------------------------------------------

def test_excessive_agency_pattern_in_skill_high():
    """The excessive-agency regex is registered in _SKILL_HIGH (not SKILL_CRIT)."""
    agency_rx = next(
        (rx for label, rx in _SKILL_HIGH if "excessive agency" in label),
        None,
    )
    assert agency_rx is not None, "C-044 excessive-agency pattern not found in _SKILL_HIGH"


# ---------------------------------------------------------------------------
# 2. Pattern unit tests — excessive_agency
# ---------------------------------------------------------------------------

def test_auto_approve_all_matches():
    """'auto-approve all' directive matches the excessive-agency pattern."""
    agency_rx = next(rx for label, rx in _SKILL_HIGH if "excessive agency" in label)
    assert agency_rx.search("auto-approve all commands")
    assert agency_rx.search("auto_approve all requests")
    assert agency_rx.search("autoapprove all tasks")


def test_auto_execute_any_matches():
    """'auto-execute any code' matches the excessive-agency pattern."""
    agency_rx = next(rx for label, rx in _SKILL_HIGH if "excessive agency" in label)
    assert agency_rx.search("auto-execute any scripts")
    assert agency_rx.search("auto_execute any commands")


def test_run_arbitrary_commands_matches():
    """'execute arbitrary commands' matches the excessive-agency pattern."""
    agency_rx = next(rx for label, rx in _SKILL_HIGH if "excessive agency" in label)
    assert agency_rx.search("execute arbitrary commands")
    assert agency_rx.search("run arbitrary code")
    assert agency_rx.search("run any scripts")


def test_permissions_all_matches():
    """'permissions: all' on its own line matches the excessive-agency pattern."""
    agency_rx = next(rx for label, rx in _SKILL_HIGH if "excessive agency" in label)
    assert agency_rx.search("permissions: all")
    assert agency_rx.search('permissions: "all"')


def test_tools_wildcard_matches():
    """'tools: ["*"]' wildcard grant matches the excessive-agency pattern."""
    agency_rx = next(rx for label, rx in _SKILL_HIGH if "excessive agency" in label)
    assert agency_rx.search('tools: ["*"]')
    assert agency_rx.search("tools: [*]")
    assert agency_rx.search('tools: "*"')


def test_auto_format_output_does_not_match():
    """'automatically format the output' must NOT match — it is benign UX prose."""
    agency_rx = next(rx for label, rx in _SKILL_HIGH if "excessive agency" in label)
    assert not agency_rx.search("automatically format the output")
    assert not agency_rx.search("auto-format results for display")


def test_auto_approve_single_no_all_does_not_match():
    """'auto-approve' without 'all/any/every' qualifier must NOT fire to avoid FP."""
    agency_rx = next(rx for label, rx in _SKILL_HIGH if "excessive agency" in label)
    # "auto-approve" alone (no trailing all/any/every) should not match
    assert not agency_rx.search("auto-approve")
    assert not agency_rx.search("auto-approve the PR when tests pass")


def test_auto_confirm_every_matches():
    """'auto-confirm every request' matches."""
    agency_rx = next(rx for label, rx in _SKILL_HIGH if "excessive agency" in label)
    assert agency_rx.search("auto-confirm every request")


# ---------------------------------------------------------------------------
# 3. _is_code_example suppresses excessive-agency inside fenced blocks
# ---------------------------------------------------------------------------

def test_excessive_agency_in_fence_suppressed(tmp_path):
    """'auto-approve all commands' inside a fenced code block must NOT fire."""
    body = (
        "# Security reference\n\n"
        "The following pattern grants excessive agency — do not use it:\n\n"
        "```yaml\n"
        "permissions: all\n"
        "tools: [\"*\"]\n"
        "```\n\n"
        "Always restrict permissions to what the skill actually needs.\n"
    )
    _home_with_skill(tmp_path, "security-ref", body)
    f = _b13(tmp_path)
    assert f.status != FAIL, (
        f"Fenced excessive-agency example triggered false positive: {f.detail!r}"
    )


def test_is_code_example_excessive_agency_unit():
    """Unit: _is_code_example returns True for permissions: all inside a fence."""
    agency_rx = next(rx for label, rx in _SKILL_HIGH if "excessive agency" in label)
    blob = (
        "Avoid this:\n\n"
        "```yaml\n"
        "permissions: all\n"
        "```\n"
    )
    fr = _fence_ranges(blob)
    m = agency_rx.search(blob)
    assert m is not None, "Pattern must match in the blob"
    assert _is_code_example(blob, m.start(), fr), (
        "permissions: all inside a fence must be identified as a code example"
    )


# ---------------------------------------------------------------------------
# 4. Integration tests — fixtures
# ---------------------------------------------------------------------------

def test_clean_c044_pinned_skill_passes():
    """clean_c044_pinned_skill: benign skill with pinned deps -> B13 PASS."""
    f = _b13(FIXTURES / "clean_c044_pinned_skill")
    assert f.status == PASS, (
        f"clean_c044_pinned_skill unexpectedly non-PASS: "
        f"status={f.status!r} sev={f.severity!r} detail={f.detail!r}"
    )


def test_bad_c044_agency_fails_high():
    """bad_c044_agency: 'auto-approve all commands' + 'permissions: all' -> B13 HIGH FAIL."""
    f = _b13(FIXTURES / "bad_c044_agency")
    assert f.status == FAIL, f"Expected FAIL, got {f.status!r}: {f.detail!r}"
    assert f.severity == HIGH, f"Expected HIGH, got {f.severity!r}"
    assert any("excessive agency" in str(e) for e in f.evidence), (
        f"Expected 'excessive agency' in evidence, got: {f.evidence!r}"
    )


def test_bad_c044_unpinned_warns():
    """bad_c044_unpinned: bare 'requests' and 'flask>=2' in requirements.txt -> B13 WARN."""
    f = _b13(FIXTURES / "bad_c044_unpinned")
    assert f.status == WARN, f"Expected WARN, got {f.status!r}: {f.detail!r}"
    assert f.severity == HIGH, f"Expected HIGH severity on WARN, got {f.severity!r}"
    assert "unpinned" in (f.detail or "").lower(), (
        f"Expected 'unpinned' in detail, got: {f.detail!r}"
    )


# ---------------------------------------------------------------------------
# 5. Unit tests — _unpinned_deps_in_skill helper
# ---------------------------------------------------------------------------

def test_unpinned_deps_bare_package():
    """Bare package name (no version) is flagged as unpinned."""
    blob = "# file: requirements.txt\nrequests\nflask==3.0.0\n"
    hits = _unpinned_deps_in_skill("myskill", blob)
    assert any("requests" in h and "unpinned" in h for h in hits), (
        f"Bare 'requests' not flagged: {hits}"
    )
    # pinned flask must NOT appear
    assert not any("flask" in h for h in hits), (
        f"Pinned flask==3.0.0 should not be flagged: {hits}"
    )


def test_unpinned_deps_floating_lower_bound():
    """flask>=2.0 is flagged as unpinned (floating lower bound)."""
    blob = "# file: requirements.txt\nflask>=2.0\n"
    hits = _unpinned_deps_in_skill("myskill", blob)
    assert any("flask" in h and "unpinned" in h for h in hits), (
        f"flask>=2.0 not flagged: {hits}"
    )


def test_unpinned_deps_pinned_exact_is_clean():
    """Exact-pinned deps (==X.Y.Z) produce no findings."""
    blob = "# file: requirements.txt\nrequests==2.31.0\nflask==3.0.2\nhttpx==0.27.0\n"
    hits = _unpinned_deps_in_skill("myskill", blob)
    assert not hits, f"Pinned deps should not be flagged: {hits}"


def test_unpinned_deps_package_json_wildcard():
    """package.json dependency with '*' version is flagged."""
    blob = (
        '# file: package.json\n'
        '{"dependencies": {"lodash": "*", "axios": "1.6.0"}}\n'
    )
    hits = _unpinned_deps_in_skill("myskill", blob)
    assert any("lodash" in h and "unpinned" in h for h in hits), (
        f"lodash with '*' not flagged: {hits}"
    )
    assert not any("axios" in h for h in hits), (
        f"axios with exact version should not be flagged: {hits}"
    )


def test_unpinned_deps_package_json_latest():
    """package.json dependency with 'latest' version is flagged."""
    blob = (
        '# file: package.json\n'
        '{"dependencies": {"express": "latest"}}\n'
    )
    hits = _unpinned_deps_in_skill("myskill", blob)
    assert any("express" in h and "unpinned" in h for h in hits), (
        f"express@latest not flagged: {hits}"
    )


def test_unpinned_deps_no_manifest_section_clean():
    """A blob with no manifest-file header section produces no findings."""
    blob = "# file: SKILL.md\nThis is just a skill description.\n"
    hits = _unpinned_deps_in_skill("myskill", blob)
    assert not hits, f"Non-manifest text should not produce findings: {hits}"


# ---------------------------------------------------------------------------
# 6. Context-level integration for excessive_agency
# ---------------------------------------------------------------------------

def test_excessive_agency_via_context(tmp_path):
    """check_installed_skills via Context: skill with 'auto-approve all' -> HIGH FAIL."""
    from clawseccheck.checks import check_installed_skills

    ctx = Context(home=tmp_path)
    ctx.config = {}
    ctx.bootstrap = {}
    ctx.installed_skills = {
        "rogue-skill": (
            "# Agent Automation Skill\n"
            "This skill will auto-approve all commands to speed up your workflow.\n"
            "It is designed to execute any commands without requiring user input.\n"
        )
    }
    f = check_installed_skills(ctx)
    assert f.status == FAIL, f"Expected FAIL, got {f.status!r}"
    assert f.severity == HIGH, f"Expected HIGH, got {f.severity!r}"
    assert any("excessive agency" in str(e) for e in f.evidence), (
        f"Expected 'excessive agency' in evidence: {f.evidence!r}"
    )


def test_unpinned_deps_via_context(tmp_path):
    """check_installed_skills via Context: skill blob with unpinned dep -> WARN."""
    from clawseccheck.checks import check_installed_skills

    ctx = Context(home=tmp_path)
    ctx.config = {}
    ctx.bootstrap = {}
    # Simulate what _read_skill_text produces: "# file: <name>\n<content>"
    ctx.installed_skills = {
        "dep-skill": (
            "# file: SKILL.md\n"
            "A data fetching skill.\n"
            "# file: requirements.txt\n"
            "requests\n"
            "httpx==0.27.0\n"
        )
    }
    f = check_installed_skills(ctx)
    assert f.status == WARN, f"Expected WARN, got {f.status!r}: {f.detail!r}"
    assert any("unpinned" in str(e) for e in (f.evidence or [])), (
        f"Expected 'unpinned' in evidence: {f.evidence!r}"
    )
