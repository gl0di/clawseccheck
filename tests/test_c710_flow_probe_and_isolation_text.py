"""Agent-facing protocol text in docs/FLOW_CHOICES.md and docs/ISOLATION.md.

These two docs are not prose for a reader, they are instructions a host agent executes and
then attests from.  Three defects, one theme: the text promised something the commands or
the schema do not deliver.

* The host-monitor probe piped each command (stderr discarded) into ``grep``.  A probed
  command that FAILED (``systemctl`` on a host without a system bus) printed nothing, which
  reads exactly like "no EDR found", and the text told the agent to attest
  ``host_monitors: []`` for that.  Failure must be visible and must not become a clean answer.
* ISOLATION.md claimed an injected payload "cannot reach or instruct the host agent"
  while the typed verdict it defines still carries a free-text field.
* The approvals self-report offered only ``required`` / ``auto`` / ``unknown`` with no
  guidance for an answer that depends on the path, sandbox or action.
"""
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_FLOW = _REPO / "docs" / "FLOW_CHOICES.md"
_ISOLATION = _REPO / "docs" / "ISOLATION.md"


def _flow() -> str:
    return _FLOW.read_text(encoding="utf-8")


def _isolation() -> str:
    return _ISOLATION.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    """Collapse hard-wrapped prose and blockquote markers so phrase checks ignore layout."""
    return re.sub(r"\s+", " ", re.sub(r"(?m)^\s*>\s?", "", text))


def _host_monitors_section() -> str:
    text = _flow()
    start = text.index("For **host_monitors**")
    end = text.index("**Step 3b", start)
    return text[start:end]


def _probe_helper_source() -> str:
    """The shell helper the doc tells the agent to define (first sh fence in the section)."""
    m = re.search(r"```sh\n(.*?)```", _host_monitors_section(), re.S)
    assert m, "the host_monitors probe must ship its helper as a ```sh fenced block"
    src = m.group(1)
    # Only the definition: drop the example invocations that follow it.
    lines = []
    for line in src.splitlines():
        if line.startswith("probe "):
            break
        lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 1. host-monitor probe: a failing probed command must be visible
# ---------------------------------------------------------------------------

def test_no_probe_pipes_a_stderr_discarded_command_straight_into_grep():
    section = _host_monitors_section()
    assert not re.search(r"2>\s*/dev/null[^\n]*\|\s*grep", section), (
        "a probe that discards stderr and pipes into grep makes a failing command look "
        "like 'no matches'")
    assert "2>/dev/null" not in section
    for line in section.splitlines():
        assert not re.search(
            r"\b(systemctl|ps|lsmod|launchctl)\b[^\n`]*\|\s*grep", line), (
            f"probe command piped straight into grep (its exit status is lost): {line!r}")


def test_probe_section_states_the_exit_status_rule_and_the_all_failed_rule():
    flat = _flat(_host_monitors_section())
    # the exit-status rule: the PROBED command's status decides, not grep's
    assert re.search(r"probed command \(not grep\)", flat)
    assert re.search(r"non-zero or prints an error", flat)
    assert re.search(r"could not be probed", flat)
    # `[]` only when a source ran successfully AND nothing matched
    assert re.search(r"only when at least one (probe )?source ran successfully", flat)
    # every source failed -> unknown / ask the user
    assert re.search(r"(?i)if every source failed[^.]*`unknown`", flat)
    # the old, unconditional wording is gone
    assert "runs clean (no matches)" not in flat
    assert "or the probe errors out" not in flat


def test_probe_section_keeps_the_macos_line_and_the_same_pattern():
    section = _host_monitors_section()
    assert "launchctl list" in section
    for name in ("crowdstrike", "wazuh", "auditd", "tetragon", "osquery"):
        assert name in section


_HAS_SH = shutil.which("sh") is not None


def _stub(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _sh(helper: str, invocation: str, cwd: Path) -> "subprocess.CompletedProcess[str]":
    script = helper + "\n" + invocation + "\n"
    return subprocess.run(
        ["sh", "-c", script], cwd=str(cwd), capture_output=True, text=True,
        timeout=30, env={"PATH": "/usr/bin:/bin"})


@pytest.mark.skipif(not _HAS_SH, reason="needs a POSIX sh")
def test_the_documented_helper_makes_a_failing_probe_visible(tmp_path):
    helper = _probe_helper_source()
    failing = _stub(
        tmp_path, "failing_probe",
        "echo 'Failed to connect to system scope bus: Operation not permitted' >&2\nexit 1")
    proc = _sh(helper, f"probe {failing}", tmp_path)
    out = proc.stdout
    assert "exit=1" in out, out
    assert "Failed to connect" in out, out
    # the old behaviour: indistinguishable from "ran clean, nothing matched"
    assert "exit=0" not in out


@pytest.mark.skipif(not _HAS_SH, reason="needs a POSIX sh")
def test_the_documented_helper_reports_a_clean_run_and_a_match_distinctly(tmp_path):
    helper = _probe_helper_source()
    clean = _stub(tmp_path, "clean_probe", "echo 'cron.service'\necho 'ssh.service'")
    matched = _stub(tmp_path, "matched_probe", "echo 'cron.service'\necho 'wazuh-agent.service'")
    out_clean = _sh(helper, f"probe {clean}", tmp_path).stdout
    out_match = _sh(helper, f"probe {matched}", tmp_path).stdout
    assert "exit=0" in out_clean and "wazuh" not in out_clean.lower(), out_clean
    assert "exit=0" in out_match and "wazuh-agent.service" in out_match, out_match
    assert "cron.service" not in out_match


@pytest.mark.skipif(not _HAS_SH, reason="needs a POSIX sh")
def test_an_error_message_naming_a_monitor_is_not_read_as_a_match(tmp_path):
    helper = _probe_helper_source()
    noisy = _stub(
        tmp_path, "noisy_probe",
        "echo 'wazuh-agent: Permission denied' >&2\nexit 13")
    out = _sh(helper, f"probe {noisy}", tmp_path).stdout
    assert "exit=13" in out, out
    assert "exit=0" not in out, out


@pytest.mark.skipif(not _HAS_SH, reason="needs a POSIX sh")
def test_a_missing_command_is_a_failed_probe_not_a_clean_one(tmp_path):
    helper = _probe_helper_source()
    out = _sh(helper, "probe definitely_not_a_real_command_c710", tmp_path).stdout
    assert re.search(r"exit=(127|126|[1-9]\d*)", out), out
    assert "exit=0" not in out


# ---------------------------------------------------------------------------
# 2. ISOLATION.md: no absolute claim the typed-verdict schema cannot back
# ---------------------------------------------------------------------------

def test_isolation_no_longer_claims_an_injection_cannot_reach_the_host_agent():
    flat = _flat(_isolation())
    assert "cannot reach or instruct the host agent" not in flat
    assert "blocks the injected instruction channel" not in flat
    assert "never enters the orchestrator's context" not in flat
    assert "typed output is inert data" not in flat
    assert "it receives no raw file contents" not in flat


def test_isolation_says_what_the_schema_guarantees_and_what_it_does_not():
    text = _isolation()
    schema = re.search(r"```json\n(.*?)```", text, re.S)
    assert schema and '"indicators"' in schema.group(1), "the doc defines the verdict schema"
    flat = _flat(text)
    # acts only on the typed fields; a free-text field is untrusted data, never an instruction
    assert re.search(r"(?i)free-text", flat)
    assert re.search(r"(?i)`indicators`[^.]*free[- ]text", flat)
    assert re.search(r"(?i)never follow[^.]*as an instruction", flat)
    # reduces, does not eliminate
    assert re.search(r"(?i)does not eliminate", flat)


def test_isolation_and_flow_choices_carry_no_other_absolute_injection_claim():
    for name, text in (("ISOLATION.md", _isolation()), ("FLOW_CHOICES.md", _flow())):
        flat = _flat(text).lower()
        for phrase in ("can never reach", "impossible for an injection",
                       "injection cannot", "before it can arrive"):
            assert phrase not in flat, f"{name} still says {phrase!r}"
        # "<payload / injection> ... cannot reach <the agent>" in any wording
        assert not re.search(r"(payload|prompt-injection)[^.]{0,80}cannot (reach|instruct)", flat), name


# ---------------------------------------------------------------------------
# 3. approvals self-report: an answer that depends on context is `unknown`
# ---------------------------------------------------------------------------

def test_approval_gates_text_routes_a_context_dependent_answer_to_unknown():
    text = _flow()
    start = text.index("For **approval_gates**")
    end = text.index("For **untrusted_to_action**", start)
    flat = _flat(text[start:end])
    assert "`\"required\"`" in flat and "`\"auto\"`" in flat  # the original answers survive
    m = re.search(r"(?i)when the answer depends on[^.]*\.", flat)
    assert m, flat
    sentence = m.group(0).lower()
    for word in ("path", "sandbox", "action", "authori", "unknown", "notes"):
        assert word in sentence, (word, sentence)


# ---------------------------------------------------------------------------
# the rewrite must stay lint-clean and tidy
# ---------------------------------------------------------------------------

def test_probe_helper_block_is_dedented_and_terminated():
    src = _host_monitors_section()
    assert src.count("```") % 2 == 0, "unbalanced code fence in the host_monitors section"
    assert textwrap.dedent(_probe_helper_source()) == _probe_helper_source()
