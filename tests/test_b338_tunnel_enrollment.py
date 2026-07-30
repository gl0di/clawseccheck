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
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.checks import (
    PASS,
    UNKNOWN,
    WARN,
    check_tunnel_enrollment,
    vet_skill,
)
from clawseccheck.checks._content import _B338_LAUNCH_RE
from clawseccheck.collector import Context
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
