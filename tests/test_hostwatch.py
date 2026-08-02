"""hostwatch.detect — read-only host-monitor detection on fake filesystem roots.

All tests are offline and deterministic: they build a fake host root under
pytest's tmp_path and pass an explicit `which` resolver, so nothing touches the
real machine's PATH or filesystem and no real monitor leaks into the result.
"""
from __future__ import annotations

import plistlib

from clawseccheck import hostwatch
from clawseccheck.hostwatch import detect


def _none(name):
    """PATH resolver that finds nothing (keeps detection filesystem-only)."""
    return None


def _touch(root, rel, text=""):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

def test_linux_blind_host_all_absent(tmp_path):
    res = detect(root=tmp_path, system="Linux", which=_none)
    assert res["supported"] is True
    assert res["system"] == "Linux"
    for cls in hostwatch.CLASSES:
        if cls == hostwatch.EGRESS_POSTURE:
            # Distinct semantics (F-084): "no readable egress-policy config found" is
            # honestly UNKNOWN, not "absent" — unlike the other classes (where absence
            # of a security TOOL is itself informative), a missing declarative config
            # says nothing about the live kernel default, so UNKNOWN is the honest call.
            assert res["classes"][cls]["status"] == "unknown"
        elif cls in hostwatch.VISIBILITY_CLASSES:
            # B-172: a read-only miss on a visibility class (network IDS / audit /
            # file-integrity / EDR) is honest UNKNOWN, never a confident "absent" —
            # the monitor's config/agent may live in a path a non-root scan can't read.
            assert res["classes"][cls]["status"] == "unknown"
        elif cls == hostwatch.TUNNEL_TRANSPORT:
            # E-065/C-324: same B-172 reasoning as the visibility classes — a miss
            # cannot prove a tunnel binary is absent (could be installed via a package
            # manager or path this scan can't see), so it is honest UNKNOWN too.
            assert res["classes"][cls]["status"] == "unknown"
        else:
            # firewall is prevention, not detection — its "absent" semantics are
            # unaffected by B-172.
            assert res["classes"][cls]["status"] == "absent"


def test_linux_suricata_detected_by_config(tmp_path):
    _touch(tmp_path, "etc/suricata/suricata.yaml", "vars:\n")
    res = detect(root=tmp_path, system="Linux", which=_none)
    net = res["classes"]["network_ids"]
    assert net["status"] == "present"
    assert "Suricata" in net["found"]


def test_linux_suricata_enabled_via_systemd_symlink(tmp_path):
    _touch(tmp_path, "etc/suricata/suricata.yaml")
    _touch(tmp_path, "etc/systemd/system/multi-user.target.wants/suricata.service")
    res = detect(root=tmp_path, system="Linux", which=_none)
    assert res["classes"]["network_ids"]["active"] is True


def test_linux_zeek_detected_by_binary_on_path(tmp_path):
    def which(n):
        return "/opt/zeek/bin/zeek" if n == "zeek" else None
    res = detect(root=tmp_path, system="Linux", which=which)
    assert "Zeek" in res["classes"]["network_ids"]["found"]


def test_linux_suricata_via_sbin_and_pidfile_is_present_active(tmp_path):
    # B-172: broaden Suricata detection beyond PATH/config-file — a binary under
    # usr/sbin plus a running pidfile is a legitimate signal too.
    _touch(tmp_path, "usr/sbin/suricata")
    _touch(tmp_path, "run/suricata/suricata.pid", "5678\n")
    res = detect(root=tmp_path, system="Linux", which=_none)
    net = res["classes"]["network_ids"]
    assert net["status"] == "present"
    assert "Suricata" in net["found"]
    assert net["active"] is True


def test_linux_suricata_does_not_mark_edr_present(tmp_path):
    # C-135 taxonomy guard: an IDS (Suricata) must never bleed into the edr_av
    # class — IDS != EDR. edr_av stays an honest UNKNOWN (B-172 miss semantics).
    _touch(tmp_path, "usr/sbin/suricata")
    _touch(tmp_path, "run/suricata/suricata.pid", "5678\n")
    res = detect(root=tmp_path, system="Linux", which=_none)
    edr = res["classes"]["edr_av"]
    assert edr["status"] == "unknown"
    assert edr["found"] == []


def test_linux_auditd_present(tmp_path):
    _touch(tmp_path, "etc/audit/auditd.conf")
    res = detect(root=tmp_path, system="Linux", which=_none)
    assert res["classes"]["host_audit"]["status"] == "present"
    assert "auditd" in res["classes"]["host_audit"]["found"]


def test_linux_auditd_via_sbin_and_pidfile_is_present_active(tmp_path):
    # B-172: broaden detection beyond PATH-only auditctl/config-file — a binary
    # under sbin plus a running pidfile is a legitimate signal too.
    _touch(tmp_path, "sbin/auditctl")
    _touch(tmp_path, "run/auditd.pid", "1234\n")
    res = detect(root=tmp_path, system="Linux", which=_none)
    audit = res["classes"]["host_audit"]
    assert audit["status"] == "present"
    assert "auditd" in audit["found"]
    assert audit["active"] is True


def test_linux_auditd_rules_d_present(tmp_path):
    # etc/audit/rules.d/ with a real .rules file is a valid auditd config signal.
    _touch(tmp_path, "etc/audit/rules.d/10-base.rules")
    res = detect(root=tmp_path, system="Linux", which=_none)
    assert res["classes"]["host_audit"]["status"] == "present"


def test_linux_auditd_empty_rules_d_is_unknown(tmp_path):
    # C-135: an EMPTY etc/audit/rules.d (a purged-package leftover dir with no
    # .rules files) must NOT read as a present monitor — that would mask a
    # genuinely-unmonitored host. It stays an honest 'unknown'.
    (tmp_path / "etc/audit/rules.d").mkdir(parents=True)
    res = detect(root=tmp_path, system="Linux", which=_none)
    assert res["classes"]["host_audit"]["status"] == "unknown"


def test_linux_bare_host_audit_miss_is_unknown(tmp_path):
    # B-172 regression pin: a read-only miss on host_audit must be honest
    # UNKNOWN, never a confident "absent" — auditd may be installed and active
    # in a path a non-root scan can't read.
    res = detect(root=tmp_path, system="Linux", which=_none)
    audit = res["classes"]["host_audit"]
    assert audit["status"] == "unknown"
    assert audit["found"] == []


def test_linux_aide_with_db_is_active(tmp_path):
    _touch(tmp_path, "etc/aide/aide.conf")
    _touch(tmp_path, "var/lib/aide/aide.db")
    res = detect(root=tmp_path, system="Linux", which=_none)
    fim = res["classes"]["file_integrity"]
    assert fim["status"] == "present"
    assert "AIDE" in fim["found"]
    assert fim["active"] is True


def test_linux_ossec_edr_detected(tmp_path):
    _touch(tmp_path, "var/ossec/etc/ossec.conf")
    res = detect(root=tmp_path, system="Linux", which=_none)
    assert "OSSEC" in res["classes"]["edr_av"]["found"]


def test_linux_ufw_enabled_yes_is_active(tmp_path):
    _touch(tmp_path, "etc/ufw/ufw.conf", "ENABLED=yes\n")
    res = detect(root=tmp_path, system="Linux", which=_none)
    fw = res["classes"]["firewall"]
    assert fw["status"] == "present"
    assert "ufw" in fw["found"]
    assert fw["active"] is True


def test_linux_ufw_enabled_no_is_inactive(tmp_path):
    _touch(tmp_path, "etc/ufw/ufw.conf", "ENABLED=no\n")
    res = detect(root=tmp_path, system="Linux", which=_none)
    fw = res["classes"]["firewall"]
    assert fw["status"] == "present"
    assert fw["active"] is False


def test_linux_nftables_conf_alone_not_active(tmp_path):
    # the .conf can exist unused; only the enable-symlink proves it is active
    _touch(tmp_path, "etc/nftables.conf")
    res = detect(root=tmp_path, system="Linux", which=_none)
    fw = res["classes"]["firewall"]
    assert "nftables" in fw["found"]
    assert fw["active"] is not True


# ---------------------------------------------------------------------------
# Egress (outbound) posture (F-084)
# ---------------------------------------------------------------------------

def test_linux_egress_nftables_output_drop_is_deny(tmp_path):
    _touch(
        tmp_path,
        "etc/nftables.conf",
        "table inet filter {\n"
        "  chain output {\n"
        "    type filter hook output priority 0; policy drop;\n"
        "  }\n"
        "}\n",
    )
    res = detect(root=tmp_path, system="Linux", which=_none)
    eg = res["classes"]["egress_posture"]
    assert eg["status"] == "present"
    assert eg["active"] is True
    assert any("policy=drop" in e for e in eg["evidence"])


def test_linux_egress_nftables_output_accept_is_allow(tmp_path):
    _touch(
        tmp_path,
        "etc/nftables.conf",
        "table inet filter {\n"
        "  chain output {\n"
        "    type filter hook output priority 0; policy accept;\n"
        "  }\n"
        "}\n",
    )
    res = detect(root=tmp_path, system="Linux", which=_none)
    eg = res["classes"]["egress_posture"]
    assert eg["status"] == "present"
    assert eg["active"] is False


def test_linux_egress_ufw_outgoing_deny_is_deny(tmp_path):
    # B-437: the real key/file is DEFAULT_OUTPUT_POLICY in /etc/default/ufw, not
    # DEFAULT_OUTGOING_POLICY in /etc/ufw/ufw.conf — and it only counts as an
    # active posture when ufw is actually enabled.
    _touch(tmp_path, "etc/default/ufw", 'DEFAULT_OUTPUT_POLICY="deny"\n')
    _touch(tmp_path, "etc/ufw/ufw.conf", "ENABLED=yes\n")
    res = detect(root=tmp_path, system="Linux", which=_none)
    eg = res["classes"]["egress_posture"]
    assert eg["status"] == "present"
    assert eg["active"] is True
    assert any("DEFAULT_OUTPUT_POLICY=deny" in e for e in eg["evidence"])


def test_linux_egress_ufw_outgoing_drop_is_deny(tmp_path):
    # B-437 follow-up: real ufw never writes the literal "deny" to this file.
    # `ufw default deny outgoing` (the exact hardening command this check's own
    # remediation recommends) writes DEFAULT_OUTPUT_POLICY="DROP" — verified
    # against backend_iptables.py's set_default_policy(). Before this fix, only
    # "deny"/"reject" counted as deny, so the single most common real value
    # ("drop") produced the backwards, self-contradictory WARN that an operator
    # who correctly hardened their host defaults to ALLOW.
    _touch(tmp_path, "etc/default/ufw", 'DEFAULT_OUTPUT_POLICY="DROP"\n')
    _touch(tmp_path, "etc/ufw/ufw.conf", "ENABLED=yes\n")
    res = detect(root=tmp_path, system="Linux", which=_none)
    eg = res["classes"]["egress_posture"]
    assert eg["status"] == "present"
    assert eg["active"] is True
    assert any("DEFAULT_OUTPUT_POLICY=drop" in e for e in eg["evidence"])


def test_linux_egress_ufw_outgoing_allow_is_allow(tmp_path):
    _touch(tmp_path, "etc/default/ufw", 'DEFAULT_OUTPUT_POLICY="allow"\n')
    _touch(tmp_path, "etc/ufw/ufw.conf", "ENABLED=yes\n")
    res = detect(root=tmp_path, system="Linux", which=_none)
    eg = res["classes"]["egress_posture"]
    assert eg["status"] == "present"
    assert eg["active"] is False


def test_linux_egress_ufw_outgoing_policy_old_key_location_not_read(tmp_path):
    # C-135 regression pin: the OLD (wrong) key/file from before B-437 must NOT
    # be read — a leftover DEFAULT_OUTGOING_POLICY in ufw.conf is not the real
    # field and must not be mistaken for a resolved policy.
    _touch(tmp_path, "etc/ufw/ufw.conf", 'DEFAULT_OUTGOING_POLICY="deny"\nENABLED=yes\n')
    res = detect(root=tmp_path, system="Linux", which=_none)
    eg = res["classes"]["egress_posture"]
    assert eg["status"] == "unknown"
    assert eg["active"] is None


def test_linux_egress_ufw_policy_present_but_disabled_is_not_active(tmp_path):
    # B-437 secondary defect: a deny policy left on disk for a DISABLED ufw
    # (`ufw disable` was run but /etc/default/ufw was never edited back) must
    # not be credited as an active egress posture.
    _touch(tmp_path, "etc/default/ufw", 'DEFAULT_OUTPUT_POLICY="deny"\n')
    _touch(tmp_path, "etc/ufw/ufw.conf", "ENABLED=no\n")
    res = detect(root=tmp_path, system="Linux", which=_none)
    eg = res["classes"]["egress_posture"]
    assert eg["status"] == "unknown"
    assert eg["active"] is None
    assert eg["found"] == []


def test_linux_egress_no_config_is_unknown(tmp_path):
    res = detect(root=tmp_path, system="Linux", which=_none)
    eg = res["classes"]["egress_posture"]
    assert eg["status"] == "unknown"
    assert eg["active"] is None


def test_linux_egress_proxy_env_is_weak_signal_only(tmp_path, monkeypatch):
    # A proxy env var alone must never read as a standalone deny/PASS signal —
    # it says nothing about whether *direct* egress is also blocked.
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:8080")
    res = detect(root=tmp_path, system="Linux", which=_none)
    eg = res["classes"]["egress_posture"]
    assert eg["status"] == "unknown"
    assert eg["active"] is None
    assert any("http_proxy" in e for e in eg["evidence"])


def test_macos_egress_is_unknown_only(tmp_path):
    # No grounded, read-only-inspectable default-outbound field exists on stock
    # macOS (ALF governs inbound only) — must stay honestly UNKNOWN, never fabricated.
    res = detect(root=tmp_path, system="Darwin", which=_none)
    eg = res["classes"]["egress_posture"]
    assert eg["status"] == "unknown"
    assert eg["active"] is None


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------

def test_macos_little_snitch_detected(tmp_path):
    (tmp_path / "Applications/Little Snitch.app").mkdir(parents=True)
    res = detect(root=tmp_path, system="Darwin", which=_none)
    assert "Little Snitch" in res["classes"]["network_ids"]["found"]


def test_macos_alf_globalstate_on(tmp_path):
    p = tmp_path / "Library/Preferences/com.apple.alf.plist"
    p.parent.mkdir(parents=True)
    with p.open("wb") as fh:
        plistlib.dump({"globalstate": 1}, fh)
    res = detect(root=tmp_path, system="Darwin", which=_none)
    fw = res["classes"]["firewall"]
    assert fw["status"] == "present"
    assert fw["active"] is True


def test_macos_alf_absent_is_unknown(tmp_path):
    # Sequoia 15+ moved ALF state out of the plist -> we must report UNKNOWN, not absent
    res = detect(root=tmp_path, system="Darwin", which=_none)
    assert res["classes"]["firewall"]["status"] == "unknown"


def test_macos_santa_detected(tmp_path):
    (tmp_path / "Applications/Santa.app").mkdir(parents=True)
    res = detect(root=tmp_path, system="Darwin", which=_none)
    assert "Santa" in res["classes"]["edr_av"]["found"]


def test_macos_host_audit_is_unknown(tmp_path):
    # OpenBSM state is not reliably determinable read-only (ships by default <=13,
    # disabled by default >=14) -> UNKNOWN, never a false PASS.
    _touch(tmp_path, "etc/security/audit_control", "flags:lo\n")
    res = detect(root=tmp_path, system="Darwin", which=_none)
    assert res["classes"]["host_audit"]["status"] == "unknown"


def test_macos_tailscale_app_detected(tmp_path):
    (tmp_path / "Applications/Tailscale.app").mkdir(parents=True)
    res = detect(root=tmp_path, system="Darwin", which=_none)
    assert "Tailscale" in res["classes"]["tunnel_transport"]["found"]


# ---------------------------------------------------------------------------
# Tunnel / mesh-VPN transport (E-065/C-324) -- present alone is NEVER a finding
# on its own; only risk.py's RISK-24 combinational rule consumes this class, and
# only under the full triple (tunnel present + exec/egress capability + a
# hardened egress-posture grade). No standalone check_host_tunnel_transport
# exists, deliberately -- see hostwatch.py's TUNNEL_TRANSPORT comment.
# ---------------------------------------------------------------------------

def test_linux_tunnel_transport_unknown_when_nothing_found(tmp_path):
    # B-172: a miss cannot prove absence (could be installed via snap/flatpak or a
    # non-PATH location a non-root scan can't see) -- honest UNKNOWN, not "absent".
    res = detect(root=tmp_path, system="Linux", which=_none)
    assert res["classes"]["tunnel_transport"]["status"] == "unknown"


def test_linux_tailscale_detected_by_binary_on_path(tmp_path):
    def which(n):
        return "/usr/bin/tailscale" if n == "tailscale" else None
    res = detect(root=tmp_path, system="Linux", which=which)
    assert res["classes"]["tunnel_transport"]["status"] == "present"
    assert "Tailscale" in res["classes"]["tunnel_transport"]["found"]


def test_linux_tailscale_detected_by_state_file(tmp_path):
    _touch(tmp_path, "var/lib/tailscale/tailscaled.state")
    res = detect(root=tmp_path, system="Linux", which=_none)
    assert "Tailscale" in res["classes"]["tunnel_transport"]["found"]


def test_linux_cloudflared_detected_by_binary_on_path(tmp_path):
    def which(n):
        return "/usr/local/bin/cloudflared" if n == "cloudflared" else None
    res = detect(root=tmp_path, system="Linux", which=which)
    assert "cloudflared" in res["classes"]["tunnel_transport"]["found"]


def test_linux_ngrok_detected_by_binary_on_path(tmp_path):
    def which(n):
        return "/usr/local/bin/ngrok" if n == "ngrok" else None
    res = detect(root=tmp_path, system="Linux", which=which)
    assert "ngrok" in res["classes"]["tunnel_transport"]["found"]


def test_linux_frpc_and_bore_detected_by_binary_on_path(tmp_path):
    def which(n):
        return f"/usr/local/bin/{n}" if n in ("frpc", "bore") else None
    res = detect(root=tmp_path, system="Linux", which=which)
    found = res["classes"]["tunnel_transport"]["found"]
    assert "frp" in found
    assert "bore" in found


def test_linux_tunnel_transport_present_alone_carries_no_active_signal(tmp_path):
    # B-434: a bare `shutil.which()` PATH hit is "present" but NOT, by itself,
    # evidence the transport is actually enrolled -- an installed-but-never-used
    # binary is indistinguishable from a live tunnel at that level. `active` stays
    # None until a stronger corroboration signal is also found (see the
    # systemd-enabled tests below); RISK-24 (risk.py) requires that corroboration.
    def which(n):
        return "/usr/bin/tailscale" if n == "tailscale" else None
    res = detect(root=tmp_path, system="Linux", which=which)
    assert res["classes"]["tunnel_transport"]["status"] == "present"
    assert res["classes"]["tunnel_transport"]["active"] is None


def test_linux_tailscale_active_via_systemd_symlink(tmp_path):
    # B-434: an enabled tailscaled.service means the daemon is actually enrolled
    # as a running service, not merely a binary someone downloaded once.
    def which(n):
        return "/usr/bin/tailscale" if n == "tailscale" else None
    _touch(tmp_path, "etc/systemd/system/multi-user.target.wants/tailscaled.service")
    res = detect(root=tmp_path, system="Linux", which=which)
    assert res["classes"]["tunnel_transport"]["active"] is True


def test_linux_cloudflared_active_via_systemd_symlink(tmp_path):
    # B-434: `cloudflared service install` (Cloudflare's own documented path to run
    # a persistent tunnel) enables this exact unit.
    def which(n):
        return "/usr/local/bin/cloudflared" if n == "cloudflared" else None
    _touch(tmp_path, "etc/systemd/system/multi-user.target.wants/cloudflared.service")
    res = detect(root=tmp_path, system="Linux", which=which)
    assert res["classes"]["tunnel_transport"]["active"] is True


def test_linux_ngrok_present_never_carries_active_signal(tmp_path):
    # B-434: ngrok has no single, authoritative systemd-unit convention to ground
    # an "active" corroboration against without fabricating one -- present stays
    # uncorroborated even with the binary on PATH. This is the exact repro from
    # CLAWSECCHECK-B-434 (an unused `ngrok` binary downloaded once, never run).
    def which(n):
        return "/usr/local/bin/ngrok" if n == "ngrok" else None
    res = detect(root=tmp_path, system="Linux", which=which)
    assert res["classes"]["tunnel_transport"]["status"] == "present"
    assert res["classes"]["tunnel_transport"]["active"] is None


def test_windows_tailscale_detected_by_binary_on_path(tmp_path):
    def which(n):
        return "C:\\Program Files\\Tailscale\\tailscale.exe" if n == "tailscale" else None
    res = detect(root=tmp_path, system="Windows", which=which)
    assert "Tailscale" in res["classes"]["tunnel_transport"]["found"]


# ---------------------------------------------------------------------------
# Windows (best-effort; registry unavailable off-Windows -> filesystem only)
# ---------------------------------------------------------------------------

def test_windows_sysmon_detected_by_file(tmp_path):
    _touch(tmp_path, "Windows/Sysmon64.exe")
    res = detect(root=tmp_path, system="Windows", which=_none)
    assert "Sysmon" in res["classes"]["network_ids"]["found"]


def test_windows_crowdstrike_detected_by_dir(tmp_path):
    (tmp_path / "Program Files/CrowdStrike").mkdir(parents=True)
    res = detect(root=tmp_path, system="Windows", which=_none)
    assert "CrowdStrike Falcon" in res["classes"]["edr_av"]["found"]


def test_windows_firewall_unknown_without_registry(tmp_path):
    # off-Windows winreg is unavailable -> firewall state cannot be read -> UNKNOWN
    res = detect(root=tmp_path, system="Windows", which=_none)
    assert res["classes"]["firewall"]["status"] == "unknown"


# ---------------------------------------------------------------------------
# Unsupported platform
# ---------------------------------------------------------------------------

def test_unsupported_platform_is_all_unknown(tmp_path):
    res = detect(root=tmp_path, system="Plan9", which=_none)
    assert res["supported"] is False
    for cls in hostwatch.CLASSES:
        assert res["classes"][cls]["status"] == "unknown"


def test_detect_never_raises_on_missing_root():
    # a nonexistent root must degrade gracefully, not crash
    res = detect(root="/nonexistent-clawseccheck-root-xyz", system="Linux", which=_none)
    assert res["supported"] is True
    # B-172: a miss on a visibility class is honest UNKNOWN, not "absent".
    assert res["classes"]["network_ids"]["status"] == "unknown"
