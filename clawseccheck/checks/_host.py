"""Topic module: host checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
from pathlib import Path
from .. import trajectory as _trajectory
from ..catalog import (
    ATTESTED,
    PASS,
    UNKNOWN,
    WARN,
    Finding,
)
from ..collector import (
    Context,
    dig,
)

from . import _shared
from ._shared import (
    _agent_is_powerful,
    _finding,
    _plugins,
)


# Keywords that map a free-text self-reported host monitor to a host-watch class.
# Used only to UPGRADE a gap (absent / unknown / not-scanned) to an attested PASS —
# never to downgrade a static detection and never to create a FAIL.
_HOST_ATTEST_HINTS = {
    "network_ids": (
        "ids",
        "ips",
        "suricata",
        "zeek",
        "snort",
        "network monitor",
        "little snitch",
        "ntopng",
        "darktrace",
    ),
    "host_audit": ("audit", "auditd", "syscall", "openbsm", "sysmon"),
    "file_integrity": ("integrity", "fim", "aide", "tripwire", "osquery", "samhain"),
    "edr_av": (
        "edr",
        "xdr",
        "antivirus",
        "anti-virus",
        "crowdstrike",
        "defender",
        "wazuh",
        "sentinelone",
        "sentinel one",
        "carbon black",
        "clamav",
        "santa",
        "cortex",
        "cylance",
        "malwarebytes",
    ),
    "firewall": (
        "firewall",
        "ufw",
        "firewalld",
        "iptables",
        "nftables",
        " pf ",
        "packet filter",
        "alf",
    ),
}


# class key -> plain-language, article-free noun phrase for detail/fix text
# (article-free so "No {label} detected", "whether {label} is present", and
#  "Install/enable {label}" all read grammatically).
_HOST_CLASS_LABEL = {
    "network_ids": "network monitoring / IDS (Suricata, Zeek, Snort)",
    "host_audit": "host audit logging (auditd / OpenBSM / Sysmon)",
    "file_integrity": "file-integrity monitoring (AIDE, Tripwire, osquery)",
    "edr_av": "endpoint protection / EDR (Wazuh, CrowdStrike, ClamAV, Defender)",
    "firewall": "host firewall (ufw, firewalld, nftables)",
}


# ---------- B16: is threat monitoring / detection set up? ----------
_MONITORING_HINTS = (
    "clawsec",
    "security-monitor",
    "openclaw-security-monitor",
    "sentinel",
    "falco",
    "osquery",
    "wazuh",
    "trent",
    "threat",
    "intrusion",
    "watchdog",
    "ids",
    "-ids",
    "edr",
    "monitor",
)


def _attested_host_monitors(ctx: Context, cls: str) -> list[str]:
    """Self-reported host monitors (attestation) that keyword-match this class."""
    att = getattr(ctx, "attestation", None) or {}
    declared = att.get("host_monitors")
    if not isinstance(declared, list):
        return []
    hints = _HOST_ATTEST_HINTS.get(cls, ())
    out = []
    for d in declared:
        if isinstance(d, str) and any(h in f" {d.lower()} " for h in hints):
            out.append(d)
    return out


def _host_finding(cid: str, cls: str, ctx: Context) -> Finding:
    label = _HOST_CLASS_LABEL[cls]
    host = getattr(ctx, "host", None)
    # Attestation fills the gap the read-only scan can't see — but only when the
    # static scan did NOT already confirm this class present (that HIGH evidence wins).
    static_present = bool(
        host
        and host.get("supported")
        and host.get("classes", {}).get(cls, {}).get("status") == "present"
    )
    attested = _attested_host_monitors(ctx, cls)
    if attested and not static_present:
        return _finding(
            cid,
            PASS,
            f"{label} not confirmed by the read-only scan, but the agent attests it "
            f"runs on this host: {', '.join(attested)} (self-reported).",
            "Self-reported — confirm it is actually active and its rules are current.",
            evidence=attested,
            confidence=ATTESTED,
        )
    if not host or not host.get("supported"):
        return _finding(
            cid,
            UNKNOWN,
            "Host monitor state not determined (host scan not run, or this OS / "
            "path is not inspectable read-only).",
            "Run ClawSecCheck on the agent's own host so it can inspect monitoring, "
            "or confirm host monitoring manually.",
        )
    info = host.get("classes", {}).get(cls, {})
    status = info.get("status")
    found = [str(x) for x in (info.get("found") or [])]
    active = info.get("active")

    if status == "present":
        names = ", ".join(found) if found else "a monitor"
        state = "enabled" if active is True else ("installed" if active is False else "present")
        return _finding(
            cid,
            PASS,
            f"Detected {names} on the host ({state}).",
            "Keep it running and its rules current.",
            evidence=found,
        )

    if status == "unknown":
        return _finding(
            cid,
            UNKNOWN,
            f"Could not determine read-only whether {label} is present on this host.",
            f"Verify manually whether {label} is active on the agent's machine.",
        )

    # status == "absent" — gate on agent blast-radius so we never cry wolf
    if _agent_is_powerful(ctx):
        return _finding(
            cid,
            WARN,
            f"No {label} detected, and this agent is high-privilege (it can act on "
            "the host and is reachable by untrusted input). If it were compromised, "
            "the activity could go unseen.",
            f"Install/enable {label} on the host, or reduce the agent's blast radius "
            "(sandbox it, lock channels to an allowlist, remove exec/write tools).",
        )
    return _finding(
        cid,
        PASS,
        f"No {label} detected, but this agent is low-privilege, so host-level "
        "monitoring is less critical here.",
        f"Consider {label} on the host if you later grant this agent exec/write "
        "tools or open it to untrusted channels.",
    )


def check_audit_log(ctx: Context) -> Finding:
    cfg = ctx.config
    # logging.audit and audit.enabled do NOT exist in the OpenClaw config schema.
    # Audit is a CLI command only: `openclaw security audit`
    # There is no config toggle to enable/disable audit logging.
    # We check what IS observable: log redaction (separate from audit).
    redact = dig(cfg, "logging.redactSensitive")
    if redact == "off":
        return _finding(
            "B10",
            WARN,
            'logging.redactSensitive is "off" — logs may expose secrets/PII '
            "(Israel Amendment 13). OpenClaw audit is a CLI command "
            "(`openclaw security audit`), not a config toggle.",
            'Set logging.redactSensitive to "tools" and run `openclaw security audit` periodically.',
        )
    return _finding(
        "B10",
        UNKNOWN,
        "OpenClaw exposes no audit-log config field (audit is a CLI command: "
        "`openclaw security audit`) — cannot assess from config alone. "
        "Run `openclaw security audit` periodically to detect issues.",
        "Schedule `openclaw security audit` and wire its output to an alert channel.",
    )


def check_monitoring(ctx: Context) -> Finding:
    """Does the user actually have threat monitoring / detection in place?"""
    cfg = ctx.config
    signals = []
    for name in list(ctx.installed_skills) + list(_plugins(cfg)):
        if any(h in str(name).lower() for h in _MONITORING_HINTS):
            signals.append(f"'{name}'")
    # monitoring, security.monitoring, alerts, security.alerts do NOT exist in the
    # OpenClaw config schema — removed to eliminate dead-code false-signal arms.
    # Detection relies on skill/plugin name hints above (confirmed reliable).
    if signals:
        return _finding(
            "B16",
            PASS,
            f"Threat monitoring present: {', '.join(signals[:5])}.",
            "Keep it enabled and make sure its alerts actually reach you.",
        )
    return _finding(
        "B16",
        WARN,
        "No threat-monitoring or detection plugin/skill is configured in this OpenClaw "
        "config. Monitors set up OUTSIDE it — a separate security agent or workspace, "
        "host-level IDS/EDR — are not visible to this config-only scan, so this is "
        "'not detected here', not proof you're unwatched; confirm before relying on it.",
        "If you have no detection, add a monitoring skill (e.g. ClawSec or "
        "openclaw-security-monitor), wire audit logging to an alert channel, or schedule "
        "ClawSecCheck's own `clawseccheck --monitor`. If monitoring lives elsewhere, you can "
        "self-report it via `--ask`/`--attest` (host_monitors) so the host-watch checks "
        "credit it.",
    )


def check_host_network_ids(ctx: Context) -> Finding:
    return _host_finding("B50", "network_ids", ctx)


def check_host_audit(ctx: Context) -> Finding:
    return _host_finding("B51", "host_audit", ctx)


def check_host_file_integrity(ctx: Context) -> Finding:
    return _host_finding("B52", "file_integrity", ctx)


def check_host_edr(ctx: Context) -> Finding:
    return _host_finding("B53", "edr_av", ctx)


def check_host_firewall(ctx: Context) -> Finding:
    return _host_finding("B54", "firewall", ctx)


# B101 (F-084): outbound (egress) filtering posture — is the default OUTPUT policy
# deny or allow? Distinct from B54 (which only asks "is a firewall present"): a
# firewall can be installed and active with a wide-open default-allow egress
# policy, which is exactly the gap this check targets. Does NOT reuse
# _host_finding — that helper's "found = PASS regardless of active state" shape
# fits "is a monitor tool present," not "is the resolved policy itself good or
# bad" (a confirmed default-allow must read as a gap, not a PASS).
def check_host_egress_posture(ctx: Context) -> Finding:
    """B101 — outbound (egress) filtering posture (F-084)."""
    host = getattr(ctx, "host", None)
    if not host or not host.get("supported"):
        return _finding(
            "B101",
            UNKNOWN,
            "Host egress-filtering state not determined (host scan not run, or this "
            "OS/path is not inspectable read-only).",
            "Run ClawSecCheck on the agent's own host so it can inspect outbound "
            "filtering policy, or confirm it manually.",
        )
    info = host.get("classes", {}).get("egress_posture", {})
    active = info.get("active")
    found = [str(x) for x in (info.get("found") or [])]
    evidence = [str(x) for x in (info.get("evidence") or [])]

    if active is None:
        return _finding(
            "B101",
            UNKNOWN,
            "Could not determine read-only whether outbound traffic defaults to "
            "deny or allow on this host.",
            "Verify manually whether outbound traffic defaults to deny (nftables/"
            "iptables OUTPUT policy, ufw DEFAULT_OUTGOING_POLICY) — an unreadable "
            "policy is the expected result on most systems.",
            evidence=evidence,
        )

    if active is True:
        return _finding(
            "B101",
            PASS,
            f"Outbound traffic on this host defaults to deny: {', '.join(found)}.",
            "Keep the default-deny egress policy and its allowlist rules current.",
            evidence=evidence,
        )

    # active is False: a default-allow outbound policy was explicitly confirmed.
    if _agent_is_powerful(ctx):
        return _finding(
            "B101",
            WARN,
            f"Outbound traffic on this host defaults to ALLOW ({', '.join(found)}), "
            "and this agent is high-privilege (it can act on the host and is "
            "reachable by untrusted input). A compromised skill/tool call can reach "
            "any destination, including the cloud-metadata endpoint "
            "(169.254.169.254) and other RFC1918 hosts.",
            "Set a default-deny OUTPUT policy and explicitly allowlist only the "
            "destinations the agent actually needs.",
            evidence=evidence,
        )
    return _finding(
        "B101",
        PASS,
        f"Outbound traffic on this host defaults to allow ({', '.join(found)}), but "
        "this agent is low-privilege, so egress filtering is less critical here.",
        "Consider a default-deny egress policy if you later grant this agent exec/"
        "write tools or open it to untrusted channels.",
        evidence=evidence,
    )


def check_incident_readiness(ctx: Context) -> Finding:
    """B85 — incident readiness: is the agent's tool-use trail present AND tamper-resistant?

    After a compromise you need to reconstruct what the agent actually did. OpenClaw's
    per-session trajectory sidecar (recon §9.1) is the on-disk, attributable record of tool
    calls — the closest thing to an audit log OpenClaw has, and unlike ``logging.file`` /
    ``cacheTrace`` it is a documented, greppable tool-call surface. This check answers two
    filesystem questions and NEVER reads call contents (§8 — no ``data.arguments`` etc.):

      1. present — does any trajectory sidecar exist (is tool use recorded at all)?
      2. tamper  — are those files, or their ``sessions/`` directory, group/world-writable,
                   so a local user (or the agent itself) could rewrite/delete the record?

    HIGH confidence — these are filesystem facts, not a self-report. Advisory (scored=False)
    so it never moves the static grade.

    PASS    — a trajectory record is present AND no file/dir is group/world-writable.
    WARN    — a trajectory record is present BUT a file or its ``sessions/`` dir is
              group/world-writable — the incident trail is tamperable.
    UNKNOWN — non-POSIX (NTFS ACLs unreadable), or no sidecar found (disabled via
              ``OPENCLAW_TRAJECTORY=0``, relocated to ``OPENCLAW_TRAJECTORY_DIR``, or the
              agent simply has not run yet). Never a false PASS/FAIL.

    Only ``stat()`` is called — no trajectory file contents are read.
    """
    if not _shared._is_posix():
        return _finding(
            "B85",
            UNKNOWN,
            "On Windows, file security uses NTFS ACLs, not POSIX mode bits — ClawSecCheck "
            "can't read those read-only, so the trajectory record's tamper-resistance is "
            "UNKNOWN, never a false PASS.",
            "Check the ACLs yourself: the trajectory sidecar files under "
            "agents/<agent>/sessions/ should not grant write to Users / Everyone.",
        )

    home = ctx.home
    files = _trajectory.find_trajectory_files(home) if isinstance(home, Path) else []
    if not files:
        return _finding(
            "B85",
            UNKNOWN,
            "No OpenClaw trajectory sidecar was found under agents/<agent>/sessions/, so "
            "there is no on-disk record of the agent's tool calls to reconstruct an "
            "incident from. This is UNKNOWN, not a failure: the record may be disabled "
            "(OPENCLAW_TRAJECTORY=0), relocated (OPENCLAW_TRAJECTORY_DIR), or the agent "
            "may simply not have run yet.",
            "Keep trajectory tracing on (the default) so tool use is recorded, and run "
            "this audit on the host where those session logs live.",
        )

    tamper: list[str] = []
    seen_dirs: set = set()
    for path in files:
        try:
            fmode = path.stat().st_mode & 0o777
        except OSError:
            continue
        if fmode & 0o022:
            tamper.append(f"{path.name} (mode {oct(fmode)[-3:]})")
        parent = path.parent
        try:
            real = parent.resolve()
        except OSError:
            real = parent
        if real in seen_dirs:
            continue
        seen_dirs.add(real)
        try:
            dmode = parent.stat().st_mode & 0o777
        except OSError:
            continue
        if dmode & 0o022:
            tamper.append(f"{parent.name}/ (dir, mode {oct(dmode)[-3:]})")

    if tamper:
        joined = "; ".join(tamper[:8])
        extra = f" (+{len(tamper) - 8} more)" if len(tamper) > 8 else ""
        return _finding(
            "B85",
            WARN,
            "The agent's trajectory record exists but is group/world-writable — a local "
            "user (or the agent itself) could rewrite or delete the tool-use trail, "
            f"destroying the evidence needed to reconstruct an incident: {joined}{extra}",
            "Tighten permissions so only the owner can write the record: `chmod 600` the "
            "*.trajectory.jsonl files and `chmod 700` their sessions/ directory.",
            evidence=tamper,
            confidence="HIGH",
        )

    return _finding(
        "B85",
        PASS,
        f"An attributable trajectory record of the agent's tool use is present "
        f"({len(files)} session file(s) checked) and neither the files nor their "
        "sessions/ directory are group/world-writable — an incident could be "
        "reconstructed from a tamper-resistant trail.",
        "Keep trajectory tracing on and its files owner-only so the incident trail stays "
        "trustworthy.",
        evidence=[f"trajectory files present: {len(files)}"],
        confidence="HIGH",
    )
