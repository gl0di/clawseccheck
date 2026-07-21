"""Topic module: host checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import re
from datetime import datetime, timezone
from pathlib import Path
from .. import trajectory as _trajectory
from ..catalog import (
    ATTESTED,
    FAIL,
    LOW,
    PASS,
    UNKNOWN,
    WARN,
    Finding,
)
from ..collector import (
    Context,
    bundled_root_overrides,
    dig,
    env_evidence_readable,
    systemd_unit_is_openclaw_related as _systemd_unit_is_openclaw_related_impl,
)

from . import _shared
from ._shared import (
    _agent_is_powerful,
    _custom,
    _dir_replaceable_by_others,
    _file_readable_by_others,
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

# The four *detection/visibility* classes (mirrors hostwatch.VISIBILITY_CLASSES).
# A read-only, often non-root scan cannot PROVE one of these is absent — a miss
# is honest UNKNOWN (hostwatch._detection_cls, B-172) — but an UNKNOWN on one of
# these still means "presence not confirmed," so a high-privilege agent still
# deserves a (lower-confidence) heads-up rather than a silent plain UNKNOWN.
# FIREWALL is prevention, not detection, and keeps the plain UNKNOWN branch.
_VISIBILITY_CLASSES = frozenset({"network_ids", "host_audit", "file_integrity", "edr_av"})


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
        if cls in _VISIBILITY_CLASSES and _agent_is_powerful(ctx):
            return _custom(
                cid,
                LOW,
                WARN,
                f"Could not confirm read-only whether {label} is present on this "
                "host, and this agent is high-privilege (it can act on the host "
                "and is reachable by untrusted input). A read-only scan cannot "
                "prove a monitor's absence — but if there genuinely is none, a "
                "compromise here could go unseen.",
                f"Confirm manually whether {label} is active on the agent's "
                "machine, or self-report it via `--attest` (host_monitors) so "
                "this check can credit it.",
            )
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
    # B-127: group-writable (not also world-writable) AND the owning group has no
    # other members currently -> no live "other group member" threat subject exists.
    # Bucketed separately so it can be reported as a lower-severity hygiene note
    # instead of the active-tamper WARN, while world-write (any local user) and
    # "membership unknown/has other members" keep the existing WARN behavior.
    tamper_singleton: list[str] = []
    seen_dirs: set = set()

    def _record(entry: str, mode: int, st) -> None:
        if mode & 0o002:  # world-writable -> always an active threat, never downgrade
            tamper.append(entry)
            return
        other_members = _shared._group_has_other_members(st.st_gid, st.st_uid)
        if other_members is False:
            tamper_singleton.append(entry)
        else:
            tamper.append(entry)

    for path in files:
        try:
            fst = path.stat()
        except OSError:
            continue
        fmode = fst.st_mode & 0o777
        if fmode & 0o022:
            _record(f"{path.name} (mode {oct(fmode)[-3:]})", fmode, fst)
        parent = path.parent
        try:
            real = parent.resolve()
        except OSError:
            real = parent
        if real in seen_dirs:
            continue
        seen_dirs.add(real)
        try:
            dst = parent.stat()
        except OSError:
            continue
        dmode = dst.st_mode & 0o777
        if dmode & 0o022:
            _record(f"{parent.name}/ (dir, mode {oct(dmode)[-3:]})", dmode, dst)

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

    if tamper_singleton:
        joined = "; ".join(tamper_singleton[:8])
        extra = f" (+{len(tamper_singleton) - 8} more)" if len(tamper_singleton) > 8 else ""
        return _custom(
            "B85", LOW, WARN,
            "The agent's trajectory record exists but is group-writable — tighten to "
            f"0600/0700; no other group members currently: {joined}{extra}",
            "Tighten permissions so only the owner can write the record: `chmod 600` the "
            "*.trajectory.jsonl files and `chmod 700` their sessions/ directory (defense "
            "in depth — group membership can change later).",
            tamper_singleton,
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


# ---------- B150: systemd user-unit Restart=always persistence (informational) ----------
# Real observed shape: ~/.config/systemd/user/openclaw-gateway.service carries
# `Restart=always` + `WantedBy=default.target` — a durable autonomy substrate (the
# gateway restarts itself indefinitely and starts automatically at login/boot). No
# existing check reads systemd unit files; hostwatch.py only detects system-wide
# *monitor* enable-symlinks (/etc/systemd/system/*.wants/), not user units or their
# content. ~/.config/systemd/user/ is a sibling of ~/.openclaw under the same real
# user home, so it is reached via ctx.home.parent (same idiom as check_backups' C3
# ctx.home.parent / "backups" lookup) rather than hostwatch's fake-OS-root model.
#
# This is disclosure only, never proof of compromise: Restart=always is legitimate,
# common infrastructure for a long-running gateway service. WARN (LOW/advisory) only
# when an OpenClaw-related unit is found with a persistent-restart directive; PASS/
# UNKNOWN otherwise. Never FAIL.
_SYSTEMD_RESTART_RE = re.compile(r"^\s*Restart\s*=\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_SYSTEMD_EXECSTART_RE = re.compile(r"^\s*ExecStart\s*=\s*(.*\S)?\s*$", re.IGNORECASE | re.MULTILINE)
_SYSTEMD_WANTEDBY_RE = re.compile(r"^\s*WantedBy\s*=\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)

# Persistent-restart directives worth disclosing (systemd.service(5)): "always" restarts
# unconditionally; "on-failure"/"on-abnormal"/"on-watchdog"/"on-abort" are conditional and
# far less interesting as a standalone autonomy signal, so only "always" is flagged here.
_SYSTEMD_PERSISTENT_RESTART = frozenset({"always"})


def _systemd_unit_is_openclaw_related(unit_name: str, exec_start: str) -> bool:
    """True if the unit's file name or ExecStart= line mentions 'openclaw'.

    B-289 moved the body to ``collector.systemd_unit_is_openclaw_related`` so the unit-env
    collector and B150 share ONE definition of "is this OpenClaw's unit" rather than two
    that can drift. Behaviour is unchanged.
    """
    return _systemd_unit_is_openclaw_related_impl(unit_name, exec_start)


def check_systemd_persistence(ctx: Context) -> Finding:
    """B150 — OpenClaw-related systemd user-unit Restart=always persistence.

    Reads ~/.config/systemd/user/*.service (a sibling of ~/.openclaw, resolved via
    ctx.home.parent) for units whose name or ExecStart= line mentions "openclaw". If
    found with Restart=always, this is reported as an informational/LOW advisory —
    legitimate infrastructure that also happens to be a durable autonomy/persistence
    mechanism worth disclosing, never proof of compromise.

    PASS    — OpenClaw-related unit(s) found, none set Restart=always (or an
              equivalent persistent-restart directive).
    WARN    — an OpenClaw-related unit sets Restart=always (advisory, LOW, never FAIL).
    UNKNOWN — no ~/.config/systemd/user/ directory (systemd not in use, non-Linux, or
              simply absent), or no OpenClaw-related unit file found there.
    """
    user_units_dir = ctx.home.parent / ".config" / "systemd" / "user"
    if not user_units_dir.is_dir():
        return _finding(
            "B150",
            UNKNOWN,
            "No ~/.config/systemd/user/ directory found — systemd user units are not in "
            "use on this host (or this is not Linux), so unit-based persistence could "
            "not be assessed.",
            "No action needed unless a systemd user unit is added later.",
        )

    try:
        unit_files = sorted(p for p in user_units_dir.iterdir()
                             if p.is_file() and not p.is_symlink() and p.suffix == ".service")
    except OSError:
        unit_files = []

    any_openclaw_unit = False
    persistent_ev: list[str] = []
    other_ev: list[str] = []

    for unit_path in unit_files:
        try:
            text = unit_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        exec_m = _SYSTEMD_EXECSTART_RE.search(text)
        exec_start = (exec_m.group(1) or "") if exec_m else ""
        if not _systemd_unit_is_openclaw_related(unit_path.name, exec_start):
            continue
        any_openclaw_unit = True

        restart_m = _SYSTEMD_RESTART_RE.search(text)
        restart_val = restart_m.group(1).lower() if restart_m else None
        wanted_m = _SYSTEMD_WANTEDBY_RE.search(text)
        wanted_by = wanted_m.group(1) if wanted_m else None

        if restart_val in _SYSTEMD_PERSISTENT_RESTART:
            detail = f"{unit_path.name}: Restart={restart_val}"
            if wanted_by:
                detail += f", WantedBy={wanted_by}"
            persistent_ev.append(detail)
        else:
            other_ev.append(unit_path.name)

    if not any_openclaw_unit:
        return _finding(
            "B150",
            UNKNOWN,
            "No OpenClaw-related systemd user unit found under "
            f"{user_units_dir} — unit-based persistence not applicable.",
            "No action needed unless an OpenClaw systemd user unit is added later.",
        )

    if persistent_ev:
        detail = "; ".join(persistent_ev[:6])
        return _finding(
            "B150",
            WARN,
            "An OpenClaw-related systemd user unit restarts itself indefinitely "
            f"(a durable autonomy substrate): {detail}. This is disclosure only — "
            "Restart=always is common, legitimate infrastructure for a long-running "
            "gateway service, not proof of compromise.",
            "Confirm this restart policy is intentional. If the service should not "
            "persist automatically, change Restart= to 'no' or 'on-failure', and "
            "review any WantedBy= target that starts it automatically at login/boot.",
            evidence=persistent_ev,
        )

    return _finding(
        "B150",
        PASS,
        "OpenClaw-related systemd user unit(s) found "
        f"({', '.join(other_ev[:6])}); none set Restart=always.",
        "Keep restart policies intentional and documented.",
        evidence=other_ev[:6],
    )


# ---------- B186 (B-289, ENV-3): relocated bundled skills/hooks code-load roots ----------
# OpenClaw resolves its BUNDLED skills and hooks directories through two environment
# variables that it honours UNCONDITIONALLY — no existence check, no trust check, ahead of
# every legitimate resolution path:
#
#   OPENCLAW_BUNDLED_SKILLS_DIR  bundled-dir-BQFrcRIS.js:22-24  resolveBundledSkillsDir
#   OPENCLAW_BUNDLED_HOOKS_DIR   workspace-zj1TEEka.js:54-56    resolveBundledHooksDir
#
# Setting either points the agent at an attacker's code and needs NO write access to the
# npm-owned install tree at all. Two delivery channels are persistent and readable:
# a systemd user unit's `Environment=`/`EnvironmentFile=`, and the two GLOBAL runtime
# dotenv files (~/.openclaw/.env, ~/.config/openclaw/gateway.env), which
# loadGlobalRuntimeDotEnvFiles admits with NO entryFilter (dotenv-eb21SB3p.js:222-223).
# The WORKSPACE .env is NOT a channel: BLOCKED_WORKSPACE_DOTENV_KEYS lists both variables
# (:125-127) and BLOCKED_WORKSPACE_DOTENV_PREFIXES contains "OPENCLAW_" (:183).
#
# HONEST SCOPE — three deliberate narrowings, each with its reason:
#
# 1. OPENCLAW_BUNDLED_PLUGINS_DIR is NOT covered and must never be added. OpenClaw
#    hardened exactly that one: bundled-dir-DKbeVv7V.js:124-134 gates the override through
#    resolveTrustedExistingOverride (:77-85), which demands the realpath be pathContains-ed
#    by a trusted bundled-plugin root under the package root AND pass
#    hasUsableBundledPluginTree. `OPENCLAW_BUNDLED_PLUGINS_DIR=/tmp/evil` is REJECTED; the
#    only bypass needs VITEST (:32-34). Flagging it would be a false positive on the
#    product's own internal uses (bundled-ClxzUaje.js:145, dist/plugin-sdk/qa-runner-*).
#
# 2. C-262 (round 2): PASS exists, but only with an explicit, permanent confidence cap.
#    Round 1 made every "found nothing" outcome UNKNOWN, on the reasoning that a variable
#    exported into an interactive shell just before launching the agent leaves no artifact
#    on disk, so "we found no override in the files we can read" is not "no override is
#    set". That reasoning is still correct — it is WHY this can never reach
#    pass_confidence="verified" — but applying it uniformly made an unconditional UNKNOWN
#    the permanent state of every clean host, including ones where a systemd unit or global
#    dotenv genuinely WAS read and genuinely carries no override. An UNKNOWN that can never
#    clear regardless of what the audit reads stops functioning as a signal. Two considered
#    resolutions, and why (b) was picked over (a):
#      (a) route it to the borderline-adjudication band (adjudication.py) instead, dropping
#          it from the plain-report/A-F view. REJECTED: every unsuppressed UNKNOWN already
#          reaches build_judge_packet() today with zero code change (adjudication.py's
#          source (a)), so this would additionally require inventing a NEW "suppress from
#          the main report but still adjudicate" mechanism with no precedent anywhere else
#          in report.py/dossier.py/sarif.py — a bigger, riskier change than the defect
#          warrants, for a check that is already scored=False and therefore already outside
#          the grade either way.
#      (b) PICKED: when at least one persistent artifact was actually read
#          (env_evidence_readable(ctx)) and it carries no override, return PASS with
#          pass_confidence="no_signal" — the same idiom B191 (this file) and B168
#          (checks/_lifecycle.py) already use for "we looked, found nothing, but our view is
#          known-incomplete." It differs from THEIR "no_signal" only in WHY the view is
#          incomplete: theirs is a sampling/retention cap that a fuller read could someday
#          clear to "verified"; B186's gap is the ambient-shell channel, which no persistent
#          read can EVER clear — so this finding can reach PASS but can never reach
#          pass_confidence="verified". That distinction is stated in the finding text itself
#          so it is never mistaken for a fully-verified clean bill of health.
#    When NOTHING persistent was even present to read (no unit, no dotenv), there is no
#    evidence to build even a capped PASS on — that state stays UNKNOWN, matching how B191
#    keeps "no audit_events table at all" as UNKNOWN rather than PASS.
#
# 3. The task this check came from proposed two extra rules that were tried and RETRACTED:
#    (a) "downgrade to informational when the override resolves INSIDE the openclaw package
#    root" — the package root is not knowable hermetically for a --home/fixture scan, and
#    the only hermetic proxy (a `node_modules/openclaw` path segment) is a string the
#    attacker picks, so it would have been a downgrade keyed on attacker-controlled input;
#    (b) "escalate when the target is /tmp-rooted" — a 0700 directory inside /tmp is as
#    private as one in the user's home, so the location is not the privilege. What replaced
#    both is the thing that is actually checkable: whether another local account can
#    replace the code (_dir_replaceable_by_others, sticky-aware, POSIX-only).
#
# A relocated SKILLS root is additionally handed to the ordinary skill-content scanners by
# collector._read_installed_skills, so its contents are audited by the existing engine
# rather than a second one. A relocated HOOKS root holds hook modules, not SKILL.md
# directories; it is disclosed here only.
def check_bundled_root_override(ctx: Context) -> Finding:
    """B186 (B-289) — bundled skills/hooks code-load root relocated by an env override.

    FAIL    — an override is observed AND its target directory is group/world-writable
              (non-sticky): another local account can replace the code the agent loads.
    WARN    — an override is observed. The agent loads and executes code from a root
              outside its install tree; legitimate for a source-checkout developer, which
              is why this is disclosure rather than an accusation.
    PASS    — no override found, AND at least one persistent artifact (an OpenClaw-related
              systemd unit or a global runtime dotenv file) was actually read to reach that
              conclusion. Always carries ``pass_confidence="no_signal"`` (see C-262 in the
              comment above this function) — never "verified": the ambient-shell delivery
              channel leaves nothing on disk for ANY read to see, no matter how complete.
    UNKNOWN — no persistent artifact was even present to read (no systemd unit, no global
              dotenv). There is no evidence to build a PASS on at all.
    """
    overrides = bundled_root_overrides(ctx)
    if not overrides:
        if env_evidence_readable(ctx):
            where = "the systemd user unit(s) and global dotenv file(s) that were readable"
            return _finding(
                "B186",
                PASS,
                "No OPENCLAW_BUNDLED_SKILLS_DIR / OPENCLAW_BUNDLED_HOOKS_DIR relocation was "
                f"found in {where}. This PASS carries reduced confidence (pass_confidence="
                "\"no_signal\") on purpose and can never reach full confidence: either "
                "variable can also be exported into the interactive shell that launches the "
                "agent, which leaves no artifact on disk for any local, read-only audit to "
                "see, however complete its read of persistent files is.",
                "No action needed if you never set these variables. If the agent is "
                "launched from a wrapper script or shell profile, check there too — "
                "OpenClaw honours both unconditionally and will load skills/hooks from "
                "wherever they point, and that channel is invisible to this check.",
                pass_confidence="no_signal",
            )
        where = "no systemd user unit or global dotenv file was present to read"
        return _finding(
            "B186",
            UNKNOWN,
            "No OPENCLAW_BUNDLED_SKILLS_DIR / OPENCLAW_BUNDLED_HOOKS_DIR relocation was "
            f"found ({where}) — but nothing persistent was present to read, so there is no "
            "evidence to build even a reduced-confidence PASS on. Either variable can also "
            "be exported into the shell that launches the agent, which leaves no artifact "
            "on disk for a local audit to read.",
            "If you never set these variables, nothing is needed. If the agent is launched "
            "from a wrapper script or shell profile, check there too — OpenClaw honours "
            "both unconditionally and will load skills/hooks from wherever they point.",
        )

    evidence: list[str] = []
    replaceable: list[str] = []
    for var, kind, value, source in overrides:
        # B-311: report the LITERAL override value — do not expanduser() it. systemd's
        # Environment=/EnvironmentFile= parsing is not a shell (no `~` expansion), and the
        # dist reads the value verbatim: resolveBundledSkillsDir / resolveBundledHooksDir
        # both do `process.env.X?.trim(); if (override) return override;`
        # (bundled-dir-BQFrcRIS.js:22-24, workspace-zj1TEEka.js:54-56) — no expansion, no
        # existence check. A `~`-prefixed override is therefore resolved by OpenClaw
        # relative to whatever the launching process's cwd happens to be, never to $HOME.
        # Expanding it here would report a directory OpenClaw does not actually load from
        # — wrong on a disclosure-only check whose entire value is telling the truth about
        # where the code-load root points. The scan below still runs against the literal
        # value; the only thing this changes is what gets PRINTED.
        resolved = Path(value)
        state = "exists" if resolved.is_dir() else "does not currently exist"
        evidence.append(f"{var}={resolved} ({kind} root, {state}) via {source}")
        why = _dir_replaceable_by_others(resolved)
        if why:
            replaceable.append(f"{var} target {resolved} is {why}")

    if replaceable:
        return _finding(
            "B186",
            FAIL,
            "A bundled code-load root is relocated to a directory other local accounts can "
            "write to, so any of them can replace the skills/hooks this agent loads and "
            "executes: " + "; ".join(replaceable) + ". "
            "OpenClaw honours these variables unconditionally, ahead of every legitimate "
            "resolution path.",
            "Move the relocated root to a directory only you can write (0755 or tighter, "
            "not group- or world-writable), or unset the variable so OpenClaw resolves its "
            "own bundled directory. Then review what is currently in that directory — it "
            "has been an executable-code root for the agent.",
            evidence=evidence + replaceable,
            confidence="HIGH",
        )

    return _finding(
        "B186",
        WARN,
        "A bundled code-load root is relocated by an environment override, so the agent "
        "loads skills/hooks from outside its own install tree: " + "; ".join(evidence) + ". "
        "This is disclosure, not proof of compromise — a source-checkout developer sets "
        "these deliberately — but it is a code-execution root, and OpenClaw honours it "
        "with no existence or trust check.",
        "Confirm you set this deliberately and that you control and have reviewed the "
        "target directory. If you did not set it, unset it and inspect the directory it "
        "pointed at; whoever wrote that variable chose what code the agent runs.",
        evidence=evidence,
        confidence="HIGH",
    )


# ---------- B193 (B-290, ENV-4): gateway secret embedded in a systemd unit ----------
# OpenClaw's OWN service audit flags this: auditGatewayToken
# (service-audit-bKq3tdW1.js:185-192) raises `gatewayTokenEmbedded` — "Gateway service
# embeds OPENCLAW_GATEWAY_TOKEN and should be reinstalled." — with the remedy
# "Run `openclaw gateway install --force` to remove embedded service token."
#
# Two things make an inlined credential worse than the same credential in a dedicated
# environment file: a unit file is a configuration artifact people copy, diff, back up and
# paste into bug reports, and it is world-readable by default on most distributions (the
# real unit on a stock install is 0664). The dist draws exactly this distinction itself —
# readEmbeddedGatewayToken returns early when the value's source is EnvironmentFile-only
# (`isEnvironmentFileOnlySource`, service-audit-bKq3tdW1.js:247, systemd-B4Oq2owH.js:29-30)
# — which is why this check reads ctx.unit_env_inline and not ctx.unit_env_values.
#
# CALIBRATION. OpenClaw rates its own finding level "recommended", so a blanket FAIL would
# be harsher than the vendor's own audit and would fire on every host that merely followed
# an older install path. The status therefore keys on a CHECKABLE privilege rather than on
# taste: FAIL only when the unit file is genuinely readable by another local account
# (_file_readable_by_others, which — per B-127 — does not count a user-private group as an
# exposure), WARN otherwise. That mirrors B182's "token store readable by others" shape.
#
# The secret's VALUE is never read into a message, evidence entry or log; only the fact
# that the key is present inline, and the mode of the file holding it (§8).
_EMBEDDED_GATEWAY_SECRET_KEYS = ("OPENCLAW_GATEWAY_TOKEN", "OPENCLAW_GATEWAY_PASSWORD")


def check_unit_embedded_gateway_secret(ctx: Context) -> Finding:
    """B193 (B-290) — a gateway credential written inline into a systemd user unit.

    FAIL    — the credential is inlined AND the unit file is readable by other local
              accounts, so the gateway secret is exposed to every one of them.
    WARN    — the credential is inlined in a unit only its owner can read. Still worth
              removing: OpenClaw's own service audit asks for a reinstall, and an embedded
              token silently drifts out of step with gateway.auth.token.
    PASS    — an OpenClaw unit was read and inlines no gateway credential.
    UNKNOWN — no OpenClaw systemd user unit was readable (not Linux, no service installed,
              or the unit could not be opened).
    """
    if not ctx.unit_env_found:
        detail = (
            "No OpenClaw-related systemd user unit was readable, so unit-embedded gateway "
            "credentials could not be assessed."
        )
        if ctx.unit_env_unreadable:
            detail = (
                "A systemd user unit was present but could not be read, so unit-embedded "
                "gateway credentials could not be assessed."
            )
        return _finding(
            "B193",
            UNKNOWN,
            detail,
            "No action needed unless this host runs OpenClaw as a systemd user service.",
        )

    exposed: list[str] = []
    private: list[str] = []
    for key in _EMBEDDED_GATEWAY_SECRET_KEYS:
        unit = ctx.unit_env_inline.get(key)
        if not unit:
            continue
        unit_path = Path(unit)
        why = _file_readable_by_others(unit_path)
        if why:
            exposed.append(f"{key} is inlined in {unit_path.name}, which is {why}")
        else:
            private.append(f"{key} is inlined in {unit_path.name}")

    if not exposed and not private:
        return _finding(
            "B193",
            PASS,
            "The OpenClaw systemd user unit(s) read do not inline a gateway token or "
            "password; any credential they use comes from the config or a separate "
            "environment file.",
            "Keep gateway credentials out of the unit file — `openclaw gateway install` "
            "writes them where they belong.",
        )

    if exposed:
        return _finding(
            "B193",
            FAIL,
            "A gateway credential is written in plaintext into a systemd unit file that "
            "other local accounts can read: " + "; ".join(exposed) + ". Anyone who can "
            "read it can authenticate to the gateway as you.",
            "Rotate the gateway credential, then run `openclaw gateway install --force` to "
            "remove the embedded service token (OpenClaw's own service audit asks for "
            "exactly this). If the unit must keep the value, move it to an "
            "EnvironmentFile= that only your account can read (chmod 0600).",
            evidence=exposed,
            confidence="HIGH",
        )

    return _finding(
        "B193",
        WARN,
        "A gateway credential is written in plaintext into a systemd unit file: "
        + "; ".join(private)
        + ". Only your account can read the file today, so this is hygiene rather than "
        "an active exposure — but unit files get copied, diffed and pasted into bug "
        "reports, and an embedded token drifts out of step with gateway.auth.token.",
        "Run `openclaw gateway install --force` to remove the embedded service token "
        "(OpenClaw's own service audit recommends this), or move the value into an "
        "EnvironmentFile= readable only by your account.",
        evidence=private,
        confidence="HIGH",
    )


# ---------------------------------------------------------------------------------------
# F-134 (DISK-1, B191): OpenClaw's OWN runtime audit trail (``audit_events`` in the shared
# state SQLite database). ``collector._collect_audit_events`` reads it into
# ``ctx.audit_events`` (+ coverage counters) — see that collector's docstring for the full
# grounding and the GR#5 hard blocker this check is scoped around.
#
# OPT-IN, --behavioral ONLY (matching the T1/T2/T3 precedent in behavioral.py): this
# function is never added to CHECKS and never runs as part of a default audit()/A-F grade.
# It is invoked exclusively from ``behavioral.analyze()`` (see ``BEHAVIORAL_CHECK_IDS`` in
# behavioral.py), which also supplies ``divergent_sessions`` — see the parameter docstring
# below for why that argument lives there and not here.
# ---------------------------------------------------------------------------------------

def _fmt_epoch_ms(ms: int) -> str:
    """UTC calendar date for an epoch-millisecond ``occurred_at`` value (audit_events)."""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).date().isoformat()


def check_audit_trail_signals(
    ctx: Context,
    *,
    divergent_sessions: frozenset = frozenset(),
    trajectory_compared: bool = False,
) -> Finding:
    """B191 (F-134, DISK-1) — OpenClaw's OWN runtime audit trail: coverage, plus two
    narrow, near-zero-FP runtime signals nothing else in ClawSecCheck sees.

    THREE THINGS, ONE FINDING:

    1. COVERAGE / OBSERVABILITY — is ``audit_events`` present, readable, and how far back
       does it reach? This alone answers a question no other check does: whether
       OpenClaw's own durable, metadata-only tool-execution record exists, and how much
       history it holds (bounded by its own documented 30-day / 100,000-row retention,
       pruned on every insert — see the collector's docstring).
    2. DIVERGENCE — the ``--behavioral`` corroboration source. ``divergent_sessions`` /
       ``trajectory_compared`` are supplied by ``behavioral.analyze()``, which already
       reads the trajectory sidecar for T1/T2/T3 and can therefore compare, at zero extra
       file I/O, the session ids ``audit_events`` has seen against the ones the
       trajectory source actually recorded (both expose a plain ``session_id`` — see
       ``behavioral._audit_event_sessions``/``audit_trail_divergence`` for why that field,
       and not ``session_key``, is the join key). A non-empty result means
       ``audit_events`` retains a session the trajectory source does not — the trajectory
       sidecar may be disabled (``OPENCLAW_TRAJECTORY=0``), relocated, or have rotated
       that session out past its own 60-file cap, while this INDEPENDENT, differently
       -bounded store still has it. This function never reads the trajectory sidecar
       itself; it only reports what its caller already computed.
    3. TWO NARROW SIGNALS:
       - ``status=='blocked'`` and ``error_code=='tool_blocked'`` — the policy engine
         actually DENIED a tool at runtime (``projectToolExecutionEventToAudit``,
         server-runtime-subscriptions-OlWMLbPY.js:~299-327). No other check or mode sees
         this anywhere — it is a runtime enforcement event, not a config posture.
       - ``tool_name=='unknown'`` — the literal sentinel OpenClaw's own ``auditToolName``
         writes when a tool-call name fails its OWN syntax check
         (``isAllowedToolCallName``, tool-call-shared-BoRDqDVC.js:23-29: not a string,
         over 64 chars, or outside ``^[A-Za-z0-9_:.-]+$``) — i.e. a tool call reached
         execution with a name so malformed OpenClaw's own audit layer could not record
         it. A well-formed ``mcp__server__tool`` name is stored verbatim (with a null
         allowlist that function is a pure syntax check, not a lookup); only a genuinely
         evasive/malformed name collapses to this sentinel. Zero such rows on the real
         box this was grounded against.

    HARD GR#5 BLOCKER (see the collector's docstring in full): ``audit_events`` stores
    ``tool_name`` alone — no argv, no command, no path, no host. This function therefore
    NEVER builds a volumetric or tool-name-presence rule; the two signals above are the
    only ``tool_name``-adjacent conditions it evaluates, and both are near-zero-FP by
    construction (a benign config never legitimately has a blocked tool call or a
    malformed tool name reach execution).

    WARN    — any of: a blocked-tool row, an evasive/malformed tool name, or a
              caller-supplied session divergence. Always advisory (``scored=False``) —
              each of the three has a legitimate benign story this check cannot rule out
              (a deliberately tightened policy; a third-party MCP tool name that still
              slipped past an older OpenClaw's syntax gate; trajectory tracing turned off
              on purpose).
    PASS    — ``audit_events`` present, readable, non-empty, and none of the three
              signals fired in the sampled window. ``pass_confidence`` is ``"verified"``
              when the sample covered the whole table, or ``"no_signal"`` when
              ``ctx.audit_events_truncated`` is True (see C-135 round-2 note below) — the
              same ``"verified"``/``"no_signal"`` split B168 already uses
              (``checks/_lifecycle.py``).
    UNKNOWN — no state DB, no ``audit_events`` table, the table present but unreadable, or
              present but currently empty (pruning can empty it, so "no rows" is not
              evidence nothing ran — same reasoning as B189's ``cron_run_logs``).

    C-135 ROUND-2 FIX (F-134/B191, DISK-1) — ABSENCE-IMPLIES-CLEAN ASYMMETRY. The row
    SAMPLE (``ctx.audit_events``) is capped at ``_MAX_AUDIT_EVENTS``, most-recent-first
    (see the collector's docstring). When ``ctx.audit_events_truncated`` is True, a
    genuine blocked-tool-call or evasive-name row older than the cap is invisible to the
    ``hits`` scan below — it was evicted before this function ever saw it — yet the PASS
    used to carry undiminished ``confidence="HIGH"`` regardless of how much of the table
    was actually sampled. Reproduced: one genuine ``blocked``/``tool_blocked`` row followed
    by 1200 ordinary rows -> PASS/HIGH/no caveat, the blocked row silently evicted from the
    window. Fixed the same way B168 handles ``cron_store_shadowed``
    (``checks/_lifecycle.py``): only the "nothing found" verdict degrades
    (``pass_confidence="no_signal"``) when the scanned set is known-incomplete — a hit that
    DID fire within the sampled window (the ``hits`` branch above) is unaffected by
    truncation and keeps its full-confidence WARN, since that finding is real regardless of
    what else may sit outside the window. This does not close DISK-1's "prove nothing
    outside the cap happened" gap — it correctly reports that the gap exists rather than
    reporting a clean bill of health the sample never actually earned.
    """
    if not ctx.audit_events_found:
        return _finding(
            "B191",
            UNKNOWN,
            "No audit_events table found (the state SQLite database, or its audit_events "
            "table, is absent) — OpenClaw's own runtime audit trail could not be read.",
            "No action needed if this OpenClaw install predates the audit_events table. "
            "Keep ~/.openclaw/state/openclaw.sqlite owner-readable so a future audit can "
            "read this trail.",
        )
    if ctx.audit_events_parse_error:
        return _finding(
            "B191",
            UNKNOWN,
            "The audit_events table was found but could not be read.",
            "Ensure ~/.openclaw/state/openclaw.sqlite is owner-readable and not locked by "
            "a running agent, then re-run the audit.",
        )
    if ctx.audit_events_total_rows == 0:
        return _finding(
            "B191",
            UNKNOWN,
            "The audit_events table is present but currently empty. This table is pruned "
            "on every insert (a documented 30-day / 100,000-row retention), so an empty "
            "table is not evidence that no tool ever ran — it may simply have nothing "
            "left in the retention window.",
            "No action needed. Re-run once the agent has been active, if a runtime audit "
            "signal is wanted.",
        )

    blocked = [
        r for r in ctx.audit_events
        if r.get("status") == "blocked" and r.get("error_code") == "tool_blocked"
    ]
    evasive = [r for r in ctx.audit_events if r.get("tool_name") == "unknown"]

    hits: list[str] = []
    evidence: list[str] = []
    if blocked:
        hits.append(
            f"{len(blocked)} tool call(s) were BLOCKED by the policy engine at runtime "
            "(status='blocked', error_code='tool_blocked')"
        )
        evidence += [
            f"blocked: {r.get('action') or 'tool.action'} run_id={r.get('run_id')}"
            + (f" session_id={r.get('session_id')}" if r.get("session_id") else "")
            for r in blocked[:6]
        ]
    if evasive:
        hits.append(
            f"{len(evasive)} tool call(s) reached execution with a tool name OpenClaw's "
            "own audit layer could not record (tool_name='unknown' — malformed or "
            "over-length)"
        )
        evidence += [
            f"evasive name: run_id={r.get('run_id')}"
            + (f" session_id={r.get('session_id')}" if r.get("session_id") else "")
            for r in evasive[:6]
        ]
    if trajectory_compared and divergent_sessions:
        hits.append(
            f"{len(divergent_sessions)} session id(s) recorded in audit_events have no "
            "matching trajectory sidecar record"
        )
        evidence += [f"divergent session_id: {s}" for s in sorted(divergent_sessions)[:6]]

    if hits:
        return _finding(
            "B191",
            WARN,
            "OpenClaw's own runtime audit trail (audit_events) shows: " + "; ".join(hits)
            + ". Each of these has a legitimate benign explanation (a tightened policy, "
            "an unusual but real tool name, trajectory tracing turned off on purpose), so "
            "this is advisory, not proof of compromise.",
            "Review the named run_id(s)/session_id(s) directly in "
            "~/.openclaw/state/openclaw.sqlite (audit_events table) and, for a session "
            "divergence, confirm whether OPENCLAW_TRAJECTORY was intentionally disabled "
            "or the trajectory sidecar has simply rotated past its 60-file cap.",
            evidence=evidence,
        )

    span = ""
    if ctx.audit_events_oldest_ms is not None and ctx.audit_events_newest_ms is not None:
        span = (
            f", spanning {_fmt_epoch_ms(ctx.audit_events_oldest_ms)} to "
            f"{_fmt_epoch_ms(ctx.audit_events_newest_ms)}"
        )
    clean_signals = ["no blocked tool call", "no evasive tool name"]
    if trajectory_compared:
        clean_signals.append("no session divergence from the trajectory sidecar")
    # C-135 round 2 (F-134/B191): "none of the three signals fired" is a claim about the
    # SAMPLED window, and ctx.audit_events_truncated means that window is not the whole
    # table (see the docstring above). Only the ABSENCE-implies-clean verdict weakens here
    # — a hit found INSIDE the window (the `hits` branch above) already returned and is
    # untouched by this.
    if ctx.audit_events_truncated:
        caveat = (
            f" The signal-detection sample was capped at the {len(ctx.audit_events)} most "
            f"recent of {ctx.audit_events_total_rows} total row(s) — a genuine blocked-"
            "tool-call or evasive tool name older than that cap would NOT have been seen "
            "by this scan."
        )
        pass_confidence = "no_signal"
    else:
        caveat = ""
        pass_confidence = "verified"
    return _finding(
        "B191",
        PASS,
        f"OpenClaw's runtime audit trail (audit_events) is present and readable: "
        f"{ctx.audit_events_total_rows} row(s){span}. "
        + ", ".join(clean_signals) + " observed in the sampled window." + caveat,
        "No action needed. This table is pruned by OpenClaw itself (30 days / 100,000 "
        "rows), so its coverage will always be partial on a long-lived install.",
        pass_confidence=pass_confidence,
    )
