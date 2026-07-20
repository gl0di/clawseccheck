"""Topic module: host checks (I-022 R2).

Carved verbatim out of the former single-file checks.py; no logic changes.
Depends only on layer-1 modules, stdlib, and the checks/_shared leaf.
"""
from __future__ import annotations
import re
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
# 2. There is NO affirmative PASS. A variable exported into an interactive shell just
#    before launching the agent leaves no artifact on disk, so "we found no override in the
#    files we can read" is not "no override is set". That state is UNKNOWN. Reading the
#    auditor's own os.environ instead would be worse than silence: the gateway runs under
#    systemd with its OWN environment, so this process's environment describes a different
#    process, and a PASS built on it would be a lying PASS.
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
    UNKNOWN — no override found in any persistent artifact. Deliberately never PASS: the
              ambient-shell delivery path leaves nothing to read (see the note above).
    """
    overrides = bundled_root_overrides(ctx)
    if not overrides:
        if env_evidence_readable(ctx):
            where = "the systemd user unit(s) and global dotenv file(s) that were readable"
        else:
            where = (
                "no systemd user unit or global dotenv file was present to read"
            )
        return _finding(
            "B186",
            UNKNOWN,
            "No OPENCLAW_BUNDLED_SKILLS_DIR / OPENCLAW_BUNDLED_HOOKS_DIR relocation was "
            f"found ({where}). This is reported as UNKNOWN rather than PASS on purpose: "
            "either variable can also be exported into the shell that launches the agent, "
            "which leaves no artifact on disk for a local audit to read.",
            "If you never set these variables, nothing is needed. If the agent is launched "
            "from a wrapper script or shell profile, check there too — OpenClaw honours "
            "both unconditionally and will load skills/hooks from wherever they point.",
        )

    evidence: list[str] = []
    replaceable: list[str] = []
    for var, kind, value, source in overrides:
        try:
            resolved = Path(value).expanduser()
        except (OSError, ValueError, RuntimeError):
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
