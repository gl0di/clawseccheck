"""Read-only detection of host defensive monitors (the "is anyone watching?" layer).

ClawSecCheck normally audits the *agent's* configuration. This module widens the
lens by one ring: it asks whether the **host** the agent runs on has any defensive
monitoring — a network IDS, host audit logging, file-integrity monitoring, an
endpoint/EDR sensor, or a host firewall. A powerful agent on an unwatched host is
a real exposure: if it were compromised, the activity could go completely unseen.

Doctrine (matches the rest of ClawSecCheck):
- **No subprocess, no network.** We inspect only the filesystem: well-known config
  paths, binary names on PATH (``shutil.which`` reads PATH, it does NOT execute),
  systemd enable-symlinks, and read-only config/plist files.
- **No fabricated positives.** Every signal here is grounded against authoritative
  upstream docs for each monitor. Low-confidence signals are
  deliberately omitted — an honest ``unknown`` beats a wrong ``present``/``absent``.
- **Injectable for tests.** ``detect(root=..., system=..., which=...)`` lets tests
  point at a fake filesystem root and a fake PATH resolver, so the suite stays
  offline, deterministic, and writes nothing outside ``tmp_path``.

Result shape (per class)::

    {"status": "present" | "absent" | "unknown",
     "found":  ["Suricata", ...],     # human-readable monitor names
     "active": True | False | None,   # enabled? None = installed, can't confirm
     "evidence": [...]}               # short, single-line, no secrets/PII
"""
from __future__ import annotations

import platform
import shutil
import struct
from pathlib import Path

# detection-class keys (stable; consumed by checks B50–B54 and risk RISK-10)
NETWORK_IDS = "network_ids"
HOST_AUDIT = "host_audit"
FILE_INTEGRITY = "file_integrity"
EDR_AV = "edr_av"
FIREWALL = "firewall"

CLASSES = (NETWORK_IDS, HOST_AUDIT, FILE_INTEGRITY, EDR_AV, FIREWALL)

# The four *detection/visibility* classes (a firewall is prevention, not detection).
# RISK-10 ("a breach would be invisible") keys off these only.
VISIBILITY_CLASSES = (NETWORK_IDS, HOST_AUDIT, FILE_INTEGRITY, EDR_AV)


# ──────────────────────────────────────────────────────────────────────────────
# Low-level read-only filesystem helpers (all root-relative, all best-effort)
# ──────────────────────────────────────────────────────────────────────────────

def _exists(root: Path, *rels: str) -> bool:
    """True if any of the given root-relative paths exists (never raises)."""
    for rel in rels:
        try:
            if (root / rel).exists():
                return True
        except OSError:
            continue
    return False


def _systemd_enabled(root: Path, unit: str) -> bool:
    """Read-only 'is this unit enabled-at-boot?' — a symlink under any *.wants/ dir.

    `systemctl enable <unit>` creates a symlink at
    /etc/systemd/system/<target>.wants/<unit> -> the unit file. Detecting that
    symlink needs no command. (Enabled != currently running, and a unit can run
    without being enabled, so absence is not proof of disabled.)
    """
    base = root / "etc/systemd/system"
    try:
        for wants in base.glob("*.wants"):
            if (wants / unit).exists():
                return True
    except OSError:
        pass
    return False


def _read_text(path: Path) -> str | None:
    """Read a small text config file, or None if unreadable (never raises)."""
    try:
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _ufw_enabled(root: Path) -> bool | None:
    """ufw on-boot state from /etc/ufw/ufw.conf: ENABLED=yes -> True, no -> False."""
    txt = _read_text(root / "etc/ufw/ufw.conf")
    if txt is None:
        return None
    for line in txt.splitlines():
        s = line.strip().replace(" ", "").lower()
        if s.startswith("enabled="):
            return s.endswith("=yes") or s.endswith('="yes"')
    return None


def _cls(found: list[str], active: bool | None = None) -> dict:
    """Build a class result from a found-list (present if non-empty, else absent)."""
    return {
        "status": "present" if found else "absent",
        "found": found,
        "active": active if found else None,
        "evidence": list(found),
    }


def _unknown_cls() -> dict:
    return {"status": "unknown", "found": [], "active": None, "evidence": []}


def _unsupported(system: str) -> dict:
    return {
        "system": system,
        "supported": False,
        "classes": {c: _unknown_cls() for c in CLASSES},
    }


# ──────────────────────────────────────────────────────────────────────────────
# Linux
# ──────────────────────────────────────────────────────────────────────────────

def _detect_linux(root: Path, which) -> dict:
    classes: dict[str, dict] = {}

    # Network IDS / monitor ----------------------------------------------------
    found, active = [], None
    if which("suricata") or _exists(root, "etc/suricata/suricata.yaml"):
        found.append("Suricata")
        if _systemd_enabled(root, "suricata.service"):
            active = True
    if (which("zeek") or which("zeekctl")
            or _exists(root, "opt/zeek/bin/zeek", "usr/local/zeek/bin/zeek")):
        found.append("Zeek")
    if which("snort") or _exists(root, "etc/snort/snort.lua", "usr/local/etc/snort/snort.lua"):
        found.append("Snort")
    classes[NETWORK_IDS] = _cls(found, active)

    # Host audit / syscall logging --------------------------------------------
    found, active = [], None
    if which("auditctl") or _exists(root, "etc/audit/auditd.conf", "etc/audit/audit.rules"):
        found.append("auditd")
        if _systemd_enabled(root, "auditd.service"):
            active = True
    classes[HOST_AUDIT] = _cls(found, active)

    # File-integrity monitoring ------------------------------------------------
    found, active = [], None
    if which("aide") or _exists(root, "etc/aide/aide.conf", "etc/aide.conf"):
        found.append("AIDE")
        if _exists(root, "var/lib/aide/aide.db", "var/lib/aide/aide.db.gz"):
            active = True  # baseline DB initialised
    if which("tripwire") or _exists(root, "etc/tripwire/tw.cfg", "etc/tripwire/twcfg.txt"):
        found.append("Tripwire")
    if which("osqueryd") or _exists(root, "etc/osquery/osquery.conf"):
        found.append("osquery")
    classes[FILE_INTEGRITY] = _cls(found, active)

    # EDR / endpoint protection / AV ------------------------------------------
    found = []
    if _exists(root, "var/ossec/bin/wazuh-control"):
        found.append("Wazuh")
    elif _exists(root, "var/ossec/bin/ossec-control", "var/ossec/etc/ossec.conf"):
        found.append("OSSEC")
    if which("falconctl") or _exists(root, "opt/CrowdStrike/falconctl"):
        found.append("CrowdStrike Falcon")
    if _exists(root, "opt/sentinelone/bin/sentinelctl"):
        found.append("SentinelOne")
    if which("mdatp") or _exists(root, "opt/microsoft/mdatp"):
        found.append("Microsoft Defender")
    if which("clamscan") or which("clamd") or _exists(root, "etc/clamav/clamd.conf"):
        found.append("ClamAV")
    classes[EDR_AV] = _cls(found)

    # Host firewall ------------------------------------------------------------
    found, active = [], None
    if which("ufw") or _exists(root, "etc/ufw/ufw.conf"):
        found.append("ufw")
        state = _ufw_enabled(root)
        if state is True:
            active = True
        elif state is False and active is None:
            active = False
    if which("firewall-cmd") or _exists(root, "etc/firewalld/firewalld.conf"):
        found.append("firewalld")
        if _systemd_enabled(root, "firewalld.service"):
            active = True
    if _exists(root, "etc/nftables.conf"):
        # the .conf can exist unused; the enable-symlink is the real "active" signal
        found.append("nftables")
        if _systemd_enabled(root, "nftables.service"):
            active = True
    classes[FIREWALL] = _cls(found, active)

    return {"system": "Linux", "supported": True, "classes": classes}


# ──────────────────────────────────────────────────────────────────────────────
# macOS
# ──────────────────────────────────────────────────────────────────────────────

def _alf_globalstate(root: Path) -> int | None:
    """macOS Application Firewall global state from com.apple.alf.plist.

    0=off, 1=on, 2=block-all. Returns None when the plist is absent (which is the
    case on macOS Sequoia 15+, where ALF state moved behind `socketfilterfw`) so
    the caller reports UNKNOWN rather than guessing.
    """
    p = root / "Library/Preferences/com.apple.alf.plist"
    if not p.is_file():
        return None
    try:
        import plistlib
        with p.open("rb") as fh:
            data = plistlib.load(fh)
    except (OSError, ValueError, struct.error):  # unreadable/corrupt plist — never crash
        return None
    gs = data.get("globalstate") if isinstance(data, dict) else None
    return gs if isinstance(gs, int) else None


def _detect_macos(root: Path, which) -> dict:
    classes: dict[str, dict] = {}

    # Network monitors (outbound-firewall class on mac) ------------------------
    found = []
    if _exists(root, "Applications/Little Snitch.app"):
        found.append("Little Snitch")
    if _exists(root, "Applications/LuLu.app"):
        found.append("LuLu")
    classes[NETWORK_IDS] = _cls(found)

    # Host audit — OpenBSM cannot be assessed honestly from the filesystem:
    # /etc/security/audit_control ships by default on macOS <=13 (present != enabled),
    # and OpenBSM is disabled-by-default and deprecated on >=14. So we report UNKNOWN
    # rather than a false PASS/active.
    classes[HOST_AUDIT] = _unknown_cls()

    # File-integrity — osquery (homebrew or system paths) ----------------------
    found = []
    if (which("osqueryd") or _exists(root, "etc/osquery/osquery.conf",
                                     "usr/local/etc/osquery/osquery.conf",
                                     "opt/homebrew/etc/osquery/osquery.conf")):
        found.append("osquery")
    classes[FILE_INTEGRITY] = _cls(found)

    # EDR / endpoint protection ------------------------------------------------
    found = []
    if _exists(root, "Applications/Falcon.app"):
        found.append("CrowdStrike Falcon")
    if _exists(root, "Applications/Microsoft Defender.app",
               "Applications/Microsoft Defender ATP.app"):
        found.append("Microsoft Defender")
    if _exists(root, "Applications/Santa.app", "var/db/santa"):
        found.append("Santa")
    if _exists(root, "Applications/SentinelOne Extensions.app",
               "Library/Sentinel"):
        found.append("SentinelOne")
    classes[EDR_AV] = _cls(found)

    # Host firewall — ALF global state ----------------------------------------
    gs = _alf_globalstate(root)
    if gs is None:
        classes[FIREWALL] = _unknown_cls()
    else:
        classes[FIREWALL] = _cls(["macOS Application Firewall"], active=gs >= 1)

    return {"system": "Darwin", "supported": True, "classes": classes}


# ──────────────────────────────────────────────────────────────────────────────
# Windows (best-effort: filesystem under root + optional read-only registry)
# ──────────────────────────────────────────────────────────────────────────────

def _win_service_exists(name: str) -> bool | None:
    """True if a Windows service registry key exists. None when winreg is absent
    (i.e. not running on Windows) so the caller can fall back / report UNKNOWN."""
    try:
        import winreg
    except ImportError:
        return None
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             rf"SYSTEM\CurrentControlSet\Services\{name}")
        winreg.CloseKey(key)
        return True
    except OSError:
        return False


def _win_firewall_enabled() -> bool | None:
    """Read EnableFirewall (any profile) from the registry. None if undeterminable."""
    try:
        import winreg
    except ImportError:
        return None
    base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    any_on = False
    seen = False
    for profile in ("DomainProfile", "StandardProfile", "PublicProfile"):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"{base}\{profile}")
            val, _ = winreg.QueryValueEx(key, "EnableFirewall")
            winreg.CloseKey(key)
            seen = True
            if int(val) == 1:
                any_on = True
        except OSError:
            continue
    return any_on if seen else None


def _detect_windows(root: Path, which) -> dict:
    classes: dict[str, dict] = {}

    # Network/host monitoring — Sysmon (filesystem + service key) --------------
    found = []
    sysmon = (_exists(root, "Windows/Sysmon64.exe", "Windows/Sysmon.exe")
              or _win_service_exists("Sysmon64") is True
              or _win_service_exists("Sysmon") is True
              or _win_service_exists("SysmonDrv") is True)
    if sysmon:
        found.append("Sysmon")
    classes[NETWORK_IDS] = _cls(found)
    # Sysmon doubles as the host syscall/event auditor on Windows
    classes[HOST_AUDIT] = _cls(list(found))

    # File-integrity — osquery -------------------------------------------------
    found = []
    if (which("osqueryd")
            or _exists(root, "Program Files/osquery/osqueryd/osqueryd.exe",
                       "ProgramData/osquery/osquery.conf")):
        found.append("osquery")
    classes[FILE_INTEGRITY] = _cls(found)

    # EDR / AV -----------------------------------------------------------------
    found = []
    if _exists(root, "Program Files/CrowdStrike") or _win_service_exists("CSFalconService") is True:
        found.append("CrowdStrike Falcon")
    if _exists(root, "Program Files/SentinelOne") or _win_service_exists("SentinelAgent") is True:
        found.append("SentinelOne")
    if _win_service_exists("WinDefend") is True or _exists(root, "ProgramData/Microsoft/Windows Defender"):
        found.append("Microsoft Defender")
    classes[EDR_AV] = _cls(found)

    # Host firewall — registry EnableFirewall ----------------------------------
    fw = _win_firewall_enabled()
    if fw is None:
        classes[FIREWALL] = _unknown_cls()
    else:
        classes[FIREWALL] = _cls(["Windows Firewall"], active=fw)

    return {"system": "Windows", "supported": True, "classes": classes}


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def detect(root: str | Path = "/", system: str | None = None, which=None) -> dict:
    """Detect host defensive monitors, read-only.

    Args:
        root: filesystem root to inspect (tests pass a fake tmp root).
        system: platform override ("Linux" | "Darwin" | "Windows"); defaults to
            ``platform.system()``.
        which: PATH resolver override (defaults to ``shutil.which``); tests pass a
            fake mapping name -> path-or-None.

    Returns a dict ``{"system", "supported", "classes": {<class>: {...}}}``. For an
    unsupported platform ``supported`` is False and every class is ``unknown``.
    """
    system = system or platform.system()
    rootp = Path(root)
    resolver = which if which is not None else shutil.which
    if system == "Linux":
        return _detect_linux(rootp, resolver)
    if system == "Darwin":
        return _detect_macos(rootp, resolver)
    if system == "Windows":
        return _detect_windows(rootp, resolver)
    return _unsupported(system)
