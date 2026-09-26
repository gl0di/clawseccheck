"""Optionally run OpenClaw's own `openclaw security audit` and fold its findings in.

This is the ONLY external command ClawSecCheck ever runs: a single, fixed,
read-only invocation of the user's own `openclaw` CLI —

    openclaw security audit --json

No shell (argument list, not a string), never `--fix`, with a timeout. If the
`openclaw` binary is not on PATH or the call fails, we degrade gracefully and
say so. Native findings are shown to the user but are NOT folded into the
ClawSecCheck score (kept deterministic / no double-counting).
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass, field

from .catalog import CRITICAL, FAIL, HIGH, LOW, MEDIUM, Finding


def _untrusted_exec_reason(exe: str) -> "tuple[bool, str] | None":
    """Return ``(must_skip, reason)`` if *exe* (or its directory) could not be trusted
    enough to exec, or ``None`` if it was CHECKED and found clean — i.e. writable by
    group/other on POSIX, which means a local user could have swapped the binary we are
    about to run.

    The audit flags group/world-writable install dirs in others, so it must not blindly
    exec from such a path itself (B-014). Two DIFFERENT reasons a caller might see no
    green light here (B-774 — both used to collapse into plain `None`, reading exactly
    like a verified-clean path):

    * ``must_skip=True`` — POSIX and the mode bits prove it writable (never exec), OR the
      stat itself raised ``OSError`` — an unreadable path is not a trusted one, so this
      fails CLOSED the same as a confirmed-unsafe verdict (Option 1: "cheap, strictly
      safer, and cannot affect a healthy machine — a stat of a binary `shutil.which` just
      resolved does not normally fail").
    * ``must_skip=False`` — non-POSIX, where ``os.stat().st_mode``'s group/other bits
      carry no meaning at all (Windows uses NTFS ACLs — the same "can't read those
      read-only" limitation `checks/_host.py`'s B85 already discloses rather than
      silently reading as clean). The check genuinely does not apply here, not merely
      "failed to run" — so the caller may still exec, but must disclose that this trust
      check specifically could not be made, never render it as an absence of concern.
    """
    if os.name != "posix":
        return (False, "this platform's file permissions can't be read as POSIX mode bits")
    try:
        real = os.path.realpath(exe)
        for target in (real, os.path.dirname(real)):
            mode = os.stat(target).st_mode
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                return (True, "group/world-writable install path")
    except OSError as exc:
        return (True, f"could not check install-path permissions ({exc})")
    return None

_SEV_MAP = {
    "critical": CRITICAL, "crit": CRITICAL, "fatal": CRITICAL,
    "high": HIGH, "error": HIGH, "severe": HIGH,
    "medium": MEDIUM, "moderate": MEDIUM, "warning": MEDIUM, "warn": MEDIUM,
    "low": LOW, "info": LOW, "informational": LOW, "notice": LOW, "minor": LOW,
}


@dataclass
class NativeResult:
    status: str                       # ok | not_found | error | timeout | skipped
    findings: list = field(default_factory=list)
    note: str = ""


def _norm_sev(v) -> str:
    return _SEV_MAP.get(str(v).strip().lower(), MEDIUM)


def _extract(obj) -> list[dict]:
    """Pull a list of finding-like dicts from an unknown JSON shape."""
    if isinstance(obj, list):
        return [x for x in obj if isinstance(x, dict)]
    if isinstance(obj, dict):
        for key in ("findings", "issues", "results", "checks", "problems", "items", "audit"):
            v = obj.get(key)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
        # nested {"security": {"findings": [...]}}
        for v in obj.values():
            inner = _extract(v)
            if inner:
                return inner
    return []


def _pick(d: dict, *keys, default=""):
    for k in keys:
        if d.get(k):
            return d[k]
    return default


def _to_finding(d: dict) -> Finding:
    sev = _norm_sev(_pick(d, "severity", "level", "risk", "impact", "priority", default="medium"))
    title = _pick(d, "title", "name", "check", "rule", "id", default="OpenClaw audit finding")
    detail = _pick(d, "message", "description", "detail", "why", "summary")
    fix = _pick(d, "remediation", "fix", "recommendation", "suggestion", "advice",
                default="See the OpenClaw security docs for remediation.")
    fid = str(_pick(d, "id", "checkId", "check", "rule", default="native"))[:24]
    return Finding(f"N:{fid}", str(title), sev, FAIL, str(detail), str(fix),
                   "OpenClaw built-in audit", scored=False)


def _parse(out: str):
    out = out.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # some CLIs emit log lines before the JSON body — try the last {...}/[...]
        for opener, closer in (("{", "}"), ("[", "]")):
            i, j = out.find(opener), out.rfind(closer)
            if 0 <= i < j:
                try:
                    return json.loads(out[i:j + 1])
                except json.JSONDecodeError:
                    continue
    return None


def run_native_audit(openclaw_bin: str = "openclaw", timeout: int = 60,
                     enabled: bool = True) -> NativeResult:
    if not enabled:
        return NativeResult("skipped", note="built-in audit skipped (--no-native)")
    exe = shutil.which(openclaw_bin)
    if not exe:
        return NativeResult("not_found", note=(
            "openclaw CLI not on PATH — run this inside OpenClaw to also include "
            "its built-in `openclaw security audit`."))
    trust = _untrusted_exec_reason(exe)
    trust_caveat = ""
    if trust is not None:
        must_skip, reason = trust
        if must_skip:
            return NativeResult("skipped", note=(
                f"openclaw at {os.path.realpath(exe)} not run: {reason}. "
                "Restore owner-only perms on the binary/dir, or run from a trusted PATH, "
                "to include the built-in audit."))
        # B-774: the install-path trust check does not apply on this platform (see
        # _untrusted_exec_reason) — proceed, but carry an honest disclosure into
        # whatever this call returns below, so "unverifiable" never reads the same
        # as "checked, clean" the way a bare `None` note used to.
        trust_caveat = f" (install-path trust check not performed: {reason})"
    try:
        proc = subprocess.run(
            [exe, "security", "audit", "--json"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return NativeResult("timeout",
                            note=f"openclaw security audit timed out after {timeout}s{trust_caveat}")
    except OSError as exc:
        return NativeResult("error", note=f"could not run openclaw: {exc}{trust_caveat}")

    data = _parse(proc.stdout)
    if data is None:
        if proc.returncode != 0:
            note = f"openclaw security audit exited {proc.returncode}"
            if proc.stderr:
                note += f": {proc.stderr.strip()[:300]}"
            return NativeResult("error", note=note + trust_caveat)
        return NativeResult("error", note="could not parse openclaw security audit JSON output"
                            + trust_caveat)
    findings = [_to_finding(d) for d in _extract(data)]
    note = f"{len(findings)} finding(s) from openclaw security audit"
    if proc.returncode != 0:
        note += f" (openclaw exited {proc.returncode})"
    note += trust_caveat
    return NativeResult("ok", findings=findings, note=note)
