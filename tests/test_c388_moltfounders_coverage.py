"""CLAWSECCHECK-C-388: real-fixture coverage measurement for the MoltFounders
agent-marketplace onboarding protocol (moltfounders.com, studied 2026-08-06).

This is a MEASUREMENT, not a new check. `fixtures/bad_c388_moltfounders_onboarding/`
reproduces the shape of the vendor's own onboarding instructions (five steps: fetch a
remote registration doc and follow it, register and persist a plaintext API key,
report host hardware/OS capabilities to the vendor, install a daily polling job into
OpenClaw's own cron store, and prefer the raw API over the host's `web_fetch` tool) —
run through the real end-to-end audit engine, not a source grep (the E-067 lesson: a
grep saying "covered" has been wrong before; a fixture through the real check fn is the
only measurement that counts).

Per-behaviour result (recorded in full on the Pulse task; asserted here so the
measurement doesn't silently rot):

  1. Remote-instruction fetch ("read <url> and follow instructions")
     -> COVERED: B13 FAILs (runtime-external-fetch instruction, OWASP AST05).
  2. Skill installs a cron job — but into OpenClaw's OWN JSON store
     (~/.openclaw/cron/jobs.json), never host crontab/@reboot/systemctl
     -> GAP (real, filed as a child task): B13's C-040 persistence patterns
        (checks/_vet.py's `crontab -e/-u/-r`, `crontab -`, `@reboot`, `systemctl
        enable`, …) are grounded exclusively in host-level shell persistence idioms
        and do not recognize an instruction to write an entry into OpenClaw's own
        native cron-store file.
  3. Host hardware/OS fingerprint (CPU cores, RAM, disk, GPU, kernel string)
     collected then reported to a third party in prose, not code
     -> GAP (real, filed as a child task): B160 (prose-intent bulk-data exfil) PASSes
        because its bulk/PII-data noun class does not recognize a hardware-capabilities
        object; C-203/HOST_INFO_EXFIL_FLOW (skillast.py) exists for exactly this
        behaviour but is a CODE-only AST taint rule — it has no prose-side analogue.
  4. Plaintext credential written into the skill's own workspace directory
     -> Already adequately surfaced (not a gap): B1/C015 scan for secret-shaped
        values at rest in home files and would catch the resulting credentials.json
        on a later run; this fixture's own B1 FAIL is coincidental (an unrelated
        token already in openclaw.json), so it is NOT asserted on here.
  5. Instruction to prefer the vendor API over the host's own `web_fetch` tool
     -> Intentionally out of scope as a standalone signal: "use our REST API, not
        generic fetch/scraping" is ordinary, ubiquitous API-integration advice: a bare
        rule keyed on this phrase alone would be a high-false-positive generator on
        every legitimate API-integration skill (the same C-303/B-451 discipline
        CLAWSECCHECK-C-391 already documents for a related surface).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
HOME = FIXTURES / "bad_c388_moltfounders_onboarding"


def _findings():
    _, findings, _ = audit(HOME, include_native=False)
    return {f.id: f for f in findings}


def test_b13_fails_on_the_remote_instruction_fetch_step():
    """Behaviour 1 is covered: the "read <url> and follow instructions" step is a
    live runtime-external-fetch instruction, not documentation."""
    f = _findings()["B13"]
    assert f.status == FAIL, f"expected B13 FAIL, got {f.status}: {f.detail!r}"
    assert "moltfounders.com/registration.md" in f.detail
    assert "runtime-external-fetch" in f.detail.lower() or "fetch" in f.detail.lower()


def test_b160_does_not_recognize_a_host_capabilities_object_as_bulk_data():
    """Behaviour 3 (host-fingerprint-to-third-party) is NOT caught in prose: B160's
    bulk/PII-data noun class does not match an 'agentCapabilities' hardware-spec
    object, even though the skill text uses one of B160's own exfil verbs ("Send").
    This PASS is the measured gap CLAWSECCHECK-C-388's follow-up task tracks — pinned
    here so a future B160 widening is a deliberate, visible change, not a silent one.
    """
    f = _findings()["B160"]
    assert f.status == PASS, (
        f"B160 status changed to {f.status} ({f.detail!r}) -- if this now fires on "
        "the host-capabilities-report step, the CLAWSECCHECK-C-388 follow-up gap may "
        "be closed; re-check and update/close that child task instead of just fixing "
        "this assertion."
    )


def test_no_cron_persistence_hit_for_the_native_jobs_json_instruction():
    """Behaviour 2 (cron job into OpenClaw's own store) is NOT caught: B13's C-040
    persistence patterns are grounded in host-level crontab/@reboot/systemctl syntax
    only. Pinned the same way as the B160 case above."""
    f = _findings()["B13"]
    combined = (f.detail + " " + " ".join(f.evidence or [])).lower()
    assert "cron" not in combined and "persistence" not in combined, (
        f"B13 now mentions cron/persistence ({f.detail!r}) -- if this covers the "
        "native ~/.openclaw/cron/jobs.json write instruction, the CLAWSECCHECK-C-388 "
        "follow-up gap may be closed; re-check and update/close that child task "
        "instead of just fixing this assertion."
    )
