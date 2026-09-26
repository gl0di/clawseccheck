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
     -> NOUN CLASS FIXED (CLAWSECCHECK-C-538): B160 (prose-intent bulk-data exfil)
        correctly still PASSes here — the object is not bulk/PII/credential-shaped,
        so folding it into B160 would have been wrong. A new prose-side sibling,
        B388, now recognizes the hardware/OS-fingerprint noun class in general (see
        tests/test_c538_host_fingerprint_exfil.py) and is the prose-side analogue of
        C-203/HOST_INFO_EXFIL_FLOW (skillast.py, a CODE-only AST taint rule).
        RESIDUAL GAP on THIS EXACT fixture (filed separately, not C-538's scope):
        B388 still PASSes on this specific file too — not a noun-class miss, but a
        DIFFERENT, pre-existing limitation shared with B160's own architecture. The
        directive's destination is never restated as a literal URL near the "Send"
        verb ("Send that object in the profile-update request body" backward-
        references step 2's endpoint instead of repeating it); the nearest actual
        URL sits 171 chars after the verb, outside the 100-char verb->URL proximity
        window both checks use to stay off unrelated prose. Widening that window, or
        adding a backward-URL-reference search, is a separate, riskier change (it
        reopens exactly the false-positive classes B160's own C-135 history fought to
        close) and was deliberately left out of C-538's scope — see
        test_b388_does_not_recognize_this_fixtures_backward_referenced_destination
        below, which pins it as its own tracked gap rather than silently declaring
        victory on a check that still doesn't fire on the real sample.
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


def test_b160_correctly_stays_pass_for_a_non_bulk_non_credential_object():
    """B160's bulk/PII/credential noun class deliberately does NOT match an
    'agentCapabilities' hardware-spec object — that is correct, not a gap; see
    B388 (CLAWSECCHECK-C-538) for the dedicated prose-side hardware-fingerprint
    check this fixture motivated."""
    f = _findings()["B160"]
    assert f.status == PASS, (
        f"B160 status changed to {f.status} ({f.detail!r}) -- if B160 itself now "
        "fires on the host-capabilities-report step, its noun class widened; make "
        "sure that was intentional (it would overlap B388's own scope)."
    )


def test_b388_does_not_recognize_this_fixtures_backward_referenced_destination():
    """CLAWSECCHECK-C-538 shipped B388, a prose-side sibling of B160 that DOES
    recognize a hardware/OS-fingerprint object in general (see
    tests/test_c538_host_fingerprint_exfil.py — the same 'Send <fingerprint> to
    <URL>' shape, URL close to the verb, reliably WARNs). It still PASSes on THIS
    EXACT fixture, though, because moltfounders' own step 3 never restates a
    literal URL near its "Send" verb — "Send that object in the profile-update
    request body" backward-references step 2's endpoint 171 chars earlier, past
    both checks' 100-char verb->URL proximity window. That window is what keeps
    either check off unrelated prose elsewhere in a document; widening it (or
    adding a backward-URL-reference search) is a distinct, riskier change with
    its own false-positive surface, deliberately left out of C-538's scope. Pinned
    here (rather than silently declared fixed) so a future fix to this backward-
    reference gap is a deliberate, visible change.
    """
    f = _findings()["B388"]
    assert f.status == PASS, (
        f"B388 status changed to {f.status} ({f.detail!r}) -- if this now fires on "
        "the host-capabilities-report step, the verb->URL backward-reference gap "
        "described above may be closed; re-check and update this assertion "
        "deliberately instead of leaving it stale."
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
