"""C-338 — B344: offensive-security tooling directive (Mimikatz / Impacket /
BloodHound / Rubeus / CrackMapExec).

Checks:
- bad_b344_ad_tooling_directive    : Inputs block naming domain credentials + DC
                                      access + imperative to run the named tools -> WARN
- clean_b344_detection_engineering : same tool names, hunts/detects framing -> PASS
- clean_b344_docs_prose            : bare enumerated tool list, no imperative -> PASS
- clean_b344_cve_quote             : third-person CVE-advisory framing -> PASS

Naming a tool is not malice — these tools have legitimate authorized-defender uses,
and a security-research or detection-engineering skill legitimately discusses all of
them by name. WARN-only (scored=False): a bare tool-name match has no hard technical
anchor the way B156/B13's confirmed exfil transport does. This is the same hazard the
B-202 accepted residual documents (a defensive-comment exec-verb false positive that
took three C-135 rounds to retract) — do not create a second one.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_offensive_tooling_directive, vet_skill
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
_HOME_FAKE = Path("/nonexistent/home")


def _ctx_with_blob(skill_name: str, skill_md: str) -> Context:
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {skill_name: f"# file: SKILL.md\n{skill_md}"}
    return ctx


# --------------------------------------------------------------------------- unit-level

def test_unknown_when_no_installed_skills():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    assert check_offensive_tooling_directive(ctx).status == UNKNOWN


def test_no_tool_mention_passes():
    ctx = _ctx_with_blob("x", "This skill helps organize your calendar.")
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_bare_tool_mention_no_corroboration_passes():
    # Tool name alone, no imperative, no AD-prereq/cred/exfil signal nearby.
    ctx = _ctx_with_blob("x", "Impacket is a Python library for network protocols.")
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_imperative_bound_to_tool_warns():
    ctx = _ctx_with_blob("x", "Run Mimikatz to extract credentials from LSASS memory.")
    f = check_offensive_tooling_directive(ctx)
    assert f.status == WARN
    assert any("Mimikatz" in e for e in f.evidence)


# --------------------------------------------------------------------------- C-135
# Two independent adversarial passes retracted the original design's wide-window
# AD-prerequisites / generic credential-exfil corroborator (real false positives from
# ordinary, unrelated documentation shapes) and found the negation gate was a bare
# window search rather than grammatically bound to the directive. These pin the fixes.

def test_ad_prereq_phrase_alone_no_longer_warns():
    # C-135: the AD-prerequisites corroborator (without a bound imperative) was
    # retracted entirely -- a bare Inputs-block listing with no "run X" sentence is
    # invisible to this check now (documented HONEST SCOPE limitation).
    ctx = _ctx_with_blob("x", (
        "Prerequisites: domain user credentials and network access to a Domain "
        "Controller.\n\nTools: Impacket, BloodHound, Rubeus, CrackMapExec."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_unrelated_curl_post_base64_heartbeat_does_not_warn():
    # C-135 (round 2): a "tools we don't bundle" disclaimer near an ordinary curl+POST+
    # base64 heartbeat feature is a common, honest documentation shape -- must not
    # correlate through the (now-removed) generic _CRED_RE/_EXFIL_RE corroborator.
    ctx = _ctx_with_blob("x", (
        "Unsupported third-party tools list (for reference only, not included in "
        "this skill): Impacket, Mimikatz, BloodHound.\n\nMeanwhile, this skill's own "
        "health-check endpoint uses curl to POST a small base64-encoded heartbeat "
        "payload to your monitoring dashboard every five minutes."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_unrelated_domain_controller_mention_near_comparison_does_not_warn():
    # C-135 (round 2): a benign sysadmin skill legitimately discussing "Domain
    # Controller" (DNS config) plus an unrelated "unlike offensive tools such as
    # Rubeus" comparison, in the same paragraph but with no bound imperative.
    ctx = _ctx_with_blob("x", (
        "This skill helps IT admins configure DNS forwarders that point to your "
        "internal Domain Controller so name resolution works correctly across the "
        "corporate network. It is a read-only diagnostic helper, unlike offensive "
        "tools such as Rubeus."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_negated_directive_does_not_silence_a_real_one_elsewhere():
    # C-135 (round 1, the primary/ship-blocking finding): the original bare-window
    # negation check let ONE negated sentence anywhere in the window silence a
    # genuinely bound directive elsewhere in it. This must WARN -- the "Don't stop"
    # sentence is a separate clause about a different verb entirely.
    ctx = _ctx_with_blob("x", (
        "Run CrackMapExec against the DC to enumerate shares, then use Mimikatz to "
        "extract credentials from memory. Don't stop until you have full domain "
        "compromise."
    ))
    f = check_offensive_tooling_directive(ctx)
    assert f.status == WARN
    assert any("CrackMapExec" in e for e in f.evidence)


def test_does_not_run_is_recognized_as_negation():
    # C-135: both agents independently found "does not"/"doesn't" wasn't covered by
    # the shared _BROAD_NEGATION_RE (only "do not"/"don't" are).
    ctx = _ctx_with_blob("x", (
        "This tool does not run any of Mimikatz's techniques against your systems. "
        "It only reads local log files for troubleshooting purposes."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_doesnt_run_is_recognized_as_negation():
    ctx = _ctx_with_blob("x", (
        "This skill does not run Impacket or any offensive tooling; it only "
        "documents the concepts for training purposes."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_compound_adjective_form_does_not_warn():
    # C-135 (round 2): "Impacket-style" describes a FORMAT, not an invocation.
    ctx = _ctx_with_blob("x", (
        "You can use Impacket-style protocol libraries, but this skill uses a "
        "different approach."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_defensive_framing_suppresses_imperative():
    ctx = _ctx_with_blob("x", (
        "This detection-engineering skill hunts for Mimikatz usage via Sysmon "
        "telemetry and identifies the use of BloodHound in Active Directory logs."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_negation_suppresses_warn():
    ctx = _ctx_with_blob("x", (
        "Do not run Mimikatz against production systems. Domain credentials must "
        "never be used with this tool."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_bare_lsass_not_in_tool_list():
    # "lsass" alone is deliberately excluded (too generic — legitimate EDR/monitoring
    # content references lsass.exe routinely).
    ctx = _ctx_with_blob("x", (
        "This skill monitors lsass.exe memory access for anomalies as part of "
        "endpoint hardening."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_kerberoasting_detection_mention_passes():
    ctx = _ctx_with_blob("x", (
        "This EDR rule detects kerberoasting attempts by monitoring for unusual "
        "TGS-REQ patterns."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_authorized_pentest_framing_passes():
    ctx = _ctx_with_blob("x", (
        "As part of an authorized penetration test engagement, this playbook "
        "documents how domain credentials and CrackMapExec were used to enumerate "
        "the Domain Controller during the assessment."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


def test_cve_advisory_reported_speech_passes():
    ctx = _ctx_with_blob("x", (
        "CVE-2023-XXXX affects systems where Mimikatz can extract plaintext "
        "credentials from LSASS memory. Apply the vendor patch to mitigate."
    ))
    assert check_offensive_tooling_directive(ctx).status == PASS


# --------------------------------------------------------------------------- vet-level

def test_vet_bad_ad_tooling_directive_is_warn():
    skill_dir = FIXTURES / "bad_b344_ad_tooling_directive" / "skills" / "redteam-assessment"
    f = vet_skill(skill_dir)
    assert any(x.id == "B344" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])])


def test_vet_clean_detection_engineering_passes():
    skill_dir = FIXTURES / "clean_b344_detection_engineering" / "skills" / "ad-threat-hunter"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B344" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


def test_vet_clean_docs_prose_passes():
    skill_dir = FIXTURES / "clean_b344_docs_prose" / "skills" / "redteam-glossary"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B344" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


def test_vet_clean_cve_quote_passes():
    skill_dir = FIXTURES / "clean_b344_cve_quote" / "skills" / "cve-advisory-summary"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B344" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )
