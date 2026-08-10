"""B-501 — a skill NAME is not evidence that monitoring exists.

`check_monitoring` (B16) asks whether the user has threat detection in place. It used to
answer by substring-matching the names of installed skills and plugins against
``_MONITORING_HINTS``, and returning PASS "Threat monitoring present" on a hit. The name
is chosen by whoever installed the skill, and it was the SOLE gate — no content, no
capability, nothing else looked at.

The corpus already held the exploit. ``fixtures/bad_ownname_clawseccheck_squat`` is a
hostile skill that calls itself ``clawseccheck`` and ships ``vendor/sitecustomize.py``
(Python auto-execution on interpreter start). Measured before the fix: only two fixtures
in the entire corpus reached PASS, and that squat was one of them — clawseccheck credited
a skill impersonating clawseccheck as the user's threat monitoring. The other was
``clean_b344_detection_engineering``, whose skill is called ``ad-threat-hunter``: a
plausible name, and equally unverified. Both now land in the candidate arm, which is the
point — the check's entire positive evidence had been a string somebody else chose.

Second, quieter half of the same bug: bare ``"ids"`` substring-matched *asteroids*,
*hybrids*, *pyramids*; bare ``"monitor"`` matched *price-monitor*. Matching is now
anchored to the START of a name token, which keeps every intended match (``clawsec`` ->
*clawseccheck*, ``monitor`` -> *monitoring*) and drops the accidents, whose hint always
sat buried mid-word.

What replaced the name-PASS is the attestation arm. B16's own fix text has told users to
self-report monitors via ``--attest`` (host_monitors) since it was written, and no code
path ever read that field.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

import clawseccheck
from clawseccheck.catalog import ATTESTED, PASS, WARN
from clawseccheck.checks import check_monitoring
from clawseccheck.checks._host import _monitoring_candidate
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(skills=(), plugins=(), attestation=None) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = {"plugins": {"allow": list(plugins)}} if plugins else {}
    c.installed_skills = {name: "" for name in skills}
    if attestation is not None:
        c.attestation = attestation
    return c


# ---- the attack: a name must not buy a PASS ----

def test_a_skill_named_like_a_monitor_does_not_pass():
    f = check_monitoring(_ctx(skills=["monitor"]))
    assert f.status == WARN


def test_the_real_squat_fixture_no_longer_passes():
    """End to end on the fixture that modelled this attack all along."""
    _, findings, _ = clawseccheck.audit(str(FIXTURES / "bad_ownname_clawseccheck_squat"))
    b16 = next(f for f in findings if f.id == "B16")
    assert b16.status == WARN, b16.detail
    assert "name is not evidence" in b16.detail


def test_the_candidate_is_named_rather_than_hidden():
    """Suppressing the observation would be the opposite mistake: the user should be
    told a monitor-shaped name is installed, just not told it is monitoring."""
    f = check_monitoring(_ctx(skills=["sentinel-agent"]))
    assert "'sentinel-agent'" in f.detail
    assert f.status == WARN


def test_the_candidate_arm_routes_to_vet_and_attest():
    f = check_monitoring(_ctx(skills=["monitor"]))
    assert "--attest" in f.fix
    assert "--vet" in f.fix


# ---- the accident: substring matching in the middle of a word ----

def test_hint_buried_mid_word_is_not_a_candidate():
    for name in ("asteroids", "hybrids", "pyramids", "androids", "solids",
                 "identity-manager"):
        assert not _monitoring_candidate(name), name


def test_intended_matches_survive_the_anchoring():
    for name in ("clawseccheck", "clawsec-agent", "monitor", "monitoring",
                 "host-ids", "ids", "my-security-monitor", "falco-bridge",
                 "osquery", "wazuh-agent"):
        assert _monitoring_candidate(name), name


def test_an_innocuous_name_is_still_not_a_candidate():
    for name in ("canvas", "browser-automation", "pdf-tools"):
        assert not _monitoring_candidate(name), name


# ---- what a PASS now requires ----

def test_attested_monitor_passes_as_self_reported():
    f = check_monitoring(_ctx(attestation={"host_monitors": ["CrowdStrike Falcon"]}))
    assert f.status == PASS
    assert f.confidence == ATTESTED
    assert "self-reported" in f.detail
    assert "CrowdStrike Falcon" in f.detail


def test_attestation_outranks_a_bare_name_candidate():
    f = check_monitoring(_ctx(skills=["monitor"], attestation={"host_monitors": ["auditd"]}))
    assert f.status == PASS


def test_empty_or_malformed_attestation_does_not_pass():
    for att in ({"host_monitors": []},
                {"host_monitors": ["", "   "]},
                {"host_monitors": "auditd"},
                {"host_monitors": None},
                {}):
        assert check_monitoring(_ctx(attestation=att)).status == WARN, att


# ---- the nothing-found arm must not drift ----

def test_nothing_found_keeps_the_established_wording():
    """All but two fixtures in the corpus sit in this arm; the fingerprint manifest
    hashes detail text, so a reworded string here would force a corpus-wide regeneration
    for no reason."""
    f = check_monitoring(_ctx(skills=["canvas"]))
    assert f.status == WARN
    assert f.detail.startswith(
        "No threat-monitoring or detection plugin/skill is configured in this OpenClaw "
        "config."
    )
    assert "not proof you're unwatched" in f.detail


def test_b16_never_fails():
    for c in (_ctx(), _ctx(skills=["monitor"]), _ctx(skills=["canvas"]),
              _ctx(attestation={"host_monitors": ["auditd"]})):
        assert check_monitoring(c).status in (PASS, WARN)


def test_the_other_corpus_pass_also_becomes_a_candidate():
    """`ad-threat-hunter` is a *plausible* monitoring name rather than a hostile one, and
    it is treated the same way: named, not credited. A check cannot tell the two apart
    from a name, which is exactly why a name stopped being the evidence."""
    _, findings, _ = clawseccheck.audit(str(FIXTURES / "clean_b344_detection_engineering"))
    b16 = next(f for f in findings if f.id == "B16")
    assert b16.status == WARN
    assert "'ad-threat-hunter'" in b16.detail
