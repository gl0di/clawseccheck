"""B184 (B-291, ENV-5) — WHICH ClawHub issued the supply-chain verdicts we report on.

Three shipped checks consume a verdict a registry issues, and none of them asked which
registry issued it:

  * B135 reads ``verification.decision`` out of ``.clawhub/lock.json``
  * B177 reads ``clawhubTrustDisposition`` out of the state DB
  * B181 verifies on-disk bytes against digests recorded from the registry's own manifest

Repointing the endpoint therefore did NOT silence those checks — it made them affirm
supply-chain health on the redirected host's word, B181's digest comparison matching by
construction.

Grounding (Golden Rule #4), read first-hand in the installed OpenClaw dist at
``~/.npm-global/lib/node_modules/openclaw/dist``:

  * ``clawhub-DxyvW6TD.js:16``   ``DEFAULT_CLAWHUB_URL = "https://clawhub.ai"``
  * ``clawhub-DxyvW6TD.js:17``   ``DEFAULT_GITHUB_CODELOAD_URL = "https://codeload.github.com"``
  * ``clawhub-DxyvW6TD.js:37``   ``normalizeBaseUrl`` — ``OPENCLAW_CLAWHUB_URL ||
    CLAWHUB_URL || DEFAULT``, then ``.replace(/\\/+$/, "")``
  * ``clawhub-DxyvW6TD.js:41``   the codeload ladder —
    ``OPENCLAW_CLAWHUB_GITHUB_CODELOAD_BASE_URL || CLAWHUB_GITHUB_CODELOAD_BASE_URL || DEFAULT``
  * ``clawhub-DxyvW6TD.js:49``   ``resolveClawHubConfigPaths`` —
    ``OPENCLAW_CLAWHUB_CONFIG_PATH || CLAWHUB_CONFIG_PATH || CLAWDHUB_CONFIG_PATH``
    (the B182 sub-bug: the first rung was missing from ``_B182_ENV_OVERRIDES``)
  * ``clawhub-DxyvW6TD.js:336``  ``resolveClawHubBaseUrl`` is a thin alias of
    ``normalizeBaseUrl``, so every consumer inherits the override
  * ``status-WbH6V7lU.js:1245``  writes ``registry: resolveClawHubBaseUrl(...)`` into the
    per-skill ``.clawhub/origin.json``
  * ``status-WbH6V7lU.js:1258``  writes the same into ``workspace/.clawhub/lock.json``
  * ``status-WbH6V7lU.js:1235``  gates only ``verificationVersion`` on
    ``installKind === "github"`` — ``registry`` is written unconditionally and GitHub
    provenance goes to the SEPARATE ``sourceUrl`` key, so a github-sourced install still
    records the canonical registry (the pinned FP guard below)
  * ``host-env-security-CWC2ZCy4.js:317-322`` ``blockedOverridePrefixes`` is exactly
    ``["GIT_CONFIG_", "NPM_CONFIG_", "CARGO_REGISTRIES_", "TF_VAR_"]`` — no CLAWHUB entry,
    so the state-dir dotenv loader does not filter the redirect, even though
    ``dotenv-eb21SB3p.js:177-185`` blocks ``CLAWHUB_``/``OPENCLAW_CLAWHUB_`` in a WORKSPACE
    ``.env``

Scope, pinned by ``test_never_fails_and_is_unscored``: this closes the DETECTION half only.
Judging whether the redirected host serves malicious skills would require contacting it,
which Golden Rule #1 forbids.

Offline, read-only; nothing is written outside pytest's tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    CHECKS,
    _B182_ENV_OVERRIDES,
    _B184_CODELOAD_ENV_VARS,
    _B184_REGISTRY_ENV_VARS,
    _b184_is_canonical,
    check_clawhub_registry_provenance,
)
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

CANONICAL = FIXTURES / "clean_b184_registry_canonical"
GITHUB_INSTALL = FIXTURES / "clean_b184_registry_github_install"
MIRROR = FIXTURES / "benign_b184_registry_enterprise_mirror"
BAD_ORIGIN = FIXTURES / "bad_b184_registry_redirect_origin"
BAD_LOCK = FIXTURES / "bad_b184_registry_redirect_lock"
BAD_DOTENV = FIXTURES / "bad_b184_registry_env_dotenv"

_REGISTRY_HOST = "clawhub.ai"
_CODELOAD_HOST = "codeload.github.com"


def _run(home: Path):
    return check_clawhub_registry_provenance(collect(home))


# --------------------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------------------
def test_b184_is_catalogued_and_registered():
    meta = BY_ID["B184"]
    assert meta.id == "B184"
    assert check_clawhub_registry_provenance in CHECKS


def test_b184_is_unscored():
    """A non-canonical registry is a fact to confirm, not a proven misconfiguration.

    A self-hosted / enterprise mirror is legitimate and disclosed, so this must never move
    the grade. Pinned so a later 'promote it to scored' edit has to argue with a test.
    """
    assert BY_ID["B184"].scored is False


# --------------------------------------------------------------------------------------
# Clean — the live-fleet state, and the false-positive guard
# --------------------------------------------------------------------------------------
def test_canonical_registry_in_lock_and_origin_passes():
    """The real-fleet shape: both records name the public registry."""
    finding = _run(CANONICAL)
    assert finding.status == PASS
    assert "clawhub.ai" in finding.detail


def test_github_sourced_install_does_not_fire():
    """FP GUARD, pinned (status-WbH6V7lU.js:1235,1245).

    An ``installKind === "github"`` install still records the CANONICAL registry; the
    GitHub provenance goes into the separate ``sourceUrl`` key. Treating ``sourceUrl`` as
    a redirect would false-positive on every github-sourced skill.
    """
    origin = json.loads(
        (GITHUB_INSTALL / "workspace/skills/gh-skill/.clawhub/origin.json").read_text()
    )
    assert origin["sourceUrl"].startswith("https://github.com/")
    assert origin["registry"] == "https://clawhub.ai"

    assert _run(GITHUB_INSTALL).status == PASS


def test_real_openclaw_home_is_not_warned(tmp_path):
    """GR#5 regression guard, expressed hermetically.

    The canonical fixture mirrors the real box's recorded shape (verified 2026-07-20:
    lock.json and origin.json both carry ``registry: https://clawhub.ai``). Re-asserted
    against a hand-built copy so the guard does not depend on the developer's own home.
    """
    home = tmp_path / "home"
    dot = home / "workspace" / "skills" / "clawseccheck" / ".clawhub"
    dot.mkdir(parents=True)
    (dot / "origin.json").write_text(
        json.dumps({"version": 1, "registry": "https://clawhub.ai", "slug": "clawseccheck"})
    )
    assert _run(home).status == PASS


# --------------------------------------------------------------------------------------
# Bad — each evidence source independently
# --------------------------------------------------------------------------------------
def test_redirect_recorded_in_origin_json_warns():
    finding = _run(BAD_ORIGIN)
    assert finding.status == WARN
    assert "clawhub-mirror.evil.example" in finding.detail
    assert "origin.json" in finding.detail


def test_redirect_recorded_in_lock_json_warns():
    finding = _run(BAD_LOCK)
    assert finding.status == WARN
    assert "clawhub-mirror.evil.example" in finding.detail
    assert "lock.json" in finding.detail


def test_redirect_in_state_dir_dotenv_warns():
    """``~/.openclaw/.env`` is loaded into process.env and is NOT filtered for CLAWHUB keys.

    The recorded provenance in this fixture is canonical — only the persistent env override
    is bad — so this proves the dotenv leg fires on its own rather than riding on a record.
    """
    origin = json.loads(
        (BAD_DOTENV / "workspace/skills/demo-skill/.clawhub/origin.json").read_text()
    )
    assert origin["registry"] == "https://clawhub.ai", "the record must be clean here"

    finding = _run(BAD_DOTENV)
    assert finding.status == WARN
    assert "OPENCLAW_CLAWHUB_URL" in finding.detail


def test_warn_names_the_three_checks_whose_verdicts_the_host_issues():
    """The point of the finding is not 'an env var changed' — it is that B135/B177/B181
    are reporting that host's assurance as if it were independent."""
    detail = _run(BAD_ORIGIN).detail
    for cid in ("B135", "B177", "B181"):
        assert cid in detail, f"{cid} must be named in the WARN text"


def test_enterprise_mirror_warns_but_never_fails():
    """A self-hosted / internal mirror is real, intentional and disclosed.

    It must still be DISCLOSED (the verdicts really do come from it) but must never FAIL —
    that would be the Golden Rule #5 false positive this check was scoped to avoid.
    """
    finding = _run(MIRROR)
    assert finding.status == WARN
    assert finding.status != FAIL


@pytest.mark.parametrize("home", [CANONICAL, GITHUB_INSTALL, MIRROR, BAD_ORIGIN, BAD_LOCK,
                                 BAD_DOTENV])
def test_never_fails_and_is_unscored(home):
    """WARN is the ceiling on EVERY input, including the deliberately-hostile ones.

    Honest labelling: this check closes the DETECTION half of the gap only. It cannot know
    whether the redirected host serves anything malicious — that needs a network lookup the
    tool deliberately never makes — so it may never escalate to FAIL.
    """
    finding = check_clawhub_registry_provenance(collect(home))
    assert finding.status != FAIL
    assert finding.scored is False


def test_warn_text_does_not_claim_the_host_is_malicious():
    """Doctrinal boundary (Golden Rule #1 + honest labelling).

    We detect WHERE skills came from. Whether that host serves malware is unknowable from
    here. The output must not imply otherwise.
    """
    finding = _run(BAD_ORIGIN)
    text = (finding.detail + " " + finding.fix).lower()
    for forbidden in ("malicious host", "is malicious", "attacker-controlled", "compromised host"):
        assert forbidden not in text, f"output must not assert {forbidden!r}"
    assert "does not and cannot judge" in text or "cannot judge" in text


# --------------------------------------------------------------------------------------
# UNKNOWN — never a fake PASS (Golden Rule #4)
# --------------------------------------------------------------------------------------
def test_no_records_and_no_override_is_unknown(tmp_path):
    home = tmp_path / "empty-home"
    (home / "workspace").mkdir(parents=True)
    finding = _run(home)
    assert finding.status == UNKNOWN
    assert "cannot be determined" in finding.detail


def test_record_without_a_registry_field_is_unknown_not_pass(tmp_path):
    """An origin.json predating the field must not be read as an all-clear."""
    home = tmp_path / "home"
    dot = home / "workspace" / "skills" / "old-skill" / ".clawhub"
    dot.mkdir(parents=True)
    (dot / "origin.json").write_text(json.dumps({"version": 1, "slug": "old-skill"}))
    assert _run(home).status == UNKNOWN


@pytest.mark.parametrize(
    "registry",
    [None, "", "   ", {"url": "https://evil.example"}, ["https://evil.example"], 42, True],
)
def test_malformed_registry_values_degrade_to_unknown(tmp_path, registry):
    """C-135 adversarial sweep, pinned.

    A ``registry`` that is absent, empty or the wrong JSON type is NO EVIDENCE. It must
    never crash, never become a fake PASS, and — the false-positive direction — never
    become a WARN about a redirect that was never recorded.
    """
    home = tmp_path / "home"
    dot = home / "workspace" / "skills" / "s" / ".clawhub"
    dot.mkdir(parents=True)
    (dot / "origin.json").write_text(json.dumps({"version": 1, "registry": registry, "slug": "s"}))
    assert _run(home).status == UNKNOWN


def test_unparseable_record_does_not_crash_the_check(tmp_path):
    """A truncated or non-JSON record is skipped, not raised."""
    home = tmp_path / "home"
    dot = home / "workspace" / "skills" / "s" / ".clawhub"
    dot.mkdir(parents=True)
    (dot / "origin.json").write_text('{"version": 1, "registry": "https://clawhub')
    assert _run(home).status == UNKNOWN


# --------------------------------------------------------------------------------------
# Both env ladders — omitting the bare fallback would make the check bypassable
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "var",
    [
        "OPENCLAW_CLAWHUB_URL",
        "CLAWHUB_URL",
        "OPENCLAW_CLAWHUB_GITHUB_CODELOAD_BASE_URL",
        "CLAWHUB_GITHUB_CODELOAD_BASE_URL",
    ],
)
def test_every_rung_of_both_ladders_is_covered(tmp_path, var):
    """Setting the SECOND rung of either pair must not be a free bypass."""
    home = tmp_path / f"home-{var}"
    home.mkdir()
    (home / ".env").write_text(f"{var}=https://redirect.evil.example\n")
    finding = _run(home)
    assert finding.status == WARN, f"{var} was not covered"
    assert var in finding.detail


def test_ladder_tables_match_the_dist():
    assert _B184_REGISTRY_ENV_VARS == ("OPENCLAW_CLAWHUB_URL", "CLAWHUB_URL")
    assert _B184_CODELOAD_ENV_VARS == (
        "OPENCLAW_CLAWHUB_GITHUB_CODELOAD_BASE_URL",
        "CLAWHUB_GITHUB_CODELOAD_BASE_URL",
    )


def test_shadowed_lower_rung_is_not_double_reported(tmp_path):
    """The dist ladder is first-non-empty-wins, so a set higher rung makes the lower one
    unreachable. Reporting both would be a finding about a value the product never reads."""
    home = tmp_path / "home"
    home.mkdir()
    (home / ".env").write_text(
        "OPENCLAW_CLAWHUB_URL=https://first.evil.example\n"
        "CLAWHUB_URL=https://second.evil.example\n"
    )
    finding = _run(home)
    assert finding.status == WARN
    assert "first.evil.example" in finding.detail
    assert "second.evil.example" not in finding.detail


def test_token_ladder_is_not_read_here(tmp_path):
    """The *_TOKEN ladder is a credential, already covered by SECRET_KEY_RE. This check is
    about the ENDPOINT and must not double-count it (and must not touch a secret value)."""
    home = tmp_path / "home"
    home.mkdir()
    # Assembled from fragments so no contiguous secret-shaped literal exists in source.
    value = "clh_" + "x" * 8
    (home / ".env").write_text("OPENCLAW_CLAWHUB" + "_TOKEN=" + value + "\n")
    finding = _run(home)
    assert finding.status == UNKNOWN
    assert value not in finding.detail


# --------------------------------------------------------------------------------------
# Canonicalisation — mirrors normalizeBaseUrl, permissive only where it cannot let a
# redirect through
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value",
    [
        "https://clawhub.ai",
        "https://clawhub.ai/",       # normalizeBaseUrl strips trailing slashes (:38)
        "https://clawhub.ai///",
        "  https://clawhub.ai  ",    # normalizeOptionalString trims
        "https://ClawHub.AI",        # host case is a DNS-identical spelling, not a redirect
        "HTTPS://clawhub.ai",
    ],
)
def test_canonical_spellings_do_not_fire(value):
    assert _b184_is_canonical(value, _REGISTRY_HOST) is True


@pytest.mark.parametrize(
    "value",
    [
        "https://clawhub-mirror.evil.example",
        "https://clawhub.ai.evil.example",       # suffix look-alike
        "https://evilclawhub.ai",                # prefix look-alike
        "http://clawhub.ai",                     # scheme downgrade = interception vector
        # Userinfo look-alike. NOTE: caught by the HOSTNAME comparison, not by the userinfo
        # guard — urlsplit parses the real host here as "evil.example". See
        # test_userinfo_guard_is_load_bearing for the case the userinfo guard itself covers.
        "https://clawhub.ai@evil.example",
        "https://clawhub.ai:8443",               # a different service on a different port
        "https://clawhub.ai/proxy",              # path-prefixed re-router
        "https://10.0.0.5",
        "https://clawhub.ai\nX",                 # control characters are refused outright
        "https://clawhub.ai\t/",
    ],
)
def test_non_canonical_spellings_fire(value):
    assert _b184_is_canonical(value, _REGISTRY_HOST) is False


@pytest.mark.parametrize("value", [None, "", "   ", 42, {}, []])
def test_unusable_values_are_neither_canonical_nor_a_finding(value):
    """None means 'no evidence' — it must not be read as a PASS or as a WARN."""
    assert _b184_is_canonical(value, _REGISTRY_HOST) is None


def test_userinfo_guard_is_load_bearing():
    """Embedded credentials on the CANONICAL host — the case only the userinfo guard catches.

    Written because the obvious ``https://clawhub.ai@evil.example`` case is caught by the
    hostname comparison instead (urlsplit reads the real host as ``evil.example``), so it
    proves nothing about this guard. Here the hostname genuinely IS ``clawhub.ai``, so
    without the userinfo check these would read as canonical — and the dist's own
    ``isDefaultClawHubBaseUrl`` string comparison would call them non-default too.
    """
    assert _b184_is_canonical("https://evil.example@clawhub.ai", _REGISTRY_HOST) is False
    assert _b184_is_canonical("https://user:pw@clawhub.ai", _REGISTRY_HOST) is False


def test_port_guard_is_load_bearing():
    """``https://clawhub.ai:8443`` parses with hostname ``clawhub.ai`` and an empty path, so
    only the explicit port check keeps it out of PASS."""
    assert _b184_is_canonical("https://clawhub.ai:8443", _REGISTRY_HOST) is False
    assert _b184_is_canonical("https://clawhub.ai:443", _REGISTRY_HOST) is False


def test_codeload_host_is_compared_against_its_own_default():
    assert _b184_is_canonical("https://codeload.github.com", _CODELOAD_HOST) is True
    assert _b184_is_canonical("https://clawhub.ai", _CODELOAD_HOST) is False
    assert _b184_is_canonical("https://codeload.github.com.evil.example", _CODELOAD_HOST) is False


def test_interior_control_character_verdict_is_interpreter_independent():
    """3.9-vs-3.12 hazard, pinned.

    ``urlsplit`` strips ASCII tab/newline from ANYWHERE in the string before parsing
    (bpo-43882), so ``https://clawhub.ai\\n.evil.example`` would parse as the host
    ``clawhub.ai.evil.example`` on a patched interpreter and differently on an unpatched
    one. Resting a verdict on that normalization is the class of bug that has already
    broken a real tag in this project (``ipaddress.is_private`` on 3.9 vs 3.12).

    Interior whitespace and control characters are therefore refused BEFORE any parsing,
    which makes the answer identical on every interpreter — and none of them is ever
    legitimate in a registry URL.
    """
    for raw in [
        "https://clawhub.ai\n.evil.example",   # the bpo-43882 splice
        "https://clawhub.ai\r.evil.example",
        "https://claw\thub.ai",
        "https://clawhub.ai\x00",
        "https://clawhub.ai\x7f",
        "https://clawhub.ai .evil.example",
    ]:
        assert _b184_is_canonical(raw, _REGISTRY_HOST) is False, raw


def test_surrounding_whitespace_is_trimmed_not_treated_as_a_redirect():
    """``normalizeOptionalString`` trims, so a trailing newline in a dotenv value is the
    same endpoint — and the trim is done here, not by ``urlsplit``, so it too is
    interpreter-independent."""
    for raw in ["https://clawhub.ai\n", "  https://clawhub.ai\r\n", "\thttps://clawhub.ai "]:
        assert _b184_is_canonical(raw, _REGISTRY_HOST) is True, raw


# --------------------------------------------------------------------------------------
# Hermeticity — the auditor's own environment must never steer a --home scan
# --------------------------------------------------------------------------------------
def test_process_env_does_not_leak_into_a_foreign_home(tmp_path, monkeypatch):
    """A fixture / --home scan must stay reproducible regardless of where it runs.

    ``dotenv_override`` gates the process-env leg on ``audits_this_users_own_home``; this
    pins that the gate actually holds for B184, so the auditor's shell cannot manufacture a
    WARN about someone else's home (Golden Rule #5).
    """
    monkeypatch.setenv("OPENCLAW_CLAWHUB_URL", "https://auditor-shell.evil.example")
    assert _run(CANONICAL).status == PASS

    home = tmp_path / "foreign-home"
    (home / "workspace").mkdir(parents=True)
    assert _run(home).status == UNKNOWN


# --------------------------------------------------------------------------------------
# B182 sub-bug (found while verifying B-291): the env ladder was missing its first rung
# --------------------------------------------------------------------------------------
def test_b182_env_ladder_includes_the_openclaw_prefixed_var():
    """clawhub-DxyvW6TD.js:49 — OpenClaw's OWN embedded client reads the token store
    through ``OPENCLAW_CLAWHUB_CONFIG_PATH || CLAWHUB_CONFIG_PATH || CLAWDHUB_CONFIG_PATH``.

    B182 was grounded against the STANDALONE clawhub CLI, which has only the last two, so a
    store relocated with the highest-precedence var was invisible — a silent miss, since an
    unfound store reports UNKNOWN rather than FAIL.
    """
    assert _B182_ENV_OVERRIDES[0] == "OPENCLAW_CLAWHUB_CONFIG_PATH"
    assert set(_B182_ENV_OVERRIDES) == {
        "OPENCLAW_CLAWHUB_CONFIG_PATH",
        "CLAWHUB_CONFIG_PATH",
        "CLAWDHUB_CONFIG_PATH",
    }
