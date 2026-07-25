"""B196 (E-060 item 3): browser.evaluateEnabled arbitrary-JS sink.

OpenClaw defaults this to true when the key is absent -- re-verified directly against
the JS bundle: config-DpWXcVmn.js:441 `const evaluateEnabled = cfg?.evaluateEnabled ??
true;`, the defaults table config-D9HgDUPt.js:103 `"browser.evaluateEnabled": true`,
and the same `?? true` resolution in sandbox-DtTssSMH.js:394,1299; enforced at
routes-VNv3nd0n.js:1274 (an `evaluate` action 403s with `evaluateDisabled` only when the
resolved flag is false). See docs/research/openclaw-schema-recon.md §31.1 (workspace
root, not shipped).

EFFECTIVE-STATE GRADING (B-331). This file previously documented and pinned a split --
absent -> WARN, explicit `true` -> FAIL -- as deliberate. That split was wrong, and this
file now pins its correction. The dist facts above prove an absent key and an explicit
`true` are byte-for-byte the SAME runtime exposure, so grading them 16 points and two
letter grades apart graded the config TEXT rather than what the machine does. Concretely
it (a) made the grade gameable by a no-op edit -- a user at C could reach A by DELETING
the `evaluateEnabled: true` line, with nothing changing on their machine, (b) inverted
the incentive by punishing the operator who writes their configuration down explicitly,
and (c) under-reported the common case, since almost nobody writes the key and so most
genuinely-exposed configs landed on the lenient rung.

CORROBORATED FAIL. Unification is one axis; the BAR is another, and a first pass set the
bar at a flat WARN for every sink-ON config. That was a false negative: it graded an
agent running arbitrary JavaScript inside the operator's real, already-signed-in browser
as an A, and it left B196's FAIL branch unreachable for every possible input -- a HIGH
check that could not move the grade. The bar is therefore corroborated, not flat:

  - no browser config at all                  -> UNKNOWN (browser tool not in use)
  - evaluateEnabled == false                  -> PASS  (the only state that closes it)
  - sink ON + unowned-session corroborator    -> FAIL
  - sink ON, no corroborator                  -> WARN
    (absent, explicit `true`, and any other non-`false` value are ONE state at BOTH
     bars -- the effective-state fix above survives the escalation)

The corroborator is "the browser tool drives a session OpenClaw did not launch": a
hand-written `browser.profiles.*.driver` of "existing-session"/"extension", or an
attach-only profile against a non-loopback `cdpUrl`. Grounded in the installed dist --
zod-schema-O9ml_nmo.js:1120-1131 (the four-way driver union),
cdp-reachability-policy-BLdT5iz3.js:11-30 (modes "local-existing-session" /
"local-extension"), docs/tools/browser.md:324 (`driver: "extension"` "drives your
signed-in Chrome"), and config-DpWXcVmn.js:391-410, which shows OpenClaw SYNTHESIZES the
`user`/`chrome` profiles at resolve time and never writes them to openclaw.json -- so an
explicit `driver` in the operator's own file is rare and deliberate, never a default.
That is what keeps this off the fleet-wide false-FAIL path, and it is orthogonal to the
reachability leg B38 grades, so it does not double-count B38.

An earlier revision of this docstring said the sink-plus-reachability combination
"belongs to the risk engine". It does not: no RISK rule reads B196 or evaluateEnabled,
and both browser chains (RISK-03, RISK-15) gate solely on `_browser_ssrf()`, which never
consults the sink. The escalation is graded in the check, where the evidence is.
"""
from __future__ import annotations

import json
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_browser_evaluate_enabled
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# Minimal but realistic base config, so audit() exercises the whole pipeline rather than
# bailing out early. The effective-state homes below differ ONLY by `browser`.
_BASE_CONFIG = {
    "gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "token", "token": "a-very-long-token-of-32-characters"},
    },
    "channels": {"telegram": {"dmPolicy": "allowlist", "groupPolicy": "allowlist"}},
    "tools": {"profile": "minimal"},
    "logging": {"redactSensitive": "tools"},
    "models": {"main": {"provider": "ollama/llama3"}},
}


def _home(tmp_path: Path, config: dict | None = None) -> Path:
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    if config is not None:
        (home / "openclaw.json").write_text(json.dumps(config), encoding="utf-8")
    return home


def _audit_browser_home(tmp_path: Path, name: str, browser: dict):
    """Audit a home whose config is _BASE_CONFIG plus the given `browser` block.

    Perms are pinned to 0600 for the same reason conftest pins the on-disk fixtures: an
    at-rest permission check must not make the score depend on the runner's umask.
    """
    home = tmp_path / name
    home.mkdir(parents=True, exist_ok=True)
    cfg = dict(_BASE_CONFIG)
    cfg["browser"] = browser
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    path.chmod(0o600)
    return audit(home)


def _b196(findings):
    return next(f for f in findings if f.id == "B196")


# ---------------------------------------------------------------------------
# On-disk fixtures
# ---------------------------------------------------------------------------

def test_clean_fixture_passes():
    r = check_browser_evaluate_enabled(collect(FIXTURES / "clean_b196_browser_evaluate_enabled"))
    assert r.status == PASS


def test_bad_fixture_explicit_true_warns():
    """The bad fixture's finding still FIRES; the bar is now WARN, not FAIL (B-331)."""
    r = check_browser_evaluate_enabled(collect(FIXTURES / "bad_b196_browser_evaluate_enabled"))
    assert r.status == WARN
    assert r.status != FAIL


def test_bad_fixture_absent_key_warns():
    """Companion bad fixture: `browser` present, `evaluateEnabled` never written -- the
    commonest real shape, and the same runtime exposure as the explicit-true fixture."""
    r = check_browser_evaluate_enabled(collect(FIXTURES / "bad_b196_browser_evaluate_default"))
    assert r.status == WARN


def test_both_bad_fixtures_agree_on_disk():
    absent = check_browser_evaluate_enabled(collect(FIXTURES / "bad_b196_browser_evaluate_default"))
    explicit = check_browser_evaluate_enabled(collect(FIXTURES / "bad_b196_browser_evaluate_enabled"))
    assert absent.status == explicit.status


# ---------------------------------------------------------------------------
# UNKNOWN: browser tool not configured at all
# ---------------------------------------------------------------------------

def test_no_browser_config_is_unknown(tmp_path):
    r = check_browser_evaluate_enabled(collect(_home(tmp_path, config={"tools": {"profile": "minimal"}})))
    assert r.status == UNKNOWN


def test_no_config_found_is_unknown(tmp_path):
    r = check_browser_evaluate_enabled(collect(_home(tmp_path, config=None)))
    assert r.status == UNKNOWN


# ---------------------------------------------------------------------------
# B-331: effective state, not spelling — absent and explicit `true` are one state
# ---------------------------------------------------------------------------

def test_evaluate_enabled_absent_warns(tmp_path):
    home = _home(tmp_path, config={"browser": {"noSandbox": False}})
    r = check_browser_evaluate_enabled(collect(home))
    assert r.status == WARN
    # The text must say plainly that the vendor default leaves the sink on.
    assert "vendor default for this key is true" in r.detail
    assert "does not turn the sink off" in r.detail


def test_evaluate_enabled_true_warns_not_fails(tmp_path):
    """Explicit `true` is no longer a FAIL: it is the identical runtime state to the
    absent key, and OpenClaw ships the sink on."""
    home = _home(tmp_path, config={"browser": {"evaluateEnabled": True}})
    r = check_browser_evaluate_enabled(collect(home))
    assert r.status == WARN
    assert r.status != FAIL


def test_absent_and_explicit_true_reach_the_same_status(tmp_path):
    absent = check_browser_evaluate_enabled(
        collect(_home(tmp_path / "a", config={"browser": {"noSandbox": False}}))
    )
    explicit = check_browser_evaluate_enabled(
        collect(_home(tmp_path / "b", config={"browser": {"evaluateEnabled": True}}))
    )
    assert absent.status == explicit.status == WARN
    # Different spellings may be named differently, but both must state the one
    # effective fact: only an explicit false closes the sink.
    for r in (absent, explicit):
        assert "only an explicit false disables it" in r.detail


def test_deleting_the_key_does_not_change_the_grade(tmp_path):
    """THE GUARD that would have caught B-331.

    Absent and explicit-`true` are the same runtime exposure, so a no-op edit that only
    deletes (or adds) the line must move the score by EXACTLY zero. Before the fix this
    delta was 16 points and two letter grades (A/95 vs C/79).
    """
    _, f_absent, s_absent = _audit_browser_home(tmp_path, "absent", {"noSandbox": False})
    _, f_true, s_true = _audit_browser_home(
        tmp_path, "explicit", {"noSandbox": False, "evaluateEnabled": True}
    )

    assert _b196(f_absent).status == _b196(f_true).status
    assert s_true.score - s_absent.score == 0
    assert s_true.grade == s_absent.grade


def test_disabling_the_sink_does_improve_the_grade(tmp_path):
    """The converse of the guard above: a REAL change (closing the sink) must still be
    rewarded, so the fix cannot have been achieved by making B196 inert."""
    _, _, s_on = _audit_browser_home(tmp_path, "on", {"noSandbox": False})
    _, f_off, s_off = _audit_browser_home(
        tmp_path, "off", {"noSandbox": False, "evaluateEnabled": False}
    )
    assert _b196(f_off).status == PASS
    assert s_off.score > s_on.score


def test_evaluate_enabled_non_bool_is_warn(tmp_path):
    """Only a literal `false` closes the sink (OpenClaw's `cfg?.evaluateEnabled ?? true`
    treats null/undefined as absent). A stray non-boolean value cannot be confirmed
    disabled, so it lands on the same WARN bar rather than a guessed PASS or FAIL."""
    home = _home(tmp_path, config={"browser": {"evaluateEnabled": "yes"}})
    r = check_browser_evaluate_enabled(collect(home))
    assert r.status == WARN


# ---------------------------------------------------------------------------
# PASS: explicit false
# ---------------------------------------------------------------------------

def test_evaluate_enabled_false_passes(tmp_path):
    home = _home(tmp_path, config={"browser": {"evaluateEnabled": False}})
    r = check_browser_evaluate_enabled(collect(home))
    assert r.status == PASS


# ---------------------------------------------------------------------------
# FAIL: the sink is ON *and* it is pointed at a browser OpenClaw does not own
# ---------------------------------------------------------------------------

# Every shape below writes a `driver`/`attachOnly` key by hand. OpenClaw synthesizes its
# own `user` (driver "existing-session") and `chrome` (driver "extension") profiles at
# RESOLVE time only (config-DpWXcVmn.js:391-410) and never writes them back to
# openclaw.json -- createBrowserProfileConfig() persists a `driver` only when the
# operator passed one to `openclaw browser create-profile` (config-mutations-C1EW6ctD.js
# :100-150). So none of these can appear in a config the operator did not write.
_UNOWNED_SESSION_BROWSERS = {
    "explicit_existing_session": {
        "profiles": {"user": {"driver": "existing-session", "cdpUrl": "http://127.0.0.1:9222"}},
    },
    "existing_session_no_cdp_url": {
        "profiles": {"work": {"driver": "existing-session"}},
    },
    "extension_driver": {
        # docs/tools/browser.md:324 -- `driver: "extension"` "drives your signed-in
        # Chrome through the OpenClaw Chrome extension".
        "profiles": {"chrome": {"driver": "extension"}},
    },
    "profile_attach_only_remote_cdp": {
        "profiles": {"far": {"attachOnly": True, "cdpUrl": "http://10.20.30.40:9222"}},
    },
    "inherited_attach_only_remote_cdp": {
        # config-DpWXcVmn.js:589 -- effective attach-only is
        # `profile.attachOnly ?? resolved.attachOnly`, so the top-level key is inherited.
        "attachOnly": True,
        "profiles": {"far": {"cdpUrl": "http://10.20.30.40:9222"}},
    },
    "top_level_attach_only_remote_cdp": {
        "attachOnly": True,
        "cdpUrl": "http://10.20.30.40:9222",
    },
}


def test_repro_config_fails_and_the_grade_drops(tmp_path):
    """THE REGRESSION THIS BRANCH EXISTS FOR.

    The agent's browser attached to the operator's real logged-in Chrome
    (driver "existing-session"), the arbitrary-JS sink at its vendor default ON, and no
    hostnameAllowlist -- so any page an injection steers the agent to reaches the sink,
    inside a browser holding every live session that user is signed into. A flat WARN
    reported that as an A with zero FAILs; it is a FAIL, and the grade must say so.
    """
    repro = {
        "enabled": True,
        "evaluateEnabled": True,
        "defaultProfile": "user",
        "attachOnly": True,
        "profiles": {"user": {"driver": "existing-session", "cdpUrl": "http://127.0.0.1:9222"}},
        "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": False},
    }
    _, f_repro, s_repro = _audit_browser_home(tmp_path, "repro", repro)
    assert _b196(f_repro).status == FAIL

    closed = dict(repro, evaluateEnabled=False)
    _, f_closed, s_closed = _audit_browser_home(tmp_path, "closed", closed)
    assert _b196(f_closed).status == PASS
    assert s_repro.score < s_closed.score
    assert s_repro.grade != s_closed.grade


def test_every_unowned_session_shape_fails(tmp_path):
    """Each corroborator, on its own, escalates the sink-ON state to FAIL."""
    for name, browser in _UNOWNED_SESSION_BROWSERS.items():
        r = check_browser_evaluate_enabled(
            collect(_home(tmp_path / f"on_{name}", config={"browser": browser}))
        )
        assert r.status == FAIL, f"{name} should FAIL with the sink on, got {r.status}"
        assert r.evidence, f"{name} must name the corroborating key in evidence"


def test_closing_the_sink_passes_even_on_an_unowned_session(tmp_path):
    """The corroborator escalates the SINK; it is not a finding in its own right (that is
    B322's job). With evaluateEnabled=false there is no sink to escalate."""
    for name, browser in _UNOWNED_SESSION_BROWSERS.items():
        r = check_browser_evaluate_enabled(
            collect(_home(tmp_path / f"off_{name}", config={"browser": dict(browser, evaluateEnabled=False)}))
        )
        assert r.status == PASS, f"{name} with the sink closed should PASS, got {r.status}"


def test_absent_and_explicit_true_agree_at_the_corroborated_bar_too(tmp_path):
    """THE UNIFICATION GUARD, re-asserted at the FAIL bar.

    Escalating one spelling but not the other would re-open exactly the gameable no-op
    edit the effective-state fix closed -- in the other direction.
    """
    for name, browser in _UNOWNED_SESSION_BROWSERS.items():
        absent = check_browser_evaluate_enabled(
            collect(_home(tmp_path / f"a_{name}", config={"browser": browser}))
        )
        explicit = check_browser_evaluate_enabled(
            collect(_home(tmp_path / f"b_{name}", config={"browser": dict(browser, evaluateEnabled=True)}))
        )
        assert absent.status == explicit.status == FAIL, name
        assert absent.detail == explicit.detail.replace(
            "browser.evaluateEnabled=true", "browser.evaluateEnabled is not set"
        ), f"{name}: the two spellings must state the same effective fact"


def test_deleting_the_key_does_not_change_the_grade_when_corroborated(tmp_path):
    """The no-op-edit guard, at the FAIL bar: same score, same grade, either spelling."""
    browser = _UNOWNED_SESSION_BROWSERS["explicit_existing_session"]
    _, f_absent, s_absent = _audit_browser_home(tmp_path, "c_absent", browser)
    _, f_true, s_true = _audit_browser_home(
        tmp_path, "c_true", dict(browser, evaluateEnabled=True)
    )
    assert _b196(f_absent).status == _b196(f_true).status == FAIL
    assert s_true.score == s_absent.score
    assert s_true.grade == s_absent.grade


# ---------------------------------------------------------------------------
# THE FLEET-WIDE FALSE-POSITIVE GUARD (§5). Mandatory: an ordinary browser config
# must NOT be dragged into the FAIL branch by the escalation above.
# ---------------------------------------------------------------------------

_ORDINARY_BROWSERS = {
    # The commonest real shape by far: a `browser` block with no profiles at all.
    "bare": {"noSandbox": False},
    "explicit_true_only": {"evaluateEnabled": True},
    "managed_profile": {"profiles": {"openclaw": {"cdpPort": 18800}}},
    # "openclaw" and its legacy alias "clawd" are OpenClaw's OWN managed Chrome
    # (zod-schema-O9ml_nmo.js:1120-1124) -- not a foreign session.
    "explicit_openclaw_driver": {"profiles": {"work": {"driver": "openclaw", "cdpPort": 18801}}},
    "legacy_clawd_driver": {"profiles": {"work": {"driver": "clawd", "cdpPort": 18802}}},
    # attachOnly alone rebinds nothing off-host; a loopback CDP endpoint is the local
    # managed one OpenClaw would have used anyway.
    "attach_only_loopback": {"attachOnly": True, "cdpUrl": "http://127.0.0.1:9222"},
    "attach_only_profile_loopback": {
        "profiles": {"near": {"attachOnly": True, "cdpUrl": "http://localhost:9222"}}
    },
    "attach_only_no_cdp_url": {"attachOnly": True},
    "remote_cdp_without_attach_only": {"cdpUrl": "http://10.20.30.40:9222"},
    # Extra flags that have nothing to do with which browser is driven.
    "headless_no_sandbox": {"headless": True, "noSandbox": True},
    "with_allowlist": {"ssrfPolicy": {"hostnameAllowlist": ["example.com"]}},
    "defaultProfile_openclaw": {"defaultProfile": "openclaw"},
    # Malformed/unexpected shapes must degrade to the WARN bar, never guess a FAIL.
    "profiles_not_a_dict": {"profiles": ["user"]},
    "profile_spec_not_a_dict": {"profiles": {"user": "existing-session"}},
    "driver_not_a_string": {"profiles": {"user": {"driver": ["existing-session"], "cdpPort": 1}}},
    "unparseable_cdp_url": {"attachOnly": True, "cdpUrl": ":::not a url:::"},
}


def test_ordinary_browser_configs_stay_warn(tmp_path):
    """§5: no false-positive FAIL. Every shape here is a browser config an ordinary
    operator plausibly ships -- none of them hands the agent a foreign browser session,
    so none may be escalated past WARN by the sink alone."""
    for name, browser in _ORDINARY_BROWSERS.items():
        r = check_browser_evaluate_enabled(
            collect(_home(tmp_path / f"ok_{name}", config={"browser": browser}))
        )
        assert r.status == WARN, f"{name} must stay WARN, got {r.status} (false positive)"
        assert "vendor default for this key is true" in r.detail
    # ...and with the sink closed they are all PASS, none of them a FAIL by another route.
    for name, browser in _ORDINARY_BROWSERS.items():
        r = check_browser_evaluate_enabled(
            collect(_home(tmp_path / f"okoff_{name}", config={"browser": dict(browser, evaluateEnabled=False)}))
        )
        assert r.status == PASS, f"{name} with the sink closed must PASS, got {r.status}"


def test_ordinary_browser_config_never_reaches_the_fail_grade(tmp_path):
    """End-to-end companion to the guard above: the plain default-browser config a
    typical user ships must not be capped by a B196 FAIL anywhere in a full audit."""
    _, findings, _ = _audit_browser_home(tmp_path, "fleet", {"noSandbox": False})
    assert _b196(findings).status == WARN
    assert "B196" not in [f.id for f in findings if f.status == FAIL]


# ---------------------------------------------------------------------------
# On-disk fixtures for the FAIL branch
# ---------------------------------------------------------------------------

def test_bad_unowned_session_fixture_fails():
    r = check_browser_evaluate_enabled(
        collect(FIXTURES / "bad_b196_browser_evaluate_unowned_session")
    )
    assert r.status == FAIL
    assert any("existing-session" in e for e in r.evidence)


def test_clean_unowned_session_fixture_passes():
    """Same config, sink closed -- the one edit that fixes it. (tests/test_fp_corpus.py
    independently enrolls this `clean_*` home in the zero-FAIL §5 gate.)"""
    r = check_browser_evaluate_enabled(
        collect(FIXTURES / "clean_b196_browser_evaluate_unowned_session")
    )
    assert r.status == PASS


def test_bad_unowned_session_fixture_drops_the_grade():
    _, findings, score = audit(FIXTURES / "bad_b196_browser_evaluate_unowned_session")
    _, _, clean_score = audit(FIXTURES / "clean_b196_browser_evaluate_unowned_session")
    assert _b196(findings).status == FAIL
    assert score.score < clean_score.score
    assert score.grade != clean_score.grade


# ---------------------------------------------------------------------------
# B196's FAIL branch must stay REACHABLE (the "HIGH check that cannot move the
# grade" pattern this project's own logic audit flagged).
# ---------------------------------------------------------------------------

def test_all_four_statuses_are_reachable(tmp_path):
    reached = set()
    reached.add(check_browser_evaluate_enabled(collect(_home(tmp_path / "u", config={}))).status)
    reached.add(
        check_browser_evaluate_enabled(
            collect(_home(tmp_path / "p", config={"browser": {"evaluateEnabled": False}}))
        ).status
    )
    reached.add(
        check_browser_evaluate_enabled(
            collect(_home(tmp_path / "w", config={"browser": {"noSandbox": False}}))
        ).status
    )
    reached.add(
        check_browser_evaluate_enabled(
            collect(
                _home(
                    tmp_path / "f",
                    config={"browser": {"profiles": {"user": {"driver": "existing-session"}}}},
                )
            )
        ).status
    )
    assert reached == {UNKNOWN, PASS, WARN, FAIL}


def test_fail_finding_is_scored_and_high():
    """A HIGH check whose FAIL cannot move the grade is the defect this branch closes."""
    _, findings, _ = audit(FIXTURES / "bad_b196_browser_evaluate_unowned_session")
    f = _b196(findings)
    assert f.status == FAIL
    assert f.severity == "HIGH"
    assert f.scored is True
