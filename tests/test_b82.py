"""B82 — cache-trace diagnostics persist full turn transcripts to disk.

Offline, read-only, stdlib only.

Grounding (installed dist, openclaw 2026.7.x):
  - `diagnostics.cacheTrace.enabled` is the gate — `dist/selection-JInn13lc.js:1050`
        enabled = parseBooleanValue(env.OPENCLAW_CACHE_TRACE) ?? config?.enabled ?? false
  - `logging.cacheTrace.*` does NOT exist (0 hits in the package) and the `logging` zod
    object is `.strict()`, so a config carrying it is rejected outright. Reading it made
    B82's "not configured" branch an affirmative false claim for anyone who had tracing on.
  - cache-trace payloads are redacted UNCONDITIONALLY by `redactAgentDiagnosticPayload`
    (`selection-JInn13lc.js:828`); `logging.redactSensitive` is not consulted there, so it
    must not move this verdict either.

Verdicts: WARN on `enabled:true`; PASS on explicit `false` or unset (documented default);
UNKNOWN only when `enabled` is present but not a boolean (config rejected at load time).
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_cachetrace_redaction
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _ctx(cfg: dict) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    return c


def _b82(cfg: dict):
    return check_cachetrace_redaction(_ctx(cfg))


# ── the gate is `enabled` ───────────────────────────────────────────────────────

def test_b82_enabled_true_is_warn():
    assert _b82({"diagnostics": {"cacheTrace": {"enabled": True}}}).status == WARN


def test_b82_enabled_false_is_pass():
    assert _b82({"diagnostics": {"cacheTrace": {"enabled": False}}}).status == PASS


def test_b82_absent_diagnostics_is_pass():
    """Unset means the documented default (`config?.enabled ?? false`) applies. Not
    UNKNOWN: the OPENCLAW_CACHE_TRACE env var overrides an explicit `enabled:false`
    exactly as it overrides an absent key, so env-uncertainty cannot separate the two —
    and treating unset as UNKNOWN would leave B82 unable to PASS at all."""
    assert _b82({"logging": {"redactSensitive": "tools"}}).status == PASS


def test_b82_absent_cachetrace_key_under_diagnostics_is_pass():
    assert _b82({"diagnostics": {}}).status == PASS


# ── C-135: `filePath` must NOT be the gate ──────────────────────────────────────

def test_b82_filepath_set_but_disabled_is_pass_not_warn():
    """THE false-positive guard. A naive 1:1 port of the old check keyed on `filePath`,
    which would WARN here — but `resolveCacheTraceConfig` writes nothing when
    `enabled` is false, no matter what `filePath` says."""
    cfg = {"diagnostics": {"cacheTrace": {
        "enabled": False, "filePath": "~/.openclaw/cache-trace.jsonl"}}}
    assert _b82(cfg).status == PASS


def test_b82_filepath_alone_without_enabled_is_pass_not_warn():
    """`filePath` set and `enabled` never stated: the default is off, so nothing is
    written. This is the shape the pre-fix check would have flagged."""
    cfg = {"diagnostics": {"cacheTrace": {"filePath": "~/.openclaw/cache-trace.jsonl"}}}
    assert _b82(cfg).status == PASS


def test_b82_enabled_without_filepath_still_warns():
    """`enabled:true` with no `filePath` still writes to the default
    `$OPENCLAW_STATE_DIR/logs/cache-trace.jsonl`, so it must not be excused."""
    f = _b82({"diagnostics": {"cacheTrace": {"enabled": True}}})
    assert f.status == WARN
    assert any("logs/cache-trace.jsonl" in e for e in f.evidence)


def test_b82_default_path_evidence_names_the_env_override():
    """`resolveCacheTraceConfig` resolves `config?.filePath?.trim() ||
    env.OPENCLAW_CACHE_TRACE_FILE?.trim()` before falling back to the state-dir default
    (`selection-JInn13lc.js:1052`), so evidence claiming a bare unconditional default
    would overstate what the config alone can tell us."""
    f = _b82({"diagnostics": {"cacheTrace": {"enabled": True}}})
    assert any("OPENCLAW_CACHE_TRACE_FILE" in e for e in f.evidence)


# ── the phantom path is gone ────────────────────────────────────────────────────

def test_b82_phantom_logging_cachetrace_does_not_drive_the_verdict():
    """B-262 regression: `logging.cacheTrace.filePath` is not a real OpenClaw field, so
    a config carrying it is no evidence that cache tracing is on. The pre-fix check read
    exactly this and WARNed on it."""
    cfg = {"logging": {"cacheTrace": {"filePath": "~/.openclaw/t.jsonl"},
                       "redactSensitive": "off"}}
    assert _b82(cfg).status == PASS


def test_b82_pass_detail_makes_no_unqualified_real_world_claim():
    """The lying PASS was the SENTENCE as much as the path: 'No cache-trace transcript
    file is configured, so full transcripts are not persisted to disk' asserted a fact
    about disk that the check had no evidence for. Every PASS must stay config-scoped."""
    for cfg in ({"logging": {"redactSensitive": "tools"}},
                {"diagnostics": {"cacheTrace": {"enabled": False}}}):
        f = _b82(cfg)
        assert f.status == PASS
        assert "No cache-trace transcript file is configured" not in f.detail


def test_b82_remediation_does_not_recommend_a_rejected_field():
    """`logging` is a `.strict()` zod object; telling a user to set
    `logging.cacheTrace.filePath` would make OpenClaw reject the whole config."""
    for cfg in ({"diagnostics": {"cacheTrace": {"enabled": True}}},
                {"diagnostics": {"cacheTrace": {"enabled": False}}},
                {"logging": {"redactSensitive": "tools"}}):
        f = _b82(cfg)
        assert "logging.cacheTrace" not in f.fix
        assert "logging.cacheTrace" not in f.detail


def test_b82_does_not_key_on_redactsensitive():
    """Cache-trace payloads go through `redactAgentDiagnosticPayload` unconditionally
    (`selection-JInn13lc.js:828`); `logging.redactSensitive` is never consulted by that
    module, so it must not move B82's verdict."""
    on = {"diagnostics": {"cacheTrace": {"enabled": True}}}
    assert _b82(dict(on, logging={"redactSensitive": "tools"})).status == WARN
    assert _b82(dict(on, logging={"redactSensitive": "off"})).status == WARN


# ── non-boolean / malformed ─────────────────────────────────────────────────────

def test_b82_non_boolean_enabled_is_unknown():
    """zod declares `enabled` a boolean inside a `.strict()` object, so a non-boolean is
    rejected at load time — we genuinely cannot say what the agent is running. This is
    the one branch where the state is undeterminable rather than merely undeclared."""
    for val in (1, "true", "yes", None):
        cfg = {"diagnostics": {"cacheTrace": {"enabled": val}}}
        assert _b82(cfg).status == UNKNOWN, val


def test_b82_unknown_is_distinct_from_the_key_being_absent():
    """`dig()` collapses "absent" and "present but null" to None; B82 must not."""
    assert _b82({"diagnostics": {"cacheTrace": {}}}).status == PASS
    assert _b82({"diagnostics": {"cacheTrace": {"enabled": None}}}).status == UNKNOWN


def test_b82_malformed_cachetrace_container_is_unknown_not_pass():
    """The same principle one level UP. `diagnostics.cacheTrace` is declared as a
    `.strict()` object, and the schema uses `.optional()` with zero `.nullable()`
    anywhere, so a string / list / null there is rejected at load time just as a
    non-boolean `enabled` is. The key is NOT "unset" — the container is malformed and the
    running state is undeterminable, so asserting "unset and defaults to false" would be
    an affirmative false claim, the exact GR#4 failure B82 was repaired to remove."""
    for bad in ("true", None, [], 0, "off"):
        f = _b82({"diagnostics": {"cacheTrace": bad}})
        assert f.status == UNKNOWN, bad
        assert "defaults to false" not in f.detail, bad


def test_b82_malformed_diagnostics_container_is_unknown_not_pass():
    """And one level up again — `diagnostics` itself is a `.strict().optional()` object
    (`zod-schema-O9ml_nmo.js:1050-1057`)."""
    for bad in ("on", None, [], 42):
        f = _b82({"diagnostics": bad})
        assert f.status == UNKNOWN, bad
        assert "defaults to false" not in f.detail, bad


def test_b82_no_malformed_shape_yields_an_affirmative_unset_claim():
    """Sweep: every reachable malformed shape must avoid the affirmative sentence. A PASS
    here is only legitimate when the key or a container is GENUINELY absent."""
    malformed = [
        {"diagnostics": "on"},
        {"diagnostics": None},
        {"diagnostics": []},
        {"diagnostics": {"cacheTrace": "true"}},
        {"diagnostics": {"cacheTrace": None}},
        {"diagnostics": {"cacheTrace": []}},
        {"diagnostics": {"cacheTrace": {"enabled": "true"}}},
        {"diagnostics": {"cacheTrace": {"enabled": None}}},
        {"diagnostics": {"cacheTrace": {"enabled": 1}}},
    ]
    for cfg in malformed:
        f = _b82(cfg)
        assert f.status == UNKNOWN, cfg
        assert "is unset" not in f.detail, cfg


def test_b82_genuinely_absent_containers_still_pass():
    """The counterweight to the three tests above: narrowing PASS must not swallow the
    B-228 invariant that a valid config declaring nothing dangerous PASSes. A bare `{}`
    has no `diagnostics` key at all."""
    for cfg in ({}, {"diagnostics": {}}, {"diagnostics": {"cacheTrace": {}}},
                {"logging": {"redactSensitive": "tools"}}):
        assert _b82(cfg).status == PASS, cfg


# ── fixtures ────────────────────────────────────────────────────────────────────

def test_b82_clean_fixture_pass():
    f = check_cachetrace_redaction(collect(FIXTURES / "clean_b82_cachetrace_redaction"))
    assert f.status == PASS


def test_b82_bad_fixture_warn():
    f = check_cachetrace_redaction(collect(FIXTURES / "bad_b82_cachetrace_redaction"))
    assert f.status == WARN


def test_b82_unknown_fixture_unknown():
    f = check_cachetrace_redaction(collect(FIXTURES / "unknown_b82_cachetrace_nonboolean"))
    assert f.status == UNKNOWN


def test_b82_registered_in_audit():
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "bad_b82_cachetrace_redaction", include_native=False)
    assert "B82" in {f.id for f in findings}


def test_b82_never_fails_on_the_clean_fixture():
    """GR#5: the clean fixture must not pick up a FAIL from this check's rewrite."""
    from clawseccheck import audit

    _, findings, _ = audit(FIXTURES / "clean_b82_cachetrace_redaction", include_native=False)
    assert [f.id for f in findings if f.id == "B82" and f.status == FAIL] == []
