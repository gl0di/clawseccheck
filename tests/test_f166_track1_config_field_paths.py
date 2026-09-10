"""F-166 track 1 — give the judge a structured config field path when a check has one.

Track 1 only: the own-config, engine-authored-literal channel this task's own design
trail (2026-08-04 through 2026-09-05, CLAWSECCHECK-F-166) repeatedly recommended funding
independently of the still-open, still-Dave's-call decision about whether attacker-
authored SKILL prose may ever reach the judge at all. That decision is untouched here —
this only wires the ~9 UNKNOWN-producing checks that read exactly one config field and
otherwise had nothing at all to show a judge (measured 2026-08-28: 172 of 175 real packet
items carry zero evidence entries).

`Finding.config_field_paths` is a NEW structured channel, set only at the check's own
dig() call site — never derived from evidence text (that channel, C-361's
`_config_field_paths`, already existed and is untouched; this one is additive and the two
are merged, structured first, in `adjudication._item_from_finding`).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from clawseccheck import adjudication as adj  # noqa: E402
from clawseccheck.catalog import Finding  # noqa: E402
from clawseccheck.checks import run_all  # noqa: E402
from clawseccheck.checks._capability import check_elevated_default_full  # noqa: E402
from clawseccheck.checks._config import (  # noqa: E402
    check_gateway_rate_limit,
    check_local_model_service_command,
    check_sandbox,
)
from clawseccheck.checks._lifecycle import check_secrets_provider_exec  # noqa: E402
from clawseccheck.checks._shared import _custom, _finding  # noqa: E402
from clawseccheck.collector import Context, collect  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures"
VULN = str(FIXTURES / "home_vuln")
SAFE = str(FIXTURES / "home_safe")


def _f(**kw) -> Finding:
    return Finding(id="B69", title="t", severity="MEDIUM", status="UNKNOWN",
                   detail="d", fix="f", framework="x", **kw)


def _minimal_ctx(config: dict) -> Context:
    ctx = Context(home="/tmp/f166-track1-nonexistent-home")
    ctx.config = config
    ctx.config_found = True
    ctx.config_parse_error = False
    return ctx


# --------------------------------------------------------------------------- Finding field

def test_config_field_paths_defaults_to_an_empty_frozenset():
    assert Finding(id="B1", title="t", severity="LOW", status="PASS", detail="d", fix="f",
                   framework="x").config_field_paths == frozenset()


def test_finding_helper_threads_config_field_paths():
    f = _finding("B69", "UNKNOWN", "d", "f", config_field_paths={"tools.exec.strictInlineEval"})
    assert f.config_field_paths == frozenset({"tools.exec.strictInlineEval"})


def test_finding_helper_defaults_when_omitted():
    f = _finding("B69", "UNKNOWN", "d", "f")
    assert f.config_field_paths == frozenset()


def test_custom_helper_threads_config_field_paths():
    f = _custom("B13", "HIGH", "UNKNOWN", "d", "f", config_field_paths={"a.b"})
    assert f.config_field_paths == frozenset({"a.b"})


# --------------------------------------------------------------------------- the merge

def test_structured_channel_alone_reaches_safe_facts():
    facts = adj._item_from_finding(_f(config_field_paths=frozenset({"tools.exec.mode"})))["safe_facts"]
    assert facts["config_field_paths"] == ["tools.exec.mode"]


def test_no_config_field_paths_key_when_neither_channel_has_anything():
    facts = adj._item_from_finding(_f())["safe_facts"]
    assert "config_field_paths" not in facts


def test_structured_and_evidence_channels_both_contribute_deduplicated():
    """A finding could in principle carry both — the merge must not drop either, and a
    path present in both must appear exactly once."""
    f = _f(
        config_field_paths=frozenset({"gateway.bind"}),
        evidence=["gateway.bind is set", "tools.profile is set"],
    )
    facts = adj._item_from_finding(f)["safe_facts"]
    assert facts["config_field_paths"] == ["gateway.bind", "tools.profile"]


def test_structured_paths_are_sorted_before_the_evidence_derived_ones():
    f = _f(config_field_paths=frozenset({"z.z", "a.a"}), evidence=[])
    facts = adj._item_from_finding(f)["safe_facts"]
    assert facts["config_field_paths"] == ["a.a", "z.z"]


def test_merged_list_is_capped_at_six():
    many = {f"gateway.field{i}" for i in range(10)}
    facts = adj._item_from_finding(_f(config_field_paths=frozenset(many)))["safe_facts"]
    assert len(facts["config_field_paths"]) == 6


def test_a_malformed_frozenset_member_does_not_crash_the_packet():
    """Type hint, not enforcement — same lesson B-386 recorded for sub_signals. Only
    strings are ever set by a real producer, but a caller mistake must degrade, not
    traceback."""
    facts = adj._item_from_finding(_f(config_field_paths=frozenset({"real.path", 12345})))["safe_facts"]
    assert "real.path" in facts["config_field_paths"]


# --------------------------------------------------------------------------- the 7 producers
# Each check reads exactly one config field and, on this specific UNKNOWN branch, has
# nothing else at all to show a judge. Verified DIRECTLY (a minimal Context, not a full
# fixture) since manufacturing the exact ambient trigger for every branch through a real
# fixture home would be far more fragile than asserting the wiring at its own call site —
# the merge/render path itself is covered end-to-end below (B56/B69) and by the tests above.

def test_b326_unresolved_env_var_substitution():
    ctx = _minimal_ctx({"agents": {"defaults": {"elevatedDefault": "${MY_VAR}"}}})
    f = check_elevated_default_full(ctx)
    assert f.status == "UNKNOWN"
    assert f.config_field_paths == frozenset({"agents.defaults.elevatedDefault"})


def test_b80_gateway_auth_mode_undetermined():
    ctx = _minimal_ctx({"gateway": {"bind": "0.0.0.0:8080"}})
    f = check_gateway_rate_limit(ctx)
    assert f.status == "UNKNOWN"
    assert f.config_field_paths == frozenset({"gateway.auth.mode"})


def test_b4_phantom_sandbox_key():
    ctx = _minimal_ctx({"sandbox": {"mode": "all"}})
    f = check_sandbox(ctx)
    assert f.status == "UNKNOWN"
    assert f.config_field_paths == frozenset({"agents.defaults.sandbox.mode"})


def test_b4_no_exec_tools_no_sandbox_config():
    ctx = _minimal_ctx({})
    f = check_sandbox(ctx)
    assert f.status == "UNKNOWN"
    assert f.config_field_paths == frozenset({"agents.defaults.sandbox.mode"})


def test_b355_models_providers_not_an_object():
    ctx = _minimal_ctx({"models": {"providers": "not-a-dict"}})
    f = check_local_model_service_command(ctx)
    assert f.status == "UNKNOWN"
    assert f.config_field_paths == frozenset({"models.providers"})


def test_b194_no_secrets_providers_configured():
    ctx = _minimal_ctx({})
    f = check_secrets_provider_exec(ctx)
    assert f.status == "UNKNOWN"
    assert f.config_field_paths == frozenset({"secrets.providers"})


def test_b194_secrets_providers_none_exec_based():
    ctx = _minimal_ctx({"secrets": {"providers": {"x": {"source": "env"}}}})
    f = check_secrets_provider_exec(ctx)
    assert f.status == "UNKNOWN"
    assert f.config_field_paths == frozenset({"secrets.providers"})


# --------------------------------------------------------------------------- end to end
# Per this task's own design trail: "The test must go through collect() -> run_all() ->
# build_judge_packet() on a fixture home. A test calling _item_from_finding directly
# stays green with the producer wiring deleted." B56/B69 both fire naturally on the
# existing fixtures/home_vuln and fixtures/home_safe (neither sets
# gateway.controlUi.allowedOrigins or tools.exec.strictInlineEval).

def test_end_to_end_b56_reaches_the_real_judge_packet():
    ctx = collect(VULN)
    findings = run_all(ctx)
    items = adj.build_judge_packet(ctx, findings)
    b56 = next(it for it in items if it["finding_id"] == "B56")
    assert b56["safe_facts"]["config_field_paths"] == ["gateway.controlUi.allowedOrigins"]


def test_end_to_end_b69_reaches_the_real_judge_packet():
    ctx = collect(SAFE)
    findings = run_all(ctx)
    items = adj.build_judge_packet(ctx, findings)
    b69 = next(it for it in items if it["finding_id"] == "B69")
    assert b69["safe_facts"]["config_field_paths"] == ["tools.exec.strictInlineEval"]


def test_end_to_end_field_paths_survive_json_rendering():
    ctx = collect(VULN)
    findings = run_all(ctx)
    raw = adj.render_judge_packet_json(ctx, findings, version="test")
    assert '"config_field_paths"' in raw
    assert "gateway.controlUi.allowedOrigins" in raw
