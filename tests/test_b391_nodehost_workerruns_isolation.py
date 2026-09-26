"""B391 (CLAWSECCHECK-F-198) — nodeHost.workerRuns execution-isolation disclosure.

Re-grounded directly against the installed 2026.9.5 dist — the internal schema-recon
doc's descriptions map has no `nodeHost.workerRuns` entry at all (same documented gap
class as B390/attachments). See checks/_config.py::check_nodehost_workerruns_isolation
for the full grounding (dist/schema-CwAIqZVE.mjs:892-896 descriptions,
dist/zod-schema-DN2u5FdA.mjs:576-580 `NodeHostWorkerRunsSchema`) and
tests/dist_verified_paths.txt (nodeHost.workerRuns.{enabled,isolation,containerImage},
regenerated against the installed 2026.9.5 dist) for the machine-checked layer.

Verdicts:
  PASS    : `nodeHost.workerRuns.enabled` is not `true` (absent, `false`, or any other
            non-`true` shape — the vendor default), so no worker session runs on this
            node at all; OR it is enabled with `isolation: "container"` (the vendor's
            own isolated option).
  WARN    : `enabled: true` and `isolation` resolves to anything other than
            `"container"` (absent, `"none"`, or an unrecognized value all collapse to
            the vendor's own host-execution default). Advisory only
            (CheckMeta.scored=False) — never moves the grade.
  UNKNOWN : (a) config unreadable/unparseable (engine-side), or (b) no config was read
            at all — not_applicable=True in that second case only, mirroring B4/B351's
            own "nothing to look at" idiom.
  (no FAIL — workerRuns is an explicit opt-in feature whose own documented default is
  the less-isolated option; see the check's own docstring for the full reasoning.)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import clawseccheck.checks as C
from clawseccheck.catalog import BY_ID, FAIL, LOW, PASS, UNKNOWN, WARN
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

# A minimal, realistic sandboxed baseline — mirrors the idiom already used across the
# fixture corpus (e.g. fixtures/clean_b390_attachments_ttl_set/openclaw.json).
_BASELINE = {
    "gateway": {
        "bind": "127.0.0.1:8080",
        "auth": {"mode": "token", "token": "a-very-long-token-of-32-characters"},
    },
    "agents": {"defaults": {"sandbox": {"mode": "all"}}},
}


def _ctx(cfg: dict, *, config_found: bool = True, parse_error: bool = False) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_parse_error = parse_error
    c.config_found = config_found
    return c


def _finding_direct(cfg: dict):
    return C.check_nodehost_workerruns_isolation(_ctx(cfg))


def _finding_via_home(cfg: dict, tmp_path):
    """Round-trip through collect()/run_all(), matching how the real audit invokes it."""
    home = tmp_path
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    return next(f for f in C.run_all(ctx) if f.id == "B391")


# ---- catalog sanity ----

def test_b391_is_catalogued_advisory_unscored_low():
    meta = BY_ID["B391"]
    assert meta.block == "advisory"
    assert meta.scored is False
    assert meta.severity == LOW


# ---- PASS: workerRuns not enabled (absent, or enabled anything but true) ----

def test_no_nodehost_at_all_passes():
    f = _finding_direct({**_BASELINE})
    assert f.status == PASS


def test_workerruns_absent_under_nodehost_passes():
    cfg = {**_BASELINE, "nodeHost": {"mcp": {"servers": {}}}}
    f = _finding_direct(cfg)
    assert f.status == PASS


def test_enabled_false_passes():
    cfg = {**_BASELINE, "nodeHost": {"workerRuns": {"enabled": False}}}
    f = _finding_direct(cfg)
    assert f.status == PASS


def test_enabled_non_bool_truthy_does_not_count_as_true():
    # Only a real `True` counts as opted-in — a stray string/number must not be
    # read as enabling the feature (mirrors B390's bool-vs-int isinstance discipline).
    cfg = {**_BASELINE, "nodeHost": {"workerRuns": {"enabled": "true"}}}
    f = _finding_direct(cfg)
    assert f.status == PASS


# ---- PASS: enabled + isolation="container" (the vendor's own isolated option) ----

def test_enabled_with_container_isolation_passes():
    cfg = {**_BASELINE, "nodeHost": {"workerRuns": {"enabled": True, "isolation": "container"}}}
    f = _finding_direct(cfg)
    assert f.status == PASS
    assert "container" in f.detail
    assert "node:24.19.0-slim" in f.detail  # default image named when none is set


def test_enabled_with_container_isolation_and_custom_image_names_it():
    cfg = {
        **_BASELINE,
        "nodeHost": {
            "workerRuns": {
                "enabled": True,
                "isolation": "container",
                "containerImage": "registry.internal/node:24.19.0-slim@sha256:deadbeef",
            }
        },
    }
    f = _finding_direct(cfg)
    assert f.status == PASS
    assert "registry.internal/node" in f.detail


# ---- WARN: enabled + isolation resolves to the host-execution default ----

def test_enabled_with_no_isolation_set_warns():
    cfg = {**_BASELINE, "nodeHost": {"workerRuns": {"enabled": True}}}
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "none" in f.detail


def test_enabled_with_explicit_none_isolation_warns():
    cfg = {**_BASELINE, "nodeHost": {"workerRuns": {"enabled": True, "isolation": "none"}}}
    f = _finding_direct(cfg)
    assert f.status == WARN


def test_enabled_with_unrecognized_isolation_value_warns():
    # Not a shape the real _enum(["none","container"]) schema would accept either —
    # treated the same as absent/none, not as a false PASS (same "unread layer defaults
    # to the permissive/less-isolated reading" doctrine B390 documents for ttlHours).
    cfg = {**_BASELINE, "nodeHost": {"workerRuns": {"enabled": True, "isolation": "sandbox"}}}
    f = _finding_direct(cfg)
    assert f.status == WARN
    assert "sandbox" in f.detail


# ---- UNKNOWN: no config read at all — not_applicable ----

def test_empty_config_is_unknown_and_not_applicable():
    f = _finding_direct({})
    assert f.status == UNKNOWN
    assert f.not_applicable is True


# ---- UNKNOWN: config truly unreadable — distinct from the "no config" case above ----

def test_unparseable_config_is_engine_degraded_unknown():
    c = Context(home=Path("/nonexistent"))
    c.config = {}
    c.config_parse_error = True
    f = C.check_nodehost_workerruns_isolation(c)
    assert f.status == UNKNOWN
    assert f.engine_degraded is True
    assert f.not_applicable is False


def test_unread_config_is_unknown_not_a_false_pass():
    """A real host that was simply never scanned (config_found=False) must not
    silently read as 'unset' and PASS — that would assert a fact about a host nobody
    actually looked at. Also distinct from the 'no config' UNKNOWN above: config was
    never read, so this stays plain UNKNOWN, not not_applicable."""
    f = C.check_nodehost_workerruns_isolation(_ctx({}, config_found=False))
    assert f.status == UNKNOWN
    assert f.not_applicable is False


# ---- never FAIL ----

def test_never_fail():
    for cfg in (
        {},
        {**_BASELINE},
        {**_BASELINE, "nodeHost": {"workerRuns": {"enabled": True}}},
        {**_BASELINE, "nodeHost": {"workerRuns": {"enabled": True, "isolation": "none"}}},
        {**_BASELINE, "nodeHost": {"workerRuns": {"enabled": True, "isolation": "container"}}},
        {**_BASELINE, "nodeHost": {"workerRuns": {"enabled": True, "isolation": "bogus"}}},
    ):
        assert _finding_direct(cfg).status != FAIL, (
            f"B391 must never return FAIL; got FAIL for {cfg}"
        )


# ---- fixtures, round-tripped through the real audit pipeline ----

def test_the_bad_fixture_fires_and_the_clean_one_does_not():
    for name, expected in (
        ("bad_b391_workerruns_unisolated", WARN),
        ("clean_b391_workerruns_disabled", PASS),
    ):
        ctx = collect(FIXTURES / name)
        f = next(fi for fi in C.run_all(ctx) if fi.id == "B391")
        assert f.status == expected, name


def test_the_no_config_fixture_is_not_applicable():
    ctx = collect(FIXTURES / "unknown_b391_no_config")
    f = next(fi for fi in C.run_all(ctx) if fi.id == "B391")
    assert f.status == UNKNOWN
    assert f.not_applicable is True


def test_full_pipeline_round_trip_matches_direct_call(tmp_path):
    cfg = {**_BASELINE, "nodeHost": {"workerRuns": {"enabled": True, "isolation": "container"}}}
    assert _finding_via_home(cfg, tmp_path).status == _finding_direct(cfg).status == PASS
