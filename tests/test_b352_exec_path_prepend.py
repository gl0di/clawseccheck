"""B352 — `tools.exec.pathPrepend`: what OpenClaw puts ahead of the agent's PATH.

Grounded on the code that APPLIES the setting, not on the descriptions map.
`wrapPosixCommandWithPathPrepend` (bash-tools.exec-runtime-u4DiNcL4.js) rewrites the
command itself —

    export PATH="${OPENCLAW_PREPEND_PATH}${PATH:+:$PATH}"; unset ...; <command>

— with the vendor's stated reason: "This ensures our paths take precedence even if user
RC files (e.g. ~/.zshenv) prepend their own entries to PATH during shell startup." So an
entry here outranks the operator's own shell configuration by design.

Three grounded facts shape these tests, and each would be a defect if missed:

* `pathPrepend: agentExec?.pathPrepend ?? globalExec?.pathPrepend` — an agent's list
  REPLACES the global one (agent-tools-BD8WL7ny.js). Reading the global key alone misses
  a list only one agent has.
* `host: "node"` makes the runtime IGNORE the list, with its own warning. Reporting a
  hijack risk there would be a finding about a setting the engine discards.
* `pathPrepend` is in `PATH_LIST_KEYS`, so `~/bin` is resolved through `resolveUserPath`
  before it reaches the runtime (io-By0s-a_s.js) — a tilde entry is absolute, not relative.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from clawseccheck.catalog import BY_ID, HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    CHECKS,
    _b352_effective_prepends,
    _b352_risky,
    check_exec_path_prepend,
)
from clawseccheck.collector import Context, collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _f(name: str):
    return check_exec_path_prepend(collect(FIXTURES / name))


def _ctx(cfg, tmp_path):
    return Context(home=tmp_path, config=cfg, config_found=True)


# ------------------------------------------------------------------ safe stays quiet
@pytest.mark.parametrize("name", [
    "clean_b352_no_prepend",
    "clean_b352_absolute_owner_only",
    "clean_b352_ignored_under_node_host",
])
def test_clean_fixtures_pass(name):
    f = _f(name)
    assert f.status == PASS, f"{name}: expected PASS, got {f.status}: {f.detail}"


def test_an_absolute_owner_only_entry_is_still_listed():
    """A PASS that names what is ahead of PATH is more useful than a bare "clean"."""
    f = _f("clean_b352_absolute_owner_only")
    assert "/usr/local/bin" in f.detail


# ------------------------------------------------------------------ it fires
@pytest.mark.parametrize("name,needle", [
    ("bad_b352_relative_entry", "relative"),
    ("bad_b352_tmp_entry", "temp directory"),
    ("bad_b352_agent_only_prepend", "temp directory"),
])
def test_hijackable_entries_warn(name, needle):
    f = _f(name)
    assert f.status == WARN, f"{name}: got {f.status}: {f.detail}"
    assert needle in f.detail
    assert "binary-hijack" in f.detail


def test_an_agent_only_list_is_not_missed():
    """The per-agent lying-PASS: global is safe, one agent replaces it with /tmp.

    `pathPrepend` resolves with `??`, so the agent's list is what actually applies for
    that agent — the global `/usr/local/bin` is not merged with it, it is discarded.
    """
    f = _f("bad_b352_agent_only_prepend")
    assert f.status == WARN
    assert "agents.list[builder]" in f.detail
    assert "/tmp/builder-bin" in f.detail


def test_the_agent_that_did_not_set_one_is_not_blamed():
    f = _f("bad_b352_agent_only_prepend")
    assert "agents.list[main]" not in f.detail


def test_it_never_fails():
    for name in ("bad_b352_relative_entry", "bad_b352_tmp_entry",
                 "bad_b352_agent_only_prepend"):
        assert _f(name).status != "FAIL", name


# ------------------------------------------------------------------ the node-host mitigation
def test_a_list_under_host_node_is_not_reported_as_a_risk():
    """The runtime ignores pathPrepend when host=node and says so in its own warning.

    `./bin` is relative and would otherwise WARN; under host=node it must not, because
    nothing applies it.
    """
    f = _f("clean_b352_ignored_under_node_host")
    assert f.status == PASS
    assert "host=node" in f.detail


def test_the_skip_is_disclosed_rather_than_silent():
    """A scope that was not assessed must say so — silence would read as "assessed and
    clean", which is the shape this project keeps finding."""
    f = _f("clean_b352_ignored_under_node_host")
    assert "Not assessed for" in f.detail


def test_the_pass_text_does_not_describe_an_empty_list():
    """When every configured list sits under host=node there is nothing to call
    owner-only; an earlier version rendered "absolute and owner-only: ." here."""
    f = _f("clean_b352_ignored_under_node_host")
    assert "owner-only: ." not in f.detail


# ------------------------------------------------------------------ the tilde rule
def test_a_tilde_entry_is_absolute_not_relative():
    """`~/bin` reaches the runtime already resolved; calling it relative would be a false
    positive on the commonest way an owner writes their own bin directory.

    A REALISTIC home is used deliberately, not pytest's `tmp_path`. `ctx.home` is
    `~/.openclaw`, so the tilde resolves against its PARENT — the `~` slot, the same slot
    `_detail_path` reasons about. Under `tmp_path` the parent is `/tmp/pytest-of-…`, and
    the entry would be flagged as living in a temp directory: a true answer about a home
    no real run has, which is a probe that cannot see what it is probing.
    """
    home = "/home/someone/.openclaw"
    assert _b352_risky("~/bin", home) is None
    assert _b352_risky("~", home) is None


def test_the_risk_predicate_discriminates():
    assert "relative" in (_b352_risky("./bin", "/home/x") or "")
    assert "relative" in (_b352_risky("bin", "/home/x") or "")
    assert "temp" in (_b352_risky("/tmp/x", "/home/x") or "")
    assert "temp" in (_b352_risky("/dev/shm/x", "/home/x") or "")
    assert _b352_risky("/usr/bin", "/home/x") is None
    for junk in ("", "   ", None, 7, []):
        assert _b352_risky(junk, "/home/x") is None, junk


# ------------------------------------------------------------------ the layering model
def test_an_agent_without_its_own_list_inherits_the_global_one(tmp_path):
    cfg = {"tools": {"exec": {"pathPrepend": ["/opt/tools"]}},
           "agents": {"list": [{"id": "a"}]}}
    scopes = _b352_effective_prepends(cfg)
    assert ("agents.list[a].tools.exec", None, ["/opt/tools"]) in scopes


def test_an_agent_list_replaces_rather_than_merges(tmp_path):
    cfg = {"tools": {"exec": {"pathPrepend": ["/opt/tools"]}},
           "agents": {"list": [{"id": "a", "tools": {"exec": {"pathPrepend": ["/opt/other"]}}}]}}
    scopes = dict((s, e) for s, _h, e in _b352_effective_prepends(cfg))
    assert scopes["agents.list[a].tools.exec"] == ["/opt/other"], "?? replaces, never merges"


def test_an_agent_inherits_the_global_host_for_the_skip(tmp_path):
    """`host: agentExec?.host ?? globalExec?.host` — a global host=node covers agents
    that do not override it, so their inherited list must be skipped too."""
    cfg = {"tools": {"exec": {"host": "node", "pathPrepend": ["./bin"]}},
           "agents": {"list": [{"id": "a"}]}}
    assert check_exec_path_prepend(_ctx(cfg, tmp_path)).status == PASS


# ------------------------------------------------------------------ UNKNOWN, not a fake PASS
def test_an_unread_config_is_unknown(tmp_path):
    f = check_exec_path_prepend(Context(home=tmp_path, config={}, config_found=False))
    assert f.status == UNKNOWN and f.not_applicable is False


def test_a_read_but_empty_config_is_not_applicable(tmp_path):
    f = check_exec_path_prepend(Context(home=tmp_path, config={}, config_found=True))
    assert f.status == UNKNOWN and f.not_applicable is True


# ------------------------------------------------------------------ hostile shapes
def test_malformed_shapes_do_not_raise(tmp_path):
    for cfg in (
        {"tools": "minimal"},
        {"tools": {"exec": "full"}},
        {"tools": {"exec": {"pathPrepend": "not-a-list"}}},
        {"tools": {"exec": {"pathPrepend": [None, 7, {}, "./ok"]}}},
        {"agents": {"list": [{"tools": {"exec": {"pathPrepend": ["./x"]}}}]}},
        {"agents": {"list": "nope"}},
    ):
        f = check_exec_path_prepend(_ctx(cfg, tmp_path))
        assert f.status in (PASS, WARN, UNKNOWN), cfg
        assert "\n" not in f.detail


# ------------------------------------------------------------------ wiring
def test_the_check_is_actually_registered():
    assert check_exec_path_prepend in CHECKS


def test_catalog_entry_matches_what_the_check_emits():
    meta = BY_ID["B352"]
    assert meta.severity == HIGH and meta.surface == "tools"
    emitted = _f("bad_b352_tmp_entry")
    assert emitted.id == "B352" and emitted.title == meta.title
