"""B-282 (ENV-2/ENV-6) — global dotenv reader + caveat-aware B82 + break-glass toggles.

`resolveCacheTraceConfig` is
``parseBooleanValue(env.OPENCLAW_CACHE_TRACE) ?? config?.enabled ?? false``
(dist/selection-JInn13lc.js:1050) — the environment WINS over the config. B82 read only
the config and therefore stated affirmatively that transcripts "are not being appended to
disk" while OpenClaw appended them on every turn.

Scope boundary these tests exist to hold: EXACTLY the two global runtime dotenv files. The
workspace `.env` blocks the whole ``OPENCLAW_`` prefix, so reading it would be a
guaranteed false positive.
"""
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    check_cachetrace_redaction,
    check_env_breakglass_toggles,
)
from clawseccheck.collector import (
    collect,
    global_dotenv_paths,
    is_truthy_env_value,
    parse_boolean_value,
)

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# --------------------------------------------------------------------------
# The truthiness mirrors. Three DIFFERENT dist predicates; collapsing them
# would misreport at least two of the three variables.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("token", ["true", "1", "yes", "on", "TRUE", " On ", "YES"])
def test_parse_boolean_value_truthy_set(token):
    """boolean-CrriykWV.js:3-8 — the truthy tokens, case/space-insensitive."""
    assert parse_boolean_value(token) is True


@pytest.mark.parametrize("token", ["false", "0", "no", "off", "OFF", " 0 "])
def test_parse_boolean_value_falsy_set(token):
    """boolean-CrriykWV.js:9-14 — falsy tokens must NOT read as 'set, therefore on'."""
    assert parse_boolean_value(token) is False


@pytest.mark.parametrize("token", ["", "maybe", "2", "enabled", "y"])
def test_parse_boolean_value_is_tristate_for_ambiguous_input(token):
    """undefined lets the `?? config?.enabled` chain fall through. No guessing."""
    assert parse_boolean_value(token) is None


def test_is_truthy_env_value_is_binary_not_tristate():
    """env-CKdem44B.js:46-55 has NO falsy set — anything unrecognised is simply false."""
    assert is_truthy_env_value("1") is True
    assert is_truthy_env_value("yes") is True
    assert is_truthy_env_value("off") is False
    assert is_truthy_env_value("maybe") is False


# --------------------------------------------------------------------------
# The reader: exactly two global files, and never the workspace .env
# --------------------------------------------------------------------------

def test_global_dotenv_paths_are_exactly_the_two_the_dist_loads(tmp_path):
    home = tmp_path / ".openclaw"
    paths = global_dotenv_paths(home, env={"HOME": str(tmp_path)})
    assert paths == [home / ".env", tmp_path / ".config" / "openclaw" / "gateway.env"]


def test_reader_parses_the_home_dotenv():
    ctx = collect(FIXTURES / "bad_b82_cachetrace_dotenv_override")
    assert ctx.dotenv_found is True
    assert ctx.dotenv_values["OPENCLAW_CACHE_TRACE"] == "1"


def test_reader_ignores_a_workspace_dotenv():
    """The headline FP guard. BLOCKED_WORKSPACE_DOTENV_PREFIXES contains "OPENCLAW_"
    (dist/dotenv-eb21SB3p.js:181), so this key never reaches process.env and is not
    evidence of anything. OPENCLAW_CACHE_TRACE is additionally in the explicit
    BLOCKED_WORKSPACE_DOTENV_KEYS set (:128)."""
    ctx = collect(FIXTURES / "clean_b82_cachetrace_workspace_dotenv")
    assert ctx.dotenv_found is False
    assert "OPENCLAW_CACHE_TRACE" not in ctx.dotenv_values


def test_gateway_env_is_read_from_the_second_global_slot(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    gw = tmp_path / ".config" / "openclaw" / "gateway.env"
    gw.parent.mkdir(parents=True)
    gw.write_text("OPENCLAW_CACHE_TRACE=1\n")
    ctx = collect(home)
    assert ctx.dotenv_values["OPENCLAW_CACHE_TRACE"] == "1"
    assert str(gw) in ctx.dotenv_sources["OPENCLAW_CACHE_TRACE"]


def test_first_file_wins_over_the_second(tmp_path):
    """loadParsedDotEnvFiles keeps the FIRST definition (dotenv-global:47-65)."""
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    (home / ".env").write_text("OPENCLAW_CACHE_TRACE=0\n")
    gw = tmp_path / ".config" / "openclaw" / "gateway.env"
    gw.parent.mkdir(parents=True)
    gw.write_text("OPENCLAW_CACHE_TRACE=1\n")
    ctx = collect(home)
    assert ctx.dotenv_values["OPENCLAW_CACHE_TRACE"] == "0"


@pytest.mark.parametrize(
    "line,expected",
    [
        ("OPENCLAW_CACHE_TRACE=1", "1"),
        ("export OPENCLAW_CACHE_TRACE=1", "1"),
        ('OPENCLAW_CACHE_TRACE="1"', "1"),
        ("OPENCLAW_CACHE_TRACE='1'", "1"),
        ("  OPENCLAW_CACHE_TRACE = 1  ", "1"),
        ("OPENCLAW_CACHE_TRACE=1 # debugging", "1"),
    ],
)
def test_parser_handles_the_common_dotenv_spellings(tmp_path, line, expected):
    """Assert the invariant over a matrix of spellings, not one."""
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    (home / ".env").write_text(line + "\n")
    assert collect(home).dotenv_values.get("OPENCLAW_CACHE_TRACE") == expected


def test_parser_skips_comments_and_blank_and_malformed_lines(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    (home / ".env").write_text(
        "# OPENCLAW_CACHE_TRACE=1\n\n"
        "NOT_AN_ASSIGNMENT\n"
        "9INVALID=x\n"
        "OPENCLAW_LOG_LEVEL=info\n"
    )
    values = collect(home).dotenv_values
    assert "OPENCLAW_CACHE_TRACE" not in values   # commented out
    assert "9INVALID" not in values               # not a portable env key
    assert values["OPENCLAW_LOG_LEVEL"] == "info"


def test_a_symlinked_dotenv_is_not_followed(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    real = tmp_path / "elsewhere.env"
    real.write_text("OPENCLAW_CACHE_TRACE=1\n")
    (home / ".env").symlink_to(real)
    assert collect(home).dotenv_found is False


def test_fixtures_dir_has_no_shared_gateway_env():
    """Guard for future maintainers, not a property of today's code.

    ``gateway.env`` resolves to ``home.parent/.config/openclaw/gateway.env``. Every
    fixture home's parent is ``fixtures/``, so a file checked in there would be picked up
    by EVERY fixture scan at once and silently contaminate unrelated tests. Test the
    gateway slot with tmp_path only.
    """
    assert not (FIXTURES / ".config").exists()


# --------------------------------------------------------------------------
# B82 becomes caveat-aware
# --------------------------------------------------------------------------

def test_b82_warns_when_a_global_dotenv_overrides_a_disabled_config():
    """The reproduced lying-PASS: config enabled=false, env turns tracing on."""
    ctx = collect(FIXTURES / "bad_b82_cachetrace_dotenv_override")
    assert ctx.config["diagnostics"]["cacheTrace"]["enabled"] is False
    f = check_cachetrace_redaction(ctx)
    assert f.status == WARN
    assert "OPENCLAW_CACHE_TRACE" in " ".join(f.evidence)


def test_b82_no_longer_asserts_transcripts_are_not_written():
    """The specific false sentence this task was filed for must be gone from BOTH
    PASS branches — it was false whenever the env override was set."""
    for name in ("clean_b82_cachetrace_redaction", "clean_b82_cachetrace_dotenv_falsy"):
        f = check_cachetrace_redaction(collect(FIXTURES / name))
        assert f.status == PASS, name
        assert "are not being appended to disk" not in f.detail, name


def test_b82_pass_is_affirmed_by_a_falsy_override():
    ctx = collect(FIXTURES / "clean_b82_cachetrace_dotenv_falsy")
    assert ctx.dotenv_values["OPENCLAW_CACHE_TRACE"] == "0"
    assert check_cachetrace_redaction(ctx).status == PASS


def test_b82_ignores_a_workspace_dotenv_override():
    """FP guard: the product discards this key, so it must not move B82's verdict."""
    f = check_cachetrace_redaction(collect(FIXTURES / "clean_b82_cachetrace_workspace_dotenv"))
    assert f.status == PASS


def test_b82_falls_through_to_the_config_on_an_unparseable_override(tmp_path):
    """`parseBooleanValue` returns undefined, so `?? config?.enabled` decides. Reporting
    a WARN here would invent a state the product does not enter."""
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text(
        '{"diagnostics": {"cacheTrace": {"enabled": false}}}')
    (home / ".env").write_text("OPENCLAW_CACHE_TRACE=perhaps\n")
    assert check_cachetrace_redaction(collect(home)).status == PASS


def test_b82_is_unknown_when_a_dotenv_exists_but_settles_nothing(tmp_path):
    """A global dotenv is present, the key is absent, and the audited home is not this
    user's own — GR#4 says report UNKNOWN, not an affirmative all-clear."""
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text(
        '{"diagnostics": {"cacheTrace": {"enabled": false}}}')
    (home / ".env").write_text("OPENCLAW_LOG_LEVEL=info\n")
    f = check_cachetrace_redaction(collect(home))
    assert f.status == UNKNOWN
    assert "cannot confirm" in f.detail or "cannot" in f.detail


def test_b82_stays_pass_for_a_self_audit_with_an_unrelated_dotenv(tmp_path, monkeypatch):
    """The UNKNOWN branch must NOT fire on a real self-audit.

    A user who keeps ``OPENCLAW_LOG_LEVEL`` in ``~/.openclaw/.env`` has a global dotenv
    that says nothing about cache tracing. On their OWN home the process environment is
    also readable, so the question IS settled and the answer is PASS. Turning that into
    UNKNOWN would make the check useless for the audience it is for — this is why the
    UNKNOWN branch is gated on the home NOT being this user's own.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("OPENCLAW_CACHE_TRACE", raising=False)
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text(
        '{"diagnostics": {"cacheTrace": {"enabled": false}}}')
    (home / ".env").write_text("OPENCLAW_LOG_LEVEL=info\n")
    ctx = collect(home)
    assert ctx.dotenv_found is True
    assert check_cachetrace_redaction(ctx).status == PASS


def test_b82_never_fails_on_any_of_these_paths():
    """B82 is scored=False and has no FAIL path; an env read must not introduce one."""
    for name in (
        "bad_b82_cachetrace_dotenv_override",
        "clean_b82_cachetrace_dotenv_falsy",
        "clean_b82_cachetrace_workspace_dotenv",
        "clean_b82_cachetrace_redaction",
        "bad_b82_cachetrace_redaction",
    ):
        assert check_cachetrace_redaction(collect(FIXTURES / name)).status != FAIL, name


# --------------------------------------------------------------------------
# B192 — ENV-6 break-glass toggles
# --------------------------------------------------------------------------

def test_b192_warns_on_allow_insecure_private_ws():
    f = check_env_breakglass_toggles(collect(FIXTURES / "bad_env6_breakglass_toggle"))
    assert f.status == WARN
    assert "OPENCLAW_ALLOW_INSECURE_PRIVATE_WS" in " ".join(f.evidence)


def test_b192_never_fails():
    """It is a DOCUMENTED break-glass — OpenClaw's own plugin docs instruct users to set
    it. A FAIL would punish following the vendor manual."""
    assert check_env_breakglass_toggles(
        collect(FIXTURES / "bad_env6_breakglass_toggle")).status != FAIL


def test_b192_passes_when_a_dotenv_carries_no_toggle():
    f = check_env_breakglass_toggles(collect(FIXTURES / "clean_env6_no_toggles"))
    assert f.status == PASS


@pytest.mark.parametrize("value", ["true", "yes", "on", "0", "false", ""])
def test_allow_insecure_private_ws_only_counts_when_it_is_exactly_1(tmp_path, value):
    """connection-details-BBobR8Xp.js:27 is a strict `=== "1"`, NOT parseBooleanValue.

    Using the wrong predicate here would WARN on `=true`, a value that provably does not
    enable the break-glass — a false positive on a setting that changes nothing.
    """
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    (home / ".env").write_text(f"OPENCLAW_ALLOW_INSECURE_PRIVATE_WS={value}\n")
    assert check_env_breakglass_toggles(collect(home)).status == PASS


def test_load_shell_env_uses_the_binary_truthy_predicate(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    (home / ".env").write_text("OPENCLAW_LOAD_SHELL_ENV=yes\n")
    f = check_env_breakglass_toggles(collect(home))
    assert f.status == WARN
    assert "OPENCLAW_LOAD_SHELL_ENV" in " ".join(f.evidence)


@pytest.mark.parametrize("var", ["OPENCLAW_SHOW_SECRETS", "OPENCLAW_CLI_CONTAINER_BYPASS"])
def test_deliberately_excluded_variables_never_produce_a_finding(tmp_path, var):
    """Both are GR#5 traps, verified against the installed dist:

    OPENCLAW_SHOW_SECRETS is INVERTED — ``showSecrets: env.OPENCLAW_SHOW_SECRETS?.trim()
    !== "0"`` (status.scan-Bm3xXn8C.js:34) means display is ON by default and only "0"
    changes anything, in the HARDENING direction. Warning on it being set would warn
    about the default.

    OPENCLAW_CLI_CONTAINER_BYPASS is the CLI's container-delegation recursion guard,
    injected by OpenClaw itself (startup-trace-Bc2ebu8Y.js:176-177) — set is the normal
    state inside any containerized install.
    """
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text("{}")
    (home / ".env").write_text(f"{var}=1\n")
    assert check_env_breakglass_toggles(collect(home)).status == PASS


def test_b192_is_registered_and_unscored():
    from clawseccheck.catalog import BY_ID
    from clawseccheck.checks import CHECKS
    assert check_env_breakglass_toggles in CHECKS
    assert BY_ID["B192"].scored is False


# --------------------------------------------------------------------------
# Hermeticity: the auditor's own environment must never steer a --home scan
# --------------------------------------------------------------------------

@pytest.mark.parametrize("var", ["OPENCLAW_CACHE_TRACE", "OPENCLAW_ALLOW_INSECURE_PRIVATE_WS"])
def test_process_env_does_not_leak_into_a_foreign_home_scan(tmp_path, monkeypatch, var):
    """Golden Rule #5: a fixture scan must be reproducible regardless of the environment
    the tool happens to run in. The process env is gated behind the audited-home-identity
    predicate; without that gate this run would emit an environment-driven finding."""
    monkeypatch.setenv(var, "1")
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True)
    (home / "openclaw.json").write_text(
        '{"diagnostics": {"cacheTrace": {"enabled": false}}}')
    ctx = collect(home)
    assert check_cachetrace_redaction(ctx).status == PASS
    assert check_env_breakglass_toggles(ctx).status in (PASS, UNKNOWN)
