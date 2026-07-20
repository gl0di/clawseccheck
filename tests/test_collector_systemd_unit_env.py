"""B-289/B-290 — the systemd-unit environment reader in collector.py.

This is the primitive that both new checks and B2's softening rest on, so it is tested
directly rather than only through them. Every behaviour below is a mirror of a specific
line in the installed OpenClaw dist; the citations are in the collector's own comment
block. Where the dist's grammar is richer than this parser, the parser UNDER-READS: a
missed key costs a false negative, a mis-parsed one would cost a false WARN, and only the
former is acceptable.

Offline, read-only, stdlib only. Nothing is written outside tmp_path.
"""
from __future__ import annotations

import os
from pathlib import Path

from clawseccheck.collector import (
    Context,
    collect,
    env_evidence_readable,
    parse_systemd_env_assignments,
    persistent_env_evidence,
    systemd_unit_is_openclaw_related,
    systemd_user_unit_dir,
)

TOKEN_VAR = "OPENCLAW_GATEWAY_" + "TOKEN"
_VALUE = "w" * 10 + "3" + "cr" + "3t" + "5" * 10


# ---------------------------------------------------------------------------
# parse_systemd_env_assignments — mirrors systemd-unit-DVDnVbxX.js:70-110
# ---------------------------------------------------------------------------

def test_bare_assignment():
    assert parse_systemd_env_assignments("A=b") == [("A", "b")]


def test_several_assignments_on_one_line():
    assert parse_systemd_env_assignments("A=b C=d") == [("A", "b"), ("C", "d")]


def test_whole_assignment_quoted_keeps_inner_spaces():
    """The shape the real unit uses: Environment="OPENCLAW_WINDOWS_TASK_NAME=OpenClaw Gateway"."""
    assert parse_systemd_env_assignments('"A=b c"') == [("A", "b c")]


def test_quoted_and_bare_mixed_on_one_line():
    assert parse_systemd_env_assignments('"A=b c" D=e') == [("A", "b c"), ("D", "e")]


def test_single_quotes_behave_like_double():
    assert parse_systemd_env_assignments("'A=b c'") == [("A", "b c")]


def test_backslash_escape_is_honoured():
    assert parse_systemd_env_assignments(r"A=b\ c") == [("A", "b c")]


def test_a_quote_after_the_item_has_started_is_a_literal():
    """quoteStart: "item-start" (systemd-unit-DVDnVbxX.js:105) — a quote only opens a run
    at the start of a token, so this is NOT a way to smuggle a space into a value."""
    assert parse_systemd_env_assignments('A="b') == [("A", '"b')]


def test_value_may_contain_equals_signs():
    """Split at the FIRST '=' only (systemd-unit-DVDnVbxX.js:92-98)."""
    assert parse_systemd_env_assignments("A=b=c") == [("A", "b=c")]


def test_token_without_an_equals_is_dropped():
    assert parse_systemd_env_assignments("noequals") == []


def test_leading_equals_is_dropped():
    """`if (eq <= 0) return null` — an empty key is not a key."""
    assert parse_systemd_env_assignments("=b") == []


def test_non_portable_key_is_dropped():
    """A key the product would reject (normalizeEnvVarKey {portable:true}) is not a key
    the product will honour, so it is not evidence."""
    assert parse_systemd_env_assignments("A-B=c") == []
    assert parse_systemd_env_assignments("1A=c") == []


def test_empty_value_is_preserved_as_empty():
    assert parse_systemd_env_assignments("A=") == [("A", "")]


# ---------------------------------------------------------------------------
# The unit walk
# ---------------------------------------------------------------------------

def _home(root: Path, *, unit_lines: str = "", name: str = "openclaw-gateway.service",
          exec_start: str = "/usr/bin/openclaw gateway run") -> Path:
    home = root / ".openclaw"
    home.mkdir(exist_ok=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    unit_dir = root / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    (unit_dir / name).write_text(
        f"[Unit]\nDescription=x\n\n[Service]\nExecStart={exec_start}\n"
        + unit_lines
        + "\n[Install]\nWantedBy=default.target\n",
        encoding="utf-8",
    )
    return home


def test_unit_dir_is_derived_from_the_audited_home_not_the_auditor(tmp_path):
    """A fixture or --home scan must read the FIXTURE's units, never this machine's."""
    assert systemd_user_unit_dir(tmp_path / ".openclaw") == (
        tmp_path / ".config" / "systemd" / "user"
    )


def test_openclaw_relation_matches_name_or_execstart():
    assert systemd_unit_is_openclaw_related("openclaw-gateway.service", "/usr/bin/node x")
    assert systemd_unit_is_openclaw_related("svc.service", "/usr/bin/openclaw gateway run")
    assert not systemd_unit_is_openclaw_related("svc.service", "/usr/bin/other")


def test_environment_lines_are_collected(tmp_path):
    ctx = collect(_home(tmp_path, unit_lines="Environment=A=b\nEnvironment=C=d\n"))
    assert ctx.unit_env_found is True
    assert ctx.unit_env_values["A"] == "b"
    assert ctx.unit_env_values["C"] == "d"
    assert env_evidence_readable(ctx) is True


def test_commented_environment_line_is_ignored(tmp_path):
    ctx = collect(_home(tmp_path, unit_lines="#Environment=A=b\n"))
    assert "A" not in ctx.unit_env_values


def test_non_openclaw_unit_is_not_collected(tmp_path):
    ctx = collect(_home(tmp_path, unit_lines="Environment=A=b\n",
                        name="other.service", exec_start="/usr/bin/other"))
    assert ctx.unit_env_found is False
    assert "A" not in ctx.unit_env_values


def test_environment_file_is_followed(tmp_path):
    envfile = tmp_path / "extra.env"
    envfile.write_text("# a comment\n; another\nA=b\nquoted='c d'\n", encoding="utf-8")
    ctx = collect(_home(tmp_path, unit_lines=f"EnvironmentFile=-{envfile}\n"))
    assert ctx.unit_env_values["A"] == "b"
    assert ctx.unit_env_values["quoted"] == "c d"


def test_environment_file_overrides_the_inline_value(tmp_path):
    """Merge order {...inline, ...fromFiles} (systemd-B4Oq2owH.js:294-297)."""
    envfile = tmp_path / "extra.env"
    envfile.write_text("A=from-file\n", encoding="utf-8")
    ctx = collect(
        _home(tmp_path, unit_lines=f"Environment=A=from-inline\nEnvironmentFile={envfile}\n")
    )
    assert ctx.unit_env_values["A"] == "from-file"
    # ...but the inline attribution is preserved, which is what B193 keys on.
    assert "A" in ctx.unit_env_inline


def test_inline_map_records_the_unit_path_not_the_value(tmp_path):
    """§8: a caller reasoning about an inlined secret must not be handed a second copy."""
    ctx = collect(_home(tmp_path, unit_lines=f"Environment={TOKEN_VAR}={_VALUE}\n"))
    assert ctx.unit_env_inline[TOKEN_VAR].endswith("openclaw-gateway.service")
    assert _VALUE not in ctx.unit_env_inline[TOKEN_VAR]


def test_relative_environment_file_resolves_against_the_unit_dir(tmp_path):
    home = _home(tmp_path, unit_lines="EnvironmentFile=sidecar.env\n")
    (tmp_path / ".config" / "systemd" / "user" / "sidecar.env").write_text(
        "A=b\n", encoding="utf-8"
    )
    assert collect(home).unit_env_values["A"] == "b"


def test_missing_environment_file_is_skipped_silently(tmp_path):
    ctx = collect(_home(tmp_path, unit_lines="EnvironmentFile=-/nonexistent/none.env\n"))
    assert ctx.unit_env_found is True
    assert "A" not in ctx.unit_env_values


def test_home_specifier_is_expanded(tmp_path):
    """expandSystemdSpecifier expands ONLY %h (systemd-B4Oq2owH.js:400-402)."""
    (tmp_path / "spec.env").write_text("A=b\n", encoding="utf-8")
    ctx = collect(_home(tmp_path, unit_lines="EnvironmentFile=%h/spec.env\n"))
    assert ctx.unit_env_values["A"] == "b"


def test_unknown_specifier_is_not_guessed(tmp_path):
    """Any other %-specifier is dropped rather than resolved to the wrong file."""
    ctx = collect(_home(tmp_path, unit_lines="EnvironmentFile=%t/spec.env\n"))
    assert "A" not in ctx.unit_env_values


def test_symlinked_environment_file_is_not_followed(tmp_path):
    real = tmp_path / "real.env"
    real.write_text("A=b\n", encoding="utf-8")
    link = tmp_path / "link.env"
    os.symlink(real, link)
    ctx = collect(_home(tmp_path, unit_lines=f"EnvironmentFile={link}\n"))
    assert "A" not in ctx.unit_env_values


# ---------------------------------------------------------------------------
# persistent_env_evidence — the verdict-moving reader
# ---------------------------------------------------------------------------

def test_unit_value_beats_the_dotenv_value(tmp_path):
    """A key already in process.env when the agent starts blocks the dotenv file value
    entirely (dotenv-global-mWLbBl_z.js:44-46, :66), and the unit's Environment= is
    exactly such a key."""
    home = _home(tmp_path, unit_lines="Environment=A=from-unit\n")
    (home / ".env").write_text("A=from-dotenv\n", encoding="utf-8")
    value, source = persistent_env_evidence(collect(home), "A")
    assert value == "from-unit"
    assert "openclaw-gateway.service" in source


def test_dotenv_value_is_used_when_the_unit_is_silent(tmp_path):
    home = _home(tmp_path)
    (home / ".env").write_text("A=from-dotenv\n", encoding="utf-8")
    value, source = persistent_env_evidence(collect(home), "A")
    assert value == "from-dotenv"
    assert ".env" in source


def test_persistent_reader_never_falls_back_to_os_environ(tmp_path, monkeypatch):
    """The load-bearing guarantee. The auditing shell's environment is not the audited
    service's, so it must never move a verdict — that is what separates this reader from
    dotenv_override, which keeps its own os.environ leg for best-effort disclosure."""
    monkeypatch.setenv("SOME_AMBIENT_KEY", "set-in-the-audit-shell")
    ctx = collect(_home(tmp_path))
    assert persistent_env_evidence(ctx, "SOME_AMBIENT_KEY") == (None, None)


def test_blank_value_is_not_evidence(tmp_path):
    ctx = collect(_home(tmp_path, unit_lines="Environment=A=\n"))
    assert persistent_env_evidence(ctx, "A") == (None, None)


def test_env_evidence_readable_is_false_when_nothing_exists(tmp_path):
    home = tmp_path / ".openclaw"
    home.mkdir()
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    assert env_evidence_readable(collect(home)) is False


def test_a_bare_context_has_the_new_fields(tmp_path):
    """Checks are called with hand-built Contexts all over the suite; the new fields must
    default safely rather than raise."""
    ctx = Context(home=tmp_path)
    assert ctx.unit_env_values == {}
    assert ctx.unit_env_inline == {}
    assert ctx.unit_env_found is False
    assert persistent_env_evidence(ctx, "A") == (None, None)
    assert env_evidence_readable(ctx) is False


# ---------------------------------------------------------------------------
# Bounds — the unit is attacker-writable in the threat model these checks exist for
# ---------------------------------------------------------------------------

def test_environment_entries_are_capped(tmp_path):
    ctx = collect(_home(tmp_path,
                        unit_lines="\n".join(f"Environment=K{i}=v" for i in range(4000))))
    assert len(ctx.unit_env_values) <= 500


def test_environment_file_specs_are_capped(tmp_path):
    """`EnvironmentFile=` accepts arbitrary absolute paths, so an unbounded spec list
    would turn one 256KB unit into hundreds of thousands of open() calls."""
    ctx = collect(_home(
        tmp_path,
        unit_lines="\n".join(f"EnvironmentFile=-/nonexistent/f{i}.env" for i in range(5000)),
    ))
    assert ctx.unit_env_found is True  # completed rather than hanging


def test_oversized_unit_records_a_limit_hit(tmp_path):
    """A padded unit must surface as an explicit coverage gap, not a silent clean read."""
    filler = "\n".join(f"# {'x' * 200}" for _ in range(2000))
    ctx = collect(_home(tmp_path, unit_lines=filler))
    assert any("systemd unit" in h for h in ctx.limit_hits)
