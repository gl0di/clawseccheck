"""B-166 — a present-but-unparseable openclaw.json is a distinct, machine-visible state.

Previously a broken config was caught, ctx.config reset to empty, and only ctx.errors
noted it — so --json carried no trace, and --exit-code (which only trips on FAIL) stayed
0. A hand-edited config with one stray syntax error could silently pass a CI gate. These
tests pin: the collector flags the state, --json surfaces it, and --exit-code trips.
Offline, read-only of the tmp_path sandbox, stdlib only.
"""
from __future__ import annotations

import json

from clawseccheck.cli import main
from clawseccheck.collector import collect

BASE = ["--no-native", "--no-history"]


def test_malformed_config_sets_parse_error_flag(tmp_path):
    (tmp_path / "openclaw.json").write_text('{"gateway": {')  # truncated -> invalid JSON
    ctx = collect(tmp_path)
    assert ctx.config_found is True
    assert ctx.config_parse_error is True
    assert ctx.config == {}


def test_non_object_config_is_a_parse_error(tmp_path):
    (tmp_path / "openclaw.json").write_text("[1, 2, 3]")  # valid JSON, wrong top-level shape
    ctx = collect(tmp_path)
    assert ctx.config_found is True
    assert ctx.config_parse_error is True


def test_valid_empty_config_is_not_a_parse_error(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}")
    ctx = collect(tmp_path)
    assert ctx.config_found is True
    assert ctx.config_parse_error is False


def test_missing_config_is_not_a_parse_error(tmp_path):
    ctx = collect(tmp_path)
    assert ctx.config_found is False
    assert ctx.config_parse_error is False


def test_json_output_surfaces_parse_error(tmp_path, capsys):
    (tmp_path / "openclaw.json").write_text('{"gateway": {')
    main(["--home", str(tmp_path), "--json"] + BASE)
    d = json.loads(capsys.readouterr().out)
    assert d["config_parse_error"] is True
    assert d["errors"], "parse error message must appear in JSON errors[]"


def test_json_output_no_false_parse_error_on_valid_config(tmp_path, capsys):
    (tmp_path / "openclaw.json").write_text("{}")
    main(["--home", str(tmp_path), "--json"] + BASE)
    d = json.loads(capsys.readouterr().out)
    assert d["config_parse_error"] is False


def test_exit_code_trips_on_parse_error(tmp_path):
    (tmp_path / "openclaw.json").write_text('{"gateway": {')
    rc = main(["--home", str(tmp_path), "--exit-code"] + BASE)
    assert rc == 1
