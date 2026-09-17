"""C-412 — raw-content egress checks: B365 (diagnostics.otel content capture) and B366
(memory.search.remote embedding egress).

Both checks replace a filed task stub that got two of its three cited paths wrong,
re-grounded against the INSTALLED dist (openclaw@2026.9.3):

- B365: the stub described diagnostics.otel.captureContent as a granular object
  ({enabled, inputMessages, outputMessages, toolInputs, toolOutputs, systemPrompt,
  toolDefinitions}). That shape is RETIRED — legacy-D51FqLiI.mjs's
  migrateFinalLayoutKills collapses any old object-shaped captureContent to a plain
  boolean on every config load. The real runtime gate for content capture
  (resolveDiagnosticModelContentCapturePolicy, dist/worker/worker.mjs, traced by
  executing its body) is a 4-key conjunction: diagnostics.enabled not-false AND
  otel.enabled===true AND otel.traces not-false AND otel.captureContent===true.
  Reading captureContent alone (the stub's own proposed WARN condition) would
  false-positive on otel.enabled left unset — a real, plausible shape (captureContent
  flipped on while experimenting, otel itself never enabled).

- B366: the stub's cited path `agents.defaults.memorySearch.remote.*` does not exist.
  The real path is `memory.search.remote.*` — at the config ROOT (global,
  MemorySchema.search) and, separately, PER-AGENT
  (agents.entries.<id>.memory.search.remote.*, via AgentEntrySchema — NOT reachable
  under agents.defaults at all; AgentDefaultsSchema has no memory key).

- The stub's third item, `memory.qmd.sessions.exportDir`, is dropped entirely: the QMD
  memory backend is RETIRED (legacy-D51FqLiI.mjs names it explicitly — "memory.qmd is
  retired because the QMD memory backend was removed; configured external paths migrate
  to memory.search.extraPaths"). There is no field left to audit.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    check_memory_search_remote_egress,
    check_otel_content_capture_egress,
)
from clawseccheck.collector import Context


def _ctx(cfg: dict, parse_error: bool = False) -> Context:
    c = Context(home=Path("/nonexistent"))
    c.config = cfg
    c.config_parse_error = parse_error
    c.config_found = True  # B-661: `cfg` stands for a real, found config
    return c


def _blob(f) -> str:
    return " ".join(f.evidence or []) + " " + (f.detail or "") + " " + (f.fix or "")


# ===========================================================================
# B365 — diagnostics.otel content capture
# ===========================================================================


def _otel_cfg(**otel_fields):
    return {"diagnostics": {"otel": otel_fields}}


class TestOtelContentCaptureGate:
    """Pins the 4-key conjunction traced from resolveDiagnosticModelContentCapturePolicy
    — each key alone, left at its permissive/absent default, must keep capture OFF."""

    def test_no_diagnostics_at_all_passes(self):
        f = check_otel_content_capture_egress(_ctx({}))
        assert f.status == PASS

    def test_otel_absent_passes(self):
        f = check_otel_content_capture_egress(_ctx({"diagnostics": {"enabled": True}}))
        assert f.status == PASS

    def test_capture_content_true_but_otel_not_enabled_passes(self):
        """The false-positive shape the stub's own proposed condition (captureContent
        alone) would have produced: captureContent left on from experimenting, but
        otel.enabled was never flipped true."""
        cfg = _otel_cfg(captureContent=True, traces=True)
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == PASS

    def test_capture_content_true_but_otel_enabled_false_passes(self):
        cfg = _otel_cfg(enabled=False, captureContent=True, traces=True)
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == PASS

    def test_traces_false_blocks_capture_even_when_everything_else_on(self):
        cfg = {
            "diagnostics": {
                "enabled": True,
                "otel": {"enabled": True, "traces": False, "captureContent": True},
            }
        }
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == PASS

    def test_diagnostics_enabled_false_blocks_capture(self):
        cfg = {
            "diagnostics": {
                "enabled": False,
                "otel": {"enabled": True, "captureContent": True},
            }
        }
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == PASS

    def test_capture_content_absent_passes_even_with_otel_enabled(self):
        cfg = _otel_cfg(enabled=True, traces=True)
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == PASS

    def test_all_four_gates_open_is_the_only_active_shape(self):
        cfg = {
            "diagnostics": {
                "enabled": True,
                "otel": {"enabled": True, "traces": True, "captureContent": True},
            }
        }
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status in (WARN, FAIL)


class TestOtelDestinationClassification:
    def test_capture_active_no_endpoint_configured_warns_env_fallback(self):
        cfg = {
            "diagnostics": {
                "otel": {"enabled": True, "captureContent": True},
            }
        }
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == WARN
        assert "OTEL_EXPORTER_OTLP_ENDPOINT" in _blob(f)

    def test_capture_active_https_endpoint_warns_not_fails(self):
        cfg = {
            "diagnostics": {
                "otel": {
                    "enabled": True,
                    "captureContent": True,
                    "endpoint": "https://collector.example.com:4318",
                },
            }
        }
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == WARN

    def test_capture_active_loopback_http_warns_not_fails(self):
        cfg = {
            "diagnostics": {
                "otel": {
                    "enabled": True,
                    "captureContent": True,
                    "endpoint": "http://127.0.0.1:4318",
                },
            }
        }
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == WARN

    def test_capture_active_private_network_http_warns(self):
        cfg = {
            "diagnostics": {
                "otel": {
                    "enabled": True,
                    "captureContent": True,
                    "endpoint": "http://192.168.1.50:4318",
                },
            }
        }
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == WARN
        assert "192.168.1.50" in _blob(f)

    def test_capture_active_public_http_fails(self):
        cfg = {
            "diagnostics": {
                "enabled": True,
                "otel": {
                    "enabled": True,
                    "traces": True,
                    "captureContent": True,
                    "endpoint": "http://collector.example.com:4318",
                },
            }
        }
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == FAIL
        assert "collector.example.com" in _blob(f)

    def test_traces_endpoint_overrides_shared_endpoint(self):
        """tracesEndpoint is the per-signal override the schema description names
        explicitly — a safe shared endpoint must not mask a bad traces-specific one."""
        cfg = {
            "diagnostics": {
                "otel": {
                    "enabled": True,
                    "captureContent": True,
                    "endpoint": "https://safe.example.com",
                    "tracesEndpoint": "http://leaky.example.com:4318",
                },
            }
        }
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == FAIL
        assert "leaky.example.com" in _blob(f)
        assert "safe.example.com" not in _blob(f)

    def test_never_claims_system_prompt_is_captured(self):
        """Golden Rule #4: the runtime hardcodes systemPrompt:false regardless of
        captureContent — the finding text must not claim it is captured."""
        cfg = {
            "diagnostics": {
                "otel": {
                    "enabled": True,
                    "captureContent": True,
                    "endpoint": "https://collector.example.com",
                },
            }
        }
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert "never the system prompt" in _blob(f)


class TestOtelHeaderSecrets:
    def test_header_with_inline_secret_warns_even_without_capture(self):
        cfg = _otel_cfg(enabled=True, headers={"Authorization": "sk-ant-abcdefgh12345678"})
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == WARN
        assert "diagnostics.otel.headers.Authorization" in _blob(f)

    def test_header_with_env_reference_not_flagged(self):
        cfg = _otel_cfg(enabled=True, headers={"Authorization": "${OTEL_COLLECTOR_TOKEN}"})
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == PASS

    def test_headers_ignored_when_otel_not_enabled(self):
        """No HTTP export happens at all when otel.enabled is not true — a header value
        cannot be exfiltrated by an exporter that never runs."""
        cfg = _otel_cfg(enabled=False, headers={"Authorization": "sk-ant-abcdefgh12345678"})
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == PASS


class TestOtelMalformed:
    def test_unreadable_config_is_unknown(self):
        f = check_otel_content_capture_egress(_ctx({}, parse_error=True))
        assert f.status == UNKNOWN

    def test_diagnostics_not_a_dict_is_unknown(self):
        f = check_otel_content_capture_egress(_ctx({"diagnostics": "nope"}))
        assert f.status == UNKNOWN

    def test_otel_not_a_dict_is_unknown(self):
        f = check_otel_content_capture_egress(_ctx({"diagnostics": {"otel": "nope"}}))
        assert f.status == UNKNOWN

    def test_capture_content_retired_object_shape_is_unknown(self):
        """Regression pin: the stub's originally-described granular shape
        ({enabled, inputMessages, ...}) is retired on the current dist — a config
        carrying it is malformed against the current .strict() schema, not a richer
        signal to parse. Must be UNKNOWN, never silently ignored as falsy-and-PASS."""
        cfg = _otel_cfg(enabled=True, captureContent={"enabled": True, "inputMessages": True})
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == UNKNOWN

    def test_otel_enabled_not_a_bool_is_unknown(self):
        cfg = _otel_cfg(enabled="yes")
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == UNKNOWN

    def test_traces_not_a_bool_is_unknown(self):
        cfg = _otel_cfg(enabled=True, traces="yes")
        f = check_otel_content_capture_egress(_ctx(cfg))
        assert f.status == UNKNOWN


class TestOtelMeta:
    def test_catalog_entry(self):
        meta = BY_ID["B365"]
        assert meta.surface == "secrets"
        assert meta.scored is True


# ===========================================================================
# B366 — memory.search.remote embedding egress
# ===========================================================================


class TestMemorySearchRemoteGlobal:
    def test_no_memory_key_at_all_passes(self):
        f = check_memory_search_remote_egress(_ctx({}))
        assert f.status == PASS

    def test_https_remote_baseurl_passes(self):
        cfg = {"memory": {"search": {"remote": {"baseUrl": "https://embeddings.example.com"}}}}
        f = check_memory_search_remote_egress(_ctx(cfg))
        assert f.status == PASS

    def test_http_loopback_passes(self):
        cfg = {"memory": {"search": {"remote": {"baseUrl": "http://127.0.0.1:8080"}}}}
        f = check_memory_search_remote_egress(_ctx(cfg))
        assert f.status == PASS

    def test_http_private_network_warns(self):
        cfg = {"memory": {"search": {"remote": {"baseUrl": "http://192.168.1.9:8080"}}}}
        f = check_memory_search_remote_egress(_ctx(cfg))
        assert f.status == WARN
        assert "192.168.1.9" in _blob(f)

    def test_http_public_host_fails(self):
        cfg = {"memory": {"search": {"remote": {"baseUrl": "http://embeddings.example.com"}}}}
        f = check_memory_search_remote_egress(_ctx(cfg))
        assert f.status == FAIL
        assert "embeddings.example.com" in _blob(f)
        assert "memory.search.remote" in _blob(f)

    def test_apikey_presence_disclosed_but_never_echoed(self):
        cfg = {
            "memory": {
                "search": {
                    "remote": {
                        "baseUrl": "http://embeddings.example.com",
                        "apiKey": "sk-ant-supersecretvalue1234",
                    }
                }
            }
        }
        f = check_memory_search_remote_egress(_ctx(cfg))
        assert f.status == FAIL
        blob = _blob(f)
        assert "remote.apiKey is also configured" in blob
        assert "sk-ant-supersecretvalue1234" not in blob

    def test_no_baseurl_but_apikey_set_is_not_flagged(self):
        """This check only judges the baseUrl's egress shape (matching B178's own
        precedent of never guessing a provider's default endpoint) — apiKey alone,
        with no baseUrl, is out of scope here (and already swept by B1's generic
        secret-at-rest walk, gated on file permissions)."""
        cfg = {"memory": {"search": {"remote": {"apiKey": "sk-ant-supersecretvalue1234"}}}}
        f = check_memory_search_remote_egress(_ctx(cfg))
        assert f.status == PASS

    def test_non_dict_remote_value_passes(self):
        cfg = {"memory": {"search": {"remote": "not-a-dict"}}}
        f = check_memory_search_remote_egress(_ctx(cfg))
        assert f.status == PASS


class TestMemorySearchRemotePerAgent:
    def test_agent_entries_shape_bad_baseurl_fails_with_agent_label(self):
        cfg = {
            "agents": {
                "entries": {
                    "researcher": {
                        "memory": {"search": {"remote": {"baseUrl": "http://leak.example.com"}}}
                    }
                }
            }
        }
        f = check_memory_search_remote_egress(_ctx(cfg))
        assert f.status == FAIL
        assert "agents.entries.researcher.memory.search.remote" in _blob(f)

    def test_legacy_agents_list_shape_bad_baseurl_fails_with_agent_label(self):
        cfg = {
            "agents": {
                "list": [
                    {
                        "id": "researcher",
                        "memory": {"search": {"remote": {"baseUrl": "http://leak.example.com"}}},
                    }
                ]
            }
        }
        f = check_memory_search_remote_egress(_ctx(cfg))
        assert f.status == FAIL
        assert "memory.search.remote" in _blob(f)

    def test_global_safe_one_agent_bad_still_fails(self):
        cfg = {
            "memory": {"search": {"remote": {"baseUrl": "https://safe.example.com"}}},
            "agents": {
                "entries": {
                    "a": {"memory": {"search": {"remote": {"baseUrl": "https://also-safe.example.com"}}}},
                    "b": {"memory": {"search": {"remote": {"baseUrl": "http://leak.example.com"}}}},
                }
            },
        }
        f = check_memory_search_remote_egress(_ctx(cfg))
        assert f.status == FAIL
        assert "agents.entries.b.memory.search.remote" in _blob(f)

    def test_all_scopes_clean_passes(self):
        cfg = {
            "memory": {"search": {"remote": {"baseUrl": "https://safe.example.com"}}},
            "agents": {
                "entries": {
                    "a": {"memory": {"search": {"remote": {"baseUrl": "https://also-safe.example.com"}}}},
                }
            },
        }
        f = check_memory_search_remote_egress(_ctx(cfg))
        assert f.status == PASS


class TestMemorySearchRemoteMalformed:
    def test_unreadable_config_is_unknown(self):
        f = check_memory_search_remote_egress(_ctx({}, parse_error=True))
        assert f.status == UNKNOWN


class TestMemorySearchRemoteMeta:
    def test_catalog_entry(self):
        meta = BY_ID["B366"]
        assert meta.surface == "tools"
