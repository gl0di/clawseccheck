"""B358/B359/B360 (CLAWSECCHECK-C-410) — gateway HTTP/remote/embed hardening, re-grounded
against openclaw@2026.9.3.

B358's original filed premise — "images.allowUrl=true with no images.urlAllowlist is
SSRF to cloud metadata endpoints / internal services" — was built, then RETRACTED before
being committed: the image-URL fetch always goes through the vendor's own
``fetchWithSsrFGuard`` with ``policy: {allowPrivateNetwork: false, ...}``, whose private-
IP predicate imports a dedicated ``isCloudMetadataIpAddress`` and is re-applied,
DNS-pinned, on every redirect hop. So private/internal/metadata targets are blocked
unconditionally, regardless of ``urlAllowlist`` — an absent allowlist is open-proxy-
shaped (any *public* host fetchable), not SSRF. See ``check_chat_completions_endpoint``'s
docstring (``clawseccheck/checks/_config.py``) for the full grounding trail. The task's
own filed "reload.mode" sub-item was dropped entirely: the current schema's enum is
``"off"``/``"hybrid"`` (not ``"hot"``/``"hybrid"``), and ``"hybrid"`` is the vendor's own
default/recommended posture — warning on it would be noise on every default install, not
a hardening gap.

No FAIL branch exists in this family — none of the three checks needed a C-135 pass in
the CLAUDE.md §4 sense (that gate is for new FAIL-capable checks); the grounding pass
above already served that adversarial role for B358, and found the filed premise wrong
before any code shipped.
"""
from __future__ import annotations

from clawseccheck.catalog import BY_ID, MEDIUM, HIGH, PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    CHECKS,
    check_chat_completions_endpoint,
    check_control_ui_embed_sandbox,
    check_gateway_remote_ssh_host_key_policy,
)
from clawseccheck.collector import Context


def _ctx(cfg, tmp_path, *, found=True):
    return Context(home=tmp_path, config=cfg, config_found=found)


# =============================================================================== B358
class TestChatCompletionsEndpoint:
    def test_disabled_by_default_is_pass(self, tmp_path):
        f = check_chat_completions_endpoint(_ctx({"gateway": {}}, tmp_path))
        assert f.status == PASS

    def test_enabled_false_is_pass(self, tmp_path):
        cfg = {"gateway": {"http": {"endpoints": {"chatCompletions": {"enabled": False}}}}}
        f = check_chat_completions_endpoint(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_enabled_alone_warns(self, tmp_path):
        cfg = {"gateway": {"http": {"endpoints": {"chatCompletions": {"enabled": True}}}}}
        f = check_chat_completions_endpoint(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "chatCompletions.enabled is true" in f.detail

    def test_enabled_and_allowurl_with_no_allowlist_warns_not_fail(self, tmp_path):
        """The retracted FAIL premise, pinned: this shape is a disclosure, never FAIL."""
        cfg = {
            "gateway": {
                "http": {
                    "endpoints": {
                        "chatCompletions": {"enabled": True, "images": {"allowUrl": True}}
                    }
                }
            }
        }
        f = check_chat_completions_endpoint(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "any public hostname is fetchable" in f.detail

    def test_never_claims_metadata_or_internal_services_are_exposed(self, tmp_path):
        """Golden Rule #4: the finding text must not assert an exposure the vendor's
        own SSRF guard already closes."""
        cfg = {
            "gateway": {
                "http": {
                    "endpoints": {
                        "chatCompletions": {"enabled": True, "images": {"allowUrl": True}}
                    }
                }
            }
        }
        f = check_chat_completions_endpoint(_ctx(cfg, tmp_path))
        assert "blocked unconditionally" in f.detail
        assert "cloud metadata endpoints, internal services" not in f.detail

    def test_enabled_allowurl_scoped_allowlist_warns_with_scoped_wording(self, tmp_path):
        cfg = {
            "gateway": {
                "http": {
                    "endpoints": {
                        "chatCompletions": {
                            "enabled": True,
                            "images": {"allowUrl": True, "urlAllowlist": ["example.com"]},
                        }
                    }
                }
            }
        }
        f = check_chat_completions_endpoint(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "scoped to an explicit images.urlAllowlist" in f.detail

    def test_allowurl_empty_allowlist_treated_same_as_absent(self, tmp_path):
        cfg = {
            "gateway": {
                "http": {
                    "endpoints": {
                        "chatCompletions": {
                            "enabled": True,
                            "images": {"allowUrl": True, "urlAllowlist": []},
                        }
                    }
                }
            }
        }
        f = check_chat_completions_endpoint(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "any public hostname is fetchable" in f.detail

    def test_allowurl_not_true_string_does_not_escalate(self, tmp_path):
        cfg = {
            "gateway": {
                "http": {
                    "endpoints": {
                        "chatCompletions": {"enabled": True, "images": {"allowUrl": "true"}}
                    }
                }
            }
        }
        f = check_chat_completions_endpoint(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "chatCompletions.enabled is true" in f.detail
        assert "allowUrl is true" not in f.detail

    def test_reach_wording_scales_with_gateway_bind(self, tmp_path):
        loopback_cfg = {
            "gateway": {
                "bind": "loopback",
                "http": {"endpoints": {"chatCompletions": {"enabled": True}}},
            }
        }
        lan_cfg = {
            "gateway": {
                "bind": "lan",
                "http": {"endpoints": {"chatCompletions": {"enabled": True}}},
            }
        }
        loopback_finding = check_chat_completions_endpoint(_ctx(loopback_cfg, tmp_path))
        lan_finding = check_chat_completions_endpoint(_ctx(lan_cfg, tmp_path))
        assert "reachable only from this host" in loopback_finding.detail
        assert "reachable beyond loopback" in lan_finding.detail

    def test_malformed_chatcompletions_node_is_unknown(self, tmp_path):
        cfg = {"gateway": {"http": {"endpoints": {"chatCompletions": "nope"}}}}
        f = check_chat_completions_endpoint(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN

    def test_malformed_images_node_is_unknown(self, tmp_path):
        cfg = {
            "gateway": {
                "http": {"endpoints": {"chatCompletions": {"enabled": True, "images": "nope"}}}
            }
        }
        f = check_chat_completions_endpoint(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN

    def test_unread_config_is_unknown(self, tmp_path):
        f = check_chat_completions_endpoint(_ctx({}, tmp_path, found=False))
        assert f.status == UNKNOWN

    def test_registered_and_catalog_consistent(self, tmp_path):
        assert check_chat_completions_endpoint in CHECKS
        meta = BY_ID["B358"]
        assert meta.severity == MEDIUM and meta.surface == "gateway"
        emitted = check_chat_completions_endpoint(_ctx({"gateway": {}}, tmp_path))
        assert emitted.id == "B358" and emitted.title == meta.title


# =============================================================================== B359
class TestGatewayRemoteSshHostKeyPolicy:
    def test_absent_is_pass(self, tmp_path):
        f = check_gateway_remote_ssh_host_key_policy(_ctx({"gateway": {}}, tmp_path))
        assert f.status == PASS

    def test_strict_is_pass(self, tmp_path):
        cfg = {"gateway": {"remote": {"sshHostKeyPolicy": "strict"}}}
        f = check_gateway_remote_ssh_host_key_policy(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_openssh_warns(self, tmp_path):
        cfg = {"gateway": {"remote": {"sshHostKeyPolicy": "openssh"}}}
        f = check_gateway_remote_ssh_host_key_policy(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "openssh" in f.detail
        assert "MITM" in f.detail

    def test_unrecognized_value_is_unknown_not_warn(self, tmp_path):
        """Golden Rule #4: never fabricate a verdict for a value outside the schema's
        two known literals."""
        cfg = {"gateway": {"remote": {"sshHostKeyPolicy": "lax"}}}
        f = check_gateway_remote_ssh_host_key_policy(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN

    def test_malformed_remote_block_is_unknown(self, tmp_path):
        f = check_gateway_remote_ssh_host_key_policy(
            _ctx({"gateway": {"remote": "nope"}}, tmp_path)
        )
        assert f.status == UNKNOWN

    def test_unread_config_is_unknown(self, tmp_path):
        f = check_gateway_remote_ssh_host_key_policy(_ctx({}, tmp_path, found=False))
        assert f.status == UNKNOWN

    def test_registered_and_catalog_consistent(self, tmp_path):
        assert check_gateway_remote_ssh_host_key_policy in CHECKS
        meta = BY_ID["B359"]
        assert meta.severity == HIGH and meta.surface == "gateway"
        emitted = check_gateway_remote_ssh_host_key_policy(_ctx({"gateway": {}}, tmp_path))
        assert emitted.id == "B359" and emitted.title == meta.title


# =============================================================================== B360
class TestControlUiEmbedSandbox:
    def test_absent_is_pass(self, tmp_path):
        f = check_control_ui_embed_sandbox(_ctx({"gateway": {}}, tmp_path))
        assert f.status == PASS

    def test_strict_is_pass(self, tmp_path):
        cfg = {"gateway": {"controlUi": {"embedSandbox": "strict"}}}
        f = check_control_ui_embed_sandbox(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_scripts_is_pass(self, tmp_path):
        cfg = {"gateway": {"controlUi": {"embedSandbox": "scripts"}}}
        f = check_control_ui_embed_sandbox(_ctx(cfg, tmp_path))
        assert f.status == PASS

    def test_trusted_warns(self, tmp_path):
        cfg = {"gateway": {"controlUi": {"embedSandbox": "trusted"}}}
        f = check_control_ui_embed_sandbox(_ctx(cfg, tmp_path))
        assert f.status == WARN
        assert "allow-same-origin" in f.detail

    def test_trusted_reach_wording_scales_with_gateway_bind(self, tmp_path):
        loopback_cfg = {"gateway": {"bind": "loopback", "controlUi": {"embedSandbox": "trusted"}}}
        lan_cfg = {"gateway": {"bind": "lan", "controlUi": {"embedSandbox": "trusted"}}}
        loopback_finding = check_control_ui_embed_sandbox(_ctx(loopback_cfg, tmp_path))
        lan_finding = check_control_ui_embed_sandbox(_ctx(lan_cfg, tmp_path))
        assert "reachable only from this host" in loopback_finding.detail
        assert "reachable beyond loopback" in lan_finding.detail

    def test_unrecognized_value_is_unknown_not_warn(self, tmp_path):
        cfg = {"gateway": {"controlUi": {"embedSandbox": "yolo"}}}
        f = check_control_ui_embed_sandbox(_ctx(cfg, tmp_path))
        assert f.status == UNKNOWN

    def test_malformed_controlui_block_is_unknown(self, tmp_path):
        f = check_control_ui_embed_sandbox(_ctx({"gateway": {"controlUi": "nope"}}, tmp_path))
        assert f.status == UNKNOWN

    def test_unread_config_is_unknown(self, tmp_path):
        f = check_control_ui_embed_sandbox(_ctx({}, tmp_path, found=False))
        assert f.status == UNKNOWN

    def test_registered_and_catalog_consistent(self, tmp_path):
        assert check_control_ui_embed_sandbox in CHECKS
        meta = BY_ID["B360"]
        assert meta.severity == MEDIUM and meta.surface == "gateway"
        emitted = check_control_ui_embed_sandbox(_ctx({"gateway": {}}, tmp_path))
        assert emitted.id == "B360" and emitted.title == meta.title
