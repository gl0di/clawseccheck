"""C-530 — B1/B11 must not fake a PASS when permission bits could not be read.

``ctx.config_mode`` stays ``None`` in a state ``_config_unreadable()`` (B-228) does not
cover: openclaw.json parsed fine (``config_parse_error`` is ``False``, the content WAS
read) but the SEPARATE ``cfg_path.stat()`` call collector.py makes afterward — solely to
read the file's permission bits — itself raised ``OSError`` (collector.py only appends to
``ctx.errors`` there; it does not mark the parse as failed). ``_perms_loose()`` then folds
that "never checked" state into the same ``False`` as "checked and found tight"
(deliberately, for the non-POSIX case — see ``tests/test_windows.py``), so B1/B11 would
otherwise emit a full-confidence PASS about permissions that were never actually read —
the exact "fake PASS instead of UNKNOWN" Golden Rule #4 forbids.

Builds a bare ``Context`` directly (same idiom as ``tests/test_b355_...``) rather than
going through ``collect()``, since the bug is a specific field combination
(``config_found=True``, ``config_parse_error=False``, ``config_mode=None``) that is hard
to reproduce end-to-end without fragile, call-order-dependent ``stat()`` mocking.
"""
from __future__ import annotations

from clawseccheck.catalog import FAIL, PASS, UNKNOWN
from clawseccheck.checks import check_secrets, check_tls
from clawseccheck.collector import Context

# Assembled at runtime so no contiguous secret-shaped literal exists in source.
_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def _ctx(cfg: dict, tmp_path, *, config_mode, config_found=True) -> Context:
    return Context(
        home=tmp_path,
        config=cfg,
        config_found=config_found,
        config_parse_error=False,
        config_mode=config_mode,
    )


class TestB11TransportPerms:
    def test_unknown_when_perms_could_not_be_read(self, tmp_path):
        cfg = {"gateway": {"bind": "127.0.0.1", "tls": {"enabled": False}}}
        f = check_tls(_ctx(cfg, tmp_path, config_mode=None))
        assert f.status == UNKNOWN
        assert "could not be verified" in f.detail

    def test_still_passes_when_perms_were_actually_read_tight(self, tmp_path):
        cfg = {"gateway": {"bind": "127.0.0.1", "tls": {"enabled": False}}}
        f = check_tls(_ctx(cfg, tmp_path, config_mode=0o600))
        assert f.status == PASS

    def test_still_unknown_on_a_plain_non_openclaw_host(self, tmp_path):
        # config_mode is ALSO None here, but for an unrelated reason: there is no
        # openclaw.json to stat() at all (config_found=False) -- must not be mistaken
        # for the "parsed but stat() failed" bug case above.
        #
        # B-661: this used to assert PASS, pinning the exact fail-open bug B-661
        # describes -- "Transport is loopback/TLS" asserted about a config nobody
        # read. check_tls now guards config_found directly (see its own B-661
        # comment) and reports UNKNOWN here instead.
        f = check_tls(_ctx({}, tmp_path, config_mode=None, config_found=False))
        assert f.status == UNKNOWN


class TestB1SecretsPerms:
    def test_unknown_when_secret_present_and_perms_could_not_be_read(self, tmp_path):
        cfg = {"apiKey": _AWS_KEY}
        f = check_secrets(_ctx(cfg, tmp_path, config_mode=None))
        assert f.status == UNKNOWN
        assert "could not be verified" in f.detail

    def test_still_passes_clean_when_no_secret_present_and_perms_unreadable(self, tmp_path):
        # Nothing this check would flag either way -- the guard must not turn an
        # unrelated stat() failure into a spurious UNKNOWN on an empty config.
        f = check_secrets(_ctx({}, tmp_path, config_mode=None))
        assert f.status == PASS

    def test_still_unknown_on_a_plain_non_openclaw_host(self, tmp_path):
        # Same config_found distinction as check_tls above, and the same B-661
        # correction: this used to assert PASS ("No exposed plaintext secrets.")
        # about a config nobody read.
        f = check_secrets(_ctx({}, tmp_path, config_mode=None, config_found=False))
        assert f.status == UNKNOWN

    def test_still_fails_when_secret_present_and_perms_were_actually_read_loose(self, tmp_path):
        cfg = {"apiKey": _AWS_KEY}
        f = check_secrets(_ctx(cfg, tmp_path, config_mode=0o644))
        assert f.status == FAIL
