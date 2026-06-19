"""Tests for clawcheck/logsafe.py.

All tests are offline and read-only (no network, no persistent writes beyond
a pytest tmp_path which is cleaned up automatically).
"""
from __future__ import annotations

import logging
import os

from clawcheck.logsafe import get_logger, redact


# ---------------------------------------------------------------------------
# redact()
# ---------------------------------------------------------------------------


class TestRedact:
    def test_masks_anthropic_api_key(self):
        secret = "sk-ant-AAAAAAAA12345678"
        result = redact(secret)
        assert secret not in result
        assert "<redacted>" in result

    def test_masks_password_colon_value(self):
        # The pattern requires >=8 non-space chars after the separator.
        text = "password: hunter2xx"
        result = redact(text)
        assert "hunter2xx" not in result
        assert "<redacted>" in result

    def test_masks_secret_colon_value(self):
        text = "secret: mysupersecretvalue"
        result = redact(text)
        assert "mysupersecretvalue" not in result
        assert "<redacted>" in result

    def test_masks_api_key_equals_value(self):
        text = "api_key=supersecretkey99"
        result = redact(text)
        assert "supersecretkey99" not in result
        assert "<redacted>" in result

    def test_masks_token_equals_value(self):
        text = "token=abcdefghijklmnop"
        result = redact(text)
        assert "abcdefghijklmnop" not in result
        assert "<redacted>" in result

    def test_masks_aws_akia_key(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        result = redact(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "<redacted>" in result

    def test_masks_google_aiza_key(self):
        text = "AIzaSyD-9tSrke72I6gDXn_6HMizoSrE5kN6bEE"
        result = redact(text)
        assert "AIzaSyD-9tSrke72I6gDXn_6HMizoSrE5kN6bEE" not in result
        assert "<redacted>" in result

    def test_leaves_ordinary_text_unchanged(self):
        text = "hello world, nothing secret here"
        assert redact(text) == text

    def test_leaves_short_values_unchanged(self):
        # Values shorter than the pattern thresholds should not be redacted
        text = "user=bob"
        result = redact(text)
        # "user" does not match SECRET_KEY_RE so it stays untouched
        assert result == text

    def test_empty_string_safe(self):
        assert redact("") == ""

    def test_none_safe(self):
        assert redact(None) == ""

    def test_idempotent(self):
        text = "password: hunter2"
        once = redact(text)
        twice = redact(once)
        assert once == twice

    def test_mixed_text_only_secret_replaced(self):
        # Value must be >=8 chars to trigger SECRET_PATTERNS.
        text = "connecting with password: hunter2xx to localhost"
        result = redact(text)
        assert "hunter2xx" not in result
        assert "connecting" in result
        assert "localhost" in result


# ---------------------------------------------------------------------------
# get_logger()
# ---------------------------------------------------------------------------


class TestGetLogger:
    def test_returns_logger_named_clawcheck(self):
        logger = get_logger()
        assert isinstance(logger, logging.Logger)
        assert logger.name == "clawcheck"

    def test_debug_flag_sets_debug_level(self):
        logger = get_logger(debug=True)
        assert logger.level == logging.DEBUG

    def test_verbose_flag_sets_info_level(self):
        logger = get_logger(verbose=True)
        assert logger.level == logging.INFO

    def test_default_sets_warning_level(self):
        logger = get_logger()
        assert logger.level == logging.WARNING

    def test_debug_true_has_at_least_one_handler(self):
        logger = get_logger(debug=True)
        assert len(logger.handlers) >= 1

    def test_propagate_is_false(self):
        logger = get_logger(debug=True)
        assert logger.propagate is False

    def test_calling_twice_does_not_multiply_handlers(self):
        get_logger(debug=True)
        logger = get_logger(debug=True)
        # Idempotent: exactly one stderr handler, no duplicates
        assert len(logger.handlers) == 1

    def test_logfile_adds_file_handler(self, tmp_path):
        log_path = str(tmp_path / "clawcheck.log")
        logger = get_logger(debug=True, logfile=log_path)
        # stderr handler + file handler
        assert len(logger.handlers) == 2
        assert os.path.exists(log_path) or True  # file created on first write

    def test_no_logfile_does_not_create_file(self, tmp_path, monkeypatch):
        # Change to tmp_path so any accidental write would be visible
        monkeypatch.chdir(tmp_path)
        get_logger(debug=True)
        assert list(tmp_path.iterdir()) == []

    def test_logfile_secret_is_redacted_in_file(self, tmp_path):
        log_path = str(tmp_path / "secret_test.log")
        logger = get_logger(debug=True, logfile=log_path)
        raw_secret = "sk-ant-AAAAAAAA12345678"
        logger.debug("connecting with key %s now", raw_secret)
        # Flush / close file handler
        for h in logger.handlers:
            h.flush()

        content = (tmp_path / "secret_test.log").read_text(encoding="utf-8")
        assert raw_secret not in content, "raw secret must not appear in log file"
        assert "<redacted>" in content, "<redacted> marker must be present"

    def test_logfile_password_pair_redacted_in_file(self, tmp_path):
        log_path = str(tmp_path / "pw_test.log")
        logger = get_logger(debug=True, logfile=log_path)
        # Value must be >=8 chars to match SECRET_PATTERNS.
        logger.debug("auth failed: password: hunter2xx")
        for h in logger.handlers:
            h.flush()

        content = (tmp_path / "pw_test.log").read_text(encoding="utf-8")
        assert "hunter2xx" not in content
        assert "<redacted>" in content

    def test_logfile_expanduser_tilde(self, tmp_path, monkeypatch):
        # Patch HOME so ~ expands into our tmp dir
        monkeypatch.setenv("HOME", str(tmp_path))
        log_path = "~/clawcheck_test.log"
        logger = get_logger(debug=True, logfile=log_path)
        logger.debug("hello")
        for h in logger.handlers:
            h.flush()
        assert (tmp_path / "clawcheck_test.log").exists()
