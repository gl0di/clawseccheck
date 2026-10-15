"""C-722 item 1 -- a config saved with a UTF-8 byte order mark is read, not refused.

Windows Notepad and some editors write ``EF BB BF`` at the start of ``openclaw.json``.
OpenClaw accepts that file (``openclaw config validate`` -> "Config valid"); the loader used
to refuse it ("invalid non-printable character U+FEFF"), so the audit was blind on a config
the platform runs.

The loader skips the leading BOM (after the size bound has counted its bytes) and reads
U+FEFF as JSON5 whitespace between tokens, as the platform does; inside a string it stays
data, inside a token it is refused. Two layers:

* **Offline** -- the loader, the ``$include`` path, the legacy ``clawdbot.json`` name, the
  size bound, the digest, and the whole audit through the real CLI (a BOM copy of each
  fixture home audits to the same ``(id, status, detail)`` set as the original).
* **Live, local-only** -- the REAL ``openclaw config validate`` over every BOM shape, so the
  shapes the loader accepts are exactly the ones the platform accepts and the shapes it
  refuses are pinned with the platform's own verdict next to them. Skipped wherever
  ``openclaw`` is not on the PATH.

Measured on OpenClaw 2026.10.2: the platform accepts U+FEFF between any two tokens (two or
three at the start, after whitespace or a comment, around a key, in the middle) and refuses
it inside a number or a keyword; UTF-16 and a BOM-only file are refused.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SAFE = REPO_ROOT / "fixtures" / "home_safe"
VULN = REPO_ROOT / "fixtures" / "home_vuln"

BOM = b"\xef\xbb\xbf"
GATEWAY = b'{"gateway":{"bind":"loopback"}}'
PARSED = {"gateway": {"bind": "loopback"}}
LIMIT = 1_000_000


def _load(path: Path, limit: int = LIMIT, digest=None):
    from clawseccheck.configloader import load_openclaw_config

    return load_openclaw_config(path, root_byte_limit=limit, root_digest=digest)


def _write(directory: Path, name: str, data: bytes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(data)
    path.chmod(0o600)
    return path


# ----------------------------------------------------------------------- the loader
def test_a_leading_bom_is_skipped(tmp_path):
    assert _load(_write(tmp_path, "openclaw.json", BOM + GATEWAY)) == PARSED


def test_the_control_without_a_bom_loads_the_same_value(tmp_path):
    assert _load(_write(tmp_path, "openclaw.json", GATEWAY)) == PARSED


def test_a_bom_before_json5_syntax_is_skipped(tmp_path):
    data = BOM + b"// saved by an editor\n{gateway: {bind: 'loopback',},}"
    assert _load(_write(tmp_path, "openclaw.json", data)) == PARSED


def test_a_bom_before_a_trailing_newline_is_skipped(tmp_path):
    assert _load(_write(tmp_path, "openclaw.json", BOM + GATEWAY + b"\n")) == PARSED


def test_a_bom_inside_a_string_value_is_data_and_stays(tmp_path):
    data = b'{"gateway":{"bind":"loopback"},"note":"' + BOM + b'x"}'
    parsed = _load(_write(tmp_path, "openclaw.json", data))
    assert parsed["note"] == "\ufeffx"


@pytest.mark.parametrize("name,data", [
    ("bom_only", BOM),
    ("utf16_le_bom", b"\xff\xfe" + GATEWAY.decode().encode("utf-16-le")),
    ("utf16_be_bom", b"\xfe\xff" + GATEWAY.decode().encode("utf-16-be")),
    ("utf16_le_without_bom", GATEWAY.decode().encode("utf-16-le")),
    ("bom_then_invalid_utf8", BOM + b'{"a":"\xff"}'),
])
def test_what_the_platform_refuses_is_still_refused(tmp_path, name, data):
    from clawseccheck.configloader import ConfigLoadError

    with pytest.raises(ConfigLoadError):
        _load(_write(tmp_path, "openclaw.json", data))


PORT = b'{"gateway":{"port":18789}}'
PORT_PARSED = {"gateway": {"port": 18789}}


@pytest.mark.parametrize("name,data", [
    ("two_boms", BOM + BOM + GATEWAY),
    ("three_boms_then_newline", BOM + BOM + BOM + b"\n" + GATEWAY),
    ("whitespace_before_bom", b" \n" + BOM + GATEWAY),
    ("bom_in_the_middle", b"{" + BOM + b'"gateway":{"bind":"loopback"}}'),
    ("bom_before_a_closing_brace", b'{"gateway":{"bind":"loopback"' + BOM + b"}}"),
    ("bom_between_key_and_colon", b'{"gateway"' + BOM + b':{"bind":"loopback"}}'),
    ("bom_after_an_unquoted_key", b"{gateway" + BOM + b":{bind:'loopback'}}"),
    ("bom_after_a_line_comment", b"// c\n" + BOM + GATEWAY),
    ("bom_after_a_block_comment", b"/* c */" + BOM + GATEWAY),
    ("bom_in_a_comment_with_an_apostrophe", b"// don't\n" + BOM + GATEWAY),
    ("bom_before_a_comma", b'{"gateway":{"bind":"loopback"' + BOM + b"}}"),
])
def test_a_bom_the_platform_reads_as_whitespace_is_read(tmp_path, name, data):
    """OpenClaw reads U+FEFF as JSON5 whitespace between any two tokens, so a config with
    one there is a config it runs: refusing it left the audit blind (UNKNOWN, no grade).
    Pinned together with the platform's verdict by ``test_live_*``."""
    assert _load(_write(tmp_path, "openclaw.json", data)) == PARSED


@pytest.mark.parametrize("name,data", [
    ("bom_splits_a_number", b'{"gateway":{"port":18' + BOM + b"789}}"),
    ("bom_splits_a_keyword", b'{"gateway":{"x":tr' + BOM + b"ue}}"),
    ("bom_splits_an_unquoted_key", b"{gate" + BOM + b"way:{port:18789}}"),
    ("bom_between_a_minus_and_its_digits", b'{"gateway":{"port":-' + BOM + b"1}}"),
    ("bom_between_a_plus_and_its_digits", b'{"gateway":{"port":+' + BOM + b"1}}"),
    ("bom_between_a_minus_and_Infinity", b'{"gateway":{"port":-' + BOM + b"Infinity}}"),
    ("bom_between_an_exponent_sign_and_its_digits", b'{"gateway":{"port":1e-' + BOM + b"5}}"),
])
def test_a_bom_inside_a_token_is_refused(tmp_path, name, data):
    """The platform refuses it too (``test_live_*``): a mark is whitespace, not nothing, so
    it must not glue two halves of a token into one."""
    from clawseccheck.configloader import ConfigLoadError

    with pytest.raises(ConfigLoadError):
        _load(_write(tmp_path, "openclaw.json", data))


def test_an_ordinary_space_after_a_sign_is_read_as_it_was_before_this_task(tmp_path):
    """An older difference, NOT the platform's behaviour (it refuses `- 1`: see the live
    table). The loader's number reading has always accepted a space after a sign; this
    task only keeps a BOM from being taken for one. Pinned so a change here is deliberate."""
    path = _write(tmp_path, "openclaw.json", b'{"gateway":{"port":- 1}}')
    assert _load(path) == {"gateway": {"port": -1}}


def test_a_bom_inside_a_string_is_data_whatever_surrounds_it(tmp_path):
    data = (BOM + b"// don't\n" + BOM + b'{"a":"x' + BOM + b'y"' + BOM + b",'b':'" + BOM + b"'}")
    assert _load(_write(tmp_path, "openclaw.json", data)) == {"a": "x\ufeffy", "b": "\ufeff"}


def test_the_bom_rule_is_not_applied_to_other_readers_of_the_lexer():
    """``loads_json5`` called without the opt-in keeps refusing U+FEFF between tokens: the
    rule is for OpenClaw's own config files, not for every third-party file."""
    from clawseccheck.configloader import loads_json5

    text = "{" + "\ufeff" + '"a":1}'
    with pytest.raises(ValueError):
        loads_json5(text)
    assert loads_json5(text, feff_is_space=True) == {"a": 1}


def test_the_bom_bytes_count_toward_the_size_bound(tmp_path):
    from clawseccheck.configloader import ConfigLoadError

    data = BOM + GATEWAY
    path = _write(tmp_path, "openclaw.json", data)
    assert _load(path, limit=len(data)) == PARSED
    with pytest.raises(ConfigLoadError, match="cap"):
        _load(path, limit=len(data) - 1)


def test_the_digest_covers_the_bytes_on_disk_including_the_bom(tmp_path):
    data = BOM + GATEWAY
    digest: list = []
    _load(_write(tmp_path, "openclaw.json", data), digest=digest)
    assert digest == [hashlib.sha256(data).hexdigest()]
    assert digest != [hashlib.sha256(GATEWAY).hexdigest()]


def test_the_nesting_bound_still_applies_after_a_bom(tmp_path):
    """Deeply nested input meets the same limit with or without the mark: whatever the
    interpreter does with it (a refusal, or a clean read), the BOM copy does the same.
    The skip changes nothing about what the parser is asked to read."""
    deep = b'{"a":' * 3000 + b"1" + b"}" * 3000

    def outcome(directory, data):
        try:
            _load(_write(directory, "openclaw.json", data), limit=10_000_000)
        except Exception as exc:  # noqa: BLE001 - the class is the observation
            return type(exc).__name__
        return "read"

    assert outcome(tmp_path / "plain", deep) == outcome(tmp_path / "bom", BOM + deep)


# --------------------------------------------------------------------------- $include
def test_a_bom_in_an_included_fragment_is_skipped(tmp_path):
    _write(tmp_path, "frag.json", BOM + GATEWAY)
    root = _write(tmp_path, "openclaw.json", b'{"$include":"./frag.json"}')
    assert _load(root) == PARSED


def test_a_bom_on_both_the_root_and_the_fragment_is_skipped(tmp_path):
    _write(tmp_path, "frag.json", BOM + GATEWAY)
    root = _write(tmp_path, "openclaw.json", BOM + b'{"$include":"./frag.json"}')
    assert _load(root) == PARSED


def test_two_boms_in_a_fragment_are_skipped(tmp_path):
    _write(tmp_path, "frag.json", BOM + BOM + GATEWAY)
    root = _write(tmp_path, "openclaw.json", b'{"$include":"./frag.json"}')
    assert _load(root) == PARSED


# --------------------------------------------------------------- legacy clawdbot.json
def test_a_bom_in_the_legacy_config_name_is_read_by_the_collector(tmp_path):
    from clawseccheck.collector import collect

    _write(tmp_path, "clawdbot.json", BOM + GATEWAY)
    ctx = collect(tmp_path)
    assert ctx.config_found is True
    assert ctx.config_path.name == "clawdbot.json"
    assert ctx.config_parse_error is False
    assert ctx.config == PARSED


def test_a_bom_in_the_canonical_config_is_read_by_the_collector(tmp_path):
    from clawseccheck.collector import collect

    _write(tmp_path, "openclaw.json", BOM + GATEWAY)
    ctx = collect(tmp_path)
    assert ctx.config_parse_error is False
    assert ctx.config == PARSED


# ------------------------------------------------------------- the whole audit, real CLI
def _audit(home: Path, scratch: Path) -> dict:
    hermetic_home = scratch / "hm"
    hermetic_home.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("OPENCLAW_")}
    env["HOME"] = str(hermetic_home)
    proc = subprocess.run(
        [sys.executable, "-m", "clawseccheck", "--home", str(home), "--json",
         "--no-history", "--no-native", "--no-deptree", "--no-host", "--no-sockets"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=400, env=env)
    assert proc.returncode in (0, 1), proc.stderr[-2000:]
    return json.loads(proc.stdout)


def _verdicts(payload: dict, home: Path) -> set:
    return {(f["id"], f["status"], f["detail"].replace(str(home), "<home>"))
            for f in payload["findings"]}


@pytest.mark.parametrize("fixture", [SAFE, VULN], ids=["home_safe", "home_vuln"])
def test_a_bom_copy_of_a_fixture_audits_to_the_same_findings(tmp_path, fixture):
    original = _audit(fixture, tmp_path)
    assert original["config_parse_error"] is False

    copy = tmp_path / "copy"
    shutil.copytree(fixture, copy)
    config = copy / "openclaw.json"
    config.write_bytes(BOM + config.read_bytes())

    with_bom = _audit(copy, tmp_path)
    assert with_bom["config_parse_error"] is False, with_bom.get("config_parse_reason")
    assert _verdicts(with_bom, copy) == _verdicts(original, fixture)
    assert with_bom["grade"] == original["grade"]
    assert with_bom["score"] == original["score"]


def test_a_config_the_loader_refuses_is_still_reported_unreadable(tmp_path):
    """The positive control for the test above: a config the loader refuses (a mark inside a
    token, which the platform refuses too) is reported unreadable through the same CLI, so the
    parity test above cannot pass by the audit ignoring the config altogether."""
    copy = tmp_path / "copy"
    shutil.copytree(SAFE, copy)
    (copy / "openclaw.json").write_bytes(b'{"gateway":{"port":18' + BOM + b"789}}")
    payload = _audit(copy, tmp_path)
    assert payload["config_parse_error"] is True


# ---------------------------------------------------- live: the real `openclaw config validate`
def _validate(directory: Path, config_name: str = "openclaw.json") -> int:
    env = dict(os.environ)
    env.update(HOME=str(directory), OPENCLAW_HOME=str(directory),
               OPENCLAW_STATE_DIR=str(directory),
               OPENCLAW_CONFIG_PATH=str(directory / config_name))
    return subprocess.run(["openclaw", "config", "validate"], env=env, capture_output=True,
                          text=True, timeout=120).returncode


needs_openclaw = pytest.mark.skipif(shutil.which("openclaw") is None,
                                    reason="the openclaw CLI is not on the PATH")

#: (shape, bytes, platform exit code on OpenClaw 2026.10.2, does the loader read it?)
_SHAPES = [
    ("control_without_bom", GATEWAY, 0, True),
    ("one_leading_bom", BOM + GATEWAY, 0, True),
    ("one_leading_bom_json5", BOM + b"// c\n{gateway:{bind:'loopback'}}", 0, True),
    ("bom_then_empty_object", BOM + b"{}", 0, True),
    ("bom_only", BOM, 1, False),
    ("utf16_le_bom", b"\xff\xfe" + GATEWAY.decode().encode("utf-16-le"), 1, False),
    ("utf16_be_bom", b"\xfe\xff" + GATEWAY.decode().encode("utf-16-be"), 1, False),
    ("utf16_le_without_bom", GATEWAY.decode().encode("utf-16-le"), 1, False),
    # The platform reads U+FEFF as JSON5 whitespace between tokens, and so does the loader.
    ("two_leading_boms", BOM + BOM + GATEWAY, 0, True),
    ("three_boms_then_newline", BOM + BOM + BOM + b"\n" + PORT, 0, True),
    ("whitespace_then_bom", b" \n" + BOM + PORT, 0, True),
    ("bom_in_the_middle", b"{" + BOM + b'"gateway":{"port":18789}}', 0, True),
    ("bom_before_a_closing_brace", b'{"gateway":{"port":18789' + BOM + b"}}", 0, True),
    ("bom_between_key_and_colon", b'{"gateway"' + BOM + b':{"port":18789}}', 0, True),
    ("bom_after_an_unquoted_key", b"{gateway" + BOM + b":{port:18789}}", 0, True),
    ("bom_after_a_line_comment", b"// c\n" + BOM + PORT, 0, True),
    ("bom_after_a_block_comment", b"/* c */" + BOM + PORT, 0, True),
    ("bom_in_a_comment_with_an_apostrophe", b"// don't\n" + BOM + PORT, 0, True),
    ("bom_before_a_comma", b'{"gateway":{"port":18789' + BOM + b',"bind":"loopback"}}', 0, True),
    # ... and refuses it where it would split a token.
    ("bom_splits_a_number", b'{"gateway":{"port":18' + BOM + b"789}}", 1, False),
    ("bom_splits_a_keyword", b'{"gateway":{"x":tr' + BOM + b"ue}}", 1, False),
    ("bom_after_a_minus", b'{"gateway":{"port":-' + BOM + b"1}}", 1, False),
    ("bom_after_a_plus", b'{"gateway":{"port":+' + BOM + b"1}}", 1, False),
    ("bom_after_a_minus_before_Infinity", b'{"gateway":{"port":-' + BOM + b"Infinity}}", 1, False),
    ("bom_after_an_exponent_sign", b'{"gateway":{"port":1e-' + BOM + b"5}}", 1, False),
]


@needs_openclaw
@pytest.mark.parametrize("shape,data,platform_rc,loader_reads", _SHAPES,
                         ids=[s[0] for s in _SHAPES])
def test_live_loader_and_platform_agree_on_every_shape_the_loader_claims(
        tmp_path, shape, data, platform_rc, loader_reads):
    from clawseccheck.configloader import ConfigLoadError

    path = _write(tmp_path, "openclaw.json", data)
    assert _validate(tmp_path) == platform_rc, f"the platform's verdict on {shape} changed"
    try:
        _load(path)
        read = True
    except ConfigLoadError:
        read = False
    assert read is loader_reads, shape
    if read:
        # For every shape in this table the loader reads nothing the platform refuses. (It is
        # broader elsewhere: an ordinary space after a sign, see the test named for it.)
        assert platform_rc == 0, shape


@needs_openclaw
def test_live_a_bom_in_an_included_fragment_matches_the_platform(tmp_path):
    for name, frag, platform_rc, loader_reads in (
        ("one_bom", BOM + GATEWAY, 0, True),
        ("two_boms", BOM + BOM + GATEWAY, 0, True),
    ):
        d = tmp_path / name
        _write(d, "frag.json", frag)
        root = _write(d, "openclaw.json", b'{"$include":"./frag.json"}')
        assert _validate(d) == platform_rc, name
        from clawseccheck.configloader import ConfigLoadError

        try:
            _load(root)
            read = True
        except ConfigLoadError:
            read = False
        assert read is loader_reads, name


@needs_openclaw
def test_live_a_bom_in_the_legacy_config_name_matches_the_platform(tmp_path):
    from clawseccheck.collector import collect

    _write(tmp_path, "clawdbot.json", BOM + GATEWAY)
    assert _validate(tmp_path, "clawdbot.json") == 0
    assert collect(tmp_path).config_parse_error is False
