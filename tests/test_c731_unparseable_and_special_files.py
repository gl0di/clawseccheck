"""C-731: a file that is PRESENT but not understood (or is not a regular file) is UNKNOWN.

The sibling of C-727 (an unreadable path) for CONTENT and FILE KIND, for B151, B136, B176,
B79 and B78: a file that does not parse, a document of the wrong top-level type, and a path
that is a symbolic link / directory / named pipe / device where a regular file is expected
answers UNKNOWN under the check's own id - never PASS, never a crash, never a blocked read.

Every audit runs in a subprocess with a hard timeout, so a regression that opens a named pipe
fails the test instead of hanging the suite. The test itself never opens a pipe.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(os.name != "posix", reason="symlinks / pipes are POSIX-only")

_RUNNER = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "from clawseccheck.collector import collect\n"
    "from clawseccheck import checks\n"
    "f = getattr(checks, sys.argv[2])(collect(Path(sys.argv[1])))\n"
    "print(json.dumps([f.id, f.status, f.detail, f.fix, bool(f.engine_degraded)]))\n"
)

HOOKS = "agents/a/agent/codex-home/.tmp/plugins/plugins/zz/hooks.json"
HOOKS_OK = "agents/a/agent/codex-home/.tmp/plugins/plugins/ok/hooks.json"
HOOKS_WARN = "agents/a/agent/codex-home/.tmp/plugins/plugins/warn/hooks.json"
TRUST = "agents/a/agent/codex-home/config.toml"
PAIRED = "devices/paired.json"
ROLLOUT = "agents/a/agent/codex-home/sessions/2026/rollout-1.jsonl"
HEALTH = "logs/config-health.json"



def _home(tmp_path: Path) -> Path:
    home = tmp_path / "h"
    home.mkdir()
    cfg = home / "openclaw.json"
    cfg.write_text("{}", encoding="utf-8")
    os.chmod(cfg, 0o600)
    return home


def _put(home: Path, rel: str, data) -> Path:
    p = home / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    p.write_bytes(data)
    return p


def _special(home: Path, rel: str, kind: str) -> None:
    p = home / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if kind == "dangling":
        os.symlink(p.parent / "no-such-target", p)
    elif kind == "zero":
        os.symlink("/dev/zero", p)
    elif kind == "self":
        os.symlink(p, p)
    elif kind == "dir":
        p.mkdir()
    elif kind == "fifo":
        os.mkfifo(p)
    elif kind == "link-to-file":
        real = p.parent / "real-target.dat"
        real.write_bytes(b"{}")
        os.symlink(real, p)
    else:  # pragma: no cover
        raise AssertionError(kind)


def _run(home: Path, check: str):
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
    done = subprocess.run(
        [sys.executable, "-c", _RUNNER, str(home), check],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=90)
    assert done.returncode == 0, (done.returncode, done.stderr[-1500:])
    cid, status, detail, fix, degraded = json.loads(done.stdout.strip().splitlines()[-1])
    return cid, status, detail, fix, degraded


def _unknown(res, cid, rel, degraded):
    got_id, status, detail, fix, got_degraded = res
    assert (got_id, status) == (cid, "UNKNOWN"), res
    assert rel in detail, detail
    assert got_degraded is degraded
    assert "no clean result is claimed" in detail
    assert fix
    return detail


KINDS = ["dangling", "zero", "self", "dir", "fifo", "link-to-file"]
KIND_TEXT = {"dir": "directory", "fifo": "not a regular file", "zero": "symbolic link",
             "dangling": "symbolic link", "self": "symbolic link", "link-to-file": "symbolic link"}
# B176, B78 and B136 have always read their file THROUGH a symbolic link (and so does the
# platform), so for them a link to a regular file is not in this list: it is judged by its
# content, exactly like the regular file (pinned below). Any other link is still UNKNOWN.
KINDS_NOT_READABLE = [k for k in KINDS if k != "link-to-file"]

JSON_BAD = [
    ("empty", b""),
    ("garbage", b"\x00\xff\xfe garbage {"),
    ("nuls", b"\x00" * 64),
    ("truncated", b'{"PostToolUse": {"Bash": '),
    ("number", b"42"),
    ("list", b"[1, 2, 3]"),            # no wiring in it (one WITH wiring still WARNs, below)
    ("string", b'"hello"'),
    ("null", b"null"),
    ("utf16", "{}".encode("utf-16")),
    ("bom-only", b"\xef\xbb\xbf"),
    ("one-line-20k", b'{"a": "' + b"x" * 20000 + b'"'),
]


# ------------------------------------------------------------------ B151

WIRING = '{"PostToolUse": {"Bash": "./scripts/post.sh"}}'


@pytest.mark.parametrize("name,data", JSON_BAD, ids=[n for n, _ in JSON_BAD])
def test_b151_present_but_not_a_json_object_is_unknown(tmp_path, name, data):
    home = _home(tmp_path)
    _put(home, HOOKS, data)
    detail = _unknown(_run(home, "check_codex_plugin_hooks"), "B151", HOOKS, True)
    assert ("not a JSON object" in detail) or ("could not be parsed as JSON" in detail)


@pytest.mark.parametrize("kind", KINDS)
def test_b151_special_hooks_file_is_unknown(tmp_path, kind):
    home = _home(tmp_path)
    _special(home, HOOKS, kind)
    detail = _unknown(_run(home, "check_codex_plugin_hooks"), "B151", HOOKS, True)
    assert KIND_TEXT[kind] in detail


@pytest.mark.parametrize("data", ['[{"event": "PreToolUse", "command": "/opt/x/run.sh"}]',
                                  '"/opt/x/run.sh"'], ids=["list", "string"])
def test_b151_wiring_in_a_document_that_is_not_an_object_still_warns(tmp_path, data):
    """The walk that finds shell wiring is shape-tolerant on purpose: a top-level list or
    string that carries it was a WARN before C-731 and stays one. Only a non-object with NO
    wiring the walk can see is "not understood"."""
    home = _home(tmp_path)
    _put(home, HOOKS, data)
    res = _run(home, "check_codex_plugin_hooks")
    assert res[:2] == ("B151", "WARN"), res
    assert "/opt/x/run.sh" in res[2]


def test_b151_a_warn_from_a_readable_sibling_stands(tmp_path):
    home = _home(tmp_path)
    _put(home, HOOKS, b"\x00garbage")
    _put(home, HOOKS_WARN, WIRING)
    res = _run(home, "check_codex_plugin_hooks")
    assert res[:2] == ("B151", "WARN"), res
    assert "./scripts/post.sh" in res[2]


def test_b151_a_clean_sibling_does_not_hide_an_unparsed_file(tmp_path):
    home = _home(tmp_path)
    _put(home, HOOKS, b"")
    _put(home, HOOKS_OK, '{"a": 1}')
    _unknown(_run(home, "check_codex_plugin_hooks"), "B151", HOOKS, True)


def test_b151_well_formed_home_is_unchanged(tmp_path):
    home = _home(tmp_path)
    _put(home, HOOKS_OK, '{"a": 1, "a": {"a": 2}}')           # D: a valid object, nothing risky
    res = _run(home, "check_codex_plugin_hooks")
    assert res[:2] == ("B151", "PASS")
    assert res[2] == ("Codex connector hooks.json file(s) found (ok); none wire a shell "
                      "script to a tool-use/lifecycle event.")
    _put(home, HOOKS_WARN, WIRING)
    assert _run(home, "check_codex_plugin_hooks")[1] == "WARN"


# ------------------------------------------------------------------ B136

TOML_BAD = [
    ("garbage", b"\x00\xff\xfe garbage"),
    ("nuls", b"\x00" * 64),
    ("utf16", "[projects]".encode("utf-16")),
]
# Text that is not valid TOML. The verdict for it must not depend on whether this
# interpreter has `tomllib` (3.11+): it is scanned by the same line reader on every Python.
TOML_TEXT_NOT_TOML = [
    ("truncated", b'[projects."/work/p"\nsandbox = '),
    ("bare-string", b'"just a string"'),
    ("one-line-20k", b"x" * 20000),
    ("bom-only", b"\xef\xbb\xbf"),
]
TRUSTED = '[projects."/work/p"]\ntrust_level = "trusted"\n'
UNTRUSTED = '[projects."/work/p"]\ntrust_level = "untrusted"\n'


def _b136_case(tmp_path, data):
    home = _home(tmp_path)
    _put(home, TRUST, data)
    detail = _unknown(_run(home, "check_codex_project_trust"), "B136", TRUST, True)
    assert "is not a text file" in detail


@pytest.mark.parametrize("name,data", TOML_BAD, ids=[n for n, _ in TOML_BAD])
def test_b136_unparseable_config_is_unknown(tmp_path, name, data):
    _b136_case(tmp_path, data)


@pytest.mark.parametrize("name,data", TOML_TEXT_NOT_TOML,
                         ids=[n for n, _ in TOML_TEXT_NOT_TOML])
def test_b136_text_that_is_not_toml_is_scanned_the_same_on_every_python(tmp_path, name, data):
    """No trusted project in it -> the answer a regular config without one gets. The same
    broken text with a trust line still WARNs: the line scan is the lenient reader."""
    home = _home(tmp_path)
    _put(home, TRUST, data)
    assert _run(home, "check_codex_project_trust")[:2] == ("B136", "PASS")
    _put(home, TRUST, data + b'\n[projects."/work/p"]\ntrust_level = "trusted"\n[broken')
    assert _run(home, "check_codex_project_trust")[:2] == ("B136", "WARN")


def test_b136_a_byte_order_mark_does_not_hide_the_first_table(tmp_path):
    home = _home(tmp_path)
    _put(home, TRUST, b"\xef\xbb\xbf" + TRUSTED.encode())
    assert _run(home, "check_codex_project_trust")[:2] == ("B136", "WARN")
    _put(home, TRUST, b"\xef\xbb\xbf" + UNTRUSTED.encode())
    assert _run(home, "check_codex_project_trust")[:2] == ("B136", "PASS")


def test_b136_binary_config_with_a_trust_line_still_warns(tmp_path):
    """A trust line the scan can still see in a file that is not text stands as a WARN; one
    it cannot see (junk glued to the table header) is UNKNOWN - never a PASS."""
    home = _home(tmp_path)
    _put(home, TRUST, b"\x00\xff\n" + TRUSTED.encode())
    assert _run(home, "check_codex_project_trust")[:2] == ("B136", "WARN")
    _put(home, TRUST, b"\x00\xff" + TRUSTED.encode())
    assert _run(home, "check_codex_project_trust")[:2] == ("B136", "UNKNOWN")


@pytest.mark.parametrize("kind", KINDS_NOT_READABLE)
def test_b136_special_config_is_unknown(tmp_path, kind):
    home = _home(tmp_path)
    _special(home, TRUST, kind)
    detail = _unknown(_run(home, "check_codex_project_trust"), "B136", TRUST, True)
    assert KIND_TEXT[kind] in detail


def test_b136_a_warn_from_a_readable_sibling_stands(tmp_path):
    home = _home(tmp_path)
    _put(home, TRUST, b"\x00garbage")
    _put(home, "agents/b/agent/codex-home/config.toml", TRUSTED)
    res = _run(home, "check_codex_project_trust")
    assert res[:2] == ("B136", "WARN"), res


def test_b136_well_formed_home_is_unchanged(tmp_path):
    home = _home(tmp_path)
    _put(home, TRUST, UNTRUSTED)
    res = _run(home, "check_codex_project_trust")
    assert res[:3] == ("B136", "PASS",
                       "codex-home/config.toml found; no project has trust_level=\"trusted\".")
    _put(home, TRUST, b"")                       # D: an empty TOML document is valid, holds nothing
    assert _run(home, "check_codex_project_trust")[1] == "PASS"


# ------------------------------------------------------------------ B176

@pytest.mark.parametrize("kind", KINDS_NOT_READABLE)
def test_b176_special_paired_file_is_unknown(tmp_path, kind):
    home = _home(tmp_path)
    _special(home, PAIRED, kind)
    detail = _unknown(_run(home, "check_paired_device_operator_authority"), "B176", PAIRED, False)
    assert KIND_TEXT[kind] in detail


def test_b176_well_formed_home_is_unchanged(tmp_path):
    home = _home(tmp_path)
    _put(home, PAIRED, "{}")
    res = _run(home, "check_paired_device_operator_authority")
    assert res[:3] == ("B176", "PASS",
                       "devices/paired.json found but empty \u2014 no paired devices to evaluate.")
    _put(home, PAIRED, '{"a": 1, "a": {"a": 2}}')   # D: a valid object with no risky entry
    assert _run(home, "check_paired_device_operator_authority")[1] == "PASS"
    _put(home, PAIRED, "[1, 2]")                    # already UNKNOWN, unchanged
    assert _run(home, "check_paired_device_operator_authority")[1] == "UNKNOWN"


def test_b138_valid_object_without_risky_entry_still_passes(tmp_path):
    home = _home(tmp_path)
    _put(home, "devices/pending.json", '{"a": 1, "a": {"a": 2}}')
    assert _run(home, "check_pending_device_pairing_scope")[1] != "WARN"


# ------------------------------------------------------------------ B79

def _session(home: Path, agent: str, policy: str) -> None:
    line = json.dumps({"type": "turn_context", "payload": {"approval_policy": policy}})
    _put(home, f"agents/{agent}/agent/codex-home/sessions/2026/rollout.jsonl",
         "\n".join([line] * 3) + "\n")


def test_b79_a_pipe_for_a_session_log_is_unknown_and_does_not_raise(tmp_path):
    """(A symbolic link there is not a case: the directory walk never offers one.)"""
    home = _home(tmp_path)
    _special(home, ROLLOUT, "fifo")
    _session(home, "a", "on-request")          # a readable log beside it must not hide it
    _unknown(_run(home, "check_session_approval_policy"), "B79", ROLLOUT, True)


def test_b79_a_warn_beside_a_pipe_stands_and_clean_is_unchanged(tmp_path):
    home = _home(tmp_path)
    _session(home, "a", "never")
    _special(home, "agents/b/agent/codex-home/sessions/2026/rollout-1.jsonl", "fifo")
    assert _run(home, "check_session_approval_policy")[1] == "WARN"
    (tmp_path / "c").mkdir()
    clean = _home(tmp_path / "c")
    _session(clean, "a", "on-request")
    res = _run(clean, "check_session_approval_policy")
    assert res[:3] == ("B79", "PASS", "recent Codex sessions include human-approval gates "
                                      "(0/3 sampled turns were approval=never).")


# ------------------------------------------------------------------ B78

@pytest.mark.parametrize("kind", KINDS_NOT_READABLE)
def test_b78_special_health_file_is_unknown_and_never_followed(tmp_path, kind):
    home = _home(tmp_path)
    _special(home, HEALTH, kind)
    detail = _unknown(_run(home, "check_config_health_integrity"), "B78", HEALTH, False)
    assert KIND_TEXT[kind] in detail


def test_b78_well_formed_legacy_file_is_unchanged(tmp_path):
    home = _home(tmp_path)
    _put(home, HEALTH, '{"entries": {}}')
    res = _run(home, "check_config_health_integrity")
    assert res[:3] == ("B78", "UNKNOWN",
                       "config-health file has no tracked config entries \u2014 nothing to evaluate.")
    _put(home, HEALTH, "not json")                  # already UNKNOWN today, wording unchanged
    assert "present but unreadable or malformed" in _run(home, "check_config_health_integrity")[2]


# ------------------------------------------- a link to a regular file is read as it always was

def _same_through_a_link(tmp_path, rel, check, content):
    """The finding for *content* as a regular file and through a symbolic link to it."""
    home = _home(tmp_path)
    _put(home, rel, content)
    direct = _run(home, check)
    (home / rel).unlink()
    target = home / "linked-target.dat"
    target.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    os.symlink(target, home / rel)
    return direct, _run(home, check)


PAIRED_ADMIN = json.dumps({"dev-1": {"deviceId": "dev-1", "platform": "web",
                                     "scopes": ["operator.admin"],
                                     "approvedScopes": ["operator.admin"]}})


@pytest.mark.parametrize("rel,check,content,status", [
    (PAIRED, "check_paired_device_operator_authority", PAIRED_ADMIN, "WARN"),
    (PAIRED, "check_paired_device_operator_authority", "{}", None),
    (TRUST, "check_codex_project_trust", TRUSTED, "WARN"),
    (TRUST, "check_codex_project_trust", UNTRUSTED, "PASS"),
    (HEALTH, "check_config_health_integrity", '{"entries": {}}', None),
], ids=["paired-admin", "paired-empty", "trust-trusted", "trust-untrusted", "health-empty"])
def test_a_link_to_a_regular_file_is_judged_like_the_file(tmp_path, rel, check, content, status):
    """These three files were read through a link before C-731 (`is_file()` follows one) and
    the platform reads them through it too: refusing the link would turn a real WARN into
    UNKNOWN. Only a link that leads to no regular file is "not understood"."""
    direct, linked = _same_through_a_link(tmp_path, rel, check, content)
    assert linked[:3] == direct[:3], (direct[:3], linked[:3])
    if status is not None:
        assert direct[1] == status, direct[:3]


# ------------------------------------------------ found by the independent review of C-731

TOML_TRUSTED_SPELLINGS = [
    ("trailing-comment", '[projects."/work/p"]\ntrust_level = "trusted"  # mine\n'),
    ("single-quoted-value", "[projects.\"/work/p\"]\ntrust_level = 'trusted'\n"),
    ("single-quoted-key", "[projects.'/work/p']\ntrust_level = \"trusted\"\n"),
    ("spaces-in-header", '[ projects . "/work/p" ]\ntrust_level="trusted"\n'),
    ("quoted-setting-name", '[projects."/work/p"]\n"trust_level" = "trusted"\n'),
    ("dotted-top-level", 'projects."/work/p".trust_level = "trusted"\n'),
    ("dotted-under-projects", '[projects]\n"/work/p".trust_level = "trusted"\n'),
    ("inline-under-projects", '[projects]\n"/work/p" = { trust_level = "trusted" }\n'),
    ("inline-top-level", 'projects = { "/work/p" = { trust_level = "trusted" } }\n'),
    ("crlf", '[projects."/work/p"]\r\ntrust_level = "trusted"\r\n'),
]
BS = chr(92)
TOML_UNREAD_SPELLINGS = [
    ("multi-line-basic", '[projects."/work/p"]\ntrust_level = """trusted"""\n'),
    ("multi-line-literal", "[projects.\"/work/p\"]\ntrust_level = \'\'\'trusted\'\'\'\n"),
    ("escaped-value", '[projects."/work/p"]\ntrust_level = "tr' + BS + 'u0075sted"\n'),
    ("escaped-setting-name", '[projects."/work/p"]\n"trust' + BS + 'u005flevel" = "trusted"\n'),
    ("escaped-everything", '"' + BS + 'u0070rojects" = { "/p" = { "' + BS + 'u0074rust_level" = "x" } }\n'),
    ("unquoted-value", '[projects."/work/p"]\ntrust_level = trusted\n'),
]
TOML_STILL_CLEAN = [
    ("comment-only", '# trust_level = "trusted"\n[projects."/work/p"]\n# trust_level = "trusted"\n'),
    ("top-level-key", 'trust_level = "trusted"\n[other]\nx = 1\n'),
    ("other-table", '[projects."/work/p"]\nx = 1\n[other]\ntrust_level = "trusted"\n'),
    ("windows-path", '[projects."C:' + BS * 2 + 'Users' + BS * 2 + 'me"]\ntrust_level = "untrusted"\n'),
    ("escape-elsewhere", '[mcp.x]\nargs = ["' + BS + 'u001b[0m"]\n[projects."/p"]\ntrust_level = "untrusted"\n'),
    ("latin1-byte-in-a-comment", b'# caf' + bytes([0xE9]) + b'\n[projects."/work/p"]\ntrust_level = "untrusted"\n'),
]


@pytest.mark.parametrize("name,text", TOML_TRUSTED_SPELLINGS, ids=[n for n, _ in TOML_TRUSTED_SPELLINGS])
def test_b136_reads_every_valid_way_to_write_a_trusted_project(tmp_path, name, text):
    """Each is valid TOML that Codex reads as a trusted project; all but the canonical
    spelling used to answer PASS."""
    home = _home(tmp_path)
    _put(home, TRUST, text)
    res = _run(home, "check_codex_project_trust")
    assert res[:2] == ("B136", "WARN"), res[:3]
    assert "/work/p" in res[2]


@pytest.mark.parametrize("name,text", TOML_UNREAD_SPELLINGS, ids=[n for n, _ in TOML_UNREAD_SPELLINGS])
def test_b136_a_trust_level_it_cannot_read_is_unknown_not_pass(tmp_path, name, text):
    home = _home(tmp_path)
    _put(home, TRUST, text)
    detail = _unknown(_run(home, "check_codex_project_trust"), "B136", TRUST, True)
    assert "sets trust_level in a form this audit does not read" in detail


@pytest.mark.parametrize("name,text", TOML_STILL_CLEAN, ids=[n for n, _ in TOML_STILL_CLEAN])
def test_b136_text_with_no_trusted_project_still_passes(tmp_path, name, text):
    home = _home(tmp_path)
    _put(home, TRUST, text)
    assert _run(home, "check_codex_project_trust")[:2] == ("B136", "PASS")


def test_b136_canonical_detail_is_what_it_was(tmp_path):
    home = _home(tmp_path)
    _put(home, TRUST, TRUSTED)
    res = _run(home, "check_codex_project_trust")
    assert res[:3] == ("B136", "WARN",
                       'Codex CLI project trust is set to "trusted" for: agent a: project '
                       "'/work/p' " + chr(0x2014) + " this disables Codex's own approval/sandbox "
                       "gating for everything run under that project path.")


@pytest.mark.skipif(os.geteuid() == 0, reason="chmod 000 does not stop root")
@pytest.mark.parametrize("rel,check,degraded", [
    (PAIRED, "check_paired_device_operator_authority", True),
    (TRUST, "check_codex_project_trust", True),
], ids=["paired", "trust"])
def test_a_link_into_a_directory_that_cannot_be_entered_is_unreadable_not_no_file(
        tmp_path, rel, check, degraded):
    """The target may well be a regular file; it could not be looked at. That is the
    "could not read" answer, not "does not lead to a regular file"."""
    home = _home(tmp_path)
    locked = home / "locked"
    locked.mkdir()
    (locked / "target").write_text("{}", encoding="utf-8")
    (home / rel).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(locked / "target", home / rel)
    os.chmod(locked, 0)
    try:
        res = _run(home, check)
    finally:
        os.chmod(locked, 0o700)
    assert res[1] == "UNKNOWN", res[:3]
    assert "does not lead to a regular file" not in res[2]
    assert "Could not read" in res[2] or "could not be read" in res[2] or "unreadable" in res[2], res[2]
    assert res[4] is degraded


def test_the_fix_text_does_not_say_links_are_never_followed(tmp_path):
    home = _home(tmp_path)
    _special(home, PAIRED, "dangling")
    res = _run(home, "check_paired_device_operator_authority")
    assert res[1] == "UNKNOWN" and "does not lead to a regular file" in res[2]
    assert "does not follow a symbolic link" not in res[3]


def test_b136_a_truncated_trust_line_is_unknown_not_pass(tmp_path):
    """The file ends in the middle of the one setting this check is about."""
    home = _home(tmp_path)
    _put(home, TRUST, b'[projects."/work/p"]\ntrust_level = ')
    detail = _unknown(_run(home, "check_codex_project_trust"), "B136", TRUST, True)
    assert "sets trust_level in a form this audit does not read" in detail
