"""TT4 (file-read -> network sink) and SSRF (tainted URL -> network-fetch) inline-taint
false negative.

Deliberately named WITHOUT a ticket number. Two independent ambiguities were found
while implementing this fix and neither was safe to silently guess past:

  1. The task that produced this fix names the ticket "SBOOK-B-132" -- but this
     project's own Pulse convention (CLAUDE.md Sec.10) is `CLAWSECCHECK-B-<n>`, not
     `SBOOK-B-<n>` (that prefix belongs to a *different* project). This looks like a
     cross-project ID bleed, not a real ID for this repo.
  2. Even reading it as plain "B-132", `CLAWSECCHECK-B-132` already exists in this
     exact codebase for something else entirely -- the B13 false-positive fixes
     (fixed-argv subprocess, `torch.load(weights_only=True)`, the first-party-host
     allowlist; see `_subprocess_call_is_fixed_argv`'s docstring and
     `tests/test_b132_b13_fp_fixes.py`). Stamping *this* fix as "B-132" too would
     silently conflate two unrelated tickets in the same file.

So: no ticket number anywhere in this file's comments, and a purely descriptive
filename. Flagged explicitly for the orchestrator to get the correct Pulse ID before
filing/closing anything.

---

Root cause (three stacked gates, all name-only):

  G1 -- a file-level pre-scan (`_has_inline_exec_sink_source` and its new SSRF/TT4
        siblings `_has_inline_ssrf_source`/`_has_inline_tt4_source` in skillast.py)
        that decides whether the whole TT5/TT4/SSRF pass runs at all for a file. Only
        the exec-sink shape was recognized; a file whose ONLY taint source was an
        inline SSRF/TT4 shape skipped the pass entirely.
  G2 -- TT4's own `if file_t:` gate, populated only by `_file_tainted` (bound NAMES
        only).
  G3 -- the shared `_call_args_tainted` per-call check, which intersects only
        `ast.Name` references against a tainted-names set -- an inline expression,
        with no intermediate variable, has no Name in it at all and can never match.

So `requests.get(os.environ["URL"])` and `requests.post(u, data=open(p).read())` --
the source read directly in the sink call's own arguments, nothing ever assigned to a
variable -- produced ZERO findings, even though the byte-identical code with the
source bound to a name first (`u = os.environ["URL"]; requests.get(u)`) already fired
correctly.

Fix shape: TWO separate, narrow, per-sink wrapper functions --
`_call_args_tainted_for_ssrf_sink` and `_call_args_tainted_for_file_net_sink` --
deliberately NOT a single shared generic helper (that would have been wrong for
both: TT4's inline source must stay file-reads-only, matching its existing bound-path
vocabulary and the ENV_EXFIL_FLOW/TT4 split; SSRF's inline check must stay scoped to
the URL-argument SLOT only -- `_ssrf_url_slot_nodes` -- never headers=/auth=/cert=,
mirroring `_ENV_AUTH_KWARGS`'s existing rule that a secret in an auth header is not
exfiltration). TT5's own exec-sink wrapper (`_call_args_tainted_for_exec_sink`,
B-916) is untouched by this fix and re-verified unaffected below.

Every URL/host/credential-shaped string below is INERT test data handed to
`analyze_python`'s read-only AST parser (never executes, never makes a network call)
-- matching every sibling test module in this directory (test_b916_inline_exec_source_
taint.py, test_taint_extended.py, ...).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from clawseccheck.skillast import analyze_python


def _rules(src: str, filename: str = "x.py") -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, filename)}


def _convicts_crit(src: str, filename: str = "x.py") -> bool:
    return any(f.severity == "crit" for f in analyze_python(src, filename))


# ---------------------------------------------------------------------------
# SSRF: inline URL-slot taint, one variant per external-source shape named in the
# ticket. Each is paired with a nearby shape that must stay silent.
# ---------------------------------------------------------------------------


def test_ssrf_inline_env_subscript_fires():
    src = (
        "import os, requests\n"
        "def f():\n"
        "    requests.get(os.environ[\"URL\"])\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r
    assert "direct" in r["TT_SSRF"].reason


def test_ssrf_fixed_url_with_env_in_auth_header_does_not_fire():
    """Paired negative: the same env read, but in headers=, not the URL -- must stay
    silent per `_ENV_AUTH_KWARGS`'s existing, deliberate rule."""
    src = (
        "import os, requests\n"
        "FIXED_URL = \"https://example.com/api\"\n"
        "def f():\n"
        "    requests.get(FIXED_URL, headers={\"Authorization\": os.environ[\"TOKEN\"]})\n"
    )
    assert "TT_SSRF" not in _rules(src)


def test_ssrf_inline_os_getenv_fires():
    src = (
        "import os, requests\n"
        "def f():\n"
        "    requests.get(os.getenv(\"URL\"))\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r
    assert r["TT_SSRF"].severity == "info"


def test_ssrf_inline_input_fires():
    src = "import requests\ndef f():\n    requests.get(input())\n"
    r = _rules(src)
    assert "TT_SSRF" in r
    assert "direct" in r["TT_SSRF"].reason


def test_ssrf_inline_fstring_embedding_os_environ_fires():
    src = (
        "import os, requests\n"
        "def f():\n"
        "    requests.get(f\"https://{os.environ['HOST']}/x\")\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r


def test_ssrf_fstring_of_pure_literals_does_not_fire():
    """Paired negative: an f-string with no tainted name inside it must stay silent."""
    src = (
        "import requests\n"
        "def f():\n"
        "    host = \"example.com\"\n"
        "    requests.get(f\"https://{host}/fixed\")\n"
    )
    assert "TT_SSRF" not in _rules(src)


def test_ssrf_inline_sys_argv_fires():
    src = "import sys, requests\ndef f():\n    requests.get(sys.argv[1])\n"
    r = _rules(src)
    assert "TT_SSRF" in r


def test_ssrf_inline_chained_json_key_off_network_call_fires():
    """`requests.get(...).json()["key"]` used directly as the next call's URL --
    external input chained through a network read, still inline, no variable."""
    src = (
        "import requests\n"
        "def f():\n"
        "    requests.get(requests.get(\"https://x.example/y\").json()[\"next\"])\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r


def test_ssrf_alias_import_os_as_o_fires():
    """`import os as o` then `o.environ["URL"]` inline -- alias handling via the
    positively-resolved-reference path (`ref_res.source_in`)."""
    src = (
        "import os as o\n"
        "import requests\n"
        "def f():\n"
        "    requests.get(o.environ[\"URL\"])\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r


def test_ssrf_subscript_only_environ_with_no_import_os_at_all_fires():
    """`os.environ["URL"]` inline with no `import os` anywhere in the file -- the
    subscript-only pattern `_rhs_has_subscript_environ` already models for the bound
    path, now reached through `_expr_is_ext_tainted` for the inline case too."""
    src = "import requests\ndef f():\n    requests.get(os.environ[\"URL\"])\n"
    r = _rules(src)
    assert "TT_SSRF" in r


def test_ssrf_starred_positional_splat_fires():
    src = (
        "import os, requests\n"
        "def f():\n"
        "    a = (os.environ[\"URL\"],)\n"
        "    requests.get(*a)\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r


def test_ssrf_kwargs_splat_fires():
    src = (
        "import os, requests\n"
        "def f():\n"
        "    kw = {\"url\": os.environ[\"URL\"]}\n"
        "    requests.get(**kw)\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r


def test_ssrf_kwargs_splat_with_no_taint_does_not_fire():
    """Paired negative: a `**kwargs` splat that carries no taint at all (only
    timeout=) against a fixed URL must stay silent."""
    src = (
        "import requests\n"
        "def f():\n"
        "    kw = {\"timeout\": 5}\n"
        "    requests.get(\"https://fixed.example/x\", **kw)\n"
    )
    assert "TT_SSRF" not in _rules(src)


def test_ssrf_fixed_url_with_env_in_auth_header_via_kwargs_splat_does_not_fire():
    """Paired negative for the DICT-LITERAL `**{...}` splat form of
    `test_ssrf_fixed_url_with_env_in_auth_header_does_not_fire` above: the same
    tainted value under `headers`, reached through `**{"headers": ...}` instead of a
    direct `headers=` keyword, must stay silent for the exact same reason -- the
    excluded key stays excluded regardless of which spelling reaches it."""
    src = (
        "import os, requests\n"
        "FIXED_URL = \"https://example.com/api\"\n"
        "def f():\n"
        "    requests.get(FIXED_URL, **{\"headers\": {\"Authorization\": os.environ[\"TOKEN\"]}})\n"
    )
    assert "TT_SSRF" not in _rules(src)


def test_ssrf_url_key_in_kwargs_splat_dict_literal_fires():
    """The `url` key IS one of `_SSRF_URL_KWARGS` -- when it is genuinely present in
    a splatted dict literal, unlike the `headers` key above, it must still fire."""
    src = (
        "import os, requests\n"
        "def f():\n"
        "    requests.get(**{\"url\": os.environ[\"URL\"]})\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r


def test_ssrf_opaque_kwargs_splat_via_call_falls_back_to_permissive_check():
    """A `**` unpack of a CALL -- not a dict literal, so its keys can never be
    statically read -- can't be narrowed like the two dict-literal cases above and
    must stay on the old, fully permissive "unknown until runtime, be conservative"
    path: the whole splat expression is still a candidate URL slot, so an
    externally-sourced value nested inside it (here, the same network-response-
    chained-into-a-key shape `test_ssrf_inline_chained_json_key_off_network_call_
    fires` already covers un-splatted) is still found."""
    src = (
        "import requests\n"
        "FIXED_URL = \"https://example.com/api\"\n"
        "def f():\n"
        "    requests.get(FIXED_URL, **requests.get(\"https://x.example/y\").json())\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r


def test_ssrf_mixed_dict_literal_splat_url_and_headers_both_tainted_fires_via_url_key():
    """A dict literal splat carrying BOTH a tainted `url` key and a tainted (but
    excluded) `headers` key: must still fire -- via the `url` key alone -- and the
    finding's reason text must not misattribute the conviction to the excluded
    `headers` key (this rule's reason string never names a specific keyword either
    way, so this also pins that it stays that way for the splat form)."""
    src = (
        "import os, requests\n"
        "def f():\n"
        "    requests.get(**{\n"
        "        \"url\": os.environ[\"URL\"],\n"
        "        \"headers\": {\"Authorization\": os.environ[\"TOKEN\"]},\n"
        "    })\n"
    )
    r = _rules(src)
    assert "TT_SSRF" in r
    assert "headers" not in r["TT_SSRF"].reason


def test_ssrf_literal_concat_url_does_not_fire():
    """Paired negative: string concatenation of only literals -- no taint anywhere --
    must not newly fire."""
    src = (
        "import requests\n"
        "BASE = \"https://example.com/\"\n"
        "def f():\n"
        "    requests.get(BASE + \"api\" + \"/x\")\n"
    )
    assert "TT_SSRF" not in _rules(src)


# ---------------------------------------------------------------------------
# TT4: inline file-read-to-network-sink taint.
# ---------------------------------------------------------------------------


def test_tt4_inline_open_read_as_data_fires():
    src = (
        "import requests\n"
        "def f(p, U):\n"
        "    requests.post(U, data=open(p).read())\n"
    )
    r = _rules(src)
    assert "TT4_FILE_NET" in r
    assert "indirect" in r["TT4_FILE_NET"].reason


def test_tt4_inline_read_text_fires():
    src = (
        "import pathlib, requests\n"
        "def f(U):\n"
        "    requests.post(U, data=pathlib.Path(\"p\").read_text())\n"
    )
    assert "TT4_FILE_NET" in _rules(src)


def test_tt4_inline_with_block_fh_read_fires():
    """`with open(p) as fh: ...fh.read()` used inline as the sink argument -- the
    idiom every style guide recommends, must not be a blind spot the way the
    equivalent B-643 bound-path gap once was."""
    src = (
        "import requests\n"
        "def f(p, U):\n"
        "    with open(p) as fh:\n"
        "        requests.post(U, data=fh.read())\n"
    )
    assert "TT4_FILE_NET" in _rules(src)


def test_tt4_inline_sendall_open_read_fires():
    """`.sendall(open().read())` inline -- the sink-name spelling this engine already
    requires (`_NET_OUT_SINK_BASES`) is a variable literally named/spelled `socket`,
    same requirement the pre-existing BOUND-path form already has; this test isolates
    the inline-taint fix from that unrelated, pre-existing sink-name-spelling
    limitation by using the spelling the sink recognizer already expects."""
    src = (
        "import socket as socketmod\n"
        "def f(p):\n"
        "    socket = socketmod.socket(socketmod.AF_INET, socketmod.SOCK_STREAM)\n"
        "    socket.connect((\"x\", 1))\n"
        "    socket.sendall(open(p).read())\n"
    )
    assert "TT4_FILE_NET" in _rules(src)


def test_tt4_inline_urlopen_read_fires():
    """`urlopen(...).read()` inline as TT4 data -- `.read()` is in
    `_FILE_READ_METHOD_ATTRS` regardless of what produced the readable object, exactly
    matching the existing bound-path source vocabulary (`_is_file_read_value`)."""
    src = (
        "from urllib.request import urlopen\n"
        "import requests\n"
        "def f(U):\n"
        "    requests.post(U, data=urlopen(\"https://x.example/y\").read())\n"
    )
    assert "TT4_FILE_NET" in _rules(src)


def test_tt4_env_value_as_data_does_not_produce_tt4():
    """Paired negative: an env value used inline as network-sink data -- TT4's source
    vocabulary is file-reads only (the existing ENV_EXFIL_FLOW/TT4 split), so this
    must NOT produce a NEW TT4_FILE_NET finding. ENV_EXFIL_FLOW firing instead is a
    separate, unrelated, pre-existing rule -- not asserted against either way here."""
    src = (
        "import os, requests\n"
        "def f(U):\n"
        "    requests.post(U, data=os.environ[\"K\"])\n"
    )
    assert "TT4_FILE_NET" not in _rules(src)


def test_bare_open_with_no_read_anywhere_does_not_fire_tt4():
    """Paired negative: `open(p, "rb")` with no `.read()`/`.read_text()`/... call
    anywhere -- not a read, must not fire TT4."""
    src = "def f(p):\n    fh = open(p, \"rb\")\n    return fh\n"
    assert "TT4_FILE_NET" not in _rules(src)


# ---------------------------------------------------------------------------
# G1 non-vacuity: the inline TT4/SSRF shape must fire on its own, independent of
# whether an inline exec-sink source ALSO happens to be present in the same file.
# ---------------------------------------------------------------------------


def test_inline_tt4_fires_in_a_file_that_also_has_an_unrelated_inline_exec_source():
    """Proves the G1 widening is a real OR of three independent conditions, not an
    accidental dependency on the pre-existing exec flag: an inline file-read-to-
    network-sink shape in one function, and a completely separate inline exec-sink
    source in another function of the SAME file. Both must fire on their own merits."""
    src = (
        "import os, requests\n"
        "def uses_exec():\n"
        "    exec(os.environ[\"CMD\"])\n"
        "def uses_tt4(p, U):\n"
        "    requests.post(U, data=open(p).read())\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert "TT4_FILE_NET" in r


def test_inline_ssrf_fires_alone_with_no_exec_sink_or_named_taint_anywhere_in_file():
    """Non-vacuity for the SSRF half of G1 in isolation: a file whose ONLY taint
    source anywhere is this one inline SSRF shape (no exec sink, no bound tainted
    NAME) must still reach the pass and fire."""
    src = "import os, requests\ndef f():\n    requests.get(os.environ[\"URL\"])\n"
    r = _rules(src)
    assert "TT_SSRF" in r
    assert "TT5_CMD_INJECTION" not in r


def test_file_with_no_sink_at_all_is_unaffected_by_the_new_gates():
    """Non-vacuity for the new file-level pre-scans themselves: a file with an inline
    external-input read but no SSRF/TT4/TT5 sink anywhere must stay exactly as
    before -- no new finding conjured out of the pre-scan alone."""
    src = (
        "import os\n"
        "def f():\n"
        "    value = os.environ[\"URL\"]\n"
        "    return value\n"
    )
    r = _rules(src)
    assert "TT_SSRF" not in r
    assert "TT4_FILE_NET" not in r
    assert "TT5_CMD_INJECTION" not in r


# ---------------------------------------------------------------------------
# TT5 regression pin: the exec-sink wrapper/site this fix deliberately leaves
# untouched must behave identically before and after.
# ---------------------------------------------------------------------------


def test_tt5_inline_env_subprocess_still_fires_unchanged():
    """The exact B-916 repro, re-run here: same finding, same severity, same flow
    kind, completely unaffected by the new SSRF/TT4 wrappers/gates."""
    src = (
        "import os, subprocess\n"
        "def f():\n"
        "    subprocess.check_call([os.environ[\"P\"], \"x\"])\n"
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"
    assert "direct" in r["TT5_CMD_INJECTION"].reason


def test_tt5_bound_name_form_still_fires_unchanged():
    src = (
        "import os, subprocess\n"
        "def f():\n"
        "    p = os.environ[\"P\"]\n"
        "    subprocess.check_call([p, \"x\"])\n"
    )
    assert _convicts_crit(src)
