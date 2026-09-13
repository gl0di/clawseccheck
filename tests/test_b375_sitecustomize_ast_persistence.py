"""Tests for B375 (F-177) — sitecustomize/PYTHONSTARTUP persistence install,
AST function-scope precision.

dossier.py's Persistence axis has exactly three feeders (B86/B87/B89), all
AST-backed. B335 (checks/_content.py's check_python_runtime_persist_install)
already recognizes this exact sitecustomize/usercustomize + PYTHONSTARTUP install
shape via a whole-file regex + a character-proximity window, but it carries no AST0x
rule of its own and cannot genuinely feed the Persistence axis the way B86/B87/B89
do (see dossier.py's `_AXIS_BY_ID` comment on the dual-axis stopgap this check
replaces with a real fourth feeder). B375 reruns the same two mechanisms at
FUNCTION-SCOPE precision via `skillast._persist_install_function_findings`:

Mechanism A — within ONE function: a site.getsitepackages()/getusersitepackages()
call, a sitecustomize.py/usercustomize.py string constant, and a write/append-mode
open() call.
Mechanism B — within ONE function: a shell-rc path string constant, a PYTHONSTARTUP=
assignment-shaped string constant, and a write/append-mode open() call.

Fixture-level cases reuse the existing B335 fixtures (the task spec is explicit that
these must now ALSO fire B375 — no new "bad" fixtures are added):
- bad_b335_no_extension_installer  : mechanism A, extension-less installer file
- bad_b335_runtime_persist_install : mechanism A (site_helper.py) and mechanism B
                                      (shell_bootstrap.py), each in its own file
- clean_b335_devtooling            : read-only site.getsitepackages() usage +
                                      in-process PYTHONSTARTUP (no shell-rc write)
- clean_b335_skill_md_doc_example  : SKILL.md fenced examples only (not Python)
- benign_b375_dotfile_alias_no_pythonstartup (NEW): an ordinary dotfile installer
                                      that appends an alias to .bashrc — no
                                      PYTHONSTARTUP anywhere. Named `benign_*`, not
                                      `clean_*` — it deliberately writes to .bashrc,
                                      which legitimately (and correctly) also trips
                                      the unrelated, pre-existing B13 "agent-config
                                      persistence" detector, so it does not belong in
                                      the clean_* "must be silent everywhere" sweep.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_sitecustomize_pythonstartup_scoped_install, vet_skill
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_HOME_FAKE = Path("/nonexistent/home")


def _ctx_with_py(skill_name: str, files: dict) -> Context:
    """Populate ctx.installed_skill_py directly (the AST engine's own input),
    mirroring test_b338_tunnel_enrollment.py's idiom. ctx.installed_skills is set to
    a non-empty placeholder so the UNKNOWN "no installed skills" gate does not fire —
    the check under test never reads its text, only installed_skill_py."""
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {skill_name: "placeholder"}
    ctx.installed_skill_py = {skill_name: list(files.items())}
    return ctx


# --------------------------------------------------------------------------- unit-level

def test_unknown_when_no_installed_skills():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == UNKNOWN
    assert f.id == "B375"


def test_no_matching_pattern_passes():
    ctx = _ctx_with_py("envtools", {"main.py": "def run():\n    pass\n"})
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == PASS, f.detail


def test_mechanism_a_site_packages_write_warns():
    ctx = _ctx_with_py("envtools", {
        "site_helper.py": (
            "import os, site\n"
            "def install():\n"
            "    sp = site.getsitepackages()\n"
            "    target = os.path.join(sp[0], \"sitecustomize.py\")\n"
            "    with open(target, \"w\") as fh:\n"
            "        fh.write(\"import os\\n\")\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == WARN, f.detail
    assert "mechanism A" in f.detail


def test_mechanism_a_usersitepackages_variant_warns():
    ctx = _ctx_with_py("envtools", {
        "site_helper.py": (
            "import os, site\n"
            "def install():\n"
            "    target = os.path.join(site.getusersitepackages(), \"usercustomize.py\")\n"
            "    with open(target, \"ab\") as fh:\n"
            "        fh.write(b\"import os\\n\")\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == WARN, f.detail


def test_mechanism_b_pythonstartup_shellrc_write_warns():
    ctx = _ctx_with_py("envtools", {
        "shell_bootstrap.py": (
            "import os\n"
            "def install():\n"
            "    startup = os.path.expanduser('~/.envtools_startup.py')\n"
            "    with open(startup, 'w') as fh:\n"
            "        fh.write('import os\\n')\n"
            "    bashrc = os.path.expanduser('~/.bashrc')\n"
            "    with open(bashrc, 'a') as fh:\n"
            "        fh.write(f'export PYTHONSTARTUP=\"{startup}\"\\n')\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == WARN, f.detail
    assert "mechanism B" in f.detail


# ------------------------------------------------------------- benign counter-examples

def test_site_packages_read_only_no_write_call_passes():
    """A venv/package-inspector skill that calls site.getsitepackages() purely to
    enumerate/print paths, with no open(..., 'w'/'a') anywhere in the function —
    signal 3 (write) is absent, so it must not fire."""
    ctx = _ctx_with_py("venv-doctor", {
        "diagnose.py": (
            "import site\n"
            "def print_site_dirs():\n"
            "    for path in site.getsitepackages():\n"
            "        print(f'candidate site-packages dir: {path}')\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == PASS, f.detail


def test_pythonstartup_set_in_process_without_shell_rc_write_passes():
    """PYTHONSTARTUP set in-process (dict-key assignment, not a shell-rc write) for a
    subprocess's env — mechanism B needs a shell-rc path AND an assignment-shaped
    PYTHONSTARTUP string AND a write, none of which appear here as real values (the
    dict-key assignment carries no textual "PYTHONSTARTUP=" anywhere)."""
    ctx = _ctx_with_py("venv-doctor", {
        "repl_env.py": (
            "import os, subprocess\n"
            "def run_with_custom_repl(startup_script):\n"
            "    env = dict(os.environ)\n"
            "    env['PYTHONSTARTUP'] = startup_script\n"
            "    subprocess.run(['python3'], env=env, check=False)\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == PASS, f.detail


# ------------------------------------------------------- C-135 adversarial-review FPs

def test_scope_locality_write_in_different_function_passes():
    """Scope-locality (per the F-177 task spec): site.getsitepackages() is called in
    ONE function; an unrelated function elsewhere in the same file computes a
    sitecustomize.py path and writes it. The two never co-occur in the same function
    scope, so this must not fire — this is the property that keeps a skill with two
    independently-benign functions from convicting on their combination."""
    ctx = _ctx_with_py("splitfunc", {
        "helper.py": (
            "import os, site\n"
            "\n"
            "def lookup_site_dirs():\n"
            "    return site.getsitepackages()\n"
            "\n"
            "def write_unrelated_cache():\n"
            "    target = os.path.join('/tmp', 'sitecustomize.py')\n"
            "    with open(target, 'w') as fh:\n"
            "        fh.write('unrelated cache content')\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == PASS, f.detail


def test_unrelated_bashrc_alias_append_passes():
    """An ordinary dotfile installer appends an alias to .bashrc; PYTHONSTARTUP never
    appears anywhere in the file. Mechanism B needs both the shell-rc target AND a
    PYTHONSTARTUP assignment-shaped string — only the first is present."""
    ctx = _ctx_with_py("dotfiles-alias", {
        "install_alias.py": (
            "import os\n"
            "def install_alias():\n"
            "    bashrc = os.path.expanduser('~/.bashrc')\n"
            "    with open(bashrc, 'a') as fh:\n"
            "        fh.write('alias ll=\"ls -la\"\\n')\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == PASS, f.detail


def test_disclaiming_docstring_mention_plus_unrelated_write_passes():
    """C-135 adversarial finding (F-177): a docstring DISCLAIMS touching
    sitecustomize.py ("Does not touch sitecustomize.py -- read-only"), and the same
    function separately writes an unrelated JSON report. Before the prose-exclusion
    fix, the docstring's own mention of the filename combined with the unrelated
    write to false-WARN; a docstring/comment mentioning a filename is not the same as
    using it as a real path."""
    ctx = _ctx_with_py("pkg-auditor", {
        "audit.py": (
            "import json, site\n"
            "def collect_env_report(output_path):\n"
            "    \"\"\"Does not touch sitecustomize.py or usercustomize.py -- "
            "read-only.\"\"\"\n"
            "    info = {'site_packages': site.getsitepackages()}\n"
            "    with open(output_path, 'w') as fh:\n"
            "        json.dump(info, fh)\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == PASS, f.detail


def test_disclaiming_docstring_pythonstartup_mention_plus_bashrc_write_passes():
    """Mechanism B's twin of the disclaiming-docstring case: a docstring explicitly
    disclaims touching PYTHONSTARTUP, and the same function appends an unrelated PATH
    export to .bashrc — the word PYTHONSTARTUP never appears in real assignment
    position, only inside the disclaiming prose."""
    ctx = _ctx_with_py("dotfiles-mgr", {
        "apply_dotfiles.py": (
            "import os\n"
            "def install_shell_env():\n"
            "    \"\"\"Adds our tool's PATH export to .bashrc.\n"
            "\n"
            "    Note: we intentionally do NOT touch PYTHONSTARTUP or any Python "
            "REPL customization here.\n"
            "    \"\"\"\n"
            "    rc_path = os.path.expanduser('~/.bashrc')\n"
            "    with open(rc_path, 'a') as fh:\n"
            "        fh.write('\\nexport PATH=\"$HOME/.mytool/bin:$PATH\"\\n')\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == PASS, f.detail


def test_mid_function_bare_string_mention_plus_unrelated_write_passes():
    """A stray mid-function bare string statement (not the docstring, but the same
    "prose, not a value in use" shape) mentioning usercustomize.py, combined with an
    unrelated write later in the same function, must not fire."""
    ctx = _ctx_with_py("noteworthy", {
        "notes.py": (
            "import site\n"
            "def do_things(output_path):\n"
            "    site.getsitepackages()\n"
            "    'TODO: consider usercustomize.py support later'\n"
            "    with open(output_path, 'w') as fh:\n"
            "        fh.write('unrelated')\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == PASS, f.detail


def test_mechanism_b_transparent_install_still_warns():
    """Counter-check (NOT a false positive, left as-is by design, mirroring B335's
    own equivalent test): a dotfiles/REPL skill that transparently sets PYTHONSTARTUP
    via .bashrc — the textbook legitimate use of the exact mechanism this check
    watches for, with every signal inside ONE function's own scope (the real
    bad_b335_runtime_persist_install fixture's own shape — see shell_bootstrap.py).
    Must still WARN, confirming the prose-exclusion fix did not reintroduce a false
    negative for the real install shape."""
    ctx = _ctx_with_py("dotfiles-mgr", {
        "repl_history.py": (
            "import os\n"
            "def install_python_repl_history():\n"
            "    startup = os.path.expanduser('~/.pythonrc')\n"
            "    with open(startup, 'w') as fh:\n"
            "        fh.write('import atexit\\n')\n"
            "    bashrc = os.path.expanduser('~/.bashrc')\n"
            "    with open(bashrc, 'a') as fh:\n"
            "        fh.write('# managed by dotfiles: python REPL history\\n')\n"
            "        fh.write(f'export PYTHONSTARTUP=\"{startup}\"\\n')\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == WARN, f.detail
    assert "mechanism B" in f.detail


def test_module_level_target_constant_referenced_by_name_is_a_known_scope_limit():
    """Documents a deliberate, accepted precision boundary (not a bug): when the
    shell-rc/sitecustomize target path is computed at MODULE level and only
    referenced by NAME inside the function (rather than computed inside the function
    itself, as both real bad_b335_* fixtures do), the target string constant is
    outside the function's own AST subtree and this function-scoped check does not
    see it — unlike B335's whole-file regex sibling, which would still catch it.
    This is the direct, intended cost of the scope-locality boundary the task spec
    requires (it is what keeps an unrelated read + an unrelated write in two
    different functions from co-convicting); B335 stays the whole-file backstop for
    this specific split-declaration variant."""
    ctx = _ctx_with_py("dotfiles-mgr", {
        "repl_history.py": (
            "import os\n"
            "STARTUP = os.path.expanduser('~/.pythonrc')\n"
            "BASHRC = os.path.expanduser('~/.bashrc')\n"
            "def install_python_repl_history():\n"
            "    with open(STARTUP, 'w') as fh:\n"
            "        fh.write('import atexit\\n')\n"
            "    with open(BASHRC, 'a') as fh:\n"
            "        fh.write(f'export PYTHONSTARTUP=\"{STARTUP}\"\\n')\n"
        ),
    })
    f = check_sitecustomize_pythonstartup_scoped_install(ctx)
    assert f.status == PASS, f.detail


# --------------------------------------------------------------------------- vet-level

def test_vet_extensionless_installer_warns():
    """bad_b335_no_extension_installer must now ALSO fire B375 (mechanism A, via a
    shebang-detected extension-less `install` file — the AST engine's own Python
    collection reaches it the same way B335's does)."""
    skill_dir = FIXTURES / "bad_b335_no_extension_installer" / "skills" / "envtools-installer"
    f = vet_skill(skill_dir)
    findings = [f, *getattr(f, "ring_findings", [])]
    assert any(x.id == "B375" and x.status == WARN for x in findings)


def test_vet_bad_runtime_persist_install_warns():
    """bad_b335_runtime_persist_install must now ALSO fire B375 (both mechanism A via
    site_helper.py and mechanism B via shell_bootstrap.py)."""
    skill_dir = FIXTURES / "bad_b335_runtime_persist_install" / "skills" / "envtools"
    f = vet_skill(skill_dir)
    findings = [f, *getattr(f, "ring_findings", [])]
    assert any(x.id == "B375" and x.status == WARN for x in findings)


def test_vet_clean_devtooling_passes():
    skill_dir = FIXTURES / "clean_b335_devtooling" / "skills" / "venv-doctor"
    f = vet_skill(skill_dir)
    findings = [f, *getattr(f, "ring_findings", [])]
    assert not any(x.id == "B375" and x.status == WARN for x in findings)


def test_vet_clean_skill_md_doc_example_passes():
    """SKILL.md is Markdown, never fed to the Python AST engine at all — this must
    stay quiet by construction, independent of the doc-only text it contains."""
    skill_dir = FIXTURES / "clean_b335_skill_md_doc_example" / "skills" / "py-devenv"
    f = vet_skill(skill_dir)
    findings = [f, *getattr(f, "ring_findings", [])]
    assert not any(x.id == "B375" and x.status == WARN for x in findings)


def test_vet_dotfile_alias_installer_does_not_fire_b375():
    """NEW fixture (F-177): an ordinary dotfile installer that appends an alias to
    .bashrc, with no PYTHONSTARTUP anywhere in the skill — B375 specifically must
    not fire (this fixture legitimately trips the unrelated, pre-existing B13
    "agent-config persistence" detector for the .bashrc write itself, which is why
    it is named `benign_*` rather than `clean_*` — see its SKILL.md)."""
    skill_dir = (
        FIXTURES / "benign_b375_dotfile_alias_no_pythonstartup" / "skills" / "dotfiles-alias"
    )
    f = vet_skill(skill_dir)
    findings = [f, *getattr(f, "ring_findings", [])]
    assert not any(x.id == "B375" and x.status == WARN for x in findings)


# --------------------------------------------------------------- Persistence axis (F-177)

def test_persistence_axis_gets_b375_directly():
    """The actual point of this task: B375 must route to the Persistence axis via
    dossier.py's `_AXIS_BY_ID`, the same direct-routing style as B86/B87/B89 — not a
    dual-axis special case like B335's own stopgap."""
    from clawseccheck.dossier import axis_for
    from clawseccheck.catalog import BY_ID

    class _FakeFinding:
        id = "B375"

    assert axis_for(_FakeFinding()) == "persistence"
    assert BY_ID["B375"].id == "B375"
