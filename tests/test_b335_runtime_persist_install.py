"""Tests for B335 (T06, SkillTrustBench / B-343) — runtime-computed Python
auto-execution persistence install (sitecustomize/usercustomize write, PYTHONSTARTUP
shell-rc).

B99's sibling: B99 catches a file *shipped as-is* named sitecustomize.py/.pth; B335
catches a script that *computes* an auto-exec target path at runtime and
writes/installs it, where the shipped skill itself contains no such filename.

Checks:
- bad_b335_runtime_persist_install : mechanism A (site.getsitepackages() + write open)
                                      and mechanism B (PYTHONSTARTUP + shell rc + write
                                      open) each in their own file -> WARN
- clean_b335_devtooling            : site.getsitepackages() used read-only (no write),
                                      and PYTHONSTARTUP set in-process for a subprocess
                                      without ever touching a shell rc file -> PASS

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import check_python_runtime_persist_install, vet_skill
from clawseccheck.collector import Context

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

_HOME_FAKE = Path("/nonexistent/home")


def _blob(files: dict) -> str:
    return "\n".join(f"# file: {name}\n{content}" for name, content in files.items())


def _ctx_with_blob(skill_name: str, files: dict) -> Context:
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {skill_name: _blob(files)}
    return ctx


# --------------------------------------------------------------------------- unit-level

def test_unknown_when_no_installed_skills():
    ctx = Context(home=_HOME_FAKE)
    ctx.installed_skills = {}
    f = check_python_runtime_persist_install(ctx)
    assert f.status == UNKNOWN


def test_mechanism_a_site_packages_write_warns():
    ctx = _ctx_with_blob("envtools", {
        "site_helper.py": (
            "import os, site\n"
            "def install():\n"
            "    sp = site.getsitepackages()\n"
            "    target = os.path.join(sp[0], \"sitecustomize.py\")\n"
            "    with open(target, \"w\") as fh:\n"
            "        fh.write(\"import os\\n\")\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == WARN, f.detail
    assert "mechanism A" in f.detail


def test_mechanism_a_usersitepackages_variant_warns():
    ctx = _ctx_with_blob("envtools", {
        "site_helper.py": (
            "import os, site\n"
            "def install():\n"
            "    target = os.path.join(site.getusersitepackages(), \"usercustomize.py\")\n"
            "    with open(target, \"ab\") as fh:\n"
            "        fh.write(b\"import os\\n\")\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == WARN, f.detail


def test_mechanism_b_pythonstartup_shellrc_write_warns():
    ctx = _ctx_with_blob("envtools", {
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
    f = check_python_runtime_persist_install(ctx)
    assert f.status == WARN, f.detail
    assert "mechanism B" in f.detail


def test_no_matching_pattern_passes():
    ctx = _ctx_with_blob("envtools", {
        "SKILL.md": "---\nname: x\ndescription: y\n---\n",
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == PASS, f.detail


# ------------------------------------------------------------- benign counter-examples

def test_site_packages_read_only_no_write_call_passes():
    """Anticipated FP #1: a venv/package-inspector skill that calls
    site.getsitepackages() purely to enumerate/print paths, with no open(..., 'w'/'a')
    anywhere in the file — signal 3 (write) is absent, so it must not fire."""
    ctx = _ctx_with_blob("venv-doctor", {
        "diagnose.py": (
            "import site\n"
            "def print_site_dirs():\n"
            "    for path in site.getsitepackages():\n"
            "        print(f'candidate site-packages dir: {path}')\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == PASS, f.detail


def test_pythonstartup_set_in_process_without_shell_rc_write_passes():
    """Anticipated FP #3 (partial): PYTHONSTARTUP set in-process for a subprocess's
    env, with no shell rc file ever opened for write — mechanism B needs all three
    signals, so this must not fire."""
    ctx = _ctx_with_blob("venv-doctor", {
        "repl_env.py": (
            "import os, subprocess\n"
            "def run_with_custom_repl(startup_script):\n"
            "    env = dict(os.environ)\n"
            "    env['PYTHONSTARTUP'] = startup_script\n"
            "    subprocess.run(['python3'], env=env, check=False)\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == PASS, f.detail


def test_pythonstartup_env_read_without_write_passes():
    """A script that only reads os.environ.get('PYTHONSTARTUP') (no write-mode open
    anywhere) must not fire — reading is not installing."""
    ctx = _ctx_with_blob("envtools", {
        "read_only.py": (
            "import os\n"
            "startup = os.environ.get('PYTHONSTARTUP')\n"
            "print(startup)\n"
            "# see also ~/.bashrc for shell customization\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == PASS, f.detail


# ------------------------------------------------------- C-135 adversarial-review FPs
#
# An independent adversarial review pass (B-343) found that mechanism A's has_write
# boolean and mechanism B's `\bPYTHONSTARTUP\b` mention were each computed once over
# the WHOLE file body with no correlation to the other signal — so an unrelated write
# elsewhere in the same file (a JSON report, a lock file, a log) combined with an
# unrelated, read-only site-packages/PYTHONSTARTUP mention to false-WARN on ordinary
# CI/devtooling/dotfiles skills. Each case below reproduces a confirmed FP and pins
# the fix (filename correlation + proximity for mechanism A; assignment-syntax +
# proximity for mechanism B).

def test_mechanism_a_unrelated_write_far_from_site_packages_call_passes():
    """CI/test-isolation helper: site.getsitepackages() used read-only to build a
    coverage-exclusion list in one function; an unrelated JSON test-report write in a
    completely different function. No sitecustomize/usercustomize filename is ever
    built or written anywhere in the file."""
    ctx = _ctx_with_blob("ci-helper", {
        "conftest.py": (
            "import json\n"
            "import site\n"
            "\n"
            "def get_stdlib_site_dirs():\n"
            "    \"\"\"Used by coverage config to exclude site-packages from "
            "instrumentation.\"\"\"\n"
            "    return site.getsitepackages()\n"
            "\n"
            "def pytest_sessionfinish(session, exitstatus):\n"
            "    results = {\"exit\": exitstatus}\n"
            "    with open(\"test-report.json\", \"w\") as fh:\n"
            "        json.dump(results, fh)\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == PASS, f.detail


def test_mechanism_a_venv_report_plus_unrelated_lockfile_write_passes():
    """venv-management tool: a diagnostic prints the user site-packages path; a
    separate freeze() writes an unrelated requirements.lock — the two are unrelated
    in purpose and location, and no sitecustomize/usercustomize path is built."""
    ctx = _ctx_with_blob("venv-report", {
        "venvtool.py": (
            "import json\n"
            "import site\n"
            "\n"
            "def report_env():\n"
            "    print(\"user site-packages:\", site.getusersitepackages())\n"
            "\n"
            "def freeze(packages):\n"
            "    with open(\"requirements.lock\", \"w\") as fh:\n"
            "        json.dump(packages, fh)\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == PASS, f.detail


def test_mechanism_a_site_packages_dir_used_for_unrelated_cache_filename_passes():
    """A lint/package-manager-style incremental-cache tool joins the site-packages
    dir with a filename that is NOT sitecustomize.py/usercustomize.py (a lint cache).
    The bare `site.getsitepackages(` alternative alone must not be enough — the
    written filename has to actually be the auto-exec target."""
    ctx = _ctx_with_blob("pkg-auditor", {
        "lintcache.py": (
            "import json\n"
            "import os\n"
            "import site\n"
            "\n"
            "def write_lint_cache(results):\n"
            "    sp = site.getsitepackages()[0]\n"
            "    cache_path = os.path.join(sp, '.lint_cache.json')\n"
            "    with open(cache_path, 'w') as fh:\n"
            "        json.dump(results, fh)\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == PASS, f.detail


def test_mechanism_a_readonly_diagnostics_plus_unrelated_report_write_passes():
    """A pkg-auditor style skill: site.getsitepackages()/getusersitepackages() used
    read-only for diagnostics; a completely separate, unrelated JSON report write.
    Empirically the strongest of the reported FPs — confirmed to drop a real vet
    dossier grade from A to B despite B335 being advisory (scored=False)."""
    ctx = _ctx_with_blob("pkg-auditor", {
        "audit.py": (
            "import json, site\n"
            "\n"
            "def collect_env_report(output_path):\n"
            "    info = {\n"
            "        'site_packages': site.getsitepackages(),\n"
            "        'user_site_packages': site.getusersitepackages(),\n"
            "    }\n"
            "    with open(output_path, 'w') as fh:\n"
            "        json.dump(info, fh, indent=2)\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == PASS, f.detail


def test_mechanism_b_pythonstartup_mentioned_only_in_disclaiming_docstring_passes():
    """A dotfiles-management skill's docstring explicitly disclaims touching
    PYTHONSTARTUP ('we intentionally do NOT touch PYTHONSTARTUP'); the actual write
    only appends an unrelated PATH export to .bashrc. The word 'PYTHONSTARTUP' never
    appears in assignment position anywhere in the file."""
    ctx = _ctx_with_blob("dotfiles-mgr", {
        "apply_dotfiles.py": (
            "import os\n"
            "\n"
            "def install_shell_env():\n"
            "    \"\"\"Adds our tool's PATH export to the user's shell rc file.\n"
            "\n"
            "    Note: we intentionally do NOT touch PYTHONSTARTUP or any Python "
            "REPL\n"
            "    customization -- only PATH/alias management is in scope for this "
            "skill.\n"
            "    \"\"\"\n"
            "    rc_path = os.path.expanduser(\"~/.bashrc\")\n"
            "    with open(rc_path, \"a\") as fh:\n"
            "        fh.write('\\nexport PATH=\"$HOME/.mytool/bin:$PATH\"\\n')\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == PASS, f.detail


def test_mechanism_b_pythonstartup_mentioned_only_in_disclaiming_comment_passes():
    """A comment disclaims using PYTHONSTARTUP ('we deliberately do NOT use
    PYTHONSTARTUP'); the actual .bashrc write only adds an unrelated alias, and a
    separate function does an unrelated write-mode open() elsewhere."""
    ctx = _ctx_with_blob("shell-profile-mgr", {
        "install_alias.py": (
            "# Note: we deliberately do NOT use PYTHONSTARTUP for REPL setup "
            "here --\n"
            "# we use a dedicated venv activation hook instead. See "
            "docs/design.md.\n"
            "\n"
            "def install_alias():\n"
            "    bashrc = os.path.expanduser('~/.bashrc')\n"
            "    with open(bashrc, 'a') as fh:\n"
            "        fh.write('alias ll=\"ls -la\"\\n')\n"
            "\n"
            "def write_install_log(path, msg):\n"
            "    with open(path, 'w') as fh:\n"
            "        fh.write(msg)\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == PASS, f.detail


def test_mechanism_b_pythonstartup_mentioned_only_in_inline_comment_passes():
    """PYTHONSTARTUP appears only as a standalone word inside a code comment
    ('you can also set PYTHONSTARTUP yourself') — never in assignment position; the
    actual shell-rc write only appends unrelated EDITOR/PATH exports."""
    ctx = _ctx_with_blob("shell-profile-mgr", {
        "apply_env.py": (
            "import os\n"
            "\n"
            "ENV_LINES = [\n"
            "    'export EDITOR=vim\\n',\n"
            "    'export PATH=\"$HOME/.local/bin:$PATH\"\\n',\n"
            "    # NOTE: you can also set PYTHONSTARTUP yourself for a custom "
            "REPL banner\n"
            "]\n"
            "\n"
            "def apply():\n"
            "    rc = os.path.expanduser('~/.bashrc')\n"
            "    with open(rc, 'a') as fh:\n"
            "        for line in ENV_LINES:\n"
            "            fh.write(line)\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == PASS, f.detail


def test_mechanism_b_transparent_pythonstartup_install_still_warns():
    """Counter-check (NOT a false positive, left as-is by design): a dotfiles/REPL
    skill that transparently sets PYTHONSTARTUP via .bashrc — the textbook legitimate
    use of the exact mechanism the check watches for. This is advisory (scored=False)
    and meant to surface for human review even when the install is disclosed and
    non-obfuscated, mirroring B99's stance on shipped sitecustomize.py files. It must
    still WARN after the C-135 tightening, or the tightening reintroduced the real
    false-negative gap the check exists to close."""
    ctx = _ctx_with_blob("dotfiles-mgr", {
        "repl_history.py": (
            "import os\n"
            "\n"
            "STARTUP = os.path.expanduser('~/.pythonrc')\n"
            "BASHRC = os.path.expanduser('~/.bashrc')\n"
            "\n"
            "def install_python_repl_history():\n"
            "    code = (\n"
            "        'import atexit, os, readline\\n'\n"
            "        'histfile = os.path.expanduser(\"~/.python_history\")\\n'\n"
            "        'atexit.register(readline.write_history_file, histfile)\\n'\n"
            "    )\n"
            "    with open(STARTUP, 'w') as fh:\n"
            "        fh.write(code)\n"
            "    with open(BASHRC, 'a') as fh:\n"
            "        fh.write('# managed by dotfiles: python REPL history\\n')\n"
            "        fh.write(f'export PYTHONSTARTUP=\"{STARTUP}\"\\n')\n"
        ),
    })
    f = check_python_runtime_persist_install(ctx)
    assert f.status == WARN, f.detail
    assert "mechanism B" in f.detail


# --------------------------------------------------------------------------- vet-level

def test_vet_bad_runtime_persist_install_is_warn():
    skill_dir = FIXTURES / "bad_b335_runtime_persist_install" / "skills" / "envtools"
    f = vet_skill(skill_dir)
    assert any(
        x.id == "B335" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )


def test_vet_clean_devtooling_b335_passes():
    skill_dir = FIXTURES / "clean_b335_devtooling" / "skills" / "venv-doctor"
    f = vet_skill(skill_dir)
    assert not any(
        x.id == "B335" and x.status == WARN for x in [f, *getattr(f, "ring_findings", [])]
    )
