"""B-1052: ``--vet-plan`` must clone a git repository, never curl its HTML landing page.

Before: ``https://github.com/o/r`` (and ``.git``) printed ``curl -fsSL <url> -o
"$QUARANTINE/download"``, which saves the repo's web page; the plan's own ``--advise`` step
then had nothing to assess. ``git+https://...`` and scp-style ``git@host:o/r.git`` printed
only "has no resolvable ecosystem". Only ``git:host/o/r`` produced a ``git clone``.
"""
from __future__ import annotations

import pytest

from clawseccheck.report import render_vet_plan


def _fetch_line(target: str) -> str:
    lines = [ln.strip() for ln in render_vet_plan(target).splitlines()
             if "git clone" in ln or "curl -fsSL" in ln or "clone safely" in ln
             or "no resolvable ecosystem" in ln]
    assert len(lines) == 1, render_vet_plan(target)
    return lines[0]


@pytest.mark.parametrize("target,expected", [
    ("https://github.com/foo/bar", 'git clone --depth 1 -- https://github.com/foo/bar "$QUARANTINE/repo"'),
    ("https://github.com/foo/bar.git", 'git clone --depth 1 -- https://github.com/foo/bar.git "$QUARANTINE/repo"'),
    ("https://git.example.org/x/y/z.git", 'git clone --depth 1 -- https://git.example.org/x/y/z.git "$QUARANTINE/repo"'),
    ("git+https://github.com/foo/bar.git", 'git clone --depth 1 -- https://github.com/foo/bar.git "$QUARANTINE/repo"'),
    ("git+https://github.com/foo/bar.git@v1.2",
     'git clone --depth 1 --branch v1.2 -- https://github.com/foo/bar.git "$QUARANTINE/repo"'),
    ("git+https://github.com/a/b.git#egg=b", 'git clone --depth 1 -- https://github.com/a/b.git "$QUARANTINE/repo"'),
    ("git@github.com:foo/bar.git", 'git clone --depth 1 -- git@github.com:foo/bar.git "$QUARANTINE/repo"'),
    ("ssh://git@gitlab.com:2222/g/p.git", 'git clone --depth 1 -- ssh://git@gitlab.com:2222/g/p.git "$QUARANTINE/repo"'),
    ("git:github.com/foo/bar", 'git clone --depth 1 -- https://github.com/foo/bar "$QUARANTINE/repo"'),
    ("git:github.com/foo/bar@v1", 'git clone --depth 1 --branch v1 -- https://github.com/foo/bar "$QUARANTINE/repo"'),
])
def test_git_sources_are_cloned(target, expected):
    assert _fetch_line(target).startswith(expected)


def test_a_plain_file_url_is_still_downloaded():
    line = _fetch_line("https://example.com/file.tar.gz")
    assert line.startswith('curl -fsSL https://example.com/file.tar.gz -o "$QUARANTINE/download"')


def test_a_forge_url_that_is_not_a_repo_root_is_not_cloned():
    line = _fetch_line("https://github.com/foo/bar/releases/download/v1/x.zip")
    assert line.startswith("curl -fsSL")


def test_an_option_shaped_host_is_never_handed_to_git():
    line = _fetch_line("ssh://-oProxyCommand=touch%20pwned/r.git")
    assert "git clone" not in line and line.startswith("#")
    assert "per ecosystem" not in line, "a refusal comment carries no command annotation"


def test_no_clone_recurses_submodules():
    for t in ("git+https://github.com/foo/bar.git", "git@github.com:foo/bar.git"):
        assert "--recurse-submodules" not in render_vet_plan(t)


def test_option_shaped_scp_user_or_ref_is_refused():
    for t in ("-oProxyCommand=touch%20pwned@evil.example:o/r.git",
              "git+https://github.com/a/b.git@-upload-pack=x"):
        line = _fetch_line(t)
        assert "git clone" not in line, line


def test_every_clone_ends_git_options_before_the_remote():
    for t in ("git@github.com:foo/bar.git", "https://github.com/foo/bar",
              "git+https://github.com/foo/bar.git@v1"):
        assert " -- " in _fetch_line(t)
