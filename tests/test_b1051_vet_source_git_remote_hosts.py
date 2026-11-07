"""B-1051: ``--vet-source`` must find the HOST of every common git-remote spelling.

Before: only ``http(s)://`` URLs and the ``git:host/owner/repo`` form carried a host into
the known-bad-infrastructure check. ``git+https://HOST/...``, ``ssh://git@HOST/...`` and
scp-style ``git@HOST:owner/repo.git`` fell through to the bare-registry branch with no
host, so a known-compromised host got "no known-bad record" (CAUTION, exit 0) while the
same host as ``https://HOST/x`` was DO-NOT-INSTALL - and the command's own banner says
git and url sources are checked against that host list.
"""
from __future__ import annotations

import pytest

from clawseccheck.catalog import FAIL, UNKNOWN, WARN
from clawseccheck.checks import _parse_source_target, vet_source

BAD = {"url": ["evil-infra.example"], "any": []}
GOOD: dict = {}


@pytest.mark.parametrize("target", [
    "https://evil-infra.example/x",
    "git+https://evil-infra.example/repo.git",
    "git+ssh://git@evil-infra.example/o/r.git",
    "ssh://git@evil-infra.example/r.git",
    "ssh://git@evil-infra.example:2222/o/r.git",
    "git://evil-infra.example/o/r.git",
    "git@evil-infra.example:o/r.git",
    "evil-infra.example:o/r.git",
    "git:evil-infra.example/o/r@v1",
    "git+https://sub.evil-infra.example/o/r.git@v1.0",
])
def test_every_spelling_of_a_known_bad_host_is_convicted(target):
    f = vet_source(target, known_bad=BAD, known_good=GOOD)
    assert f.status == FAIL, (target, f.detail)
    assert "known-compromised infrastructure" in f.detail


def test_the_real_dataset_convicts_the_reported_iocs():
    for target in ("git+https://laosji.net/repo.git", "ssh://git@laosji.net/r.git",
                   "git@91.92.242.30:x/y.git", "git+https://91.92.242.30/repo.git"):
        assert vet_source(target).status == FAIL, target


@pytest.mark.parametrize("target,host,owner,ref,scheme", [
    ("git@github.com:openclaw/openclaw.git", "github.com", "openclaw", None, "ssh"),
    ("git+https://github.com/a/b.git@v1.2", "github.com", "a", "v1.2", "https"),
    ("ssh://git@gitlab.com:2222/grp/proj.git", "gitlab.com", "grp", None, "ssh"),
    ("git+https://github.com/a/b.git#egg=b", "github.com", "a", None, "https"),
    ("git+https://github.com/a/b.git#v2", "github.com", "a", "v2", "https"),
])
def test_git_remote_parse_shapes(target, host, owner, ref, scheme):
    info = _parse_source_target(target)
    assert info["ecosystem"] == "git"
    assert (info["host"], info["owner"], info["ref"], info["scheme"]) == (
        host, owner, ref, scheme)


@pytest.mark.parametrize("target,eco", [
    ("npm:left-pad", "npm"), ("npm:@scope/pkg@1.0.0", "npm"), ("pypi:requests==2.0", "pypi"),
    ("clawhub:foo", "clawhub"), ("left-pad", "registry"), ("C:\\\\x\\\\y", "registry"),
    ("localhost:8080", "registry"), ("https://github.com/a/b", "url"),
])
def test_non_git_shapes_are_unchanged(target, eco):
    assert _parse_source_target(target)["ecosystem"] == eco


def test_host_heuristics_now_reach_git_remotes():
    f = vet_source("git@10.1.2.3:o/r.git", known_bad={}, known_good=GOOD)
    assert f.status == WARN and "bare-IP host" in f.detail
    f = vet_source("git://example.org/o/r.git@v1", known_bad={}, known_good=GOOD)
    assert f.status == WARN and "plaintext" in f.detail


def test_a_clean_pinned_remote_is_still_only_unknown():
    f = vet_source("git+https://github.com/a/b.git@v1.2", known_bad={}, known_good=GOOD)
    assert f.status == UNKNOWN, f.detail
