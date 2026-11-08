"""B-1054: the OpenClaw build installed on THIS machine is evidence only about this
machine's own OpenClaw home.

``build_context(include_dist=True)`` used to fill ``ctx.installed_dist_version`` for any
``--home`` - a copy, a backup, a fixture, another user's home - so B382/B350/B363/B175/B9
and the dist-derived defaults read by B2/B48/B171 judged that directory by the auditing
machine's package, and a ``--no-dist`` run of the same directory disagreed (measured on
dev @1bc28cda: bad_b48_wildcard_authority B48 WARN vs FAIL, bad_b171_bash_wildcard B171
UNKNOWN vs FAIL, bad_b2_insecure_auth B2 PASS vs WARN). USAGE and ``--help`` promise that
only the machine's own home is judged by the installed build. One predicate now gates the
field at its source - the one B33 already used - so every consumer agrees with B33.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import clawseccheck
from clawseccheck import audit, build_context

REPO = Path(__file__).resolve().parents[1]
FIXTURES = [
    REPO / "fixtures" / "bad_b48_wildcard_authority",
    REPO / "fixtures" / "bad_b171_bash_wildcard",
    REPO / "fixtures" / "bad_b2_insecure_auth",
    REPO / "fixtures" / "reliability" / "clean_loopback_minimal",
]


@pytest.fixture
def installed_new(monkeypatch):
    # Pretend a current OpenClaw is installed on this machine, whatever is really on PATH.
    monkeypatch.setattr(clawseccheck, "_installed_dist_version", lambda *a, **k: "2026.11.1")


def test_a_fixture_home_never_receives_the_installed_build(installed_new):
    ctx = build_context(FIXTURES[0], include_dist=True)
    assert ctx.include_dist is True
    assert ctx.installed_dist_version is None


def test_this_machines_own_home_still_receives_it(installed_new, monkeypatch):
    monkeypatch.setattr(clawseccheck, "_dist_applies_to_home", lambda *a, **k: True)
    ctx = build_context(FIXTURES[0], include_dist=True)
    assert ctx.installed_dist_version == "2026.11.1"


@pytest.mark.parametrize("home", FIXTURES, ids=lambda p: p.name)
def test_a_foreign_home_gets_the_same_verdicts_with_and_without_dist(installed_new, home):
    with_dist = {f.id: f.status for f in audit(home, include_dist=True)[1]}
    without = {f.id: f.status for f in audit(home, include_dist=False)[1]}
    assert with_dist == without, {
        k: (with_dist.get(k), without.get(k))
        for k in set(with_dist) | set(without) if with_dist.get(k) != without.get(k)}


def test_the_predicate_fails_closed_to_not_own_home(monkeypatch, tmp_path):
    import clawseccheck.checks._lifecycle as lc

    def boom(_home):
        raise RuntimeError("cannot decide")

    monkeypatch.setattr(lc, "_b33_is_this_machines_home", boom)
    assert clawseccheck._dist_applies_to_home(tmp_path) is False
