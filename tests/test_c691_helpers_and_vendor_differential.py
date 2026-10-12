"""C-691 helper-level tests (names / parameters that exist only on the fixed tree) and the
differential of the B323 env-token port against the installed vendor function.

The differential is local-only (skips without the dist or node) and covers builds >= 2026.9.7,
where `default_operator=True` is the reading; `default_operator=False` is pinned by table
(it is the pre-2026.9.7 grammar, which is no longer installed on this machine).
"""
from __future__ import annotations

import itertools
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from _distgrounding import dist_file, require_dist

from clawseccheck.checks import (
    _b323_contains_env_var_reference,
    _b323_is_literal_path_override,
    _managed_github_profile_ids,
)


def _gh_id(seed: bytes) -> str:
    import hashlib

    return "ghp" + "_" + hashlib.sha256(seed).hexdigest()[:32]


def test_the_helper_collects_only_vendor_shaped_ids_at_vendor_paths():
    cfg = {
        "tools": {"github": {"profileId": _gh_id(b"a")}},
        "agents": {"entries": {"a": {"tools": {"github": {"profileId": "ghp" + "_" + "A" * 36}}},
                               "b": {"tools": {"github": {"profileId": _gh_id(b"b")}}},
                               "c": "not a dict"}},
        "other": {"github": {"profileId": _gh_id(b"x")}},
    }
    assert sorted(_managed_github_profile_ids(cfg)) == sorted([_gh_id(b"a"), _gh_id(b"b")])
    assert _managed_github_profile_ids(None) == []
    assert _managed_github_profile_ids({"tools": "x", "agents": {"entries": []}}) == []


# Pinned vendor answers (containsEnvVarReference on openclaw 2026.10.2, executed in node).
_PINNED_WITH_OPERATOR = {
    "${HOME}/bin": True, "/usr/bin": False, "$${HOME}": False, "${home}": False,
    "${FOO:-a$b}": False, "${FOO:-{x}}": False, "${HOME:-/x}/bin": True, "${FOO:-}": True,
    "x${FOO:-/a:/b}y": True, "${FOO:-a:-b}": True, "${:-x}": False, "${FOO:-a}${BAR}": True,
    "$${FOO:-a}": False, "$${FOO:-a}${BAR}": True, "${FOO": False, "${FOO\n}": False,
    "${FOO:-a\n}": True, "${FOO:-$}": False, "${FOO:-a}}": True, "${f:-x}": False,
    # a value holding ANY reference is dropped by the vendor, whatever else it holds
    "${FOO:-/tmp/evil}": True, "${FOO:-a}:/tmp/evil": True, "${HOME}:/tmp/evil": True,
}


@pytest.mark.parametrize("value,expected", list(_PINNED_WITH_OPERATOR.items()),
                         ids=[repr(v) for v in _PINNED_WITH_OPERATOR])
def test_port_with_the_operator_matches_the_pinned_vendor_answers(value, expected):
    assert _b323_contains_env_var_reference(value, default_operator=True) is expected


# Without the operator (a build before 2026.9.7, or an undetermined one) the body must be
# the bare NAME: only the operator-free spellings are references.
_PINNED_WITHOUT_OPERATOR = {
    "${HOME}/bin": True, "$${HOME}": False, "${home}": False, "${HOME:-/x}/bin": False,
    "${FOO:-}": False, "/opt/evil:${FOO:-/usr/bin}": False, "${HOME:-x}${y}/evil": False,
    "${FOO:-a}${BAR}": True, "${FOO\n}": False,
}


@pytest.mark.parametrize("value,expected", list(_PINNED_WITHOUT_OPERATOR.items()),
                         ids=[repr(v) for v in _PINNED_WITHOUT_OPERATOR])
def test_port_without_the_operator_is_the_old_grammar(value, expected):
    assert _b323_contains_env_var_reference(value) is expected
    assert _b323_contains_env_var_reference(value, default_operator=False) is expected


def test_the_default_is_the_conservative_old_reading():
    assert _b323_is_literal_path_override("PATH", "${HOME:-/x}/bin") is True
    assert _b323_is_literal_path_override("PATH", "${HOME:-/x}/bin", True) is False
    assert _b323_is_literal_path_override("PATH", "${HOME:-$X}/bin", True) is True
    assert _b323_is_literal_path_override("PATH", "/opt/evil/bin:/usr/bin", True) is True


_ORACLE = r"""
import { readFileSync } from "node:fs";
const cfg = JSON.parse(readFileSync(0, "utf8"));
const m = await import("file://" + cfg.module);
const f = m[cfg.fn];
console.log(JSON.stringify(cfg.values.map((v) => f(v))));
"""


def _vendor_contains_env_var_reference(values: "list[str]") -> "list[bool]":
    require_dist()
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed - the differential executes the vendor")
    # `managed-handoff-runtime.mjs` carries a sealed copy; the live module is env-substitution-*
    mod = dist_file("env-substitution-*.mjs", symbol="containsEnvVarReference",
                    contains="function containsEnvVarReference(")
    text = mod.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"\bexport\s*\{[^}]*?\bcontainsEnvVarReference(?:\s+as\s+(\w+))?\s*[,}]", text, re.S)
    assert m, f"{mod.name} no longer exports containsEnvVarReference - re-ground (C-691)"
    payload = json.dumps({"module": str(mod), "fn": m.group(1) or "containsEnvVarReference",
                          "values": values})
    with tempfile.TemporaryDirectory(prefix="c691-oracle-") as tmp:
        scratch = Path(tmp)
        (scratch / "home").mkdir()
        harness = scratch / "harness.mjs"
        harness.write_text(_ORACLE, encoding="utf-8")
        env = {"HOME": str(scratch / "home"), "PATH": os.environ.get("PATH", ""), "LANG": "C"}
        proc = subprocess.run(
            [node, str(harness)], input=payload, capture_output=True, text=True,
            env=env, cwd=str(scratch), timeout=300,
        )
    assert proc.returncode == 0, f"node exited {proc.returncode}: {proc.stderr.strip()[-600:]}"
    return json.loads(proc.stdout)


def test_port_agrees_with_the_installed_vendor_function():
    """Every string of length <= 6 over the token alphabet, plus the pinned table: the port with
    the operator on and the installed `containsEnvVarReference` (>= 2026.9.7) must agree."""
    alphabet = "${}:-Ax\n"
    values = [
        "".join(t) for n in range(1, 7) for t in itertools.product(alphabet, repeat=n)
    ] + list(_PINNED_WITH_OPERATOR)
    vendor = _vendor_contains_env_var_reference(values)
    assert len(vendor) == len(values)
    assert any(vendor) and not all(vendor)  # anti-vacuity: the vendor answered both ways
    assert vendor[values.index("${A:-}")] is True  # ... and `:-` is among the true cases
    mismatches = [
        (v, ours, theirs)
        for v, theirs in zip(values, vendor)
        if (ours := _b323_contains_env_var_reference(v, default_operator=True)) is not theirs
    ]
    assert not mismatches, f"{len(mismatches)} mismatch(es) vs the vendor, first: {mismatches[:5]!r}"
    for value, expected in _PINNED_WITH_OPERATOR.items():
        assert vendor[values.index(value)] is expected, f"pinned table is stale for {value!r}"


def test_the_differential_can_fail():
    """Positive control: the operator-free grammar (the pre-fix port) disagrees with the vendor
    on `:-`, so a port that lost the operator would be caught by the comparison above."""
    assert _b323_contains_env_var_reference("${HOME:-/x}/bin", default_operator=False) is False
    assert _b323_contains_env_var_reference("${HOME:-/x}/bin", default_operator=True) is True
