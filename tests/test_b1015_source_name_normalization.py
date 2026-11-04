"""B-1015: --vet-source matches a package by the name the package manager resolves.

pip resolves a requirement by its PEP 503-normalized project name, so separator and case
variants, extras, any version operator, markers and whitespace all install the project a
known-bad record names. npm installs the real package behind `alias@npm:real`. Every case
uses an injected `known_bad=` pool, never the shipped IOC data.
"""
from __future__ import annotations

import pytest

from clawseccheck.catalog import FAIL, UNKNOWN, WARN
from clawseccheck.checks import _parse_source_target, vet_source
from clawseccheck.report import render_vet_plan

_E = frozenset()
_BAD = {
    "npm": frozenset({"persona-ai-sdk", "@ifasn/md-doc-mcp"}),
    # `is_it_ai` is stored with underscores on purpose: the pool side is normalized too.
    "pypi": frozenset({"skills-analyzer", "is_it_ai"}),
    "clawhub": _E, "git": _E, "url": _E, "any": _E,
}


@pytest.mark.parametrize("target", [
    # the task's table
    "pypi:skills-analyzer",
    "pypi:is-it-ai==0.1.3",
    "pypi:skills_analyzer",
    "pypi:Skills.Analyzer",
    "pypi:is_it_ai",
    "pypi:is-it-ai>=0.1",
    "pypi:is-it-ai~=0.1",
    "pypi:is-it-ai!=0.1.0",
    "pypi:is-it-ai[cli]",
    "pypi:is-it-ai[cli]==0.1.1",
    # the rest of the class
    "pypi:is-it-ai<=0.2",
    "pypi:is-it-ai<0.2",
    "pypi:is-it-ai>0.0",
    "pypi:is-it-ai===0.1",
    "pypi:is-it-ai (>=0.1)",
    "pypi:is-it-ai ; python_version>'3'",
    "pypi:is-it-ai;python_version>'3'",
    "pypi:is-it-ai @ https://example.invalid/x.whl",
    "pypi: is-it-ai ",
    "pypi:skills--analyzer",
    "pypi:SKILLS_._ANALYZER",
    "PYPI:Is.It.Ai",
])
def test_pypi_variants_of_a_known_bad_project_fail(target):
    assert vet_source(target, known_bad=_BAD).status == FAIL


@pytest.mark.parametrize("target", [
    "pypi:skills-analyzers",
    "pypi:isitai",
    "pypi:is-it-aix",
    "pypi:xis-it-ai",
    "pypi:skillsanalyzer",
    # not a requirement pip accepts: no project name is taken from it
    "pypi:is-it-ai.",
    "pypi:is-it-ai/x",
    "pypi:is-it-ai-",
])
def test_pypi_near_misses_stay_unknown(target):
    assert vet_source(target, known_bad=_BAD).status == UNKNOWN


def test_pool_entry_is_normalized_at_compare_time():
    # The record is stored as `is_it_ai`; the hyphen spelling must still match it.
    assert vet_source("pypi:is-it-ai", known_bad=_BAD).status == FAIL
    dotted = dict(_BAD, pypi=frozenset({"Some.Bad_Pkg"}))
    assert vet_source("pypi:some-bad-pkg==1", known_bad=dotted).status == FAIL
    assert vet_source("pypi:some-bad-pkgs", known_bad=dotted).status == UNKNOWN


def test_pypi_normalization_is_scoped_to_python_pools():
    # A pypi spelling variant does not convict an npm record, and vice versa.
    npm_only = dict(_BAD, pypi=_E)
    assert vet_source("pypi:persona_ai_sdk", known_bad=npm_only).status == UNKNOWN
    assert vet_source("npm:is_it_ai", known_bad=_BAD).status == UNKNOWN


def test_bare_registry_name_normalized_pypi_hit_is_warn_not_fail():
    # OpenClaw resolves a bare name through npm, which does not fold separators, so a
    # normalized-only pypi match must not FAIL. pip would still install the known-bad
    # project from it, so it must not read UNKNOWN either.
    assert vet_source("skills-analyzer", known_bad=_BAD).status == FAIL  # exact, as before
    assert vet_source("is_it_ai", known_bad=_BAD).status == FAIL
    for bare in ("skills_analyzer", "Skills.Analyzer", "is-it-ai", "is_it_ai[x]",
                 "skills-analyzer @ http://x"):
        f = vet_source(bare, known_bad=_BAD)
        assert f.status == WARN, bare
        assert "pip would install it" in f.detail
    for bare in ("skills-analyzers", "isitai", "is-it-ai."):
        assert vet_source(bare, known_bad=_BAD).status == UNKNOWN, bare
    # an npm-only record is not reached through pypi normalization
    npm_only = dict(_BAD, pypi=_E)
    assert vet_source("persona_ai_sdk", known_bad=npm_only).status == UNKNOWN


def test_parser_keeps_name_and_version_and_adds_the_project():
    # name/version are what the --vet-plan command is built from: unchanged.
    info = _parse_source_target("pypi:Is_It.Ai[cli]>=0.1")
    assert info["name"] == "Is_It.Ai[cli]>=0.1" and info["version"] is None
    assert info["project"] == "is-it-ai"
    pinned = _parse_source_target("pypi:is-it-ai==0.1.3")
    assert pinned["name"] == "is-it-ai" and pinned["version"] == "0.1.3"
    assert pinned["project"] == "is-it-ai"
    assert _parse_source_target("pypi:is-it-ai.")["project"] is None
    assert _parse_source_target("pypi:--index-url=x")["project"] is None


def test_option_shaped_pypi_spec_is_still_refused():
    assert _parse_source_target("pypi:--index-url=x")["option_shaped"] is True
    assert "pip download" not in render_vet_plan("pypi:--index-url=x")


# ---- npm: the same class ---------------------------------------------------- #

@pytest.mark.parametrize("target", [
    "npm:PERSONA-AI-SDK",
    "npm:@IFASN/md-doc-mcp",
    "npm:persona-ai-sdk@^1.0.0",
    "npm:persona-ai-sdk@~1.2",
    "npm:persona-ai-sdk@latest",
    "npm:persona-ai-sdk@>=1 <2",
    "npm: persona-ai-sdk ",
    "npm:@ifasn/md-doc-mcp@2.0.0",
    # alias syntax installs the real package under another name
    "npm:harmless@npm:persona-ai-sdk",
    "npm:harmless@npm:persona-ai-sdk@1.0.0",
    "npm:@a/b@npm:@ifasn/md-doc-mcp@2",
    "npm:harmless@NPM:Persona-AI-SDK",
])
def test_npm_variants_of_a_known_bad_package_fail(target):
    assert vet_source(target, known_bad=_BAD).status == FAIL


@pytest.mark.parametrize("target", [
    "npm:persona-ai-sdk-x",
    "npm:persona_ai_sdk",  # npm does not normalize separators
    "npm:harmless@npm:persona-ai-sdkx",
    "npm:harmless@1.0.0",
    "npm:@ifasn/md-doc-mcp-x",
])
def test_npm_near_misses_stay_unknown(target):
    assert vet_source(target, known_bad=_BAD).status == UNKNOWN


def test_npm_alias_parse_records_the_real_package():
    info = _parse_source_target("npm:harmless@npm:@ifasn/md-doc-mcp@2")
    assert info["name"] == "harmless" and info["version"] == "npm:@ifasn/md-doc-mcp@2"
    assert info["npm_real"] == "@ifasn/md-doc-mcp"
    assert _parse_source_target("npm:persona-ai-sdk@1.0.0")["npm_real"] is None
