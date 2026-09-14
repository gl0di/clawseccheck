"""B-758 items #1-3: three more shapes of "the same run states opposite facts in
different blocks" (item #4, `runState` vs the top-level JSON, was fixed separately in
commit 9c01b4f and is pinned by test_b758_run_state_agrees_with_top_level.py).

### Item #1 -- the header's "most urgent" finding disagreed with the risk-chain section

`_urgent_headline` picked the single most severe FAIL/WARN *Finding* and never looked at
`risk.py`'s RiskPath chains, even though both `render_report` and `render_dashboard`
already had a `risk` list in scope and render a "Highest-risk paths"/"RISK Chains"
section from it. A RiskPath's severity is a property of the *combination*, not summed
from its legs, so a chain could easily outrank every individual finding -- "Most urgent:
HIGH -- ..." printed directly above a CRITICAL chain two sections later, neither block
acknowledging the other. Fixed by giving `_urgent_headline` an optional `risk` param and
picking whichever of (top finding, top chain) is more severe, with a finding winning an
exact-severity tie so a caller that passes no `risk` (e.g. `render_html`, which has no
risk-chain section at all) reproduces the prior behavior byte-for-byte.

### Item #2 -- the skills/MCP inventory row read as its own internal contradiction

Measured on a real machine (v4.0.1): `Skills -- 0 flagged - 2 bundled with a plugin -
1 self-excluded - 5 issue(s)   FAIL`. "0 flagged" and the FAIL dot bracket "5 issue(s)"
with an unrelated roster DESCRIPTION sitting between them, so a reader who stops at "0
flagged" misses the very thing the FAIL is about. The two counts ("N flagged" = per-item,
"N issue(s)" = subject-level -- see `_subject_summary_rows`'s own long comment on why
they are named separately rather than summed) are real, distinct, non-contradictory
facts; the terminal "Inventory by subject" block never had this problem because it keeps
them adjacent (`_roster_and_subject_count_text`) and puts the roster description in a
separate parenthetical. Fixed by reordering the skills/MCP row construction so the two
FAIL-driving counts stay adjacent and the roster description trails, matching the
terminal block's own adjacency.

### Item #3 -- `--vet-source`'s IOC coverage notice contradicted the FAIL under it

Reproduced live: `--vet-source https://laosji.net/payload.js` (a real, dated HOSTS
entry -- Palo Alto Unit 42, ClawHavoc/letssendit infrastructure) prints
"IOC dataset carries no indicators for: git, npm, pypi, url. A clean identity result for
a source in one of those ecosystems means 'nothing is known here'..." and then, two lines
later, "FAIL   KNOWN-BAD source '...': host 'laosji.net' is known-compromised
infrastructure (exact IOC match, catalog: url)" -- the FAIL directly disproving what the
notice just said about "url" carrying no indicators. Root cause: `coverage_notice()`'s
"missing ecosystems" computation reads only `iocdb.SOURCES` (name/slug records), while a
"url"/"git" source is ALSO checked against the entirely separate `iocdb.HOSTS`
(infrastructure) table in `vet_source`'s step 1b, which is non-empty on the shipped
dataset. Fixed by disclosing that exception in the notice text rather than silencing
either side: the "no name-based indicators" claim stays true, and the notice now says why
a host match can still fire for one of those ecosystems.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import CRITICAL, FAIL, HIGH, MEDIUM, WARN
from clawseccheck.catalog import Finding as CatalogFinding
from clawseccheck.collector import _OWN_ENGINE_MARKERS, collect
from clawseccheck.report import _subject_summary_rows, _urgent_headline
from clawseccheck.risk import RiskPath

REPO_ROOT = Path(__file__).resolve().parents[1]


def _finding(id_, severity, status, title="t") -> CatalogFinding:
    return CatalogFinding(id_, title, severity, status, "detail", "fix", "framework")


def _risk(id_="RISK-01", severity=CRITICAL, title="chain") -> RiskPath:
    return RiskPath(id_, severity, title, ["A", "B"], "why", "fix")


# --------------------------------------------------------------------------- item #1

def test_default_call_with_no_risk_matches_the_prior_finding_only_behavior():
    f = _finding("B1", HIGH, FAIL, "a fail")
    assert _urgent_headline([f]) == "Most urgent: HIGH — a fail  [B1]"
    assert _urgent_headline([f]) == _urgent_headline([f], risk=None)
    assert _urgent_headline([f]) == _urgent_headline([f], risk=[])


def test_a_more_severe_risk_chain_leads_over_a_less_severe_fail_finding():
    f = _finding("B1", HIGH, FAIL, "a fail")
    chain = _risk(severity=CRITICAL, title="a dangerous combination")
    headline = _urgent_headline([f], risk=[chain])
    assert "CRITICAL" in headline
    assert "dangerous capability chain" in headline
    assert "a dangerous combination" in headline
    assert "[RISK-01]" in headline


def test_a_less_severe_risk_chain_does_not_override_a_worse_fail_finding():
    f = _finding("B1", CRITICAL, FAIL, "the real worst thing")
    chain = _risk(severity=HIGH, title="a lesser combination")
    headline = _urgent_headline([f], risk=[chain])
    assert headline == "Most urgent: CRITICAL — the real worst thing  [B1]"


def test_an_exact_severity_tie_keeps_the_finding_not_the_chain():
    f = _finding("B1", HIGH, FAIL, "a fail")
    chain = _risk(severity=HIGH, title="a same-severity chain")
    headline = _urgent_headline([f], risk=[chain])
    assert headline == "Most urgent: HIGH — a fail  [B1]"


def test_a_risk_chain_can_headline_over_warn_only_findings():
    """No FAIL-weight finding at all -- previously the headline could name only a WARN
    (or say 'nothing urgent'), never a chain, even one built on positive evidence for
    every leg. A live chain competes in the SAME 'Most urgent' bracket a FAIL finding
    would, not the weaker WARN-tier bracket, since it is evidenced the same way a FAIL
    is (positive evidence per leg, not an absence-based WARN heuristic)."""
    warn = _finding("B2", MEDIUM, WARN, "a warn")
    chain = _risk(severity=HIGH, title="still worse than the warn")
    headline = _urgent_headline([warn], risk=[chain])
    assert headline.startswith("Most urgent: HIGH")
    assert "dangerous capability chain" in headline
    assert "still worse than the warn" in headline


def test_a_suppressed_risk_chain_is_ignored_even_if_it_would_otherwise_win():
    f = _finding("B1", HIGH, FAIL, "a fail")
    chain = _risk(severity=CRITICAL, title="suppressed")
    chain.suppressed = True
    headline = _urgent_headline([f], risk=[chain])
    assert headline == "Most urgent: HIGH — a fail  [B1]"


def test_no_findings_and_no_risk_is_still_the_all_clear():
    assert _urgent_headline([], risk=[]) == "Nothing urgent found in what was checked."


def test_a_risk_chain_alone_with_no_findings_at_all_still_headlines():
    chain = _risk(severity=CRITICAL, title="alone")
    headline = _urgent_headline([], risk=[chain])
    assert headline.startswith("Most urgent: CRITICAL")
    assert "alone" in headline


# --------------------------------------------------------------------------- item #2

def _cfg(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text('{"gateway": {"bind": "127.0.0.1"}}', encoding="utf-8")
    cfg.chmod(0o600)


def _skill_md(d: Path, name: str) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: A helper skill.\n---\n\nDoes something local.\n",
        encoding="utf-8")


def _own_engine(skill_dir: Path) -> None:
    _skill_md(skill_dir, "clawseccheck")
    checks = skill_dir / "checks"
    checks.mkdir(parents=True, exist_ok=True)
    (checks / "_engine.py").write_text("\n".join(_OWN_ENGINE_MARKERS), encoding="utf-8")


def _bundled(home: Path, name: str, pkg: Path) -> None:
    _skill_md(pkg, name)
    (home / "plugin-skills").mkdir(parents=True, exist_ok=True)
    (home / "plugin-skills" / name).symlink_to(pkg, target_is_directory=True)


def _skills_row(findings, ctx) -> str:
    rows = {label: count for label, _status, count in _subject_summary_rows(findings, ctx)}
    hits = [c for label, c in rows.items() if "Skills" in label]
    assert len(hits) == 1, rows
    return hits[0]


def _mcp_row(findings, ctx) -> str:
    rows = {label: count for label, _status, count in _subject_summary_rows(findings, ctx)}
    hits = [c for label, c in rows.items() if "MCP" in label]
    assert len(hits) == 1, rows
    return hits[0]


def test_skills_row_no_longer_splits_flagged_and_issue_with_the_roster_description(tmp_path):
    """The exact real-machine shape: 0 individually-flagged skills, 2 bundled + 1
    self-excluded (roster description), 5 subject-level issues, overall FAIL. Before the
    fix this read "0 flagged · 2 bundled with a plugin · 1 self-excluded · 5 issue(s)" --
    the two FAIL-driving numbers split apart by an unrelated description."""
    home = tmp_path / ".openclaw"
    _cfg(home)
    _own_engine(home / "skills" / "clawseccheck")
    _bundled(home, "browser-automation", tmp_path / "pkg-browser" / "skills" / "browser-automation")
    _bundled(home, "canvas", tmp_path / "pkg-canvas" / "skills" / "canvas")
    ctx = collect(home)
    assert ctx.installed_skill_bundled == {"browser-automation", "canvas"}
    assert ctx.self_excluded_skills == ["clawseccheck"]

    findings = [_finding("B25", HIGH, FAIL, "subject-level skills issue")]
    row = _skills_row(findings, ctx)

    assert "0 flagged · 1 issue(s)" in row, row
    assert "· 2 bundled with a plugin · 1 self-excluded" in row, row
    # The old, contradiction-shaped join must be gone: the roster description no longer
    # sits between the two counts.
    assert "0 flagged · 2 bundled with a plugin" not in row, row


def test_skills_row_with_no_subject_issue_is_unchanged(tmp_path):
    """Non-regression: when the subject bucket is clear, the row must not gain a
    trailing ' · clear' or any other new noise."""
    home = tmp_path / ".openclaw"
    _cfg(home)
    _skill_md(home / "skills" / "notes-helper", "notes-helper")
    ctx = collect(home)
    row = _skills_row([], ctx)
    # Pre-existing behavior (unchanged by this fix): "N flagged" is always stated
    # explicitly for a non-empty roster, clean or not -- disclosure over tidiness,
    # same convention _skills_roster_text itself documents for the cap/self-excluded
    # cases. This test's job is only to confirm no new ' · clear' / duplicate suffix
    # was introduced when the subject bucket has nothing to add.
    assert row == "0 flagged · 1 installed", row


def test_mcp_row_no_longer_splits_flagged_and_issue_with_the_server_count(tmp_path):
    """Same defect, same fix, for the MCP row: 'N flagged · N configured · N issue(s)'
    used to bury the subject-level issue count after the roster size instead of beside
    the flagged count."""
    home = tmp_path / ".openclaw"
    home.mkdir(parents=True, exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text(
        '{"gateway": {"bind": "127.0.0.1"}, '
        '"mcp": {"servers": {"ok-server": {"command": "/usr/local/bin/mcp-server"}}}}',
        encoding="utf-8")
    cfg.chmod(0o600)
    ctx = collect(home)

    findings = [_finding("B24", HIGH, FAIL, "subject-level mcp issue")]
    row = _mcp_row(findings, ctx)

    assert "0 flagged · 1 issue(s) · 1 configured" in row, row


def test_mcp_row_with_no_servers_and_a_subject_issue_still_orders_issue_first(tmp_path):
    home = tmp_path / ".openclaw"
    _cfg(home)
    ctx = collect(home)
    findings = [_finding("B24", HIGH, FAIL, "subject-level mcp issue, no servers configured")]
    row = _mcp_row(findings, ctx)
    assert row == "none configured · 1 issue(s)", row


# --------------------------------------------------------------------------- item #3

def test_coverage_notice_discloses_the_host_exception_when_hosts_is_populated():
    from clawseccheck.iocdb import HOSTS, coverage_notice

    assert HOSTS, "premise: the shipped dataset carries real host/IP indicators"
    notice = coverage_notice()
    joined = "\n".join(notice)
    assert "carries no indicators for" in joined
    assert "url" in joined  # premise: url has zero name-based SOURCES records today
    assert "Exception" in joined
    assert "known-bad-infrastructure" in joined
    assert "url" in joined.split("Exception", 1)[1]


def test_a_real_host_match_no_longer_contradicts_the_notice_above_it():
    """The exact live repro: a URL whose host is a real HOSTS entry FAILs via the
    host-match branch, and the notice printed above it must now disclose why that is
    possible instead of claiming 'url' carries no indicators with no qualifier."""
    from clawseccheck.checks._vet import vet_source
    from clawseccheck.iocdb import coverage_notice

    f = vet_source("https://laosji.net/payload.js")
    assert f.status == FAIL
    assert "catalog: url" in f.detail

    joined = "\n".join(coverage_notice())
    assert "url" in joined
    # The notice must no longer read as an unqualified "nothing can be found for url" —
    # it must name the host-based exception that the FAIL above just demonstrated.
    assert "Exception" in joined and "host" in joined.lower()


def test_coverage_notice_omits_the_exception_when_hosts_is_actually_empty(monkeypatch):
    """Non-regression / non-vacuity: the exception clause is conditional on HOSTS
    actually carrying records, not printed unconditionally alongside 'url'/'git'."""
    import clawseccheck.iocdb as iocdb

    monkeypatch.setattr(iocdb, "HOSTS", ())
    notice = iocdb.coverage_notice()
    joined = "\n".join(notice)
    assert "carries no indicators for" in joined
    assert "Exception" not in joined
