"""UI strings for ClawSecCheck (English-only).

Pure stdlib. English is the canonical source of truth (strings copied
verbatim from report.py). Missing keys return the key itself. Formatting
errors fall back to the raw template. Functions never raise.

(Hebrew / RTL support and the multi-language layer were removed in v2.0.0.)
"""
from __future__ import annotations


STRINGS: dict[str, str] = {
    'report.title': 'ClawSecCheck - OpenClaw Security Audit',
    'fix.header': 'Remediation (copy-paste)',
    'fix.note': 'ClawSecCheck does NOT apply these — review and run them yourself.',
    'fix.none': 'Nothing to paste-apply — no current FAIL/WARN has a paste-ready fix.',
    'report.score_line': 'Score: {score}/100   Grade: {grade}   Lethal Trifecta: {trifecta}',
    'report.capped': '(capped from {raw} - open {sev} finding)',
    'report.no_issues': 'No issues found by ClawSecCheck. Keep it that way. {ok}',
    'report.to_fix': '{n} thing(s) to fix (ClawSecCheck) - most urgent first:',
    'report.label_why': 'why',
    'report.label_fix': 'fix',
    'report.suppressed_count': '({n} finding(s) suppressed via .clawseccheckignore)',
    'report.gov_warning': 'WARNING: a {sev} finding ({id}) is suppressed via .clawseccheckignore — it still counts against your real security; review your ignore list.',
    'report.score_breakdown': 'Why {score}/100: weighted pass-rate over {n_scored} scored checks — {n_pass} pass, {n_warn} warn (half weight), {n_fail} fail. UNKNOWN/advisory checks are excluded.',
    'report.score_breakdown_detail': '({n_fail} FAIL, {n_warn} WARN — incl. {sev_summary})',
    'report.scope_note': 'This score reflects your configuration. It does not test live prompt-injection resistance or do a deep MCP supply-chain vet — run `--canary` / `--redteam` / `--dryrun` (live injection) and `--vet-mcp` (deep MCP) for those.',
    'report.capability_graph_title': 'Capability graph',
    'report.capability_graph_intro': 'Static config + attestation summary:',
    'report.nonstandard_banner': 'No openclaw.json found — this looks like a non-standard or custom setup. ClawSecCheck is calibrated for OpenClaw, the only fully-supported target right now, so checks that need the standard config could not be assessed.',
    'report.nonstandard_unknown': '{n} check(s) were not assessed (UNKNOWN) and are NOT counted against your score — the grade reflects only the {n_scored} assessable check(s).',
    'report.native_header': "--- Also from OpenClaw's built-in `security audit` ---",
    'report.native_additional': "{n} additional finding(s) the platform's own audit reports:",
    'report.native_clean': 'Clean — openclaw security audit found nothing.',
    'report.native_not_included': '(not included: {note})',
    'card.security_label': 'OpenClaw Security',
    'card.trifecta_label': 'Lethal Trifecta',
    'card.audited_by': 'audited by ClawSecCheck',
    'monitor.title': 'ClawSecCheck - Threat Monitor',
    'monitor.current': 'Current: {score}/100  Grade: {grade}',
    'monitor.baseline': 'Baseline saved. Future runs will alert on what changes since now.',
    'monitor.no_threats': 'No new threats since last check. {ok}',
    'monitor.changes': '{n} change(s) detected since last check:',
    'prompts.title': 'ClawSecCheck - copy-paste fix prompts',
    'prompts.intro': 'Paste each into your OpenClaw agent to fix it:',
    'prompts.nothing': 'Nothing to fix. {ok}',
    'html.title': 'ClawSecCheck Security Audit Report',
    'html.h1': '🔍 ClawSecCheck Security Audit Report',
    'html.label_score': 'Score:',
    'html.label_trifecta': 'Lethal Trifecta:',
    'html.label_capped': 'Capped:',
    'html.capped_detail': 'from {raw} (open {sev} finding)',
    'html.private_title': '⚠ Private Report',
    'html.private_body': 'This report contains detailed security findings and must <strong>NOT</strong> be shared publicly.',
    'html.section_findings': 'Findings',
    'html.label_why2': 'Why:',
    'html.label_fix2': 'Fix:',
    'html.no_issues': 'No issues found. Keep it that way.',
    'guide.next_header': 'What you can do next:',
    'guide.run_label': 'run:',
    'guide.all_clear': "You're in good shape — re-run anytime to stay safe.",
    'guide.fix_guidance.title': 'See exactly how to fix each issue, most urgent first',
    'guide.fix_guidance.why': 'Get a copy-paste fix you can hand to your agent.',
    'guide.vet_skills.title': 'Double-check your installed skills for malware',
    'guide.vet_skills.why': "Installed skills run with your agent's full permissions.",
    'guide.setup_monitoring.title': "Turn on ongoing monitoring so you're alerted if something changes",
    'guide.setup_monitoring.why': "An agent with no monitoring won't warn you if it's compromised.",
    'guide.live_test.title': 'Run a live prompt-injection test to see if your agent actually resists',
    'guide.live_test.why': 'Passive checks tell you the config; this tests real behavior.',
    'guide.review_mcp.title': 'Vet your connected MCP servers for supply-chain risk',
    'guide.review_mcp.why': 'MCP servers can inject prompts or reach internal services.',
    'guide.track_trend.title': 'Track your security score over time',
    'guide.track_trend.why': "See if you're getting safer or drifting.",
    'guide.share_grade.title': 'Share your grade (safe — findings stay private)',
    'guide.share_grade.why': 'Only the grade + score is shared, never your findings.',
    'freshness.self_test_never': 'Coverage gap: prompt-injection tests (--self-test / --redteam / --dryrun / --canary) have never been run. Run periodically to test live resistance, not just config. (offline notice; ClawSecCheck made no network call)',
    'freshness.self_test_stale': 'Coverage gap: prompt-injection tests (--self-test / --redteam / --dryrun / --canary) last run {age} days ago (threshold: {threshold} days). Run again to keep resistance tests current. (offline notice; ClawSecCheck made no network call)',
    'freshness.vet_mcp_never': 'Coverage gap: MCP supply-chain vetting (--vet-mcp) has never been run. Run periodically to check your MCP servers for supply-chain risk. (offline notice; ClawSecCheck made no network call)',
    'freshness.vet_mcp_stale': 'Coverage gap: MCP supply-chain vetting (--vet-mcp) last run {age} days ago (threshold: {threshold} days). Run again to keep your MCP server vetting current. (offline notice; ClawSecCheck made no network call)',
}


def t(key: str, **kw: object) -> str:
    """Look up a UI string by *key* and format it with **kw.

    Falls back to the key itself for unknown keys, and to the raw
    template on any formatting error. Never raises.
    """
    template = STRINGS.get(key, key)
    if not kw:
        return template
    try:
        return template.format(**kw)
    except (KeyError, IndexError):
        return template
