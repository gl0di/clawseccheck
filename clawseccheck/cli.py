"""ClawSecCheck command-line interface.

Exposed as the `clawseccheck` console script (see pyproject.toml), as `python -m clawseccheck`,
and via the bundled skill entrypoint `python3 {baseDir}/audit.py`.

Read-only with respect to OpenClaw config, with exactly one named, opt-in,
confirmation-gated exception: --apply-ignore-proposals appends previously-proposed
entries to <home>/.clawseccheckignore (see its own --help text) and never invents one.
No other flag writes inside the audited OpenClaw home.
Writes local ~/.clawseccheck score history by default; opt out with --no-history.
C-251: --trend and --monitor are NOT suppressors of that write — they are the two modes
that record a history point unconditionally, as part of their own job, so --no-history
has no effect on them (see _flag_coherence_notes / the --no-history --help text).
No network. Pure stdlib. Cross-platform.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from . import (
    audit, diff, fingerprint, load_events, load_ignore, make_canary, record_events,
    render_canary, render_card, render_dashboard, render_dashboard_findings, render_events,
    render_json, render_monitor,
    render_report, render_svg, render_vet_json, save_state, snapshot,
    detect_vet_type, vet_mcp, vet_plugin, vet_skill, vet_source,
)
from . import __released__, __version__
from .brand import WORDMARK
# B-460: same rationale as the .monitor import below — taken from the submodule so this
# internal resolver does not have to widen the curated public API in __init__.py.
from .checks import resolve_skill_target
from .collector import LIMIT_DOMAIN_SKILL, Context, collect, limit_hits_for
# B-270: the shared baseline predicate. Imported from the submodule rather than the package
# root so the new vocabulary does not have to widen the curated public API in __init__.py.
from .monitor import (
    BASELINE_ABSENT, BASELINE_CORRUPT, BASELINE_CORRUPT_ALERT, BASELINE_OK, read_baseline,
)
from .update import update_notice
from .ledger import freshness_notice as _compute_freshness, load_ledger, record_run
from .iocdb import coverage_notice as _iocdb_coverage_notice
from .iocdb import freshness_notice as _iocdb_freshness_notice
from . import risk as _risk
from .guide import render_next_actions, suggest_actions
from .integrity import package_digest
from .report import render_html
from .report import (
    _sanitize,
    render_advise,
    render_advise_json,
    render_permission_manifest,
    render_vet_dossier,
    render_vet_plan,
    surfaced_despite_suppression,
)
from .adjudication import (
    escalate_vet_output,
    render_ignore_proposals_json,
    render_judge_packet_json,
    render_judged_json,
    render_vet_judge_packet_json,
)
from .scanbudget import (
    DEFAULT_FULL_BUDGET_S, DEFAULT_VET_ALL_BUDGET_S, ScanBudgetExceeded, budget_deadline,
    budget_exceeded,
)
from . import pipeline as _pipeline
from .baseline import append_entries, is_fingerprint
from .catalog import CRITICAL, HIGH, LOW, MEDIUM, Finding
from .dossier import build_profile
from .ansi import should_color, strip_ansi
from .monitor import DEFAULT_EVENTS, DEFAULT_STATE, verify_chain
from .tamperscore import tamper_subgrade
from .scoring import compute
from .redteam import make_suite, render_suite
from .dryrun import make_scenarios, render_dryrun
from .multiturn import make_multiturn, render_multiturn
from .sarif import render_sarif
from .pdf import render_pdf
from .history import (
    DEFAULT_HISTORY,
    load as history_load,
    record as history_record,
    render_trend,
    verify as history_verify,
)
from .menu import compute_ages, render_menu, render_onboarding
from .palette import render_palette
from .percentile import render_percentile
from .logsafe import get_logger
from .safeio import secure_write_bytes, secure_write_text
from .textnorm import asciify
from .incident import render_incident
from .trajaudit import render_trajectory_analysis
from .behavioral import analyze as _behavioral_analyze
from .behavioral import explicit_path_problem as _behavioral_path_problem
from .behavioral import grade_cap_signal as _behavioral_grade_cap_signal
from .behavioral import render_behavioral_analysis
from .sbom import render_sbom


def _unicode_ok() -> bool:
    """Best-effort: make stdout UTF-8 and report whether unicode is safe to print."""
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    if "utf" in enc:
        return True
    try:  # Python 3.7+: try to force UTF-8 (works on most modern Windows terminals)
        sys.stdout.reconfigure(encoding="utf-8")
        return True
    except Exception:
        return False


# B-351: when set, every _emit() line is also appended here. The appended --full
# sections are printed as they are produced — the skill sweep in particular narrates
# per-target because progress feedback matters on a run that can take minutes — so a
# caller assembling the combined report cannot recover those lines after the fact.
# A tee rather than an `emit=` parameter on each producer, deliberately: threading a
# sink argument through would change published call signatures (and break every test
# double written against the current one) to solve a problem that belongs entirely to
# this one output path. Always installed via _tee_emitted(), which restores it.
_EMIT_TEE: list[str] | None = None


def _emit(text: str) -> None:
    """Print, falling back to ASCII-safe bytes if the console can't encode it."""
    if _EMIT_TEE is not None:
        _EMIT_TEE.append(text)
    try:
        print(text)
    except UnicodeEncodeError:
        print(asciify(text))


@contextlib.contextmanager
def _tee_emitted(sink: list[str]):
    """Collect every _emit() line into ``sink`` for the duration of the block.

    Restores the previous tee on the way out, including on an exception — a leaked tee
    would keep accumulating another run's output in a long-lived process.
    """
    global _EMIT_TEE
    prev = _EMIT_TEE
    _EMIT_TEE = sink
    try:
        yield
    finally:
        _EMIT_TEE = prev


def _record_run(capability: str, args) -> None:
    """Coverage-ledger write, gated by --no-history (B-156).

    Every opt-in capability path (vet/vet-mcp/vet-plugin/vet-source/self-test
    family/behavioral) funnels through here instead of calling
    ``ledger.record_run`` directly, so ``--no-history`` reliably suppresses
    the ``~/.clawseccheck/coverage.json`` write everywhere, not just on the
    audit-trend path (Golden Rule #2: local-only / no surprise writes).
    """
    if getattr(args, "no_history", False):
        return
    record_run(capability)


# Vet-MCP icon / verdict constants — shared by the standalone --vet-mcp path
# and the embedded vet-mcp section inside --full.
_VET_ICON_ASCII: dict[str, str] = {"FAIL": "[X]", "WARN": "[!]", "PASS": "[OK]", "UNKNOWN": "[?]"}
_VET_ICON_UNI: dict[str, str] = {"FAIL": "⛔", "WARN": "⚠️", "PASS": "✅", "UNKNOWN": "❔"}
_VET_VERDICT: dict[str, str] = {"FAIL": "DANGEROUS", "WARN": "SUSPICIOUS", "PASS": "NO KNOWN ISSUE", "UNKNOWN": "UNKNOWN"}

# Installed-skill SWEEP vocabulary (F-149) — deliberately SEPARATE names, not a
# widening of the three vet-mcp dicts above. The sweep needs two states vet-mcp has
# no concept of:
#   "SKIPPED"   = the sweep-wide deadline was hit before this target was ever reached
#                 at all ("never looked at").
#   "TRUNCATED" = this target's OWN per-target budget cut ITS scan short, so it never
#                 becomes a clean verdict either ("looked at, but not all the way").
# Two distinct rows on purpose. They must NOT be folded into _VET_ICON_ASCII /
# _VET_ICON_UNI / _VET_VERDICT: those three are the vet-mcp vocabulary and are pinned
# to exactly {FAIL, WARN, PASS, UNKNOWN} by tests/test_c106_exit_code.py, so widening
# them would silently change what every vet-mcp consumer is promised.
_SWEEP_ICON_ASCII: dict[str, str] = {
    "FAIL": "[X]", "WARN": "[!]", "PASS": "[OK]", "UNKNOWN": "[?]",
    "SKIPPED": "[-]", "TRUNCATED": "[~]",
}
_SWEEP_ICON_UNI: dict[str, str] = {
    "FAIL": "⛔", "WARN": "⚠️", "PASS": "✅", "UNKNOWN": "❔",
    "SKIPPED": "⏭️", "TRUNCATED": "⏳",
}
_SWEEP_VERDICT: dict[str, str] = {
    "FAIL": "DANGEROUS", "WARN": "SUSPICIOUS",
    "PASS": "looks like no known issue", "UNKNOWN": "could not assess",
    "SKIPPED": "not scanned (budget exceeded)",
    "TRUNCATED": "partially scanned — coverage incomplete",
}

# The wording every producer of an incomplete scan uses in its finding detail —
# load-bearing elsewhere too (dossier.py's _danger_coverage_gap matches the same
# substring). Named here rather than re-literalled at each call site.
_VET_COVERAGE_GAP_SUBSTRING = "coverage is incomplete"


def _vet_coverage_incomplete(f) -> bool:
    """True when a ``vet_skill()`` result `f` did not inspect all of its target.

    Detects the CONDITION, not one cause of it, and the distinction matters: several
    unrelated limits produce a coverage gap — the per-target scan budget inside
    ``checks/_vet.py:_run_content_ring``, and the collector's own size/file caps that
    ``check_installed_skills`` reports the same way (a 1.5 MB benign skill hits the
    1000KB/500-file cap without going anywhere near a time budget). An earlier version
    of this helper claimed to detect the budget specifically and then printed "this
    skill's own scan budget was exceeded" over a size-cap finding that said, one line
    above, that it had hit the file cap — a self-contradicting report and a fabricated
    cause. Callers must therefore describe the STATE ("partially scanned") and let the
    finding itself carry the reason.

    Mirrors dossier.py's ``_danger_coverage_gap`` detection: the signal is an UNKNOWN
    finding whose ``.detail`` contains the literal substring "coverage is incomplete".
    It can either BE the primary finding `f`, or ride along on ``f.ring_findings`` when
    a worse WARN/FAIL outranked it as primary (``checks/_vet.py:vet_skill``'s
    ``_VET_MERGE_RANK``) — so both must be checked, or a partially scanned target that
    also tripped a real WARN/FAIL would read as an ordinary, complete result.
    """
    pool = [f, *getattr(f, "ring_findings", [])]
    return any(
        fx.status == "UNKNOWN" and _VET_COVERAGE_GAP_SUBSTRING in (fx.detail or "")
        for fx in pool
    )


@dataclass
class SkillSweep:
    """The outcome of one installed-skill sweep, with no rendering baked in.

    F-149: the sweep now has three consumers — the ``--vet-all`` narrative, the
    ``--full`` SKILL SWEEP section, and the one-line ``--full --quiet`` summary —
    and vetting a fleet is the most expensive thing this tool does. Separating the
    result from its rendering is what lets all three read one run, and (the reason
    it is a hard requirement rather than a tidiness preference) what makes
    ``has_fail`` provably identical on the quiet and verbose ``--full`` branches
    instead of two hand-written tallies that can disagree.

    ``rows`` holds ``(sanitized name, row status, evidence count)`` for every target
    the sweep accounted for — including the ones it never scanned, which carry the
    SKIPPED/TRUNCATED states from ``_SWEEP_VERDICT`` rather than being dropped.
    ``findings`` carries ``(sanitized display name, resolved absolute path, primary
    Finding)`` for every target that produced one, so a later consumer never has to
    re-vet to get at the evidence.

    2026-08-01: the path used to live in a SEPARATE dict,
    ``target_paths``, keyed by that same sanitized display name — needed because a
    judge packet binds its verdicts to a target's RESOLVED PATH, not its bare name.
    That was itself unsafe: sanitizing strips zero-width/bidi characters (report.py's
    ``_sanitize``), so two skill directories differing ONLY by an invisible character
    (a real obfuscation an attacker-planted skill can use to visually impersonate an
    existing one) sanitized down to the IDENTICAL name. The second write to
    ``target_paths[name]`` then silently overwrote the first, and ``vet_targets()``'s
    name-keyed lookup handed BOTH findings the SAME (impostor's) path — a verdict a
    judge submitted for one target's fingerprint would then escalate the OTHER
    target's finding too. Confirmed by direct repro before this fix (two skills,
    ``helper`` and ``help<ZWSP>er``, under different roots: both findings resolved to
    the same path, ``len({p for p, _f in vet_targets()}) == 1`` instead of 2). Storing
    the path directly alongside its own Finding, atomically, in the one loop that
    produces both, removes the lossy name-keyed indirection entirely rather than
    re-keying it by something else — there is no longer a shared mutable map for two
    unrelated targets to collide in.
    """

    home_dir: Path
    checked_dirs: list[Path] = field(default_factory=list)
    rows: list[tuple[str, str, int]] = field(default_factory=list)
    findings: list[tuple[str, str, Finding]] = field(default_factory=list)
    truncated: bool = False
    worst: str = "PASS"
    budget_s: float = 0.0
    # B-404: the concrete reason(s) skill DISCOVERY ITSELF could not be
    # confirmed complete — collector.limit_hits_for(ctx, LIMIT_DOMAIN_SKILL), the same
    # signal check_installed_skills (B13) already uses. Distinct from a per-target
    # SKIPPED/TRUNCATED row (a target we KNOW about but could not finish scanning):
    # this is "the walk that finds targets in the first place did not finish", which
    # can be non-empty even when every row found so far scanned cleanly. Empty for a
    # sweep whose discovery genuinely completed.
    discovery_incomplete_reasons: list[str] = field(default_factory=list)

    def vet_targets(self) -> list[tuple[str, Finding]]:
        """``(vetted path, primary finding)`` for every target that produced one —
        the input the adjudication phase needs to build a per-target judge packet.

        Reads the path straight off ``findings`` (see its docstring above)
        — never through a name-keyed map, which is exactly what let two different
        targets collide onto one path before."""
        return [(path, f) for _name, path, f in self.findings]

    @property
    def no_roots(self) -> bool:
        """True when the home has no skills directory at all (nothing to sweep)."""
        return not self.checked_dirs

    @property
    def no_targets(self) -> bool:
        """True when no installed skill was found (with or without a skills root)."""
        return not self.rows

    @property
    def has_fail(self) -> bool:
        """FAIL-only, mirroring vm_has_fail's semantics for ``--exit-code``.

        A WARN (SUSPICIOUS) skill deliberately does NOT trip this — the same
        FAIL-only rule tests/test_c106_exit_code.py pins for a WARN MCP server.
        Neither do SKIPPED/TRUNCATED rows: an incomplete sweep is reported as
        incomplete (``complete`` below, and its own printed section), never by
        reddening a CI gate that would otherwise be green. The honest signal for
        "we did not look at everything" is the section, not the exit code.
        """
        return any(status == "FAIL" for _name, status, _ev in self.rows)

    @property
    def complete(self) -> bool:
        """False when any target was skipped or only partially scanned."""
        return not self.truncated

    def counts(self) -> dict[str, int]:
        """Tally buckets. Unscanned targets get their OWN buckets and are kept out
        of ``safe`` — folding them in (as ``total - fails - warns`` would, since
        they are neither FAIL nor WARN) is exactly the reassuring-but-false number
        Golden Rule #4 forbids."""
        scanned = [r for r in self.rows if r[1] != "SKIPPED"]
        truncated_n = sum(1 for _n, s, _e in scanned if s == "TRUNCATED")
        fails = sum(1 for _n, s, _e in scanned if s == "FAIL")
        warns = sum(1 for _n, s, _e in scanned if s == "WARN")
        total = len(scanned)
        return {
            "total": total,
            "fails": fails,
            "warns": warns,
            "truncated": truncated_n,
            "skipped": len(self.rows) - total,
            "safe": total - fails - warns - truncated_n,
        }

    def not_scanned(self) -> list[str]:
        """Every target this sweep cannot vouch for, named. No silent caps here —
        the narrative print may elide with "(+N more)", this may not."""
        return [n for n, s, _e in self.rows if s in ("SKIPPED", "TRUNCATED")]


def _discovery_gap_note(reasons: list[str]) -> str:
    """One narration line naming why skill DISCOVERY ITSELF — not any one target's own
    scan — was incomplete (B-404). Printed before the per-skill/aggregate
    output so the caveat is seen first, never buried after results that may themselves
    look clean."""
    extra = f" (+{len(reasons) - 6} more)" if len(reasons) > 6 else ""
    return (
        "(skill discovery was incomplete — this sweep cannot claim full coverage: "
        + "; ".join(reasons[:6]) + extra + ")"
    )


def _discovery_gap_suffix(sweep: SkillSweep) -> str:
    """A short trailing caveat for the ``--quiet`` one-liner, which (unlike the verbose
    branch) never sees ``sweep_installed_skills``'s own live narration. Empty when
    discovery completed, so every pre-existing caller is unaffected."""
    if not sweep.discovery_incomplete_reasons:
        return ""
    return (
        " Skill discovery was incomplete — coverage may be missing target(s): "
        + sweep.discovery_incomplete_reasons[0] + "."
    )


def sweep_installed_skills(
    home_dir: Path,
    ascii_only: bool = False,
    sweep_budget_s: float = DEFAULT_VET_ALL_BUDGET_S,
    narrate: bool = True,
    ctx: Context | None = None,
) -> SkillSweep:
    """Vet every installed skill the collector engine itself discovered.

    B-404: this used to run its OWN, second, flat ``iterdir()`` over
    ``collector.SKILL_DIRS`` — exactly one level deep, requiring
    ``<root>/<entry>/SKILL.md``. A GROUPED skill layout (a vendor-pack directory
    nesting a skill one level further down, e.g.
    ``skills/vendor-pack/grouped-skill/SKILL.md``) was therefore silently invisible
    to both ``--full``'s SKILL SWEEP and ``--vet-all`` — while the sweep still
    reported itself ``complete``. ``collector.py``'s own ``_read_installed_skills``
    already resolves grouped (and every config-declared) layout correctly, via the
    dedicated, bounded, cycle-safe ``skilldiscovery.py`` walk, and is what the MAIN
    audit is scored against. So this now CONSUMES that same result —
    ``ctx.installed_skill_dirs`` — instead of re-deriving a second, narrower view
    that can silently drift from it. Passing an already-collected *ctx* (as the
    ``--full`` call site does — it already ran ``collect()`` for the audit above
    it) skips a second, redundant collection pass over the same home; when *ctx* is
    omitted (the ``--vet-all`` call site, which runs before any audit) one is
    collected here.

    Completeness is read off the SAME signal ``check_installed_skills`` (B13)
    already uses to decide "was the skill scan complete" —
    ``limit_hits_for(ctx, LIMIT_DOMAIN_SKILL)`` — rather than inventing a second
    notion of "truncated" for this one CLI surface. Any genuine enumeration
    failure the collector recorded (a permission-denied skill root or
    sub-directory, the discovery engine's own directory-count cap, the
    installed-skill collection cap) surfaces here as a named reason
    (``SkillSweep.discovery_incomplete_reasons``) and forces ``complete`` to
    False — even when zero skills were found at all, because an empty result
    from a walk that could not finish is not the same claim as an empty result
    from a walk that finished and genuinely found nothing.

    With ``narrate`` (the default) it prints the per-skill verdict blocks as it
    goes — progress feedback matters on a sweep that can run for minutes — and
    with ``narrate=False`` it is completely silent, which is what the one-line
    ``--full --quiet`` summary needs. Either way it returns the same
    :class:`SkillSweep`; the aggregate table and the return code are the caller's
    job (see :func:`_sweep_summary_lines` and :func:`vet_all`).

    F-148: bounded by a whole-sweep wall-clock budget (``sweep_budget_s``,
    default DEFAULT_VET_ALL_BUDGET_S). Cost here is driven by content
    hostility, not skill count or size, so an unbounded sweep over a large or
    hostile fleet (up to collector._MAX_SKILLS) could run for the better part
    of an hour with no way to interrupt it short of Ctrl-C. Once the deadline
    passes, remaining targets are simply never vetted — but per Golden Rule #4
    (report UNKNOWN with the reason, never a silent skip or a guessed PASS)
    they are still named in the output, carried into the aggregate table with
    an explicit "not scanned" state, kept out of the "safe" tally, and force a
    non-zero return code from ``--vet-all`` (see the reasoning on
    :func:`vet_all`'s return statement).

    F-148 follow-up (post-adversarial-review): a SECOND, per-target budget also
    applies inside ``vet_skill`` itself (``checks/_vet.py:_run_content_ring``'s own
    CPU ceiling, distinct from the sweep-wide wall-clock one above). A skill whose
    OWN scan is cut short comes back one of two ways, and both are handled the same
    as the sweep-level "not scanned" case — named, excluded from "safe", non-zero
    return — never silently folded into a clean verdict:

    * ``vet_skill`` returns normally with a synthetic ``VET-COVERAGE`` UNKNOWN
      finding (as the primary result, or riding along on ``.ring_findings`` when a
      worse WARN/FAIL outranked it) whose ``.detail`` contains the literal substring
      "coverage is incomplete" — see :func:`_vet_coverage_incomplete`.
    * ``vet_skill`` raises :class:`~clawseccheck.scanbudget.ScanBudgetExceeded`
      instead of returning. Note this is NOT only the per-target CPU deadline:
      ``skillast`` also raises it cooperatively for its own reached-sinks cap, which
      is not a clock at all. Either way the target was not fully inspected, which is
      all this caller needs to know — and it must never fall into a bare
      ``except Exception``, which would read as a generic vetting error and get
      bucketed the way a clean result would. Since B-352 the type derives from
      ``BaseException``, so no such handler can take it by accident.
    """
    if ctx is None:
        ctx = collect(home_dir)

    # B-404: the single discovery implementation — see this function's
    # docstring. ``checked_dirs`` is every root the collector itself confirmed exists
    # and walked (a superset of the old static SKILL_DIRS list: it also covers every
    # config-declared workspace/extraDirs/plugins.load.paths root, the personal
    # ~/.agents/skills tier, a bundled-root override, and plugin-skills).
    # ``ctx.installed_skill_dirs`` is keyed by the collector's own collision-safe
    # name (its own dedup, richer than a bare directory basename); sorted here purely
    # for a stable, predictable sweep ordering independent of tier/root plumbing.
    checked_dirs: list[Path] = list(ctx.installed_skill_roots)
    skill_items = sorted(ctx.installed_skill_dirs.items())
    skill_paths: list[Path] = [path for _name, path in skill_items]
    skill_names: list[str] = [name for name, _path in skill_items]

    # B-404: the collector's own record of "discovery could not finish"
    # — see the docstring above. Read BEFORE the roots/targets early-returns below, so
    # a root that exists but could not be enumerated (permission denied, or a cyclic/
    # malformed structure past skilldiscovery's own caps) is never reported as a
    # clean, complete "nothing found", regardless of whether it left any OTHER target
    # scannable.
    discovery_gaps = limit_hits_for(ctx, LIMIT_DOMAIN_SKILL)

    sweep = SkillSweep(home_dir=home_dir, checked_dirs=checked_dirs,
                       budget_s=sweep_budget_s)
    if discovery_gaps:
        sweep.truncated = True
        sweep.discovery_incomplete_reasons = list(discovery_gaps)

    if not checked_dirs:
        if narrate:
            _emit(f"No skills directory found under {home_dir}")
            if discovery_gaps:
                _emit(_discovery_gap_note(discovery_gaps))
        return sweep

    if not skill_paths:
        if narrate:
            dirs_str = ", ".join(str(d) for d in checked_dirs)
            _emit(f"No skills found under {dirs_str}")
            if discovery_gaps:
                _emit(_discovery_gap_note(discovery_gaps))
        return sweep

    if narrate and discovery_gaps:
        _emit(_discovery_gap_note(discovery_gaps))

    results = sweep.rows  # (sanitized name, status, evidence_count)
    worst = "PASS"
    # F-148 + B-404: True once the sweep budget cuts the run short, OR
    # discovery itself was already known incomplete (seeded above).
    truncated = sweep.truncated

    # F-148: a monotonic deadline for the WHOLE sweep, checked before every target
    # (including the first) — never mid-target, so a target already underway always
    # finishes rather than being interrupted part-way through.
    deadline = budget_deadline(sweep_budget_s)

    for idx, skill_dir in enumerate(skill_paths):
        if budget_exceeded(deadline):
            truncated = True
            remaining_names = skill_names[idx:]
            if narrate:
                bullet = "*" if ascii_only else "•"
                _emit("")
                _emit(
                    f"(sweep budget of {sweep_budget_s:g}s exceeded — "
                    f"{len(remaining_names)} skill(s) NOT scanned; listed below, not counted as safe)"
                )
                for skipped_name in remaining_names[:12]:
                    _emit(f"  {bullet} {_sanitize(skipped_name)}")
                if len(remaining_names) > 12:
                    _emit(f"  {bullet} (+{len(remaining_names) - 12} more)")
            # Every skipped target still gets its own row in the aggregate table
            # below, even the ones elided from the printed list above (no silent
            # caps on the machine-checkable summary, only on the narrative print).
            for skipped_name in remaining_names:
                results.append((_sanitize(skipped_name), "SKIPPED", 0))
            break

        # C8: the skill NAME is attacker-controlled (it is a directory name inside
        # an untrusted, third-party install), so it is sanitized ONCE here and the
        # sanitized form is what both the narrative and the aggregate table use —
        # sanitizing only at print time let a raw name reach the table and set its
        # column width.
        skill_name = _sanitize(skill_names[idx])
        if narrate:
            _emit(f"\n=== {skill_name} ===")
        try:
            f = vet_skill(str(skill_dir))
        except ScanBudgetExceeded:
            # Adversarial-review blocker: _run_content_ring deliberately RE-RAISES
            # ScanBudgetExceeded past vet_skill (see checks/_vet.py) so the caller that
            # owns the per-target deadline can report it honestly instead of it being
            # swallowed into a false clean verdict. It MUST be caught here by NAME: the
            # bare `except Exception` below would otherwise print it as a generic
            # "(error vetting …)" row and bucket it UNKNOWN, which — same as a plain
            # PASS/UNKNOWN — currently reads as "safe" in the tally below. Since B-352
            # the type derives from BaseException, so that misfiling is now structurally
            # impossible too; this arm is what turns the signal into a verdict. Treat
            # it exactly like the finding-shaped per-target truncation just below:
            # named, excluded from "safe", and it forces a non-zero return.
            if narrate:
                _emit(
                    f"  (scan of {skill_name} ended early — only partially "
                    "scanned; not counted as safe)"
                )
            results.append((skill_name, "TRUNCATED", 0))
            truncated = True
            continue
        except Exception as exc:  # noqa: BLE001
            if narrate:
                _emit(f"  (error vetting {skill_name}: {_sanitize(str(exc))})")
            results.append((skill_name, "UNKNOWN", 0))
            continue

        if f.status == "FAIL":
            worst = "FAIL"
        elif f.status == "WARN" and worst != "FAIL":
            worst = "WARN"

        icon = _SWEEP_ICON_ASCII[f.status] if ascii_only else _SWEEP_ICON_UNI[f.status]
        lines = [
            f"{icon} '{skill_name}': {_SWEEP_VERDICT[f.status]} [{f.severity}]",
            f"    {_sanitize(f.detail)}",
        ]
        if f.evidence:
            bullet = "*" if ascii_only else "•"
            lines.append("    Evidence:")
            for ev in f.evidence[:12]:
                lines.append(f"      {bullet} {_sanitize(ev)}")
            if len(f.evidence) > 12:
                lines.append(f"      {bullet} (+{len(f.evidence) - 12} more)")
        lines.append(f"    {_sanitize(f.fix)}")

        # Adversarial-review blocker: vet_skill()'s OWN per-target CPU ceiling
        # (checks/_vet.py:_run_content_ring, distinct from this sweep's wall-clock
        # one) can cut a single skill's scan short without raising — it comes back
        # as an ordinary-looking Finding carrying a synthetic VET-COVERAGE UNKNOWN
        # (as the primary result, or on .ring_findings when a worse WARN/FAIL
        # outranked it). Left alone, a PASS/UNKNOWN verdict like that folds into the
        # "safe" tally below exactly like a real clean result. Bucket those as
        # TRUNCATED instead. A real FAIL/WARN found before the budget ran out stays
        # FAIL/WARN — it is already excluded from "safe" and demoting it would bury
        # a genuine danger signal — but the truncation is still noted in the
        # per-skill output and still forces the sweep to a non-zero return.
        row_status = f.status
        if _vet_coverage_incomplete(f):
            lines.append(
                "    (this skill was only PARTIALLY scanned — coverage is "
                "incomplete; not counted as safe)"
            )
            truncated = True
            if row_status not in ("FAIL", "WARN"):
                row_status = "TRUNCATED"
        if narrate:
            _emit("\n".join(lines))

        results.append((skill_name, row_status, len(f.evidence) if f.evidence else 0))
        sweep.findings.append((skill_name, str(skill_dir), f))

    sweep.truncated = truncated
    sweep.worst = worst
    return sweep


def _sweep_summary_lines(sweep: SkillSweep, ascii_only: bool = False) -> list[str]:
    """The aggregate summary table + tally for a finished sweep.

    Returned as lines rather than printed so the identical table can be emitted by
    ``--vet-all`` and by ``--full``'s SKILL SWEEP section. Empty when the sweep had
    no targets — the caller has already said so in plain words, and ``max()`` over
    no rows would raise.
    """
    results = sweep.rows
    if not results:
        return []
    icons = _SWEEP_ICON_ASCII if ascii_only else _SWEEP_ICON_UNI
    lines = ["", "=" * 50, "Aggregate summary:"]
    col_w = max(len(r[0]) for r in results) + 2
    # F-148: sized off the verdicts actually present this run (not the static dict),
    # so a clean, non-truncated sweep keeps today's exact column width — the wider
    # "not scanned (budget exceeded)" label only widens the table when it is used.
    verdict_w = max(len(_SWEEP_VERDICT[r[1]]) for r in results) + 1
    lines.append(f"  {'Skill':<{col_w}} {'Verdict':<{verdict_w}} Evidence items")
    lines.append(f"  {'-' * col_w} {'-' * verdict_w} --------------")
    # C-307: a FAIL/WARN row whose OWN scan was also truncated used to render with
    # the finding's row state only — "this verdict is based on an incomplete scan"
    # stayed visible in the per-skill narration above but silently dropped out of
    # this row. `row_status` above only demotes to TRUNCATED when the finding is
    # NOT already FAIL/WARN (a real danger signal must never be buried), so recover
    # the fact here instead, from `sweep.findings` (populated for every completed
    # vet) — a marker suffix, not a change to `status` itself, since that value is
    # load-bearing for the icon lookup and `sweep.counts()`'s tally.
    # Display-only lookup: a name collision here (e.g. two skills sanitizing to the
    # same visible name) means the LATER entry wins, same as a plain dict(...) would
    # have — this is a cosmetic annotation on an already name-deduplicated printed
    # row, not the adjudication binding path (see SkillSweep.findings/vet_targets()
    # docstrings for that fix).
    findings_by_name = {name: f for name, _path, f in sweep.findings}
    partial_marker = "[~ partial: coverage incomplete]" if ascii_only else "⏳ partial: coverage incomplete"
    for name, status, ev_count in results:
        marker = ""
        if status in ("FAIL", "WARN"):
            f = findings_by_name.get(name)
            if f is not None and _vet_coverage_incomplete(f):
                marker = f"  {partial_marker}"
        lines.append(
            f"  {name:<{col_w}} {icons[status]} {_SWEEP_VERDICT[status]:<{verdict_w}} {ev_count}{marker}"
        )

    # F-148: unscanned targets get their own tally bucket — folding them into
    # "safe" (as `total - fails - warns` would, since they are neither FAIL nor
    # WARN) is exactly the reassuring-but-false number Golden Rule #4 forbids.
    # Adversarial-review blocker: a per-target TRUNCATED row is the same shape of
    # problem (it is neither FAIL nor WARN either) and gets the same treatment —
    # it stays in "skill(s) checked" (it WAS attempted, unlike a SKIPPED row) but
    # is subtracted out of "safe" via its own named bucket.
    c = sweep.counts()
    tally = (f"\n  {c['total']} skill(s) checked | {c['safe']} safe | "
             f"{c['warns']} suspicious | {c['fails']} dangerous")
    if c["truncated"]:
        tally += f" | {c['truncated']} partially scanned"
    if c["skipped"]:
        tally += f" | {c['skipped']} not scanned (budget exceeded)"
    lines.append(tally)
    return lines


def _sweep_quiet_line(sweep: SkillSweep) -> str:
    """One honest line for ``--full --quiet`` — the same collapse --quiet already
    applies to the self-test and vet-mcp sections.

    It never claims more than the sweep actually did: an incomplete sweep says so
    on the same line, so a reader who only ever sees this line cannot mistake a
    partial sweep for a clean one.
    """
    if sweep.no_roots:
        line = f"SKILL SWEEP: no skills directory found under {_sanitize(str(sweep.home_dir))}."
        return line + _discovery_gap_suffix(sweep)
    if sweep.no_targets:
        dirs_str = ", ".join(_sanitize(str(d)) for d in sweep.checked_dirs)
        line = f"SKILL SWEEP: no installed skills found under {dirs_str}."
        return line + _discovery_gap_suffix(sweep)
    c = sweep.counts()
    line = (f"SKILL SWEEP: {c['total']} installed skill(s) vetted — "
            f"{c['fails']} dangerous, {c['warns']} suspicious, {c['safe']} no known issue")
    if c["truncated"]:
        line += f", {c['truncated']} partially scanned"
    if c["skipped"]:
        line += f", {c['skipped']} not scanned (budget exceeded)"
    line += "."
    dangerous = [n for n, s, _e in sweep.rows if s == "FAIL"]
    if dangerous:
        named = ", ".join(dangerous[:3])
        if len(dangerous) > 3:
            named += f", +{len(dangerous) - 3} more"
        line += f" Dangerous: {named}."
    return line + _discovery_gap_suffix(sweep) + " Full detail: --vet-all."


def _sweep_to_json(sweep: SkillSweep) -> dict:
    """Machine-readable form of a finished :class:`SkillSweep`, for ``--full --json``.

    Same underlying data as :func:`_sweep_summary_lines`/:func:`_sweep_quiet_line`
    (``sweep.rows``/``sweep.counts()``), never their prose — no string here is meant
    for a terminal. Skill names are already sanitized once, in ``sweep.rows``
    (C8, sweep_installed_skills) — not re-sanitized here.
    """
    return {
        "checked_dirs": [str(d) for d in sweep.checked_dirs],
        "no_roots": sweep.no_roots,
        "no_targets": sweep.no_targets,
        "truncated": sweep.truncated,
        "complete": sweep.complete,
        "worst": sweep.worst,
        "counts": sweep.counts(),
        "targets": [
            {"name": name, "status": status, "evidence_count": ev}
            for name, status, ev in sweep.rows
        ],
        "not_scanned": sweep.not_scanned(),
    }


def vet_all(
    home_dir: Path,
    ascii_only: bool = False,
    sweep_budget_s: float = DEFAULT_VET_ALL_BUDGET_S,
) -> int:
    """``--vet-all``: sweep every installed skill and render the result.

    Thin shell over :func:`sweep_installed_skills` (which owns the discovery, the
    budget and the per-target verdicts) plus :func:`_sweep_summary_lines`. Returns
    0 if every finding is PASS/UNKNOWN and nothing was left unscanned, else 1.
    """
    sweep = sweep_installed_skills(home_dir, ascii_only=ascii_only,
                                   sweep_budget_s=sweep_budget_s, narrate=True)
    if sweep.no_targets:
        # B-404: "no targets" is not "clean" when discovery itself could
        # not be confirmed complete (e.g. a permission-denied skill root) — that has
        # no basis for the same 0 a genuinely-empty, fully-enumerated fleet gets. The
        # reason was already narrated above (sweep_installed_skills ran narrate=True).
        return 1 if sweep.truncated else 0
    for line in _sweep_summary_lines(sweep, ascii_only=ascii_only):
        _emit(line)

    # F-148 return-code decision: a truncated sweep must NOT return the same 0 a
    # fully-clean sweep would. 0 asserts "checked everything, found nothing" — but
    # a truncated sweep never looked at the unscanned skills, so it has no basis
    # for that claim; returning 0 here would be exactly the guessed-PASS Golden
    # Rule #4 forbids, just moved from a per-check status to the process exit code.
    # This is independent of `worst` among the skills that WERE scanned: even an
    # all-clean scanned subset does not make the incomplete sweep as a whole "PASS".
    # (No third exit code: this file's vet paths are all binary 0/1 — see e.g.
    # _run_vet_mcp below — so "incomplete" reuses 1, the same code already used for
    # "found something to act on"; a caller must inspect the printed/JSON output,
    # not the bare exit code, to tell "dangerous" from "incomplete" apart.)
    #
    # `truncated` is set the moment ANY single target comes back TRUNCATED
    # (per-target budget, either the ScanBudgetExceeded catch or
    # _vet_coverage_incomplete) — same "no basis to claim PASS" reasoning, just
    # scoped to one skill instead of the whole sweep.
    #
    # NOTE this rc rule is the STANDALONE sweep's own verdict. Under --full the rc
    # belongs to the audit, so the sweep contributes FAIL-only there (SkillSweep
    # .has_fail) and truncation is reported by the printed section instead — see
    # the --exit-code tail at the end of _main().
    if sweep.truncated:
        return 1
    return 0 if sweep.worst in ("PASS", "UNKNOWN") else 1


def _build_layer_ledger(args, findings, *, degraded_count: int = 0,
                        attestation: dict | None = None, live_test_bucket=None,
                        behavioral_ran: bool = False,
                        commit_full_phases: bool = False):
    """C-425/C-426: the ONE producer of the five-layer ledger (``layers.py`` via
    ``pipeline.PipelineResult.to_ledger``) — extracted from ``_resolve_runtime_caps``
    (C-425) so the bare (non-`--full`) audit path (C-426) can call the SAME code
    instead of a second, competing builder. Every call site funnels through here;
    the mapping itself still lives in ``PipelineResult.to_ledger`` and is never
    re-derived by hand anywhere else.

    ``commit_full_phases`` — deliberately NOT just ``bool(args.full)`` read
    internally — is True only from a call site that has actually committed to
    running the installed-skill/plugin sweep and the behavioral replay LATER in
    THIS SAME invocation (today: only ``_resolve_runtime_caps``, itself gated on
    ``args.full``, for the default `--full` report/`--json` path and
    `--dashboard --full`). Marking those phases "ran" is a promise the caller must
    be able to keep: a `--full --badge`/`--html`/`--sarif`/`--risk-paths` run (or
    any of `--trend`/`--monitor`/`--percentile`/`--next`) never runs the sweep or
    the behavioral replay at all — `--full` is a documented no-op for every one of
    them — so a call from `_main`'s early, pre-dispatch path (C-426) always leaves
    this False and gets exactly the "no phases added" bare-run ledger
    ``to_ledger()`` already produces correctly (static ran, everything else
    not_reached/unavailable per its own docstring). Reading ``args.full`` directly
    here instead would fabricate a completed sweep for those runs — the one thing
    Golden Rule #4 forbids.

    Returns a ``layers.LayerLedger`` — never ``None``. A bare/incomplete ledger is
    exactly what a bare run's own ``to_ledger()`` mapping already produces; there is
    no "no ledger" state left to represent once this is the shared entry point.
    """
    prelim = _pipeline.PipelineResult(fast=args.fast)
    if commit_full_phases:
        if args.fast:
            prelim.add(_pipeline.PhaseResult(
                name=_pipeline.PHASE_SKILL_SWEEP, status=_pipeline.STATUS_SKIPPED,
                complete=False, detail="skipped — --fast was given."))
            prelim.add(_pipeline.PhaseResult(
                name=_pipeline.PHASE_PLUGIN_SWEEP, status=_pipeline.STATUS_SKIPPED,
                complete=False, detail="skipped — --fast was given."))
            prelim.add(_pipeline.PhaseResult(
                name=_pipeline.PHASE_BEHAVIORAL, status=_pipeline.STATUS_SKIPPED,
                complete=False, detail="skipped — --fast was given."))
        else:
            prelim.add(_pipeline.PhaseResult(
                name=_pipeline.PHASE_SKILL_SWEEP, status=_pipeline.STATUS_RAN,
                detail="scheduled this invocation (installed-skill sweep)."))
            prelim.add(_pipeline.PhaseResult(
                name=_pipeline.PHASE_PLUGIN_SWEEP, status=_pipeline.STATUS_RAN,
                detail="scheduled this invocation (installed-plugin sweep)."))
            prelim.add(_pipeline.PhaseResult(
                name=_pipeline.PHASE_BEHAVIORAL,
                status=_pipeline.STATUS_RAN if behavioral_ran else _pipeline.STATUS_ERROR,
                detail=("behavioral replay completed." if behavioral_ran
                        else "behavioral replay raised — see run_behavioral's own section.")))
    return prelim.to_ledger(findings, degraded_count=degraded_count,
                            attestation=attestation, live_test_bucket=live_test_bucket)


def _percentile_line(score, ascii_only: bool) -> str:
    """C-426: rank the score, or say plainly why there is nothing to rank.

    `render_percentile` takes a bare int and would happily rank the number a
    `graded=False` ScoreResult still carries internally — publishing, through a
    different command, exactly the figure the report withheld. That is the same leak
    C-423 already had to close in `render_json`'s projection block, arriving through
    `--percentile`/`--trend` instead.

    A percentile is a comparison against a reference distribution of *complete*
    audits, so an incomplete run has no honest place in it: withholding the rank is
    the correct answer, not a degraded one. Both call sites route through here so the
    two cannot drift.
    """
    if not getattr(score, "graded", True):
        return ("No rank yet — ranking compares your score against a reference "
                "profile, and this run has no score. Complete the remaining layers "
                "to get one.")
    return render_percentile(score.score, ascii_only)


def _resolve_runtime_caps(ctx, findings, score, args, *, attestation=None):
    """F-153: shared by `--full`'s own cap computation and `--dashboard --full`'s —
    the exact same two cap-only signals (F-154 behavioral, F-155 live-injection),
    computed identically, so the two output surfaces can never show a different
    grade for the same run. Pure extraction of the pre-existing `--full` logic;
    behaviour is unchanged for that call site.

    Returns `(score, full_deadline, judged_bundle, live_signal, behavioral_fired_ids)`.
    `score` is the SAME object passed in when neither cap fires, a freshly recomputed
    one otherwise (mirrors `scoring.compute`'s own "never mutate, always return"
    contract). `live_signal` is returned (not just consumed here) because the caller
    also uses it afterwards to decide whether an unreproducible live-test verdict must
    be kept OUT of history/trend/baseline (see the F-155 note at the history-record
    call). `behavioral_fired_ids` is returned too (B-379) so callers building a
    "what-if" projection (`scoring.project`) over the same findings can thread the
    IDENTICAL cap inputs through their own `compute()` calls — this function already
    has them; re-deriving them a second time is what caused `scoring.project()`'s
    "projection" block to silently disagree with the top-level capped score before.

    Known, deliberate scope limit carried over unchanged from the pre-F-153 code
    this replaces: this re-runs `behavioral.analyze(ctx)` a second time when the P8
    phase later renders its OWN section (both `--full` and `--dashboard --full`
    render one) — there is no cheap way to thread the result through without
    widening `run_pipeline`/`run_behavioral`'s signatures, and P8's own budget
    check runs at a different point in the pipeline than this early call can see.

    C-425: also a choke point (via the shared `_build_layer_ledger`, C-426) that
    builds the five-layer ledger (`layers.py`) and threads it into `compute()` —
    deliberately not as three separate blocks at `--full`'s own report/--json call
    site and `--dashboard --full`'s, so the two surfaces cannot drift apart on what
    "ran" means, the same guarantee this function already gives the two cap signals
    above. `attestation` is the already-parsed attestation dict (or `None`/`{}`) the
    caller resolved before `audit()` ran — passed in rather than re-read so this
    function does not have to know `--attest`/`--judged-bundle`'s own parsing rules.

    C-426: the returned `ledger` is never `None` — even when `args.full` is False
    this now builds the SAME bare (no-phases-committed) ledger `_main`'s own
    pre-dispatch call already built for `score` above, via the identical
    `_build_layer_ledger` helper (the one producer both call sites share), so a
    plain (non-`--full`) `--json` run's `render_json` projection block sees the
    IDENTICAL ledger the top-level `score` was already computed against — never a
    stale `None` that would silently re-grade the projection's own `compute()`
    calls. `score` itself is only recomputed `if args.full:` below, exactly as
    before: a non-`--full` call returns the SAME `score` object the caller passed
    in, already ungraded by `_main`'s own bare-path recompute.

    The installed-sweep layer cannot be read off REAL phase results here — P6/P7
    (skill/plugin sweep) run later, in the caller's own report/--json or
    --dashboard branch, and re-running them here just to know their outcome would
    scan the fleet a second time (the exact cost this function's own behavioral
    duplication above already accepts is worth avoiding for a cheaper check, not a
    second full sweep). So under `--full` (not `--fast`) they are optimistically
    marked `ran` — this invocation has committed to running them later in the SAME
    call, barring a rare later error/budget-exceeded. The behavioral layer input
    does NOT need that optimism: it reuses the REAL outcome of the
    `behavioral.analyze(ctx)` call just above (already paid for here) — `ran` if it
    completed, `error` if it raised. A later real P6/P7 failure still prints its own
    honest section (P10) even though it cannot retroactively ungrade a score already
    shown — a documented gap, not a silent one.
    """
    # F-153: the pipeline's wall-clock window opens HERE, before the first appended
    # phase, so the time the earlier phases spend is charged against the same window
    # the later ones draw from. Cooperative (a plain monotonic float) — never a nested
    # check_deadline block, whose disarm-on-exit would delete an outer deadline.
    full_deadline = _pipeline.start_deadline(DEFAULT_FULL_BUDGET_S) if args.full else None
    judged_bundle = (
        _judged_bundle(args.judged_bundle)
        if (args.full and args.judged_bundle is not None) else None
    )
    # F-155: a VULNERABLE live injection-test verdict (canary/dryrun/redteam/multiturn),
    # fed back through the SAME --judged-bundle file the "judged"/"vetJudged" buckets
    # already use (no second submission channel) — never a second CLI flag. Only present
    # when --full carried one; every other invocation sees `live_signal.hit is False` and
    # this whole function is a no-op, which is what keeps every non---full path (a plain
    # --dashboard with no --full, --trend, --monitor, the plain report) byte-identical to
    # before this feature existed. `--dashboard --full` (F-153) is a DELIBERATE new
    # exception: it calls this helper too, so its card shows the identical capped grade
    # `--full`'s own report/--json would for the same run.
    live_test_bucket = judged_bundle.get("liveTest") if judged_bundle else None
    live_signal = _pipeline.live_test_cap_signal(live_test_bucket)
    # F-154: the behavioral cap-only signal (T1/T2/T3/B191), gated on THIS invocation
    # having ACTUALLY run `behavioral.analyze(ctx)` — mirrors --fast's own skip of P8
    # (`_pipeline.run_pipeline`'s `run_behavioral`), so a --full --fast run (or any
    # non---full invocation) sees byte-identical behaviour to before this cap existed:
    # no analysis run == no cap, never a guess.
    #
    # B-378: `behavioral.analyze(ctx)` is wrapped the same way `pipeline.run_behavioral`
    # already wraps its own call to it (that phase's own comment: "one phase must not
    # break the whole card"). Before this guard, ANY exception here — e.g. a schema-
    # drifted `channels.<provider>.accounts` shaped as a list instead of a dict, which
    # `behavioral.py`'s own ingress-classification helpers can raise on — propagated
    # out of `_resolve_runtime_caps` before a single line of the report had been
    # printed, so `--full`/`--dashboard --full` exited 1 with zero report, zero grade,
    # zero findings. A security tool that produces NO verdict at all on a schema-
    # drifted config is strictly worse than one that degrades a phase: on failure, the
    # behavioural cap is simply not resolved (treated as "nothing fired"), exactly as
    # it already is for every non---full / --fast invocation above.
    behavioral_fired_ids: "frozenset[str]" = frozenset()
    _behavioral_ran = False
    if args.full and not args.fast:
        try:
            behavioral_fired_ids = _behavioral_grade_cap_signal(_behavioral_analyze(ctx))
            _behavioral_ran = True
        except Exception:  # noqa: BLE001 — see run_behavioral's identical containment
            behavioral_fired_ids = frozenset()

    # C-425/C-426: build the five-layer ledger via the ONE shared producer
    # (`_build_layer_ledger`) — see that function's own docstring for why
    # `commit_full_phases` (not a bare `args.full` read) is what decides whether the
    # installed-sweep/behavioral phases are marked "ran": THIS call site is exactly
    # the one that has committed to running them later in the same invocation, so it
    # opts in on the same `args.full` gate the pre-extraction code used.
    ledger = _build_layer_ledger(
        args, findings, degraded_count=score.degraded_count, attestation=attestation,
        live_test_bucket=live_test_bucket, behavioral_ran=_behavioral_ran,
        commit_full_phases=args.full,
    )

    if args.full:
        # C-425: recompute unconditionally under --full, not only when a cap-only
        # signal fired above — an INCOMPLETE ledger must change `graded`/
        # `missing_layers`/`not_checked` on its own, with nothing else scored
        # differently (see compute()'s own `ledger` docstring paragraph). A COMPLETE
        # ledger produces a byte-identical ScoreResult to omitting it (C-422), so
        # this is never a behaviour change for a run where every layer ran.
        score = compute(findings, ctx, live_test_vulnerable=live_signal.hit,
                        live_test_reason=live_signal.reason,
                        behavioral_fired_ids=behavioral_fired_ids, ledger=ledger)
    # C-423: the ledger is returned, not just consumed, for the same reason
    # `behavioral_fired_ids` is (B-379): render_json's projection block runs its own
    # compute() calls, and without the ledger `projection.current.score` published the
    # very number the top-level `score` key was withholding -- one key apart in the
    # same document. Caught by test_full_json_projection_current_matches_top_level_score.
    return score, full_deadline, judged_bundle, live_signal, behavioral_fired_ids, ledger


def _apply_live_test_cap(ctx, findings, score, args):
    """F-155 fix (C-135): `--trend` and `--monitor` both return from `_main`'s dispatch
    cascade BEFORE `_resolve_runtime_caps` ever runs (that call sits after both branches,
    reached only by the default `--full` report/--json path and by `--dashboard --full`)
    — so a VULNERABLE live-test verdict, seeded or not, could never bind
    `LIVE_INJECTION_CAP` for these two modes. That contradicts SKILL.md,
    docs/OUTPUT_SCHEMA.md §12, and docs/USAGE.md, which all promise a seeded liveTest
    verdict reaches `--trend`/`--monitor` (and that an unseeded one still caps the run
    without being recorded). This helper is called from inside each of those two
    branches, before they compute/print/record anything that reads `score`.

    Deliberately narrower than `_resolve_runtime_caps`: this resolves ONLY the liveTest
    bucket — never the F-154 behavioral cap (`behavioral.analyze(ctx)` is not re-run
    here) and never the `judged`/`vetJudged` buckets. Neither has a matching documented
    promise for `--trend`/`--monitor` (both stay visibility/advisory-only there, exactly
    as before this fix), so folding them in here would be undocumented scope creep, not
    a fix for this defect.

    Returns `(score, live_signal)` — `score` is the SAME object passed in when the
    signal does not hit, a freshly recomputed one otherwise (the same "never mutate,
    always return" contract `_resolve_runtime_caps`/`scoring.compute` already follow).
    The caller uses `live_signal.hit and not live_signal.reproducible` to decide whether
    this run must be excluded from history/the monitor baseline (an unseeded verdict
    still caps THIS run's displayed score, but must never be recorded — see the F-155
    note at `_resolve_runtime_caps`'s own history-record call site).

    B-379: reads `args.judged_bundle` regardless of `args.full`. This helper exists
    SPECIFICALLY to reach `--trend`/`--monitor`/`--percentile`/`--next`, none of which
    require `--full` — gating the read on `args.full` (as an earlier version of this
    function did) meant `--trend --judged-bundle X` (no `--full`) silently dropped the
    bundle with no warning and recorded an UNCAPPED score, exactly the defect this
    function was written to close.
    """
    judged_bundle = (
        _judged_bundle(args.judged_bundle)
        if args.judged_bundle is not None else None
    )
    live_test_bucket = judged_bundle.get("liveTest") if judged_bundle else None
    live_signal = _pipeline.live_test_cap_signal(live_test_bucket)
    if live_signal.hit:
        # C-426: the ledger MUST be threaded through this recompute. `_main` already
        # built a bare one and computed `score` against it, so the run reaching here
        # is ungraded; a bare `compute(findings, ctx, live_test_vulnerable=True)` would
        # silently hand the grade BACK — and it would do so on exactly the runs that
        # submitted a VULNERABLE live-test verdict, i.e. the most alarming ones. The
        # bucket is known here (it was not at `_main`'s early call), so layer 5 now
        # reads `ran` rather than `unavailable`: a submitted verdict IS the live-
        # behaviour layer having run, regardless of its value — see `to_ledger`'s own
        # docstring for why presence, not verdict, is what that layer observes.
        ledger = _build_layer_ledger(
            args, findings, degraded_count=score.degraded_count,
            attestation=getattr(ctx, "attestation", None),
            live_test_bucket=live_test_bucket,
        )
        score = compute(findings, ctx, live_test_vulnerable=True,
                        live_test_reason=live_signal.reason, ledger=ledger)
    return score, live_signal


def _run_vet_mcp(target, args, ascii_only: bool) -> int:
    """Run vet_mcp on `target` (None = all configured servers) and render the risk
    dossier — shared by the explicit --vet-mcp mode and the --vet autodetect route
    (F-072), so the two entry points can never drift."""
    findings = vet_mcp(target=target, home=args.home)
    profile = build_profile(findings, target or "configured", "mcp")
    # Side output: SARIF file (mirrors the full-audit --sarif behavior, incl. the same
    # graceful handling of an unwritable path — B-014).
    if args.sarif:
        try:
            secure_write_text(
                Path(args.sarif).expanduser(),
                render_sarif(findings, tool_version=__version__, profile=profile),
            )
            _emit(f"(SARIF written to {args.sarif})")
        except OSError as exc:
            _emit(f"(could not write SARIF: {exc})")
    _record_run("vet_mcp", args)
    _vet_rc = 1 if profile.overall_status in ("FAIL", "WARN") else 0
    if args.json:
        _emit(render_vet_json(profile, mode="vet-mcp", version=__version__))
    else:
        _emit(render_vet_dossier(profile, ascii_only=ascii_only))
    return _vet_rc


# --- Flag-coherence pre-flight (B-066 / B-067) ---------------------------------
# main() resolves "modes" via a fixed-order cascade of early returns; a second mode
# flag, or a global modifier the chosen mode doesn't honor, would otherwise be dropped
# silently. We never change a mode's behavior — we only surface, on stderr (so
# machine-readable stdout stays clean), what is being ignored. Warn-and-continue.

# I3: rank for --fail-on's "at or above SEVERITY" comparison. catalog.py deliberately
# carries no ordered severity tuple (WEIGHT is a magnitude, not a rank a CLI flag should
# lean on) — this is the local, single-purpose ordering: higher rank = more severe, so
# "SEVERITY and everything ranked >= it" is exactly `{s: r for s, r in _SEVERITY_RANK.items()
# if r >= _SEVERITY_RANK[threshold]}`.
_SEVERITY_RANK = {CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0}

# Primary modes in the EXACT precedence order main() resolves them below.
# kind "opt" → active when the value is not None; "bool" → active when truthy.
#
# B-276: this list used to be hand-ordered and had drifted from _main()'s real
# cascade in 27 pairs — so _flag_coherence_notes named the WRONG winner. The worst
# case was `--monitor --judge-packet`: stderr said "--judge-packet ignored (running
# --monitor)" while _main() actually ran --judge-packet at :1048 (before --monitor at
# :1074), printed the judge packet, and never advanced the monitor baseline. The note
# accused the mode that had in fact won. Detection was deferred, not destroyed (the
# baseline never advanced, so a later monitor-only run still fires), but three
# consecutive combined runs each returned rc=0, wrote nothing, and repeated the lie.
#
# The order below is now the order tests/test_mode_drift_guard.py extracts from
# _main()'s top-level `if` cascade, and that test asserts EQUALITY, not membership.
# Reordering this list changes only which mode the stderr note NAMES — dispatch has
# always been decided by _main()'s cascade and is untouched.
_PRIMARY_MODES = [
    ("purge", "--purge", "bool"),
    ("apply_ignore_proposals", "--apply-ignore-proposals", "opt"),
    ("verify_self", "--verify-self", "bool"),
    ("verify_history", "--verify-history", "bool"),
    ("verify_events", "--verify-events", "bool"),
    ("vet_plan", "--vet-plan", "opt"),
    ("menu", "--menu", "bool"),
    ("functions", "--functions", "bool"),
    ("vet", "--vet", "opt"),
    ("vet_skill", "--vet-skill", "opt"),
    ("vet_plugin", "--vet-plugin", "opt"),
    ("vet_all", "--vet-all", "bool"),
    ("vet_mcp", "--vet-mcp", "opt"),
    ("vet_source", "--vet-source", "opt"),
    ("advise", "--advise", "opt"),
    ("canary", "--canary", "bool"),
    ("redteam", "--redteam", "bool"),
    ("dryrun", "--dryrun", "bool"),
    ("multiturn", "--multiturn", "bool"),
    ("self_test", "--self-test", "bool"),
    ("ask", "--ask", "bool"),
    ("show_suppressed", "--show-suppressed", "bool"),
    ("watch_log", "--watch-log", "bool"),
    ("risk_paths", "--risk-paths", "bool"),
    ("badge", "--badge", "opt"),
    ("html", "--html", "opt"),
    ("sarif", "--sarif", "opt"),
    ("pdf", "--pdf", "opt"),
    ("trend", "--trend", "bool"),
    ("percentile", "--percentile", "bool"),
    ("next", "--next", "bool"),
    ("dashboard", "--dashboard", "bool"),
    ("dashboard_findings", "--dashboard-findings", "bool"),
    ("sbom", "--sbom", "bool"),
    ("incident", "--incident", "bool"),
    ("judge_packet", "--judge-packet", "bool"),
    ("judged", "--judged", "opt"),
    ("propose_ignore", "--propose-ignore", "opt"),
    ("analyze_trajectory", "--analyze-trajectory", "opt"),
    ("behavioral", "--behavioral", "opt"),
    ("monitor", "--monitor", "bool"),
]

# Which tracked global modifiers each primary mode actually honors. The default
# report path (no primary mode) honors all of them. --sarif additionally rides
# along as a side output under --vet/--vet-mcp (handled specially below).
_MODE_HONORS = {
    "vet": frozenset({"json"}),
    "vet_skill": frozenset({"json"}),
    "vet_plugin": frozenset({"json"}),
    "vet_mcp": frozenset({"json"}),
    "vet_source": frozenset({"json"}),
    "advise": frozenset({"json"}),
    # F-153: --dashboard --full renders the whole combined pipeline report (the
    # phases --full itself runs); --compact only ever modifies THAT combined render.
    "dashboard": frozenset({"full", "compact"}),
    # C-374: --pdf wins the mode race over --dashboard (it is earlier in _PRIMARY_MODES),
    # but both are honored now — and under `--dashboard --full --pdf` the --full phases
    # are what the PDF's pipeline blocks are rendered FROM, so --full genuinely has an
    # effect here. Saying "no effect" was true of the findings-only PDF, not this one.
    "pdf": frozenset({"full", "compact"}),
    # F-155 fix (C-135): --judged-bundle's `liveTest` bucket now caps the score
    # reaching --trend/--monitor too (see _apply_live_test_cap) — a SEPARATE honor
    # from "full", deliberately not folded into it the way --dashboard's is: --full/
    # --quiet/--fast genuinely still have no effect here (no deep phase ever runs for
    # --trend/--monitor), only --judged-bundle does, so the "full"-bundle no_effect
    # check below is given its own "judged_bundle" escape hatch rather than reusing
    # "full" (which would wrongly silence the still-true --full/--quiet/--fast notes).
    "trend": frozenset({"judged_bundle"}),
    "monitor": frozenset({"judged_bundle"}),
    # B-379: --percentile/--next now resolve the liveTest cap the same way
    # --trend/--monitor already did (see _apply_live_test_cap's call sites below).
    "percentile": frozenset({"judged_bundle"}),
    "next": frozenset({"judged_bundle"}),
}

# Primary modes that run AFTER the --attest block in main()'s cascade: their ctx and
# findings come from audit(attestation=...), so --attest is genuinely consumed there,
# not ignored. This is exactly the tail of _PRIMARY_MODES from "risk_paths" onward —
# every mode dispatched below the audit() call at _main():~960 — and
# tests/test_mode_drift_guard.py derives that tail from the AST and asserts equality,
# so the set cannot drift from the cascade again.
#
# B-301 (adjacent): "behavioral" was missing here, so `--behavioral --attest f.json`
# printed "note: --attest has no effect with --behavioral" — false in the opposite
# direction, since T3 reads ctx.attestation. "sbom", "incident", "judge_packet",
# "judged" and "analyze_trajectory" were missing for the same reason.
_ATTEST_CONSUMERS = frozenset({
    "risk_paths", "badge", "html", "sarif", "pdf", "trend", "percentile",
    "next", "dashboard", "dashboard_findings", "sbom", "incident",
    "judge_packet", "judged", "propose_ignore", "analyze_trajectory",
    "behavioral", "monitor",
})


def _mode_active(args, attr: str, kind: str) -> bool:
    v = getattr(args, attr, None)
    return v is not None if kind == "opt" else bool(v)


def _flag_coherence_notes(args) -> list[str]:
    """Notes for ignored modes / no-effect global modifiers. Never mutates args."""
    active = [(a, f) for a, f, k in _PRIMARY_MODES if _mode_active(args, a, k)]
    notes: list[str] = []
    # C-426: the "--fail-under is deprecated and ignored" note lived here. The flag is
    # gone now, so argparse itself reports it (`unrecognized arguments`) and a note
    # about a flag that cannot be parsed would be unreachable code.
    if not active:
        # No primary mode: the default path resolves output as --json > --card > text.
        # If both format flags are set, --json wins and --card is silently dropped.
        if bool(getattr(args, "json", False)) and bool(getattr(args, "card", False)):
            notes.append("note: --card ignored (running --json)")
        # --quiet only collapses --full's appended sections; alone it has nothing to do.
        if bool(getattr(args, "quiet", False)) and not bool(getattr(args, "full", False)):
            notes.append("note: --quiet has no effect without --full")
        # --fast / --judged-bundle are --full modifiers on exactly the same terms:
        # --fast drops --full's deep phases, --judged-bundle answers their judge packet.
        # Without --full there are no phases to drop and no packet to answer, so both
        # would be silently dropped — the B-068 bug class this block exists to prevent.
        if bool(getattr(args, "fast", False)) and not bool(getattr(args, "full", False)):
            notes.append("note: --fast has no effect without --full")
        if (getattr(args, "judged_bundle", None) is not None
                and not bool(getattr(args, "full", False))):
            notes.append("note: --judged-bundle has no effect without --full")
        # F-153: --compact only ever modifies --dashboard --full's combined render;
        # with no primary mode active here, --dashboard cannot be the one that ran.
        if bool(getattr(args, "compact", False)):
            notes.append("note: --compact has no effect without --dashboard --full")
        # B-482: --purge / --apply-ignore-proposals are the only two consumers of --yes,
        # and both are primary modes — so reaching HERE at all means no mode that can
        # honor it ran. Checked in this branch too (not only the winning-mode one below),
        # because the default report path is exactly where a scripted `--yes` most often
        # lands, believing it disabled a confirmation gate it never reached.
        if bool(getattr(args, "yes", False)):
            notes.append("note: --yes has no effect without --purge or "
                         "--apply-ignore-proposals")
        return notes  # the default path honors every tracked global modifier
    win_attr, win_flag = active[0]
    ignored = [
        f for a, f in active[1:]
        # --sarif is a side output under --vet/--vet-mcp, not an ignored mode.
        if not (a == "sarif" and win_attr in ("vet", "vet_skill", "vet_plugin", "vet_mcp"))
        # C-373: --pdf and --dashboard COMPOSE rather than supersede — the card is the
        # chat message that fits, the PDF is the attachment it points at, and both are
        # produced in one run. Reporting "--dashboard ignored (running --pdf)" was true
        # of the old early-return dispatch and is a lie about the new one.
        and not (a == "dashboard" and win_attr == "pdf")
    ]
    # --card is a default-path output selector; any primary mode supersedes it.
    if bool(getattr(args, "card", False)):
        ignored.append("--card")
    if ignored:
        notes.append(f"note: {', '.join(ignored)} ignored (running {win_flag})")
    honored = _MODE_HONORS.get(win_attr, frozenset())
    # C-374: --pdf consumes --full/--compact ONLY alongside --dashboard — that is the
    # path which computes the pipeline phases the PDF's blocks are rendered from. A bare
    # `--pdf --full` genuinely ignores --full, and must keep saying so; silencing that
    # note for every --pdf run would trade one lie for another.
    if win_attr == "pdf" and not bool(getattr(args, "dashboard", False)):
        honored = honored - {"full", "compact"}
    no_effect: list[str] = []
    if bool(getattr(args, "json", False)) and "json" not in honored:
        no_effect.append("--json")
    if getattr(args, "save", None) is not None and "save" not in honored:
        no_effect.append("--save")
    if bool(getattr(args, "exit_code", False)) and "exit_code" not in honored:
        no_effect.append("--exit-code")
    if getattr(args, "fail_on", None) is not None and "fail_on" not in honored:
        no_effect.append("--fail-on")
    # --full / --attest are enrichment modifiers a winning primary mode can silently
    # defeat (B-068). --full is consumed only on the default report path, so ANY
    # winning mode drops it. --attest feeds audit(), so modes that run AFTER the
    # attest block genuinely consume it (their findings reflect B43/B44) — only the
    # early-returning modes (menu/vet/live-test family) truly ignore it.
    if bool(getattr(args, "full", False)) and "full" not in honored:
        no_effect.append("--full")
    # --quiet is a --full modifier; a winning primary mode drops --full, so --quiet too.
    if bool(getattr(args, "quiet", False)) and "full" not in honored:
        no_effect.append("--quiet")
    # Same for the other two --full modifiers (C7): they are modifiers, never primary
    # modes, so they are never in _PRIMARY_MODES and never get their own top-level
    # dispatch branch — a winning mode drops --full, and takes them with it.
    if bool(getattr(args, "fast", False)) and "full" not in honored:
        no_effect.append("--fast")
    # F-155 fix (C-135): --trend/--monitor now genuinely honor --judged-bundle's
    # liveTest bucket (the cap reaches them — see _apply_live_test_cap) even though
    # --full itself still has no effect there, so this checks its OWN "judged_bundle"
    # honor rather than reusing "full" the way --dashboard's does (which would wrongly
    # silence the still-true --full/--quiet/--fast notes above for --trend/--monitor).
    if (getattr(args, "judged_bundle", None) is not None
            and "full" not in honored and "judged_bundle" not in honored):
        no_effect.append("--judged-bundle")
    # F-153: --quiet has no --dashboard analogue — --compact is the dashboard's own
    # channel-limit lever — so it stays un-honored there even though --fast /
    # --judged-bundle now genuinely are (checked above via the generic "full" gate,
    # which --dashboard --full's honored set now includes).
    if bool(getattr(args, "quiet", False)) and win_attr == "dashboard":
        no_effect.append("--quiet")
    # F-153: --compact only ever modifies --dashboard --full's combined render —
    # both halves are required, so a winning --dashboard without --full still
    # leaves it with no effect, same as any other winning mode.
    if (bool(getattr(args, "compact", False))
            and not (win_attr == "dashboard" and bool(getattr(args, "full", False)))):
        no_effect.append("--compact")
    if getattr(args, "attest", None) is not None and win_attr not in _ATTEST_CONSUMERS:
        no_effect.append("--attest")
    # F-164: --exhaustive is consumed by the same audit() call --attest's consumers
    # already share downstream, plus --show-suppressed (which re-runs audit() itself
    # to keep B164/B180 fingerprints matching a real --exhaustive run — see its own
    # comment). Every other mode (vet/menu/live-test family, etc.) never touches a
    # real check-execution audit() call, so --exhaustive genuinely has no effect there.
    if (bool(getattr(args, "exhaustive", False))
            and win_attr not in _ATTEST_CONSUMERS and win_attr != "show_suppressed"):
        no_effect.append("--exhaustive")
    # --trend / --monitor record a score-history point as part of their job, so
    # --no-history cannot suppress it there (every other mode either records on the
    # default path or writes no history at all, where --no-history is a no-op).
    if win_attr in ("trend", "monitor") and bool(getattr(args, "no_history", False)):
        no_effect.append("--no-history")
    # B-482: --yes skips the confirmation prompt for exactly two commands, and its own
    # help already says "has no effect without one of those two" — but nothing enforced
    # that, so passing it anywhere else was silently accepted. That is the specific
    # failure this whole warn-and-continue mechanism exists to prevent: a scripted run
    # that believes it disabled an interactive gate it never reached.
    if (bool(getattr(args, "yes", False))
            and win_attr not in ("purge", "apply_ignore_proposals")):
        no_effect.append("--yes")
    if no_effect:
        notes.append(f"note: {', '.join(no_effect)} has no effect with {win_flag}")
    return notes


def _onboarding_reason(home: Path) -> str | None:
    """Screen-13 trigger: is there genuinely nothing to audit?

    Returns ``"missing"`` (home path absent), ``"empty"`` (home is a bare directory),
    or ``None`` (something is there — hand off to the normal audit path). A home that
    exists but is unreadable (perms) returns ``None`` on purpose: that is the "config
    present but unreadable" case, which the dashboard/error path surfaces distinctly —
    onboarding must not hide a real, permission-blocked setup behind a welcome screen.
    """
    if not home.exists():
        return "missing"
    try:
        if home.is_dir() and not any(home.iterdir()):
            return "empty"
    except OSError:
        return None
    return None


# --- --purge: opt-in, confirmation-gated local-store cleanup (C-164) -----------

# The ONLY files --purge will ever touch, plus their advisory-lock sidecars
# (locking.journal_lock creates "<file>.lock" next to history.jsonl/events.jsonl).
# Deliberately a fixed whitelist, never a glob/rmtree of the store directory —
# an unrelated file a user happens to keep in ~/.clawseccheck/ must never be at risk.
#
# F-162: --badge/--html/--sarif/--pdf all take an explicit --flag PATH, so nothing
# writes into the store automatically today — but SKILL.md's own promise ("writes only
# its own local report/history, removable with --purge") reads as covering any report
# artifact an agent is told to write there by convention, and a purge test with a
# populated store previously left a badge file untouched among the survivors. Rather
# than let that gap grow with every new output format, the conventional default
# filenames for all four report renderers are whitelisted here too — inert (a plain
# no-op) until/unless something actually writes one of them, same as any other
# not-yet-created whitelist entry.
_PURGE_FILENAMES = (
    "history.jsonl", "events.jsonl", "state.json", "coverage.json",
    "openclaw-security-badge.svg", "openclaw-security-report.html",
    "openclaw-security-report.sarif", "openclaw-security-report.pdf",
)


def _confirm_purge(paths: "list[Path]") -> "tuple[bool, bool]":
    """Print the exact files to be deleted and ask for confirmation.

    Returns (proceed, eof):
      - (True, False)  — explicit y/yes answer: proceed.
      - (False, False) — any other typed answer (including blank/"n"): declined,
        a normal (non-error) abort.
      - (False, True)  — EOFError (no stdin / non-interactive): abort loudly,
        the caller reports this as an error (rc 1), never a silent proceed.
    Kept as its own function so tests can monkeypatch it.
    """
    _emit("The following files will be permanently deleted:")
    for p in paths:
        _emit(f"  {p}")
    try:
        answer = input("Delete these files? [y/N]: ")
    except EOFError:
        return False, True
    return answer.strip().lower() in ("y", "yes"), False


def _run_purge(args) -> int:
    """Delete ClawSecCheck's local store (opt-in, confirmation-gated).

    Resolves the store directory from --history's parent (all four known files
    live alongside each other under ~/.clawseccheck/ by default). Operates ONLY
    on the fixed whitelist of known filenames plus their ".lock" sidecars —
    never globs or rmtree's the directory, so an unrelated file the user happens
    to keep there is never at risk. Read-only until the user (or --yes) confirms.
    """
    store_dir = Path(args.history).expanduser().parent
    candidates = [store_dir / name for name in _PURGE_FILENAMES]
    candidates += [store_dir / (name + ".lock") for name in _PURGE_FILENAMES]
    existing = [p for p in candidates if p.exists()]

    if not existing:
        _emit("Nothing to purge — no ClawSecCheck local store files found.")
        return 0

    if not args.yes:
        proceed, eof = _confirm_purge(existing)
        if not proceed:
            if eof:
                _emit("Purge aborted — no confirmation input available (not a tty / EOF).")
                return 1
            _emit("Purge aborted — no files were deleted.")
            return 0
    else:
        _emit("The following files will be permanently deleted:")
        for p in existing:
            _emit(f"  {p}")

    deleted = 0
    for p in existing:
        try:
            p.unlink()
            deleted += 1
        except OSError as exc:
            _emit(f"(could not delete {p}: {exc})")

    _emit(f"Purged {deleted} file(s) from {store_dir}.")
    return 0


# --- --apply-ignore-proposals: opt-in, confirmation-gated (C-253) --------------

def _confirm_apply_ignore(entries: "list[str]", ignore_path: Path) -> "tuple[bool, bool]":
    """Same (proceed, eof) contract as _confirm_purge — kept separate so tests can
    monkeypatch either confirmation independently."""
    _emit(f"The following entries will be appended to {ignore_path}:")
    for e in entries:
        _emit(f"  {e}")
    try:
        answer = input("Apply these judge-proposed suppressions? [y/N]: ")
    except EOFError:
        return False, True
    return answer.strip().lower() in ("y", "yes"), False


def _run_apply_ignore_proposals(args) -> int:
    """Apply a --propose-ignore output (opt-in, confirmation-gated, C-253).

    Reads the exact JSON --propose-ignore rendered and appends each proposal's
    ``entry`` fingerprint to <home>/.clawseccheckignore via baseline.append_entries.
    Never invents an entry beyond what that file already listed — this step can
    only mutate the SAME suppression mechanism baseline.py already implements, and
    every existing safety property (a suppressed score-capping CRITICAL/HIGH FAIL or
    a SENSITIVE_SUPPRESSED_IDS id still surfaces; any .clawseccheckignore change is
    still flagged by --monitor) is untouched by this being the write's origin.
    """
    try:
        raw = Path(args.apply_ignore_proposals).expanduser().read_text(encoding="utf-8")
    except OSError as exc:
        _emit(f"clawseccheck: could not read proposals file ({type(exc).__name__}).")
        return 1
    try:
        data = json.loads(raw)
    except ValueError:
        _emit("clawseccheck: proposals file is not valid JSON.")
        return 1
    proposals = data.get("proposedIgnoreEntries") if isinstance(data, dict) else None
    if not isinstance(proposals, list):
        _emit("clawseccheck: proposals file has no 'proposedIgnoreEntries' list — nothing to apply.")
        return 1
    # C-135 (2026-07-22): only ever apply something SHAPED like a real fingerprint()
    # output. A hand-crafted (not genuinely --propose-ignore-produced) proposals file
    # could otherwise carry a bare "entry": "B1"/"B2"/"B20" and suppress that id
    # file-wide via apply()'s bare-id match — exactly what this command's whole
    # premise ("only ever what --propose-ignore already offered") is meant to rule
    # out. A non-fingerprint entry is skipped and named, never silently dropped.
    entries: list = []
    rejected: list = []
    for p in proposals:
        if not (isinstance(p, dict) and isinstance(p.get("entry"), str)):
            continue
        candidate = p["entry"].strip()
        if not candidate:
            continue
        if is_fingerprint(candidate):
            entries.append(candidate)
        else:
            rejected.append(candidate)
    if rejected:
        _emit(
            "clawseccheck: ignoring "
            f"{len(rejected)} proposal entr{'y' if len(rejected) == 1 else 'ies'} not "
            f"shaped like a real fingerprint (refusing to apply): {', '.join(rejected)}"
        )
    if not entries:
        _emit("Nothing to apply — no proposed entries in that file.")
        return 0

    ignore_path = Path(args.home).expanduser() / ".clawseccheckignore"
    # B-478: `append_entries` skips entries the file already holds, so a second apply of
    # the same proposals printed the full list under "will be appended to ..." and then
    # "Applied 0" — which reads as a failed write, not as the idempotency it actually is.
    # Split the two here so the confirmation asks about what will really be written, and
    # the outcome line accounts for every entry. `written` below stays authoritative
    # (append_entries re-reads the file, so a concurrent edit is reflected there, not here).
    # Read the file ONCE: `load_ignore` inside the comprehension would re-read it per
    # entry, and would also compare different entries against different on-disk states.
    _existing = load_ignore(args.home)
    already = [e for e in entries if e in _existing]
    entries = [e for e in entries if e not in _existing]
    if not entries:
        _emit(f"Nothing to apply — all {len(already)} proposed "
              f"entr{'y is' if len(already) == 1 else 'ies are'} already in {ignore_path}.")
        return 0
    if not args.yes:
        proceed, eof = _confirm_apply_ignore(entries, ignore_path)
        if not proceed:
            if eof:
                _emit("Apply aborted — no confirmation input available (not a tty / EOF).")
                return 1
            _emit("Apply aborted — no entries were written.")
            return 0
    else:
        _emit(f"The following entries will be appended to {ignore_path}:")
        for e in entries:
            _emit(f"  {e}")

    try:
        written = append_entries(
            args.home, entries, comment=f"judge-proposed, applied {date.today().isoformat()}"
        )
    except OSError as exc:
        # C-135: append_entries writes via safeio.secure_append_text, which refuses
        # to follow a symlinked .clawseccheckignore (OSError/ELOOP) rather than
        # writing through it — surface that plainly instead of a generic crash.
        _emit(f"clawseccheck: could not write {ignore_path} ({type(exc).__name__}); nothing applied.")
        return 1
    tail = (f" ({len(already)} more were already present.)" if already else "")
    _emit(f"Applied {written} judge-proposed suppression(s) to {ignore_path}.{tail}")
    return 0


#: C-314: printed by both main() error arms below, and mirrored in
#: docs/TROUBLESHOOTING.md's "how to file a good report" section — keep in sync.
_ISSUES_URL = "https://github.com/gl0di/clawseccheck/issues"


def main(argv=None) -> int:
    """Thin top-level guard (B-101): never dump a raw traceback at users.

    Any unexpected error inside the audit/render pipeline becomes a clean one-line
    stderr message (stdout stays clean for --json/--sarif). The full traceback is
    shown only under --debug. KeyboardInterrupt / SystemExit propagate untouched —
    they derive from BaseException, not Exception. Only the exception *type* is
    named, never its message, so a path or config value can't leak (§8, B-076).

    ``ScanBudgetExceeded`` also derives from BaseException (B-352), so it needs its
    own arm to stay inside that no-raw-traceback contract. Reaching here at all means
    every designated per-check / per-target / phase handler failed to claim its own
    deadline, which should not happen by design — but "should not happen" is not
    "print a traceback at a user", so it degrades the same way: one line, and a
    NON-ZERO exit, because a run cut short mid-scan produced no verdict anyone may
    read as clean. It is reported separately from a crash rather than folded into the
    generic message, since a truncated scan and a bug are different things to a user.

    C-314: the Python-version check runs before anything else in this
    function — including the try/except below — because an unpacked (non-pip)
    install on Python <3.9 parses cleanly (no clean ImportError) but can fail later
    with a confusing runtime error; see docs/TROUBLESHOOTING.md.
    """
    if sys.version_info < (3, 9):
        print(
            "clawseccheck: needs Python 3.9+ (found "
            f"{sys.version_info[0]}.{sys.version_info[1]}); see "
            "docs/TROUBLESHOOTING.md for how to point the skill at a newer interpreter.",
            file=sys.stderr,
        )
        return 1
    try:
        return _main(argv)
    except ScanBudgetExceeded:
        raw = list(sys.argv[1:] if argv is None else argv)
        if "--debug" in raw:
            raise
        print(
            "clawseccheck: the scan was cut short by its own time budget and did not "
            "complete; no verdict from this run is reliable. Re-run with --debug for "
            "the traceback, or narrower (--fast, or a targeted --vet <path>). If this "
            f"keeps happening, see docs/TROUBLESHOOTING.md or open an issue: {_ISSUES_URL}",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:  # noqa: BLE001 — a security tool must fail readably, not crash
        raw = list(sys.argv[1:] if argv is None else argv)
        if "--debug" in raw:
            raise
        print(
            f"clawseccheck: unexpected internal error ({type(exc).__name__}); "
            "re-run with --debug for the traceback. If this keeps happening, see "
            f"docs/TROUBLESHOOTING.md or open an issue: {_ISSUES_URL}",
            file=sys.stderr,
        )
        return 1


_JUDGED_BUNDLE_CACHE: dict = {}


def _judged_bundle(path: str) -> dict:
    """``pipeline.read_judged_bundle`` memoized for the duration of ONE run.

    B-476: ``--judged-bundle -`` reads stdin, and stdin can be consumed exactly once —
    but the bundle already had two independent readers (``_resolve_runtime_caps`` and
    the --trend/--monitor cap helper), and B-476 added a third (the ``attestation``
    bucket, which must be resolved BEFORE ``audit()`` so B43/B44 can see it). Whoever
    read second got an empty document and silently lost every bucket. Caching also
    removes the pre-existing redundant re-read of a bundle FILE on the branches that
    call both helpers.

    Cleared at the top of every ``_main`` so an in-process second run (the whole test
    suite, and any library caller) never inherits the previous run's bundle."""
    if path not in _JUDGED_BUNDLE_CACHE:
        _JUDGED_BUNDLE_CACHE[path] = _pipeline.read_judged_bundle(path)
    return _JUDGED_BUNDLE_CACHE[path]


def _main(argv=None) -> int:
    _JUDGED_BUNDLE_CACHE.clear()
    p = argparse.ArgumentParser(
        prog="clawseccheck",
        description=(
            "ClawSecCheck OpenClaw security self-audit — read-only with respect to your "
            "OpenClaw config; see --apply-ignore-proposals below for the one named exception."
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__} ({__released__})",
                   help="print version and exit")
    p.add_argument("--home", default="~/.openclaw", help="OpenClaw home dir (default: ~/.openclaw)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--card", action="store_true", help="print only the shareable badge")
    p.add_argument("--functions", action="store_true",
                   help="print the full capability palette (everything the skill can do, "
                        "as speakable prompts) and exit — Screen 12, reached from the menu")
    p.add_argument("--menu", action="store_true",
                   help="print the capability menu (the guided Welcome screen) and exit")
    p.add_argument("--ascii", action="store_true", help="ASCII-only output (no unicode icons/box)")
    p.add_argument("--no-color", action="store_true",
                   help="disable ANSI colour (also honoured via the NO_COLOR env var; "
                        "colour is auto-off when output is not a terminal)")
    p.add_argument("--no-native", action="store_true",
                   help="do not also run the built-in `openclaw security audit`")
    p.add_argument("--no-host", action="store_true",
                   help="skip host-monitor detection (IDS / audit / FIM / EDR / firewall posture)")
    p.add_argument("--no-sockets", action="store_true",
                   help="skip the effective-bind socket scan (B340: corroborates gateway.bind "
                        "against /proc/net/tcp{,6}, plus a read-only /proc/*/fd walk for "
                        "process-identity correlation)")
    p.add_argument("--no-deptree", action="store_true",
                   help="skip the OpenClaw dependency-tree walk (B349: a package in "
                        "node_modules whose install-time target — a lifecycle hook or a "
                        "binding.gyp command-expansion — carries a code-execution signal). "
                        "The walk is read-only and offline, but traverses the whole installed "
                        "tree, so this is the escape hatch on a very large one")
    p.add_argument("--save", metavar="PATH", help="also write the report to a file")
    p.add_argument("--monitor", action="store_true",
                   help="monitor mode: alert on what changed since the last check")
    p.add_argument("--state", default=DEFAULT_STATE, metavar="PATH",
                   help=f"snapshot file for --monitor (default: {DEFAULT_STATE})")
    p.add_argument("--events", default=DEFAULT_EVENTS, metavar="PATH",
                   help=f"Agent Watch event journal, read by --watch-log/--incident and "
                        f"written by --monitor (default: {DEFAULT_EVENTS})")
    p.add_argument("--watch-log", action="store_true",
                   help="print the Agent Watch event journal (timeline of what changed)")
    p.add_argument("--vet", metavar="TARGET",
                   help="vet a skill / plugin / MCP target BEFORE installing it — the type is "
                        "autodetected by content (explicit flags below force an engine)")
    p.add_argument("--vet-skill", metavar="PATH", dest="vet_skill",
                   help="vet a skill (dir or SKILL.md) for malware BEFORE installing it")
    p.add_argument("--vet-plugin", metavar="PATH", dest="vet_plugin",
                   help="vet an OpenClaw plugin (root dir or openclaw.plugin.json) "
                        "BEFORE installing it")
    p.add_argument("--vet-mcp", nargs="?", const="", metavar="NAME|FILE",
                   help="vet configured MCP servers (or a NAME/FILE) for supply-chain risk before trusting them")
    p.add_argument("--vet-source", metavar="SLUG|URL|PKG", dest="vet_source",
                   help="pre-download reputation gate: vet the identity of a source (IOC / typosquat / "
                        "host heuristics) BEFORE fetching anything — zero network, bundled catalogs")
    p.add_argument("--vet-all", "--recursive", action="store_true", dest="vet_all",
                   help="vet every installed skill across all discovered skill roots "
                        "(~/.openclaw/skills, workspace/skills, …) — one verdict per skill + aggregate")
    p.add_argument("--advise", metavar="PATH", dest="advise",
                   help="INSTALL / CAUTION / DO-NOT-INSTALL recommendation for a quarantined "
                        "skill or plugin (dir autodetected same as --vet), with reasons + a "
                        "cleanup command — pairs with --vet-plan")
    p.add_argument("--vet-plan", metavar="SLUG|URL|PKG", dest="vet_plan",
                   help="print the zero-network fetch+isolate+advise+cleanup commands for "
                        "vetting a source before installing it (the tool never touches the "
                        "network — you or your agent run these commands)")
    p.add_argument("--incident", action="store_true",
                   help="print a local, read-only incident-response evidence pack: findings "
                        "snapshot, skill/MCP hashes (--sbom), trajectory-sidecar hashes, the "
                        "credential rotation list, and monitor event history from --events "
                        "(recorded in the pack as monitor_events_source) — never rotates "
                        "or deletes anything itself")
    p.add_argument("--analyze-trajectory", nargs="?", const="", default=None, metavar="PATH",
                   dest="analyze_trajectory",
                   help="post-hoc incident analysis: correlate installed skills' credential / "
                        "exfil / secret-path indicators against tool.call arguments in OpenClaw "
                        "trajectory sidecars (agents/*/sessions/*.trajectory.jsonl) to see if a "
                        "skill's instruction was actually acted on at runtime. Read-only; reads "
                        "data.arguments only in memory to test known indicators, never echoes "
                        "raw args. Optional PATH to one .trajectory.jsonl; default scans the home")
    p.add_argument("--behavioral", nargs="?", const="", default=None, metavar="PATH",
                   dest="behavioral",
                   help="behavioral trajectory audit: reconstruct observed tool-call SEQUENCES "
                        "from OpenClaw trajectory sidecars (agents/*/sessions/*.trajectory.jsonl) "
                        "and flag a proven-by-log behavioral trifecta (T1: ingress -> sensitive "
                        "-> egress verb order) or an outcome anomaly (T2: repeated failure then "
                        "success on a sensitive verb). Read-only, metadata-only — never reads "
                        "call/return payloads, only verb identity and sequencing. WARN-only, "
                        "never scored. Optional PATH to one .trajectory.jsonl; default scans "
                        "the home")
    p.add_argument("--emit-manifest", action="store_true", dest="emit_manifest",
                   help="print a proposed permission manifest (YAML-shaped) derived from "
                        "static effect analysis; use with --vet/--vet-skill on a single skill")
    p.add_argument("--vet-judge-packet", action="store_true", dest="vet_judge_packet",
                   help="use with --vet/--vet-skill/--vet-plugin: print the vetted "
                        "target's own borderline findings as JSON for a host-agent judge "
                        "— never changes the vet verdict")
    p.add_argument("--vet-judged", metavar="PATH", dest="vet_judged",
                   help="use with --vet/--vet-skill/--vet-plugin: feed back a host-agent "
                        "judge panel's verdicts for a prior --vet-judge-packet — the judge "
                        "may only ESCALATE a finding (never lower one) since this is "
                        "untrusted third-party content, not the user's own config; "
                        "use '-' to read from stdin")
    p.add_argument("--canary", action="store_true",
                   help="active prompt-injection canary self-test")
    p.add_argument("--redteam", action="store_true",
                   help="print a live red-team payload suite for adversarial self-testing")
    p.add_argument("--seed", default=None, metavar="VALUE",
                   # B-475: this reached make_suite only, so `--seed X --self-test` gave
                   # reproducible red-team tokens and freshly random canary/dry-run/
                   # multi-turn ones in the same output — three of the four harnesses
                   # silently ignored it, though all four have taken a seed all along.
                   help="fixed seed for the self-test harness tokens — --canary, "
                        "--redteam, --dryrun, --multiturn and the --self-test/--full "
                        "sections that render them (reproducible CI runs, and the seed a "
                        "--judged-bundle liveTest verdict must carry to be eligible for "
                        "history/trend); default is a fresh random seed each run")
    p.add_argument("--dryrun", action="store_true",
                   help="print a behavioral dry-run harness (prompt-injection self-test across all sources)")
    p.add_argument("--multiturn", action="store_true",
                   help="print a two-phase multi-turn taint harness (plant a poisoned rule, "
                        "then trigger it in a later turn)")
    p.add_argument("--self-test", action="store_true",
                   # B-480: this named three of the four harnesses it renders — the
                   # multi-turn plant/trigger harness has always been in this mode's
                   # output and was missing from its own description.
                   help="render all four self-test harnesses together: canary + live "
                        "red-team + dry-run + multi-turn (use --seed for reproducible "
                        "tokens)")
    p.add_argument("--full", action="store_true",
                   # B-480: "extra sections skipped in --json / --card" was half wrong.
                   # --json runs the whole pipeline and merges its output as additional
                   # top-level keys (judgePacket, coveragePage, phases, vetPackets, ...);
                   # only --card drops them. Telling a CI user their --json run skips the
                   # deep phases misdescribes both its cost and its content.
                   help="run audit + self-test + vet-mcp + the deep phases in one command "
                        "(self-test emits deterministic test material only, does not "
                        "attack; --json delivers the extra sections as additional keys "
                        "rather than printed blocks, --card drops them)")
    p.add_argument("--quiet", action="store_true",
                   help="only with --full: collapse the appended self-test and vet-mcp "
                        "sections to one-line summaries (lighter for CI logs / scroll); the "
                        "full detail stays available via --self-test / --vet-mcp")
    p.add_argument("--fast", action="store_true",
                   help="only with --full: skip the deep phases (installed-skill sweep, "
                        "installed-plugin sweep, behavioural/trajectory replay) and run "
                        "only the audit + self-test + vet-mcp sections — this is today's "
                        "--full shape, for CI runs the deep phases are too slow for. The "
                        "judge packet is still emitted; it re-runs no check and is free")
    p.add_argument("--exhaustive", action="store_true",
                   help="F-164: raise the trajectory-file / log-sink / per-line scan caps "
                        "instead of today's interactive-fast defaults, and scan the full "
                        "byte range of over-length log lines via overlapping windows instead "
                        "of only their head/tail. Applies to B164/B180, which run on every "
                        "audit (not only --full) — so this has effect with or without --full. "
                        "The per-check and whole-audit wall-clock budgets are raised in the "
                        "same step so a wider scan cannot degrade a check into a capped "
                        "UNKNOWN. Slower; use when a normal run flagged something suspicious "
                        "and you want maximum coverage")
    p.add_argument("--judged-bundle", metavar="PATH", dest="judged_bundle",
                   help="only with --full: feed back one file holding a host-agent judge's "
                        "answers to a prior '--full --json' packet — an 'attestation' "
                        "object, a 'judged' verdicts object for your own config (advisory: "
                        "the grade and findings stay unchanged), a 'vetJudged' array of "
                        "per-target verdicts for swept content (which may only ESCALATE a "
                        "finding, never lower one), and a 'liveTest' object carrying a "
                        "canary/dryrun/redteam/multiturn VULNERABLE|RESISTANT verdict (only "
                        "VULNERABLE ever caps the grade; a seeded 'seed' makes the verdict "
                        "reproducible and eligible for history/trend); use '-' to read from stdin")
    p.add_argument("--ask", action="store_true",
                   help="emit an attestation template (JSON) for the agent to self-report "
                        "facts the config can't show; fill it, then pass --attest")
    p.add_argument("--attest", metavar="PATH",
                   help="enrich the audit with an agent self-report JSON (enables B43/B44); "
                        "use '-' to read the JSON from stdin")
    p.add_argument("--badge", metavar="PATH", help="write a shareable SVG badge to PATH")
    p.add_argument("--html", metavar="PATH", help="write a standalone HTML report to PATH")
    p.add_argument("--show-suppressed", action="store_true",
                   help="list suppressed finding ids + fingerprints and exit")
    p.add_argument("--verify-self", action="store_true",
                   help="print the SHA-256 digest of the ClawSecCheck engine source for tamper detection")
    p.add_argument("--sarif", metavar="PATH",
                   help="write a SARIF 2.1.0 report to PATH")
    p.add_argument("--pdf", metavar="PATH",
                   help="write the complete audit as a paginated PDF to PATH — attach the "
                        "file itself into chat (a mobile client opens it inline; do not "
                        "paste the path or re-render its contents)")
    # C-426: `--fail-under N` was REMOVED here, not deprecated-in-place. It thresholded
    # the audit SCORE, and under the five-layer rule a run only carries one when all
    # five layers ran — so for the ordinary invocation there was nothing left for it to
    # compare. The two honest alternatives were both worse than removal: silently
    # gating on the internal number the report withholds (a CI verdict the tool refuses
    # to publish), or always failing closed (identical practical breakage to removal,
    # while leaving a flag in `--help` that can never pass). `--fail-on` below is the
    # replacement and needs no score at all.
    p.add_argument("--fail-on", metavar="SEVERITY", choices=["critical", "high", "medium", "low"],
                   default=None,
                   help="exit 1 if any unsuppressed FAIL finding at or above SEVERITY exists "
                        "(critical/high/medium/low, ranked highest-first; 'high' also trips on "
                        "a critical). Suppressed findings are excluded the same way --exit-code "
                        "excludes them (a suppressed score-capping CRITICAL/HIGH or sensitive-id "
                        "finding still counts). Gates on findings the way --exit-code does, at a "
                        "chosen severity floor instead of any FAIL")
    p.add_argument("--exit-code", action="store_true",
                   help="exit 1 if any unsuppressed FAIL finding exists")
    p.add_argument("--trend", action="store_true",
                   help="record this run to history, print trend + percentile, and exit")
    p.add_argument("--percentile", action="store_true",
                   help="print offline percentile rank for the current score and exit")
    p.add_argument("--history", default=DEFAULT_HISTORY, metavar="PATH",
                   help=f"path for trend history file (default: {DEFAULT_HISTORY})")
    p.add_argument("--no-history", action="store_true",
                   help="do not record this run to the local score history (default: record) "
                        "— has no effect under --trend/--monitor, which always record one "
                        "regardless (a stderr note says so if combined)")
    p.add_argument("--verify-history", action="store_true",
                   help="verify the score history file's tamper-evident hash-chain and exit")
    p.add_argument("--verify-events", action="store_true",
                   help="verify the Agent Watch event journal's (--events) tamper-evident "
                        "hash-chain and exit — same check as --verify-history, run against "
                        "--events instead of --history")
    p.add_argument("--purge", action="store_true",
                   help="delete ClawSecCheck's local store (history/events/state/coverage "
                        "files + their lock sidecars) and exit — confirmation-gated unless "
                        "--yes is also given; nothing else is touched")
    p.add_argument("--apply-ignore-proposals", metavar="PATH", dest="apply_ignore_proposals",
                   help="apply a --propose-ignore output: append its proposed entries to "
                        "<home>/.clawseccheckignore — confirmation-gated unless --yes is also "
                        "given; never invents entries beyond what that file already proposed")
    p.add_argument("--yes", action="store_true",
                   help="skip the interactive confirmation prompt for --purge or "
                        "--apply-ignore-proposals (for scripted use); has no effect without "
                        "one of those two")
    p.add_argument("--no-update-notice", action="store_true",
                   help="suppress the offline 'your build may be stale' reminder "
                        "(also suppressible via CLAWSECCHECK_NO_UPDATE_NOTICE=1; offline, never a network call)")
    p.add_argument("--no-freshness-notice", action="store_true",
                   help="suppress the coverage-freshness reminder for opt-in tests and the "
                        "IOC dataset's own staleness and coverage-gap notices "
                        "(also suppressible via CLAWSECCHECK_NO_FRESHNESS_NOTICE=1; offline, never a network call)")
    p.add_argument("--next", action="store_true",
                   help="print recommended next actions based on the audit result")
    p.add_argument("--dashboard", action="store_true",
                   help="print the deterministic chat Dashboard card (grade + framed "
                        "findings, Sections 1-2, + a Skills block when any are installed) "
                        "and exit; add --full to render the WHOLE combined pipeline report "
                        "(Skills/Plugins/MCP vet, RISK chains, behavioural replay, "
                        "adjudication, coverage, worth-a-glance) in one fixed-order card "
                        "instead of --full's own separate appended sections (F-153)")
    p.add_argument("--compact", action="store_true",
                   help="only with --dashboard --full: a condensed, ~4096-char "
                        "Telegram-safe layout of the combined pipeline report — headline "
                        "counts only for Plugins/MCP/RISK chains, trimmed why-text/no "
                        "evidence bullets for Findings and Worth-a-glance (nothing "
                        "dropped, just condensed), plus a pointer to --save/--html for "
                        "the full detail (F-153; named --compact rather than the spec's "
                        "suggested --card, which already means the shareable "
                        "grade+score+trifecta badge above)")
    p.add_argument("--dashboard-findings", action="store_true",
                   help="print only the framed Section-2 Findings block for the chat Dashboard "
                        "(FAIL/WARN, high-confidence, grouped by family) and exit")
    p.add_argument("--risk-paths", action="store_true",
                   help="print only the highest-risk capability chains and exit")
    p.add_argument("--sbom", action="store_true",
                   help="export a local bill-of-materials (skills, MCP servers, hashes, "
                        "declared/unpinned deps) as deterministic JSON to stdout and exit")
    p.add_argument("--judge-packet", action="store_true", dest="judge_packet",
                   help="export the borderline finding band (UNKNOWN, FN-prone WARN, "
                        "B62, dropped taint) as JSON for a host-agent judge to review "
                        "— never changes the grade")
    p.add_argument("--judged", metavar="PATH", dest="judged",
                   help="feed back a host-agent judge panel's verdicts JSON for a prior "
                        "--judge-packet; renders the audit's UNCHANGED grade/findings plus "
                        "an advisory secondOpinion panel — use '-' to read from stdin")
    p.add_argument("--propose-ignore", metavar="PATH", dest="propose_ignore",
                   help="feed back a host-agent judge panel's verdicts JSON for a prior "
                        "--judge-packet; prints PROPOSED (not applied) .clawseccheckignore "
                        "entries for findings verdicted SAFE — use '-' to read from stdin, "
                        "then --apply-ignore-proposals to actually write them")
    p.add_argument("--verbose", action="store_true",
                   help="emit INFO-level log breadcrumbs to stderr")
    p.add_argument("--debug", action="store_true",
                   help="emit DEBUG-level log breadcrumbs to stderr")
    p.add_argument("--log", metavar="PATH", default=None,
                   help="also write INFO-level log output to PATH (only when given; "
                        "raises the FILE's level to INFO, never the console's — pass "
                        "--verbose/--debug for that)")
    args = p.parse_args(argv)

    # Surface (on stderr) any second mode flag or global modifier the resolved mode
    # won't honor, so nothing is dropped silently (B-066 / B-067). Warn-and-continue:
    # the cascade below is unchanged.
    for _note in _flag_coherence_notes(args):
        print(_note, file=sys.stderr)

    ascii_only = args.ascii or not _unicode_ok()
    # Colour is a terminal-only presentation layer: auto-off when piped/redirected,
    # always overridable by --no-color / NO_COLOR (see ansi.should_color). Saved reports
    # are stripped back to plain text below so files never carry escape codes.
    use_color = should_color(no_color_flag=args.no_color)

    # Set up safe logger early — level from --verbose/--debug; file only when --log given.
    logger = get_logger(
        verbose=getattr(args, "verbose", False),
        debug=getattr(args, "debug", False),
        logfile=getattr(args, "log", None),
    )

    # standalone modes that don't audit ~/.openclaw
    if args.purge:
        # Dispatched FIRST, before any audit()/history-record call-site below, so
        # purge can never race its own uninstall by writing a fresh history point.
        return _run_purge(args)

    if args.apply_ignore_proposals:
        # C-253: like --purge, this only touches its own known file (.clawseccheckignore
        # under --home) and needs no audit() pass, so it is dispatched here too.
        return _run_apply_ignore_proposals(args)

    if args.verify_self:
        combined, per_file = package_digest()
        lines = [f"{WORDMARK} {__version__} — engine source digest (SHA-256)",
                 f"combined : {combined}",
                 ""]
        for name, digest in sorted(per_file.items()):
            lines.append(f"  {digest}  {name}")
        lines.append("")
        lines.append("Compare the 'combined' value against the digest printed by a trusted release.")
        lines.append("Any mismatch means a source file was modified after that release.")
        lines.append(f"Trusted digest: see SHA256SUMS.txt on the v{__version__} GitHub Release, signed via cosign.")
        lines.append("")
        lines.append("A checksum you just read off a web page or a chat reply proves nothing by")
        lines.append("itself — it could be tampered with too. Verify the cosign signature instead")
        lines.append("(after downloading SHA256SUMS.txt and SHA256SUMS.txt.bundle from that Release):")
        lines.append("")
        lines.append("  cosign verify-blob \\")
        lines.append("    --bundle SHA256SUMS.txt.bundle \\")
        lines.append('    --certificate-identity-regexp "^https://github.com/gl0di/clawseccheck/" \\')
        lines.append("    --certificate-oidc-issuer https://token.actions.githubusercontent.com \\")
        lines.append("    SHA256SUMS.txt")
        _emit("\n".join(lines))
        return 0

    if args.verify_history:
        ok, msg = history_verify(args.history)
        if ok:
            _emit(f"History chain OK ({args.history}): {msg}")
            return 0
        _emit(f"History chain BROKEN ({args.history}): {msg}")
        return 1

    if args.verify_events:
        # C-250(c): --verify-history --history <events-path> already verified an events
        # journal correctly (verify_chain() is the same entry-agnostic algorithm for both
        # journals — see history.verify()'s own docstring), but its output always said
        # "History chain" regardless of which journal was actually named. This is the
        # discoverable, correctly-worded entry point --events users were missing.
        ok, msg = verify_chain(args.events)
        if ok:
            _emit(f"Events chain OK ({args.events}): {msg}")
            return 0
        _emit(f"Events chain BROKEN ({args.events}): {msg}")
        return 1

    if getattr(args, "vet_plan", None):
        # F-065: zero-network plan emitter — prints commands, touches nothing itself.
        _emit(render_vet_plan(args.vet_plan))
        return 0

    if args.menu:
        # The guided Welcome screen as a runnable command. Read-only: reads local
        # score history for the "last check" nudge and the offline staleness hint;
        # no network, no writes, no record_run().
        rows = history_load(args.history)
        last_check = rows[-1]["date"] if rows else None
        build_age, last_days = compute_ages(released=__released__, last_check=last_check)
        stale = bool(update_notice(__version__, released=__released__))
        _emit(render_menu(version=__version__, build_age_days=build_age,
                          last_check_days=last_days, stale=stale, ascii_only=ascii_only))
        return 0

    if args.functions:
        # Screen 12 — the full capability palette (Welcome's "menu"/item 4 expands here).
        # Read-only: no scan, no network, no writes — just the grounded capability list.
        from .checks import CHECKS  # noqa: PLC0415
        _emit(render_palette(n_checks=len(CHECKS), ascii_only=ascii_only))
        return 0

    # F-072 (D1): --vet autodetects the artifact type by content and routes to the
    # right engine; --vet-skill / --vet-plugin / --vet-mcp are the explicit escape
    # hatches. The detected-type note goes to stderr so machine stdout stays clean.
    # B-466: an EMPTY target ("--vet ''") used to be falsy here, so the vet dispatch was
    # skipped entirely and the run fell through to a full audit of the local machine —
    # printing a normal grade and exiting 0. The user asked to vet something and got a
    # verdict about something else, with nothing saying so.
    #
    # `--vet-mcp` is deliberately absent from this list: it is declared nargs="?" const="",
    # so an empty value is its documented "every configured MCP server" form.
    _empty_target = [
        flag for flag, attr in (
            ("--vet", "vet"), ("--vet-skill", "vet_skill"), ("--vet-plugin", "vet_plugin"),
            ("--vet-source", "vet_source"), ("--advise", "advise"),
        )
        if getattr(args, attr, None) is not None and not str(getattr(args, attr)).strip()
    ]
    if _empty_target:
        print(f"{_empty_target[0]} needs a target — got an empty value. "
              "Pass a path, slug, or URL.", file=sys.stderr)
        return 2

    _vet_route = None  # (kind, target) with kind in {"skill", "plugin", "mcp"}
    if args.vet:
        detected = detect_vet_type(args.vet, home=args.home)
        print(f"detected type: {detected}", file=sys.stderr)
        # 'unknown' routes to the skill engine, which answers with an honest UNKNOWN —
        # exactly today's --vet behavior for a non-skill target (never a guessed PASS).
        _vet_route = (detected if detected in ("plugin", "mcp") else "skill", args.vet)
    elif getattr(args, "vet_skill", None):
        _vet_route = ("skill", args.vet_skill)
    elif getattr(args, "vet_plugin", None):
        _vet_route = ("plugin", args.vet_plugin)

    if args.emit_manifest and not (_vet_route and _vet_route[0] == "skill"):
        print(
            "note: --emit-manifest requires --vet/--vet-skill on a single skill; ignored",
            file=sys.stderr,
        )
    if (args.vet_judge_packet or args.vet_judged) and not (
        _vet_route and _vet_route[0] in ("skill", "plugin")
    ):
        print(
            "note: --vet-judge-packet/--vet-judged require --vet/--vet-skill/--vet-plugin "
            "on a single skill or plugin; ignored",
            file=sys.stderr,
        )

    if _vet_route and _vet_route[0] in ("skill", "plugin"):
        vet_kind, vet_path = _vet_route
        # B-460: a SKILL.md target resolves to the skill DIRECTORY that contains it. Relabel
        # here too, from the same helper the engine uses, so the dossier names what was
        # actually scanned rather than what was typed (it read "skill 'SKILL.md'" before).
        if vet_kind == "skill":
            vet_path = str(resolve_skill_target(vet_path))
        vet_target = Path(vet_path).expanduser()
        f = vet_skill(vet_path) if vet_kind == "skill" else vet_plugin(vet_path)
        # C-254: use with --vet/--vet-skill/--vet-plugin only (checked above) — a
        # distinct stdout artifact, same pattern as --emit-manifest below.
        if args.vet_judge_packet:
            _emit(render_vet_judge_packet_json(f, target=vet_path, version=__version__))
            return 0
        if args.vet_judged:
            if args.vet_judged == "-":
                verdicts_raw = sys.stdin.read()
            else:
                try:
                    verdicts_raw = Path(args.vet_judged).expanduser().read_text(encoding="utf-8")
                except OSError:
                    verdicts_raw = ""
            # Escalate-only: rebuild f's ring_findings so a borderline finding can only
            # rank higher, never lower, than the deterministic engine already ranked it
            # (adjudication._escalated_status). build_profile below is UNCHANGED —
            # it re-derives overall_status/score/grade from this pool the normal way.
            f = escalate_vet_output(f, verdicts_raw, target=vet_path)
        profile = build_profile(f, vet_path, vet_kind)
        # rc: overall FAIL/WARN → 1 (dangerous/suspicious target);
        # UNKNOWN + target absent (not found / path unusable) → 1;
        # UNKNOWN + target exists (valid target, inconclusive assessment) → 0;
        # PASS → 0.
        if profile.overall_status in ("FAIL", "WARN"):
            _vet_rc = 1
        elif profile.overall_status == "UNKNOWN" and not vet_target.exists():
            _vet_rc = 1
        else:
            _vet_rc = 0
        # --emit-manifest: a stdout side output, single-skill vet only (B98/F-083).
        # Never runs the normal dossier/JSON render below — this is a distinct artifact.
        if args.emit_manifest and vet_kind == "skill":
            _emit(render_permission_manifest(getattr(f, "ctx", None), vet_path))
            return _vet_rc
        # Record the run in the coverage ledger, symmetric with --vet-mcp (C-128).
        # freshness_notice has no "vet" threshold, so this updates the ledger without
        # adding a staleness nudge — it just keeps the vet modes consistent.
        _record_run("vet" if vet_kind == "skill" else "vet_plugin", args)
        # Side output: SARIF file (mirrors the full-audit --sarif behavior, incl.
        # the same graceful handling of an unwritable path — B-014).
        if args.sarif:
            try:
                secure_write_text(
                    Path(args.sarif).expanduser(),
                    render_sarif([f, *getattr(f, "ring_findings", [])],
                                 tool_version=__version__, ctx=getattr(f, "ctx", None),
                                 profile=profile),
                )
                _emit(f"(SARIF written to {args.sarif})")
            except OSError as exc:
                _emit(f"(could not write SARIF: {exc})")
        # Primary output: machine-readable JSON dossier, else the human dossier.
        if args.json:
            _emit(render_vet_json(profile,
                                  mode="vet" if vet_kind == "skill" else "vet-plugin",
                                  version=__version__))
            return _vet_rc
        _emit(render_vet_dossier(profile, ascii_only=ascii_only))
        return _vet_rc

    if _vet_route and _vet_route[0] == "mcp":
        # --vet routed to the MCP engine: mode "vet" keeps its table precedence
        # (above --vet-all), so the shared renderer runs here, not further below.
        return _run_vet_mcp(_vet_route[1], args, ascii_only)

    if args.vet_all:
        home_dir = Path(args.home).expanduser()
        return vet_all(home_dir, ascii_only=ascii_only)

    if args.vet_mcp is not None:
        return _run_vet_mcp(args.vet_mcp if args.vet_mcp else None, args, ascii_only)

    if getattr(args, "vet_source", None):
        # F-073: pre-download reputation gate — identity only, zero network, no fetch.
        f = vet_source(args.vet_source)
        profile = build_profile(f, args.vet_source, "source")
        _src_rc = 1 if profile.overall_status in ("FAIL", "WARN") else 0
        _record_run("vet_source", args)
        # B-385: the IOC dataset's own staleness advisory is renderer-only — it never
        # enters `f`/`profile`/Finding.evidence (see checks/_vet.py's vet_source), so it
        # cannot drift a fingerprint or make --json output change day to day. Printed to
        # STDERR only: it is presentation metadata about the audit tool's own dataset,
        # not part of either the human dossier's or --json's result payload. Reuses
        # --no-freshness-notice — the same opt-out the config-age notice already uses.
        if not args.no_freshness_notice and not os.environ.get("CLAWSECCHECK_NO_FRESHNESS_NOTICE"):
            for _line in _iocdb_freshness_notice() + _iocdb_coverage_notice():
                print(_line, file=sys.stderr)
        if args.json:
            _emit(render_vet_json(profile, mode="vet-source", version=__version__))
            return _src_rc
        _emit(render_vet_dossier(profile, ascii_only=ascii_only))
        return _src_rc

    if getattr(args, "advise", None):
        # F-067: same vet engines/profile as --vet, reframed as an install decision.
        advise_target = args.advise
        detected = detect_vet_type(advise_target, home=args.home)
        print(f"detected type: {detected}", file=sys.stderr)
        advise_kind = detected if detected in ("plugin",) else "skill"
        f = vet_skill(advise_target) if advise_kind == "skill" else vet_plugin(advise_target)
        profile = build_profile(f, advise_target, advise_kind)
        _advise_rc = 1 if profile.overall_status in ("FAIL", "WARN") else 0
        _record_run("vet" if advise_kind == "skill" else "vet_plugin", args)
        if args.json:
            _emit(render_advise_json(profile, version=__version__))
            return _advise_rc
        _emit(render_advise(profile, ascii_only=ascii_only))
        return _advise_rc

    if args.canary:
        _emit(render_canary(make_canary(args.seed), ascii_only))
        _record_run("self_test", args)
        return 0

    if args.redteam:
        seed = args.seed if args.seed is not None else secrets.token_hex(8)
        _emit(render_suite(make_suite(seed), ascii_only, seed=seed))
        _record_run("self_test", args)
        return 0

    if args.dryrun:
        _emit(render_dryrun(make_scenarios(args.seed), ascii_only))
        _record_run("self_test", args)
        return 0

    if args.multiturn:
        _emit(render_multiturn(make_multiturn(args.seed), ascii_only))
        _record_run("self_test", args)
        return 0

    if args.self_test:
        seed = args.seed if args.seed is not None else secrets.token_hex(8)
        _emit(render_canary(make_canary(args.seed), ascii_only))
        _emit("")
        _emit(render_suite(make_suite(seed), ascii_only, seed=seed))
        _emit("")
        _emit(render_dryrun(make_scenarios(args.seed), ascii_only))
        _emit("")
        _emit(render_multiturn(make_multiturn(args.seed), ascii_only))
        _record_run("self_test", args)
        return 0

    if args.ask:
        import json as _json  # noqa: PLC0415
        from . import attest as _attest  # noqa: PLC0415
        _emit(_json.dumps(_attest.template(), indent=2, ensure_ascii=False))
        return 0

    if args.show_suppressed:
        ignore = load_ignore(Path(args.home).expanduser())
        if not ignore:
            _emit("No .clawseccheckignore entries found.")
        else:
            _emit(f"{len(ignore)} entry/entries in .clawseccheckignore.")
            # B-379: match the real audit path's include_sockets, or B340's finding
            # detail differs here from a normal run (ctx.sockets is None => a
            # different "socket scan was not run" UNKNOWN text) — since
            # fingerprint() hashes the detail, a suppression captured from a real run
            # was silently never found here, and the reverse also held. F-164:
            # --exhaustive changes B164/B180's disclosure text the same way, so it
            # needs the same mirroring or an --exhaustive suppression stops matching
            # here.
            # B-474 (C-135 on B-474's own fix): include_host/include_native must be
            # mirrored too, for the reason B-379 already gave for include_sockets —
            # fingerprint() hashes the finding DETAIL, and a subsystem that did not run
            # here produces different detail text (or no finding at all) than it does on a
            # real run. Before this, a suppression captured from a normal run of a host
            # (B50-B54) or native (`openclaw security audit`) finding simply never matched
            # here. That was merely invisible while this command only listed matches; the
            # moment it began NAMING unmatched entries it would have become an active
            # false claim — "this entry matches nothing", about an entry that matches
            # perfectly well on every real run. Fidelity beats speed here, same call
            # B-379 made: the point of this command is to answer what IS suppressed.
            ctx, findings, _ = audit(args.home, include_native=not args.no_native,
                                     include_host=not args.no_host,
                                     include_sockets=not args.no_sockets,
                                     include_deptree=not args.no_deptree,
                                     exhaustive=args.exhaustive)
            suppressed = [f for f in findings if getattr(f, "suppressed", False)]
            # B-154: a bare "RISK-NN" entry matches a RiskPath.id, not any Finding —
            # surface those explicitly too, or --show-suppressed silently missed them.
            suppressed_risk = [p for p in _risk.risk_paths(ctx, findings, ignore=ignore)
                                if p.suppressed]
            # B-474: the headline counted ENTRIES IN THE FILE and the list below showed
            # MATCHED FINDINGS, so "3 suppressed entry/entries" printed above a single
            # line was routine — and the two entries that matched nothing were invisible
            # in the one command whose job is to show what is suppressed. A dead entry is
            # not cosmetic: it means the finding is gone (fixed) or its fingerprint has
            # drifted (the suppression silently stopped working and the finding is live
            # again). Both are things the owner of the file needs told.
            matched_entries: set[str] = set()
            for f in suppressed:
                matched_entries.update({f.id, fingerprint(f)} & ignore)
            for p in suppressed_risk:
                matched_entries.update({p.id} & ignore)
            dead = sorted(ignore - matched_entries)
            if suppressed or suppressed_risk:
                _emit(f"{len(suppressed) + len(suppressed_risk)} suppressed in this run:")
                for f in suppressed:
                    _emit(f"  {f.id}  {fingerprint(f)}  ({f.title})")
                for p in suppressed_risk:
                    _emit(f"  {p.id}  ({p.title})")
            if dead:
                _emit("")
                _emit(f"{len(dead)} entry/entries match nothing in this run — the finding "
                      "is either fixed, or its fingerprint changed and the suppression is "
                      "no longer in effect:")
                for entry in dead:
                    _emit(f"  {entry}")
        return 0

    if args.watch_log:
        _emit(render_events(load_events(args.events), ascii_only))
        return 0

    # B-476: read the bundle's attestation bucket at most once — `--judged-bundle -` reads
    # stdin, and stdin can only be consumed once.
    _bundle_att = None
    if args.full and args.judged_bundle is not None and args.attest != "-":
        _bundle_att = _judged_bundle(args.judged_bundle).get("attestation")

    attestation = None
    if args.attest:
        from . import attest as _attest  # noqa: PLC0415
        if args.attest == "-":
            attestation = _attest.parse_attestation(sys.stdin.read())
            src = "stdin"
        else:
            attestation = _attest.load_attestation(Path(args.attest).expanduser())
            src = args.attest
        if not attestation:
            # Diagnostic, not report content: keep machine-readable stdout (--json/--sarif)
            # clean — a stdout warning here corrupts `--attest bad.json --json` (B-070).
            print(f"⚠ could not read a valid attestation from {src} "
                  "(ignored; B43/B44 stay UNKNOWN). See 'clawseccheck --ask'.",
                  file=sys.stderr)
    elif args.full and args.judged_bundle is not None:
        # B-476: --judged-bundle's own --help promises four buckets, and
        # `split_judged_bundle` has always parsed all four — but nothing in the codebase
        # ever read the `attestation` one. An agent that answered the judge packet by
        # filling in the attestation object alongside its verdicts got B43/B44 left at
        # UNKNOWN with no indication its answers had been dropped: a documented input,
        # silently discarded. Routed through the SAME parse_attestation() the --attest
        # file path uses, so an invalid object degrades identically rather than being
        # trusted because it arrived by a different door.
        #
        # Gated on --full to match the flag's documented "only with --full" contract and
        # `_resolve_runtime_caps`'s own gate — a bucket honored where the flag itself is
        # reported as having no effect would be a new incoherence, not a fix for one.
        # --attest wins when both are given (an explicit flag beats an embedded bucket),
        # which is why this is `elif`; the note below says so rather than dropping it
        # silently.
        from . import attest as _attest  # noqa: PLC0415
        if _bundle_att is not None:
            attestation = _attest.parse_attestation(_bundle_att)
            if not attestation:
                print("⚠ the --judged-bundle 'attestation' object is not a valid "
                      "attestation (ignored; B43/B44 stay UNKNOWN). "
                      "See 'clawseccheck --ask'.", file=sys.stderr)
    if args.attest and _bundle_att is not None:
        print("note: --attest was given, so the --judged-bundle 'attestation' object "
              "was not used.", file=sys.stderr)

    # First-run onboarding (Screen 13): when there is genuinely nothing to audit —
    # ~/.openclaw missing, or an empty directory — don't render a wall of UNKNOWNs;
    # show a friendly "point me at your config" screen. BARE human runs only: any
    # machine/CI/artifact/work flag (--json/--card, --fail-on/--exit-code,
    # --save, --full, --badge/--html/--sarif, --attest, or any primary mode) takes the
    # normal audit path so nothing is silently dropped and CI gates keep failing loud
    # (B-075). Checked BEFORE audit() so a missing home never burns a scan or the
    # native-audit subprocess just to print a welcome.
    #
    # I3/C-426: `--fail-on` is a machine gate and belongs in this guard for the same
    # reason `--exit-code` does — without it a lone `--fail-on critical` against a
    # genuinely-empty home would print the friendly onboarding screen and exit 0
    # instead of taking the audit path a CI script asked for. (`--fail-under` was here
    # on identical terms until C-426 removed the flag.)
    _bare_run = (
        not any(_mode_active(args, a, k) for a, _f, k in _PRIMARY_MODES)
        and not args.json and not args.card and not args.save and not args.full
        and args.fail_on is None
        and not args.exit_code and not args.attest
    )
    if _bare_run:
        first_run = _onboarding_reason(Path(args.home).expanduser())
        if first_run:
            from .checks import CHECKS  # noqa: PLC0415
            _emit(render_onboarding(reason=first_run, home=_sanitize(args.home),
                                    n_checks=len(CHECKS), ascii_only=ascii_only))
            return 0

    logger.info("auditing home=%s", args.home)
    # A home that exists but can't be read at all must be a controlled, honest outcome
    # for a security tool — a plain-language error, never a raw traceback (B-076).
    try:
        ctx, findings, score = audit(args.home, include_native=not args.no_native,
                                     include_host=not args.no_host,
                                     include_sockets=not args.no_sockets,
                                     include_deptree=not args.no_deptree,
                                     attestation=attestation,
                                     exhaustive=args.exhaustive)
    except (PermissionError, OSError) as exc:
        _emit(f"Cannot read the OpenClaw home at {_sanitize(args.home)}: {_sanitize(str(exc))}")
        _emit("Fix the permissions (or run as the owning user) and re-run the audit.")
        return 1
    # B-464: record which subsystems the OPERATOR opted out of, so the score rationale can
    # disclose that its denominator was narrowed. Set here, from the parsed flags, because
    # ctx.include_host/native default to "off" and cannot tell an explicit opt-out from an
    # ordinary library audit() call.
    ctx.cli_opt_outs = tuple(
        flag for flag, passed in (
            ("--no-host", args.no_host),
            ("--no-native", args.no_native),
            ("--no-sockets", args.no_sockets),
            ("--no-deptree", args.no_deptree),
        ) if passed
    )
    # C-426: every downstream mode below (`--badge`, `--html`, `--sarif`, `--pdf`,
    # `--risk-paths`, `--dashboard` without `--full`, the default report/--json, and
    # — via `_apply_live_test_cap`'s own matching change — `--trend`/`--monitor`/
    # `--percentile`/`--next`) takes its `score` from THIS `audit()` call, so
    # building the bare five-layer ledger here, once, means every one of them
    # inherits the correct "graded" answer with no per-mode plumbing. No phases are
    # committed at this point (`commit_full_phases` stays False — see
    # `_build_layer_ledger`'s own docstring for why a bare/early call must never
    # optimistically claim the sweep or behavioral replay ran): under `--full`,
    # `_resolve_runtime_caps` below builds the richer, phase-aware ledger later and
    # recomputes `score` again — that recompute wins (C-422: a COMPLETE ledger is
    # byte-identical to omitting one, so this is a no-op there once every layer
    # genuinely ran). No live-test bucket is known yet this early (`--judged-bundle`
    # is read by `_resolve_runtime_caps`/`_apply_live_test_cap`, further down), so
    # layer 5 starts `unavailable` here — exactly right for a run that has not yet
    # resolved one.
    _bare_ledger = _build_layer_ledger(
        args, findings, degraded_count=score.degraded_count, attestation=attestation,
    )
    score = compute(findings, ctx, ledger=_bare_ledger)
    logger.debug("ran %d checks", len(findings))
    logger.info("score=%s grade=%s", score.score, score.grade)

    # B-154: RISK-* chains must honor .clawseccheckignore too — pass the same
    # ignore set findings were suppressed with, then drop suppressed chains
    # before they reach any render/JSON path.
    _risk_ignore = load_ignore(Path(args.home).expanduser())
    paths = [p for p in _risk.risk_paths(ctx, findings, ignore=_risk_ignore)
             if not p.suppressed]

    if args.risk_paths:
        _emit(_risk.render_risk_paths(paths, ascii_only=ascii_only))
        return 0

    def _report_dest(raw: str) -> Path:
        """Resolve a user-requested report path, creating its directory if it is missing.

        B-459: SKILL.md's guided flow hardcodes ``--pdf ~/.clawseccheck/report.pdf``, but
        none of the commands that precede it create ``~/.clawseccheck`` — so on a first run
        the very command the docs tell the host agent to run died with ENOENT from
        ``mkstemp``, and (because the card had already been collapsed in anticipation of the
        attachment) the whole audit was discarded: 118 bytes of stdout, exit 1, no grade and
        no findings. Every first-time user hit that.

        Only a directory we create ourselves is touched, and it is created 0700 because a
        report carries the user's audit detail. A parent that already exists is left exactly
        as it is — ``secure_dir`` would ``chmod 0700`` it, which for a shared parent like
        ``/tmp`` (``--pdf /tmp/report.pdf``) would be a destructive surprise well outside
        what this tool is allowed to do to the user's machine.
        """
        p = Path(raw).expanduser()
        parent = p.parent
        if not parent.exists():
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        return p

    if args.badge:
        try:
            secure_write_text(_report_dest(args.badge), render_svg(score, findings))
            _emit(
                f"(badge written to {args.badge} — attach this SVG file as-is; "
                "do not redraw, rasterize, or generate your own badge image)"
            )
            return 0
        except OSError as exc:
            _emit(f"(could not write badge: {exc})")
            return 1

    if args.html:
        try:
            secure_write_text(
                _report_dest(args.html),
                render_html(findings, score, native=ctx.native, ctx=ctx),
            )
            _emit(f"(HTML report written to {args.html})")
            return 0
        except OSError as exc:
            _emit(f"(could not write HTML report: {exc})")
            return 1

    if args.sarif:
        try:
            secure_write_text(_report_dest(args.sarif), render_sarif(findings, score, __version__, ctx=ctx))
            _emit(f"(SARIF written to {args.sarif})")
            return 0
        except OSError as exc:
            _emit(f"(could not write SARIF: {exc})")
            return 1

    # C-373: `--dashboard --pdf <path>` is the chat delivery PAIR — the card is the
    # message that fits, the PDF is the attachment carrying every finding with its why
    # and evidence. When both are asked for, write the file here and fall through to the
    # dashboard branch (which points the card at this exact path) instead of returning;
    # `--pdf` on its own keeps its pre-existing standalone behaviour, byte-identical.
    pdf_written = None

    def _emit_attach_instruction(path):
        """B-468: tell the HOST AGENT what to do with the report — on stderr.

        stdout is the card the agent pastes verbatim into a chat, so an instruction
        addressed to the agent must not sit inside it. That contradiction is not
        theoretical: in a real session the agent, handed "attach this file" inside text it
        had been ordered to reproduce word for word, resolved it by sending the user a
        link — twice — before ever attaching anything. ClawSecCheck is local-only (Golden
        Rule #1): there is no URL, only a file to send.
        """
        if not path:
            return
        print(f"note: report written to {path} — attach this PDF file itself into the "
              "chat. Do not paste its path, do not send a link (there is none — the tool "
              "is local-only), and do not re-render its contents.", file=sys.stderr)
    # C-374: under `--dashboard --full` the PDF must also carry the pipeline blocks, and
    # those phases are computed further down (in the dashboard branch). Defer the write
    # to there rather than emitting a findings-only PDF the card would then describe as
    # complete.
    _defer_pdf = bool(args.pdf) and args.dashboard and args.full
    if args.pdf and not _defer_pdf:
        try:
            _pdf_dest = _report_dest(args.pdf)
            secure_write_bytes(_pdf_dest,
                               render_pdf(findings, score, native=ctx.native, ctx=ctx))
            pdf_written = str(_pdf_dest)
        except OSError as exc:
            _emit(f"(could not write PDF report: {exc})")
            return 1
        if not args.dashboard:
            _emit(
                f"(PDF report written to {args.pdf} — attach this file itself into the "
                "chat, do not re-render its contents or paste the path; a mobile client "
                "opens a PDF inline where an HTML attachment would just be a download)"
            )
            return 0

    if args.trend:
        # F-155 fix (C-135): resolve the liveTest cap BEFORE recording/rendering, so a
        # VULNERABLE verdict binds here too, not just on the default --full --json path
        # (see _apply_live_test_cap's own docstring for why this is scoped to ONLY the
        # liveTest bucket). A seeded (reproducible) verdict is capped AND recorded; an
        # unseeded one still caps THIS run's shown/percentile score but is excluded from
        # history — the same seed-gate the default path already applies below.
        score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)
        _skip_live_test_history = _live_signal.hit and not _live_signal.reproducible
        # --trend's job is to record the point AND show the trend, so it records even
        # under --no-history (a documented, tested contract). The conflict is surfaced
        # as a stderr note by _flag_coherence_notes rather than silently honored (B-066).
        if not _skip_live_test_history:
            history_record(score, args.history)
        rows = history_load(args.history)
        _emit(render_trend(rows, ascii_only))
        _emit(_percentile_line(score, ascii_only))
        return 0

    if args.percentile:
        # B-379: resolve the liveTest cap before ranking — previously this returned
        # before any cap resolution ran at all, so a run --full would grade F was
        # ranked against the recorded distribution as though it were an uncapped A.
        score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)
        _emit(_percentile_line(score, ascii_only))
        return 0

    if args.next:
        # B-379: same cap-resolution gap as --percentile above — suggested next actions
        # should reflect the capped grade, not an uncapped one.
        score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)
        _emit(render_next_actions(suggest_actions(findings, score), ascii_only))
        return 0

    if args.dashboard:
        if not args.full:
            # Byte-identical to before F-153: the overwhelming majority of callers
            # (every pre-existing test, and every plain `--dashboard` invocation)
            # never asked for the rest of the pipeline, so nothing extra is computed.
            _emit(render_dashboard(findings, score, ascii_only=ascii_only, ctx=ctx,
                                   pdf_path=pdf_written))
            _emit_attach_instruction(pdf_written)
            return 0
        # F-153: Dave settled 2026-07-30 that --dashboard must fully render
        # everything --full does, in the fixed order (Skills · Plugins · MCP · RISK
        # chains · Behavioural · "Second opinion (advisory)" · Coverage · "Worth a
        # glance"), replacing --full's own additive-append shape as the ONE combined
        # pipeline report. The open mechanism call this task owns: does --dashboard
        # itself repeat the expensive phases Step 2's `--full --attest` already ran
        # in the same guided-flow turn, or does the flow feed Step 2's artifact in
        # instead? Chosen here: --dashboard --full computes the phases itself, ONCE,
        # using the exact same functions --full uses (no second engine, no risk of
        # the two renderers drifting) — and the guided flow (SKILL.md, C-297) drops
        # the separate discarded `--full --attest` call and merges Steps 2+3 into
        # this one command instead, so a guided-flow turn still computes each phase
        # exactly once, never twice. That is simpler and safer than a second code
        # path that re-hydrates Finding objects from a saved --full --json artifact
        # just to avoid a second process invocation — this project's own precedent
        # (B-356's Skills block reusing _skills_inventory_lines) is "one source of
        # truth, not a second formatter to drift out of sync", and a JSON-rehydration
        # renderer would be exactly that second formatter.
        #
        # _resolve_runtime_caps also applies here (not just to --full's own report/
        # --json branch below) so --dashboard --full shows the IDENTICAL F-154/F-155
        # capped grade a plain --full run of the same config would — and, C-425, the
        # IDENTICAL five-layer ledger / graded state too.
        score, full_deadline, judged_bundle, _live_signal, _behavioral_fired_ids, _ledger = (
            _resolve_runtime_caps(ctx, findings, score, args, attestation=attestation)
        )
        sweep_home = Path(args.home).expanduser()
        plugin_sweep = None
        # B-405: also swept for adjudication's own-target corpus (below) — NOT for a
        # separate SKILL SWEEP section (the Skills section above already came from
        # `ctx`/`build_inventory`, unaffected by this). Before this fix, this branch
        # fed P9 ONLY plugin_sweep.vet_targets() — a plain `--full` (human/json) fed
        # P9 only its SKILL sweep's targets via `run_pipeline`'s own P6/P7 union (see
        # that function's docstring) — so the SAME audit run's judge packet covered
        # plugins-only here and skills-only there. Computing the skill sweep here too,
        # exactly the way `--full` already does, closes that gap: both renderers now
        # union skills + plugins into the SAME corpus.
        skill_sweep = None
        if not args.fast:
            _plugin_sweep_fn = _pipeline.resolve_plugin_sweep()
            if _plugin_sweep_fn is not None and not budget_exceeded(full_deadline):
                _sweep_budget_s = _pipeline.sub_budget(full_deadline, DEFAULT_VET_ALL_BUDGET_S)
                try:
                    plugin_sweep = _plugin_sweep_fn(
                        sweep_home, ascii_only=ascii_only,
                        sweep_budget_s=_sweep_budget_s, narrate=False)
                except Exception:  # noqa: BLE001 — one phase must not break the whole card
                    plugin_sweep = None
            if not budget_exceeded(full_deadline):
                _skill_sweep_budget_s = _pipeline.sub_budget(full_deadline, DEFAULT_VET_ALL_BUDGET_S)
                try:
                    # B-404: reuse the SAME ctx the audit above already collected —
                    # same pattern the --full (human/json) call sites use.
                    skill_sweep = sweep_installed_skills(
                        sweep_home, ascii_only=ascii_only,
                        sweep_budget_s=_skill_sweep_budget_s, narrate=False, ctx=ctx)
                except Exception:  # noqa: BLE001 — one phase must not break the whole card
                    skill_sweep = None
        behavioral_phase = None
        if not args.fast and not budget_exceeded(full_deadline):
            behavioral_phase = _pipeline.run_behavioral(ctx, ascii_only=ascii_only)
        # P9 (adjudication) is deliberately NOT gated on --fast or the budget, same as
        # --full's own P9: it re-runs no check, so there is no expense to skip.
        _dashboard_vet_targets = (
            list(plugin_sweep.vet_targets()) if plugin_sweep is not None else []
        ) + (
            list(skill_sweep.vet_targets()) if skill_sweep is not None else []
        )
        adjudication_phase = _pipeline.run_adjudication(
            ctx, findings,
            vet_targets=_dashboard_vet_targets,
            version=__version__, bundle=judged_bundle)
        if _defer_pdf:
            try:
                _pdf_dest = _report_dest(args.pdf)
                secure_write_bytes(_pdf_dest, render_pdf(
                    findings, score, native=ctx.native, ctx=ctx,
                    plugin_sweep=plugin_sweep, risk=paths,
                    behavioral=behavioral_phase, adjudication=adjudication_phase))
                pdf_written = str(_pdf_dest)
            except OSError as exc:
                # B-459: the PDF is the DELIVERY of this audit, not the audit. Failing to
                # write it must never destroy the analysis: fall through with
                # pdf_written=None so render_dashboard renders every section inline
                # instead of collapsing to a card that points at a file we never wrote.
                _emit(f"(could not write PDF report: {exc} — showing the full report inline)")
        _emit(render_dashboard(
            findings, score, ascii_only=ascii_only, ctx=ctx, full=True,
            risk=paths, plugin_sweep=plugin_sweep, behavioral=behavioral_phase,
            adjudication=adjudication_phase, compact=args.compact,
            pdf_path=pdf_written))
        _emit_attach_instruction(pdf_written)
        return 0

    if args.dashboard_findings:
        _emit(render_dashboard_findings(findings, ascii_only=ascii_only))
        return 0

    if args.sbom:
        _emit(render_sbom(ctx))
        return 0

    if args.incident:
        # B-277: --events was accepted and silently dropped here, so the pack
        # harvested the DEFAULT journal no matter what the operator named. Threaded
        # like --watch-log (:~915) and --monitor (:~1078) already do.
        _emit(render_incident(ctx, findings, score, events=args.events))
        return 0

    if args.judge_packet:
        _emit(render_judge_packet_json(ctx, findings, version=__version__))
        return 0

    if args.judged:
        if args.judged == "-":
            verdicts_raw = sys.stdin.read()
        else:
            try:
                verdicts_raw = Path(args.judged).expanduser().read_text(encoding="utf-8")
            except OSError:
                verdicts_raw = ""
        # B-355: `paths` (the RISK-* attack-chain data, computed above) was never
        # threaded through, so --judged silently omitted the risk_paths key entirely
        # (not an empty list -- absent) even though plain --json on the same run
        # carries it. Mirror the plain --json call site below (:~1737), which already
        # passes risk=paths.
        _emit(render_judged_json(ctx, findings, score, verdicts_raw=verdicts_raw, risk=paths))
        return 0

    if args.propose_ignore:
        if args.propose_ignore == "-":
            verdicts_raw = sys.stdin.read()
        else:
            try:
                verdicts_raw = Path(args.propose_ignore).expanduser().read_text(encoding="utf-8")
            except OSError:
                verdicts_raw = ""
        _emit(render_ignore_proposals_json(findings, verdicts_raw=verdicts_raw, version=__version__))
        return 0

    if args.analyze_trajectory is not None:
        _emit(render_trajectory_analysis(
            ctx, explicit_path=args.analyze_trajectory or None, ascii_only=ascii_only))
        return 0

    if args.behavioral is not None:
        _record_run("behavioral", args)
        _behavioral_target = args.behavioral or None
        _emit(render_behavioral_analysis(
            ctx, explicit_path=_behavioral_target, ascii_only=ascii_only))
        # B-462: a path the user named that does not resolve is an operational failure of
        # THIS invocation, not an inconclusive audit — exit non-zero so a typo in a script
        # cannot pass for a clean behavioural run.
        if _behavioral_path_problem(_behavioral_target):
            return 1
        return 0

    if args.monitor:
        # F-155 fix (C-135): resolve the liveTest cap BEFORE the snapshot is taken, so a
        # VULNERABLE verdict is baked into the drift baseline capped — not the uncapped
        # score --monitor recorded before this fix (this branch returned before the
        # liveTest bucket in --judged-bundle was ever parsed; see _apply_live_test_cap's
        # own docstring for why this is scoped to ONLY the liveTest bucket). An unseeded
        # (non-reproducible) VULNERABLE verdict still caps what THIS run reports, but —
        # per the same seed-gate the default --full path already applies
        # (docs/OUTPUT_SCHEMA.md §12) — is excluded from the persisted baseline/history
        # below, so a random token can never manufacture drift on the next run.
        score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)
        _skip_live_test_persist = _live_signal.hit and not _live_signal.reproducible
        # B-270: ONE predicate decides what "no usable baseline" means, and it tells
        # *absent* (a real first run) apart from *corrupt* (a prior baseline existed and is
        # gone). Both used to collapse into `prev is None`, so a destroyed baseline
        # rendered the same reassuring "Baseline saved." line as a healthy first run.
        base_status, prev = read_baseline(args.state)
        # B-269: snapshot() needs the previous state so that a run which could not read
        # openclaw.json preserves the last known-good config baseline instead of writing
        # the collapsed (empty) view over it — see monitor._degrade_snapshot.
        snap = snapshot(ctx, findings, score, prev=prev)
        alerts = diff(prev, snap)
        if base_status == BASELINE_CORRUPT:
            # prev is None here, so diff() produced nothing to compare — the lost baseline
            # IS the event. Prepended (not rendered separately) so the identical string
            # reaches the screen and the tamper-evident journal.
            alerts = [BASELINE_CORRUPT_ALERT] + alerts
        # ── B-278 + B-271: write order is a deliberate choice, documented here ──────────
        # Journal FIRST, then advance the baseline, and skip the advance if the journal
        # write failed. The alternative (advance first) is what lost drift permanently: a
        # `chmod 0444` events.jsonl swallowed a CRITICAL gateway-exposure alert while the
        # baseline moved on, so the next run compared against the NEW state and reported
        # "No new threats" over an exposed gateway. Not advancing keeps the event
        # unconsumed: the same drift is re-detected next run and gets another chance to be
        # recorded. That re-detection is not a false alert — the change really is still
        # there — and a later, unrelated change is still caught, because the diff is taken
        # against the older baseline and reports the union.
        # The accepted cost: if the journal succeeds and the *state* write then fails, the
        # next run re-detects the same drift and journals it a second time. A duplicated
        # line in the timeline is strictly recoverable; a missing one is not, and the
        # duplicate only follows a failure that is now loud and non-zero anyway.
        # B-379: gate the journal write behind the SAME F-155 seed-gate that already
        # guards save_state/history_record below — this write used to run
        # unconditionally, so an unseeded VULNERABLE verdict re-journaled the identical
        # "score dropped" alert on every single run forever (the baseline never
        # advances, so nothing ever consumes it), which is exactly the manufactured-
        # drift failure mode the seed gate exists to prevent.
        journal_err = record_events(alerts, args.events) if not _skip_live_test_persist else None
        state_err = None
        # F-155: an unseeded VULNERABLE verdict must never be recorded, so the baseline
        # advance is skipped exactly like a write failure would skip it — except this is
        # not a failure (state_err stays None; no stderr, no non-zero exit below).
        if journal_err is None and not _skip_live_test_persist:
            try:
                save_state(args.state, snap)
            except OSError as exc:
                state_err = str(exc)
        persisted = journal_err is None and state_err is None and not _skip_live_test_persist
        # B-271: render AFTER the writes, and tell the renderer whether they landed — the
        # success wording used to be printed before the save was even attempted.
        _emit(render_monitor(alerts, score, ascii_only,
                             baseline=base_status == BASELINE_ABSENT,
                             persisted=persisted,
                             baseline_corrupt=base_status == BASELINE_CORRUPT,
                             live_test_skipped=_skip_live_test_persist))
        # --monitor records a score-history point as part of tracking drift, even under
        # --no-history; the conflict is surfaced as a stderr note (B-066), not silently
        # honored, to keep monitor's drift baseline intact. Recorded even on the failure
        # paths below: this run's score was really measured, and the trend should not gain
        # a hole because a different file was unwritable. Skipped only for the same F-155
        # unseeded-live-test exclusion as the baseline advance above.
        if not _skip_live_test_persist:
            history_record(score, args.history)
        # B-271/B-278: a write mode that could not write must not report success. --badge /
        # --html / --sarif / --save all return 1 on OSError; --monitor was the sole outlier,
        # returning 0 forever while persisting nothing, so cron saw a healthy job.
        if journal_err is not None:
            print(f"MONITORING NOT ESTABLISHED — could not record drift events to "
                  f"{args.events}: {journal_err}\n"
                  "The drift above was NOT written to the journal, so the baseline was "
                  "deliberately left unchanged and this run's changes will be re-reported "
                  "next time. Fix the journal path's permissions and re-run.",
                  file=sys.stderr)
            return 1
        if state_err is not None:
            print(f"MONITORING NOT ESTABLISHED — could not write monitor state to "
                  f"{args.state}: {state_err}\n"
                  "No baseline was saved, so this run cannot detect future changes. Fix "
                  "the state path's permissions and re-run.", file=sys.stderr)
            return 1
        return 0

    vm_has_fail = False
    sweep_has_fail = False
    pipeline_has_fail = False
    # `score` was already computed once, above, by `audit()`; `_resolve_runtime_caps`
    # returns the SAME object when neither cap-only signal fires, a freshly recomputed
    # one (never mutated in place) otherwise — see its own docstring for the F-154/
    # F-155 detail this used to carry inline.
    #
    # B-379: `render_json`'s "projection" (what-if FIX FIRST) sub-block used to call
    # `scoring.project` -> `scoring.compute` a second time over (findings, ctx) ALONE,
    # with no live-test/behavioral signal threaded through — unlike the three earlier
    # cap-only signals (config-blind/degraded/runtime), which are fully derivable from
    # (findings, ctx) alone and so already agreed with `score` for free, F-154/F-155
    # need the external input resolved right here. Now threaded through explicitly
    # (see the `render_json` call below) so `payload["projection"]["current"]` can
    # never disagree with `payload["score"]`/`payload["grade"]` for the same run.
    score, full_deadline, judged_bundle, live_signal, behavioral_fired_ids, layer_ledger = (
        _resolve_runtime_caps(ctx, findings, score, args, attestation=attestation)
    )
    if args.json:
        # F-149 JSON gap: --full's printed SKILL SWEEP section had no machine-readable
        # counterpart — the whole self-test/vet-mcp/sweep block below is skipped
        # outright for --json (it is gated on `not args.json`), so a --full --json
        # consumer could not see per-skill vet verdicts at all. Scope stays to the
        # sweep only (self-test/vet-mcp are a separate, pre-existing --json gap this
        # task does not cover — see docs/OUTPUT_SCHEMA.md). Silent (narrate=False),
        # matching the --quiet collapse: JSON output must never carry the narrative
        # prose a human report prints.
        #
        # F-153: --full --json is ALSO the phase-1 carrier — the one artifact handed to a
        # host-agent judge — so it runs the whole pipeline, not just the sweep, and gains
        # the pipeline's additive top-level keys below. C2 is untouched by this: C2 gates
        # printed SECTIONS on `not args.json`, and nothing here prints.
        full_sweep_json = None
        full_pipeline = None
        if args.full:
            sweep_home = Path(args.home).expanduser()
            sweep = None
            if not args.fast:
                # B-404: reuse the SAME ctx the audit above already collected
                # (ctx.home == sweep_home) instead of a second, redundant collect()
                # pass — and, just as importantly, so the sweep's view of "what
                # skills exist" can never disagree with what the score was actually
                # computed against.
                sweep = sweep_installed_skills(
                    sweep_home, ascii_only=ascii_only,
                    sweep_budget_s=_pipeline.sub_budget(
                        full_deadline, DEFAULT_VET_ALL_BUDGET_S),
                    narrate=False, ctx=ctx)
                full_sweep_json = _sweep_to_json(sweep)
                sweep_has_fail = sweep.has_fail
                _record_run("vet", args)
            full_pipeline = _pipeline.run_pipeline(
                ctx, findings, home_dir=sweep_home, skill_sweep=sweep,
                vet_targets=sweep.vet_targets() if sweep is not None else (),
                deadline=full_deadline, budget_s=DEFAULT_FULL_BUDGET_S,
                fast=args.fast, ascii_only=ascii_only, version=__version__,
                bundle=judged_bundle)
            pipeline_has_fail = full_pipeline.has_fail
            if not args.fast:
                _record_run("behavioral", args)
        body = render_json(findings, score, risk=paths, ctx=ctx, skill_sweep=full_sweep_json,
                           live_test_vulnerable=live_signal.hit,
                           live_test_reason=live_signal.reason,
                           behavioral_fired_ids=behavioral_fired_ids,
                           ledger=layer_ledger)
        if full_pipeline is not None:
            # Additive merge, done here rather than by widening render_json's signature:
            # these keys belong to the pipeline, not to the audit payload, and every
            # existing key keeps its meaning and its value. Re-serialized with the same
            # dumps() settings render_json uses, so the base document is unchanged.
            _doc = json.loads(body)
            _doc.update(full_pipeline.to_json())
            body = json.dumps(_doc, ensure_ascii=True, indent=2)
    elif args.card:
        body = render_card(score, findings, ascii_only)
    else:
        # Offline staleness advisory — human report only; never in --json/--card/--sarif.
        # Reads only the local clock + an optional local hint file; makes no network call.
        notice = []
        if not args.no_update_notice and not os.environ.get("CLAWSECCHECK_NO_UPDATE_NOTICE"):
            notice = update_notice(__version__, released=__released__)
        # Coverage freshness advisory — human report only; never in --json/--card/--sarif.
        # Reads only the local coverage ledger and the local clock; makes no network call.
        # Advisory only: never alters score, grade, or findings.
        f_notice: list[str] = []
        if not args.no_freshness_notice and not os.environ.get("CLAWSECCHECK_NO_FRESHNESS_NOTICE"):
            # Under --full the self-test + vet-mcp sections run later in this same
            # invocation and refresh their ledger entries, so suppress their
            # freshness lines here — otherwise the report prints "never run" directly
            # above the sections that run them (the freshness is computed pre-run).
            _refreshed = ("self_test", "vet_mcp") if args.full else ()
            f_notice = _compute_freshness(load_ledger(), skip=_refreshed)
            # C-361: the IOC dataset's own age and coverage reached only --vet-source
            # before this, so a normal audit said nothing about how much a clean
            # identity result is worth. Same advisory list render_report already
            # treats as never touching score/grade/findings; same --no-freshness-notice
            # opt-out (this whole block is already inside it). NEVER a Finding (B-385).
            f_notice = f_notice + _iocdb_freshness_notice() + _iocdb_coverage_notice()
        # Tamper Score sub-grade — human report only; presentation-layer only, never
        # alters score/grade/findings. mon_present reflects whether a --monitor
        # baseline snapshot already exists on disk for this state file.
        # B-270: the SAME predicate the --monitor path uses, instead of this call site's
        # own `is not None` rule. A state file holding `{}` used to satisfy `is not None`
        # and earn full HIGH-weight tamper credit for a baseline that cannot detect
        # anything — measured on fixtures/home_safe as 24/100 vs 3/100 with no file at all.
        mon_present = read_baseline(args.state)[0] == BASELINE_OK
        tamper = tamper_subgrade(findings, mon_present)
        parts = [render_report(findings, score, ascii_only, native=ctx.native,
                               risk=paths, update_notice=notice, freshness_notice=f_notice,
                               openclaw_detected=ctx.config_found, ctx=ctx, color=use_color,
                               tamper=tamper,
                               # B-473: the plugin sweep is pipeline phase P7, which runs
                               # BELOW this body (the tee block). There is no sweep object
                               # to render here, but "not scanned — run --full" is a lie on
                               # a run that is about to print the sweep a few hundred lines
                               # down. --fast drops P7/P8 and the pipeline prints its own
                               # honest "skipped" line in that slot, so the section exists
                               # either way and the pointer stays true.
                               plugins_deferred=args.full),
                 "", render_card(score, findings, ascii_only)]
        if ctx.errors:
            parts.append("\nnotes:\n" + "\n".join(f"  - {_sanitize(e)}" for e in ctx.errors))
        parts.append("")
        parts.append(render_next_actions(
            suggest_actions(findings, score), ascii_only))
        body = "\n".join(parts)

    _emit(body)

    # B-351: --save must write the WHOLE combined report. `body` is assembled above,
    # BEFORE these sections are emitted, so a saved --full report used to stop at the
    # report body — the self-test, vet-mcp, sweep and pipeline sections silently never
    # reached the file, and nothing said so. The tee collects them as they print.
    _full_lines: list[str] = []
    with _tee_emitted(_full_lines):
        if args.full and not args.json and not args.card:
            seed = args.seed if args.seed is not None else secrets.token_hex(8)
            # F-149: the installed-skill sweep runs under the same wall-clock ceiling
            # --vet-all uses. Cost is driven by content hostility, not skill count, so a
            # hostile fleet is what this bounds. Kept as the phase default rather than a
            # new flag, following the precedent that vet_all()'s sweep_budget_s is a
            # Python parameter the CLI deliberately does not expose.
            #
            # F-153: clamped to whatever is left of the pipeline's outer wall-clock window
            # (min(own default, remaining)). An unclamped phase would defeat the outer
            # budget entirely — it could spend the whole window on its own and leave every
            # later phase reporting "not reached" on a run that was in fact healthy. The
            # clamp is cooperative arithmetic on a monotonic float, never a nested
            # check_deadline block; the deadline is consulted BETWEEN targets, inside the
            # sweep, so a target already underway always finishes.
            sweep_home = Path(args.home).expanduser()
            sweep_budget_s = _pipeline.sub_budget(full_deadline, DEFAULT_VET_ALL_BUDGET_S)
            sweep = None
            if args.quiet:
                # C-110: --full --quiet — the appended self-test material + per-server
                # vet-mcp detail are what push --full to ~700 lines; collapse each to a
                # single honest summary line (the concise report above is unchanged).
                # The self-test harnesses emit generated adversarial *scenarios* for the
                # agent to run — there is no PASS/score the tool computes, so the summary
                # states counts, not a verdict (Golden Rule #4: no fabricated result).
                # record_run() / vm_has_fail still fire, so ledger freshness and
                # --exit-code behave identically to the verbose path.
                n_rt = len(make_suite(seed))
                n_dr = len(make_scenarios(args.seed))
                n_mt = len(make_multiturn(args.seed))
                _emit("")
                _emit(f"SELF-TEST: 1 canary + {n_rt} red-team + {n_dr} dry-run + {n_mt} multi-turn "
                      "injection scenario(s) generated — run them against your agent "
                      "(RESISTANT = good). Full harness: --self-test.")
                _record_run("self_test", args)
                vm_findings = vet_mcp(target=None, home=args.home)
                vm_has_fail = any(vmf.status == "FAIL" for vmf in vm_findings)
                if len(vm_findings) == 1 and vm_findings[0].status == "UNKNOWN":
                    _emit(f"VET-MCP: {_sanitize(vm_findings[0].detail)}")
                else:
                    _vc = {st: sum(1 for v in vm_findings if v.status == st)
                           for st in ("FAIL", "WARN", "PASS", "UNKNOWN")}
                    _summary = (f"VET-MCP: {len(vm_findings)} server-check(s) — "
                                f"{_vc['FAIL']} FAIL, {_vc['WARN']} WARN, {_vc['PASS']} PASS")
                    if _vc["UNKNOWN"]:
                        _summary += f", {_vc['UNKNOWN']} UNKNOWN"
                    _emit(_summary + ". Full detail: --vet-mcp.")
                _record_run("vet_mcp", args)
                # F-149: the installed-skill sweep, collapsed the same way. narrate=False
                # keeps the sweep completely silent; the single line below is the whole
                # section. sweep.has_fail is read from the SAME SkillSweep object the
                # verbose branch reads, so --exit-code cannot diverge between the two.
                #
                # F-153: --fast drops this phase (and P7/P8) entirely. The pipeline then
                # prints its own honest "skipped — --fast was given" line in this slot, so
                # the section never simply vanishes.
                if not args.fast:
                    # B-404: reuse the SAME ctx the audit above already collected —
                    # see the matching comment at the --json call site above.
                    sweep = sweep_installed_skills(
                        sweep_home, ascii_only=ascii_only,
                        sweep_budget_s=sweep_budget_s, narrate=False, ctx=ctx)
                    _emit(_sweep_quiet_line(sweep))
                    sweep_has_fail = sweep.has_fail
                    _record_run("vet", args)
            else:
                # --- Self-test section (canary + red-team + dry-run) ---
                _emit("")
                _emit("=" * 60)
                _emit("CLAWSECCHECK SELF-TEST")
                _emit("=" * 60)
                _emit(render_canary(make_canary(args.seed), ascii_only))
                _emit("")
                _emit(render_suite(make_suite(seed), ascii_only, seed=seed))
                _emit("")
                _emit(render_dryrun(make_scenarios(args.seed), ascii_only))
                _emit("")
                _emit(render_multiturn(make_multiturn(args.seed), ascii_only))
                _record_run("self_test", args)
                # --- vet-mcp section ---
                _emit("")
                _emit("=" * 60)
                _emit("CLAWSECCHECK VET-MCP")
                _emit("=" * 60)
                vm_findings = vet_mcp(target=None, home=args.home)
                if len(vm_findings) == 1 and vm_findings[0].status == "UNKNOWN":
                    vmf = vm_findings[0]
                    vm_icon = "[?]" if ascii_only else "❔"
                    _emit(f"{vm_icon} {_sanitize(vmf.detail)}")
                else:
                    vm_has_fail = any(vmf.status == "FAIL" for vmf in vm_findings)
                    for vmf in vm_findings:
                        vm_icon = _VET_ICON_ASCII[vmf.status] if ascii_only else _VET_ICON_UNI[vmf.status]
                        vm_verdict = _VET_VERDICT[vmf.status]
                        _emit(f"{vm_icon} {vm_verdict}: {_sanitize(vmf.title)}")
                        if vmf.evidence:
                            for vm_ev in vmf.evidence[:4]:
                                _emit(f"    - {_sanitize(vm_ev)}")
                        _emit(f"    fix: {_sanitize(vmf.fix)}")
                        _emit("")
                _record_run("vet_mcp", args)
                # --- installed-skill sweep section (F-149) ---
                # Appended LAST on purpose. Everything above it — the report body, the
                # SELF-TEST section, the VET-MCP section — keeps the byte-for-byte shape
                # and order it has always had; a new section inserted higher up would
                # break the report-body prefix --full --quiet is compared against.
                #
                # What this adds on top of the audit, since the audit already inspects
                # skill content (the surface="skills" checks plus the shared content
                # ring): the audit answers "is anything wrong across this fleet", as
                # findings attributed to the HOME. The sweep answers "which skill, and
                # how bad is THAT skill" — one merged verdict per installed skill, from
                # the vet engine, which builds its own Context per target precisely
                # because a skill is untrusted third-party content and must not share
                # the audit's. So the unit of the answer differs, and that unit is what
                # an owner acts on: you uninstall a skill, not a finding.
                #
                # Visibility only: these verdicts are deliberately NOT folded into the
                # audit score or grade. Changing a scoring rule is a separate, explicit
                # decision — it is not something a new section gets to do as a side
                # effect. The one place the sweep does reach the outside world is
                # --exit-code, FAIL-only, exactly as the vet-mcp section already does.
                if not args.fast:
                    _emit("")
                    _emit("=" * 60)
                    _emit("CLAWSECCHECK SKILL SWEEP")
                    _emit("=" * 60)
                    _emit("Per-skill verdict for every installed skill. Not folded into the "
                         "score or grade above; per-skill dossier: --vet <path>.")
                    # B-404: reuse the SAME ctx the audit above already collected —
                    # see the matching comment at the --json call site above.
                    sweep = sweep_installed_skills(
                        sweep_home, ascii_only=ascii_only,
                        sweep_budget_s=sweep_budget_s, narrate=True, ctx=ctx)
                    for _sweep_line in _sweep_summary_lines(sweep, ascii_only=ascii_only):
                        _emit(_sweep_line)
                    sweep_has_fail = sweep.has_fail
                    _record_run("vet", args)

            # --- pipeline phases P7-P9 + the combined roll-up (P10) ------------------
            # Appended after everything above, for the same reason the skill sweep is: the
            # report body, SELF-TEST and VET-MCP keep the byte-for-byte shape and order they
            # have always had. Nothing new is printed between the report body and the
            # SELF-TEST line, which is the prefix --full --quiet is compared against.
            full_pipeline = _pipeline.run_pipeline(
                ctx, findings, home_dir=sweep_home, skill_sweep=sweep,
                vet_targets=sweep.vet_targets() if sweep is not None else (),
                deadline=full_deadline, budget_s=DEFAULT_FULL_BUDGET_S,
                fast=args.fast, ascii_only=ascii_only, version=__version__,
                bundle=judged_bundle)
            # C5: read from the SAME PipelineResult on both branches, so --exit-code cannot
            # diverge between quiet and verbose — the property the sweep already guarantees.
            pipeline_has_fail = full_pipeline.has_fail
            _rendered = (_pipeline.quiet_lines(full_pipeline) if args.quiet
                         else _pipeline.render_sections(full_pipeline, ascii_only=ascii_only))
            for _pipeline_line in _rendered:
                _emit(_pipeline_line)
            if not args.fast:
                # C1: ledger writes route through _record_run, never ledger.record_run —
                # so --no-history suppresses them here exactly as everywhere else.
                _record_run("behavioral", args)

    _save_failed = False
    if args.save:
        try:
            # Persist plain text — a saved report must never carry ANSI escape codes,
            # even when the on-screen copy was colourised for the terminal.
            #
            # B-351: the WHOLE combined output, not just `body`. `body` is assembled
            # before the appended --full sections are emitted, so a saved --full report
            # used to stop at the report body — the self-test, vet-mcp, sweep and
            # pipeline sections silently never reached the file, and nothing said so.
            # `_full_lines` is empty on every non---full path, so this is exactly
            # today's behaviour there.
            _saved = "\n".join([body, *_full_lines]) if _full_lines else body
            secure_write_text(_report_dest(args.save), strip_ansi(_saved))
            _emit(f"\n(report saved to {args.save})")
        except OSError as exc:
            _emit(f"\n(could not save report: {exc})")
            _save_failed = True

    # F-155: a live-test verdict that fired the cap but was NOT reproducible (no usable
    # seed — see LiveTestSignal.reproducible / LIVE_INJECTION_CAP's docstring) must still
    # cap THIS run's score/grade above, but must never be written to history.jsonl/trend/
    # baseline — those exist to show drift across runs, and a random, unrepeatable signal
    # recorded there would manufacture drift where none exists and let the grade oscillate
    # on its own every time the harness is re-run with a fresh token. A seeded (or absent)
    # live-test signal records exactly as before this feature existed.
    _skip_history_for_live_test = live_signal.hit and not live_signal.reproducible
    if not args.no_history and not args.trend and not args.monitor and not _skip_history_for_live_test:
        history_record(score, args.history)

    if _save_failed:
        return 1

    # I3/C-426: --fail-on gates on FINDINGS (like --exit-code), never on a score. It
    # replaced `--fail-under N`, which thresholded the audit score and was removed once
    # the five-layer rule meant an ordinary run does not produce one — see the argparse
    # block for why removal beat both alternatives.
    #
    # "Unsuppressed" reuses --exit-code's own predicate verbatim (not a parallel one):
    # a suppressed finding counts only when surfaced_despite_suppression() says a
    # .clawseccheckignore line must not be able to silently flip the gate for a
    # score-capping CRITICAL/HIGH FAIL or a SENSITIVE_SUPPRESSED_IDS check.
    #
    # Scope: severity is only available per-finding on `findings` (the main audit
    # list) — vm_findings/sweep/pipeline below contribute to --exit-code's FAIL-only
    # disjunction as bare booleans (vm_has_fail/sweep_has_fail/pipeline_has_fail) with
    # no severity attached, so --fail-on (a severity-gated flag) does not join that
    # disjunction; it reads `findings` only, same as --exit-code's own `has_fail` term.
    if args.fail_on is not None:
        _fail_on_rank = _SEVERITY_RANK[args.fail_on.upper()]
        if any(
            f.status == "FAIL"
            and _SEVERITY_RANK.get(f.severity, -1) >= _fail_on_rank
            and (
                not getattr(f, "suppressed", False)
                or surfaced_despite_suppression(f)
            )
            for f in findings
        ):
            return 1
        # C-426/B-166/B-363: a config the tool could not read produces only UNKNOWN and
        # WARN, never a FAIL — so a purely FAIL-driven gate stays GREEN on a run that
        # audited nothing. `--exit-code` has tripped on this explicitly since B-166
        # (unreadable) and B-363 (absent); `--fail-on` did not, because until C-426 the
        # score-based `--fail-under` covered the case for anyone who used it: an
        # unreadable config caps the score to CONFIG_BLIND_CAP, so any sane threshold
        # tripped. Removing `--fail-under` without this would have left the replacement
        # gate strictly weaker than the flag it replaces, in precisely the case B-363
        # exists to prevent — hiding the evidence turning a gate green.
        #
        # Deliberately NOT severity-ranked: "I could not read your config" has no
        # severity, and gating it on the operator's chosen floor would let
        # `--fail-on critical` pass a run that read nothing at all.
        if (getattr(ctx, "config_parse_error", False)
                or not getattr(ctx, "config_found", True)):
            return 1

    if args.exit_code:
        has_fail = any(
            f.status == "FAIL"
            and (
                not getattr(f, "suppressed", False)
                or surfaced_despite_suppression(f)
            )
            for f in findings
        )
        # B-166: a present-but-unparseable openclaw.json produces only UNKNOWN/WARN, so a
        # FAIL-only gate would stay green on a broken config. Trip on it explicitly.
        #
        # F-149: sweep_has_fail joins the disjunction on exactly the terms vm_has_fail
        # already sits on — FAIL-only. A SUSPICIOUS (WARN) skill does not redden the
        # gate, and neither does an incomplete sweep: the contract this gate keeps is
        # "a FAIL verdict from any of the six sources below, plus an unreadable
        # config" — an ABSENT verdict is not a FAIL, and flipping the gate on
        # truncation would silently redden every CI run that passes today. An
        # incomplete sweep is reported honestly in its printed section instead.
        # docs/USAGE.md ("CI / automation") and references/cli-flags.md state all six
        # sources; keep them in step with this disjunction if a seventh is ever added.
        #
        # F-153: pipeline_has_fail joins on identical terms — FAIL-only, aggregated
        # across the pipeline phases. A phase that was skipped (--fast), never reached
        # (budget), unavailable in this build or errored contributes nothing: an ABSENT
        # verdict is not a FAIL. Truncation is reported by the printed section and by
        # the JSON "complete"/"notScanned" keys, never by reddening a gate that would
        # otherwise be green.
        #
        # B-363: a wholly ABSENT openclaw.json (no target found at all — strictly LESS
        # information than a present-but-unparseable one) must trip this gate exactly
        # like config_parse_error already does, or `--exit-code` stays 0 on a run that
        # never read anything. `config_found` defaults True via getattr so a duck-typed
        # ScoreResult/ctx stand-in some tests build (which predates this field) stays
        # inert, same tolerance as the config_parse_error term above.
        if (has_fail or vm_has_fail or sweep_has_fail or pipeline_has_fail
                or getattr(ctx, "config_parse_error", False)
                or not getattr(ctx, "config_found", True)):
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
