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
from datetime import date, datetime
from pathlib import Path

from . import (
    audit, fingerprint, load_events, load_ignore, load_state, make_canary, record_events,
    render_canary, render_card, render_dashboard, render_dashboard_findings, render_events,
    render_json, render_monitor,
    render_report, render_svg, render_vet_json, save_state, snapshot,
    vet_mcp, vet_plugin, vet_skill, vet_source,
)
from . import __released__, __version__
from .brand import WORDMARK
# B-460: same rationale as the .monitor import below — taken from the submodule so this
# internal resolver does not have to widen the curated public API in __init__.py.
# B-682 adds `detect_vet_type_with_reason` on the same terms: it is the pair-function that
# carries WHY a classification may be undetermined, and `detect_vet_type` — the curated
# public name — stays exactly as it was, wrapping it.
from .checks import detect_vet_type_with_reason, resolve_skill_target
from .collector import LIMIT_DOMAIN_SKILL, Context, collect, limit_hits_for
from .checks import _credential_store_state
from .invocation import _display_path, command_prefix
# B-270: the shared baseline predicate. Imported from the submodule rather than the package
# root so the new vocabulary does not have to widen the curated public API in __init__.py.
from .monitor import (
    BASELINE_ABSENT, BASELINE_CORRUPT, BASELINE_CORRUPT_ALERT, BASELINE_OK,
    BASELINE_DIGEST_CHARS, baseline_reference, baseline_witness_event,
    _coverage_signature, _diff_coverage,
    diff_with_notes, read_baseline, snapshot_reference,
)
# Aliased: `args.verify_baseline` holds the user's reference string, and giving the
# function the same bare name next to it reads as though one were the other.
from .monitor import verify_baseline as _verify_baseline
from .update import update_notice
from .ledger import freshness_notice as _compute_freshness, load_ledger, record_run
from .iocdb import coverage_notice as _iocdb_coverage_notice
from .iocdb import freshness_notice as _iocdb_freshness_notice
from . import risk as _risk
from .guide import render_next_actions, suggest_actions
from .integrity import (
    NOTE_PATH_ESCAPE,
    NOTE_SYMLINK,
    NOTE_UNCHECKED_PYC,
    NOTE_UNREADABLE,
    NOTE_VANISHED,
    package_digest,
)
from .report import _missing_layers_sentence
from .report import render_html
from .report import (
    _evidence_bullets,
    _redact_home_paths,
    _sanitize,
    render_advise,
    render_advise_json,
    render_permission_manifest,
    render_vet_dossier,
    render_vet_plan,
    self_excluded_line,
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
from .catalog import CRITICAL, HIGH, LOW, MEDIUM, UNKNOWN, Finding
from .dossier import build_profile, verdict_for
from .ansi import should_color, strip_ansi
from .monitor import (
    CHAIN_ABSENT,
    CHAIN_BAD_PATH,
    CHAIN_UNREADABLE,
    DEFAULT_EVENTS,
    DEFAULT_STATE,
    chain_provenance_note,
    load_events_with_problem,
    verify_chain,
)
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
    load_with_problem as history_load_with_problem,
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
from .layers import LAYER_ORDER
from .trajaudit import render_trajectory_analysis
from .behavioral import analyze as _behavioral_analyze
from .behavioral import analysis_incompleteness as _behavioral_incompleteness
from .behavioral import explicit_path_problem as _behavioral_path_problem
from .behavioral import grade_cap_signal as _behavioral_grade_cap_signal
from .behavioral import render_behavioral_analysis
from .hostpersist import scan as _hostpersist_scan
from .hostpersist import to_snapshot as _hostpersist_to_snapshot
from .openclawdist import describe_install as _describe_install
from .skillprovenance import read_provenance as _read_provenance
from .skillprovenance import workspace_roots as _workspace_roots
from .monitor import NOTE_INSPECTION_CAPPED, NOTE_UNDETERMINED
from .monitor import changed_skills as _changed_skills
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

# B-723: when set, _emit() diverts here INSTEAD of printing (and instead of
# teeing). Installed only via _capture_emitted(); see its docstring.
_EMIT_CAPTURE: list[str] | None = None


#: B-605: above this many characters the Dashboard card stops being a thing a chat message
#: can carry, and the note says so. Not a channel limit -- the tool cannot know the
#: channel's -- but a disclosure threshold, chosen from measured shapes rather than taste:
#: `--dashboard --full --pdf` renders ~1,643 chars (relayed intact by a live host) while
#: `--dashboard --full` alone renders ~19,972 (relayed not at all). 8,000 sits above the
#: ~6,482 `SKILL.md` cites for an ordinary Sections 1-2 render, so the note stays quiet on
#: the shapes that work, and fires on the one that measurably does not.
_RELAYABLE_CARD_CHARS = 8000


# B-604: the compact pointer, named once so its length can be RESERVED from the card's
# budget instead of being discovered after the fact. It is appended after
# render_dashboard has already enforced the budget, so anything not reserved is simply
# over the cap: measured on a real config, a 4,066-char card plus these 55 characters
# emitted 4,121 against a documented 4,096. Fixed string on purpose (see below) —
# which is exactly what makes reserving it possible.
_COMPACT_NEXT_POINTER = "\nWhat you can do next: run --next for the ranked list.\n"


def _with_next_actions(card: str, findings, score, ascii_only: bool,
                       compact: bool = False) -> str:
    """B-604: the Dashboard was the one verdict surface that offered the user nothing.

    `--next` (`cli.py`) and the default report both render `guide.render_next_actions`;
    the `--dashboard` branch returned before reaching either, so the mode `SKILL.md` Step 3
    designates as THE user-facing deliverable ended at its last findings section. Measured
    on the real config: a card stating Grade F, 49/100 and two open CRITICALs, followed by
    nothing to do about them. Same shape as the B-379 family -- a mode branch returning
    early and missing what the main path does.

    `SKILL.md` DOES design an offer here (Step 3's "Section 6 -- Next menu"), but as prose
    the host agent is asked to compose. Across four live Control-UI runs it reached the user
    **0 times out of 4** -- no menu, no monitoring offer, no closing question. That is the
    B-605 family, and B-605's own measurement is why this is wired into the render instead:
    across those same runs the tool's CONTENT was relayed 4/4 (grade, score, the cap from
    86, the live verdict) while prose the host was asked to author was not. So an offer that
    must survive is one the tool prints, not one the document requests.

    Appended INTO the card rather than emitted beside it: it is part of what the user is
    meant to read, so it belongs inside the payload the relay instruction covers and inside
    the character count the size disclosure reports. Emitting it separately would make the
    disclosed size a lie about the thing being disclosed.

    Under ``--compact`` it collapses to a one-line pointer, and that is not a nicety: the
    compact card exists to fit a message-capped channel, and `home_vuln` already renders
    3,881 of Telegram's 4,096 there. The full block is 919 chars, so appending it broke the
    budget outright (`test_compact_home_vuln_fits_telegram_budget`, caught on the first run
    of the suite). Even one full item leaves 26 chars of slack, which is a budget that
    depends on the config -- not a budget. Dropping the block instead would recreate this
    very defect on the one channel where a phone-sized reader most needs the guidance, so it
    condenses rather than disappears, following the convention the same mode already uses
    for its pipeline detail ("Full pipeline detail: --save <path> or --html <path>."). The
    pointer is a fixed string on purpose: naming the top action would make its length vary
    with the finding, and the whole problem here is a budget with no room to vary.
    """
    actions = suggest_actions(findings, score)
    if not actions:
        return card
    if compact:
        return card.rstrip("\n") + _COMPACT_NEXT_POINTER
    return card.rstrip("\n") + "\n\n" + render_next_actions(actions, ascii_only)


def _emit(text: str) -> None:
    """Print, falling back to ASCII-safe bytes if the console can't encode it."""
    if _EMIT_CAPTURE is not None:
        # B-723: intercepted, not copied — the line is replayed later, in its own slot.
        _EMIT_CAPTURE.append(text)
        return
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


@contextlib.contextmanager
def _capture_emitted(sink: list[str]):
    """Divert every ``_emit()`` line into *sink* WITHOUT printing it, for the block.

    B-723: the twin of :func:`_tee_emitted`, and the difference is the whole point. The
    tee copies; this one intercepts. It exists because the human ``--full`` report prints
    its grade at the top while the sweeps that decide whether a grade may be issued at all
    used to run a hundred and fifty lines further down — so the WORK has to move up while
    the OUTPUT stays exactly where it is. ``run_pipeline`` is already pure computation
    (it returns a ``PipelineResult``; ``render_sections`` prints it), so the only part
    that had to be intercepted is ``sweep_installed_skills``, which narrates per-target as
    it walks. Those lines are collected here and replayed verbatim into their established
    slot once the body has been emitted.

    The outer tee is suspended too, not just stdout. A captured line replayed later goes
    through ``_emit`` again, so leaving the tee installed would put it into the ``--save``
    transcript twice — once at capture, once at replay — and out of order the first time.
    """
    global _EMIT_TEE, _EMIT_CAPTURE
    prev_tee, prev_cap = _EMIT_TEE, _EMIT_CAPTURE
    _EMIT_TEE, _EMIT_CAPTURE = None, sink
    try:
        yield
    finally:
        _EMIT_TEE, _EMIT_CAPTURE = prev_tee, prev_cap


def _store_dir(args) -> Path:
    """The directory this run's local state lives in.

    Resolved from ``--history``'s parent, which is where ``--data-dir`` has already
    placed it. That is not a new convention: ``_run_purge`` has always derived the
    store this way and ``_PURGE_FILENAMES`` has always listed ``coverage.json``
    among the files living there — the tree already believed the four move together.

    B-599: only three of them actually did. ``--data-dir``'s help text promises that
    "the three move together, so a scratch run cannot half-redirect and write into
    your real history", and the coverage ledger — the fourth file, and the one
    ``--purge`` deletes from this very directory — ignored it. Deriving both from
    one helper is what makes the promise structural instead of a list someone has to
    remember to extend.
    """
    return Path(args.history).expanduser().parent


def _coverage_path(args) -> str:
    """This run's coverage/freshness ledger — beside its history, never elsewhere."""
    return str(_store_dir(args) / "coverage.json")


def _record_run(capability: str, args) -> None:
    """Coverage-ledger write, gated by --no-history (B-156).

    Every opt-in capability path (vet/vet-mcp/vet-plugin/vet-source/self-test
    family/behavioral) funnels through here instead of calling
    ``ledger.record_run`` directly, so ``--no-history`` reliably suppresses
    the ``~/.clawseccheck/coverage.json`` write everywhere, not just on the
    audit-trend path (Golden Rule #2: local-only / no surprise writes).

    B-599: that funnel was the right shape and still wrote to the wrong file —
    ``record_run`` was called with no path at all, so all nineteen call sites
    resolved to the real ``~/.clawseccheck`` however the run was redirected.
    """
    if getattr(args, "no_history", False):
        return
    record_run(capability, path=_coverage_path(args))


def _record_history_point(score, args, live_signal, findings) -> None:
    """The ONE decision about whether a run's verdict reaches the score history.

    B-598: this guard used to be written out at the tail of the default path and
    nowhere else, so any ``_mode`` branch that returns before that tail silently
    recorded nothing. ``--dashboard`` is such a branch — and it is the command
    ``SKILL.md`` puts in the guided flow, so *every audit a user gets through a chat
    agent* was invisible to ``--trend``, ``--percentile`` and the pre-scan menu's
    "last check" line. Measured on the live agent: two complete audits ran on
    2026-08-20, one of them graded, and the menu still said "Last check: 4 days ago".

    That is the exact shape ``cli.py``'s ``--monitor`` comment already records once
    ("this branch returned before the liveTest bucket was ever parsed"), so the fix is
    a shared helper rather than a second copy of the condition: a duplicated guard is
    how the two would drift apart on the next F-155-shaped change.

    ``live_signal`` may be ``None`` for a caller that never resolved one; that is not a
    licence to skip the gate, only an admission that there is no signal to gate on.

    **Which modes call this is a decision, not an accident.** B-601 settled it: *a run
    that measured a verdict for this setup records it.* That is what this module's own
    docstring and ``docs/USAGE.md`` ("the timeline stays unbroken") have always claimed,
    and it now covers all nine ``_mode`` branches that run a full audit and return early
    — ``--dashboard``, ``--badge``, ``--html``, ``--sarif``, ``--pdf``, ``--percentile``,
    ``--next``, ``--risk-paths`` — alongside the default path's tail.

    The principle is about VERDICTS, not invocations: ``--menu``, ``--purge``,
    ``--verify-*`` and the ``--vet`` family measure nothing about this setup's posture
    and record nothing. ``--trend`` and ``--monitor`` do NOT come through here either,
    for the opposite reason: they record unconditionally as part of their own job,
    including under ``--no-history`` (C-251), which is why they are excluded below
    rather than omitted.

    ``tests/test_b598_dashboard_history.py`` pins the answer for every mode, so a future
    change has to come through that test and say so — which is exactly how B-601 arrived.

    B-691: ``findings`` is a REQUIRED positional, deliberately undefaulted. The row now
    carries the uncapped pass-rate plus a hash of the check set behind it, and without the
    finding list that hash cannot be computed — so a defaulted ``findings=None`` would let a
    future ``_mode`` branch record a permanently uncomparable row, silently, which is the
    exact shape B-598 built this helper to stop. Every call site is downstream of the
    ``audit()`` that produced ``score``, so the list is always in scope; a ``TypeError`` at
    a new one is the point.
    """
    if getattr(args, "no_history", False) or args.trend or args.monitor:
        return
    # F-155: a live-test verdict that fired the cap but was NOT reproducible (no usable
    # seed — see LiveTestSignal.reproducible / LIVE_INJECTION_CAP's docstring) still caps
    # what THIS run reports, but must never be written to history/trend/baseline: those
    # exist to show drift across runs, and a random, unrepeatable signal recorded there
    # would manufacture drift where none exists and let the grade oscillate on its own
    # every time the harness is re-run with a fresh token.
    if live_signal is not None and live_signal.hit and not live_signal.reproducible:
        return
    # B-691: `home` was never passed by ANY call site, so every row ever written
    # carries `home: None` — and `history.jsonl` sits behind one default path for
    # every `--home`, so two rows can describe different machines and the trend
    # would compare them. `--home` defaults to the string "~/.openclaw", so this is
    # a real value on every run, and `_sanitize_home` keeps it the user-typed
    # `~/...` form rather than an absolute path naming the operator (§8/B-381).
    history_record(score, args.history, home=args.home, findings=findings,
                   version=__version__)


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

    Shares dossier.py's ``_danger_coverage_gap`` legs, minus the one it cannot reach.
    That function has three: (1) ``Finding.engine_degraded``, (2) ``ctx.limit_hits``,
    (3) the literal substring "coverage is incomplete". This helper is handed a
    ``vet_skill()`` result and no ``ctx``, so leg 2 is structurally unavailable here —
    it keys on 1 and 3, and callers that DO hold a ctx should prefer the dossier
    predicate.

    B-548: it used to key on leg 3 ALONE while claiming in this docstring to mirror the
    dossier predicate — a claim ``3fe2554`` made false when it added leg 1 there and not
    here. Leg 3 is documented in dossier.py as a fallback for hand-built ``Finding``
    objects precisely because matching English prose loses the signal the moment a
    producer rewords its detail, and never had it for a producer that used other words.
    B13's parse-error branch is exactly such a producer: it sets ``engine_degraded=True``
    and says "could not analyze <file> — parse error(s)". So
    ``--vet-all --home fixtures/unknown_b347_deaddrop_unparseable`` printed
    ``[?] 'broken-sync': could not assess`` and then ``1 skill(s) checked | 1 safe``,
    counting a target it could not read as safe — contradicting its own line above and
    docs/USAGE.md's promise that such a target is kept out of the "safe" tally.

    The signal can either BE the primary finding `f`, or ride along on
    ``f.ring_findings`` when a worse WARN/FAIL outranked it as primary
    (``checks/_vet.py:vet_skill``'s ``_VET_MERGE_RANK``) — so both must be checked, or a
    partially scanned target that also tripped a real WARN/FAIL would read as an
    ordinary, complete result.
    """
    pool = [f, *getattr(f, "ring_findings", [])]
    return any(
        fx.status == "UNKNOWN"
        and (
            getattr(fx, "engine_degraded", False)
            or _VET_COVERAGE_GAP_SUBSTRING in (fx.detail or "")
        )
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
    # B-404: the concrete reason(s) the skill scan could not be confirmed complete —
    # collector.limit_hits_for(ctx, LIMIT_DOMAIN_SKILL), the same signal
    # check_installed_skills (B13) already uses. B-553: that domain is NOT
    # discovery-only — it also carries ~40 CONTENT-scan reasons (a per-skill file
    # cap, an unreadable file/dir, an oversize archive, the archive-expansion
    # family), so a reason here can name either "the walk that finds targets in the
    # first place did not finish" OR a target's own content scan being cut short; it
    # can be non-empty even when every row found so far scanned cleanly. Empty for a
    # sweep whose scan genuinely completed.
    discovery_incomplete_reasons: list[str] = field(default_factory=list)
    # B-521: names withheld from `rows`/`findings` above because they are
    # ClawSecCheck's OWN content-verified install (B-265, collector.py's
    # `_is_own_source`/`ctx.self_excluded_skills`) — a tool auditing itself is noise,
    # so `sweep_installed_skills` never vets it, but report.py has disclosed the same
    # exclusion (`self_excluded`, since B-507) in the text inventory for a while.
    # `--vet-all`/the SKILL SWEEP section read straight off `rows`/`counts()` and had
    # no equivalent trace, so a home whose only skill is ClawSecCheck's own copy
    # printed "0 skill(s) checked" with no hint why. Carried here so both consumers of
    # this dataclass (the sweep table and the quiet one-liner) can disclose it the
    # same way the text inventory already does. Empty (never omitted downstream) when
    # nothing was withheld.
    self_excluded_skills: list[str] = field(default_factory=list)

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
    """One narration line naming that the skill scan could not claim full coverage
    (B-404). Printed before the per-skill/aggregate output so the caveat is seen
    first, never buried after results that may themselves look clean.

    B-553: ``reasons`` comes from ``limit_hits_for(ctx, LIMIT_DOMAIN_SKILL)``, and that
    domain is not discovery-only — collector.py tags ~ 40 CONTENT-scan reasons with it
    too (a per-skill file cap, an unreadable file/dir, an oversize archive, the whole
    archive-expansion family). So this cannot assert "discovery was incomplete" as the
    cause; it names the true superset instead — discovery OR a target's own content
    scan — rather than a specific wrong one."""
    extra = f" (+{len(reasons) - 6} more)" if len(reasons) > 6 else ""
    return (
        "(the skill scan could not cover everything (discovery or content) — "
        "this sweep cannot claim full coverage: "
        + "; ".join(reasons[:6]) + extra + ")"
    )


def _discovery_gap_suffix(sweep: SkillSweep) -> str:
    """A short trailing caveat for the ``--quiet`` one-liner, which (unlike the verbose
    branch) never sees ``sweep_installed_skills``'s own live narration. Empty when
    the scan completed, so every pre-existing caller is unaffected.

    B-553: same superset wording as ``_discovery_gap_note`` — see its docstring;
    kept identical on purpose so the verbose and quiet paths never diverge."""
    if not sweep.discovery_incomplete_reasons:
        return ""
    return (
        " The skill scan could not cover everything (discovery or content) — "
        "coverage may be missing target(s): "
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
    installed-skill collection cap) — B-553: OR one of the ~40 CONTENT-scan
    reasons the same domain also carries (a per-skill file cap, an unreadable
    file/dir, an oversize archive, an archive-expansion limit) — surfaces here as
    a named reason (``SkillSweep.discovery_incomplete_reasons``) and forces
    ``complete`` to False — even when zero skills were found at all, because an
    empty result from a walk that could not finish is not the same claim as an
    empty result from a walk that finished and genuinely found nothing.

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
    # B-521: see SkillSweep.self_excluded_skills docstring — sorted, same as report.py's
    # own self_excluded rendering and sbom.py's self_excluded_skills, for deterministic
    # output.
    sweep.self_excluded_skills = sorted(set(getattr(ctx, "self_excluded_skills", None) or []))
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
            if sweep.self_excluded_skills:
                note_icon = "[i]" if ascii_only else "ℹ️ "
                _emit(f"   {note_icon}" + self_excluded_line(
                    _sanitize(n) for n in sweep.self_excluded_skills))
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
            # B-629: this site is where the disclosure was invented; it now shares one
            # implementation with the two that used to cut silently, so a fourth site
            # cannot inherit the cut without the notice.
            bullet = "*" if ascii_only else "•"
            lines.append("    Evidence:")
            lines.extend(
                _evidence_bullets(f.evidence, limit=12, indent="      ", bullet=bullet)
            )
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
    # B-521: same disclosure report.py's text inventory already carries for the
    # "skills" subject (report.py:1995-1998 / 2040-2043) — reused verbatim rather
    # than invented fresh, so the sweep table and the inventory never disagree about
    # whether ClawSecCheck's own copy is a silently-shrunk count or a named exclusion.
    if sweep.self_excluded_skills:
        note_icon = "[i]" if ascii_only else "ℹ️ "
        lines.append(f"   {note_icon}" + self_excluded_line(
            _sanitize(n) for n in sweep.self_excluded_skills))
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
                        behavioral_ran: bool = False, behavioral_analysis: dict | None = None,
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
    `--dashboard --full`). A `--full --badge`/`--html`/`--sarif`/`--risk-paths` run
    (or any of `--trend`/`--monitor`/`--percentile`/`--next`) never runs the sweep
    or the behavioral replay at all — `--full` is a documented no-op for every one
    of them — so a call from `_main`'s early, pre-dispatch path (C-426) always
    leaves this False and gets exactly the "no phases added" bare-run ledger
    ``to_ledger()`` already produces correctly (static ran, everything else
    not_reached/unavailable per its own docstring).

    **B-723 (retracted argument):** this function used to ALSO mark
    :data:`~clawseccheck.pipeline.PHASE_SKILL_SWEEP` and
    :data:`~clawseccheck.pipeline.PHASE_PLUGIN_SWEEP` ``ran`` right here, on the
    strength of ``commit_full_phases`` alone — the reasoning above (a caller that
    has "committed" to running them later in the same invocation) sounded like
    enough of a promise to justify it. It was not: the letter grade a ``ran``
    ``installed_sweep`` layer unlocks is a claim about a sweep the caller had not
    yet observed complete — an intention recorded as an outcome, which is exactly
    the guessed-PASS Golden Rule #4 forbids, just one layer up from a single
    check. This function now leaves those two phases OUT of the ledger entirely
    when ``commit_full_phases`` is set (non-`--fast`); ``PipelineResult.to_ledger``
    already derives the honest ``STATUS_NOT_REACHED`` for a phase absent from
    ``self.phases`` (``pipeline.py:1411-1412``), so simply not adding the promise is
    the whole fix — no new status invented. The caller that made the promise
    (``_main``'s `--full --json` branch) is responsible for RE-PROJECTING the
    ledger from the real ``pipeline.PipelineResult`` — via that object's own
    ``to_ledger(...)`` — once ``pipeline.run_pipeline`` has actually executed the
    sweep, and recomputing ``score`` against it before anything is rendered. The
    behavioral phase below is unaffected and stays exactly as it was: it is marked
    from ``behavioral_ran``, which reflects a replay this function's OWN caller has
    ALREADY run (paid for, not merely scheduled) by the time it calls this
    function — an observed outcome, not a promise.

    ``behavioral_analysis`` — B-558: the raw ``behavioral.analyze(ctx)`` result, when
    this invocation actually ran it (paired with ``behavioral_ran=True``). Threaded
    straight through to ``to_ledger`` unchanged; this function does not interpret it
    itself — see that method's own docstring for the coverage rule it drives.

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
            # B-723: no PHASE_SKILL_SWEEP/PHASE_PLUGIN_SWEEP entries here any more —
            # see the retracted-argument paragraph above. Leaving both phases OUT
            # of `prelim` makes `to_ledger` derive STATUS_NOT_REACHED for
            # `installed_sweep` on its own; the caller re-projects from the real
            # `pipeline.PipelineResult` once the sweep has actually run.
            prelim.add(_pipeline.PhaseResult(
                name=_pipeline.PHASE_BEHAVIORAL,
                status=_pipeline.STATUS_RAN if behavioral_ran else _pipeline.STATUS_ERROR,
                detail=("behavioral replay completed." if behavioral_ran
                        else "behavioral replay raised — see run_behavioral's own section.")))
    return prelim.to_ledger(findings, degraded_count=degraded_count,
                            attestation=attestation, live_test_bucket=live_test_bucket,
                            behavioral_analysis=behavioral_analysis)


def _last_complete_history_row(path=None):
    """The most recent history row a COMPLETE check produced, or ``None`` (B-578).

    The discriminator is ``score is not None``, NOT ``"score" in row``. history.py's own
    note says an ungraded row omits the key; the rows on this machine write it as
    ``null`` alongside ``"graded": false``, so a membership test counts every ungraded
    row as rankable. Measured against the real store: 4,678 rows, of which key-presence
    calls 4,678 graded and ``score is not None`` calls 4,193 — the 485-row difference is
    exactly the ungraded runs this must never rank. Both the null check and the
    ``graded`` flag agree on 4,193; the null check is primary because it also covers rows
    written before the flag existed.

    A bool is rejected explicitly: ``isinstance(True, int)`` is True in Python, so a
    malformed row carrying ``"score": true`` would otherwise rank as 1/100.
    """
    rows, _problem = history_load_with_problem(path) if path else history_load_with_problem()
    for row in reversed(list(rows or ())):
        if not isinstance(row, dict) or row.get("graded") is False:
            continue
        value = row.get("score")
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        if 0 <= value <= 100:
            return row
    return None


def _percentile_line(score, ascii_only: bool, history_path=None) -> str:
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

    B-578: withholding was correct, but it was ALSO the only thing this mode could ever
    do. `--percentile` does not honor `--full`, and `graded` is True only once the
    five-layer ledger is complete, which only a `--full` run reaches — so the rank branch
    was unreachable from every documented invocation and the reference distribution was
    dead code. Worse, the message told the user to "complete the remaining layers",
    which is an instruction this mode rejects.

    So an ungraded run now ranks the most recent COMPLETE check from local history,
    labelled with that check's own date and never attributed to this run. What is
    deliberately NOT done is falling back to `score.score` on an ungraded ScoreResult:
    that number exists internally and publishing it is precisely the leak the first
    paragraph describes. Ranking a score some complete check actually produced is a
    different act from inventing one for a run that has none.

    This is the first time this mode reads local history, but it introduces no
    ordering dependency: `percentile.py` ranks against a BUILT-IN reference CDF and
    never reads history (see its module docstring), so history supplies only the score,
    never the distribution. The `--percentile` call site also emits before recording, so
    the current run's own row cannot be the one ranked.
    """
    # B-696: BOTH ungraded branches compose their own prose — an em dash of their own,
    # plus `_missing_layers_sentence`, whose "No grade yet — N of 5 layers…" carries two
    # more — and neither folded, so `--percentile` and `--trend` (which prints this line)
    # emitted non-ASCII under `--ascii`. Predates B-691; found by the guard B-696 added
    # for B-691's own leak, which is the point of adding it. The graded branch below was
    # always clean because `render_percentile` folds at its own exit — this brings the two
    # early returns to the same discipline rather than adding a second rule per branch.
    if not getattr(score, "graded", True):
        opened = _missing_layers_sentence(score)
        row = _last_complete_history_row(history_path)
        if row is None:
            text = (
                f"{opened} No rank yet — a percentile compares a score against a "
                "reference profile of complete audits, and no complete check has been "
                f"recorded here yet. Run '{command_prefix()} --full' to complete one, then "
                "'--percentile' to rank it."
            )
        else:
            when = row.get("date") or row.get("ts") or "an earlier run"
            text = (
                f"{opened} Ranking your last COMPLETE check instead — {when}, scored "
                f"{row['score']}/100, not this run: "
                f"{render_percentile(row['score'], ascii_only)}"
            )
        return asciify(text) if ascii_only else text
    return render_percentile(score.score, ascii_only)


def _sweep_not_folded_clause(score) -> str:
    """B-536: the middle clause of the SKILL SWEEP header's "visibility only" sentence.

    The sentence exists to carry ONE fact — a per-skill sweep verdict never moves the
    audit's own number — and that fact is true whether or not a number exists. So the
    fact survives in both branches and only the *noun* moves, exactly as
    `report._degraded_incomplete_clause` moves only its trailing clause.

    What moves, and why: ``the score or grade above`` is deixis, and on a `graded=False`
    run there is no score and no grade above it to point at (C-423 removed both from
    every renderer). The reader is sent hunting up the page for a figure this run
    deliberately refused to print, and the only "score" they find on the way is the
    tamper posture, which carries its own "not this run's verdict" disclaimer. The
    ungraded wording therefore states the same mechanism rule without pointing anywhere.

    Deliberately NOT one invariant wording for both branches. A graded run really does
    print a score and a grade a few lines up, and naming them is what tells that reader
    *which* number the sweep leaves alone — collapsing to a single pointer-free sentence
    would trade a false claim on one run shape for a vaguer one on the other, which is
    the swap this increment is supposed to avoid, not perform.

    `getattr` default matches every other `graded` read in this module (and in
    `report.py`): a duck-typed ScoreResult stand-in with no `graded` attribute reads as
    graded, which is `scoring.compute`'s own `ledger=None` contract.
    """
    return ("the score or grade above"
            if getattr(score, "graded", True)
            else "the audit's score or grade")


def _resolve_runtime_caps(ctx, findings, score, args, *, attestation=None):
    """F-153: shared by `--full`'s own cap computation and `--dashboard --full`'s —
    the exact same two cap-only signals (F-154 behavioral, F-155 live-injection),
    computed identically, so the two output surfaces can never show a different
    grade for the same run. Pure extraction of the pre-existing `--full` logic;
    behaviour is unchanged for that call site.

    Returns `(score, full_deadline, judged_bundle, live_signal, behavioral_fired_ids,
    ledger, live_test_bucket, behavioral_analysis)`. The last two (B-723) are this
    function's own internal inputs to `_build_layer_ledger`, threaded OUT rather than
    left as locals: a caller that later re-projects the ledger from a real
    `pipeline.PipelineResult` (once the sweep this function only promised has actually
    run) needs the SAME `live_test_bucket`/`behavioral_analysis` this function's own
    `to_ledger` call used, not a second, independently re-derived copy of either.
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
    _behavioral_analysis: dict | None = None
    if args.full and not args.fast:
        try:
            # B-558: keep the analysis this call already produced instead of dropping
            # it — it is the ledger's only source for logs_trajectories coverage
            # (PipelineResult.to_ledger's behavioral_analysis kwarg), so a caller
            # re-deriving it would be a second, driftable read of the same trajectory
            # sidecar.
            _behavioral_analysis = _behavioral_analyze(ctx)
            behavioral_fired_ids = _behavioral_grade_cap_signal(_behavioral_analysis)
            _behavioral_ran = True
        except Exception:  # noqa: BLE001 — see run_behavioral's identical containment
            behavioral_fired_ids = frozenset()
            _behavioral_analysis = None

    # C-425/C-426: build the five-layer ledger via the ONE shared producer
    # (`_build_layer_ledger`) — see that function's own docstring for why
    # `commit_full_phases` (not a bare `args.full` read) is what decides whether the
    # installed-sweep/behavioral phases are marked "ran": THIS call site is exactly
    # the one that has committed to running them later in the same invocation, so it
    # opts in on the same `args.full` gate the pre-extraction code used.
    ledger = _build_layer_ledger(
        args, findings, degraded_count=score.degraded_count, attestation=attestation,
        live_test_bucket=live_test_bucket, behavioral_ran=_behavioral_ran,
        behavioral_analysis=_behavioral_analysis, commit_full_phases=args.full,
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
    return (score, full_deadline, judged_bundle, live_signal, behavioral_fired_ids, ledger,
            live_test_bucket, _behavioral_analysis)


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
    # B-681: the named subject does not exist, so there is nothing to render a verdict
    # about. Before this, `--vet-mcp <typo>` printed "RISK DOSSIER — mcp '<typo>'
    # CAUTION" over five UNKNOWN axes and returned 0 — the code a CLEAN vet returns — so
    # a caller branching on `$?` was told "I checked it and there is nothing to act on"
    # about a server that was never found. That failure direction is toward silence,
    # which is worse than B-680's original shape: that one at least exited non-zero.
    #
    # 2 is the same usage-error code B-680 gave the three path-taking vet modes and that
    # `_empty_mode_target` already answers for `--vet-mcp`'s neighbours. The signal is a
    # declared field on the finding, not its `detail` text: an exit-code contract keyed
    # on a sentence would break the first time the sentence was reworded.
    #
    # The no-target form ("every configured server") cannot reach this — `vet_mcp` only
    # sets the flag on the target-is-a-name branch — and a server that IS configured but
    # cannot be assessed keeps its UNKNOWN dossier at its usual code. Those two are the
    # lines this must not cross.
    if any(getattr(f, "subject_absent", False) for f in findings):
        print(
            f"--vet-mcp: cannot assess '{target}' — no configured MCP server by that "
            "name, and no readable spec file at that path. No verdict was produced.",
            file=sys.stderr,
        )
        return 2
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

# F-175 tier 3. A backstop against a pathological tree, not a budget: `vet_skill` averages
# 0.010 s across the fixture corpus, so the cap is nowhere near binding in ordinary use.
# When it does bite it is disclosed, because a silent top-N reads as "everything that
# changed was checked".
_REVET_CAP = 10

# What a re-check verdict is worth as a drift alert. PASS is deliberately absent: a skill
# that changed and still looks clean is not news — the CHANGE is already reported — and a
# line per clean re-check would train the reader to skip the block that carries the FAILs.
_REVET_SEVERITY = {"FAIL": HIGH, "WARN": MEDIUM, UNKNOWN: "INFO"}

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
    ("verify_baseline", "--verify-baseline", "opt"),
    ("vet_plan", "--vet-plan", "opt"),
    ("menu", "--menu", "bool"),
    ("brief", "--brief", "bool"),
    ("cron_recipe", "--cron-recipe", "bool"),
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

#: Modes that are a SIDE OUTPUT when `--dashboard` also runs, rather than racing it
#: (C-373/C-374 for `--pdf`; B-586 added the other three). Their file is written from the
#: dashboard's own audit, which is the only non-default path that actually runs the
#: installed-skill/plugin sweep — and therefore the only one that can honestly reach a
#: complete five-layer ledger.
_DASHBOARD_SIDE_OUTPUTS = frozenset({"pdf", "badge", "html", "sarif"})

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
    # B-584: the artifact-rendering modes honor the CI gate. They all run the base audit
    # and can answer "did it find an unsuppressed FAIL" exactly as the default report path
    # does; refusing was never a decision, it was `_MODE_HONORS` being an allowlist that
    # nobody extended. Same move C-419 made for --monitor, and for the same reason: an
    # honest refusal on stderr is still a gate that does not gate.
    "dashboard": frozenset({"full", "compact", "exit_code", "fail_on"}),
    # C-374: --pdf wins the mode race over --dashboard (it is earlier in _PRIMARY_MODES),
    # but both are honored now — and under `--dashboard --full --pdf` the --full phases
    # are what the PDF's pipeline blocks are rendered FROM, so --full genuinely has an
    # effect here. Saying "no effect" was true of the findings-only PDF, not this one.
    "pdf": frozenset({"full", "compact", "exit_code", "fail_on"}),
    # F-155 fix (C-135): --judged-bundle's `liveTest` bucket now caps the score
    # reaching --trend/--monitor too (see _apply_live_test_cap) — a SEPARATE honor
    # from "full", deliberately not folded into it the way --dashboard's is: --full/
    # --quiet/--fast genuinely still have no effect here (no deep phase ever runs for
    # --trend/--monitor), only --judged-bundle does, so the "full"-bundle no_effect
    # check below is given its own "judged_bundle" escape hatch rather than reusing
    # "full" (which would wrongly silence the still-true --full/--quiet/--fast notes).
    # B-584: --sarif is the documented CI artifact (docs/USAGE.md's "Gate my CI on this"
    # row names it with --fail-on/--exit-code in the same breath); --badge/--html write
    # the other two report artifacts on the same audit.
    "sarif": frozenset({"exit_code", "fail_on"}),
    "badge": frozenset({"exit_code", "fail_on"}),
    "html": frozenset({"exit_code", "fail_on"}),
    "trend": frozenset({"judged_bundle"}),
    # C-419: --exit-code / --fail-on were ALREADY flags; --monitor simply refused them and
    # said so via the no-effect note. Honouring them here is what turns that honest refusal
    # into a working machine channel, without inventing a second flag with different
    # semantics in a different mode.
    # F-176: "json" joined the same way — --monitor --json used to be silently dropped
    # (the no-effect note fired and no payload was ever built). See the `if args.json:`
    # branch in the "monitor" mode dispatch for the payload shape.
    # F-180: "probe" is a monitor-only modifier — it suppresses the three writes so a
    # frequent poll does not consume the drift it is polling for.
    "monitor": frozenset({"judged_bundle", "exit_code", "fail_on", "json", "probe"}),
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


# C-426 part B: mode flags that take a REQUIRED value, so an empty one is a malformed
# invocation rather than a mode. `--vet-mcp`, `--analyze-trajectory` and `--behavioral`
# are deliberately absent: each is declared nargs="?" const="", so an empty value is its
# documented "everything of this kind" form, not a missing argument.
#
# This list is what makes _mode_active's `is not None` safe as the single dispatch
# predicate. The branches it selects test truthiness, so before this check existed the
# two disagreed for every opt mode given "" — 182 argv shapes, of which `--badge ""`
# printing a full default report at rc=0 was the visible one. Rejecting the empty value
# up front removes the disagreement instead of encoding it twice.
_VALUE_REQUIRED_MODES = tuple(
    (flag, attr) for attr, flag, kind in _PRIMARY_MODES
    if kind == "opt" and attr not in ("vet_mcp", "analyze_trajectory", "behavioral")
)


def _describe_os_error(exc: OSError, *, what: str = "file") -> str:
    """A short human reason for an ``OSError`` raised reading a user-named path.

    The single classifier for every "you named a file I could not open" message in this
    module (B-561's three verdicts flags, B-562's ``--judged-bundle`` and
    ``--apply-ignore-proposals``). It lives here rather than in a leaf because it is
    presentation — ``pipeline`` hands back the exception and lets the shell word it, which
    is the same direction every other renderer runs.

    Deliberately no ``FileNotFoundError``-vs-``NotADirectoryError`` split: to a user who
    mistyped a path they read the same, and inventing a distinction the message cannot act
    on is noise.
    """
    if isinstance(exc, FileNotFoundError):
        return "no such file or directory"
    if isinstance(exc, IsADirectoryError):
        return f"is a directory, not a {what}"
    return _sanitize(exc.strerror or str(exc))


def _path_problem_text(raw_path, exc: OSError, *, what: str) -> str:
    """``"<path>: <reason>"`` for a user-named path that could not be read.

    An EMPTY argument is its own case, and this is the C-135 finding on B-562 rather than
    foresight. ``Path("")`` normalizes to ``Path(".")``, so the OS reports on the CURRENT
    DIRECTORY — something the user never typed — and the composed line read

        note: --judged-bundle: : is a directory, not a bundle file.

    which names nothing and blames the wrong thing. Reachable only for
    ``--judged-bundle``: an empty value for ``--judged``/``--propose-ignore`` is already
    rejected up front by ``_VALUE_REQUIRED_MODES`` (rc 2), which that list can do because
    those two are primary MODES. ``--judged-bundle`` modifies a run rather than being one,
    so aborting a whole ``--full`` audit over it would be the harsher answer; it is
    reported and the run continues, as with every other unreadable path here.

    B-581: also runs the composed line through ``report._redact_home_paths``. A path a
    user types on the command line routinely embeds their OS username (``/home/dave/…``,
    ``~dave/…`` post-expanduser) and this text reaches stderr on every call site that
    uses it — CLAUDE.md §8 ("No PII... in logs") is not scoped to the dashboard card
    ``_redact_home_paths`` was first written for; that scope note describes its first
    caller, not a limit on the function. Widening the classifier closes the hole at
    ALL of its call sites at once (this file's five pre-existing ones plus B-581's two
    new ones) instead of folding redaction in only at the new sites, which would leave
    the old ones still leaking and duplicate the redaction decision per call site.
    """
    if not str(raw_path).strip():
        return "no path was given"
    return _redact_home_paths(f"{_sanitize(str(raw_path))}: {_describe_os_error(exc, what=what)}")


class UnusableInputPath(Exception):
    """A file the user named exists but could not be turned into text at all.

    B-684. Two shapes reach here, and B-561 decided — correctly — that both must stay
    LOUD rather than degrade to the `note:` an OSError gets: a non-zero exit, empty
    stdout, no artifact. Turning them into a note would hand back a normal-looking rc 0
    report to someone who pointed the tool at the wrong file.

    What B-561 explicitly left for later is what this class is for: *"Naming the path in
    them is a separate improvement to the crash handler, not this one."* Until now the
    failure was loud and anonymous — no path, no reason, only an exception class name,
    and an invitation to open an issue about the caller's own typo. Being loud and being
    a bug report are different things.

    Carries the composed, redacted text rather than the raw path, so the handler prints
    it without needing to know which reader raised.
    """

    def __init__(self, raw_path, reason: str):
        self.raw_path = raw_path
        self.reason = reason
        self.text = _unusable_path_text(raw_path, reason)
        super().__init__(self.text)


def _unusable_path_text(raw_path, reason: str) -> str:
    """``"<path>: <reason>"`` for a user-named file that could not be decoded.

    The `_path_problem_text` composition minus `_describe_os_error`, because there is no
    errno here — the same `_sanitize` + `_redact_home_paths` pair, for the same B-581
    reason: a path typed on the command line routinely embeds the operator's OS username
    and this text reaches stderr unconditionally.
    """
    if not str(raw_path).strip():
        return "no path was given"
    return _redact_home_paths(f"{_sanitize(str(raw_path))}: {reason}")


def _read_verdicts_payload(raw_path: str) -> "tuple[str, str | None]":
    """``(payload, problem)`` for a judge-verdicts path. *problem* is None when it was read.

    B-561: all three judge-feedback flags did ``except OSError: verdicts_raw = ""``, so a
    path that could not be read became an EMPTY payload and the path was never named —
    not on stdout, not on stderr, not once, in any of the three.

    Scope is exactly the ``OSError`` family, and deliberately no wider. Two shapes reach
    the generic crash handler instead, in this tree and before it alike:

    * ``~nosuchuser/x.json`` — ``expanduser()`` raises ``RuntimeError``, not ``OSError``.
    * an existing file holding invalid UTF-8 — ``UnicodeDecodeError``.

    An earlier draft caught the first one. That was wrong in the direction this whole
    task is about: it turned a LOUD failure (``rc 1``, empty stdout, "unexpected internal
    error") into a quiet ``rc 0`` full report. B-561 exists to make silent failures
    audible, so trading a crash for a note is the reverse of it, and it moved the exit
    code and the artifact — the one thing the narrowed fix promises not to do. Both
    shapes stay loud. Naming the path in them is a separate improvement to the crash
    handler, not this one.

    ``-`` reads stdin, unchanged.
    """
    if raw_path == "-":
        return sys.stdin.read(), None
    try:
        return Path(raw_path).expanduser().read_text(encoding="utf-8"), None
    except OSError as exc:
        return "", _path_problem_text(raw_path, exc, what="verdicts file")
    except UnicodeDecodeError:
        # B-684: still loud — this returns nothing, it raises. See UnusableInputPath for
        # why widening the OSError arm to cover this would undo B-561, and why naming the
        # file was the part B-561 deferred rather than the part it settled.
        raise UnusableInputPath(
            raw_path, "not valid UTF-8 text (a binary file?), so it holds no verdicts"
        ) from None
    except RuntimeError:
        # `~nosuchuser/x.json` — expanduser() raises this, not OSError. The other shape
        # B-561 names, and the same answer.
        raise UnusableInputPath(
            raw_path, "the '~user' in it names no account on this machine"
        ) from None


def _verdicts_with_note(raw_path: str, flag: str) -> str:
    """The payload for a judge-verdicts flag. An unreadable path is REPORTED, not hidden.

    stdout, the artifact and the exit code are deliberately unchanged — the run continues
    exactly as it did before, as if no verdicts had been submitted. Only the silence goes
    away. That narrow scope is the whole point:

    `docs/OUTPUT_SCHEMA.md` §13 promises that "an explicitly empty ``"verdicts": []``, an
    empty payload, or an unreadable PATH stays quiet: those genuinely are 'no verdicts
    submitted'", and `adjudication._payload_carries_content` says the same in code. That
    promise is right for the first two and wrong for the third, and the reason is visible
    in its own justification: the existing `note:` exists to tell "0 of N applied" apart
    from "no verdicts submitted", and an unreadable path is a THIRD case that dichotomy
    has no room for. An empty payload is a statement — the judge submitted nothing. An
    unreadable path is the ABSENCE of a statement: nothing at all is known about what the
    judge decided, and the user believes they said something.

    So the fix is to split the two where the difference is actually known. `adjudication`
    cannot: by the time it sees ``""`` the reason is gone. The CLI can, because it did the
    read. Its parser's contract ("a genuinely empty payload stays silent") is untouched.

    Reporting is all this does, and it is deliberately less than the first attempt at
    B-561, which refused to run and exited 1. That broke three tests asserting the
    documented degradation and would have destroyed the ``--vet`` verdict the user also
    asked for. `note:` matches `adjudication._note`'s prefix and stream so the three
    diagnostics a verdicts file can produce read as one family.
    """
    payload, problem = _read_verdicts_payload(raw_path)
    if problem is not None:
        print(f"note: {flag}: {problem}. Nothing was judged; continuing as if no verdicts "
              "had been submitted.", file=sys.stderr)
    return payload


def _unassessable_target(typed) -> "str | None":
    """Why a user-named path cannot be assessed AT ALL, or None if it can be reached.

    B-680: a target that is not there is a USAGE error, not a verdict. `--vet
    <workspace>/skills/browser-automation` -- a name the audit's own inventory had just
    listed as clean, because those skills live inside a plugin and that standalone path
    does not exist -- printed "RISK DOSSIER — skill 'browser-automation'  CAUTION" over
    five UNKNOWN axes and returned 1, the same code a genuinely suspicious skill returns.
    Nothing downstream could tell a mistyped path from a finding, and CAUTION — a word
    about software — was spent on a path with no software at all.

    The test is the raised errno, not `.exists()`: `.exists()` collapses "not there", "a
    link to nothing" and "I am not allowed to look" into one False, and answering "there
    is nothing there" to the last two would be a second lying verdict. Each gets its own
    sentence. Any other OSError returns None and leaves today's dossier, which prints the
    reason in full.

    The permission arm is not merely a wrong verdict: `resolve_skill_target` calls
    `Path.is_file()`, which does NOT swallow EACCES, so an unreadable parent reached the
    top-level handler and printed "unexpected internal error (PermissionError) ... open an
    issue" — the tool asking to be bug-reported for the user's own directory mode.
    """
    target_path = Path(str(typed)).expanduser()
    try:
        os.stat(target_path)  # follows symlinks: "is there something here to read?"
    except (FileNotFoundError, NotADirectoryError):
        try:
            os.lstat(target_path)
        except OSError:
            return "no such file or directory"
        # lstat saw it, stat did not: a symlink whose target is gone. Saying "no such
        # file" here would be wrong — the link IS there.
        return "the symlink there points at a path that does not exist"
    except PermissionError:
        return "permission denied"
    except OSError:
        return None  # e.g. a symlink loop: still assessable-ish, leave today's dossier
    return None


def _report_unassessable(flag: str, typed, why: str, undetermined: "str | None" = None) -> int:
    """Print why nothing could be assessed and return the usage-error code.

    rc=2, not a fourth code: this is the family `_empty_mode_target` below already answers
    2 for (`--vet ""`), and it is argparse's own usage-error code. The reason --monitor
    refused 2 for drift was the mirror image of this rule — a finding must not wear the
    usage-error code — so it argues for 2 here, not against it. All three reasons share
    it; a caller that must tell a typo from a chmod reads the message, exactly as it would
    for argparse's own several rc=2 messages.

    stdout stays empty on purpose. It is the channel a pipeline parses, and a dossier
    there says a subject was examined.
    """
    # B-682: when the classifier could not read the config, "no such file or directory"
    # is true and incomplete — the "is this a configured MCP server?" question was never
    # asked, so answering only about the path would state one fact and imply another that
    # was never established. Redacted, because we composed this path ourselves and it
    # carries the operator's home (B-581); the typed target is echoed as given, since that
    # is what the user needs to see to spot their own typo.
    if undetermined:
        why = f"{why}, and {_redact_home_paths(undetermined)}"
    # The hint is for the shape that actually sent this bug in — a skill name the audit
    # listed as clean, typed as a path it never had. It would be noise on a link to
    # nothing, on a directory mode, or where an unread config is the better explanation,
    # so it is tied to the reason.
    tail = (
        " A skill bundled inside a plugin has no standalone path — vet the plugin instead."
        if why == "no such file or directory"
        else ""
    )
    print(f"{flag}: cannot assess {typed} — {why}. No verdict was produced.{tail}",
          file=sys.stderr)
    return 2


def _empty_mode_target(args):
    """The first mode flag given an empty value, or None. Never mutates args."""
    for flag, attr in _VALUE_REQUIRED_MODES:
        v = getattr(args, attr, None)
        if v is not None and not str(v).strip():
            return flag
    return None


_MODE_ORDER = [attr for attr, _flag, _kind in _PRIMARY_MODES]
# Attribute -> the flag the user typed, derived from the SAME table so a note naming the
# winning mode cannot invent a spelling (`--dashboard_findings`) no parser accepts.
_MODE_FLAG = {attr: flag for attr, flag, _kind in _PRIMARY_MODES}


def _write_dashboard_side_outputs(args, findings, score, ctx, report_dest, emit) -> None:
    """B-586: write `--badge`/`--html`/`--sarif` as side outputs of a `--dashboard` run.

    These three used to WIN the mode race against `--dashboard`, run their own bare
    audit and render that. So the documented complete check —
    `--dashboard --full --attest a.json --judged-bundle b.json --badge b.svg` — wrote
    `no grade yet` into the one artifact whose entire purpose is sharing a grade, while
    `--save`/`--card` on the same command line reported `F 49/100`. `SKILL.md` offers
    "share grade — `--badge grade.svg` or `--card`" as one line; only half of it could.

    Composition rather than honouring `--full` inside those modes, because
    `_build_layer_ledger`'s `commit_full_phases` is a promise the caller has to keep: a
    bare `--badge --full` never runs the installed-skill/plugin sweep, and marking those
    phases "ran" for it would fabricate a completed sweep (Golden Rule #4). The dashboard
    path genuinely runs them, so the artifact rides that instead.

    Call this only where *score* is FINAL for the path in question — before
    `_resolve_runtime_caps`, `score` is still the bare-ledger one and every artifact
    would report an ungraded run that has since been graded.

    A failed write is reported and does not stop the card: the dashboard is the
    deliverable and the file is its delivery (B-459's rule, applied to the riders).
    """
    for value, label, render in (
        (getattr(args, "badge", None), "badge", lambda: render_svg(score, findings)),
        (getattr(args, "html", None), "HTML report",
         lambda: render_html(findings, score, native=ctx.native, ctx=ctx)),
        (getattr(args, "sarif", None), "SARIF",
         lambda: render_sarif(findings, score, __version__, ctx=ctx)),
    ):
        if not value:
            continue
        try:
            secure_write_text(report_dest(value), render())
            emit(f"({label} written to {value})")
        except OSError as exc:
            emit(f"(could not write {label}: {exc})")


def _pdf_is_produced(args, win_attr) -> bool:
    """Is --pdf's file actually written on this run, alongside *win_attr*'s own output?

    C-373/C-374 make `--pdf` COMPOSE with `--dashboard` instead of racing it, so calling
    it "ignored" would be a lie — but only when the winning mode gets as far as the
    write. One way it does not, and it must keep `--pdf` in the ignored list because it
    was asked for and never produced (B-067 is exactly this): a mode declared BEFORE
    `--pdf` wins and returns first — `--badge b.svg --pdf p.pdf --dashboard` writes a
    badge and no PDF.

    B-530 removed the second way. Under `--full` the write used to be DEFERRED into the
    dashboard branch unconditionally, so a rider that beat it (`--trend`/`--percentile`/
    `--next`) meant it never happened — a real lost file this predicate could only report
    after the fact. Deferral is now conditioned on the dashboard being the elected mode,
    so a rider gets the reduced (findings-only) PDF written at the `--pdf` site, disclosed
    by both the document's own C-423 ledger page and a stderr note. So there is no
    `--full` case left to special-case: past the ordering test above, the file is written.
    """
    return _side_output_is_produced(args, "pdf", win_attr)


def _side_output_is_produced(args, attr, win_attr) -> bool:
    """Generalisation of the above for every `_DASHBOARD_SIDE_OUTPUTS` member (B-586).

    All four are written from the same place in the cascade — the block just above
    `--pdf`'s own write — so the ordering rule `_pdf_is_produced` documents applies to
    each of them unchanged: a mode declared BEFORE that point wins and returns first, and
    the file is genuinely never produced. Measured: `--risk-paths --dashboard --badge
    b.svg --pdf p.pdf` writes neither, and both stay in the ignored note.

    Keyed on `"pdf"`'s index rather than each flag's own, because the index that matters
    is the WRITE SITE's, not the flag's position in the mode table.
    """
    if not (getattr(args, attr, None) and bool(getattr(args, "dashboard", False))):
        return False
    if win_attr not in _MODE_ORDER:
        return False
    if _MODE_ORDER.index(win_attr) < _MODE_ORDER.index("pdf"):
        return False
    return True


def _select_primary_mode(args, skip=frozenset()):
    """The mode _PRIMARY_MODES elects, in table order. Single source of truth."""
    for attr, _flag, kind in _PRIMARY_MODES:
        if attr not in skip and _mode_active(args, attr, kind):
            return attr
    return None


def _resolve_mode(args):
    """Which mode actually runs — the table's verdict, with --pdf's composition applied.

    C-426 part B. Dispatch used to be decided by the physical order of _main()'s
    if-cascade while this table only NAMED the winner for the coherence notes. Keeping
    two mechanisms in agreement was left to a test, and B-276 caught them disagreeing in
    27 pairs. Both now read this one function, so "which mode runs" and "which mode the
    note names" cannot differ by construction.

    The one thing the table cannot express is that the export artifacts COMPOSE with
    `--dashboard` rather than racing it (C-373/C-374): with both flags the file is a side
    output and the dashboard — or `--trend`/`--percentile`/`--next`, when asked for — is
    what renders. In the cascade that came out of `--pdf`'s branch not returning, so
    control fell through to whichever branch came next. Resolving it here, once, is what
    lets every branch below ask a plain `_mode == "..."` question; leaving it implicit is
    why `--dashboard --pdf out.pdf --trend` printed "note: --trend ignored (running
    --pdf)" on a run where `--trend` was exactly what ran.

    B-586: `--badge`/`--html`/`--sarif` join `--pdf` in that composition, because racing
    it was what made a graded badge unreachable. Each of them won the race, ran its own
    BARE audit and rendered that — so `--dashboard --full --attest --judged-bundle
    --badge b.svg`, the documented complete check, wrote `no grade yet` into the one
    artifact meant for sharing a grade, while `--save`/`--card` on the same command line
    reported `F 49/100`.

    Composition is the only sound fix, and `_build_layer_ledger`'s own docstring says
    why: marking the sweep phases "ran" is a promise the caller must keep, and a bare
    `--badge --full` never runs them. Honouring `--full` inside those modes would
    fabricate a completed sweep — Golden Rule #4 — so the artifact instead rides the one
    path that genuinely runs it. A bare `--badge --full` (no `--dashboard`) therefore
    still says `--full` has no effect, exactly as C-374 decided for `--pdf`.
    """
    mode = _select_primary_mode(args)
    if mode in _DASHBOARD_SIDE_OUTPUTS and bool(getattr(args, "dashboard", False)):
        return _select_primary_mode(args, skip=_DASHBOARD_SIDE_OUTPUTS)
    return mode


def _flag_coherence_notes(args) -> list[str]:
    """Notes for ignored modes / no-effect global modifiers. Never mutates args."""
    active = [(a, f) for a, f, k in _PRIMARY_MODES if _mode_active(args, a, k)]
    # C-426 part B: the winner is whoever _resolve_mode elects — the SAME call _main
    # dispatches on — not merely the first active entry. The two differ only for the
    # --pdf/--dashboard composition, and that difference is the B-276 bug class itself:
    # the run that announced "--trend ignored (running --pdf)" is the run on which
    # --trend was what rendered.
    _winner = _resolve_mode(args)
    active.sort(key=lambda af: af[0] != _winner)
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
        #
        # C-426 part B: _resolve_mode now elects the dashboard (or a --trend/--percentile/
        # --next rider) in that case and leaves --pdf as the side output, so the exemption
        # runs the other way round — but ONLY when the file is genuinely written. An
        # unconditional exemption re-created B-067 in a new place: `--badge b.svg --pdf
        # p.pdf --dashboard` returns from the badge branch having produced no PDF, and
        # would have said nothing about it.
        and not (a == "pdf" and _pdf_is_produced(args, win_attr))
        # B-586: --badge/--html/--sarif compose with --dashboard on the same terms and
        # from the same write site, so they take the same predicate — including its
        # ordering guard, which is what keeps a genuinely-lost file (an earlier mode
        # returned first) in this list instead of exempting it into silence.
        and not (a in _DASHBOARD_SIDE_OUTPUTS and _side_output_is_produced(args, a, win_attr))
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

    Resolves the store directory from --history's parent (all _PURGE_FILENAMES
    entries — the four store files plus the four default report-renderer
    filenames, see that constant's comment for why — live alongside each other
    under ~/.clawseccheck/ by default). Operates ONLY on that fixed whitelist
    plus their ".lock" sidecars — never globs or rmtree's the directory, so an
    unrelated file the user happens to keep there is never at risk. Read-only
    until the user (or --yes) confirms.
    """
    store_dir = _store_dir(args)
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
        # B-562: this always reported and exited 1, so it was never the silent failure
        # its two siblings were — but it printed only the exception CLASS
        # ("could not read proposals file (FileNotFoundError)"), so the user could not
        # tell WHICH path failed, which is the half of B-561 that actually mattered.
        _emit(f"clawseccheck: could not read the proposals file "
              f"{_sanitize(str(args.apply_ignore_proposals))}: "
              f"{_describe_os_error(exc, what='proposals file')}.")
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


def _chain_verdict(label: str, path: str, ok: "bool | None", msg: str,
                   explicit: bool, cause: str = "") -> "tuple[str, int]":
    """Render one of THREE outcomes for a hash-chain verifier (B-589).

    ``--verify-baseline`` (F-173) reasoned this out first and refused the collapse: "it
    does not match" and "I could not check" ask the reader for opposite reactions. The two
    chain verifiers folded the third case into the first, so ``rm history.jsonl`` — the
    crudest tampering there is — printed "History chain OK (...): OK" with exit 0 over a
    file that was never opened, and an attacker erasing the event that recorded their own
    install never had to defeat the hash chain.

    Exit status follows ``--verify-baseline``'s existing convention: 0 only when something
    was actually verified, 1 for both "broken" and "could not check". Those two read very
    differently in the text, deliberately, but they mean the same thing to a script - do
    not proceed as if this was verified. Giving "could not check" its own exit code would
    just move the collapse into a place no shell idiom looks.
    """
    if ok is True:
        return f"{label} chain OK ({path}): {msg}", 0
    if ok is False:
        return f"{label} chain BROKEN ({path}): {msg}", 1
    lines = [f"{label} chain NOT VERIFIED ({path}): {msg}"]
    # WHICH sentence follows is decided by whether anything is actually there, not by
    # whether the user typed the flag. An independent pass caught the first version doing
    # the latter: a default-location store holding 200 overwritten lines was told
    # "nothing usable has been written there yet, which is normal" — a sentence that
    # contradicts the line above it and talks the reader out of the exact tampering the
    # third outcome exists to expose. Getting that reachable only by passing an explicit
    # flag made it unreachable for the common invocation.
    if cause == CHAIN_BAD_PATH:
        # Never the "check its permissions / someone locked this down" sentence: this
        # path cannot name a file at all, so there is nobody to suspect. An earlier
        # version routed ENAMETOOLONG here and accused the user about a file that
        # cannot exist.
        lines.append("This path cannot name a journal file at all, so nothing was looked "
                     "at — check it for a typo. No conclusion about any store follows "
                     "from this.")
    elif cause == CHAIN_UNREADABLE:
        lines.append("Something is at this path and it could not be read. That is not a "
                     "first-run state: check its permissions. A store made unreadable to "
                     "the user auditing it is itself worth investigating, and re-running "
                     "the check that WRITES it would overwrite the evidence \u2014 look "
                     "first.")
    elif cause and cause != CHAIN_ABSENT:
        lines.append("Something is at this path and it is not a usable journal. That is "
                     "not a first-run state \u2014 a store that existed and no longer "
                     "verifies is worth investigating on its own; emptying, truncating or "
                     "overwriting it is the crudest way to erase what it recorded.")
    elif explicit:
        lines.append("You named this path and there is nothing at it, so this is not a "
                     "first-run state: either the path is wrong, or the store it names is "
                     "gone. Deleting a journal is the crudest way to erase what it "
                     "recorded.")
    else:
        # Not "the default location": --data-dir lands here too, and it is not the default.
        lines.append("No journal has been written to this location yet, which is normal "
                     "before the first run that records one. If you have run checks on "
                     "this machine before, it is missing rather than never written.")
    lines.append("Nothing was verified here. This is neither a pass nor a tamper finding, "
                 "and the exit status is non-zero so a script cannot read it as a pass.")
    return "\n".join(lines), 1


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
    except UnusableInputPath as exc:
        # B-684: loud, and now named. The exit code and the empty stdout are deliberately
        # the same ones the generic arm below produces — that is the half B-561 protects,
        # and moving it would trade a wrong verdict for a missing one. What changes is
        # that the message says which file and what was wrong with it, and does NOT ask
        # for a bug report: that banner is for defects in this tool, and a file the user
        # picked is not one.
        raw = list(sys.argv[1:] if argv is None else argv)
        if "--debug" in raw:
            raise
        print(f"clawseccheck: {exc.text}. Nothing was produced; fix the path and re-run.",
              file=sys.stderr)
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
        bundle, problem = _pipeline.read_judged_bundle_with_problem(path)
        if problem is not None:
            # B-562. Inside the cache-miss branch on purpose: three readers ask for this
            # bundle in one run (see the docstring above), and a diagnostic repeated three
            # times reads like three separate failures. The buckets are named because
            # "nothing was applied" understates it — `liveTest` carries a score CAP, so a
            # bundle that never arrives leaves the run scoring higher than it should.
            print(f"note: --judged-bundle: "
                  f"{_path_problem_text(path, problem, what='bundle file')}. Nothing was "
                  "applied; continuing with no attestation, no judge verdicts and no "
                  "live-test signal, including any score cap that file carried.",
                  file=sys.stderr)
        _JUDGED_BUNDLE_CACHE[path] = bundle
    return _JUDGED_BUNDLE_CACHE[path]


def _findings_exit_gate(args, findings, ctx, *, extra_fail: bool = False) -> int:
    """The `--fail-on` / `--exit-code` gate: 1 when it trips, 0 otherwise.

    B-584: extracted so the artifact-rendering modes can reach it. It used to live inline
    at the very end of `_main`, which every early-returning mode branch jumps over — so
    `--sarif results.sarif --fail-on high`, the invocation `docs/USAGE.md` publishes as
    THE CI recipe, exited 0 on a config with three CRITICAL FAILs. A stderr note said the
    flag had no effect, and a green build's stderr is exactly where nobody looks.

    *extra_fail* carries the FAIL sources a caller knows about beyond `findings`
    (`vm_has_fail` / `sweep_has_fail` / `pipeline_has_fail`). It joins **only**
    `--exit-code`'s disjunction, never `--fail-on`: those sources are bare booleans with
    no severity attached, and a severity-gated flag cannot rank what carries no severity.
    A caller that ran no sweep passes nothing — an ABSENT verdict is not a FAIL, which is
    the doctrine the disjunction's own comments already state.
    """
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
        if (has_fail or extra_fail
                or getattr(ctx, "config_parse_error", False)
                or not getattr(ctx, "config_found", True)):
            return 1

    return 0


#: B-606: a bare ``--pdf`` (flag given, no PATH) auto-resolves through
#: ``_default_pdf_target`` instead of requiring a value. Any non-empty string works as
#: the ``nargs="?"`` const EXCEPT the empty one, which ``_VALUE_REQUIRED_MODES`` already
#: treats as a malformed invocation for every "opt" mode — this deliberately is not that
#: string, and is not a value anyone would type as a real filename.
_PDF_AUTO = "\0pdf-auto\0"


def _default_pdf_target(home: str) -> "tuple[str, bool]":
    """Where a bare ``--pdf`` writes, and whether that is the managed root.

    B-606: OpenClaw parses a ``MEDIA:<path>`` directive off the assistant's own reply and
    turns it into a real attachment — documented in OpenClaw's own system prompt, on by
    default — but the path has to be one its read tool can open, and by
    ``toolpolicy.py``'s own measurement most homes deny that for anything outside the
    workspace. ``<home>/media/outbound`` is the one exception: OpenClaw seeds it into the
    allowed roots unconditionally, ahead of every other permission check, because it is
    the runtime's own managed area for outbound attachments — so writing there is the one
    placement with a real chance of being read back.

    The test is existence + writability, nothing else — deliberately not a product
    version: a version number is a fact about the tool that made the directory, not about
    whether THIS install still can, and an unusual host with the directory absent gets
    the honest fallback rather than a default earned from misreading a version string.

    Never CREATES the directory — an explicit, opt-in ``--pdf`` write is what CLAUDE.md
    allows; auto-resolution must not manufacture the very precondition it is testing for.
    """
    managed = Path(home).expanduser() / "media" / "outbound"
    try:
        if managed.is_dir() and os.access(managed, os.W_OK):
            return str(managed / "clawseccheck-report.pdf"), True
    except OSError:
        pass
    return "~/.clawseccheck/report.pdf", False


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
    p.add_argument("--no-dist", action="store_true",
                   help="skip reading the installed OpenClaw package's own version "
                        "(C4 corroborates it against meta.lastTouchedVersion to "
                        "surface a version rollback). Read-only PATH lookup, no subprocess")
    p.add_argument("--save", metavar="PATH", help="also write the report to a file")
    p.add_argument("--monitor", action="store_true",
                   help="monitor mode: alert on what changed since the last check")
    p.add_argument("--probe", action="store_true",
                   help="with --monitor: report drift WITHOUT recording it — writes none "
                        "of the three local files, so the same drift is still reported by "
                        "the next ordinary run. For cheap polling.")
    p.add_argument("--state", default=None, metavar="PATH",
                   help=f"snapshot file for --monitor (default: {DEFAULT_STATE})")
    p.add_argument("--events", default=None, metavar="PATH",
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
    p.add_argument("--pdf", metavar="PATH", nargs="?", const=_PDF_AUTO,
                   help="write the complete audit as a paginated PDF to PATH — attach the "
                        "file itself into chat (a mobile client opens it inline; do not "
                        "paste the path or re-render its contents). Given with no PATH, "
                        "auto-resolves to OpenClaw's managed attachment directory when "
                        "one exists and is writable, else ~/.clawseccheck/report.pdf")
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
                   # B-536 sibling: "the current score" presupposed every run has one.
                   # `_percentile_line` has withheld the rank on an ungraded run since
                   # C-426 ("No rank yet — ... this run has no score"), so the blurb
                   # promised an output the flag already, correctly, declines to print.
                   # Additive, not a narrowing: the graded case still says exactly what
                   # it ranks.
                   help="print offline percentile rank for this run's score, or say why "
                        "there is none, and exit")
    p.add_argument("--history", default=None, metavar="PATH",
                   help=f"path for trend history file (default: {DEFAULT_HISTORY})")
    # NOT `--store`, however much better that reads. `--st` was an unambiguous abbreviation
    # of `--state`, and adding any second `--st*` flag turns it into a hard usage error for
    # someone who passed none of the new flags — the exact regression this task's DoD
    # forbids. No existing flag begins `--dat`, so no working abbreviation changes meaning.
    p.add_argument("--brief", action="store_true",
                   help="is the watch still running, and did it say anything while you "
                        "were away — reads three local files, WRITES NOTHING")
    p.add_argument("--cron-recipe", action="store_true",
                   help="print an OpenClaw cron job that runs the drift check on a "
                        "schedule, for your agent to create — prints only, creates nothing")
    p.add_argument("--data-dir", metavar="DIR", default=None,
                   help="put this run's whole local store under DIR — the monitor state, "
                        "the event journal, the score history AND the coverage/freshness "
                        "ledger. They move together, so a scratch run cannot half-redirect "
                        "and write into your real store. An explicitly given "
                        "--state/--events/--history still wins (the ledger follows "
                        "--history, which is also where --purge looks for it).")
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
    p.add_argument("--verify-baseline", metavar="REFERENCE", dest="verify_baseline",
                   help="check the drift baseline (--state) against a reference value a "
                        "previous --monitor run printed, and exit; read-only")
    p.add_argument("--purge", action="store_true",
                   help="delete ClawSecCheck's local store (history/events/state/coverage "
                        "files, plus the default-named badge/html/sarif/pdf report files if "
                        "present, + their lock sidecars) and exit — confirmation-gated unless "
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
                   help="print which further ClawSecCheck checks are worth running given this result")
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
                   # B-536 sibling: UNCHANGED is the load-bearing word and stays put —
                   # only the noun moves, because an ungraded run has no grade to leave
                   # unchanged (its --judged output carries "grade": null) and the
                   # promise is really that a judge never moves the audit's verdict,
                   # whatever shape that verdict has.
                   help="feed back a host-agent judge panel's verdicts JSON for a prior "
                        "--judge-packet; renders the audit's UNCHANGED verdict and findings "
                        "plus an advisory secondOpinion panel — use '-' to read from stdin")
    p.add_argument("--propose-ignore", metavar="PATH", dest="propose_ignore",
                   help="feed back a host-agent judge panel's verdicts JSON for a prior "
                        "--judge-packet; prints PROPOSED (not applied) .clawseccheckignore "
                        "entries for findings verdicted SAFE — use '-' to read from stdin, "
                        "then --apply-ignore-proposals to actually write them")
    p.add_argument("--verbose", action="store_true",
                   help="emit INFO-level log breadcrumbs to stderr; with --monitor, also "
                        "list what could not be compared instead of only counting it")
    p.add_argument("--debug", action="store_true",
                   help="emit DEBUG-level log breadcrumbs to stderr")
    p.add_argument("--log", metavar="PATH", default=None,
                   help="also write INFO-level log output to PATH (only when given; "
                        "raises the FILE's level to INFO, never the console's — pass "
                        "--verbose/--debug for that)")
    args = p.parse_args(argv)
    # C-419: --monitor writes THREE files and --history defaulted independently of the
    # other two, so redirecting only --state/--events silently kept writing into the real
    # history. That is not hypothetical: a test campaign did exactly this and put ~51
    # fixture-score rows into the live history, where every row carries `home: null` and is
    # therefore indistinguishable from a genuine one after the fact. Our own exit-code test
    # already worked around it by redirecting all three by hand.
    #
    # An explicitly given path still wins — detected by "differs from the default", which
    # is right whichever way a user who passes the default explicitly meant it, since both
    # readings produce the same file.
    # "Explicit" is `is not None`, not "differs from the default string". The string
    # comparison looked equivalent and was not: a wrapper passing the UNEXPANDED literal
    # `~/.clawseccheck/state.json` compares equal to the default and had its named path
    # silently replaced, while `~` resolves against whatever HOME is set — so the two
    # readings do NOT produce the same file, which is what an earlier comment here claimed.
    # B-589: "you named this file and it is not there" and "nothing has been written to
    # the default location yet" are different facts that call for opposite reactions, and
    # the default-resolution below erases the difference — after it every path looks
    # explicitly given. Captured here, while it is still knowable. A --data-dir-derived
    # path counts as NOT explicit: choosing a store directory is not naming a journal, and
    # a fresh data dir legitimately has no journal in it yet.
    _explicit_paths = {
        _attr: getattr(args, _attr) is not None
        for _attr in ("state", "events", "history")
    }
    if args.data_dir is not None:
        if not str(args.data_dir).strip():
            p.error("--data-dir needs a directory; an empty value would silently target "
                    "the current working directory, which --purge would then empty")
        _store = Path(args.data_dir).expanduser()
        for _attr, _name in (("state", "state.json"), ("events", "events.jsonl"),
                             ("history", "history.jsonl")):
            if getattr(args, _attr) is None:
                setattr(args, _attr, str(_store / _name))
    for _attr, _default in (("state", DEFAULT_STATE), ("events", DEFAULT_EVENTS),
                            ("history", DEFAULT_HISTORY)):
        if getattr(args, _attr) is None:
            setattr(args, _attr, _default)

    # B-606: an explicit `--pdf <path>` always wins — this branch only fires for the bare
    # form (`_PDF_AUTO`, this ``nargs="?"``'s const), never for a user-named path. Resolved
    # here, once, before any mode dispatch, so every later reader of `args.pdf` (mode
    # detection, the write site, the attach note) sees the same real path with no extra
    # plumbing.
    _pdf_used_managed_root = False
    _pdf_was_auto = args.pdf == _PDF_AUTO
    if _pdf_was_auto:
        args.pdf, _pdf_used_managed_root = _default_pdf_target(args.home)

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

    # B-466 / C-426 part B: a mode flag given an empty target is a malformed invocation,
    # and it is rejected here — before ANY mode dispatches — rather than inside the vet
    # family where the check used to sit. Two reasons. It stops an empty value being
    # masked by whichever mode happened to be earlier in the cascade (`--menu --vet ""`
    # ran the menu and said nothing). And it is what makes _mode_active's `is not None`
    # sound as the one dispatch predicate: the branches below test truthiness, so an
    # empty value was the single input on which the note layer and the dispatch layer
    # disagreed — `--badge ""` printed a full default report at rc=0 while the coherence
    # note announced it was running --badge.
    _empty_flag = _empty_mode_target(args)
    if _empty_flag:
        print(f"{_empty_flag} needs a target — got an empty value. "
              "Pass a path, slug, or URL.", file=sys.stderr)
        return 2

    # C-426 part B: _PRIMARY_MODES decides which mode runs. Every branch below asks this
    # one value rather than re-testing its own flag, so the table's order IS the dispatch
    # order instead of a hand-maintained mirror of it (see _resolve_mode).
    _mode = _resolve_mode(args)

    # standalone modes that don't audit ~/.openclaw
    if _mode == "purge":
        # Dispatched FIRST, before any audit()/history-record call-site below, so
        # purge can never race its own uninstall by writing a fresh history point.
        return _run_purge(args)

    if _mode == "apply_ignore_proposals":
        # C-253: like --purge, this only touches its own known file (.clawseccheckignore
        # under --home) and needs no audit() pass, so it is dispatched here too.
        return _run_apply_ignore_proposals(args)

    if _mode == "verify_self":
        # B-590: opt into package_digest()'s disclosure channel. Without it a symlink
        # dropped into the package tree left no trace anywhere in this output, and a
        # module the user cannot read aborted the whole command with a generic
        # "unexpected internal error" that named no file.
        _notes: list = []
        combined, per_file = package_digest(notes=_notes)
        # Three kinds, three consequences — matched explicitly rather than by "everything
        # that is not unreadable", which silently folded a fourth kind into the listing
        # annotations the moment one was added.
        _uncovered = {rel: (kind, detail) for kind, rel, detail in _notes
                      if kind in (NOTE_SYMLINK, NOTE_PATH_ESCAPE)}
        _unreadable = [(rel, detail) for kind, rel, detail in _notes
                       if kind == NOTE_UNREADABLE]
        _vanished = [(rel, detail) for kind, rel, detail in _notes
                     if kind == NOTE_VANISHED]
        # B-608: presence-only disclosure of a PEP 552 unchecked-hash .pyc found inside a
        # real __pycache__. Never folded into rc — see the block below; this is a
        # disclosure that something could not be checked, not a verdict that it is bad.
        _unchecked_pyc = [(rel, detail) for kind, rel, detail in _notes
                          if kind == NOTE_UNCHECKED_PYC]
        lines = [f"{WORDMARK} {__version__} — engine source digest (SHA-256)",
                 f"combined : {combined}",
                 ""]
        for name, digest in sorted(per_file.items()):
            _note = _uncovered.get(name)
            if _note is None:
                lines.append(f"  {digest}  {name}")
            else:
                # Say what the row's digest is over. A link's row is a digest of the
                # link, not of any file's bytes, and printing it like every other row
                # would be the report claiming it read something it never opened.
                _kind, _target = _note
                lines.append(f"  {digest}  {name}  [{_kind} -> {_target}; "
                             f"name and target hashed, target contents NOT read]")
        if _uncovered:
            lines.append("")
            lines.append(f"Coverage note: {len(_uncovered)} entr"
                         f"{'y' if len(_uncovered) == 1 else 'ies'} in the package tree "
                         f"{'is' if len(_uncovered) == 1 else 'are'} a symlink or a path "
                         f"escape.")
            lines.append("Only the name and target are hashed, never the target's contents — so")
            lines.append("adding, removing, renaming or repointing one DOES change the combined")
            lines.append("digest, but what it points at is outside this scan. A clean install has")
            lines.append("none of these at all, so any entry listed above is worth investigating.")
        if _unchecked_pyc:
            # B-608: this is presence-only disclosure, never folded into `combined` or rc —
            # a real __pycache__ is excluded from the digest by content (B-069, .pyc bytes
            # vary by interpreter), so this is the one signal that can still be surfaced
            # from inside it without making the digest environment-dependent.
            lines.append("")
            lines.append(f"Coverage note: {len(_unchecked_pyc)} __pycache__ director"
                         f"{'y' if len(_unchecked_pyc) == 1 else 'ies'} in the package "
                         f"tree "
                         f"{'contains' if len(_unchecked_pyc) == 1 else 'contain'} a PEP "
                         f"552 unchecked-hash .pyc.")
            lines.append("__pycache__ contents are never read into the digest above (compiled")
            lines.append("bytecode varies by interpreter, which would make the digest")
            lines.append("irreproducible) — but a hash-based .pyc that is NOT checked against its")
            lines.append(".py before Python imports it is worth naming even though it stays")
            lines.append("outside the scan:")
            for _rel, _detail in _unchecked_pyc:
                lines.append(f"  {_rel}  —  {_detail}")
            lines.append("This is not what an ordinary build, test or install leaves behind: it")
            lines.append("takes an explicit, non-default compile flag. Measured on one healthy")
            lines.append("machine, 7,850 .pyc files on the interpreter's own paths were all")
            lines.append("timestamp-based and none was hash-based at all. Worth investigating if")
            lines.append("you did not put it there yourself.")
        if _unreadable:
            lines.append("")
            lines.append(f"INTEGRITY CANNOT BE ESTABLISHED: {len(_unreadable)} path"
                         f"{'' if len(_unreadable) == 1 else 's'} in the package tree could")
            lines.append("not be read, so the digest above covers less than the tree it names:")
            for _rel, _why in _unreadable:
                lines.append(f"  {_rel}  —  {_why}")
            lines.append("A file or directory made unreadable to the auditing user is itself worth")
            lines.append("investigating; the combined digest above must not be compared against a")
            lines.append("trusted release digest, because it was computed over a smaller tree.")
        if _vanished:
            # Deliberately neutral, and deliberately rc 0. These paths were listed by the
            # walk and gone by the time it reached them, which is what an update or an
            # rsync running alongside the scan looks like. Wording it like the block above
            # would accuse the user of tampering for running two ordinary things at once.
            lines.append("")
            lines.append(f"Note: {len(_vanished)} path"
                         f"{'' if len(_vanished) == 1 else 's'} disappeared while the scan "
                         f"was running, so the digest")
            lines.append("does not cover them. This is ordinary if the tree was being updated at the")
            lines.append("same time; re-run on a quiet tree for a digest you can compare:")
            for _rel, _why in _vanished:
                lines.append(f"  {_rel}  —  {_why}")
        lines.append("")
        if _unreadable or _vanished:
            # The footer used to assert "any mismatch means a source file was modified"
            # five lines under a block saying this digest covers less than the tree — two
            # sentences in one screen telling the reader opposite things. Whichever they
            # believed, one of them was wrong.
            lines.append("The 'combined' value above is NOT comparable against a trusted "
                         "release digest:")
            lines.append("it was computed over less than the whole tree, for the reason "
                         "stated above. Re-run")
            lines.append("once that is resolved, then compare.")
        else:
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
        _self_text = "\n".join(lines)
        _emit(asciify(_self_text) if ascii_only else _self_text)
        # Non-zero only when the digest is incomplete. A disclosed symlink still produced a
        # digest that covers the whole tree (by name and target), so it stays rc 0 and is
        # reported; an unreadable path means this command could not do its one job.
        return 1 if _unreadable else 0

    if _mode == "verify_history":
        _cause: list = []
        ok, msg = history_verify(args.history, cause=_cause)
        text, rc = _chain_verdict("History", args.history, ok, msg,
                                  explicit=_explicit_paths["history"],
                                  cause=_cause[0] if _cause else "")
        _emit(asciify(text) if ascii_only else text)
        return rc

    if _mode == "verify_events":
        # C-250(c): --verify-history --history <events-path> already verified an events
        # journal correctly (verify_chain() is the same entry-agnostic algorithm for both
        # journals — see history.verify()'s own docstring), but its output always said
        # "History chain" regardless of which journal was actually named. This is the
        # discoverable, correctly-worded entry point --events users were missing.
        _cause = []
        ok, msg = verify_chain(args.events, cause=_cause)
        text, rc = _chain_verdict("Events", args.events, ok, msg,
                                  explicit=_explicit_paths["events"],
                                  cause=_cause[0] if _cause else "")
        _emit(asciify(text) if ascii_only else text)
        return rc

    if _mode == "verify_baseline":
        # F-173: three outcomes, never two. "It does not match" and "I could not check"
        # ask the reader for opposite reactions, and collapsing them into a bool is how an
        # absent state file starts reporting as tampering — the single most damaging thing
        # a security tool can get wrong in this direction, because the user's next move is
        # to go looking for an intruder who is not there.
        #
        # A mismatch is reported as a fact about the two values and NOTHING more. It has
        # ordinary causes — any --monitor run advances the baseline, so a reference from
        # before the last scheduled run is simply stale — and this tool cannot tell those
        # from an edit. Saying which it is would be a claim the evidence does not support.
        _ok, _actual, _why = _verify_baseline(args.verify_baseline, args.state)
        if _ok is None:
            # "Absent" and "unreadable" are separate sentences, not one hedge. An earlier
            # version collapsed them and told the user of a present-but-unreadable
            # state.json that no baseline had ever been saved — which sends them to re-run
            # --monitor, the one action that overwrites the evidence.
            _emit(f"Cannot check ({args.state}): " + {
                "absent": "no baseline has been saved yet — run --monitor first.",
                "unreadable": "the baseline file is there but could not be read or parsed. "
                              "Check its permissions. Do NOT re-run --monitor first — that "
                              "would overwrite it.",
                "reference_too_short": (
                    f"a reference needs at least {BASELINE_DIGEST_CHARS} characters to mean "
                    f"anything; the current one is {_actual[:BASELINE_DIGEST_CHARS]}."),
            }.get(_why, "no comparison was possible."))
            return 1
        # The recorded run shape, shown on both outcomes. An independent pass found the
        # reference moving on a completely untouched machine simply because the run was
        # taken with --no-host or --no-sockets: those change `scope`, `host`, `checks` and
        # the scores, so a differently-shaped run of the SAME setup fingerprints
        # differently. That is correct behaviour — a narrower run recorded less — but the
        # first version's wording listed four causes, none of which was "you ran it with
        # different options", so the honest answer looked like an unexplained mismatch.
        # Printing the shape turns a dead end into something the user can act on.
        _b_scope = (read_baseline(args.state)[1] or {}).get("scope")
        _shape = (", ".join(_b_scope) if isinstance(_b_scope, list) and _b_scope
                  else "config only" if isinstance(_b_scope, list) else "not recorded")
        if _ok:
            _emit(f"Baseline still matches your reference "
                  f"({_actual[:BASELINE_DIGEST_CHARS]}). Nothing it records has changed "
                  f"since the run that gave you that value.\n"
                  f"  covering: {_shape}")
            return 0
        _emit(f"Baseline does NOT match your reference.\n"
              f"  you gave: {args.verify_baseline.strip().lower()}\n"
              f"  currently: {_actual[:BASELINE_DIGEST_CHARS]}\n"
              f"  covering: {_shape}\n"
              f"This value moves whenever anything the last run recorded is different — "
              f"which includes the options you ran it with. A run taken with --no-host or "
              f"--no-sockets covers less ground and so fingerprints differently even though "
              f"nothing on the machine changed; so do a settings edit, a skill update, a "
              f"changed check result, and a ClawSecCheck upgrade that adds checks. Compare "
              f"the covering line above against how you took your reference first, then run "
              f"--watch-log to see what was recorded in between.")
        return 1

    if _mode == "vet_plan":
        # F-065: zero-network plan emitter — prints commands, touches nothing itself.
        _emit(render_vet_plan(args.vet_plan))
        return 0

    if _mode == "menu":
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

    if _mode == "brief":
        # F-171: reads state.json, events.jsonl and history.jsonl — and writes NOTHING.
        # No audit, no snapshot, no journal append. That constraint is what lets SKILL.md
        # have the agent run this at session start with no consent prompt; the consent rule
        # covers --monitor, which writes.
        from .report import render_brief  # noqa: PLC0415
        _state_path = Path(args.state).expanduser()
        _state, _mtime = None, None
        try:
            if _state_path.is_file():
                _mtime = datetime.fromtimestamp(
                    _state_path.stat().st_mtime).isoformat(timespec="seconds")
                _state = json.loads(_state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _state = None
        try:
            _events = load_events(args.events)
        except OSError:
            _events = []
        try:
            _hist = history_load(args.history)
        except OSError:
            _hist = []
        _emit(render_brief(_state if isinstance(_state, dict) else None, _events, _hist,
                           state_mtime_iso=_mtime, ascii_only=ascii_only))
        return 0

    if _mode == "cron_recipe":
        # F-172: print-only by construction — no scan, no writes, and emphatically no
        # `openclaw cron` call. A security tool that installs a recurring job as a side
        # effect of being asked how to install one has taken a decision nobody offered it.
        from .guide import render_cron_recipe  # noqa: PLC0415
        _emit(render_cron_recipe(ascii_only=ascii_only,
                                 data_dir=args.data_dir or "~/.clawseccheck"))
        return 0

    if _mode == "functions":
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
    # C-426 part B: the empty-target check that lived here now runs before ANY mode
    # dispatches (see _empty_mode_target), so it covers every mode flag that takes a
    # required value instead of only this family.

    _vet_route = None  # (kind, target) with kind in {"skill", "plugin", "mcp"}
    _detect_undetermined = None  # B-682: why the classification is less than it looks
    if _mode == "vet":
        detected, _detect_undetermined = detect_vet_type_with_reason(
            args.vet, home=args.home)
        print(f"detected type: {detected}", file=sys.stderr)
        # 'unknown' routes to the skill engine, which answers with an honest UNKNOWN —
        # exactly today's --vet behavior for a non-skill target (never a guessed PASS).
        _vet_route = (detected if detected in ("plugin", "mcp") else "skill", args.vet)
    elif _mode == "vet_skill":
        _vet_route = ("skill", args.vet_skill)
    elif _mode == "vet_plugin":
        _vet_route = ("plugin", args.vet_plugin)


    # B-680: an unassessable target is a usage error, not a verdict. Shared with
    # --advise below through `_unassessable_target` / `_report_unassessable`, which carry
    # the reasoning; a second copy of this decision is exactly how the two would drift.
    #
    # A configured MCP server NAME is not a path, and `os.stat` on it raises
    # FileNotFoundError like any typo would — so this is gated on the route the target
    # actually took. Move it above `detect_vet_type` and every named MCP server starts
    # failing as "no such file or directory".
    if _vet_route and _vet_route[0] in ("skill", "plugin"):
        _why = _unassessable_target(_vet_route[1])
        if _why is not None:
            return _report_unassessable(
                "--vet" if _mode == "vet" else "--vet-" + _vet_route[0],
                _vet_route[1], _why, _detect_undetermined)

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
            verdicts_raw = _verdicts_with_note(args.vet_judged, "--vet-judged")
            # Escalate-only: rebuild f's ring_findings so a borderline finding can only
            # rank higher, never lower, than the deterministic engine already ranked it
            # (adjudication._escalated_status). build_profile below is UNCHANGED —
            # it re-derives overall_status/score/grade from this pool the normal way.
            f = escalate_vet_output(f, verdicts_raw, target=vet_path)
        profile = build_profile(f, vet_path, vet_kind)
        # rc: overall FAIL/WARN → 1 (dangerous/suspicious target);
        # UNKNOWN + target unusable → 1;
        # UNKNOWN + target exists (valid target, inconclusive assessment) → 0;
        # PASS → 0.
        #
        # B-680: "absent" no longer reaches this line — a path that simply is not there
        # returned 2 above, before anything was assessed. What still lands here is the
        # narrower case the guard deliberately declines to claim is absent: a path we
        # could not stat at all (an unreadable parent). `.exists()` is False for that
        # too, so the arm below is unchanged and still keeps it off 0.
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

    if _mode == "vet_all":
        home_dir = Path(args.home).expanduser()
        return vet_all(home_dir, ascii_only=ascii_only)

    if _mode == "vet_mcp":
        return _run_vet_mcp(args.vet_mcp if args.vet_mcp else None, args, ascii_only)

    if _mode == "vet_source":
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

    if _mode == "advise":
        # F-067: same vet engines/profile as --vet, reframed as an install decision.
        advise_target = args.advise
        detected, _advise_undetermined = detect_vet_type_with_reason(
            advise_target, home=args.home)
        print(f"detected type: {detected}", file=sys.stderr)
        # B-685: the fourth member of B-680's family, and it failed the worse way. An
        # absent path printed "⚠️  CAUTION — skill 'no-such-skill'", told the reader to
        # "review manually before trusting this source", and returned 0 — the code a clean
        # assessment returns — about a subject that was never examined. --advise is the
        # surface whose entire job is the install decision, which is what makes rendering
        # one about nothing worse here than in --vet.
        #
        # Same guard, not a second copy of it (see _unassessable_target). Skipped when the
        # target resolved to a configured MCP server: that is a name, not a path, so
        # "no such file or directory" would be true of it and useless. Routing an MCP name
        # to the skill engine is pre-existing and left alone here.
        if detected != "mcp":
            _why = _unassessable_target(advise_target)
            if _why is not None:
                return _report_unassessable("--advise", advise_target, _why,
                                            _advise_undetermined)
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

    if _mode == "canary":
        _emit(render_canary(make_canary(args.seed), ascii_only))
        _record_run("self_test", args)
        return 0

    if _mode == "redteam":
        seed = args.seed if args.seed is not None else secrets.token_hex(8)
        _emit(render_suite(make_suite(seed), ascii_only, seed=seed))
        _record_run("self_test", args)
        return 0

    if _mode == "dryrun":
        _emit(render_dryrun(make_scenarios(args.seed), ascii_only))
        _record_run("self_test", args)
        return 0

    if _mode == "multiturn":
        _emit(render_multiturn(make_multiturn(args.seed), ascii_only))
        _record_run("self_test", args)
        return 0

    if _mode == "self_test":
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

    if _mode == "ask":
        import json as _json  # noqa: PLC0415
        from . import attest as _attest  # noqa: PLC0415
        _emit(_json.dumps(_attest.template(), indent=2, ensure_ascii=False))
        return 0

    if _mode == "show_suppressed":
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
                                     include_dist=not args.no_dist,
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

    if _mode == "watch_log":
        # B-581: load_events() alone can't tell "no journal at the default location yet
        # (a genuine first run)" apart from "you named a path I could not open" — both
        # returned [] and "No recorded change events yet." lied about the second case.
        # Attempt the real read via load_events_with_problem and only report the OSError
        # when the user actually NAMED this path (_explicit_paths) — an absent default
        # store stays silent, exactly as before.
        _events_rows, _events_problem = load_events_with_problem(args.events)
        if _events_problem is not None and _explicit_paths["events"]:
            print(f"note: --events: {_path_problem_text(args.events, _events_problem, what='events file')}. "
                  "Showing no events for this run; your real event journal (if any) is "
                  "unaffected.", file=sys.stderr)
        # B-583: an empty journal is ambiguous on its own — "monitoring never ran" and
        # "monitoring ran and nothing changed" are opposite facts that rendered as one
        # sentence. Supply the two signals that separate them. `journal_exists` comes
        # from the read we already did: a FileNotFoundError means no journal, whatever
        # path it was. The "since" date is the monitor's own last-run timestamp, NOT
        # this file's mtime — a rotation, a restore or a permission change would
        # fabricate a date with zero events behind it.
        _journal_exists = not isinstance(_events_problem, FileNotFoundError)
        _events_since = None
        if not _events_rows:
            # Asked whenever there are no rows, NOT only when the journal exists:
            # `record_events` is a no-op when nothing changed, so a monitor that ran
            # cleanly leaves NO journal at all. Gating this on the file's existence
            # made that case print "monitoring has not run yet" while the state file
            # sitting beside it proved otherwise — a contradiction inside one run.
            with contextlib.suppress(Exception):
                _state = load_state(args.state) if args.state else load_state()
                _events_since = (_state or {}).get("ts")
        _emit(render_events(_events_rows, ascii_only,
                            journal_exists=_journal_exists, since=_events_since))
        # B-582: same tamper-evident check --verify-events already has, run here too
        # — this viewer used to present the journal without ever consulting it. A
        # broken chain is disclosed, never withheld or called tampering (see
        # chain_provenance_note); render_events itself is untouched (owned
        # elsewhere), so the note is appended as its own line.
        _events_note = chain_provenance_note(*verify_chain(args.events))
        if _events_note:
            _emit(asciify(_events_note) if ascii_only else _events_note)
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
                  f"(ignored; B43/B44 stay UNKNOWN). See '{command_prefix()} --ask'.",
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
                      f"See '{command_prefix()} --ask'.", file=sys.stderr)
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
                                     include_dist=not args.no_dist,
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
    # A `ScoreResult` keeps its computed number when `graded` is False — only the
    # renderers withhold it — so every writer has to opt in, and this one had not.
    # `--log` is where an operator looks once the terminal has scrolled, and what
    # they paste into an issue; it stated a grade the report on screen refused to give.
    if getattr(score, "graded", True):
        logger.info("score=%s grade=%s", score.score, score.grade)
    else:
        logger.info("no grade: %d of %d layers did not run",
                    len(getattr(score, "missing_layers", ())), len(LAYER_ORDER))

    # B-154: RISK-* chains must honor .clawseccheckignore too — pass the same
    # ignore set findings were suppressed with, then drop suppressed chains
    # before they reach any render/JSON path.
    _risk_ignore = load_ignore(Path(args.home).expanduser())
    paths = [p for p in _risk.risk_paths(ctx, findings, ignore=_risk_ignore)
             if not p.suppressed]

    if _mode == "risk_paths":
        # B-601: an analysis VIEW over findings this run already measured — the verdict is
        # as real as any other run's, so the timeline carries it. Resolving the liveTest cap
        # first is what gives `_record_history_point` a signal to honour; without one an
        # unseeded VULNERABLE verdict would be persisted, which is the single thing the
        # F-155 gate exists to prevent.
        score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)
        _emit(_risk.render_risk_paths(paths, ascii_only=ascii_only))
        _record_history_point(score, args, _live_signal, findings)
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

    if _mode == "badge":
        # B-601: the cap is resolved BEFORE the artifact is rendered, not just before the
        # history write. An exported badge that ignores a submitted VULNERABLE verdict is
        # the same lying artifact B-600 fixed in the HTML and the PDF — one run, one verdict,
        # on every surface it reaches.
        score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)
        try:
            secure_write_text(_report_dest(args.badge), render_svg(score, findings))
            _emit(
                f"(badge written to {args.badge} — attach this SVG file as-is; "
                "do not redraw, rasterize, or generate your own badge image)"
            )
            # Recorded on the success path only: a run that returns 1 because the file could
            # not be written is one the user will repeat, and two lines for one intended
            # audit is a worse timeline than none.
            _record_history_point(score, args, _live_signal, findings)
            return _findings_exit_gate(args, findings, ctx)
        except OSError as exc:
            _emit(f"(could not write badge: {exc})")
            return 1

    if _mode == "html":
        score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)   # B-601
        try:
            secure_write_text(
                _report_dest(args.html),
                render_html(findings, score, native=ctx.native, ctx=ctx),
            )
            _emit(f"(HTML report written to {args.html})")
            _record_history_point(score, args, _live_signal, findings)
            return _findings_exit_gate(args, findings, ctx)
        except OSError as exc:
            _emit(f"(could not write HTML report: {exc})")
            return 1

    if _mode == "sarif":
        score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)   # B-601
        try:
            secure_write_text(_report_dest(args.sarif), render_sarif(findings, score, __version__, ctx=ctx))
            _emit(f"(SARIF written to {args.sarif})")
            _record_history_point(score, args, _live_signal, findings)
            return _findings_exit_gate(args, findings, ctx)
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

        B-595: moving it to stderr was not enough, and the reason is in what it said. The
        note read "Do not paste its path, do not send a link" — and for a channel that
        cannot attach a file, those are the only two things it can do, so the note left it
        with no compliant move at all. Driving the live agent on 2026-08-20 produced both
        halves of that: one host wrote `<a href="/report.pdf">`, which the Control UI's
        catch-all answered with its own index page (a link to nothing, on the deliverable
        the whole `--full` pipeline exists to produce); a second host obeyed the note,
        said it could not attach, and gave the user nothing to open.

        Worse, the note was stricter than the guidance it implements. `SKILL.md` says
        never paste the path "as if it were the deliverable" and tells the agent what to
        do instead when it cannot attach; this note flattened that into an absolute ban
        and dropped the fallback entirely — and since B-468 put it at the moment of the
        decision, the flattened version is the one that won. It now carries `SKILL.md`'s
        own ordering, so the two cannot disagree: attach, else say so and name the path,
        never a link.

        The anti-link clause is the half that was always right, and it is kept — with the
        reason attached, because "there is none" did not stop either host from writing one.

        B-606: and it did not stop a third. Dave clicked the PDF in the Control UI and
        nothing happened; the DOM showed an `<a>` with no href at all, because the host had
        written `[report.pdf](/…/report.pdf)` — a markdown link around a LOCAL PATH, which
        the client correctly refuses to give an href and renders inert. The clause said
        "never write a link or a URL"; what was written has no scheme and no host, so an
        agent reading "URL" as `scheme://host/…` need not have seen either. The clause named
        the category and never the syntax, so it now names both, plus the form that works.

        Measured across seven live runs, and the shape of this failure is unlike B-605's:
        four hosts wrote the path as inline code (which renders and is clickable-to-copy)
        and three wrote a markdown link. The agent is choosing between two forms with no
        stated preference and getting it right about half the time — not refusing an
        instruction, which is why naming the form is expected to work here where eight
        attempts at the card did not.

        B-606 (this change): naming the anti-link rule was never the whole gap -- nothing
        here told the agent HOW to attach a file at all, only that it should, so it kept
        improvising the rest. OpenClaw documents exactly one mechanism to its own model: a
        `MEDIA:<path>` line, alone on its own line, outside any code fence, parsed out of
        the reply and turned into a real attachment. The note now hands over that literal
        line instead of describing the goal. Whether the read behind it succeeds depends
        on where the file landed -- `<home>/media/outbound` is the one directory OpenClaw
        always allows its own read tool to reach, ahead of every other permission check;
        anywhere else is gated the same way most of a user's files already are, and a
        blocked read is dropped by the host silently, with nothing surfaced here to catch
        it. That is why the path is still said in words below regardless -- it costs
        nothing to include, and it is the only fallback a blocked read leaves.
        """
        if not path:
            return
        _media_path = _display_path(path)
        _fallback_line = (
            "      This run could not confirm OpenClaw's managed attachment directory "
            "(it did not exist, or was not writable), so the report fell back to a "
            "location the read tool may not be allowed to open: the MEDIA line above "
            "may be silently dropped. Say the path in words too, so the user still has "
            "something to open.\n"
            if _pdf_was_auto and not _pdf_used_managed_root else ""
        )
        print(f"note: report written to {path}. Send it now: on its own line, outside "
              "any code fence, write exactly this line, verbatim (OpenClaw parses it "
              "out of your reply and attaches the file for you; do not merely describe "
              "doing so):\n"
              f"      MEDIA:{_media_path}\n"
              f"{_fallback_line}"
              "      — attach this PDF file itself into the "
              "chat; that is the deliverable.\n"
              "      If your channel cannot attach files: say so plainly, offer the "
              "inline report (--dashboard --full, split across messages), and name the "
              "path above so the user can open it themselves — just never as the "
              "deliverable.\n"
              "      Never write a link or a URL: the tool is local-only, so none exists "
              "and any link you write will be broken.\n"
              "      Markdown link syntax counts as a link: `[report.pdf](path)` is one, and "
              "a chat client\n"
              "      strips the href off a local path and leaves a dead one the user can "
              "click forever.\n"
              "      Write the path as plain text or inline code \u2014 never as a link.\n"
              "      Do not re-render the PDF's contents into the chat.",
              file=sys.stderr)

    def _emit_paste_instruction(pdf_path=None, card_chars=0):
        """B-605: tell the agent HOW to relay the card, in the buffer that carries it.

        `SKILL.md` states the contract as emphatically as prose can -- "Do not compose the
        card -- paste it ... paste its entire stdout here, verbatim". Measured across five
        live Control-UI sessions it is obeyed by exactly one host: gpt-5.6-sol pasted the
        card; gpt-5.6-luna composed its own bullet list 4 times out of 4, and 3 of those 4
        dropped even the tool's name from the reply. The card is emitted correctly every
        time -- the loss is entirely between stdout and the screen.

        Two things were wrong with relying on that paragraph, and `_emit_attach_instruction`
        above already names the mechanism for the first: an instruction placed "at the
        moment of the decision" beats the document read hundreds of lines earlier -- that
        is precisely how B-595's flattened note came to override SKILL.md's richer rule.
        For the card there was no such instruction AT ALL: `--dashboard` without `--pdf`
        printed nothing to stderr, which is exactly the shape of the session that composed
        with no note present. So this is not a second copy of the rule; it is the first
        time the rule reaches the buffer where the choice is made.

        The second is that "paste it verbatim" names an outcome, not an action. The one
        host that succeeded did something specific -- it wrapped the card in a ```text
        fenced block, which is what keeps the header, the score-bar and the per-subject
        frames intact in a markdown chat client. So the note names that action rather than
        restating the goal. n=1 on the fence, which is why it is offered as the shape
        observed to work and not asserted as the only one that can.

        stderr, like its sibling, and for the same reason: the agent must read this and the
        user must never see it. That split does hold in practice -- the host that pasted the
        card did not paste the attach note (checked in that session's assistant-authored
        text, isolated from tool output).

        Emitted BEFORE the card, and that ordering is load-bearing rather than cosmetic.
        The first version printed it after, and a live run found the consequence: on
        `--dashboard --full` without `--pdf` the merged stream is 25,686 bytes, the card
        starts at 0 and the note started at byte 25,265 -- past the ~20 KB cap the host's
        bash tool truncates at. The instruction to relay the card was the first thing lost,
        and it was lost exactly on the runs with the biggest card. Printing it first makes
        that deterministic: stderr is unbuffered and nothing of the card has been written
        yet, so it cannot be ordered away by stdout's block buffering (which is what made
        the small-card case look fine).

        `card_chars` drives the second half. With `--pdf` the card collapses to a ~1.6 KB
        overview that points at the file, and that shape does get relayed. Without it,
        `--dashboard --full` renders ~20 KB across ~183 lines -- more than a chat message
        can carry, so no instruction can make it relayable and pretending otherwise just
        moves the failure. The remedy already exists in the product and in `SKILL.md`
        (`--pdf` to attach, `--compact` to condense, or split across messages); nothing
        said so at the moment the oversized card was produced. The size is DISCLOSED rather
        than a limit asserted: the cap is the channel's, the tool cannot know it, and
        `SKILL.md`'s own worked example is Telegram's ~4096.

        Splitting is named FIRST, and that order came from the trajectory rather than from
        taste. The live host reached the oversized shape by the documented route: it wrote
        the PDF, checked with `ls` whether it existed, could not attach it in that channel,
        and fell back to the inline report exactly as `_emit_attach_instruction` tells it
        to. Leading with "re-run with --pdf" would answer a channel that has already proved
        it cannot use one. Splitting is the only remedy that always applies and needs no
        re-run, and it is what `SKILL.md`'s own attach-fallback already prescribes.
        """
        lines = [
            "note: the Dashboard card on stdout is a deterministic render \u2014 paste it "
            "into your reply verbatim,",
            "      inside a fenced code block (```text \u2026 ```), exactly as printed.",
            "      Do not summarise it, do not rebuild it as your own bullet list, do not "
            "drop its header line:",
            "      composing it yourself silently loses the header, the score-bar and the "
            "per-subject frames,",
            "      which is why it is rendered here rather than described.",
        ]
        if card_chars > _RELAYABLE_CARD_CHARS:
            lines.append(
                f"      This card is {card_chars:,} characters, which many chat channels "
                "cannot carry in one message")
            lines.append(
                "      (Telegram caps at ~4,096). If yours cannot, pick one: split it "
                "across several messages,")
            lines.append(
                "      re-run with --compact to condense it, or re-run with --pdf and "
                "attach the file.")
            lines.append(
                "      Do not silently relay part of it as if it were the whole.")
        if pdf_path:
            lines.append(
                "      The card is not the PDF's contents \u2014 paste the card AND attach "
                "the PDF; they are different artifacts.")
        print("\n".join(lines), file=sys.stderr)
    # C-374: under `--dashboard --full` the PDF must also carry the pipeline blocks, and
    # those phases are computed further down (in the dashboard branch). Defer the write
    # to there rather than emitting a findings-only PDF the card would then describe as
    # complete.
    #
    # B-530: `and _mode == "dashboard"` — deferring is only right when the branch the
    # write was deferred INTO is the one that runs. A rider (`--dashboard --full --pdf
    # out.pdf --trend`) returns ~1200 lines above the dashboard branch, so the write was
    # never reached: exit 0, a sparkline, no file — and no P7-P10 phase had run either,
    # so deferral bought nothing there but the loss. A rider now gets the reduced
    # (findings-only) PDF, which discloses its own scope via C-423's ledger page with no
    # help from here; the note below repeats that for the agent. Full reasoning, and why
    # the two other options lose, in tests/test_b530_deferred_pdf_rider.py.
    _defer_pdf = bool(args.pdf) and args.dashboard and args.full and _mode == "dashboard"
    # C-426 part B: --pdf is a MODE when asked for alone and a SIDE OUTPUT when it rides
    # with --dashboard — the one composition _PRIMARY_MODES cannot express, since the
    # table models "exactly one mode wins". _resolve_mode elects the dashboard (or
    # --trend/--percentile/--next) in that case, so this names the other half explicitly
    # instead of relying on this branch not returning and control falling through.
    _pdf_side_output = bool(args.pdf) and args.dashboard
    # B-586: --badge/--html/--sarif ride --dashboard on exactly --pdf's terms. Written
    # HERE when the dashboard is present but is not what renders (a --trend/--percentile/
    # --next rider beat it) — the artifact is then the bare audit's, which is what it
    # would have been anyway — and DEFERRED into the dashboard branch when it is, because
    # only after `_resolve_runtime_caps` there is `score` the phase-aware, possibly-graded
    # one. Writing them early on that path is what produced a "no grade yet" badge on a
    # run that had just earned a grade.
    _defer_side_outputs = args.dashboard and args.full and _mode == "dashboard"
    if args.dashboard and not _defer_side_outputs:
        _write_dashboard_side_outputs(args, findings, score, ctx, _report_dest, _emit)
    if _mode == "pdf":
        # B-601: STANDALONE --pdf only. The write below is shared with `--dashboard`'s
        # riders, and those have their own cap story (B-586's deferral, B-600's follow-up),
        # so resolving here is scoped to the branch that returns from this block. Guarding
        # on the mode rather than editing the shared write keeps the rider path byte-for-
        # byte what it was.
        score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)
    if (_mode == "pdf" or _pdf_side_output) and not _defer_pdf:
        try:
            _pdf_dest = _report_dest(args.pdf)
            secure_write_bytes(_pdf_dest,
                               render_pdf(findings, score, native=ctx.native, ctx=ctx))
            pdf_written = str(_pdf_dest)
        except OSError as exc:
            # B-459: this branch serves two compositions and they want opposite answers.
            #
            # `_mode == "pdf"` is a BARE `--pdf`: the artifact is the entire deliverable,
            # so a write that failed is a run that failed, and exit 1 is the contract
            # `tests/test_cli_exit_codes.py` pins deliberately.
            #
            # `_pdf_side_output` is `--dashboard --pdf`: the dashboard is the deliverable
            # and the PDF is its DELIVERY. Returning 1 there discards the analysis because
            # a file could not be written — the same shape as the original defect, which
            # printed 118 bytes and no grade on the guided flow's own first run. Three
            # review passes named this branch as the unfixed half; the sibling deferred
            # branch below already falls through with `pdf_written` left None, and this is
            # that same treatment.
            #
            # The two are mutually exclusive by construction, not by luck: `_resolve_mode`
            # re-elects when `--dashboard` is present, so `_mode == "pdf"` implies no
            # dashboard was asked for.
            if _mode == "pdf":
                _emit(f"(could not write PDF report: {exc})")
                return 1
            _emit(f"(could not write PDF report: {exc} — showing the full report inline)")
        if not args.dashboard:
            _emit(
                f"(PDF report written to {args.pdf} — attach this file itself into the "
                "chat, do not re-render its contents or paste the path; a mobile client "
                "opens a PDF inline where an HTML attachment would just be a download)"
            )
            _record_history_point(score, args, _live_signal, findings)          # B-601
            return _findings_exit_gate(args, findings, ctx)
        if _mode != "dashboard" and pdf_written:
            # B-459: `and pdf_written` — everything in this block SPEAKS ABOUT A FILE. With
            # the fall-through above, a failed write now reaches here with pdf_written
            # None, and the `--full` note below would describe a document that does not
            # exist ("The report states this on its own first page") while pointing the
            # agent at nothing. `_emit_attach_instruction` already no-ops on None; the
            # note did not, and telling the user about an artifact we failed to write is
            # the same class of defect this task exists to close.
            #
            # B-530: `--pdf` rode in with `--dashboard`, but a rider (`--trend`/
            # `--percentile`/`--next`) renders, and every rider branch returns before the
            # dashboard branch's own `_emit_attach_instruction`. Without this the file was
            # written and NOT ONE WORD said about it — real CLI: `--dashboard --pdf o.pdf
            # --trend` exited 0 printing only "--dashboard ignored (running --trend)". A
            # report the tool produced and never mentioned is one nobody attaches.
            _emit_attach_instruction(pdf_written)
            if args.full:
                # Say the scope out loud rather than let "--full was passed" imply a
                # completeness this document lacks. Not a suppression of the PDF's own
                # disclosure — a second copy, on the channel the agent reads, since it
                # decides what to say about a file it may never open.
                _won = _MODE_FLAG.get(_mode, _mode)
                print(
                    "note: this PDF carries the findings only — the --full pipeline "
                    "blocks (installed-skill/plugin sweep, behavioural replay, second "
                    f"opinion) did not run, because {_won} ran instead of the "
                    "dashboard. The report states this on its own first page. For the "
                    f"complete document, run --dashboard --full --pdf without {_won}.",
                    file=sys.stderr,
                )

    if _mode == "trend":
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
        #
        # B-581: history_record() now REPORTS a dropped write instead of swallowing it
        # (history.record, B-278's shape). Surfaced unconditionally, not gated on
        # _explicit_paths like the read note below — a write failure is never a "normal
        # first run" state the way an absent file is, at the default location or not, and
        # this is the more serious of the two failures this task exists to catch: a cron
        # running `--trend --history /mnt/backup/hist.jsonl` after the mount drops loses
        # the point forever while "No history yet" looks like nothing is wrong.
        if not _skip_live_test_history:
            # B-579: this row is produced by the ACT of looking at the trend, not by a
            # check the user asked for — tag it distinctly ("view") so render_trend can
            # tell a run performed apart from a run merely looked at, both in the
            # per-row [source] tag and in the "N of M runs have no grade" count, which
            # otherwise inflates itself every time this branch runs: three bare --trend
            # invocations into one fresh store used to read "3 of 3 runs have no grade" —
            # the tool grading its own look.
            _write_err = history_record(score, args.history, source="view",
                                         home=args.home, findings=findings,
                                         version=__version__)
            if _write_err is not None:
                # B-581: history.record() hands back the raw OSError text (e.g.
                # "[Errno 13] Permission denied: '/home/dave/...'"), which — unlike
                # _path_problem_text's composed line — has NOT been through
                # _redact_home_paths yet; apply it here too, or this is the one message
                # in the pair that still leaks the OS username.
                print(f"note: --trend: this run's score could not be recorded to "
                      f"{_redact_home_paths(_sanitize(str(args.history)))}: "
                      f"{_redact_home_paths(_sanitize(_write_err))}. The point was NOT "
                      "saved; your existing history (if any) is unaffected.",
                      file=sys.stderr)
        # Same "attempt, then classify" read as --watch-log above: an unreadable path the
        # user actually NAMED is reported, an absent default-location file stays silent
        # (a genuine first run).
        rows, _read_problem = history_load_with_problem(args.history)
        if _read_problem is not None and _explicit_paths["history"]:
            print(f"note: --history: {_path_problem_text(args.history, _read_problem, what='history file')}. "
                  "Showing no history for this run; your real history (if any) is "
                  "unaffected.", file=sys.stderr)
        # B-582: this viewer used to render the store without ever running the
        # tamper-evident check that exists for it. Same file, read again — cheap
        # (measured: 0.6% of a --trend run's own cost) — and never withholds a row
        # on a broken chain, only discloses it (see chain_provenance_note).
        _chain_status = history_verify(args.history)
        _emit(render_trend(rows, ascii_only, chain_status=_chain_status))
        _emit(_percentile_line(score, ascii_only, args.history))
        return 0

    if _mode == "percentile":
        # B-379: resolve the liveTest cap before ranking — previously this returned
        # before any cap resolution ran at all, so a run --full would grade F was
        # ranked against the recorded distribution as though it were an uncapped A.
        score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)
        # B-601: records, like every other mode that measures a verdict.
        #
        # The task that asked for this reasoned that recording first would make the run
        # rank against a distribution containing itself. That premise is wrong, and the
        # correction is worth leaving here so nobody re-derives it: `percentile.py` ranks
        # against a BUILT-IN reference CDF and never reads the local history at all (see
        # its module docstring — "NOT telemetry, NOT collected from real users"). So there
        # is no ordering dependency to protect. The record still comes after the emit, for
        # no stronger reason than that every sibling branch reads that way.
        _emit(_percentile_line(score, ascii_only, args.history))
        _record_history_point(score, args, _live_signal, findings)
        return 0

    if _mode == "next":
        # B-379: same cap-resolution gap as --percentile above — suggested next actions
        # should reflect the capped grade, not an uncapped one.
        score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)
        _emit(render_next_actions(suggest_actions(findings, score), ascii_only))
        # B-601: advice is what this mode RENDERS, but it measured a full verdict to get
        # there. The timeline records runs, not renderings.
        _record_history_point(score, args, _live_signal, findings)
        return 0

    if _mode == "dashboard":
        if not args.full:
            # Byte-identical to before F-153: the overwhelming majority of callers
            # (every pre-existing test, and every plain `--dashboard` invocation)
            # never asked for the rest of the pipeline, so nothing extra is computed.
            #
            # B-598: except that it recorded no history point, so a chat-driven audit
            # never reached --trend or the menu's "last check" line. Resolving the
            # liveTest cap first is the same one-liner --percentile/--next already carry
            # (B-379) and is what gives the history gate a signal to honour. It cannot
            # move this card's grade: a plain --dashboard never runs the installed-skills
            # sweep, so the run is ungraded by construction and there is no number for
            # F-155 to cap — the recorded line carries no score and no letter either way
            # (docs/USAGE.md's "the timeline stays unbroken", C-426's history rows).
            score, _live_signal = _apply_live_test_cap(ctx, findings, score, args)
            # B-605: render first, then put the relay instruction out BEFORE the card.
            # Emitting it after cost the whole fix on a long card -- see
            # `_emit_paste_instruction`'s docstring for the measured byte offsets.
            _card = _with_next_actions(
                render_dashboard(findings, score, ascii_only=ascii_only, ctx=ctx,
                                 pdf_path=pdf_written),
                findings, score, ascii_only)
            _emit_paste_instruction(pdf_written, len(_card))
            _emit(_card)
            _emit_attach_instruction(pdf_written)
            _record_history_point(score, args, _live_signal, findings)
            return _findings_exit_gate(args, findings, ctx)
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
        (score, full_deadline, judged_bundle, _live_signal, _behavioral_fired_ids, _ledger,
         _live_test_bucket, _behavioral_analysis) = (
            _resolve_runtime_caps(ctx, findings, score, args, attestation=attestation)
        )
        # B-586: AFTER the recompute, never before. `score` above is the phase-aware,
        # possibly-graded one; the value these renderers see at the `--pdf` write site
        # further up is still the bare-ledger score computed pre-dispatch, and writing
        # the badge there produced the very "no grade yet" this task is about — on the
        # run that had just earned a grade. Same reason `--pdf` defers its own write
        # under `--full` (`_defer_pdf`), one line of cause apart.
        # B-723: the write moved BELOW the ledger re-projection further down. B-586
        # already established that these renderers must see the phase-aware score
        # rather than the pre-dispatch one; the re-projection makes the score move a
        # second time, once the sweeps this branch runs have actually finished, so the
        # same reasoning puts the write after that too. Writing here would put a grade
        # in the badge that the run had not yet earned.
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
        # B-723: WHY a sweep produced no object is not one fact but four, and the layer
        # ledger below has to state the right one. `--fast`, a build without the plugin
        # sweep, a budget spent before the phase started, and a phase that raised all
        # leave `plugin_sweep is None` — but they are "the operator narrowed the run",
        # "this build cannot", "we ran out of time" and "it broke". Collapsing them would
        # be the same shape as the promise this task removed: one status standing in for
        # states nobody observed apart.
        _plugin_absent = _pipeline._skipped(
            _pipeline.PHASE_PLUGIN_SWEEP, "skipped — --fast was given.", section=False)
        _skill_absent = _pipeline._skipped(
            _pipeline.PHASE_SKILL_SWEEP, "skipped — --fast was given.", section=False)
        if not args.fast:
            _plugin_sweep_fn = _pipeline.resolve_plugin_sweep()
            if _plugin_sweep_fn is None:
                _plugin_absent = _pipeline.PhaseResult(
                    name=_pipeline.PHASE_PLUGIN_SWEEP, status=_pipeline.STATUS_UNAVAILABLE,
                    complete=False, section=False,
                    detail=("the installed-plugin sweep is not available in this build — "
                            "no plugin was inspected. Vet a plugin directly with "
                            "--vet-plugin."))
            elif budget_exceeded(full_deadline):
                _plugin_absent = _pipeline._not_reached(
                    _pipeline.PHASE_PLUGIN_SWEEP, DEFAULT_FULL_BUDGET_S)
            else:
                _sweep_budget_s = _pipeline.sub_budget(full_deadline, DEFAULT_VET_ALL_BUDGET_S)
                try:
                    plugin_sweep = _plugin_sweep_fn(
                        sweep_home, ascii_only=ascii_only,
                        sweep_budget_s=_sweep_budget_s, narrate=False)
                except Exception as _exc:  # noqa: BLE001 — one phase must not break the card
                    plugin_sweep = None
                    _plugin_absent = _pipeline.PhaseResult(
                        name=_pipeline.PHASE_PLUGIN_SWEEP, status=_pipeline.STATUS_ERROR,
                        complete=False, section=False,
                        detail=(f"the plugin sweep could not complete ({_sanitize(str(_exc))})"
                                " — no plugin verdict below can be relied on."))
            if budget_exceeded(full_deadline):
                _skill_absent = _pipeline._not_reached(
                    _pipeline.PHASE_SKILL_SWEEP, DEFAULT_FULL_BUDGET_S)
            else:
                _skill_sweep_budget_s = _pipeline.sub_budget(full_deadline, DEFAULT_VET_ALL_BUDGET_S)
                try:
                    # B-404: reuse the SAME ctx the audit above already collected —
                    # same pattern the --full (human/json) call sites use.
                    skill_sweep = sweep_installed_skills(
                        sweep_home, ascii_only=ascii_only,
                        sweep_budget_s=_skill_sweep_budget_s, narrate=False, ctx=ctx)
                except Exception as _exc:  # noqa: BLE001 — one phase must not break the card
                    skill_sweep = None
                    _skill_absent = _pipeline.PhaseResult(
                        name=_pipeline.PHASE_SKILL_SWEEP, status=_pipeline.STATUS_ERROR,
                        complete=False, section=False,
                        detail=(f"the skill sweep could not complete ({_sanitize(str(_exc))})"
                                " — no skill verdict below can be relied on."))
        behavioral_phase = None
        if not args.fast and not budget_exceeded(full_deadline):
            behavioral_phase = _pipeline.run_behavioral(ctx, ascii_only=ascii_only)
        # B-723: the ledger this branch scores against is now projected from the phases
        # that ACTUALLY ran, not from `_resolve_runtime_caps`'s pre-sweep promise. Built
        # here rather than from a `run_pipeline` call because this branch runs its phases
        # inline (it renders a card, not the pipeline's own sections), so there is no
        # `PipelineResult` to inherit — the phases are folded through the same public
        # recorders `run_pipeline` uses, so both paths derive `installed_sweep` from one
        # rule. Placed BEFORE P9 on purpose: the adjudication packet carries `score`, and
        # a judge reading a grade the run had not earned is the same defect one surface on.
        _dashboard_phases = _pipeline.PipelineResult(fast=args.fast)
        _dashboard_phases.add(_pipeline.record_skill_sweep(skill_sweep)
                              if skill_sweep is not None else _skill_absent)
        _dashboard_phases.add(_pipeline.record_plugin_sweep(plugin_sweep,
                                                            absent=_plugin_absent))
        if behavioral_phase is not None:
            _dashboard_phases.add(behavioral_phase)
        _ledger = _dashboard_phases.to_ledger(
            findings, degraded_count=score.degraded_count, attestation=attestation,
            live_test_bucket=_live_test_bucket, behavioral_analysis=_behavioral_analysis)
        score = compute(findings, ctx, live_test_vulnerable=_live_signal.hit,
                        live_test_reason=_live_signal.reason,
                        behavioral_fired_ids=_behavioral_fired_ids, ledger=_ledger)
        # B-586 + B-723: written only now, against the score the completed phases earned.
        _write_dashboard_side_outputs(args, findings, score, ctx, _report_dest, _emit)
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
            version=__version__, bundle=judged_bundle, score=score)
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
        _card = _with_next_actions(
            render_dashboard(
                findings, score, ascii_only=ascii_only, ctx=ctx, full=True,
                risk=paths, plugin_sweep=plugin_sweep, behavioral=behavioral_phase,
                adjudication=adjudication_phase, compact=args.compact,
                pdf_path=pdf_written,
                # Reserve what _with_next_actions is about to append, so the card's own
                # severity-ordered ladder absorbs it rather than the cap being exceeded.
                compact_reserve=len(_COMPACT_NEXT_POINTER) if args.compact else 0),
            findings, score, ascii_only, compact=args.compact)
        _emit_paste_instruction(pdf_written, len(_card))
        _emit(_card)
        _emit_attach_instruction(pdf_written)
        # B-598: `score` here is the phase-aware, possibly-GRADED one from
        # `_resolve_runtime_caps` — the same object the card above just rendered — so the
        # recorded line carries the letter this run actually earned. This is the shape
        # SKILL.md's guided flow uses, and the one whose absence meant no graded run was
        # ever recorded by anyone following the documented path.
        _record_history_point(score, args, _live_signal, findings)
        # The sweeps this branch ran are FAIL sources the default `--full` path already
        # feeds the gate; passing them keeps `--dashboard --full --exit-code` exactly as
        # strong as `--full --exit-code`, instead of quietly weaker on the same depth.
        return _findings_exit_gate(
            args, findings, ctx,
            extra_fail=bool(getattr(plugin_sweep, "has_fail", False))
            or bool(getattr(skill_sweep, "has_fail", False)),
        )

    if _mode == "dashboard_findings":
        # Same contract as the full card: SKILL.md Step 3 pastes this block verbatim, so
        # it carries the same relay instruction. No PDF is written on this path.
        _card = render_dashboard_findings(findings, ascii_only=ascii_only)
        _emit_paste_instruction(card_chars=len(_card))
        _emit(_card)
        return 0

    if _mode == "sbom":
        _emit(render_sbom(ctx))
        return 0

    if _mode == "incident":
        # B-277: --events was accepted and silently dropped here, so the pack
        # harvested the DEFAULT journal no matter what the operator named. Threaded
        # like --watch-log (:~915) and --monitor (:~1078) already do.
        _emit(render_incident(ctx, findings, score, events=args.events))
        return 0

    if _mode == "judge_packet":
        _emit(render_judge_packet_json(ctx, findings, version=__version__, score=score))
        return 0

    if _mode == "judged":
        verdicts_raw = _verdicts_with_note(args.judged, "--judged")
        # B-355: `paths` (the RISK-* attack-chain data, computed above) was never
        # threaded through, so --judged silently omitted the risk_paths key entirely
        # (not an empty list -- absent) even though plain --json on the same run
        # carries it. Mirror the plain --json call site below (:~1737), which already
        # passes risk=paths.
        _emit(render_judged_json(ctx, findings, score, verdicts_raw=verdicts_raw, risk=paths))
        return 0

    if _mode == "propose_ignore":
        verdicts_raw = _verdicts_with_note(args.propose_ignore, "--propose-ignore")
        _emit(render_ignore_proposals_json(findings, verdicts_raw=verdicts_raw, version=__version__))
        return 0

    if _mode == "analyze_trajectory":
        _traj_target = args.analyze_trajectory or None
        # B-599: read the ledger from the store THIS run is using. `_coverage_path` is
        # the same resolver the write side (`_record_run`) and the freshness notice
        # already go through, so --data-dir moves this file with the other three instead
        # of leaving one reader pointed at the operator's real ~/.clawseccheck/.
        _emit(render_trajectory_analysis(
            ctx, explicit_path=_traj_target, ascii_only=ascii_only,
            ledger_path=_coverage_path(args)))
        # B-686: a path the user named that could not be used is THEIR fact, and 0 said
        # the opposite — the report explained the problem while the exit code told any
        # script reading `$?` that the analysis had completed. Decided rather than
        # inherited: 1 is what --behavioral already returns for the same three cases
        # through the same predicate (see `_behavioral_path_problem` below), and the two
        # modes taking the same kind of argument should not answer it differently.
        #
        # Only reachable with an explicit path: with none, the predicate returns None and
        # this stays 0, which is the correct answer for "this host has no trajectories".
        if _behavioral_path_problem(_traj_target):
            return 1
        return 0

    if _mode == "behavioral":
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

    if _mode == "monitor":
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
        # F-173: run the behavioural layer HERE, in the shell, and hand `snapshot()` only
        # the reduced verdict. Two deliberate choices:
        #
        # `monitor.py` never imports `behavioral` — the containment for a subsystem that
        # can raise on a schema-drifted config belongs in the shell, which is where
        # `_resolve_runtime_caps` and `pipeline.run_behavioral` already wrap this identical
        # call. A monitor run must not be taken down by the layer it just gained.
        #
        # `_behavioral_grade_cap_signal`, never `result["findings"]`. The rule is
        # structural: a bare B191 divergence under a rotated cap is behavioral.py's own
        # documented benign background noise, so raw findings would put a permanent entry
        # in the drift stream. On failure the key is left ABSENT rather than set empty, so
        # the next diff says "not examined" instead of "nothing found".
        #
        # The measurement this used to cite is re-grounded rather than restated, because it
        # had rotted into something that no longer reproduces. As of 2026-08-26 on the
        # maintainer's machine: files_capped is still True (60 of 88 trajectory files read,
        # not the 93 this comment used to name), but B191 reads PASS and grade_cap_signal()
        # returns the empty set — so the divergence that motivates the filter is NOT
        # currently firing. It is a hazard the filter exists to hold off, not a live
        # measurement, and writing it in the present tense made a test-pinned claim out of
        # a state of the world.
        #
        # Cost, re-measured the same day: analyze() 0.26 s against a 7.66 s run_all (both
        # up from the 0.176 s / 4.9 s originally recorded here) — still under 4% of a run
        # it makes materially less blind.
        _behavioral_snap = None
        try:
            _b_result = _behavioral_analyze(ctx)
            _behavioral_snap = {
                "fired": sorted(_behavioral_grade_cap_signal(_b_result)),
                "undetermined": sorted(
                    f.id for f in _b_result.get("findings", ()) if f.status == UNKNOWN),
                "capped": bool(_b_result.get("files_capped")),
                # F-182 follow-up. `files_capped` is ONE of six reasons a replay cannot
                # support a clean verdict, and the severity gate in monitor.py was keyed on
                # it alone. Measured: a sidecar the reader cannot OPEN (mode 000, a broken
                # link, a race) leaves `files_capped` False while the run parsed nothing —
                # so an incomplete run read as complete and would have paged on a detector
                # that was newly SEEN rather than newly done. That is exactly the false
                # alarm the advisory wording existed to prevent.
                #
                # `analysis_incompleteness` is the single predicate that owns this question
                # and lives beside the flags it reads, precisely so a caller re-deriving it
                # cannot miss a new one. Asking it here rather than restating its six arms.
                "incomplete": _behavioral_incompleteness(_b_result) is not None,
            }
        except Exception:  # noqa: BLE001 — see run_behavioral's identical containment
            _behavioral_snap = None
        # F-174: the two supply-chain subjects. Resolved HERE for the same reason the
        # behavioural layer above is — one of them reads PATH, which is a shell concern —
        # and contained the same way, so a subject that cannot be read leaves its key
        # absent instead of taking the run down or writing an empty view as fact.
        #
        # Cost measured on the real machine before either was written: describe_install
        # 0.34 s (7,717 files / 77.8 MB, after an os.walk rewrite from 0.89 s),
        # read_provenance 0.4 ms. Against a ~7.8 s monitor run.
        _install_snap = None
        try:
            _found = _describe_install("openclaw")
            _install_snap = _found.as_dimension() if _found is not None else None
        except Exception:  # noqa: BLE001 — a supply-chain reader must not kill the watch
            _install_snap = None
        _provenance_snap = None
        try:
            _scan = _read_provenance(ctx.home, ctx.config)
            # Gated on `present`, not on the scan succeeding. A scan that found no lock
            # file returns an empty mapping, and so does one that found a lock file with
            # nothing installed — recording the first as `{}` would state "you have no
            # skills installed" about a setup we never looked at the right place for, and
            # the next run that DID find the file would report every skill as newly
            # installed. Absent means "not established"; `{}` means "established, empty".
            _provenance_snap = _scan.as_dimension() if _scan.present else None
        except Exception:  # noqa: BLE001 — same containment
            _provenance_snap = None
        # F-179: the host's own startup and scheduling surface. Same containment as the two
        # above — it walks `/etc` and `sys.path`, and a permission surprise on an unusual
        # box must leave the dimension absent rather than take the watch down.
        #
        # THE HOME HERE IS THE USER'S, NOT `ctx.home`. This looks like an inconsistency with
        # every other collector in this file and it is deliberate — `ctx.home` is the
        # OpenClaw state directory (`~/.openclaw`), while this surface lives in the account's
        # home (`~/.config/systemd/user`, `~/.bashrc`). Passing `ctx.home` was the first
        # version and it FAILED SILENTLY: the scan looked for `~/.openclaw/.config/...`,
        # found nothing there, and returned 23 entries instead of 36 with no error — every
        # home-rooted family missing, the two system-wide ones intact, and a plausible
        # number on the screen. Caught by comparing the two counts before shipping.
        #
        # `os.path.expanduser` rather than `Path.home()`: on POSIX it consults $HOME first,
        # so a test can redirect it, which `Path.home()` does not reliably allow. `--home`
        # deliberately does NOT move this scan; it names a different directory.
        #
        # Cost measured on the real machine: 63 ms cold, 5.2 ms warm, for 34 entries across
        # three families, against a ~12.9 s monitor run. Both figures are stated because the
        # cold one is what a 6-hourly cron job actually pays.
        _host_persist_snap = None
        try:
            _hp_scan = _hostpersist_scan(os.path.expanduser("~"))
            _host_persist_snap = _hostpersist_to_snapshot(_hp_scan)
        except Exception:  # noqa: BLE001 — same containment
            _host_persist_snap = None
        # B-269: snapshot() needs the previous state so that a run which could not read
        # openclaw.json preserves the last known-good config baseline instead of writing
        # the collapsed (empty) view over it — see monitor._degrade_snapshot.
        # B-677: OpenClaw's own credential store, read HERE in the shell for the same
        # reason `host_persist` is — the scan is the caller's to run, and `monitor.py`
        # stays out of the collection business. Digests and names only, never a value.
        # Contained: a store that cannot be walked must not take a monitor run down.
        try:
            _credentials_snap = _credential_store_state(ctx.home)
        except Exception:  # noqa: BLE001 - never let the store scan end the run
            _credentials_snap = None
        snap = snapshot(ctx, findings, score, prev=prev, behavioral=_behavioral_snap,
                        install=_install_snap, provenance=_provenance_snap,
                        host_persist=_host_persist_snap, credentials=_credentials_snap)
        # C-418: `notes` records every comparison this run DECLINED to make. They are
        # deliberately NOT passed to record_events below — a note is not an event, and a
        # tamper-evident timeline of what changed must not fill with entries about what
        # did not.
        alerts, monitor_notes = diff_with_notes(prev, snap)
        # F-175 tier 3: an update is the moment a vetted setup silently becomes an unvetted
        # one. When the install records show a skill moved, re-run the vetting for THAT
        # skill and report the verdict — not merely "the version is different". This is the
        # only tier of the pre-update story that needs no cooperation from the user: it
        # happens on the next scheduled run whether or not they remembered to ask.
        #
        # Affordable, measured rather than assumed: `vet_skill` averages 0.010 s across the
        # fixture corpus, so even a bulk update costs less than the behavioural layer. The
        # cap is a backstop against a pathological tree, not a budget, and it is DISCLOSED
        # when it bites — a silent top-N would read as "everything that changed was
        # checked".
        #
        # Gated on there being changes, so a quiet run does nothing at all. Contained the
        # same way every other reader in this branch is: vetting reads third-party skill
        # content, and a crash in it must not take down the watch that found the change.
        _revet_names = _changed_skills(prev, snap)
        if _revet_names:
            _revet_roots = _workspace_roots(Path(args.home).expanduser(), ctx.config)
            for _name in _revet_names[:_REVET_CAP]:
                _target = next((r / "skills" / _name for r in _revet_roots
                                if (r / "skills" / _name).is_dir()), None)
                if _target is None:
                    # The record moved but the directory is not where the records say. Not
                    # an accusation: a workspace we cannot reach, or a removal mid-update.
                    monitor_notes.append((NOTE_UNDETERMINED,
                                          f"The skill '{_name}' changed, but its files "
                                          f"could not be found to re-check."))
                    continue
                try:
                    _finding = vet_skill(_target)
                    # The PROFILE's verdict, not the bare Finding's status — the same
                    # `build_profile` result `--vet-skill` and `--advise` render. The
                    # reason is structural, not a measurement: INSTALL / CAUTION /
                    # DO-NOT-INSTALL exists ONLY on the profile, so the bare status cannot
                    # express the word this line has to print, and reporting it would make
                    # the monitor and `--vet-skill` disagree about the same skill — worse
                    # than not re-checking at all.
                    #
                    # C-440: this comment used to justify the choice with "on a real
                    # ClickFix fixture `vet_skill(...).status` is PASS while the dossier
                    # says CAUTION". That does not reproduce. Measured on
                    # `fixtures/bad_b100_clickfix_setup/skills/quick-tool`: bare WARN,
                    # profile WARN, ring_findings 0 — the two agree and the ring is empty.
                    # The decision is still right for the structural reason above; only
                    # its stated evidence was wrong, which is worth more than a footnote
                    # because a false measurement in a comment is load-bearing until
                    # someone re-runs it.
                    _profile = build_profile(_finding, str(_target), "skill")
                    _status = _profile.overall_status
                    # B-540: with ONE exception. `build_profile` scores only the
                    # PASS/WARN/FAIL axes, so a skill whose content could not be parsed at
                    # all loses the one fact that mattered — that the re-check concluded
                    # "I cannot tell". UNKNOWN is not a point on the PASS/WARN/FAIL scale
                    # and must not be resolved onto it.
                    #
                    # C-440: the failure this guards against is not the one the comment
                    # used to describe. It said the profile came back PASS and the finding
                    # was then dropped by the `_lvl is None` branch below, so the user
                    # heard nothing. Re-measured on
                    # `fixtures/unknown_b347_deaddrop_unparseable/skills/broken-sync`:
                    # bare UNKNOWN, profile WARN, verdict CAUTION, and
                    # `_REVET_SEVERITY[WARN]` is MEDIUM — not None, so nothing is dropped.
                    # Today the same input would be REPORTED, as a CAUTION the engine never
                    # concluded. Silence became misattribution; the guard is still required
                    # and is now required for a different reason.
                    #
                    # This does NOT reopen the disagreement the comment above closes:
                    # `--vet-skill` on that same directory prints the UNKNOWN danger axis
                    # one line under its headline, so the fact survives there. The profile
                    # still owns every PASS/WARN/FAIL verdict.
                    if _finding.status == UNKNOWN:
                        _status = UNKNOWN
                except Exception:  # noqa: BLE001 — see the containment above
                    monitor_notes.append((NOTE_UNDETERMINED,
                                          f"The skill '{_name}' changed and could not be "
                                          f"re-checked this run."))
                    continue
                _lvl = _REVET_SEVERITY.get(_status)
                if _lvl is None:
                    continue          # PASS after a change is not news; the change is
                if _status == UNKNOWN:
                    # Say both facts and neither more: it changed, and this run could not
                    # tell whether the new content is safe. UNKNOWN is the absence of
                    # evidence, not evidence — the line must not read as an accusation.
                    # The verdict word comes from the FORCED status, because
                    # `_profile.verdict` is INSTALL here and "INSTALL: could not analyze"
                    # is the same self-contradiction one layer down.
                    alerts.append((
                        _lvl,
                        f"The skill '{_name}' changed and this run could not determine "
                        f"whether it is safe — {verdict_for(UNKNOWN)}: {_finding.detail}"))
                    continue
                alerts.append((
                    _lvl,
                    f"Re-checked '{_name}' after it changed — {_profile.verdict}: "
                    f"{_finding.detail}"))
            if len(_revet_names) > _REVET_CAP:
                monitor_notes.append((
                    NOTE_INSPECTION_CAPPED,
                    f"{len(_revet_names) - _REVET_CAP} more skill(s) changed than this run "
                    f"re-checks. Run --vet-all to cover them."))
        if base_status == BASELINE_CORRUPT:
            # prev is None here, so diff() produced nothing to compare — the lost baseline
            # IS the event. Prepended (not rendered separately) so the identical string
            # reaches the screen and the tamper-evident journal.
            alerts = [BASELINE_CORRUPT_ALERT] + alerts
        # ── B-676: the watch getting quieter is itself drift ───────────────────────────
        #
        # Runs HERE, not inside `diff_with_notes`, because three of the note appends above
        # happen in this shell — the re-vet overflow, the history-write failure and the
        # re-vet cap — so an arm one level down would compare against an incomplete note
        # set and report those three as newly lost on the following run.
        #
        # The signature is taken BEFORE the arm runs, so a note the arm itself emits (the
        # post-upgrade stand-down, the cap disclosure) is not recorded as a comparison this
        # run skipped — it would read as newly lost next run and vanish the run after.
        #
        # Appends to `alerts`, which is the whole point: `--exit-code`/`--fail-on` stay a
        # pure function of alerts (cli.py's contract note below is unmoved), and a coverage
        # regression now simply IS an alert, so `--fail-on medium` picks it up like any
        # other drift.
        _coverage_now = _coverage_signature(monitor_notes)
        _diff_coverage(prev, snap, monitor_notes, alerts,
                       lambda _cat, _msg: monitor_notes.append((_cat, _msg)))
        if base_status == BASELINE_OK:
            # Conditional on a USABLE baseline: a run that compared nothing must not store
            # an empty list, which would mean "the watch skipped nothing last time".
            snap["not_compared"] = _coverage_now
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
        # F-180: a probe answers "is anything different" without ANSWERING it — none of the
        # three files moves, so the drift stays unconsumed and the next ordinary run reports
        # it again. That re-detection is the point, not a duplicate: B-278's note a few
        # lines up already established that leaving a baseline un-advanced is how drift
        # survives a failed write, and this is the same shape chosen deliberately.
        _probe = bool(getattr(args, "probe", False))
        journal_err = (record_events(alerts, args.events)
                       if not (_skip_live_test_persist or _probe) else None)
        state_err = None
        # F-155: an unseeded VULNERABLE verdict must never be recorded, so the baseline
        # advance is skipped exactly like a write failure would skip it — except this is
        # not a failure (state_err stays None; no stderr, no non-zero exit below).
        if journal_err is None and not _skip_live_test_persist and not _probe:
            try:
                save_state(args.state, snap)
            except OSError as exc:
                state_err = str(exc)
        persisted = (journal_err is None and state_err is None
                     and not _skip_live_test_persist and not _probe)
        # F-173 Part B: an off-machine anchor for the baseline — on screen always, in the
        # event chain only when it MOVED.
        #
        # Read back from disk after the save (not fingerprinted from `snap` in memory), so
        # a short write that left the file truncated fails here instead of matching.
        #
        # Journaled AFTER save_state, which is the reverse of the B-278 order above —
        # deliberately, and without conflicting with it. B-278 journals first so a failed
        # journal cannot let the baseline advance past unrecorded drift. This entry makes a
        # claim ABOUT the file on disk, so writing it before the save would assert
        # something not yet true, and a failed save would leave a record of a baseline that
        # never existed.
        #
        # Gated on the value having CHANGED, and that gate is load-bearing. An earlier
        # version journaled unconditionally and broke three things at once: two tests that
        # pin "a first monitor run journals nothing", `--brief`'s event count (a daily cron
        # would report "365 event(s) recorded" over a timeline of nothing), and the
        # journal's own 5,000-line retention, which would start evicting the genuine drift
        # alerts a quiet machine had kept.
        #
        # A failure here is NOT `MONITORING NOT ESTABLISHED`: the baseline is saved and
        # drift detection works. What is lost is one local record of the anchor, which is
        # worth a line on stderr and nothing more.
        _reference = baseline_reference(args.state)[0] if persisted else ""
        _prev_reference = snapshot_reference(prev)
        # `_prev_reference` empty means there was no prior baseline to move FROM — a first
        # run, or one whose baseline was corrupt. Treating that as "the value changed" is
        # what a first version did, and it journaled on a first run, which two existing
        # tests pin as writing nothing. The reference still reaches the user: the screen is
        # where they get it, and the journal is where its LATER movements are recorded.
        if _reference and _prev_reference and _reference != _prev_reference:
            _witness_err = record_events(baseline_witness_event(_reference), args.events)
            if _witness_err is not None:
                print(f"Note: the baseline was saved, but its reference value could not be "
                      f"recorded in {args.events}: {_witness_err}", file=sys.stderr)
        # F-176: one boolean saying whether THIS run made every comparison this build knows
        # how to make — the machine-channel analogue of the scoped ✅ C-418 gave the human
        # report. Named `fully_compared`, never `complete`: a first run legitimately has
        # nothing to compare against yet, and that is correct, not a defect, so the name
        # must not read as a verdict on the run itself — only as a coverage fact.
        #
        # Definition: `base_status == BASELINE_OK and not monitor_notes`. Two narrower
        # definitions were tried and rejected against the actual note sites above:
        #
        # - `not monitor_notes` alone. Rejected: `diff_with_notes` deliberately returns
        #   `([], [])` — NO notes — on both BASELINE_ABSENT and BASELINE_CORRUPT (its own
        #   comment: "A note would be a second, vaguer voice for a state that is already
        #   named precisely"). Using notes alone would call an empty first run, which
        #   compared nothing, "fully compared" — the exact reassuring lie this field exists
        #   to stop making.
        # - `base_status == BASELINE_OK` alone. Rejected: an OK (present, usable) baseline
        #   can still carry NOTE_CONFIG_BLIND / NOTE_INSPECTION_CAPPED / NOTE_UNDETERMINED /
        #   NOTE_NO_PRIOR_RECORD notes — from `diff_with_notes` itself, or appended by the
        #   re-vet loop above — each recording a real comparison this run skipped despite
        #   having a valid prior baseline to compare against.
        #
        # Both conditions together are exactly "there was something to compare against, and
        # every comparison this build knows how to make against it was actually made".
        _fully_compared = base_status == BASELINE_OK and not monitor_notes
        # B-271: render AFTER the writes, and tell the renderer whether they landed — the
        # success wording used to be printed before the save was even attempted.
        if args.json:
            # F-176: the machine channel. `alerts`/`notes` carry EXACTLY what
            # `diff_with_notes` (plus the re-vet loop's own appends) produced — no
            # transformation beyond `_sanitize`, the same redaction the text renderer
            # already applies to both. A note never appears here as an alert, and neither
            # array is ever written to `args.events` (only `alerts` is, above).
            _monitor_payload = {
                "alerts": [{"severity": lvl, "message": _sanitize(msg)}
                          for lvl, msg in alerts],
                "notes": [{"category": cat, "message": _sanitize(msg)}
                         for cat, msg in monitor_notes],
                "baseline_status": base_status,
                "persisted": persisted,
                "fully_compared": _fully_compared,
                # Parity with the text renderer's other inputs — free to compute, and a
                # JSON consumer should not have to shell out to --json (no --monitor) just
                # to learn the score this run actually saw.
                "score": score.score if getattr(score, "graded", True) else None,
                "grade": score.grade if getattr(score, "graded", True) else None,
                "graded": bool(getattr(score, "graded", True)),
                "baseline_reference": _reference or None,
            }
            _emit(json.dumps(_monitor_payload, ensure_ascii=True, indent=2))
        else:
            _emit(render_monitor(alerts, score, ascii_only,
                                 baseline=base_status == BASELINE_ABSENT,
                                 persisted=persisted,
                                 baseline_corrupt=base_status == BASELINE_CORRUPT,
                                 live_test_skipped=_skip_live_test_persist,
                                 notes=monitor_notes,
                                 verbose=bool(getattr(args, "verbose", False)),
                                 baseline_ref=_reference))
        # --monitor records a score-history point as part of tracking drift, even under
        # --no-history; the conflict is surfaced as a stderr note (B-066), not silently
        # honored, to keep monitor's drift baseline intact. Recorded even on the failure
        # paths below: this run's score was really measured, and the trend should not gain
        # a hole because a different file was unwritable. Skipped only for the same F-155
        # unseeded-live-test exclusion as the baseline advance above.
        # F-180: `_probe` too, and this one was NOT obvious — the first implementation
        # gated only `record_events` and `save_state`, and the end-to-end test caught
        # `history.jsonl` still growing on every poll. That is the documented three-file
        # footgun (--state and --events do not isolate a run; --history defaults
        # independently), reappearing inside the very feature written to avoid consuming
        # state. A frequent poll would have quietly padded the score trend with a row per
        # poll while claiming to write nothing.
        if not _skip_live_test_persist and not _probe:
            history_record(score, args.history, home=args.home,
                           findings=findings, version=__version__)
        # F-180: a probe must SAY it did not record, or the user reads the alert as filed
        # and then sees the identical alert on the next ordinary run with no explanation.
        if _probe:
            print("\nThis was a probe: nothing was recorded, so your baseline still points "
                  "at the last ordinary check.\n  The change above is still outstanding and "
                  "the next ordinary run will report it again.")
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
        # C-419: opt-in machine channel. `rc=1` above is RESERVED for "monitoring is not
        # established" — a cron job has to be able to tell "drift was found" from "the
        # store is unwritable", and overloading one code would destroy that distinction.
        # So drift exits 3 (see the return below for why not 2).
        #
        # F-176: `fully_compared`/`baseline_status` do NOT get their own exit code, and the
        # decision is deliberate, not an oversight. Rejected: a fifth value (say, "4" for
        # "ran clean but was partial") — it would need its own opt-in flag to stay backward
        # compatible (the task forbids a second, competing --exit-code surface), and a bare
        # `--exit-code`/`--fail-on` invocation that started returning non-zero on an
        # ordinary partial run (any first run, any run with a momentarily-unreadable
        # config) would silently change what 0 already promises the published cron recipe.
        # The JSON payload's `fully_compared`/`baseline_status`/`notes` carry the scoping
        # instead — the "keep 0, let the JSON carry it" option the task calls safest. The
        # exit code stays a pure function of `alerts`/`persisted`, exactly as C-419 left it.
        #
        # Off unless asked for, because the previous behaviour is documented as deliberate
        # and a published cron recipe is built on it: users running that recipe under
        # `set -e` would break the day they upgraded.
        #
        # Threshold defaults to HIGH and above. On the audit path a bare --exit-code means
        # "any FAIL" — the strongest verdict class only, WARN does not trip it. The monitor
        # analogue of that is not "any alert": alerts run CRITICAL..INFO, and INFO carries
        # routine advisories, so paging on those is the noise that gets a check switched
        # off. --fail-on moves the line for anyone who disagrees, using the ranking that
        # already ships.
        if getattr(args, "exit_code", False) or args.fail_on is not None:
            _rank = (_SEVERITY_RANK[args.fail_on.upper()] if args.fail_on is not None
                     else _SEVERITY_RANK[HIGH])
            # Gated on `persisted`, not on having got this far. The two `return 1` blocks
            # above cover a FAILED write, but there is a third state: the F-155 seed gate
            # deliberately skips persistence for an unseeded live-test verdict, and that
            # path sets no error at all. Reaching here with `persisted` False means the
            # alerts were computed and NOT recorded — so the next run will report them
            # again, and an exit code claiming "drift was journaled" would be describing
            # something that did not happen. An earlier version of this comment asserted
            # these alerts were always journaled; it was wrong on exactly that path.
            # F-180: `or _probe`. Reading this arm as written, a non-persisting run returns
            # 0 EVEN WITH DRIFT — which for the F-155 seed gate is right (nothing was
            # recorded, so claiming "drift was journaled" would be false), and for a probe
            # is exactly backwards: a poll that cannot report drift is not a poll. The two
            # cases differ in intent, and only one of them chose not to write. So for a
            # probe, 3 means "drift exists and was deliberately left unconsumed" — which is
            # the signal a `trigger.script` needs — while 1 stays reserved for a store that
            # genuinely could not be written.
            if (persisted or _probe) and any(_SEVERITY_RANK.get(lvl, -1) >= _rank
                                             for lvl, _ in alerts):
                # 3, not 2. argparse exits 2 on ANY usage error, so a cron job reading the
                # published recipe reported "drift detected" for a mistyped flag —
                # reproduced with `--fail-on hgih`. A machine channel whose "something
                # changed" code is also "you typed it wrong" is worse than no channel.
                return 3
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
    (score, full_deadline, judged_bundle, live_signal, behavioral_fired_ids, layer_ledger,
     _live_test_bucket, _behavioral_analysis) = (
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
                bundle=judged_bundle, score=score,
                ledger_path=_coverage_path(args))
            pipeline_has_fail = full_pipeline.has_fail
            if not args.fast:
                _record_run("behavioral", args)
            # B-723: re-project the ledger from the REAL `full_pipeline` now that
            # P6/P7 (installed-skill/plugin sweep) have actually run, instead of the
            # pre-sweep PROMISE `_resolve_runtime_caps` built above (see
            # `_build_layer_ledger`'s retracted-argument paragraph). Same kwargs that
            # call already used — `live_test_bucket`/`behavioral_analysis` threaded
            # out of `_resolve_runtime_caps` rather than re-derived, `degraded_count`
            # off the same `score` object (a pure function of `findings`, so
            # identical whichever ledger it was computed against), `attestation` the
            # same local this function already threads into every ledger build.
            layer_ledger = full_pipeline.to_ledger(
                findings, degraded_count=score.degraded_count, attestation=attestation,
                live_test_bucket=_live_test_bucket, behavioral_analysis=_behavioral_analysis)
            score = compute(findings, ctx, live_test_vulnerable=live_signal.hit,
                            live_test_reason=live_signal.reason,
                            behavioral_fired_ids=behavioral_fired_ids, ledger=layer_ledger)
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
            f_notice = _compute_freshness(load_ledger(path=_coverage_path(args)), skip=_refreshed)
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
        # ── B-723: the work moves up, the output does not ────────────────────────
        # This report prints its grade in the body below, and the sweeps that decide
        # whether a grade may be issued at all used to run ~150 lines further down. So
        # the ledger the body was scored against described phases that had not happened.
        #
        # The phases are computed here and RENDERED where they always were. That is only
        # possible because `run_pipeline` is pure — it returns a `PipelineResult`;
        # `render_sections` prints it — and because `sweep_installed_skills`, the one
        # part that narrates inline as it walks, can have those lines intercepted and
        # replayed verbatim into its own slot (`_capture_emitted`).
        #
        # Only `self_test` and `vet_mcp` are stamped early, and only because
        # `run_pipeline` READS the coverage ledger for its self-test corroboration block:
        # hoisting the pipeline above those writes would make the block silently vanish.
        # Both are in the `_refreshed` set the freshness notice above skips under `--full`,
        # so moving them changes no prose. `vet` and `behavioral` are NOT hoisted — they
        # are outside that set, and stamping them before the notice is computed would
        # rewrite it.
        _hoisted_pipeline = None
        _hoisted_sweep = None
        _hoisted_sweep_lines: list[str] = []
        if args.full and not args.json and not args.card:
            sweep_home = Path(args.home).expanduser()
            sweep_budget_s = _pipeline.sub_budget(full_deadline, DEFAULT_VET_ALL_BUDGET_S)
            if not args.fast:
                _record_run("self_test", args)
                _record_run("vet_mcp", args)
                with _capture_emitted(_hoisted_sweep_lines):
                    _hoisted_sweep = sweep_installed_skills(
                        sweep_home, ascii_only=ascii_only,
                        sweep_budget_s=sweep_budget_s,
                        narrate=not args.quiet, ctx=ctx)
            _hoisted_pipeline = _pipeline.run_pipeline(
                ctx, findings, home_dir=sweep_home, skill_sweep=_hoisted_sweep,
                vet_targets=(_hoisted_sweep.vet_targets()
                             if _hoisted_sweep is not None else ()),
                deadline=full_deadline, budget_s=DEFAULT_FULL_BUDGET_S,
                fast=args.fast, ascii_only=ascii_only, version=__version__,
                bundle=judged_bundle, score=score,
                ledger_path=_coverage_path(args))
            layer_ledger = _hoisted_pipeline.to_ledger(
                findings, degraded_count=score.degraded_count, attestation=attestation,
                live_test_bucket=_live_test_bucket,
                behavioral_analysis=_behavioral_analysis)
            score = compute(findings, ctx, live_test_vulnerable=live_signal.hit,
                            live_test_reason=live_signal.reason,
                            behavioral_fired_ids=behavioral_fired_ids, ledger=layer_ledger)
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
                    # B-723: walked above the report body (silently, --quiet) — see the
                    # verbose branch for why it is not re-run here.
                    sweep = _hoisted_sweep
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
                            # B-629: cap of 4 here, and it used to end silently.
                            for line in _evidence_bullets(
                                vmf.evidence, limit=4, indent="    "
                            ):
                                _emit(line)
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
                #
                # B-536: that "visibility only" fact holds on every run shape, but the
                # sentence below used to assert it by POINTING ("the score or grade
                # above"), which is false on an ungraded run — see
                # `_sweep_not_folded_clause` for why only the noun moves.
                if not args.fast:
                    _emit("")
                    _emit("=" * 60)
                    _emit("CLAWSECCHECK SKILL SWEEP")
                    _emit("=" * 60)
                    _emit("Per-skill verdict for every installed skill. Not folded into "
                          + _sweep_not_folded_clause(score)
                          + "; per-skill dossier: --vet <path>.")
                    # B-723: already walked, above the report body — the per-target
                    # narration it produced is replayed here verbatim, in the slot it has
                    # always occupied. Re-running it would sweep the fleet twice and could
                    # disagree with the ledger the grade above was computed from.
                    sweep = _hoisted_sweep
                    for _sweep_line in _hoisted_sweep_lines:
                        _emit(_sweep_line)
                    for _sweep_line in _sweep_summary_lines(sweep, ascii_only=ascii_only):
                        _emit(_sweep_line)
                    sweep_has_fail = sweep.has_fail
                    _record_run("vet", args)

            # --- pipeline phases P7-P9 + the combined roll-up (P10) ------------------
            # Appended after everything above, for the same reason the skill sweep is: the
            # report body, SELF-TEST and VET-MCP keep the byte-for-byte shape and order they
            # have always had. Nothing new is printed between the report body and the
            # SELF-TEST line, which is the prefix --full --quiet is compared against.
            # B-723: computed above the report body, so the ledger the grade rests on
            # describes phases that ran. Rendered here, unchanged, in its own slot.
            full_pipeline = _hoisted_pipeline
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

    # B-598: the guard this used to spell out inline now lives in
    # `_record_history_point`, which the --dashboard branch calls too. Its docstring
    # carries the F-155 seed-gate reasoning that was written here.
    _record_history_point(score, args, live_signal, findings)

    if _save_failed:
        return 1

    return _findings_exit_gate(
        args, findings, ctx,
        extra_fail=vm_has_fail or sweep_has_fail or pipeline_has_fail,
    )


if __name__ == "__main__":
    raise SystemExit(main())
