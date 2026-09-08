"""B-755 — no consumer may discriminate between two statuses that rank identically.

WHY THIS FILE EXISTS
--------------------
``tests/test_b751_fail_weight.py`` got the METHOD right — drive the real consumers, do not
grep for literals — and still missed roughly thirteen consumers, because its **status** list is
derived from ``_VET_MERGE_RANK`` while its **consumer** list is written by hand. A new status
is picked up automatically; a new consumer is picked up never. That asymmetry is the defect
one level above any individual blind site, and this file closes it.

THE ORACLE
----------
``_VET_MERGE_RANK`` gives ``SKILL_ARCHIVE_PATH_TRAVERSAL`` exactly the rank it gives ``FAIL``.
So for any consumer, the two are interchangeable BY CONSTRUCTION, and the experiment is a
single-variable one:

    take one real finding list, produce a twin identical except that the finding carrying the
    FAIL-weight status carries plain ``FAIL`` instead, drive every consumer on both, and
    require the outputs to agree once the status STRING itself is normalised away.

Any residual difference means the consumer *behaved* differently — it counted, sorted, coloured,
headlined or dropped the finding on the strength of the literal — and that is blindness.

ONE home with the status swapped, never the two b746 fixture HOMES against each other. Those
differ in severity as well (HIGH vs MEDIUM), and severity is read independently by the sort
keys, the severity chips, the score caps and ``surfaced_despite_suppression`` — so a two-home
diff would report every one of those as blind. ``test_the_substitution_moves_exactly_one_field``
asserts the single variable rather than assuming it.

WHAT IT FOUND
-------------
On the pre-fix tree it named **twenty-one consumers across six modules, of which twenty were
real** — including five that no hand-enumeration had found, and three the project believed were
already covered:

    report._urgent_headline        "Nothing failed outright" — on a confirmed zip-slip
    report.render_json             fail_counts_by_severity high 0; the whole blast_radius
                                   block absent; worst "warn"
    pdf.render_pdf                 "0 FAIL, 7 WARN" in the header, and the finding's own
                                   entry missing from the body — while the escape string
                                   appeared elsewhere in the document, which is why the
                                   presence-only test stayed green
    sarif.render_sarif             failCountsBySeverity high 0 (a SECOND counter beside the
                                   sound failCount)
    adjudication._corroboration_groups   the finding dropped from its corroboration group

The twenty-first, ``pipeline.run_adjudication``, was a FALSE positive, and worth recording as
such: its ``PhaseResult`` carries ``elapsed_s``. ``monitor.snapshot`` failed the same way about
one run in ten, from a ``ts`` at second resolution. Both are retired by ``_NON_DETERMINISTIC``
rather than by excusing the consumer — excusing ``monitor.snapshot`` would have retired the
drift monitor from the oracle to spare the guard an inconvenience.

THE SECOND LAYER
----------------
A behavioural oracle can only speak about consumers it can CALL. So a callable that reads a
status and cannot be driven from the argument pool is exactly where the next blind site would
hide. ``test_every_status_consumer_is_driven_or_registered`` closes that: every module-level
callable in the package that touches a finding status must be driven here, or named in
``_NOT_DRIVEN`` with a reason. The registry is a list of EXCLUSIONS, not of inclusions — a new
renderer is a build failure until someone drives it or justifies it. Prefer a pool entry to a
registry line: a registry line stops a consumer being checked.

THE THIRD LAYER
---------------
Both layers above enumerate FUNCTIONS, so a status-keyed dict at module scope is invisible to
each. That is not a corner: two live defects lived there, and both were PRESENT-BUT-WRONG —
``_STATUS_COLOR`` mapped a confirmed escape to the grey reserved for "could not assess", and a
counter filed it under UNKNOWN. ``test_b750``'s icon-table guard asks whether the status is
*renderable*, a presence question, and is green on both.
``test_every_status_keyed_table_treats_fail_weight_alike`` asks whether the table agrees with
itself, which is the question that catches them.

WHAT THIS FILE CANNOT SEE — stated, because an unstated limit reads as coverage
------------------------------------------------------------------------------
* **Fold-after-truncation.** The fold runs on the OUTPUT, so any length-sensitive step —
  character truncation, wrapping, width-based alignment — has already consumed the difference
  in string length and the fold cannot put it back. Dormant while the pool is an audit finding
  list; it goes live the day anyone drives the vet path, where ``checks/_mcp.py`` embeds
  ``f"{f.status}: {f.detail}"`` into evidence.
* **Flags are bound to defaults.** ``color`` is forced on, because a colour table cannot be
  observed otherwise; every other flag takes its default, so a status comparison inside a
  non-default branch is structurally unreachable here.
* **``scripts/`` is outside the package walk.** That is not hypothetical: the release-blocking
  C-303 gate, ``scripts/fleet_fp_gate.py``, was itself blind at two sites, and no sweep scoped
  to ``clawseccheck/`` could have found it.
* **A consumer that ignores status entirely is invisible by construction.**
  ``report.compute_scan_receipt`` hashes severity and detail but never status, so it is
  correctly not flagged — and a tamper-evidence receipt that cannot tell a conviction from a
  pass is still a defect, of a kind this oracle is the wrong instrument for.
* **Ordering needs a peer.** An ordering flip is unobservable when the escape is the only item
  of its severity, which is why ``_with_a_comparable_sibling`` exists — established by mutation
  test, not by reasoning.

Offline, read-only, stdlib only.
"""
from __future__ import annotations

import ast
import copy
import dataclasses
import importlib
import inspect
import pkgutil
import re
import zlib
from pathlib import Path

import pytest

from clawseccheck.catalog import FAIL_WEIGHT_STATUSES
from clawseccheck.checks import run_all
from clawseccheck.checks._vet import _VET_MERGE_RANK
from clawseccheck.collector import collect
from clawseccheck.scoring import compute

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures"
TRAVERSAL_HOME = FIXTURES / "bad_b746_traversal_masked_by_warn"

#: The statuses under test, DERIVED. Everything ``_VET_MERGE_RANK`` ranks with FAIL and that is
#: not the literal ``"FAIL"`` must be indistinguishable from it to every consumer. A status
#: added to the cascade tomorrow enters this file with no edit here.
SUBSTITUTABLE = sorted(
    s for s, rank in _VET_MERGE_RANK.items()
    if rank == _VET_MERGE_RANK["FAIL"] and s != "FAIL"
)

#: Callables that read a status and cannot be driven from the pool below. Each entry states
#: WHY, because an unexplained entry is how a blind site gets parked. Keep this list short: the
#: right response to a new one is usually a new pool entry, not a new exclusion.
_NOT_DRIVEN = {
    # --- Vet-profile shaped: the pool cannot build a VetProfile from an audit finding list.
    # Two different reasons live here and they must not be confused. `_dossier_top_fix`,
    # `render_vet_dossier` and `render_vet_json` read AXIS statuses, which dossier._axis_status()
    # has already normalised to FAIL — the raw status provably cannot reach them.
    # `_advise_reasons` does NOT: it reads `profile.findings`, the RAW finding objects, so it
    # was genuinely blind and is fixed in place, pinned by test_the_advice_does_not_contradict_itself.
    "report._advise_reasons": "needs a VetProfile; reads RAW profile.findings, so fixed in place and pinned separately",
    "report._dossier_top_fix": "needs a VetProfile; reads axis statuses, normalised upstream",
    "report.render_vet_dossier": "needs a VetProfile; reads axis statuses, normalised upstream",
    "report.render_vet_json": "needs a VetProfile; reads axis statuses, normalised upstream",
    "dossier._axis_status": "IS the normaliser; its own contract is pinned in test_b751_fail_weight",
    "dossier._danger_coverage_gap": "operates on an axis bucket, downstream of the normaliser",
    "dossier._grade_profile": "operates on already-normalised axis statuses",
    "dossier._reason_and_fix": "operates on an axis bucket, downstream of the normaliser",
    "dossier.build_profile": "needs a vet engine_output, not an audit finding list",
    "pipeline._vet_second_opinion": "needs vet targets and a second engine run, not a finding list",
    # --- Producers, not consumers. These MINT the status; substituting it in a finding list
    # they never read changes nothing. Their own merge rank is what test_b750 and
    # test_b751_fail_weight pin.
    "checks._vet.check_installed_skills": "produces the status; does not consume a finding list",
    "checks._vet._vet_resolved_skill": "produces the status; does not consume a finding list",
    "checks._vet._run_content_ring": "produces the status; does not consume a finding list",
    "checks._vet._merge_narrowed_scope_gap": "merges producer output, upstream of every consumer",
    "checks._mcp.sweep_plugins": "produces sweep rows; their rendering is pinned by test_b750",
    "checks._mcp.vet_plugin": "produces the status; does not consume a finding list",
    "checks._mcp._merge_mcp_tool_surface": "merges producer output, upstream of every consumer",
    "report._skill_inventory": "re-derives each skill's verdict from ctx, not from the finding list — which is exactly why _normalise folds symmetrically",
    # --- The shell. cli's own status gates are driven by their CLI, not from a pool:
    # test_b751_fail_weight::test_the_exit_code_gate_sees_a_fail_weight_status covers the gate.
    "cli._main": "the entry point; driving it would parse argv and exit the test process",
    "cli._findings_exit_gate": "pinned by test_b751_fail_weight::test_the_exit_code_gate_sees_a_fail_weight_status",
    "cli.sweep_installed_skills": "walks the filesystem; the sweep's rendering is pinned by test_b750",
    "cli._run_vet_mcp": "runs a vet target end to end, not a finding-list consumer",
    # --- Need a renderer-internal object the pool has no business synthesising. Each is
    # exercised through a public renderer that IS driven above.
    "pdf._finding_block": "needs a live _PageFlow; exercised through render_pdf",
    "report._inventory_bucket_lines": "needs a built inventory bucket; exercised through render_report",
    # --- Behavioural detectors: their subject is trajectory events, not audit findings.
    "behavioral.grade_cap_signal": "consumes behavioural detector ids, not a finding list",
    "behavioral.render_behavioral_analysis": "consumes behavioural detector output, not a finding list",
    # --- The monitor arms. Fourteen parameters of diff state each; they are driven through
    # `diff_with_notes` by the acquisition tests at the bottom of this file, which is the
    # right level — the arm's contract is about two SNAPSHOTS, not about a finding list.
    "monitordims._checks._diff_check_transitions": "driven via diff_with_notes by test_the_monitor_alerts_when_a_check_acquires_a_fail_weight_status",
    "monitordims._checks._diff_vanished_checks": "driven via diff_with_notes by test_the_monitor_reports_a_lost_fail_weight_verdict",
    # --- Need a renderer-internal object; exercised through a public renderer that IS driven.
    "report._plugins_inventory_lines": "needs a PluginSweep; exercised through render_report",
    "dossier._route_axis_reasons": "needs an axis bucket map, downstream of the normaliser",
    "catalog.display_status": "IS the presentation fold; pinned by test_the_raw_status_never_reaches_a_human",
    # --- Producers / whole-target re-runs, not finding-list consumers.
    "checks._mcp.vet_mcp": "re-runs a vet against a real home; not a finding-list consumer",
    "checks._mcp.check_mcp_host_sanitizer_gap": "produces a status; does not consume a finding list",
    # --- Risk rules. Bindable, and driven — but each returns None on this fixture (its chain
    # does not fire here), so the oracle has two Nones to compare and nothing to say. That is
    # `_observe`'s inobservable branch doing its job: silence is not agreement. The public
    # entry point `risk.risk_paths` IS driven and compared, and the RISK-09 chain that carries
    # this finding is pinned by test_b751_fail_weight::test_the_risk_chain_fires.
    **{f"risk.{name}": "returns None on this fixture; covered through risk_paths"
       for name in ("_rule_fs_write_tamper", "_rule_injection_browser_ssrf",
                    "_rule_markdown_image_persistence", "_rule_marketplace_unreviewed_install",
                    "_rule_self_modification", "_rule_sleeper_delayed_rce",
                    "_rule_workshop_autonomy_untrusted_ingress")},
    # --- Numeric: the parameter named `score` here is an int, not a ScoreResult.
    "scoring.grade_for": "takes an integer score, not findings",
    "percentile.percentile": "takes an integer score, not findings",
    "percentile.render_percentile": "takes an integer score, not findings",
}

#: Consumers whose output differs from itself between two identical runs, so an equivalence
#: oracle can say nothing about them. EMPTY, and that is the point: the two candidates —
#: `monitor.snapshot`'s second-resolution `ts` and `pipeline.run_adjudication`'s `elapsed_s` —
#: were retired by scrubbing the clock rather than by excusing the consumer. Registering an
#: unjudgeable consumer is the last resort, not the first.
_UNSTABLE: dict = {}


# --------------------------------------------------------------------- the subject, built once


def _audit():
    ctx = collect(TRAVERSAL_HOME)
    return ctx, run_all(ctx)


@pytest.fixture(scope="module")
def audit():
    return _audit()


def _variant(findings, status):
    """The finding list with the FAIL-weight carrier re-stamped to ``status``.

    Only ``status`` moves. Severity, detail, evidence and order are untouched, so any output
    difference is attributable to the status and to nothing else.
    """
    carriers = [i for i, f in enumerate(findings) if f.status in FAIL_WEIGHT_STATUSES]
    if not carriers:
        # No natural carrier in this home: synthesise one on the worst WARN, so a status
        # added to the cascade later is still exercised without needing its own fixture.
        carriers = [i for i, f in enumerate(findings) if f.status == "WARN"][:1]
    out = list(findings)
    for i in carriers:
        out[i] = dataclasses.replace(findings[i], status=status)
    return out


def _with_a_comparable_sibling(findings):
    """The same findings, plus a SECOND definite failure at the carrier's severity.

    Not a refinement — a hole closed. An independent pass re-introduced pdf.py's blind sort
    key (``f.status != FAIL`` as the tie-break under severity) into a scratch tree and measured
    that this oracle does NOT detect it, because on this fixture the escape is the only item of
    its severity that the key can reorder: with nothing to swap places with, a wrong sort order
    produces identical output. Giving the carrier a same-severity peer makes the flip visible.

    The peer is a REAL finding from the same run re-stamped to FAIL, never a synthesised one
    with an id the catalog does not know — several renderers look their id up.
    """
    carrier = next((f for f in findings if f.status in FAIL_WEIGHT_STATUSES), None)
    if carrier is None:
        return list(findings)
    out = list(findings)
    for i, f in enumerate(out):
        if f is not carrier and f.severity == carrier.severity and f.status == "WARN":
            out[i] = dataclasses.replace(f, status="FAIL")
            break
    return out


def _pdf_text(blob: bytes) -> str:
    """The PDF's own text, decompressed.

    Comparing PDF BYTES is uninformative: the status string differs in length, every later
    xref offset shifts, and a byte diff reports a hundred regions of compression noise. The
    document's actual words are what a reader sees, so those are what is compared.
    """
    out = []
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", blob, re.S):
        try:
            out.append(zlib.decompress(m.group(1)).decode("latin-1"))
        except zlib.error:
            continue
    return "\n".join(out)


#: Values that move on their own, scrubbed so a clock cannot masquerade as a verdict change.
#: This is not a convenience: `monitor.snapshot` embeds `ts` at SECOND resolution, so the
#: variant and control calls straddle a second boundary every so often and the consumer was
#: reported blind on roughly one run in ten. A stability re-run catches that, but only by
#: declaring the consumer unjudgeable — which would have retired the drift monitor, the single
#: most important consumer in this file, from the oracle. Scrubbing keeps it judged.
_NON_DETERMINISTIC = (
    re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"),   # ISO timestamps
    re.compile(r"(elapsed_s['\"]?[=:]\s*)-?\d+\.?\d*(?:e-?\d+)?"),   # wall-clock durations
)


def _normalise(value) -> str:
    """Render an output for comparison, with every FAIL-weight status folded to ``FAIL``.

    Folding the literal is what keeps the oracle sound for surfaces that faithfully echo the
    real status — a JSON ``"status"`` field should carry the true value. What survives the fold
    is behaviour: counts, ordering, colour, inclusion, headline wording.

    The fold is applied SYMMETRICALLY, to both worlds, and that is not a detail. Folding only
    the status this run stamped made the oracle report ``build_inventory``, ``render_json``,
    ``render_html`` and ``_subject_summary_rows`` as blind when they were not: those go through
    ``_skill_inventory(ctx)``, which re-derives each skill's verdict from the CONTEXT rather
    than from the finding list handed in, so the raw status appears in both outputs and only
    one of them was being folded. An asymmetric normaliser manufactures the difference it then
    reports.

    Note what this deliberately gives up: a raw status reaching human-visible text is invisible
    to an equivalence oracle, because an echo is exactly what the fold erases. That defect is
    real and is covered separately, by ``test_the_raw_status_never_reaches_a_human``.
    """
    text = _pdf_text(value) if isinstance(value, bytes) else repr(value)
    for status in SUBSTITUTABLE:
        text = text.replace(status, "FAIL")
    text = _NON_DETERMINISTIC[0].sub("<TS>", text)
    return _NON_DETERMINISTIC[1].sub(r"\1<T>", text)


def _inventory_for(findings, ctx):
    from clawseccheck.report import build_inventory

    return build_inventory(findings, ctx)


def _report_icons():
    from clawseccheck.report import _ICON

    return _ICON


def _pool(findings, ctx):
    """Arguments the oracle can supply, keyed by the parameter names the package actually uses.

    ``lines`` is deliberately a FRESH list per call: several report.py helpers are accumulators
    that append to a caller-supplied list and return ``None``. Their effect is the mutation, so
    the mutation is what gets compared — see ``_observe``.
    """
    score = compute(findings)
    carrier = next((f for f in findings if f.status in FAIL_WEIGHT_STATUSES), findings[0])
    return {
        "findings": findings, "scored_findings": findings, "fs": findings,
        "all_findings": findings, "issues": findings, "members": findings,
        "ctx": ctx, "score": score, "scorecard": score, "result": score,
        "f": carrier, "finding": carrier,
        "by_id": {f.id: f for f in findings},
        "fids": [f.id for f in findings],
        "lines": [],
        "surface": "skills",
        # Rendered COLOURED, because the uncoloured path cannot observe a status-keyed colour
        # table at all — and one of them mapped a confirmed escape to the grey this palette
        # reserves for "could not assess". Coloured output carries strictly more signal: the
        # words are still there, with the paint beside them.
        "color": True,
        # `cfg` gates report._render_finding's blast-radius block. Leaving it unbound would
        # have driven that helper with the branch switched off — driven, but not exercised.
        "cfg": getattr(ctx, "config", {}) or {},
        "icon": _report_icons(),
        "verdicts_map": {},
        "check_id": carrier.id,
        "ids": (carrier.id,),
        "checks_run": len(findings),
        "checks_total": len(findings),
        "monitor_state_present": False,
        # `tools` and `inv` exist so eight risk rules and the skills inventory renderer are
        # DRIVEN rather than registered. A registry line stops a consumer being checked; a
        # pool entry keeps it checked. Reach for the pool first.
        "tools": ["read", "write", "exec", "apply_patch"],
        "inv": _inventory_for(findings, ctx),
    }


#: Pool entries that carry findings. A callable that receives none of them cannot be
#: discriminating on a finding's status, and driving it anyway is how this file first ran
#: ``cli.main()`` — every parameter had a default, so the binder "drove" the CLI entry point,
#: which parsed pytest's own argv and called ``sys.exit``. The oracle must not have side
#: effects on the machine it audits, so a bound finding is now the licence to call.
_CARRIERS = frozenset({
    "findings", "scored_findings", "fs", "all_findings", "issues", "members",
    "f", "finding", "by_id", "fids",
})

#: Accumulator parameters: the callable's real output is what it appends here.
_ACCUMULATORS = ("lines",)


def _bind(fn, pool):
    """Keyword arguments for ``fn`` drawn from the pool, or None if it cannot be driven."""
    kwargs = {}
    for param in inspect.signature(fn).parameters.values():
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        if param.name in pool:
            kwargs[param.name] = pool[param.name]
        elif param.default is param.empty:
            return None
    if not (_CARRIERS & set(kwargs)):
        return None
    return kwargs


def _observe(fn, kwargs):
    """Everything the call produced: its return value AND anything it appended.

    Returning the accumulators too is what keeps an accumulator-style helper from reading as
    "agrees". ``report._render_finding`` returns ``None`` in both worlds; comparing only return
    values would have called it sound while it rendered a confirmed escape as a WARN. A
    callable that produces NEITHER a return value nor a mutation is reported as inobservable
    rather than as agreeing — silence is not evidence.
    """
    before = {k: list(kwargs[k]) for k in _ACCUMULATORS if isinstance(kwargs.get(k), list)}
    result = fn(**kwargs)
    after = {k: kwargs[k] for k in before}
    observable = result is not None or any(after[k] != before[k] for k in before)
    return observable, _normalise((result, after))


# --------------------------------------------------------------------- the consumer surface


def _package_modules():
    """Every importable module in the package — DERIVED, so a new renderer joins by existing."""
    import clawseccheck

    # `__main__` is excluded because IMPORTING it runs `sys.exit(main())` at module scope —
    # enumerating the package must not be able to terminate the test process.
    names = ["clawseccheck." + m.name for m in pkgutil.iter_modules(clawseccheck.__path__)
             if not m.name.startswith("__")]
    for sub in ("checks", "monitordims"):
        pkg = importlib.import_module(f"clawseccheck.{sub}")
        names += [f"clawseccheck.{sub}.{m.name}" for m in pkgutil.iter_modules(pkg.__path__)
                  if not m.name.startswith("__")]
    out = []
    for name in sorted(set(names)):
        try:
            out.append(importlib.import_module(name))
        except Exception:  # pragma: no cover - a module that cannot import is not a consumer
            continue
    return out


def _module_functions(mod):
    return [
        (name, fn) for name, fn in sorted(vars(mod).items())
        if inspect.isfunction(fn) and getattr(fn, "__module__", "") == mod.__name__
    ]


#: Names that denote a FAIL-weight value when they appear in a COMPARISON.
_STATUS_NAMES = frozenset({"FAIL", "FAIL_WEIGHT_STATUSES", "ACTIONABLE_STATUSES"})


def _is_status_operand(node) -> bool:
    if isinstance(node, ast.Name) and node.id in _STATUS_NAMES:
        return True
    if isinstance(node, ast.Constant) and node.value in FAIL_WEIGHT_STATUSES:
        return True
    if isinstance(node, (ast.Tuple, ast.Set, ast.List)):
        return any(_is_status_operand(e) for e in node.elts)
    return False


def _touches_status(fn) -> bool:
    """Does this callable COMPARE something against a FAIL-weight value?

    The first version keyed on exactly two shapes — an attribute named ``status`` and a string
    constant in the FAIL-weight set — and an independent pass measured it returning False for
    ``monitordims._checks._diff_check_transitions``: the arm that decides whether ``--monitor``
    announces a new failure. It compares a LOCAL named ``status`` against the imported NAME
    ``FAIL``, so there is no attribute and no constant, and the layer that exists to catch what
    the oracle cannot drive skipped the most consequential consumer in the tree.

    Widening to "mentions the name ``FAIL`` anywhere" was tried and RETRACTED: it flagged every
    ``check_*`` function in the package, because a producer MINTS ``FAIL`` as a call argument.
    Several hundred registry lines is not a stricter guard, it is a guard nobody reads.

    The distinction that separates them is grammatical, not semantic. A consumer COMPARES a
    status; a producer PASSES one. So only comparison operands count.
    """
    try:
        tree = ast.parse(inspect.getsource(fn).lstrip())
    except (OSError, SyntaxError, IndentationError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "status":
            return True
        if isinstance(node, ast.Compare):
            if _is_status_operand(node.left) or any(
                    _is_status_operand(c) for c in node.comparators):
                return True
    return False


def _short(mod, name):
    return f"{mod.__name__.split('.', 1)[1]}.{name}"


def _sweep(ctx, findings, status):
    """Drive every drivable consumer on both worlds.

    Returns ``(blind, driven, undriven, unstable)``. A consumer whose output differs is
    re-driven on the SAME world before being called blind: a difference that reproduces against
    itself is non-determinism, not blindness. ``pipeline.run_adjudication`` is the live example
    — its ``PhaseResult`` carries ``elapsed_s``, a wall-clock measurement, so an equivalence
    oracle can never judge it and saying so is more honest than reporting it as a defect.
    """
    base = _with_a_comparable_sibling(findings)
    variant, control = _variant(base, status), _variant(base, "FAIL")
    blind, driven, undriven, unstable = [], [], [], []
    for mod in _package_modules():
        for name, fn in _module_functions(mod):
            label = _short(mod, name)
            outs, observable = [], True
            for pool_findings in (variant, control):
                pool = _pool(copy.deepcopy(pool_findings), ctx)
                kwargs = _bind(fn, pool)
                if kwargs is None:
                    outs = None
                    break
                try:
                    seen, text = _observe(fn, kwargs)
                except BaseException:  # noqa: BLE001 - SystemExit included, deliberately
                    outs = None
                    break
                observable = observable and seen
                outs.append(text)
            if outs is None or not observable:
                undriven.append(label)
                continue
            driven.append(label)
            if outs[0] == outs[1]:
                continue
            # Differs — but is it the status, or is the consumer unstable against itself?
            pool = _pool(copy.deepcopy(variant), ctx)
            kwargs = _bind(fn, pool)
            try:
                _, again = _observe(fn, kwargs)
            except BaseException:  # noqa: BLE001
                again = None
            (unstable if again != outs[0] else blind).append(label)
            if again != outs[0]:
                driven.remove(label)
    return blind, driven, undriven, unstable


# --------------------------------------------------------------------- the experiment is clean


def test_the_substitution_moves_exactly_one_field(audit):
    """A single-variable experiment, asserted rather than assumed.

    If the twin differed in severity too — as the two b746 fixture HOMES do — a difference in
    a consumer's output would no longer be attributable to the status.
    """
    _, findings = audit
    for status in SUBSTITUTABLE:
        variant, control = _variant(findings, status), _variant(findings, "FAIL")
        assert len(variant) == len(control) == len(findings)
        moved = [(a, b) for a, b in zip(variant, control) if a != b]
        assert moved, f"{status}: nothing was substituted — the oracle would pass vacuously"
        for a, b in moved:
            assert a.status == status and b.status == "FAIL"
            assert dataclasses.replace(a, status="FAIL") == b, (
                f"{status}: the twin differs in a field other than status: "
                f"{[fld.name for fld in dataclasses.fields(a) if getattr(a, fld.name) != getattr(b, fld.name)]}"
            )


def test_the_substituted_statuses_are_derived_not_listed():
    """The status list comes from the live rank table, so a new cascade status is covered."""
    assert SUBSTITUTABLE, "no FAIL-weight status besides FAIL — this file would test nothing"
    assert set(SUBSTITUTABLE) | {"FAIL"} == set(FAIL_WEIGHT_STATUSES)


# --------------------------------------------------------------------- the oracle itself


@pytest.mark.parametrize("status", SUBSTITUTABLE)
def test_no_consumer_discriminates_between_fail_weight_statuses(audit, status):
    ctx, findings = audit
    blind, _, _, _ = _sweep(ctx, findings, status)
    assert not blind, (
        f"{len(blind)} consumer(s) treat {status!r} differently from 'FAIL', although "
        f"_VET_MERGE_RANK ranks them the same — so a confirmed finding degrades toward "
        f"'fine' on each of these surfaces:\n  " + "\n  ".join(blind)
    )


def test_the_oracle_actually_reaches_the_headline_consumers(audit):
    """A control on the control: an oracle that drives nothing passes silently.

    These are the surfaces a human actually reads. If a refactor makes one undrivable from the
    pool, this file must fail loudly rather than quietly shrink to a tautology.
    """
    ctx, findings = audit
    _, driven, undriven, _ = _sweep(ctx, findings, SUBSTITUTABLE[0])
    must_reach = {
        "report.render_report", "report.render_html", "report.render_json",
        "report.render_dashboard", "report.build_inventory",
        "report.finding_counts_by_severity", "report._urgent_headline",
        "report.issue_population_line", "report._subject_summary_rows",
        "sarif.render_sarif", "pdf.render_pdf",
        "coverage.coverage", "coverage._tally",
        "adjudication._corroboration_groups",
    }
    missing = sorted(must_reach - set(driven))
    assert not missing, (
        "the oracle can no longer drive these consumers, so it is no longer testing them: "
        f"{missing} (they are now among the {len(undriven)} undriven — add a pool entry)"
    )


def test_every_status_consumer_is_driven_or_registered(audit):
    """The closure. A callable that reads a status and is not driven must say why.

    This is the half that makes the file structural rather than another hand-list: the
    enumeration is of the package's own callables, so a new consumer arrives here by being
    written, not by being remembered.
    """
    ctx, findings = audit
    _, driven, undriven, _ = _sweep(ctx, findings, SUBSTITUTABLE[0])
    driven_set = set(driven)

    unexplained = []
    for mod in _package_modules():
        for name, fn in _module_functions(mod):
            label = _short(mod, name)
            if label in driven_set or label in _NOT_DRIVEN or label in _UNSTABLE:
                continue
            if _touches_status(fn):
                unexplained.append(label)

    assert not unexplained, (
        "these callables read a finding status but the oracle cannot drive them, and they are "
        "not registered in _NOT_DRIVEN with a reason — each is a place the next blind site "
        "would hide:\n  " + "\n  ".join(sorted(unexplained))
    )
    assert len(undriven) >= len(_NOT_DRIVEN)


def test_the_registry_does_not_rot(audit):
    """A _NOT_DRIVEN entry that has become drivable is a stale excuse — drop it."""
    ctx, findings = audit
    _, driven, _, _ = _sweep(ctx, findings, SUBSTITUTABLE[0])
    stale = sorted(set(_NOT_DRIVEN) & set(driven))
    assert not stale, (
        f"{stale} are now drivable by the oracle — remove them from _NOT_DRIVEN so they are "
        "actually checked"
    )
    known = {f"{m.__name__.split('.', 1)[1]}.{n}"
             for m in _package_modules() for n, _ in _module_functions(m)}
    vanished = sorted(set(_NOT_DRIVEN) - known)
    assert not vanished, f"_NOT_DRIVEN names callables that no longer exist: {vanished}"


# --------------------------------------------------------------------- what the fold hides


def test_the_unstable_registry_is_honest(audit):
    """The consumers the oracle cannot judge are exactly the ones it says it cannot judge.

    Without this, "unstable" would be a silent escape hatch: a consumer that became
    non-deterministic would drop out of the oracle with nobody told.
    """
    ctx, findings = audit
    _, _, _, unstable = _sweep(ctx, findings, SUBSTITUTABLE[0])
    assert sorted(unstable) == sorted(_UNSTABLE), (
        f"the oracle found {sorted(unstable)} unstable but _UNSTABLE records "
        f"{sorted(_UNSTABLE)}. A consumer that differs from itself cannot be judged here — "
        "prefer scrubbing the non-deterministic value in _NON_DETERMINISTIC (a clock, a "
        "duration, an address) over registering the consumer, because a registered consumer "
        "stops being checked at all."
    )


#: Surfaces a person reads. The raw status must never appear here: a status table keyed on the
#: literal falls through to its default, and an f-string interpolating a status prints the enum.
#: Machine surfaces (`render_json`, `render_sarif`) are deliberately NOT in this list — they
#: SHOULD carry the true status, and the equivalence oracle above already folds that echo away.
def _human_surfaces(findings, ctx, score):
    from clawseccheck import report
    from clawseccheck.checks import vet_skill
    from clawseccheck.dossier import build_profile
    from clawseccheck.pdf import render_pdf

    skill = TRAVERSAL_HOME / "workspace" / "skills" / "archive-demo"
    profile = build_profile(vet_skill(str(skill)), "archive-demo", "skill")
    return {
        "render_report": report.render_report(findings, score, ctx=ctx),
        "render_html": report.render_html(findings, score, ctx=ctx),
        "render_dashboard": report.render_dashboard(findings, score, ctx=ctx),
        "render_advise": report.render_advise(profile),
        "render_vet_dossier": report.render_vet_dossier(profile),
        "render_pdf": _pdf_text(render_pdf(findings, score, ctx=ctx)),
    }


def test_the_raw_status_never_reaches_a_human(audit):
    ctx, findings = audit
    score = compute(findings)
    leaks = {
        name: [ln.strip()[:120] for ln in text.splitlines() if any(s in ln for s in SUBSTITUTABLE)]
        for name, text in _human_surfaces(findings, ctx, score).items()
        if any(s in text for s in SUBSTITUTABLE)
    }
    assert not leaks, (
        "these human-facing surfaces print the raw status enum, which names an internal "
        f"constant instead of a verdict:\n{leaks}"
    )


def test_the_human_surfaces_actually_name_the_finding(audit):
    """The control for the test above: an empty report leaks no enum either.

    Folding a status to nothing would satisfy the leak test perfectly, so each surface must
    still carry the conviction it is being asked to label correctly.
    """
    ctx, findings = audit
    score = compute(findings)
    silent = [
        name for name, text in _human_surfaces(findings, ctx, score).items()
        if "traversal" not in text.lower()
    ]
    assert not silent, f"these surfaces no longer mention the escape at all: {silent}"


def test_the_advice_does_not_contradict_itself():
    """``--advise`` said "I found something dangerous", then "no findings", then "see above".

    The verdict came from the axis rollup (normalised, so correct) while the reasons came from
    ``profile.findings`` (raw, so empty). One surface, two status vocabularies.
    """
    from clawseccheck.checks import vet_skill
    from clawseccheck.dossier import build_profile
    from clawseccheck.report import _advise_reasons, render_advise

    skill = TRAVERSAL_HOME / "workspace" / "skills" / "archive-demo"
    profile = build_profile(vet_skill(str(skill)), "archive-demo", "skill")
    reasons, omitted = _advise_reasons(profile)
    text = render_advise(profile)

    assert "DO-NOT-INSTALL" in text, text[:400]
    assert reasons, (
        "the verdict is DO-NOT-INSTALL and the reason list is empty — the exact contradiction "
        "this test exists for"
    )
    assert any("traversal" in r.lower() for r in reasons), reasons
    assert omitted == 0, omitted
    assert "No FAIL/WARN findings" not in text, (
        "the advice still claims there are no findings while refusing to recommend the skill"
    )


# --------------------------------------------------------------------- the drift monitor

# The monitor is the one consumer the equivalence oracle above cannot reach, and it is the
# most consequential: `--monitor` is what a cron job reads, so a silence here is a silence
# nobody is present to notice. It is out of reach because its input is two SNAPSHOTS rather
# than a finding list, and the snapshot faithfully records the raw status — correctly, it is a
# machine record. The blindness lives in the arm that compares two snapshots, so that is what
# these drive: a check that ACQUIRES a FAIL-weight status between two runs.


def _scrub(pairs):
    """Alert pairs with the clock removed, so a timestamp cannot read as a changed verdict."""
    return sorted((sev, _NON_DETERMINISTIC[0].sub("<TS>", str(text))) for sev, text in pairs)


def _both(diff):
    """Alerts AND notes. An arm that refuses to assert a regression writes to the note channel,
    so a comparison that reads only alerts is blind to exactly those arms."""
    alerts, notes = diff
    return _scrub(alerts), _scrub(notes)


def _snapshot_of(findings, ctx):
    from clawseccheck.monitor import snapshot

    return snapshot(ctx=ctx, findings=findings, score=compute(findings))


def _restamped(findings, status):
    """The finding list with the FAIL-weight carrier set to ``status`` — WARN, PASS, anything."""
    return _variant(findings, status)


@pytest.mark.parametrize("status", SUBSTITUTABLE)
def test_the_monitor_alerts_when_a_check_acquires_a_fail_weight_status(audit, status):
    from clawseccheck.monitor import diff_with_notes

    ctx, findings = audit
    before = _snapshot_of(_restamped(findings, "WARN"), ctx)

    raw_alerts, _ = diff_with_notes(before, _snapshot_of(_restamped(findings, status), ctx))
    fail_alerts, _ = diff_with_notes(before, _snapshot_of(_restamped(findings, "FAIL"), ctx))

    assert fail_alerts, (
        "the control produced no alert at all, so this test cannot prove anything about the "
        "other status — the WARN -> FAIL transition itself has stopped being reported"
    )
    assert _scrub(raw_alerts) == _scrub(fail_alerts), (
        f"a check acquiring {status!r} does not produce the alerts that the same check "
        f"acquiring 'FAIL' produces:\n  with {status}: {_scrub(raw_alerts)}\n"
        f"  with FAIL:   {_scrub(fail_alerts)}"
    )


@pytest.mark.parametrize("status", SUBSTITUTABLE)
def test_the_monitor_does_not_invent_a_regression_that_did_not_happen(audit, status):
    """The other direction, which the same bare literal also got wrong.

    ``status == FAIL and pc.get(cid) != FAIL`` fires when the PREVIOUS run carried the
    FAIL-weight status and this one carries plain ``FAIL``: the verdict has not moved, and the
    journal would have recorded a brand-new failure. A tamper-evident log is exactly the place
    a fabricated entry must not reach.
    """
    from clawseccheck.monitor import diff_with_notes

    ctx, findings = audit
    alerts, _ = diff_with_notes(
        _snapshot_of(_restamped(findings, status), ctx),
        _snapshot_of(_restamped(findings, "FAIL"), ctx),
    )
    regressions = [text for _sev, text in alerts if "Now FAILING" in text]
    assert not regressions, (
        f"the verdict did not move ({status} and FAIL rank the same) but the monitor "
        f"announced a new failure: {regressions}"
    )


# --------------------------------------------------------------------- status-keyed tables

# The oracle enumerates FUNCTIONS. A status-keyed dict declared at module scope is therefore
# invisible to it in both layers — it can be neither driven nor registered — and that is
# precisely where a whole class of this defect lives. Two live examples were found by an
# independent pass rather than by the oracle:
#
#   report._STATUS_COLOR   mapped the escape to "grey", the colour reserved for "could not
#                          assess", while FAIL is "red"
#   report.py's n_unknown  counted the escape as UNKNOWN
#
# Both are worse than an omission: the status IS a key, put on the wrong side. `test_b750`'s
# icon-table guard asks "is the status renderable" — a PRESENCE question — and is green on
# both. The question that catches them is whether the table AGREES with itself.


#: Tables whose keys are AXIS statuses, not finding statuses. ``dossier._axis_status()``
#: normalises every FAIL-weight status to ``FAIL`` before an axis exists, so the raw value
#: cannot reach them — an independent pass attacked that claim on twelve sites and upheld it
#: on all twelve. Adding the rows anyway was tried and REVERTED: it broke four tests whose
#: stated purpose is that the vet-mcp vocabulary stays at exactly four states, and insurance
#: that contradicts a deliberate, tested invariant is not insurance. If a raw status ever does
#: reach an axis, the fix is the normaliser, not these tables.
_AXIS_LEVEL_TABLES = frozenset({
    "cli._REVET_SEVERITY", "cli._VET_ICON_ASCII", "cli._VET_ICON_UNI", "cli._VET_VERDICT",
    "dossier.VERDICT_WORD", "dossier._MODE_C_VERDICT",
    "report._ADVISE_VERDICT", "report._AXIS_ICON_ASCII", "report._AXIS_ICON_UNI",
    "report._TOP_FIX_ORDER",
})


def _preserves_fail(value, fail_value) -> bool:
    """Is ``value`` at least what FAIL means here?

    Equality is the usual answer, but two verdict tables deliberately SPECIALISE: they map the
    escape to "DANGEROUS (archive escapes its directory)" where FAIL is "DANGEROUS". That is
    better prose, not a wrong entry, and a rule that forbids it would push the project toward
    less informative output. So a string may extend FAIL's value; it may not replace it — which
    still catches "grey" where FAIL is "red", the entry this test was written for.
    """
    if value == fail_value:
        return True
    return isinstance(value, str) and isinstance(fail_value, str) and fail_value in value


def _status_keyed_tables():
    """Module-level dicts keyed by status — anything with ``FAIL`` among its keys."""
    for mod in _package_modules():
        for name, value in sorted(vars(mod).items()):
            if isinstance(value, dict) and "FAIL" in value:
                yield f"{mod.__name__.split('.', 1)[1]}.{name}", value


def test_every_status_keyed_table_treats_fail_weight_alike():
    disagreeing, absent = [], []
    for label, table in _status_keyed_tables():
        for status in SUBSTITUTABLE:
            if status not in table:
                if label not in _AXIS_LEVEL_TABLES:
                    absent.append(f"{label}[{status}] is missing (falls through to the default)")
            elif not _preserves_fail(table[status], table["FAIL"]):
                disagreeing.append(
                    f"{label}[{status}] = {table[status]!r} but {label}['FAIL'] = "
                    f"{table['FAIL']!r}")
    assert not disagreeing, (
        "these tables carry a FAIL-weight status and map it somewhere other than where they "
        "map FAIL — a present-but-wrong entry, which a presence check cannot see:\n  "
        + "\n  ".join(disagreeing))
    assert not absent, (
        "these tables are keyed by status and have no entry for a FAIL-weight status, so it "
        "silently takes the default — which in every case measured so far was the value "
        "meaning 'nothing to see here':\n  " + "\n  ".join(absent))


def test_the_table_sweep_actually_finds_the_known_tables():
    """A control: the sweep must reach the tables this defect actually lived in."""
    found = {label for label, _ in _status_keyed_tables()}
    for expected in ("report._STATUS_ORDER", "report._ICON", "report._ICON_ASCII",
                     "report._STATUS_COLOR"):
        assert expected in found, (
            f"{expected} is no longer reachable by the table sweep (found: {sorted(found)})")


@pytest.mark.parametrize("status", SUBSTITUTABLE)
def test_the_monitor_reports_a_check_that_went_dark(audit, status):
    """A conviction that becomes UNKNOWN is strictly worse than one that stays put.

    An open FAIL that turns UNKNOWN stops counting against the score, so the grade can RISE on
    the strength of a check ceasing to work.

    This test compares ALERTS AND NOTES, and the distinction is not cosmetic: the first version
    compared alerts alone and a mutation pass measured it green with the arm reverted. The arm
    deliberately emits a NOTE rather than an alert — `cid not in _na_curr` is the absence of a
    marker, and the code refuses to assert a regression on an absence — so a test that reads
    only the alert channel is reading the channel this arm never writes to.
    """
    from clawseccheck.monitor import diff_with_notes

    ctx, findings = audit
    dark = _snapshot_of(_restamped(findings, "UNKNOWN"), ctx)

    raw = _both(diff_with_notes(_snapshot_of(_restamped(findings, status), ctx), dark))
    control = _both(diff_with_notes(_snapshot_of(_restamped(findings, "FAIL"), ctx), dark))
    quiet = _both(diff_with_notes(_snapshot_of(_restamped(findings, "PASS"), ctx), dark))

    assert control != quiet, (
        "going dark from FAIL produces the same output as going dark from PASS, so the arm "
        "under test is not firing at all and this comparison proves nothing"
    )
    assert raw == control, (
        f"a check going dark from {status!r} is not reported the way going dark from 'FAIL' "
        f"is:\n  from {status}: {raw}\n  from FAIL:   {control}"
    )


@pytest.mark.parametrize("status", SUBSTITUTABLE)
def test_the_monitor_reports_a_lost_fail_weight_verdict(audit, status):
    """A check that DISAPPEARS takes its verdict with it, and that reads as an improvement.

    Driven by snapshot surgery rather than by a second home, because the arm's trigger is a
    check id vanishing from the checks map beside a crash marker — a shape no fixture produces.
    """
    from clawseccheck.monitor import diff_with_notes

    ctx, findings = audit
    carrier = next(f for f in findings if f.status in FAIL_WEIGHT_STATUSES)

    def _pair(prev_status):
        prev = _snapshot_of(_restamped(findings, prev_status), ctx)
        curr = _snapshot_of(_restamped(findings, prev_status), ctx)
        curr["checks"] = {k: v for k, v in curr["checks"].items() if k != carrier.id}
        curr["checks"]["ERR:_some_check"] = "UNKNOWN"
        return diff_with_notes(prev, curr)[0]

    raw, control = _pair(status), _pair("FAIL")
    assert control, (
        f"the control produced no alert for {carrier.id} vanishing while it carried a FAIL, "
        "so this test cannot speak about the other status"
    )
    assert _scrub(raw) == _scrub(control), (
        f"a vanished check that carried {status!r} is not reported the way one carrying 'FAIL' "
        f"is:\n  with {status}: {_scrub(raw)}\n  with FAIL:   {_scrub(control)}"
    )


# ------------------------------------------------------- reachable only off this fixture

# A mutation pass reverted each fix below and the whole file stayed green. That is not a
# missing assertion in the oracle — it is the oracle correctly reporting that on THIS home the
# two worlds produce identical output, because something unrelated masks the difference. Each
# gets a direct test built to remove the mask.


def test_a_suppressed_fail_weight_finding_is_still_surfaced():
    """``surfaced_despite_suppression`` compared the bare literal.

    Unobservable through the audit fixture because its second disjunct, ``f.id in
    SENSITIVE_SUPPRESSED_IDS``, contains "B13" — the only check that mints this status today —
    so the function returns True either way and the bug is masked by an allowlist rather than
    by being absent. Driven here with an id the allowlist does not carry.
    """
    from clawseccheck.catalog import CRITICAL, Finding
    from clawseccheck.report import SENSITIVE_SUPPRESSED_IDS, surfaced_despite_suppression

    unlisted = next(cid for cid in ("B999", "ZZ1", "B404") if cid not in SENSITIVE_SUPPRESSED_IDS)
    for status in SUBSTITUTABLE:
        raw = Finding(id=unlisted, title="t", severity=CRITICAL, status=status,
                      detail="d", fix="f", framework="")
        control = dataclasses.replace(raw, status="FAIL")
        raw = dataclasses.replace(raw, suppressed=True)
        control = dataclasses.replace(control, suppressed=True)
        assert surfaced_despite_suppression(raw) == surfaced_despite_suppression(control), (
            f"a suppressed CRITICAL carrying {status!r} is not surfaced the way a suppressed "
            "CRITICAL FAIL is — it would be dropped from the report, the badge and the gates"
        )


def test_a_fail_weight_status_is_not_counted_as_undetermined(tmp_path):
    """The 'no OpenClaw config detected' branch counted a conviction as UNKNOWN.

    Unreachable from the traversal fixture, which HAS a config — so the branch never runs and
    the oracle sees no difference. Driven here against a home with no config at all.
    """
    from clawseccheck.report import render_report

    _ctx, findings = _audit()
    empty = collect(tmp_path)
    # `openclaw_detected` is a PARAMETER of render_report, not something derived from ctx —
    # passing an empty home was not enough, and the first version of this test drove the
    # default-True path and proved nothing. Measured: without this the mutation is invisible.
    for status in SUBSTITUTABLE:
        raw = render_report(_variant(findings, status), compute(findings), ctx=empty,
                            openclaw_detected=False)
        control = render_report(_variant(findings, "FAIL"), compute(findings), ctx=empty,
                                openclaw_detected=False)
        for line in raw.splitlines():
            assert status not in line, f"the raw enum reached the reader: {line.strip()!r}"
        assert _normalise(raw) == _normalise(control), (
            f"the no-config branch treats {status!r} differently from 'FAIL'"
        )


def test_a_pool_of_only_a_fail_weight_finding_counts_as_assessed():
    """``dossier.build_profile`` asked "was anything assessed?" against ``(PASS, WARN, FAIL)``.

    A pool whose only finding is a conviction answered NO, which forces every empty axis to
    UNKNOWN — the fabricated-PASS guard firing on a definite verdict. Masked on the fixture by
    the second disjunct (``target_type in ("skill", "plugin") and ctx.installed_skills``), so it
    is driven here with a target type that disjunct does not cover.
    """
    from clawseccheck.catalog import HIGH, Finding
    from clawseccheck.dossier import build_profile

    for status in SUBSTITUTABLE:
        def _profile(st):
            f = Finding(id="B13", title="t", severity=HIGH, status=st,
                        detail="Archive path traversal detected: bundle.zip::../x", fix="f",
                        framework="")
            return build_profile([f], "target", "mcp")

        raw, control = _profile(status), _profile("FAIL")
        assert [a.status for a in raw.axes] == [a.status for a in control.axes], (
            f"a pool carrying only {status!r} produces different axis statuses from one "
            f"carrying only 'FAIL':\n  {[(a.axis, a.status) for a in raw.axes]}\n"
            f"  {[(a.axis, a.status) for a in control.axes]}"
        )
