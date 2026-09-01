"""B-706 — MCP safety hints are inert on 2026.7.x and load-bearing on 2026.8.1.

B333 shipped the sentence *"OpenClaw does not read destructiveHint/readOnlyHint, so any
policy relying on them is not enforced"*, grounded against 2026.7.1-2 where it was true.
On 2026.8.1 both halves are false: the registration entry carries
``codexAnnotations: normalizeMcpCodexToolAnnotations(tool.annotations)`` and
``requiresMcpCodexToolApproval`` reads them to decide which MCP tools reach an UNATTENDED
scheduled run. A server's own ``readOnlyHint: true`` waives the gate, so the old advice
pointed the reader away from a live grant rather than merely going stale.

The port is validated DIFFERENTIALLY against the installed dist, not by reading it —
`reference_execute_the_vendor_function_dont_read_it`. Three semantics would have been got
wrong by reading, and each is a real case below.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

import clawseccheck.checks as C
from clawseccheck.catalog import PASS, UNKNOWN, WARN
from clawseccheck.checks import (
    _mcp_codex_annotations,
    _mcp_codex_approval_mode,
    _mcp_codex_requires_approval,
    _mcp_normalize_tool_filter,
    _mcp_tool_allowed,
    _mcp_tool_filter_matches,
)
from clawseccheck.collector import collect

MODERN = "2026.8.1"
LEGACY = "2026.7.1-2"

_DIST = Path("/home/glodi/.npm-global/lib/node_modules/openclaw/dist")


# ======================================================================================
# 1. The port, checked against the dist that defines it
# ======================================================================================

_APPROVAL_CASES = [
    (None, None), (None, {}), ("auto", {}), ("prompt", {}), ("approve", {}),
    ("auto", {"readOnlyHint": True}), ("auto", {"readOnlyHint": False}),
    ("auto", {"destructiveHint": True}), ("auto", {"destructiveHint": False}),
    ("auto", {"openWorldHint": True}), ("auto", {"openWorldHint": False}),
    ("auto", {"idempotentHint": True}), ("auto", {"idempotentHint": False}),
    ("auto", {"destructiveHint": False, "openWorldHint": False}),
    ("auto", {"destructiveHint": False, "openWorldHint": True}),
    ("auto", {"destructiveHint": True, "readOnlyHint": True}),
    ("auto", {"readOnlyHint": True, "openWorldHint": True}),
    ("auto", {"readOnlyHint": True, "destructiveHint": False}),
    ("prompt", {"readOnlyHint": True}), ("approve", {"destructiveHint": True}),
    ("zzz", {"readOnlyHint": True}), ("AUTO", {"readOnlyHint": True}),
    ("", {"readOnlyHint": True}),
    ("auto", {"readOnlyHint": "true"}), ("auto", {"readOnlyHint": 1}),
    ("auto", {"destructiveHint": 0}), ("auto", {"destructiveHint": None}),
    ("auto", {"readOnlyHint": None, "destructiveHint": False, "openWorldHint": False}),
]

_MODE_CASES = [
    ("plain", {}),
    ("plain", {"codex": {}}),
    ("plain", {"codex": {"defaultToolsApprovalMode": "approve"}}),
    ("plain", {"codex": {"defaultToolsApprovalMode": "prompt"}}),
    ("plain", {"codex": {"defaultToolsApprovalMode": "auto"}}),
    ("plain", {"codex": {"defaultToolsApprovalMode": "APPROVE"}}),
    ("plain", {"codex": {"defaultToolsApprovalMode": "zzz"}}),
    ("plain", {"codex": {"defaultToolsApprovalMode": 1}}),
    ("plain", {"codex": {"default_tools_approval_mode": "approve"}}),
    ("plain", {"codex": {"defaultToolsApprovalMode": "prompt",
                         "default_tools_approval_mode": "approve"}}),
    ("plain", {"codex": {"defaultToolsApprovalMode": "zzz",
                         "default_tools_approval_mode": "approve"}}),
    ("plain", {"codex": []}), ("plain", {"codex": None}), ("plain", {"codex": "approve"}),
    ("openclaw", {"url": "http://127.0.0.1:8080/mcp"}),
    ("openclaw", {"url": "https://localhost:9000/mcp"}),
    ("openclaw", {"url": "http://127.0.0.1:8080/mcp?x=1"}),
    ("openclaw", {"url": "http://127.0.0.1:8080/mcp#f"}),
    ("openclaw", {"url": "http://127.0.0.1:8080/mcp/extra"}),
    ("openclaw", {"url": "http://192.168.1.5:8080/mcp"}),
    ("openclaw", {"url": "http://evil.example:8080/mcp"}),
    ("openclaw", {"url": "http://127.0.0.1/mcp"}),
    ("openclaw", {"url": "ws://127.0.0.1:8080/mcp"}),
    ("openclaw", {}),
    ("openclaw", {"url": "http://127.0.0.1:8080/mcp",
                  "codex": {"defaultToolsApprovalMode": "prompt"}}),
    ("OpenClaw", {"url": "http://127.0.0.1:8080/mcp"}),
    ("other", {"url": "http://127.0.0.1:8080/mcp"}),
]

_DIFF_SCRIPT = """
import { readFileSync } from "node:fs";
const mod = process.argv[2];
const { n: requires, t: normalize, r: resolveMode } = await import(mod);
const payload = JSON.parse(readFileSync(process.argv[3], "utf8"));
console.log(JSON.stringify({
  approval: payload.approval.map(([mode, ann]) => ({
    normalized: normalize(ann),
    requires: requires({ mode: mode ?? undefined, annotations: normalize(ann) }),
  })),
  modes: payload.modes.map(([name, srv]) => resolveMode(name, srv)),
}));
"""


def _dist_module():
    hits = sorted(_DIST.glob("mcp-codex-tool-approval-*.js")) if _DIST.is_dir() else []
    return hits[0] if hits else None


@pytest.mark.skipif(shutil.which("node") is None, reason="no node on this machine")
def test_the_port_agrees_with_the_installed_dist_on_every_case():
    """The whole basis of this check. Reading the module would have got three of these
    wrong: an invalid camelCase mode falls THROUGH to the snake_case spelling instead of
    ending the lookup; `destructiveHint: false` + `openWorldHint: false` waives the gate
    with no `readOnlyHint` present; and a non-boolean value is dropped, so
    `readOnlyHint: "true"` grants nothing.
    """
    module = _dist_module()
    if module is None:
        pytest.skip("no installed OpenClaw dist to differ against")

    work = Path(tempfile.mkdtemp(prefix="b706-"))
    (work / "diff.mjs").write_text(_DIFF_SCRIPT, encoding="utf-8")
    (work / "cases.json").write_text(json.dumps({
        "approval": [[m, a] for m, a in _APPROVAL_CASES],
        "modes": [[n, s] for n, s in _MODE_CASES],
    }), encoding="utf-8")
    proc = subprocess.run(
        ["node", str(work / "diff.mjs"), str(module), str(work / "cases.json")],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    dist = json.loads(proc.stdout)

    disagreements = []
    for (mode, ann), expected in zip(_APPROVAL_CASES, dist["approval"]):
        ours_norm = _mcp_codex_annotations(ann)
        ours = _mcp_codex_requires_approval(mode if mode is not None else "auto", ours_norm)
        if ours_norm != expected["normalized"] or ours != expected["requires"]:
            disagreements.append(
                f"mode={mode!r} ann={ann!r}: dist normalized={expected['normalized']} "
                f"requires={expected['requires']}; ours {ours_norm} {ours}")
    for (name, spec), expected in zip(_MODE_CASES, dist["modes"]):
        ours = _mcp_codex_approval_mode(name, spec)
        if ours != expected:
            disagreements.append(f"{name} {spec!r}: dist={expected} ours={ours}")

    assert not disagreements, "\n".join(disagreements)


def test_the_differential_battery_covers_both_answers():
    """A battery that only ever produced one answer would agree with anything. Asserted on
    OUR port, so it runs on a machine with no OpenClaw installed too."""
    answers = {_mcp_codex_requires_approval(m or "auto", _mcp_codex_annotations(a))
               for m, a in _APPROVAL_CASES}
    assert answers == {True, False}
    modes = {_mcp_codex_approval_mode(n, s) for n, s in _MODE_CASES}
    assert modes == {"auto", "prompt", "approve"}


# ======================================================================================
# 2. The three semantics that reading would have got wrong, pinned individually
# ======================================================================================

def test_a_non_boolean_hint_grants_nothing():
    """`normalizeMcpCodexToolAnnotations` keeps boolean values only. Treating a truthy
    string as a grant would report an exemption the runtime never applies."""
    assert _mcp_codex_annotations({"readOnlyHint": "true"}) == {}
    assert _mcp_codex_annotations({"readOnlyHint": 1}) == {}
    assert _mcp_codex_requires_approval("auto", _mcp_codex_annotations(
        {"readOnlyHint": "true"})) is True
    # The control: the same key with a real boolean DOES waive it.
    assert _mcp_codex_requires_approval("auto", _mcp_codex_annotations(
        {"readOnlyHint": True})) is False


def test_two_false_hints_waive_the_gate_with_no_read_only_hint_in_sight():
    """The shape a `readOnlyHint`-shaped reading misses entirely: the final line is
    `destructiveHint !== false || openWorldHint !== false`, so declaring BOTH false is a
    second, separate way to buy the exemption."""
    assert _mcp_codex_requires_approval(
        "auto", {"destructiveHint": False, "openWorldHint": False}) is False
    # Either one alone is not enough — the control that keeps this from over-firing.
    assert _mcp_codex_requires_approval("auto", {"destructiveHint": False}) is True
    assert _mcp_codex_requires_approval("auto", {"openWorldHint": False}) is True


def test_an_invalid_camel_case_mode_falls_through_to_the_retired_spelling():
    """`normalizeApprovalMode` returns undefined for a value outside the enum, so the `??`
    chain continues rather than stopping. 2026.8.1 removed `default_tools_approval_mode`
    from the SCHEMA but the runtime still honours it, so a config carrying it is live."""
    assert _mcp_codex_approval_mode("s", {"codex": {
        "defaultToolsApprovalMode": "zzz", "default_tools_approval_mode": "approve"}}) == "approve"
    # A VALID camelCase value wins over the snake_case one — the control.
    assert _mcp_codex_approval_mode("s", {"codex": {
        "defaultToolsApprovalMode": "prompt", "default_tools_approval_mode": "approve"}}) == "prompt"


def test_destructive_wins_over_read_only():
    """Order matters: a server cannot buy the exemption by declaring both."""
    assert _mcp_codex_requires_approval(
        "auto", {"destructiveHint": True, "readOnlyHint": True}) is True


def test_the_loopback_exemption_is_exact():
    """OpenClaw pre-approves its OWN loopback server. Every near miss must NOT get it, or
    a hostile server named `openclaw` would inherit the vendor's trust."""
    ok = {"url": "http://127.0.0.1:8080/mcp"}
    assert _mcp_codex_approval_mode("openclaw", ok) == "approve"
    for name, spec in (
        ("OpenClaw", ok),                                            # case
        ("other", ok),                                               # name
        ("openclaw", {"url": "http://evil.example:8080/mcp"}),       # host
        ("openclaw", {"url": "http://127.0.0.1/mcp"}),               # no port
        ("openclaw", {"url": "http://127.0.0.1:8080/mcp/extra"}),    # trailing path
        ("openclaw", {"url": "ws://127.0.0.1:8080/mcp"}),            # scheme
    ):
        assert _mcp_codex_approval_mode(name, spec) == "auto", (name, spec)


# ======================================================================================
# 3. B333's verdict, per generation
#
# §4 asks for a clean + bad FIXTURE per changed check. `fixtures/bad_b333_mcp_annotation_
# ignored` still covers the legacy leg and still fires. The MODERN leg deliberately has no
# corpus fixture and cannot have a useful one: `clawseccheck.audit(home)` leaves
# `installed_dist_version` unset (the dist read is opt-in via `include_dist`), so every
# corpus entry resolves to the `unknown` generation and takes the legacy branch. A fixture
# added for the modern leg would sit in the corpus proving nothing — the same trap as
# seeding a file the walk cap cannot reach. The version is therefore injected here, exactly
# as tests/test_c471_retired_subjects.py and tests/test_b705_owner_wildcard.py do for the
# other version-split checks in this epic.
# ======================================================================================

def _cfg(tools, *, codex=None):
    server = {"command": "srv", "tools": tools}
    if codex is not None:
        server["codex"] = codex
    return {"mcp": {"servers": {"srv": server}}}


def _finding(cfg, installed, cid="B333"):
    home = Path(tempfile.mkdtemp(prefix="b706-home-"))
    path = home / "openclaw.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    os.chmod(path, 0o600)
    ctx = collect(home)
    ctx.installed_dist_version = installed
    return next(f for f in C.run_all(ctx) if f.id == cid)


def _tool(name, annotations=None):
    t = {"name": name, "description": "does a thing", "inputSchema": {"type": "object"}}
    if annotations is not None:
        t["annotations"] = annotations
    return t


def test_a_read_only_hint_is_a_waived_gate_on_a_modern_build():
    f = _finding(_cfg([_tool("fetch", {"readOnlyHint": True})]), MODERN)
    assert f.status == WARN
    detail = f.detail or ""
    assert "waive their own approval gate" in detail
    assert "2026.8.1" in detail


def test_a_destructive_hint_is_NOT_reported_as_a_grant_on_a_modern_build():
    """The failure mode this check invites: `destructiveHint: true` is the approval-REQUIRED
    side, and OpenClaw omits such a tool from an unattended run. Reporting it would accuse a
    server of the opposite of what it did."""
    assert _finding(_cfg([_tool("rm", {"destructiveHint": True})]), MODERN).status == PASS


def test_an_idempotent_hint_alone_is_still_inert_on_a_modern_build():
    """`normalizeMcpCodexToolAnnotations` extracts it and `requiresMcpCodexToolApproval`
    never reads it, so this ONE hint really is still inert on 8.1. Lumping it in with the
    other three would be the same error in reverse."""
    for value in (True, False):
        assert _finding(_cfg([_tool("t", {"idempotentHint": value})]), MODERN).status == PASS


def test_both_false_hints_are_reported_on_a_modern_build():
    """The second waiver shape, end to end and not just at the predicate."""
    f = _finding(_cfg([_tool("t", {"destructiveHint": False, "openWorldHint": False})]),
                 MODERN)
    assert f.status == WARN


def test_a_tool_with_no_annotations_is_clean_on_a_modern_build():
    """The common case, and the control: without it, "always WARN on modern" passes every
    assertion above."""
    assert _finding(_cfg([_tool("t")]), MODERN).status == PASS


def test_a_prompt_mode_server_is_clean_even_with_a_waiving_annotation():
    """`mode="prompt"` short-circuits before annotations are consulted, so a server the
    operator has already hardened must not be reported. Skipping this read would have made
    a correctly-configured setup produce a false WARN."""
    f = _finding(_cfg([_tool("fetch", {"readOnlyHint": True})],
                      codex={"defaultToolsApprovalMode": "prompt"}), MODERN)
    assert f.status == PASS


def test_the_legacy_verdict_is_unchanged():
    """B333 was right for 2026.7.x and a fleet on that build must keep the finding it had —
    including for `destructiveHint`, which really was inert there."""
    for annotations in ({"readOnlyHint": True}, {"destructiveHint": True},
                        {"idempotentHint": True}):
        f = _finding(_cfg([_tool("t", annotations)]), LEGACY)
        assert f.status == WARN, annotations
        assert "not read" in (f.detail or "") or "drops them" in (f.detail or "")


def test_an_undeterminable_build_keeps_the_legacy_verdict():
    """The rule every other version-split check in this epic follows: silence would be a
    claim about a build we cannot see, and on the legacy reading the operator is told their
    policy is unenforced, which is the safer thing to be wrong about."""
    f = _finding(_cfg([_tool("t", {"idempotentHint": True})]), None)
    assert f.status == WARN


def test_no_mcp_servers_is_still_unknown_on_every_build():
    for installed in (MODERN, LEGACY, None):
        assert _finding({}, installed).status == UNKNOWN


def test_the_source_split_did_not_move():
    """A trajectory- or probe-derived surface structurally cannot carry annotations, so
    absence there proves nothing about what the server declared — UNKNOWN on both builds,
    unchanged by this task."""
    from clawseccheck import mcpsurface as _ms

    surface = _ms.from_tool_defs("s", [_tool("t", {"readOnlyHint": True})])
    assert surface is not None and surface.source == "manifest"


# ======================================================================================
# 4. No shipped text still says the hints are ignored
# ======================================================================================

def _normalized(text: str) -> str:
    """Comment markers stripped and whitespace collapsed.

    Line-based matching is the wrong tool here and the C-135 pass proved it twice: a wrapped
    comment splits `annotations is NEVER stored` across two lines, so a per-line ban list
    missed three live claims while reporting itself green. The claim is a property of the
    SENTENCE, so normalize first and match the sentence.
    """
    stripped = "\n".join(ln.lstrip().lstrip("#*").strip() for ln in text.splitlines())
    return re.sub(r"\s+", " ", stripped)


# The claims 2026.8.1 falsified. Regexes, not substrings, because the distinction that
# matters is the SUBJECT: "OpenClaw does not read them" is a claim about the product and is
# now false; "this OpenClaw BUILD does not read them", inside the legacy branch, is a claim
# about a build and stays true. Each pattern is written so the qualified form does not match.
# TENSE is part of the distinction, not just the subject. "`annotations` IS never stored"
# is a present-tense claim about OpenClaw and is now false; "when it REGISTERED a tool,
# `annotations` WAS never stored", inside the 2026.7.x paragraph, is a historical fact and
# stays true. The first version of these patterns was tense-blind and flagged the very
# sentences that carry the legacy grounding.
_BANNED_CLAIMS = (
    r"annotations`?\s+(?:is|are)\s+never stored",
    r"OpenClaw(?:'s)?(?: runtime(?: code)?| registration path)?\s+(?:never reads|simply never reads)",
    r"OpenClaw does not read",
    r"OpenClaw drops them",
    r"and never reads these",
    r"OpenClaw's registration path stores only",
)


def test_no_shipped_artifact_still_claims_openclaw_ignores_the_hints():
    """Golden Rule #4 applies to our own docstrings and shipped docs, not only to findings.
    The false claim lived in the check, the catalog and THREAT_COVERAGE, and each was a
    MEASURED assertion ("0 occurrences in the dist") that 2026.8.1 falsified.
    """
    root = Path(__file__).resolve().parent.parent
    targets = [root / "clawseccheck" / "checks" / "_mcp.py",
               root / "clawseccheck" / "catalog.py",
               root / "docs" / "THREAT_COVERAGE.md"]
    offenders = []
    for path in targets:
        if not path.exists():
            continue
        text = _normalized(path.read_text(encoding="utf-8"))
        for pattern in _BANNED_CLAIMS:
            for m in re.finditer(pattern, text, re.I):
                offenders.append(f"{path.name}: ...{text[max(0, m.start() - 60):m.end() + 40]}...")
    assert not offenders, (
        "a shipped artifact still says OpenClaw ignores the MCP safety hints, which "
        "2026.8.1 falsified:\n" + "\n".join(offenders))


def test_the_ban_list_covers_every_claim_the_previous_revision_actually_made():
    """A ban list is only as good as its RECALL, and the first version of this one missed
    three live phrases — the guard above passed while the check's own docstring still said
    OpenClaw never reads the hints, and the C-135 pass found it.

    So the list is re-derived from the PRE-CHANGE revision rather than from memory: every
    sentence in B333's old region that asserts the hints are ignored must be matched by some
    banned pattern. Scoped to that region because the module is ~7,600 lines and a dozen
    unrelated checks legitimately say things like "check_sandbox never reads" — a whole-file
    scan measured the wrong text, which is its own version of this same mistake.
    """
    import subprocess as _sp

    root = Path(__file__).resolve().parent.parent
    # Anchored on the last revision that CONTAINED the claim, not on "the previous
    # revision". Once this task landed, the previous revision became the fixed one and the
    # guard had nothing to measure — it failed its own vacuity assertion, correctly. `-S`
    # finds the commit where the string was removed; its parent still has it.
    try:
        rev = _sp.run(["git", "log", "--format=%H", "-1",
                       "-S", "OpenClaw's runtime code never reads",
                       "--", "clawseccheck/checks/_mcp.py"],
                      cwd=root, capture_output=True, text=True, timeout=60)
        if rev.returncode != 0 or not rev.stdout.strip():
            pytest.skip("the claim is not in this repo's history (shallow clone?)")
        prev = _sp.run(["git", "show", f"{rev.stdout.strip()}^:clawseccheck/checks/_mcp.py"],
                       cwd=root, capture_output=True, text=True, timeout=60)
        if prev.returncode != 0:
            pytest.skip("could not read the revision that carried the claim")
    except (OSError, _sp.SubprocessError):
        pytest.skip("git unavailable")

    text = _normalized(prev.stdout)
    start = text.find("B333 (F-143/W2.1)")
    end = text.find("B332 (F-145/W2.3)", start + 1)
    if start == -1:
        pytest.skip("B333's region is not in the previous revision in a recognisable form")
    region = text[start:end if end != -1 else len(text)]

    # Every sentence in the old region that asserts the hints are ignored.
    sentences = [s.strip() for s in re.split(r"(?<=[.!?]) ", region)
                 if re.search(r"never read|never stored|drops them", s, re.I)]
    assert sentences, "the previous revision made no such claim — this guard is vacuous"
    uncovered = [s for s in sentences
                 if not any(re.search(p, s, re.I) for p in _BANNED_CLAIMS)]
    assert not uncovered, (
        "the ban list does not cover every ignored-hints claim the previous revision made, "
        "so it can pass while one of them survives:\n"
        + "\n".join(u[:150] for u in uncovered))


# ======================================================================================
# 5. The vendor's own words, and the source split they settle
# ======================================================================================

@pytest.mark.skipif(shutil.which("node") is None, reason="no node on this machine")
def test_openclaw_itself_says_annotations_are_what_removes_the_approval_step():
    """The strongest available grounding for how this finding is FRAMED, and it is the
    vendor's, not ours. `openclaw mcp probe --json` emits a per-server `approvalHint`
    exactly when the mode is auto and every tool's `codexAnnotations` is empty, and its text
    is "tools have no safety annotations; calls will require interactive approval".

    OpenClaw is telling the operator that the ABSENCE of annotations is what keeps the
    approval step — so their presence is what can remove it. If this string ever disappears,
    the framing needs re-grounding, which is the whole point of anchoring on it.
    """
    cli = sorted(_DIST.glob("mcp-cli-*.js")) if _DIST.is_dir() else []
    if not cli:
        pytest.skip("no installed OpenClaw dist")
    text = cli[0].read_text(errors="replace")
    assert "tools have no safety annotations" in text
    assert "will require interactive approval" in text


@pytest.mark.skipif(shutil.which("node") is None, reason="no node on this machine")
def test_the_probe_still_cannot_carry_annotations_so_the_source_split_stands():
    """The claim the UNKNOWN legs rest on, re-checked against 2026.8.1 rather than inherited
    from the 2026.7.x grounding. The probe projection is
    `tools: projectedTools.map((tool) => tool.name).toSorted()` — names only. A change here
    would mean a probe-derived surface could carry annotations, and the UNKNOWN legs would be
    hiding real evidence instead of declining to guess.
    """
    cli = sorted(_DIST.glob("mcp-cli-*.js")) if _DIST.is_dir() else []
    if not cli:
        pytest.skip("no installed OpenClaw dist")
    text = cli[0].read_text(errors="replace")
    assert "tools: projectedTools.map((tool) => tool.name).toSorted()" in text, (
        "the probe's tool projection changed shape — re-check whether it now carries "
        "annotations, because B333's UNKNOWN source legs assume it cannot"
    )


# ======================================================================================
# 6. The title, which is static and therefore has to be true on both builds
# ======================================================================================

def test_the_catalog_title_is_true_on_both_builds():
    """The title is STATIC — one string for every generation — and the old one said
    "declared but not enforced by OpenClaw", which is false on 2026.8.1. A user reads the
    title and the detail together, so on a modern build they would have contradicted each
    other on the same screen while every test passed.

    Found by rendering the finding rather than by reading the source string. The rule the
    title has to satisfy is that it names the SUBJECT and leaves the verdict to the detail,
    since only the detail knows which build is installed.
    """
    from clawseccheck.catalog import BY_ID

    title = BY_ID["B333"].title
    assert "not enforced" not in title, "the title cannot assert a verdict the build decides"
    assert "safety-hint annotation" in title, "it must still name its subject"


def test_the_title_and_the_modern_detail_do_not_contradict_each_other():
    """The pair, asserted together — this is what the reader actually sees."""
    from clawseccheck.catalog import BY_ID

    f = _finding(_cfg([_tool("fetch", {"readOnlyHint": True})]), MODERN)
    screen = f"{BY_ID['B333'].title} {f.detail}"
    assert "not enforced" not in screen
    assert "waive their own approval gate" in screen


# ======================================================================================
# 7. What the C-135 adversarial pass found — one test per confirmed defect
#
# Every one of these was written AFTER the fix and then mutation-checked: reverting the fix
# must redden the test. Before they existed, all four fixes could be deleted and the file
# still reported 23 passed, which is the whole reason the mutation step is not optional.
# ======================================================================================

def test_a_tool_the_operator_filtered_out_is_not_reported_as_waiving_anything():
    """C-135, major. `toolFilter` takes a tool out of the catalog entirely: the runtime marks
    it `excludedFromOpenClawCatalog`, keeps it out of `catalog.tools`, and the scheduled-run
    filter therefore never sees it. Reporting it as "exempt from the approval gate in
    unattended scheduled runs" states a grant that cannot exist.

    The sting: B333's own legacy remediation tells the operator to enforce read-only
    behaviour "via OpenClaw's own tool allowlist" — so following this check's advice earned
    this check's new finding.
    """
    ro = {"readOnlyHint": True}
    for label, spec in (
        ("exclude", {"toolFilter": {"exclude": ["fetch"]}}),
        ("include-other", {"toolFilter": {"include": ["other"]}}),
        ("exclude-glob", {"toolFilter": {"exclude": ["fet*"]}}),
    ):
        cfg = {"mcp": {"servers": {"s": dict(
            {"command": "c", "tools": [_tool("fetch", ro)]}, **spec)}}}
        assert _finding(cfg, MODERN).status == PASS, label


def test_the_same_tool_without_a_filter_still_warns():
    """The control for the test above. Without it, "always PASS" satisfies it and the whole
    modern leg could be deleted."""
    assert _finding(_cfg([_tool("fetch", {"readOnlyHint": True})]), MODERN).status == WARN


def test_a_filter_that_does_not_match_the_tool_leaves_the_warning_alone():
    """The other half: a filter is not a blanket excuse. A tool the filter KEEPS is still
    reachable and still waives its gate."""
    cfg = {"mcp": {"servers": {"s": {"command": "c", "toolFilter": {"exclude": ["other"]},
                                     "tools": [_tool("fetch", {"readOnlyHint": True})]}}}}
    assert _finding(cfg, MODERN).status == WARN


def test_a_disabled_server_is_not_reported():
    """C-135, major. `bundle-mcp-config-*.js` builds `enabledConfiguredMcp` by filtering on
    `server.enabled !== false`, so a disabled server never reaches the bundle MCP runtime and
    none of its tools are ever materialized."""
    cfg = {"mcp": {"servers": {"s": {"command": "c", "enabled": False,
                                     "tools": [_tool("fetch", {"readOnlyHint": True})]}}}}
    assert _finding(cfg, MODERN).status == PASS
    # The control: the same server, enabled.
    cfg["mcp"]["servers"]["s"]["enabled"] = True
    assert _finding(cfg, MODERN).status == WARN


@pytest.mark.parametrize("url,why", [
    ("http://localhost:1/mcp\n", "python `$` matches before a trailing newline; JS `$` does not"),
    ("http://localhost:1/mcp?a\n", "same, through the optional query group"),
    ("http://127.0.0.1:\u0663\u0660\u0660\u0660/mcp", "Arabic-Indic digits: python `\\d` accepts them, JS does not"),
    ("http://127.0.0.1:\uff13\uff10\uff10\uff10/mcp", "fullwidth digits"),
    ("http://127.0.0.1:\u0969\u0966\u0966\u0966/mcp", "Devanagari digits"),
])
def test_the_loopback_regex_does_not_over_match_where_javascript_would_not(url, why):
    """C-135, major, and the dangerous direction: every one of these made the port answer
    "approve" where the runtime answers "auto" — handing OpenClaw's implicit trust for its
    own loopback server to a server merely NAMED `openclaw`.

    Both causes are Python-vs-JavaScript regex semantics, not logic: `$` matches before a
    trailing newline (so `\\Z`), and `\\d` accepts every Unicode decimal digit (so `[0-9]`).
    An independent harness ran 92 url cases against the real dist and found exactly these.
    """
    assert _mcp_codex_approval_mode("openclaw", {"url": url}) == "auto", why


def test_the_loopback_exemption_still_works_for_the_real_thing():
    """The control: without it, a regex that never matches passes every case above."""
    assert _mcp_codex_approval_mode("openclaw", {"url": "http://127.0.0.1:8080/mcp"}) == "approve"
    assert _mcp_codex_approval_mode("openclaw", {"url": "https://localhost:9000/mcp?x=1"}) == "approve"


@pytest.mark.parametrize("annotations,codex,extra", [
    ({"destructiveHint": True}, None, {}),
    ({"idempotentHint": True}, None, {}),
    ({"readOnlyHint": True}, {"defaultToolsApprovalMode": "prompt"}, {}),
    ({"readOnlyHint": True}, {"defaultToolsApprovalMode": "approve"}, {}),
    ({"readOnlyHint": True}, None, {"enabled": False}),
    ({"readOnlyHint": True}, None, {"toolFilter": {"exclude": ["fetch"]}}),
], ids=["destructive", "idempotent", "prompt", "approve", "disabled", "filtered"])
def test_the_modern_pass_text_does_not_deny_annotations_that_are_right_there(
        annotations, codex, extra):
    """C-135, and the most serious thing it found: the modern leg reached PASS with the
    LEGACY sentence, which says the servers "declare no readOnlyHint/destructiveHint/
    openWorldHint/idempotentHint annotations" — about configs that plainly declare them,
    including the repo's own `bad_b333_mcp_annotation_ignored` fixture.

    The two legs ask different questions ("did anyone declare a hint" vs "does any
    declaration waive the gate"), so they cannot share a PASS sentence. Golden Rule #4: a
    PASS may say the danger is absent; it may not say the DATA is absent when we read it and
    it was there.

    My own tests could not see this — they asserted `f.status` and never `f.detail`.
    """
    server = dict({"command": "c", "tools": [_tool("fetch", annotations)]}, **extra)
    if codex is not None:
        server["codex"] = codex
    f = _finding({"mcp": {"servers": {"s": server}}}, MODERN)
    assert f.status == PASS
    detail = f.detail or ""
    assert "declare no readOnlyHint" not in detail, detail
    assert "asks OpenClaw to waive its approval gate" in detail, detail


def test_the_legacy_pass_text_is_untouched():
    """The control: the legacy sentence is still correct for the build it describes, and
    changing it would have been a different kind of wrong."""
    f = _finding(_cfg([_tool("plain")]), LEGACY)
    assert f.status == PASS
    assert "declare no readOnlyHint" in (f.detail or "")


# ======================================================================================
# 8. The tool-filter port, also checked against the dist rather than read
# ======================================================================================

_FILTER_CASES = [
    (None, "fetch"), ({}, "fetch"),
    ({"include": []}, "fetch"), ({"exclude": []}, "fetch"),
    ({"include": ["fetch"]}, "fetch"), ({"include": ["other"]}, "fetch"),
    ({"exclude": ["fetch"]}, "fetch"), ({"exclude": ["other"]}, "fetch"),
    ({"include": ["fetch"], "exclude": ["fetch"]}, "fetch"),
    ({"exclude": ["*"]}, "fetch"), ({"include": ["*"]}, "fetch"),
    ({"exclude": ["fet*"]}, "fetch"), ({"exclude": ["*tch"]}, "fetch"),
    ({"exclude": ["f*t*h"]}, "fetch"), ({"exclude": ["f*t*z"]}, "fetch"),
    ({"exclude": ["*e*t*"]}, "fetch"), ({"exclude": ["**"]}, "fetch"),
    ({"exclude": ["  fetch  "]}, "fetch"), ({"exclude": ["   "]}, "fetch"),
    ({"exclude": ["FETCH"]}, "fetch"), ({"exclude": ["fetchx"]}, "fetch"),
    ({"exclude": ["fetc"]}, "fetch"), ({"include": ["fetch", "other"]}, "other"),
    ({"exclude": [1, "fetch"]}, "fetch"), ({"include": [None]}, "fetch"),
    ({"include": "fetch"}, "fetch"), ({"exclude": {"a": 1}}, "fetch"),
    ({"exclude": ["*fetch*"]}, "prefetching"),
    ({"exclude": ["a*b*c"]}, "axbxc"), ({"exclude": ["a*b*c"]}, "abc"),
    ({"exclude": ["a*a"]}, "a"),
]

_FILTER_SCRIPT = """
import { readFileSync } from "node:fs";
const { n: normalize, t: allowed } = await import(process.argv[2]);
const cases = JSON.parse(readFileSync(process.argv[3], "utf8"));
console.log(JSON.stringify(cases.map(([raw, name]) => {
  const norm = normalize(raw ?? undefined);
  return { normalized: norm ?? null, allowed: allowed(norm, name) };
})));
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="no node on this machine")
def test_the_tool_filter_port_agrees_with_the_installed_dist():
    """`matchesMcpToolFilterPattern` is a hand-rolled glob with a cursor and an end-bound,
    NOT fnmatch and not a regex — `a*a` against `a` is the case where the difference shows.
    Ported by reading it once and then checked by running it, because the reachability gate
    that decides whether B333 speaks now rests on it.
    """
    hits = sorted(_DIST.glob("mcp-tool-filter-*.js")) if _DIST.is_dir() else []
    if not hits:
        pytest.skip("no installed OpenClaw dist to differ against")

    work = Path(tempfile.mkdtemp(prefix="b706-filter-"))
    (work / "f.mjs").write_text(_FILTER_SCRIPT, encoding="utf-8")
    (work / "cases.json").write_text(json.dumps([[r, n] for r, n in _FILTER_CASES]),
                                     encoding="utf-8")
    proc = subprocess.run(["node", str(work / "f.mjs"), str(hits[0]), str(work / "cases.json")],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    dist = json.loads(proc.stdout)

    bad = []
    for (raw, name), expected in zip(_FILTER_CASES, dist):
        ours_norm = _mcp_normalize_tool_filter(raw)
        ours_allowed = _mcp_tool_allowed(ours_norm, name)
        if ours_norm != expected["normalized"] or ours_allowed != expected["allowed"]:
            bad.append(f"{raw!r} / {name!r}: dist {expected}; ours {ours_norm} {ours_allowed}")
    assert not bad, "\n".join(bad)


def test_the_filter_battery_covers_both_answers():
    """Without this a port that always allows would agree with a battery of allow-only
    cases. Runs with no dist installed."""
    answers = {_mcp_tool_allowed(_mcp_normalize_tool_filter(r), n) for r, n in _FILTER_CASES}
    assert answers == {True, False}


# ======================================================================================
# 9. C-135 round two — what the SECOND adversarial pass found
# ======================================================================================

def test_the_warn_does_not_assert_a_grant_this_audit_cannot_confirm():
    """C-135 round two, major, and the one I had not considered at all.

    `requiresMcpCodexToolApproval` is reachable from ONE decision site, behind the Codex
    app-server extension's `ownsScheduledConfiguredMcpSurface`. OpenClaw's own schema says
    so in as many words: `mcp.servers.*.codex` is "projection metadata for Codex app-server
    threads only. It does not affect ACP sessions or generic Codex harness config."

    Measured: an Anthropic-model agent resolves to `runtime: "auto"`, not `codex`. So the
    first version of this WARN told an Anthropic user that a gate was being waived when no
    such gate existed on their setup, at confidence HIGH, and then recommended a setting
    that would change nothing for them — inert advice, which this repo treats as the defect
    itself (see `_openclaw_generation`'s docstring in checks/_shared.py).

    The verdict still fires — the servers really do declare the waiver, and determining the
    harness needs a port this task does not have — but every claim is now conditional and
    the condition is named. Precision is tracked separately.
    """
    f = _finding(_cfg([_tool("fetch", {"readOnlyHint": True})]), MODERN)
    detail, fix = f.detail or "", f.fix or ""
    assert "does not determine" in detail, "the audit must say what it cannot see"
    assert "Codex app-server" in detail
    assert "inert on" in fix, "the fix must say when it would change nothing"


def test_the_pass_sentence_does_not_enumerate_causes_it_cannot_cover():
    """C-135 round two. The first modern PASS text listed the reasons a config could reach
    it ("declares nothing, declares destructiveHint, or is out of reach"), and the list was
    incomplete: `openWorldHint: true` alone and a non-boolean `readOnlyHint: "true"` both
    reach PASS and are in none of the three. An enumeration in a verdict is a promise about
    completeness — so the sentence states the property and offers the causes as examples.
    """
    for annotations in ({"openWorldHint": True}, {"readOnlyHint": "true"},
                        {"idempotentHint": True}, {"destructiveHint": True}):
        f = _finding(_cfg([_tool("t", annotations)]), MODERN)
        assert f.status == PASS, annotations
        assert "asks OpenClaw to waive its approval gate" in (f.detail or "")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/mcp?a\r",
    "http://127.0.0.1:8080/mcp?a\u2028",
    "http://127.0.0.1:8080/mcp#a\u2029",
])
def test_the_loopback_regex_respects_javascripts_dot_class(url):
    """C-135 round two, same family as the first round's `$`/`\\d` finding and the same
    dangerous direction. JavaScript's `.` excludes \\r and U+2028/U+2029 as well as \\n;
    Python's excludes only \\n, so the optional query/fragment group over-matched on those
    three and handed the loopback exemption to a url the runtime rejects."""
    assert _mcp_codex_approval_mode("openclaw", {"url": url}) == "auto"


@pytest.mark.parametrize("pad,strips_in_python,strips_in_js", [
    ("\x1c", True, False), ("\x1f", True, False), ("\x85", True, False),
    ("\ufeff", False, True),
])
def test_the_filter_trims_the_way_javascript_does(pad, strips_in_python, strips_in_js):
    """C-135 round two: a 220-case differential found 48 disagreements, every one from
    padding. Python's `str.strip()` removes the C1/field separators that JS keeps, and JS
    removes U+FEFF that Python keeps — and each disagreement changed whether a filter
    matched, i.e. whether this check speaks at all.

    Asserted against the vendor's behaviour, not against Python's: a pattern padded with a
    character JS does NOT trim cannot match, and one padded with a character JS DOES trim
    must match.
    """
    del strips_in_python  # named to document the asymmetry being tested
    assert _mcp_tool_filter_matches(f"{pad}fetch{pad}", "fetch") is strips_in_js
