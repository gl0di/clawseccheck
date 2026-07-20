"""RISK-21 (F-135): open group ingress joined with a high-blast verb PROVEN from it.

Before this rule the engine had both halves and related neither: `risk_paths` took only
static findings, and the log-observed half lived behind a terminal `--behavioral` branch.
The whole difficulty is that the COARSE join ("an open channel exists" AND "a high-blast
verb is proven somewhere") fires on an ordinary maintainer's machine — measured there, an
open wildcard-group telegram channel sits beside 867 proven `bash` calls of which ZERO
came from a group or channel origin across 73 sidecars; every one was `telegram:direct`
(the owner's own DM), `dashboard` (his own web UI) or an unrecognised `other` key.

`fixtures/clean_risk21_owner_origin_exec` IS that shape, reduced: the static leg fully
satisfied, high-blast verbs proven, and silence — which is what makes the bad fixture's
firing mean something. Each clean fixture is pinned by an ablation test that flips only
its own discriminator and shows the chain then fires, so none of them can pass for an
incidental reason.

Offline, read-only; writes nothing outside tmp_path.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from clawseccheck import audit
from clawseccheck.catalog import MEDIUM
from clawseccheck.risk import _open_group_channels, render_risk_paths, risk_paths

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# --------------------------------------------------------------------------- helpers

def _risk21(home):
    ctx, findings, _ = audit(home, include_native=False, include_host=False)
    paths = risk_paths(ctx, findings)
    return next((p for p in paths if p.id == "RISK-21"), None)


def _sidecar(home: Path, session: str, key: str, calls, agent: str = "main") -> None:
    """Write one trajectory sidecar: a prompt.submitted followed by *calls*."""
    d = home / "agents" / agent / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps({
        "traceSchema": "openclaw-trajectory", "schemaVersion": 1,
        "type": "prompt.submitted", "ts": "2026-07-20T00:00:01Z", "seq": 1,
        "sessionId": session, "sessionKey": key,
        "data": {"turnId": "t1", "threadId": "t1"},
    })]
    for i, name in enumerate(calls, start=2):
        lines.append(json.dumps({
            "traceSchema": "openclaw-trajectory", "schemaVersion": 1,
            "type": "tool.call", "ts": f"2026-07-20T00:00:{i:02d}Z", "seq": i,
            "sessionId": session, "sessionKey": key,
            "data": {"name": name, "arguments": {}, "toolCallId": f"c{i}",
                     "turnId": "t1", "threadId": "t1"},
        }))
    (d / f"{session}.trajectory.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _home(tmp_path: Path, channels: dict, session_key: str | None = None,
          calls=("bash",)) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "openclaw.json").write_text(
        json.dumps({"channels": channels}), encoding="utf-8")
    (tmp_path / "openclaw.json").chmod(0o600)
    if session_key is not None:
        _sidecar(tmp_path, "s1", session_key, calls)
    return tmp_path


_OPEN_WILDCARD = {"telegram": {"enabled": True, "groups": {"*": {}}}}
_GROUP_KEY = "agent:main:telegram:group:synthetic-group-1"


# --------------------------------------------------------------------------- fixtures: bad

def test_bad_fixture_fires_as_an_advisory_medium():
    p = _risk21(FIXTURES / "bad_risk21_group_proven_exec")
    assert p is not None, "RISK-21 did not fire on a group-origin session that ran bash"
    assert p.severity == MEDIUM, "RISK-21 is advisory — it must not claim HIGH/CRITICAL"
    assert "telegram" in p.chain[0]
    assert "bash" in p.chain[2]


def test_bad_fixture_names_only_the_high_blast_verb_not_the_mundane_one():
    """The bad fixture's session also ran `web_search`; only the blast verb is evidence."""
    p = _risk21(FIXTURES / "bad_risk21_group_proven_exec")
    assert "web_search" not in p.chain[2]


# --------------------------------------------------------------------------- fixtures: clean

def test_clean_owner_origin_stays_silent():
    """THE decisive FP guard, and the real-host shape: the static leg is fully satisfied
    (open wildcard group) and high-blast verbs ARE proven — but every session was opened
    from the owner's own DM or dashboard, so no group sender demonstrably reached them."""
    assert _risk21(FIXTURES / "clean_risk21_owner_origin_exec") is None


def test_clean_group_origin_low_blast_stays_silent():
    """Group-origin traffic doing ordinary things — search, read, reply — is not a chain."""
    assert _risk21(FIXTURES / "clean_risk21_group_low_blast") is None


def test_clean_group_allowlisted_stays_silent():
    """Same group origin, same proven bash — but groupAllowFrom scopes who may send."""
    assert _risk21(FIXTURES / "clean_risk21_group_allowlisted") is None


# --------------------------------------------------------------------------- ablations

def test_ablation_owner_origin_fires_once_the_origin_is_a_group(tmp_path):
    """Flip ONLY the origin kind in the clean fixture: direct -> group."""
    h = tmp_path / "h"
    shutil.copytree(FIXTURES / "clean_risk21_owner_origin_exec", h)
    f = h / "agents" / "main" / "sessions" / "s1.trajectory.jsonl"
    f.write_text(f.read_text().replace("telegram:direct:", "telegram:group:"),
                 encoding="utf-8")
    assert _risk21(h) is not None, (
        "clean_risk21_owner_origin_exec is silent for some reason OTHER than the "
        "session origin — the fixture would not be pinning what it claims to pin"
    )


def test_ablation_low_blast_fires_once_a_blast_verb_is_added(tmp_path):
    """Add ONLY a bash call to the clean fixture's group session."""
    h = tmp_path / "h"
    shutil.copytree(FIXTURES / "clean_risk21_group_low_blast", h)
    f = h / "agents" / "main" / "sessions" / "s1.trajectory.jsonl"
    rec = json.loads([ln for ln in f.read_text().splitlines() if ln][-1])
    rec["seq"] += 1
    rec["data"]["name"] = "bash"
    f.write_text(f.read_text() + json.dumps(rec) + "\n", encoding="utf-8")
    assert _risk21(h) is not None


def test_ablation_allowlisted_fires_once_the_allowlist_is_removed(tmp_path):
    """Drop ONLY groupAllowFrom from the clean fixture's config."""
    h = tmp_path / "h"
    shutil.copytree(FIXTURES / "clean_risk21_group_allowlisted", h)
    cfg_path = h / "openclaw.json"
    cfg = json.loads(cfg_path.read_text())
    del cfg["channels"]["telegram"]["groupAllowFrom"]
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    assert _risk21(h) is not None


# --------------------------------------------------------------------------- static leg

def test_group_policy_open_arms_the_static_leg(tmp_path):
    assert _risk21(_home(tmp_path, {"telegram": {"enabled": True, "groupPolicy": "open"}},
                         _GROUP_KEY)) is not None


def test_group_policy_open_is_not_restricted_by_group_allow_from(tmp_path):
    """Dist fact, not a shortcut: the live sender gate returns allow("group_policy_open")
    BEFORE consulting any allowlist (message-access-DucCKzfO.js:193), so a leftover
    groupAllowFrom beside groupPolicy:"open" restricts nothing. Reading the @deprecated
    SDK helper instead (group-access-CyF0dAER.js:8-10, which downgrades open->allowlist
    when groupAllowFrom is non-empty) would make this a silent false negative."""
    assert _risk21(_home(tmp_path, {"telegram": {
        "enabled": True, "groupPolicy": "open", "groupAllowFrom": ["u1"]}},
        _GROUP_KEY)) is not None


def test_group_policy_allowlist_stays_silent(tmp_path):
    assert _risk21(_home(tmp_path, {"telegram": {
        "enabled": True, "groupPolicy": "allowlist", "groupAllowFrom": ["u1"]}},
        _GROUP_KEY)) is None


def test_absent_group_policy_stays_silent(tmp_path):
    """Positive evidence only. The bundled zod schemas default several providers to
    "allowlist" while the runtime resolver defaults a configured provider to "open", so
    an absent groupPolicy is genuinely ambiguous — arming on it would be a false FIRE."""
    assert _risk21(_home(tmp_path, {"telegram": {"enabled": True}}, _GROUP_KEY)) is None


def test_group_policy_disabled_beside_a_wildcard_group_stays_silent(tmp_path):
    """A leftover groups {"*"} beside groupPolicy:"disabled" admits no group message at
    all — the C-135 shape B-297 already taught the shared predicate to drop."""
    assert _risk21(_home(tmp_path, {"telegram": {
        "enabled": True, "groupPolicy": "disabled", "groups": {"*": {}}}},
        _GROUP_KEY)) is None


def test_disabled_channel_stays_silent(tmp_path):
    assert _risk21(_home(tmp_path, {"telegram": {
        "enabled": False, "groups": {"*": {}}}}, _GROUP_KEY)) is None


def test_dm_open_but_groups_allowlisted_stays_silent(tmp_path):
    """The runtime leg is a GROUP-origin session, so DM posture must not arm it — even
    though `_open_channel_labels` (RISK-01's broader question) counts dmPolicy:"open"."""
    assert _risk21(_home(tmp_path, {"telegram": {
        "enabled": True, "dmPolicy": "open",
        "groupPolicy": "allowlist", "groupAllowFrom": ["u1"]}}, _GROUP_KEY)) is None


def test_account_override_to_allowlist_stays_silent(tmp_path):
    """Account merge, per the dist's own mergeAccountConfig: a base groupPolicy:"open"
    overridden per-account is not what any running account resolves to."""
    assert _risk21(_home(tmp_path, {"telegram": {
        "enabled": True, "groupPolicy": "open",
        "accounts": {"a1": {"groupPolicy": "allowlist", "groupAllowFrom": ["u1"]}}}},
        _GROUP_KEY)) is None


def test_channels_defaults_block_is_not_a_provider(tmp_path):
    assert _open_group_channels({"channels": {"defaults": {"groupPolicy": "open"}}}) == {}


def test_open_group_channels_tolerates_junk_shapes():
    for cfg in ({}, {"channels": None}, {"channels": []}, {"channels": {"telegram": None}},
                {"channels": {"telegram": {"accounts": "nope"}}}):
        assert _open_group_channels(cfg) == {}


# --------------------------------------------------------------------------- runtime leg

def test_channel_peer_kind_also_arms_the_chain(tmp_path):
    """":channel:" is the other multi-party origin OpenClaw's own discriminator accepts
    (status-message-CQq9FqoB.js:445), not just ":group:"."""
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD,
                         "agent:main:telegram:channel:synthetic-1")) is not None


def test_account_scoped_group_session_key_arms_the_chain(tmp_path):
    """The four-segment account-scoped delivery shape must parse as a group origin too."""
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD,
                         "agent:main:telegram:acct1:group:synthetic-1")) is not None


def test_dashboard_origin_stays_silent(tmp_path):
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD,
                         "agent:main:dashboard:synthetic-uuid")) is None


def test_main_origin_stays_silent(tmp_path):
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD, "agent:main:main")) is None


def test_unparseable_session_key_stays_silent(tmp_path):
    """An unrecognised key buckets as an honest UNKNOWN and is never armed as ingress."""
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD, "not-a-session-key")) is None


def test_egress_only_group_traffic_stays_silent(tmp_path):
    """The ordinary-traffic guard. A channel-connected agent answers a group message by
    SENDING, so an agent holding an MCP send verb produces an EGRESS-classified call in
    essentially every group session it serves. Arming on EGRESS would fire this chain on
    every group-enabled bot that has ever replied — noise, not signal. Known, documented
    false negative: a group-origin exfil done purely through a send verb."""
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD, _GROUP_KEY,
                         calls=("slack_send_message", "sessions_send", "post_reply"))) is None


def test_destructive_verb_from_a_group_origin_fires(tmp_path):
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD, _GROUP_KEY,
                         calls=("empty_trash",))) is not None


def test_mailbox_config_verb_from_a_group_origin_fires(tmp_path):
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD, _GROUP_KEY,
                         calls=("create_filter",))) is not None


def test_reversible_verbs_from_a_group_origin_stay_silent(tmp_path):
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD, _GROUP_KEY,
                         calls=("web_search", "list_files", "read_file"))) is None


def test_group_origin_on_a_different_channel_than_the_open_one(tmp_path):
    """The join is per-channel: an open group on discord plus a group session on telegram
    is two unrelated facts, not a chain."""
    assert _risk21(_home(tmp_path, {
        "discord": {"enabled": True, "groups": {"*": {}}},
        "telegram": {"enabled": True, "groupPolicy": "allowlist",
                     "groupAllowFrom": ["u1"]}}, _GROUP_KEY)) is None


def test_channel_id_case_is_folded_on_both_sides(tmp_path):
    assert _risk21(_home(tmp_path, {"Telegram": {"enabled": True, "groups": {"*": {}}}},
                         _GROUP_KEY)) is not None


# --------------------------------------------------------- C-135 adversarial pass
# An independent "try to make this fire wrongly" sweep over 15 shapes; the ones that
# could plausibly have gone the other way are pinned here. Zero unexpected results.

def test_cron_origin_stays_silent(tmp_path):
    """A scheduled job that runs bash on a host with an open group channel is the
    coarse join's most obvious false positive — a machine-initiated session is not an
    untrusted sender."""
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD, "agent:main:cron:job1")) is None


def test_subagent_origin_stays_silent(tmp_path):
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD, "agent:main:subagent:worker")) is None


def test_per_group_allow_from_restricts(tmp_path):
    assert _risk21(_home(tmp_path, {"telegram": {
        "enabled": True, "groups": {"*": {"allowFrom": ["u1"]}}}}, _GROUP_KEY)) is None


def test_channel_level_allow_from_restricts(tmp_path):
    assert _risk21(_home(tmp_path, {"telegram": {
        "enabled": True, "groups": {"*": {}}, "allowFrom": ["u1"]}}, _GROUP_KEY)) is None


def test_allow_from_containing_a_wildcard_is_not_a_restriction(tmp_path):
    """OpenClaw's isSenderIdAllowed short-circuits on the wildcard BEFORE consulting the
    sender id, so a '*' among otherwise-narrow entries still admits everyone. A non-empty
    list must not read as a restriction."""
    assert _risk21(_home(tmp_path, {"telegram": {
        "enabled": True, "groups": {"*": {}}, "groupAllowFrom": ["u1", "*"]}},
        _GROUP_KEY)) is not None


def test_disabled_wildcard_group_entry_stays_silent(tmp_path):
    assert _risk21(_home(tmp_path, {"telegram": {
        "enabled": True, "groups": {"*": {"enabled": False}}}}, _GROUP_KEY)) is None


def test_provider_name_cannot_pollute_the_verb_class(tmp_path):
    """`mcp__BashCorp__list_items` is a reversible list, not exec — classification runs
    on the normalized verb so a server name can never decide the class."""
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD, _GROUP_KEY,
                         calls=("mcp__BashCorp__list_items",))) is None


def test_soft_delete_verb_is_not_destructive(tmp_path):
    """A bare delete is a reversible soft-delete in most real APIs; only names that spell
    out irreversibility count. Arming on `delete_*` would manufacture chains."""
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD, _GROUP_KEY,
                         calls=("delete_message",))) is None


def test_feishu_allowall_group_policy_arms_the_static_leg(tmp_path):
    """Feishu's own schema transforms "allowall" -> "open"."""
    assert _risk21(_home(tmp_path, {"feishu": {"enabled": True, "groupPolicy": "allowall"}},
                         "agent:main:feishu:group:g1")) is not None


def test_allowall_on_a_channel_whose_schema_rejects_it_stays_silent(tmp_path):
    """Every non-Feishu channel schema in the dist rejects "allowall" outright, so a
    config carrying it there never loaded — treating it as open would chain on a value
    OpenClaw itself refuses."""
    assert _risk21(_home(tmp_path, {"telegram": {
        "enabled": True, "groupPolicy": "allowall"}}, _GROUP_KEY)) is None


# --------------------------------------------------------------------------- UNKNOWN paths

def test_no_trajectory_at_all_stays_silent(tmp_path):
    """Trajectory absent (or OPENCLAW_TRAJECTORY off) means the runtime leg is UNPROVEN,
    not proven-absent. The rule invents nothing — the static half of this exposure is
    what RISK-01/A1 report unconditionally."""
    assert _risk21(_home(tmp_path, _OPEN_WILDCARD, session_key=None)) is None


def test_empty_home_stays_silent(tmp_path):
    assert _risk21(tmp_path) is None


def test_wrong_schema_version_is_not_proof(tmp_path):
    """A sidecar in an ungrounded format proves nothing — same gate read_proven_tools
    applies. Never guessed at."""
    h = _home(tmp_path, _OPEN_WILDCARD, session_key=None)
    d = h / "agents" / "main" / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    (d / "s1.trajectory.jsonl").write_text(json.dumps({
        "traceSchema": "openclaw-trajectory", "schemaVersion": 99, "type": "tool.call",
        "ts": "t", "seq": 1, "sessionId": "s1", "sessionKey": _GROUP_KEY,
        "data": {"name": "bash"},
    }) + "\n", encoding="utf-8")
    assert _risk21(h) is None


# --------------------------------------------------------------------------- §8 privacy

def test_no_peer_id_or_raw_session_key_reaches_any_output_surface(tmp_path):
    """The sessionKey embeds a real sender id (a Telegram user id is PII). Assembled from
    fragments so no contiguous secret-shaped literal exists in this file."""
    peer = "3076" + "15315"
    key = f"agent:main:telegram:group:{peer}"
    h = _home(tmp_path, _OPEN_WILDCARD, key)
    ctx, findings, _ = audit(h, include_native=False, include_host=False)
    paths = risk_paths(ctx, findings)
    p = next(x for x in paths if x.id == "RISK-21")
    blob = " ".join([p.title, p.why, p.fix, *p.chain,
                     render_risk_paths(paths), render_risk_paths(paths, ascii_only=True)])
    assert peer not in blob
    assert key not in blob
    assert "telegram" in blob  # the channel id itself is not PII and IS reported


def test_read_proven_tools_by_origin_never_returns_a_peer_id(tmp_path):
    from clawseccheck.trajectory import read_proven_tools_by_origin

    peer = "3076" + "15315"
    _sidecar(tmp_path, "s1", f"agent:main:telegram:group:{peer}", ["bash"])
    by_origin, _ = read_proven_tools_by_origin(tmp_path)
    assert by_origin == {("group", "telegram"): {"bash"}}
    assert peer not in json.dumps({str(k): sorted(v) for k, v in by_origin.items()})


# --------------------------------------------------------------------------- grade contract

def test_risk21_does_not_move_the_grade(tmp_path):
    """Owner ruling (2026-07-20): only an ARGUMENTS-corroborated runtime signal may ever
    affect the A-F grade, and only as a cap. RISK-21 is metadata-only (a verb name and a
    session-key origin kind), so it must not. This is structural — cli.py computes the
    score BEFORE calling risk_paths, and scoring.py does not import risk — but assert it
    end-to-end rather than trust the layering.

    The ablation varies exactly ONE thing: the origin segment of the session key, which
    nothing but RISK-21 reads. Comparing "sidecar present" against "sidecar absent"
    instead would prove nothing, because four unrelated scored checks (B19/B84/B85/B164)
    legitimately move from UNKNOWN once a trajectory exists at all — a real 85 -> 84
    delta that predates this rule and has nothing to do with it."""
    fires = _home(tmp_path / "a", _OPEN_WILDCARD, _GROUP_KEY)
    silent = _home(tmp_path / "b", _OPEN_WILDCARD,
                   "agent:main:telegram:direct:synthetic-owner-1")

    _, f_fires, s_fires = audit(fires, include_native=False, include_host=False)
    _, f_silent, s_silent = audit(silent, include_native=False, include_host=False)

    assert _risk21(fires) is not None and _risk21(silent) is None
    assert (s_fires.grade, s_fires.score) == (s_silent.grade, s_silent.score)
    assert ({f.id: f.status for f in f_fires} == {f.id: f.status for f in f_silent})
    assert not [f for f in f_fires if f.id == "RISK-21"], (
        "a RISK chain must never materialise as a scored Finding"
    )


def test_scoring_does_not_import_the_risk_engine():
    """The structural half of the grade contract: no import edge exists for a chain to
    reach the score through, in either direction."""
    import clawseccheck.scoring as scoring

    src = Path(scoring.__file__).read_text(encoding="utf-8")
    assert "import risk" not in src and "from .risk" not in src


def test_risk21_is_not_a_catalog_check():
    """RISK-* chains are derived advisories, not catalogued checks — they carry no
    CheckMeta and so cannot be scored, suppressed as a check, or counted in the badge."""
    from clawseccheck.catalog import BY_ID

    assert "RISK-21" not in BY_ID


def test_risk21_honours_the_ignore_file(tmp_path):
    """B-154: an explicitly-listed RISK id is marked suppressed, not dropped."""
    h = _home(tmp_path, _OPEN_WILDCARD, _GROUP_KEY)
    ctx, findings, _ = audit(h, include_native=False, include_host=False)
    p = next(x for x in risk_paths(ctx, findings, ignore={"RISK-21"})
             if x.id == "RISK-21")
    assert p.suppressed is True


# --------------------------------------------------------------------------- refactor guard

def test_flat_proven_set_is_the_union_of_the_origin_buckets(tmp_path):
    """`read_proven_tools` is now derived from `read_proven_tools_by_origin` rather than
    being a second copy of the same scan loop. Its existing callers (B84, T3) must see
    exactly what they saw before, which is what "union" has to mean."""
    from clawseccheck.trajectory import read_proven_tools, read_proven_tools_by_origin

    _sidecar(tmp_path, "s1", "agent:main:telegram:group:g1", ["bash", "web_search"])
    _sidecar(tmp_path, "s2", "agent:main:telegram:direct:owner", ["apply_patch", "bash"])
    _sidecar(tmp_path, "s3", "not-a-key", ["memory_search"])

    verbs, meta = read_proven_tools(tmp_path)
    by_origin, meta2 = read_proven_tools_by_origin(tmp_path)

    assert verbs == {"bash", "web_search", "apply_patch", "memory_search"}
    assert verbs == set().union(*by_origin.values())
    assert meta == meta2
    assert by_origin[(None, None)] == {"memory_search"}
