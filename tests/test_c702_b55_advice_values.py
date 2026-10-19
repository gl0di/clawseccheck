"""C-702 -- B55's advice names only policy values the installed OpenClaw accepts.

B55's fix used to say "Lock the channel(s) to 'owner'". ``owner`` is not a ``dmPolicy`` or
``groupPolicy`` value: ``openclaw config validate`` rejects it (exit 1), so a user who followed
the advice wrote a config OpenClaw then refuses. Two layers, ranked by what they know:

* **Live, local-only** -- executes the REAL ``openclaw config validate`` over a throwaway
  config for every shape the advice can print, and over the rejected values as a control
  (a validation that cannot fail would prove nothing). Skipped wherever ``openclaw`` is not
  on the PATH; that is the only stand-down.
* **Offline, CI** -- the advice text, taken from the real finding, names only values in the
  pinned sets below (measured with the live layer on OpenClaw 2026.10.2). The extractor is
  itself checked against the OLD advice, so the guard is proven able to fail.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from clawseccheck.catalog import WARN
from clawseccheck.checks import check_fs_write_exposure
from clawseccheck.collector import collect

#: ``channels.telegram.dmPolicy`` / ``.groupPolicy`` value sets, as the installed
#: ``openclaw config validate`` printed them on OpenClaw 2026.10.2. Re-measure and re-pin if the
#: live test below reports a different set.
_DM_VALUES = {"pairing", "allowlist", "open", "disabled"}
_GROUP_VALUES = {"open", "disabled", "allowlist"}

#: What B55's old fix told users to write.
_OLD_ADVICE = (
    "Lock the channel(s) to 'owner' (or 'disabled'); tools.exec.mode='ask' alone does not "
    "clear this -- it doesn't scope write-capable tools."
)


def _quoted_policy_values(text: str) -> list:
    """Every single-quoted lowercase word that is not the right-hand side of ``=`` (which is
    ``tools.exec.mode='ask'``, a different setting)."""
    return re.findall(r"(?<!=)'([a-z][a-z-]*)'", text)


def _b55_fix(tmp_path: Path) -> str:
    """The fix B55 prints for a declared, not-open, untrusted-content channel under an
    approval gate (the WARN branch the advice sits in)."""
    (tmp_path / "openclaw.json").write_text(
        '{"tools": {"profile": "full", "exec": {"mode": "ask"}},'
        ' "channels": {"telegram": {"enabled": true, "dmPolicy": "allowlist",'
        ' "groupPolicy": "allowlist"}}}',
        encoding="utf-8",
    )
    finding = check_fs_write_exposure(collect(tmp_path))
    assert finding.status == WARN, finding.detail
    return finding.fix


# ------------------------------------------------------------------------ offline (CI)
def test_the_advice_names_only_values_both_policies_accept(tmp_path):
    fix = _b55_fix(tmp_path)
    values = _quoted_policy_values(fix)
    assert values, f"the extractor found no policy value in the advice: {fix!r}"
    assert set(values) <= _DM_VALUES & _GROUP_VALUES, (
        f"B55 advises {sorted(set(values) - (_DM_VALUES & _GROUP_VALUES))}, which "
        f"dmPolicy/groupPolicy do not both accept on OpenClaw 2026.10.2: {fix!r}"
    )
    assert "owner" not in fix


def test_the_advice_names_the_fields_a_user_must_edit(tmp_path):
    fix = _b55_fix(tmp_path)
    for field in ("dmPolicy", "allowFrom", "groupPolicy", "groupAllowFrom"):
        assert field in fix, f"{field} missing from the advice: {fix!r}"


def test_the_advice_does_not_demand_fields_some_channels_lack(tmp_path):
    """Discord and Slack have a groupPolicy but no groupAllowFrom, and several providers have
    no flat dmPolicy or groupPolicy at all (measured by the live schema test below), so each
    field is advised conditionally."""
    fix = _b55_fix(tmp_path)
    for hedge in ("where the channel has a dmPolicy", "where it has a groupPolicy",
                  "on channels that have that field"):
        assert hedge in fix, f"missing hedge {hedge!r}: {fix!r}"


def test_the_guard_is_able_to_fail_on_the_old_advice():
    """Positive control: the same extractor and the same acceptance rule reject the text
    this task replaced."""
    values = _quoted_policy_values(_OLD_ADVICE)
    assert "owner" in values
    assert not set(values) <= _DM_VALUES & _GROUP_VALUES


# ------------------------------------------------------------------------ live (local-only)
_OPENCLAW = shutil.which("openclaw")
live = pytest.mark.skipif(_OPENCLAW is None, reason="openclaw is not on the PATH")


def _validate(tmp_path: Path, channel: dict):
    """``openclaw config validate`` over a throwaway home; returns (exit code, output)."""
    home = tmp_path / "oc-home"
    home.mkdir(exist_ok=True)
    cfg = home / "openclaw.json"
    cfg.write_text(
        json.dumps({"channels": {"telegram": {"enabled": False, **channel}}}), encoding="utf-8"
    )
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "OPENCLAW_HOME": str(home),
        "OPENCLAW_STATE_DIR": str(home),
        "OPENCLAW_CONFIG_PATH": str(cfg),
    }
    proc = subprocess.run(
        [_OPENCLAW, "config", "validate"],
        cwd=str(home), env=env, capture_output=True, text=True, timeout=120,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _allowed_values(output: str) -> set:
    match = re.search(r"allowed: ((?:\"[a-z]+\"(?:, )?)+)", output)
    assert match, f"no 'allowed:' list in the validator output: {output!r}"
    return set(re.findall(r'"([a-z]+)"', match.group(1)))


_ADVISED_SHAPES = [
    pytest.param(
        {"dmPolicy": "allowlist", "allowFrom": ["123456789"],
         "groupPolicy": "allowlist", "groupAllowFrom": ["123456789"]},
        id="allowlist-with-owner-ids",
    ),
    pytest.param({"dmPolicy": "disabled"}, id="dm-disabled"),
    pytest.param({"groupPolicy": "disabled"}, id="group-disabled"),
]


@live
@pytest.mark.parametrize("channel", _ADVISED_SHAPES)
def test_every_advised_shape_validates_on_the_installed_openclaw(tmp_path, channel):
    code, output = _validate(tmp_path, channel)
    assert code == 0, output


@live
@pytest.mark.parametrize("field,pinned", [("dmPolicy", _DM_VALUES), ("groupPolicy", _GROUP_VALUES)])
def test_owner_is_rejected_and_the_accepted_set_is_the_pinned_one(tmp_path, field, pinned):
    """The control: the old advice's value fails validation, and the validator's own list of
    accepted values is the one pinned above (a new value or a removed one turns this red)."""
    code, output = _validate(tmp_path, {field: "owner"})
    assert code != 0, output
    assert _allowed_values(output) == pinned, output


def _channel_schema() -> dict:
    """``channels.<provider>`` property maps from the installed ``openclaw config schema``,
    with ``$ref`` resolved one level per property."""
    proc = subprocess.run([_OPENCLAW, "config", "schema"], capture_output=True, text=True,
                          timeout=180, env={"PATH": os.environ.get("PATH", "")})
    assert proc.returncode == 0, proc.stderr
    schema = json.loads(proc.stdout)
    defs = schema.get("$defs") or schema.get("definitions") or {}

    def resolve(node):
        for _ in range(6):
            if isinstance(node, dict) and "$ref" in node:
                node = defs.get(node["$ref"].split("/")[-1], {})
        return node

    def enum_of(node):
        node = resolve(node)
        if not isinstance(node, dict):
            return set()
        if "enum" in node:
            return set(node["enum"])
        if "const" in node:
            return {node["const"]}
        values = set()
        for key in ("anyOf", "oneOf"):
            for member in node.get(key, []):
                values |= enum_of(member)
        return values

    out = {}
    channels = schema["properties"]["channels"]["properties"]
    for provider, node in channels.items():
        if provider in ("defaults", "modelByChannel"):
            continue
        props = (resolve(node) or {}).get("properties", {})
        out[provider] = {"fields": set(props),
                         "dm": enum_of(props.get("dmPolicy", {})),
                         "group": enum_of(props.get("groupPolicy", {}))}
    return out


# C-744: the X channel (new in 2026.10.5) has no direct messages at all: its `dmPolicy` is the
# single constant "disabled" (measured on the installed root JSON schema, `channels.x.dmPolicy`
# and `channels.x.accounts.<key>.dmPolicy` are `{type: string, const: "disabled"}`). The advised
# value "disabled" is accepted; "allowlist" is not a thing to advise there, and a DM-less
# channel has no direct-message ingress for the advice to narrow.
_DM_DISABLED_ONLY = {"x"}


@live
def test_every_provider_that_has_the_policy_accepts_the_advised_values():
    """The whole channel x policy matrix of the installed build: wherever a provider has a
    dmPolicy / groupPolicy, both 'allowlist' and 'disabled' are accepted values."""
    matrix = _channel_schema()
    with_dm = [p for p, v in matrix.items() if "dmPolicy" in v["fields"]]
    with_group = [p for p, v in matrix.items() if "groupPolicy" in v["fields"]]
    assert len(with_dm) >= 10 and len(with_group) >= 10, (with_dm, with_group)  # not vacuous
    for provider in with_dm:
        if provider in _DM_DISABLED_ONLY:
            assert matrix[provider]["dm"] == {"disabled"}, (provider, matrix[provider]["dm"])
            continue
        assert {"allowlist", "disabled"} <= matrix[provider]["dm"], (provider, matrix[provider]["dm"])
    for provider in with_group:
        assert {"allowlist", "disabled"} <= matrix[provider]["group"], (provider, matrix[provider]["group"])


@live
def test_some_providers_lack_the_fields_so_the_advice_must_stay_conditional():
    """If this turns red (every provider now has all four fields) the hedges in the advice
    can be dropped; until then dropping them would tell Discord/Slack users to write a field
    their schema rejects."""
    matrix = _channel_schema()
    no_group_allow = [p for p, v in matrix.items()
                      if "groupPolicy" in v["fields"] and "groupAllowFrom" not in v["fields"]]
    no_flat_dm = [p for p, v in matrix.items() if "dmPolicy" not in v["fields"]]
    assert no_group_allow, "every provider with a groupPolicy now has groupAllowFrom"
    assert no_flat_dm, "every provider now has a flat dmPolicy"


@live
def test_the_validator_rejects_an_unknown_field(tmp_path):
    """Control for the advice's field names: a misspelt one fails, so exit 0 above means the
    names exist."""
    code, output = _validate(tmp_path, {"groupAllowFromX": ["1"]})
    assert code != 0, output
