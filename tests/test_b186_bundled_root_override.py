"""B186 (B-289, ENV-3) — bundled skills/hooks code-load root relocated by an env override.

OpenClaw honours OPENCLAW_BUNDLED_SKILLS_DIR and OPENCLAW_BUNDLED_HOOKS_DIR
unconditionally, ahead of every legitimate resolution path
(bundled-dir-BQFrcRIS.js:22-24, workspace-zj1TEEka.js:54-56), so either variable points
the agent at code of the setter's choosing without needing any write to the npm-owned
install tree.

BEFORE this check existed, a relocation was completely invisible: a repo-wide grep for
OPENCLAW_BUNDLED* returned zero hits, and collector.SKILL_TIER_ORDER omits the bundled
tier entirely — this is an unenumerated load root, not a stale snapshot.

Offline, read-only, stdlib only. Nothing is written outside tmp_path.
"""
from __future__ import annotations

import os
from pathlib import Path

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_bundled_root_override
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

SKILLS_VAR = "OPENCLAW_BUNDLED_SKILLS_DIR"
HOOKS_VAR = "OPENCLAW_BUNDLED_HOOKS_DIR"
PLUGINS_VAR = "OPENCLAW_BUNDLED_PLUGINS_DIR"


def _home(root: Path, *, unit_lines: str = "", dotenv: str = "", units: bool = True) -> Path:
    """A synthetic OpenClaw home whose parent carries .config/systemd/user."""
    home = root / ".openclaw"
    home.mkdir(exist_ok=True)
    (home / "openclaw.json").write_text("{}", encoding="utf-8")
    if units:
        unit_dir = root / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        (unit_dir / "openclaw-gateway.service").write_text(
            "[Unit]\nDescription=OpenClaw Gateway\n\n"
            "[Service]\nExecStart=/usr/bin/openclaw gateway run\nRestart=always\n"
            + unit_lines
            + "\n[Install]\nWantedBy=default.target\n",
            encoding="utf-8",
        )
    if dotenv:
        (home / ".env").write_text(dotenv + "\n", encoding="utf-8")
    return home


# ---------------------------------------------------------------------------
# C-262: the clean paths — a reduced-confidence PASS when a persistent artifact was
# actually read, UNKNOWN only when nothing persistent was even present to read.
# ---------------------------------------------------------------------------

def test_no_override_with_readable_env_is_reduced_confidence_pass(tmp_path):
    """No override, but a real OpenClaw unit WAS read: PASS, never full confidence.

    C-262 (round 2): round 1 made every "found nothing" outcome UNKNOWN forever, even
    when a persistent artifact genuinely was read and genuinely carries no override.
    That made B186 a permanent, unclearable UNKNOWN on every clean host. The ambient-shell
    channel (a variable exported into the shell that launches the agent, never touching
    disk) is still unobservable — which is why this can never claim full confidence — but
    "we read what we could and it is clean" is worth more than an unconditional UNKNOWN,
    so it is PASS with pass_confidence="no_signal": the same idiom B191 (this module) and
    B168 (checks/_lifecycle.py) already use for "looked, found nothing, view incomplete."
    """
    f = check_bundled_root_override(collect(_home(tmp_path)))
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"
    assert f.pass_confidence != "verified"
    # The residual must be stated, not implied.
    assert "shell" in f.detail.lower()


def test_no_units_and_no_dotenv_is_unknown_not_pass(tmp_path):
    """Nothing persistent was even present to read: stays UNKNOWN, not a bare-evidence PASS."""
    f = check_bundled_root_override(collect(_home(tmp_path, units=False)))
    assert f.status == UNKNOWN
    assert f.status != "PASS"


def test_clean_fixture_with_ordinary_unit_env_is_reduced_confidence_pass():
    """A real-shaped unit carrying several OPENCLAW_* vars, none of them a relocation."""
    home = FIXTURES / "clean_b186_no_bundled_override" / "openclaw_home"
    f = check_bundled_root_override(collect(home))
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"


def test_empty_override_value_is_not_an_override(tmp_path):
    """`process.env.X?.trim()` falsy means the dist falls through to normal resolution.

    An empty assignment is not a relocation and must not be reported as one; since the
    unit carrying it WAS read, this reaches the reduced-confidence PASS, not UNKNOWN.
    """
    f = check_bundled_root_override(
        collect(_home(tmp_path, unit_lines=f"Environment={SKILLS_VAR}=\n"))
    )
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"


# ---------------------------------------------------------------------------
# The bad paths, one per delivery channel
# ---------------------------------------------------------------------------

def test_unit_borne_skills_relocation_warns(tmp_path):
    target = tmp_path / "relocated"
    target.mkdir()
    f = check_bundled_root_override(
        collect(_home(tmp_path, unit_lines=f"Environment={SKILLS_VAR}={target}\n"))
    )
    assert f.status == WARN
    joined = " ".join(f.evidence)
    assert SKILLS_VAR in joined
    assert str(target) in joined
    assert "openclaw-gateway.service" in joined


def test_unit_borne_hooks_relocation_warns(tmp_path):
    target = tmp_path / "relocated-hooks"
    target.mkdir()
    f = check_bundled_root_override(
        collect(_home(tmp_path, unit_lines=f"Environment={HOOKS_VAR}={target}\n"))
    )
    assert f.status == WARN
    assert HOOKS_VAR in " ".join(f.evidence)


def test_quoted_and_multi_assignment_unit_line_is_parsed(tmp_path):
    """systemd allows several space-separated assignments per line, each optionally quoted.

    The real unit on a stock install uses exactly that shape
    (`Environment="OPENCLAW_WINDOWS_TASK_NAME=OpenClaw Gateway"`), so a parser that only
    handled the bare form would miss a relocation hidden beside a benign assignment.
    """
    target = tmp_path / "relocated"
    target.mkdir()
    line = f'Environment="OPENCLAW_WINDOWS_TASK_NAME=OpenClaw Gateway" {SKILLS_VAR}={target}\n'
    f = check_bundled_root_override(collect(_home(tmp_path, unit_lines=line)))
    assert f.status == WARN
    assert str(target) in " ".join(f.evidence)


def test_home_dotenv_borne_relocation_warns(tmp_path):
    target = tmp_path / "relocated"
    target.mkdir()
    f = check_bundled_root_override(
        collect(_home(tmp_path, dotenv=f"{SKILLS_VAR}={target}"))
    )
    assert f.status == WARN
    assert ".env" in " ".join(f.evidence)


def test_gateway_env_borne_relocation_warns(tmp_path):
    """The second global runtime dotenv file, ~/.config/openclaw/gateway.env."""
    target = tmp_path / "relocated"
    target.mkdir()
    gw = tmp_path / ".config" / "openclaw"
    gw.mkdir(parents=True)
    (gw / "gateway.env").write_text(f"{SKILLS_VAR}={target}\n", encoding="utf-8")
    f = check_bundled_root_override(collect(_home(tmp_path)))
    assert f.status == WARN
    assert "gateway.env" in " ".join(f.evidence)


def test_environment_file_borne_relocation_warns(tmp_path):
    """EnvironmentFile= is a real delivery channel and must be followed like Environment=."""
    target = tmp_path / "relocated"
    target.mkdir()
    envfile = tmp_path / "gateway-extra.env"
    envfile.write_text(f"{SKILLS_VAR}={target}\n", encoding="utf-8")
    f = check_bundled_root_override(
        collect(_home(tmp_path, unit_lines=f"EnvironmentFile=-{envfile}\n"))
    )
    assert f.status == WARN
    assert "gateway-extra.env" in " ".join(f.evidence)


def test_bad_fixture_unit_relocation_warns():
    home = FIXTURES / "bad_b186_bundled_skills_relocated" / "openclaw_home"
    f = check_bundled_root_override(collect(home))
    assert f.status == WARN
    joined = " ".join(f.evidence)
    assert SKILLS_VAR in joined and HOOKS_VAR in joined


def test_bad_fixture_dotenv_relocation_warns():
    home = FIXTURES / "bad_b186_bundled_dotenv" / "openclaw_home"
    f = check_bundled_root_override(collect(home))
    assert f.status == WARN
    assert SKILLS_VAR in " ".join(f.evidence)


# ---------------------------------------------------------------------------
# The escalation, and the two rules that were deliberately NOT implemented
# ---------------------------------------------------------------------------

def test_world_writable_target_fails(tmp_path):
    """The one escalation: another local account can replace the code the agent runs."""
    target = tmp_path / "relocated"
    target.mkdir()
    os.chmod(target, 0o777)
    f = check_bundled_root_override(
        collect(_home(tmp_path, unit_lines=f"Environment={SKILLS_VAR}={target}\n"))
    )
    assert f.status == FAIL
    assert "world-writable" in " ".join(f.evidence)


def test_private_directory_inside_tmp_is_not_escalated(tmp_path):
    """"The target is under /tmp" is NOT the signal — the privilege is.

    The originating task proposed escalating on a /tmp-rooted target. That was retracted:
    a 0700 directory inside /tmp is exactly as private as one in the user's home, so the
    location is a path string, not a privilege. This test pins the retraction so nobody
    reintroduces a location heuristic.
    """
    target = tmp_path / "relocated"
    target.mkdir()
    os.chmod(target, 0o700)
    f = check_bundled_root_override(
        collect(_home(tmp_path, unit_lines=f"Environment={SKILLS_VAR}={target}\n"))
    )
    assert f.status == WARN


def test_node_modules_openclaw_path_is_not_a_downgrade(tmp_path):
    """A `node_modules/openclaw` path segment must NOT quiet the finding.

    The originating task proposed treating "resolves inside the openclaw package root" as
    informational. That was retracted: the only hermetic proxy for the package root is a
    path segment, and the path is chosen by whoever set the variable — downgrading on it
    would key the verdict on attacker-controlled input.
    """
    target = tmp_path / "node_modules" / "openclaw" / "skills"
    target.mkdir(parents=True)
    f = check_bundled_root_override(
        collect(_home(tmp_path, unit_lines=f"Environment={SKILLS_VAR}={target}\n"))
    )
    assert f.status == WARN


# ---------------------------------------------------------------------------
# The regression guard that matters most
# ---------------------------------------------------------------------------

def test_plugins_variable_never_fires(tmp_path):
    """OPENCLAW_BUNDLED_PLUGINS_DIR must never be flagged — OpenClaw hardened that one.

    resolveBundledPluginsDirUncached (bundled-dir-DKbeVv7V.js:124-134) puts the override
    through resolveTrustedExistingOverride (:77-85), which requires the realpath to be
    pathContains-ed by a trusted bundled-plugin root under the package root AND to pass
    hasUsableBundledPluginTree; the only bypass (:32-34) requires VITEST.
    `OPENCLAW_BUNDLED_PLUGINS_DIR=/tmp/evil` is REJECTED by the product, so reporting it
    would be a false positive — and the product's own internals set it deliberately
    (bundled-ClxzUaje.js:145). Do not "widen" the check to cover it.
    """
    target = tmp_path / "relocated"
    target.mkdir()
    os.chmod(target, 0o777)
    f = check_bundled_root_override(
        collect(_home(tmp_path, unit_lines=f"Environment={PLUGINS_VAR}={target}\n"))
    )
    # PLUGINS_VAR is ignored, so `overrides` is empty; the unit WAS read (it carries the
    # ignored var), so this reaches the reduced-confidence PASS, not a bare-evidence UNKNOWN.
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"


def test_plugins_variable_fixture_is_clean():
    home = FIXTURES / "clean_b186_plugins_var_ignored" / "openclaw_home"
    f = check_bundled_root_override(collect(home))
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"


def test_non_openclaw_unit_is_not_read(tmp_path):
    """A relocation in someone else's unit is not this agent's environment.

    That unit is NOT OpenClaw-related, so it never sets unit_env_found; combined with
    units=False (no OpenClaw unit either) and no dotenv, env_evidence_readable is False —
    nothing persistent was read, so this stays UNKNOWN, not a bare-evidence PASS.
    """
    target = tmp_path / "relocated"
    target.mkdir()
    unit_dir = tmp_path / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True)
    (unit_dir / "some-other-app.service").write_text(
        "[Service]\nExecStart=/usr/bin/some-other-app\n"
        f"Environment={SKILLS_VAR}={target}\n",
        encoding="utf-8",
    )
    f = check_bundled_root_override(collect(_home(tmp_path, units=False)))
    assert f.status == UNKNOWN


# ---------------------------------------------------------------------------
# The relocated skills root reaches the ordinary content scanners
# ---------------------------------------------------------------------------

def test_relocated_skills_root_is_handed_to_the_skill_scanners(tmp_path):
    """A relocated SKILLS root is a real auto-load root, so its skills must be collected.

    The point of the fix is not only to disclose the relocation but to stop the relocated
    skills from being invisible — they go through the SAME collector path as every other
    tier rather than a second engine.
    """
    target = tmp_path / "relocated"
    (target / "planted").mkdir(parents=True)
    (target / "planted" / "SKILL.md").write_text(
        "---\nname: planted\ndescription: a skill nobody enumerated\n---\n\nbody\n",
        encoding="utf-8",
    )
    ctx = collect(_home(tmp_path, unit_lines=f"Environment={SKILLS_VAR}={target}\n"))
    assert "planted" in ctx.installed_skills


def test_hooks_root_is_not_treated_as_a_skill_root(tmp_path):
    """A hooks root holds hook modules, not SKILL.md directories — disclosure only.

    Feeding it to the skill scanners would be claiming a capability we do not have.
    """
    target = tmp_path / "relocated-hooks"
    (target / "planted").mkdir(parents=True)
    (target / "planted" / "SKILL.md").write_text(
        "---\nname: planted\ndescription: x\n---\n\nbody\n", encoding="utf-8"
    )
    ctx = collect(_home(tmp_path, unit_lines=f"Environment={HOOKS_VAR}={target}\n"))
    assert "planted" not in ctx.installed_skills
    assert check_bundled_root_override(ctx).status == WARN


# ---------------------------------------------------------------------------
# B-311: the reported path is the LITERAL override value — no expanduser().
#
# systemd's Environment=/EnvironmentFile= parsing is not a shell (no `~` expansion), and
# the dist reads the value verbatim: resolveBundledSkillsDir / resolveBundledHooksDir both
# do `process.env.X?.trim(); if (override) return override;` (bundled-dir-BQFrcRIS.js:
# 22-24, workspace-zj1TEEka.js:54-56) — no expansion, no existence check. A `~`-prefixed
# override is therefore resolved by OpenClaw relative to the launching process's OWN cwd,
# never to $HOME. Reporting an expanduser()'d path here names a directory OpenClaw never
# actually loads from.
# ---------------------------------------------------------------------------

def test_tilde_override_is_reported_literally_not_expanded(tmp_path):
    """A `~`-prefixed override must be reported verbatim, not expanded to $HOME."""
    f = check_bundled_root_override(
        collect(_home(tmp_path, unit_lines=f"Environment={SKILLS_VAR}=~/foo\n"))
    )
    assert f.status == WARN
    joined = " ".join(f.evidence)
    assert "~/foo" in joined
    # The auditor's own expanded home directory must NOT appear — that would be reporting
    # a path OpenClaw itself never resolves to.
    assert str(Path.home()) not in joined


def test_absolute_path_override_is_unaffected_by_the_b311_fix(tmp_path):
    """An absolute-path override (the common case) is reported exactly as before."""
    target = tmp_path / "relocated"
    target.mkdir()
    f = check_bundled_root_override(
        collect(_home(tmp_path, unit_lines=f"Environment={SKILLS_VAR}={target}\n"))
    )
    assert f.status == WARN
    assert str(target) in " ".join(f.evidence)


def test_tilde_override_scan_coverage_is_at_least_as_wide_as_before(tmp_path):
    """The SCAN still runs against the literal value — only the printed path changed.

    Constructing `Path("~/foo")` and stat()-ing it does not expand `~` either, so a
    relatively-rooted override is still evaluated for the world-writable escalation; this
    pins that the B-311 fix does not narrow detection, only corrects what gets displayed.
    """
    home = _home(tmp_path, unit_lines=f"Environment={SKILLS_VAR}=~/foo\n")
    ctx = collect(home)
    f = check_bundled_root_override(ctx)
    # A non-existent relative/tilde target cannot be proven world-writable (stat() fails,
    # _dir_replaceable_by_others returns None) — same as it would for any other
    # non-existent path pre- or post-fix. The important invariant is that this is still
    # WARN (an override IS observed), not silently dropped to UNKNOWN.
    assert f.status == WARN


# ---------------------------------------------------------------------------
# Catalog wiring
# ---------------------------------------------------------------------------

def test_b186_is_catalogued_and_unscored():
    meta = BY_ID["B186"]
    assert meta.severity == "HIGH"
    # Deliberately out of the score (C-262): the near-universal state is a reduced-
    # confidence PASS or UNKNOWN, and the state that occurs benignly is WARN (a
    # source-checkout developer). Scoring it would dock a setup that is working as its
    # owner intended.
    assert meta.scored is False
