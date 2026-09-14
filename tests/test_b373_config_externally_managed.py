"""B373 (CLAWSECCHECK-C-527) — externally-managed, read-only config posture.

New in OpenClaw 2026.9.4. Grounded against the LIVE installed 9.4 dist:

    paths-V8kKIUzt.mjs:60-67
        function resolveIsNixMode(env = process.env) {
            return env.OPENCLAW_NIX_MODE === "1";
        }
        function resolveIsConfigReadOnly(env = process.env) {
            return env.OPENCLAW_CONFIG_READONLY === "1" || resolveIsNixMode(env);
        }

Only the exact string "1" enables either mode, and Nix mode implies read-only too. This
check is disclosure-only by construction: an externally-managed config is a deliberate
hardening posture (Nix, a container/K8s-managed deployment), not a risk, so it can only
ever report PASS or UNKNOWN — never WARN/FAIL (Golden Rule #5).

Detection reuses the same persistent, on-disk evidence channel as B41/B186
(``persistent_env_evidence`` — an OpenClaw-related systemd unit's Environment=/
EnvironmentFile=, then the two global runtime dotenv files) and deliberately never
``os.environ``, which is the auditing shell's environment, not the audited gateway
process's.

Offline, read-only, stdlib only. Nothing is written outside tmp_path.
"""
from __future__ import annotations

from pathlib import Path

from clawseccheck.catalog import BY_ID, FAIL, PASS, UNKNOWN, WARN
from clawseccheck.checks import check_config_externally_managed
from clawseccheck.collector import collect

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

READONLY_VAR = "OPENCLAW_CONFIG_READONLY"
NIX_VAR = "OPENCLAW_NIX_MODE"


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
# The clean/neutral paths — absence of the mode is the default, never adverse.
# ---------------------------------------------------------------------------

def test_no_mode_with_readable_evidence_is_reduced_confidence_pass(tmp_path):
    """No override observed, but a real unit WAS read: PASS, never full confidence.

    Same idiom as B186's C-262 split: the ambient-shell delivery channel (an export in
    the interactive shell that launches the agent) leaves nothing on disk for any
    persistent, read-only scan to see, however complete the read is — so this can never
    claim full confidence when absent.
    """
    f = check_config_externally_managed(collect(_home(tmp_path)))
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"
    assert f.pass_confidence != "verified"
    # The residual must be stated, not implied (same rule B186 pins).
    assert "shell" in f.detail.lower()


def test_no_units_and_no_dotenv_is_unknown_not_pass(tmp_path):
    """Nothing persistent was even present to read: stays UNKNOWN, not a bare-evidence PASS."""
    f = check_config_externally_managed(collect(_home(tmp_path, units=False)))
    assert f.status == UNKNOWN


def test_clean_fixture_no_readonly_mode_is_reduced_confidence_pass():
    home = FIXTURES / "clean_b373_no_readonly_mode" / "openclaw_home"
    f = check_config_externally_managed(collect(home))
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"


def test_unknown_fixture_no_persistent_evidence_is_unknown():
    home = FIXTURES / "unknown_b373_no_persistent_evidence" / "openclaw_home"
    f = check_config_externally_managed(collect(home))
    assert f.status == UNKNOWN


def test_empty_value_is_not_an_active_mode(tmp_path):
    """An empty ``Environment=OPENCLAW_CONFIG_READONLY=`` assignment must not read as active."""
    f = check_config_externally_managed(
        collect(_home(tmp_path, unit_lines=f"Environment={READONLY_VAR}=\n"))
    )
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"


def test_non_exact_value_is_not_an_active_mode(tmp_path):
    """The vendor resolver is a STRICT `=== "1"` check — "true"/"yes" do not enable it.

    A check that treated any truthy-looking string as active would report a mode that is
    not actually in effect on the real gateway process.
    """
    f = check_config_externally_managed(
        collect(_home(tmp_path, unit_lines=f"Environment={READONLY_VAR}=true\n"))
    )
    assert f.status == PASS
    assert f.pass_confidence == "no_signal"


# ---------------------------------------------------------------------------
# The detected paths — one per variable, one per delivery channel.
# ---------------------------------------------------------------------------

def test_unit_borne_readonly_mode_is_pass_with_evidence(tmp_path):
    f = check_config_externally_managed(
        collect(_home(tmp_path, unit_lines=f"Environment={READONLY_VAR}=1\n"))
    )
    assert f.status == PASS
    assert f.pass_confidence is None
    joined = " ".join(f.evidence)
    assert READONLY_VAR in joined
    assert "openclaw-gateway.service" in joined


def test_unit_borne_nix_mode_is_pass_with_evidence(tmp_path):
    """OPENCLAW_NIX_MODE=1 also counts — it implies config-read-only in the resolver."""
    f = check_config_externally_managed(
        collect(_home(tmp_path, unit_lines=f"Environment={NIX_VAR}=1\n"))
    )
    assert f.status == PASS
    assert f.pass_confidence is None
    assert NIX_VAR in " ".join(f.evidence)


def test_dotenv_borne_readonly_mode_is_pass_with_evidence(tmp_path):
    f = check_config_externally_managed(
        collect(_home(tmp_path, dotenv=f"{READONLY_VAR}=1"))
    )
    assert f.status == PASS
    assert ".env" in " ".join(f.evidence)


def test_gateway_env_borne_readonly_mode_is_pass_with_evidence(tmp_path):
    """The second global runtime dotenv file, ~/.config/openclaw/gateway.env."""
    gw = tmp_path / ".config" / "openclaw"
    gw.mkdir(parents=True)
    (gw / "gateway.env").write_text(f"{READONLY_VAR}=1\n", encoding="utf-8")
    f = check_config_externally_managed(collect(_home(tmp_path)))
    assert f.status == PASS
    assert "gateway.env" in " ".join(f.evidence)


def test_environment_file_borne_readonly_mode_is_pass_with_evidence(tmp_path):
    """EnvironmentFile= is a real delivery channel and must be followed like Environment=."""
    envfile = tmp_path / "gateway-extra.env"
    envfile.write_text(f"{READONLY_VAR}=1\n", encoding="utf-8")
    f = check_config_externally_managed(
        collect(_home(tmp_path, unit_lines=f"EnvironmentFile=-{envfile}\n"))
    )
    assert f.status == PASS
    assert "gateway-extra.env" in " ".join(f.evidence)


def test_both_vars_active_reports_both_in_evidence(tmp_path):
    f = check_config_externally_managed(
        collect(_home(
            tmp_path,
            unit_lines=f"Environment={READONLY_VAR}=1\nEnvironment={NIX_VAR}=1\n",
        ))
    )
    assert f.status == PASS
    joined = " ".join(f.evidence)
    assert READONLY_VAR in joined
    assert NIX_VAR in joined


def test_bad_fixture_unit_relocation_pass():
    # Named "clean_" because a PASS is the correct, good-posture outcome here — see the
    # fixture naming note at the top of the module (this check has no bad/adverse state).
    home = FIXTURES / "clean_b373_readonly_mode_detected" / "openclaw_home"
    f = check_config_externally_managed(collect(home))
    assert f.status == PASS
    assert READONLY_VAR in " ".join(f.evidence)


def test_nix_mode_fixture_via_dotenv_is_pass():
    home = FIXTURES / "clean_b373_nix_mode_detected_dotenv" / "openclaw_home"
    f = check_config_externally_managed(collect(home))
    assert f.status == PASS
    assert NIX_VAR in " ".join(f.evidence)


# ---------------------------------------------------------------------------
# Never WARN/FAIL — the whole point of the ticket's grounding.
# ---------------------------------------------------------------------------

def test_never_warn_or_fail_across_every_constructed_case(tmp_path):
    roots = []
    for name in ("a", "b", "c", "d", "e", "f"):
        root = tmp_path / name
        root.mkdir()
        roots.append(root)
    cases = [
        _home(roots[0]),
        _home(roots[1], units=False),
        _home(roots[2], unit_lines=f"Environment={READONLY_VAR}=1\n"),
        _home(roots[3], unit_lines=f"Environment={NIX_VAR}=1\n"),
        _home(roots[4], dotenv=f"{READONLY_VAR}=1"),
        _home(roots[5], unit_lines=f"Environment={READONLY_VAR}=true\n"),
    ]
    for home in cases:
        f = check_config_externally_managed(collect(home))
        assert f.status not in (WARN, FAIL), f"{home}: {f.status}"


# ---------------------------------------------------------------------------
# Catalog wiring
# ---------------------------------------------------------------------------

def test_b373_is_catalogued_advisory_and_never_scored():
    meta = BY_ID["B373"]
    assert meta.severity == "LOW"
    assert meta.block == "advisory"
    # No plausible FAIL/WARN shape exists for "the config is protected from being
    # rewritten" (Golden Rule #5) — this must stay out of the score denominator.
    assert meta.scored is False
